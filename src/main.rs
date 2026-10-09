//! axum-cache: a signed read-through cache. GET /api/cache/{key} answers from
//! Redis, else from Postgres (which refills Redis for 60 s).

mod cache;
mod zoo;

use std::env;
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::extract::{Path, Request, State};
use axum::response::{Html, Response};
use axum::routing::get;
use axum::{Router, middleware};
use redis::aio::ConnectionManager;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Semaphore;

use crate::zoo::{Check, json_resp};

const NAME: &str = "axum-cache";
const STACK: &str = "Rust Axum + sqlx + redis-rs";
const KEY_NAME: &str = "INTERNAL_TOKEN";
const CALLERS: &[&str] = &["sveltekit-ssr"];

#[derive(Clone)]
struct App {
    db: PgPool,
    redis: ConnectionManager,
    probe: Arc<Semaphore>,
    started: SystemTime,
    built_at: Option<String>,
}

fn require(name: &str) -> String {
    match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => fail(&format!("{name} is not set")),
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("axum-cache: {msg}");
    std::process::exit(1)
}

#[tokio::main]
async fn main() {
    let db = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(&require("DATABASE_URL"))
        .unwrap_or_else(|e| fail(&format!("DATABASE_URL: {e}")));
    match tokio::time::timeout(Duration::from_secs(30), sqlx::migrate!("./migrations").run(&db)).await {
        Ok(Ok(())) => println!("migrations up to date"),
        Ok(Err(e)) => fail(&format!("migrate: {e}")),
        Err(_) => fail("migrate: timeout after 30 s"),
    }
    let client = redis::Client::open(require("REDIS_URL")).unwrap_or_else(|e| fail(&format!("REDIS_URL: {e}")));
    let redis = match tokio::time::timeout(Duration::from_secs(10), ConnectionManager::new(client)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => fail(&format!("redis: {e}")),
        Err(_) => fail("redis: timeout after 10 s"),
    };
    let built_at = env::current_exe().and_then(std::fs::metadata).and_then(|m| m.modified()).ok().map(zoo::rfc3339);
    let app = App { db, redis, probe: Arc::new(Semaphore::new(1)), started: SystemTime::now(), built_at };

    let host = env::var("HOST").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "127.0.0.1".into());
    let port = env::var("PORT").ok().filter(|p| !p.is_empty()).unwrap_or_else(|| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await.unwrap_or_else(|e| fail(&format!("bind: {e}")));
    println!("listening on {host}:{port}, release {}", zoo::release());
    axum::serve(listener, routes(app)).with_graceful_shutdown(shutdown()).await.unwrap_or_else(|e| fail(&format!("serve: {e}")));
    println!("stopped");
}

async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    println!("SIGTERM: draining in-flight requests");
}

fn routes(app: App) -> Router {
    let panel = Arc::new(zoo::parse_origins(&env::var("ZOO_PANEL_ORIGIN").unwrap_or_default()));
    let zoo_routes = Router::new()
        .route("/_zoo/health", get(health))
        .route("/_zoo/probe", get(probe))
        .route("/_zoo/trace/{id}", get(trace))
        .layer(middleware::from_fn_with_state(panel, zoo::cors));
    Router::new()
        .route("/", get(index))
        .route("/api/cache/{key}", get(lookup))
        .route("/_zoo/verify", get(verify))
        .merge(zoo_routes)
        .with_state(app)
}

fn key_value() -> String {
    env::var(KEY_NAME).unwrap_or_default()
}

async fn lookup(State(app): State<App>, Path(key): Path<String>, req: Request) -> Response {
    let signed = match zoo::guard(KEY_NAME, &key_value(), CALLERS, req, zoo::unix_now()).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if !cache::valid_key(&key) {
        return json_resp(400, json!({"error": "key must match ^[a-z0-9-]{1,64}$"}));
    }
    let found = match cache::lookup(&app.db, &app.redis, &key).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("lookup {key}: {e}");
            return json_resp(503, json!({"error": "cache unavailable"}));
        }
    };
    let Some((value, source)) = found else {
        return json_resp(404, json!({"error": "no such key", "key": key}));
    };
    if let Some(t) = &signed.trace {
        let detail = format!("key {key} from {}, caller {}", source.as_str(), signed.caller);
        if let Err(e) = cache::add_hop(&app.db, t, "signed-lookup", &detail).await {
            eprintln!("hop {t}: {e}");
        }
    }
    json_resp(200, json!({"key": key, "value": value, "source": source.as_str(), "trace": signed.trace, "release": zoo::release()}))
}

async fn verify(req: Request) -> Response {
    let key = key_value();
    match zoo::guard(KEY_NAME, &key, CALLERS, req, zoo::unix_now()).await {
        Err(resp) => resp,
        Ok(s) => json_resp(200, json!({
            "ok": true, "name": NAME, "public_url": env::var("PUBLIC_URL").unwrap_or_default(), "verified_by": KEY_NAME,
            "key_fp": zoo::fp(&key), "caller": s.caller, "server": zoo::server(), "release": zoo::release(),
        })),
    }
}

async fn health(State(app): State<App>) -> Response {
    let mut build = json!({"runtime": concat!("rust ", env!("CARGO_PKG_RUST_VERSION"))});
    if let Some(b) = &app.built_at {
        build["built_at"] = json!(b);
    }
    json_resp(200, json!({
        "name": NAME, "stack": STACK, "server": zoo::server(), "release": zoo::release(), "env": zoo::ox_env(),
        "uptime_s": app.started.elapsed().map_or(0, |d| d.as_secs()), "started_at": zoo::rfc3339(app.started), "build": build,
    }))
}

async fn trace(State(app): State<App>, Path(id): Path<String>) -> Response {
    if !zoo::is_trace(&id) {
        return json_resp(400, json!({"error": "bad trace id"}));
    }
    match cache::hops(&app.db, &id).await {
        Ok(hops) => json_resp(200, json!({"trace": id, "found": !hops.is_empty(), "hops": hops})),
        Err(e) => {
            eprintln!("trace {id}: {e}");
            json_resp(500, json!({"error": "trace lookup failed"}))
        }
    }
}

fn token() -> String {
    format!("{:016x}", RandomState::new().hash_one(SystemTime::now()))
}

async fn probe(State(app): State<App>) -> Response {
    let Ok(Ok(_permit)) = tokio::time::timeout(Duration::from_secs(5), app.probe.clone().acquire_owned()).await else {
        return json_resp(429, json!({"error": "probe busy"}));
    };
    let start = std::time::Instant::now();
    let (db, redis) = (app.db.clone(), app.redis.clone());
    let (db2, redis2) = (app.db.clone(), app.redis.clone());
    let checks = vec![
        Check { id: "postgres", label: "Postgres write, read, delete", env: &["DATABASE_URL"],
            run: Box::pin(async move { cache::probe_postgres(&db, &token()).await }) },
        Check { id: "redis", label: "Redis SET/GET/DEL with TTL", env: &["REDIS_URL"],
            run: Box::pin(async move { cache::probe_redis(&redis, &token()).await }) },
        Check { id: "cache-path", label: "Cache miss reads Postgres, then hit reads Redis", env: &["DATABASE_URL", "REDIS_URL"],
            run: Box::pin(async move { cache::probe_path(&db2, &redis2, &token()).await }) },
    ];
    let whole = tokio::time::timeout(Duration::from_secs(20), zoo::run_checks(checks, format!("{NAME}@{}", zoo::server()))).await;
    let Ok((ok, results)) = whole else {
        return json_resp(504, json!({"error": "probe timeout after 20000 ms"}));
    };
    json_resp(200, json!({
        "name": NAME, "stack": STACK, "server": zoo::server(), "release": zoo::release(), "env": zoo::ox_env(),
        "ok": ok, "ms": start.elapsed().as_millis() as u64, "at": zoo::rfc3339(SystemTime::now()), "checks": results,
        "vars": [zoo::secret_var("INTERNAL_TOKEN", "verifies"), zoo::secret_var("DATABASE_URL", "service"),
                 zoo::secret_var("REDIS_URL", "service"), zoo::plain_var("ZOO_PANEL_ORIGIN")],
    }))
}

async fn index(State(app): State<App>) -> Html<String> {
    let rows: Vec<(String, String)> = tokio::time::timeout(zoo::LOCAL_TIMEOUT,
        sqlx::query_as("SELECT key, value FROM entries WHERE key NOT LIKE 'probe-%' ORDER BY key LIMIT 50").fetch_all(&app.db))
        .await.ok().and_then(Result::ok).unwrap_or_default();
    let list: String = rows.iter().map(|(k, v)| format!("<li><code>{}</code>: {}</li>", esc(k), esc(v))).collect();
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>axum-cache</title>\
         <style>body{{font:15px system-ui;margin:2rem;max-width:44rem}}code{{color:#555}}</style></head><body>\
         <h1>axum-cache</h1><p>Signed <code>GET /api/cache/{{key}}</code> reads Redis first, then Postgres, \
         which refills Redis for {} s. Only sveltekit-ssr may call it (zoo-sig v1 with INTERNAL_TOKEN).</p>\
         <p>Server {}, release <code>{}</code>.</p><h2>Entries</h2><ul>{}</ul></body></html>",
        cache::TTL_SECS, zoo::server(), zoo::release(), if list.is_empty() { "<li>none or store unavailable</li>".into() } else { list }
    ))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
