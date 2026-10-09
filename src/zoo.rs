//! The oxzoo-live contract from DESIGN.md: zoo-sig v1, CORS, trace ids,
//! health fields, and the probe runner.

use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_BODY: usize = 64 * 1024;
pub const LOCAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SKEW: u64 = 300;

fn mac(key: &str, t: i64, method: &str, path_query: &str, body: &[u8]) -> Hmac<Sha256> {
    let body_hash = hex::encode(Sha256::digest(body));
    let mut m = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    m.update(format!("{t}.{}.{path_query}.{body_hash}", method.to_uppercase()).as_bytes());
    m
}

/// The zoo-sig v1 hex signature.
pub fn sign(key: &str, t: i64, method: &str, path_query: &str, body: &[u8]) -> String {
    hex::encode(mac(key, t, method, path_query, body).finalize().into_bytes())
}

/// The last 4 hex characters of sha256(value).
pub fn fp(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[60..].to_string()
}

/// Checks an X-Zoo-Signature header and returns the caller, or one of the
/// DESIGN.md reasons.
pub fn verify(
    key: &str, callers: &[&str], header: Option<&str>, method: &str, path_query: &str, body: &[u8], now: i64,
) -> Result<String, &'static str> {
    let h = header.ok_or("missing signature")?;
    let mut parts = HashMap::new();
    for kv in h.split(',') {
        let (k, v) = kv.trim().split_once('=').ok_or("bad format")?;
        parts.insert(k, v);
    }
    let t: i64 = parts.get("t").and_then(|s| s.parse().ok()).ok_or("bad format")?;
    let sig = parts.get("sig").and_then(|s| hex::decode(s).ok()).filter(|s| s.len() == 32).ok_or("bad format")?;
    let caller = *parts.get("caller").filter(|c| !c.is_empty()).ok_or("bad format")?;
    if now.checked_sub(t).is_none_or(|d| d.unsigned_abs() > MAX_SKEW) {
        return Err("expired");
    }
    if !callers.contains(&caller) {
        return Err("unknown caller");
    }
    if key.is_empty() || mac(key, t, method, path_query, body).verify_slice(&sig).is_err() {
        return Err("bad signature");
    }
    Ok(caller.to_string())
}

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub fn json_resp(status: u16, v: Value) -> Response {
    (StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), Json(v)).into_response()
}

/// A request that passed zoo-sig verification.
pub struct Signed {
    pub caller: String,
    pub trace: Option<String>,
}

/// Reads the body (64 KB cap), verifies the signature with the value of
/// key_name, and validates X-Zoo-Trace. Err is the answer to send.
pub async fn guard(key_name: &str, key: &str, callers: &[&str], req: Request, now: i64) -> Result<Signed, Response> {
    if key.is_empty() {
        return Err(json_resp(503, json!({"ok": false, "error": format!("{key_name} is not set")})));
    }
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| json_resp(413, json!({"ok": false, "error": "body too large"})))?;
    let path_query = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let header = parts.headers.get("x-zoo-signature").and_then(|v| v.to_str().ok());
    let caller = verify(key, callers, header, parts.method.as_str(), path_query, &body, now)
        .map_err(|e| json_resp(401, json!({"ok": false, "error": e})))?;
    let trace = match parts.headers.get("x-zoo-trace") {
        None => None,
        Some(v) => match v.to_str() {
            Ok(t) if is_trace(t) => Some(t.to_string()),
            _ => return Err(json_resp(400, json!({"error": "bad X-Zoo-Trace"}))),
        },
    };
    Ok(Signed { caller, trace })
}

pub fn is_trace(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

pub fn release() -> String {
    match env::var("OX_RELEASE") {
        Ok(r) if !r.is_empty() => r.chars().take(12).collect(),
        _ => "unknown".into(),
    }
}

pub fn ox_env() -> String {
    env::var("OX_ENV").ok().filter(|e| !e.is_empty()).unwrap_or_else(|| "local".into())
}

/// The sN label of a host name, else "local".
pub fn server_label(host: &str) -> String {
    host.split('.')
        .find(|l| l.len() > 1 && l.starts_with('s') && l[1..].bytes().all(|c| c.is_ascii_digit()))
        .unwrap_or("local")
        .to_string()
}

pub fn server() -> String {
    server_label(&env::var("PUBLIC_HOST").unwrap_or_default())
}

/// RFC 3339 UTC for a Unix time (days-from-civil, Howard Hinnant).
pub fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// CORS for /_zoo/* from the ZOO_PANEL_ORIGIN list; lets only GET through.
pub async fn cors(State(origins): State<Arc<Vec<String>>>, req: Request, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).filter(|o| origins.iter().any(|x| x.as_bytes() == o.as_bytes())).cloned();
    let preflight = req.method() == Method::OPTIONS;
    let mut resp = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else if req.method() != Method::GET {
        json_resp(405, json!({"error": "method not allowed"}))
    } else {
        next.run(req).await
    };
    if let Some(o) = origin {
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
        h.append(header::VARY, HeaderValue::from_static("Origin"));
        if preflight {
            h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
            h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type"));
            h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        }
    }
    resp
}

pub fn parse_origins(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|p| !p.is_empty()).map(String::from).collect()
}

pub type CheckFuture = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;

/// One probe check: a real round trip that answers a detail or an error.
pub struct Check {
    pub id: &'static str,
    pub label: &'static str,
    pub env: &'static [&'static str],
    pub run: CheckFuture,
}

/// Runs the checks in parallel, each with the 5 s local limit.
pub async fn run_checks(checks: Vec<Check>, hop: String) -> (bool, Vec<Value>) {
    let mut tasks = Vec::new();
    for c in checks {
        let hop = hop.clone();
        tasks.push(tokio::spawn(async move {
            let mut res = json!({"id": c.id, "label": c.label, "ok": false, "ms": 0, "env": c.env, "hops": [hop]});
            if let Some(name) = c.env.iter().find(|n| env::var(n).map_or(true, |v| v.is_empty())) {
                res["error"] = json!(format!("{name} is not set"));
                return res;
            }
            let start = Instant::now();
            let out = tokio::time::timeout(LOCAL_TIMEOUT, c.run).await;
            res["ms"] = json!(start.elapsed().as_millis() as u64);
            match out {
                Err(_) => res["error"] = json!(format!("timeout after {} ms", LOCAL_TIMEOUT.as_millis())),
                Ok(Err(e)) => res["error"] = json!(e),
                Ok(Ok(detail)) => {
                    res["ok"] = json!(true);
                    res["detail"] = json!(detail);
                }
            }
            res
        }));
    }
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap_or_else(|e| json!({"ok": false, "error": format!("check panicked: {e}")})));
    }
    (results.iter().all(|r| r["ok"] == true), results)
}

pub fn secret_var(name: &str, role: &str) -> Value {
    match env::var(name) {
        Ok(v) if !v.is_empty() => json!({"name": name, "fp": fp(&v), "role": role}),
        _ => json!({"name": name, "role": role, "missing": true}),
    }
}

pub fn plain_var(name: &str) -> Value {
    match env::var(name) {
        Ok(v) if !v.is_empty() => json!({"name": name, "value": v, "role": "plain"}),
        _ => json!({"name": name, "role": "plain", "missing": true}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    const KEY: &str = "zoo-test-key-0123456789abcdef";
    const T: i64 = 1_760_000_000;

    #[test]
    fn signing_vectors() {
        assert_eq!(
            sign(KEY, T, "POST", "/api/items?x=1", br#"{"sku":"ZOO-1"}"#),
            "50c22839fe6a06cb51a9fd25167d9e457eb0b5ee63ce696f4c5428a6b9271da1"
        );
        assert_eq!(sign(KEY, T, "get", "/_zoo/verify", b""), "9a404bebaa32497c5ed39ef8990e8466428f8023d6aa9f5acc94f16fb7670ecb");
        assert_eq!(fp(KEY), "915a");
    }

    #[test]
    fn verify_reasons() {
        let callers = ["sveltekit-ssr"];
        let good = format!("t={T},caller=sveltekit-ssr,sig={}", sign(KEY, T, "GET", "/api/cache/zoo", b""));
        let v = |h: Option<&str>, now: i64| verify(KEY, &callers, h, "GET", "/api/cache/zoo", b"", now);
        assert_eq!(v(Some(&good), T + 300), Ok("sveltekit-ssr".into()));
        assert_eq!(v(None, T), Err("missing signature"));
        assert_eq!(v(Some("garbage"), T), Err("bad format"));
        assert_eq!(v(Some(&format!("t=x,caller=a,sig={}", "0".repeat(64))), T), Err("bad format"));
        assert_eq!(v(Some(&format!("t={},caller=a,sig={}", i64::MIN, "0".repeat(64))), T), Err("expired"));
        assert_eq!(v(Some(&good), T + 301), Err("expired"));
        let other = good.replace("sveltekit-ssr", "mesh-shop");
        assert_eq!(v(Some(&other), T), Err("unknown caller"));
        let tampered = format!("t={T},caller=sveltekit-ssr,sig={}", sign(KEY, T, "GET", "/api/cache/ox", b""));
        assert_eq!(v(Some(&tampered), T), Err("bad signature"));
        assert_eq!(verify("", &callers, Some(&good), "GET", "/api/cache/zoo", b"", T), Err("bad signature"));
    }

    #[tokio::test]
    async fn guard_checks_trace_and_body() {
        let sig = format!("t={T},caller=sveltekit-ssr,sig={}", sign(KEY, T, "GET", "/api/cache/zoo", b""));
        let req = |trace: &str| {
            Request::builder().uri("/api/cache/zoo").header("x-zoo-signature", &sig).header("x-zoo-trace", trace).body(Body::empty()).unwrap()
        };
        let ok = guard("INTERNAL_TOKEN", KEY, &["sveltekit-ssr"], req("0f8fad5b-d9cb-469f-a165-70867728950e"), T).await;
        assert_eq!(ok.ok().and_then(|s| s.trace).as_deref(), Some("0f8fad5b-d9cb-469f-a165-70867728950e"));
        let bad = guard("INTERNAL_TOKEN", KEY, &["sveltekit-ssr"], req("not-a-trace"), T).await;
        assert_eq!(bad.err().map(|r| r.status()), Some(StatusCode::BAD_REQUEST));
        let unset = guard("INTERNAL_TOKEN", "", &["sveltekit-ssr"], req("x"), T).await;
        assert_eq!(unset.err().map(|r| r.status()), Some(StatusCode::SERVICE_UNAVAILABLE));
        let big = Request::builder().uri("/api/cache/zoo").body(Body::from(vec![b'a'; MAX_BODY + 1])).unwrap();
        let big = guard("INTERNAL_TOKEN", KEY, &["sveltekit-ssr"], big, T).await;
        assert_eq!(big.err().map(|r| r.status()), Some(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[test]
    fn trace_ids() {
        assert!(is_trace("0f8fad5b-d9cb-469f-a165-70867728950e"));
        for bad in ["", "0F8FAD5B-D9CB-469F-A165-70867728950E", "0f8fad5b-d9cb-469f-a165-70867728950", "0f8fad5bxd9cb-469f-a165-70867728950e", "0f8fad5b-d9cb-469f-a165-70867728950g"] {
            assert!(!is_trace(bad), "{bad}");
        }
    }

    #[test]
    fn labels_and_time() {
        assert_eq!(server_label("axum-cache.s4.zoo.sorv.dev"), "s4");
        assert_eq!(server_label("localhost"), "local");
        assert_eq!(server_label("s.example"), "local");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(1_760_000_000)), "2025-10-09T08:53:20Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00Z");
    }

    #[tokio::test]
    async fn cors_only_for_listed_origins() {
        let origins = Arc::new(parse_origins(" https://zoo-control.s1.zoo.sorv.dev, http://localhost:5173"));
        let app = Router::new()
            .route("/_zoo/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(origins, cors));
        let call = |method: &str, origin: &str| {
            let req = Request::builder().method(method).uri("/_zoo/health").header("origin", origin).body(Body::empty()).unwrap();
            app.clone().oneshot(req)
        };
        let r = call("GET", "http://localhost:5173").await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["access-control-allow-origin"], "http://localhost:5173");
        assert_eq!(r.headers()["vary"], "Origin");
        let r = call("OPTIONS", "https://zoo-control.s1.zoo.sorv.dev").await.unwrap();
        assert_eq!(r.status(), 204);
        assert_eq!(r.headers()["access-control-allow-methods"], "GET, POST, OPTIONS");
        assert_eq!(r.headers()["access-control-max-age"], "600");
        let r = call("OPTIONS", "https://evil.example").await.unwrap();
        assert_eq!(r.status(), 204);
        assert!(r.headers().get("access-control-allow-origin").is_none());
        assert_eq!(call("POST", "http://localhost:5173").await.unwrap().status(), 405);
    }
}
