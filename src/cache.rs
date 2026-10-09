//! Read-through cache: Redis first, then Postgres, which refills Redis.

use std::time::Duration;

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::time::timeout;

use crate::zoo::LOCAL_TIMEOUT;

pub const TTL_SECS: u64 = 60;

pub fn valid_key(k: &str) -> bool {
    (1..=64).contains(&k.len()) && k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

pub fn redis_key(k: &str) -> String {
    format!("axum-cache:entry:{k}")
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Source {
    Redis,
    Postgres,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Redis => "redis",
            Source::Postgres => "postgres",
        }
    }
}

async fn within<T, E: std::fmt::Display>(what: &str, d: Duration, f: impl Future<Output = Result<T, E>>) -> Result<T, String> {
    match timeout(d, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: timeout after {} ms", d.as_millis())),
    }
}

/// Looks a valid key up. Ok(None) means no entry exists.
pub async fn lookup(db: &PgPool, redis: &ConnectionManager, key: &str) -> Result<Option<(String, Source)>, String> {
    let mut r = redis.clone();
    let rk = redis_key(key);
    let hit: Option<String> = within("redis get", LOCAL_TIMEOUT, r.get(&rk)).await?;
    if let Some(v) = hit {
        return Ok(Some((v, Source::Redis)));
    }
    let row: Option<(String,)> = within(
        "postgres select",
        LOCAL_TIMEOUT,
        sqlx::query_as("SELECT value FROM entries WHERE key = $1").bind(key).fetch_optional(db),
    )
    .await?;
    let Some((value,)) = row else { return Ok(None) };
    within::<(), _>("redis set", LOCAL_TIMEOUT, r.set_ex(&rk, &value, TTL_SECS)).await?;
    Ok(Some((value, Source::Postgres)))
}

pub async fn add_hop(db: &PgPool, trace: &str, step: &str, detail: &str) -> Result<(), String> {
    within(
        "postgres hop",
        LOCAL_TIMEOUT,
        sqlx::query("INSERT INTO hops (trace, step, detail) VALUES ($1::uuid, $2, $3) ON CONFLICT DO NOTHING")
            .bind(trace)
            .bind(step)
            .bind(detail)
            .execute(db),
    )
    .await
    .map(|_| ())
}

pub async fn hops(db: &PgPool, trace: &str) -> Result<Vec<serde_json::Value>, String> {
    let rows: Vec<(String, String, String)> = within(
        "postgres hops",
        LOCAL_TIMEOUT,
        sqlx::query_as(
            r#"SELECT to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), step, detail
               FROM hops WHERE trace = $1::uuid ORDER BY at"#,
        )
        .bind(trace)
        .fetch_all(db),
    )
    .await?;
    Ok(rows.into_iter().map(|(at, step, detail)| serde_json::json!({"at": at, "step": step, "detail": detail})).collect())
}

/// Probe: a fresh key misses Redis and reads Postgres, then the second
/// lookup hits Redis. The key and the row are removed afterwards.
pub async fn probe_path(db: &PgPool, redis: &ConnectionManager, token: &str) -> Result<String, String> {
    let key = format!("probe-{token}");
    within("postgres insert", LOCAL_TIMEOUT, sqlx::query("INSERT INTO entries (key, value) VALUES ($1, $2)").bind(&key).bind(token).execute(db)).await?;
    let result = async {
        let first = lookup(db, redis, &key).await?;
        let second = lookup(db, redis, &key).await?;
        match (first, second) {
            (Some((a, Source::Postgres)), Some((b, Source::Redis))) if a == token && b == token => {
                Ok("miss read Postgres and filled Redis, then hit Redis".to_string())
            }
            other => Err(format!("unexpected lookups {other:?}")),
        }
    }
    .await;
    let mut r = redis.clone();
    let _ = within::<(), _>("redis del", LOCAL_TIMEOUT, r.del(redis_key(&key))).await;
    let _ = within("postgres delete", LOCAL_TIMEOUT, sqlx::query("DELETE FROM entries WHERE key = $1").bind(&key).execute(db)).await;
    result
}

pub async fn probe_postgres(db: &PgPool, token: &str) -> Result<String, String> {
    let (id, got): (i64, String) = within(
        "insert",
        LOCAL_TIMEOUT,
        sqlx::query_as("INSERT INTO zoo_probe (token) VALUES ($1) RETURNING id, token").bind(token).fetch_one(db),
    )
    .await?;
    let (read,): (String,) = within("read", LOCAL_TIMEOUT, sqlx::query_as("SELECT token FROM zoo_probe WHERE id = $1").bind(id).fetch_one(db)).await?;
    within("delete", LOCAL_TIMEOUT, sqlx::query("DELETE FROM zoo_probe WHERE id = $1").bind(id).execute(db)).await?;
    let (version,): (String,) = within("version", LOCAL_TIMEOUT, sqlx::query_as("SHOW server_version").fetch_one(db)).await?;
    if got != token || read != token {
        return Err("read back a different token".into());
    }
    Ok(format!("zoo_probe row round trip, server {version}"))
}

pub async fn probe_redis(redis: &ConnectionManager, token: &str) -> Result<String, String> {
    let mut r = redis.clone();
    let k = format!("axum-cache:probe:{token}");
    within::<(), _>("set", LOCAL_TIMEOUT, r.set_ex(&k, token, 30)).await?;
    let got: Option<String> = within("get", LOCAL_TIMEOUT, r.get(&k)).await?;
    let ttl: i64 = within("ttl", LOCAL_TIMEOUT, r.ttl(&k)).await?;
    let removed: i64 = within("del", LOCAL_TIMEOUT, r.del(&k)).await?;
    match (got.as_deref() == Some(token), (1..=30).contains(&ttl), removed == 1) {
        (true, true, true) => Ok(format!("SET EX 30, GET, TTL {ttl}, DEL")),
        _ => Err(format!("got {got:?}, ttl {ttl}, removed {removed}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        for ok in ["zoo", "a", "probe-0123abcd", &"a".repeat(64)] {
            assert!(valid_key(ok), "{ok}");
        }
        for bad in ["", "Zoo", "a_b", "a/b", "../x", "zoo ", &"a".repeat(65), "é"] {
            assert!(!valid_key(bad), "{bad}");
        }
    }
}
