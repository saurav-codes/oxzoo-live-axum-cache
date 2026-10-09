# axum-cache

> **Role in the zoo:** project `axum-cache` of [oxzoo-live](https://github.com/saurav-codes/oxzoo-live-control/blob/main/zoo/README.md#projects), deployed with ox on server s4 at https://axum-cache.s4.zoo.sorv.dev. The contract it follows is [DESIGN.md](https://github.com/saurav-codes/oxzoo-live-control/blob/main/zoo/DESIGN.md).

A Rust read-through cache on Axum 0.8: signed `GET /api/cache/{key}` answers from Redis, else from Postgres, which refills Redis for 60 s. It is the `axum` leg of the `ssr-fanout` chain: sveltekit-ssr calls it server-side with `INTERNAL_TOKEN`.

## What it proves

- A Rust service builds and runs on ox from `Cargo.toml`, `Cargo.lock`, and `rust-toolchain.toml` (`cargo build --release --locked`, start `target/release/axum-cache`).
- ox Postgres and Redis reach a Rust process through `DATABASE_URL` and `REDIS_URL` (sqlx with rustls, redis-rs `ConnectionManager`).
- sqlx migrations embedded in the binary (`sqlx::migrate!`) run at start, before the listener opens; the first migration seeds `zoo`, `axum`, and `ox`.
- zoo-sig v1 verification, CORS, trace hops, and a probe that exercises the real cache path.
- Graceful shutdown on SIGTERM through `axum::serve(...).with_graceful_shutdown`.

## ox features

Detected: Rust toolchain, build, start. Declared in `ox.toml`: `[services] postgres` and `redis`, because ox does not infer services from Rust crates, and `[app] health`, which is also what keeps the detected start command (see the findings below).

## Routes

| Route | What |
|---|---|
| `GET /` | the entries list |
| `GET /api/cache/{key}` | signed (`INTERNAL_TOKEN`, caller `sveltekit-ssr`). `key` must match `^[a-z0-9-]{1,64}$` (else 400). 200 `{"key","value","source":"redis"\|"postgres","trace","release"}`, 404 when no entry, 503 when Redis or Postgres fails. With a valid `X-Zoo-Trace` it records hop `signed-lookup`; a malformed one is 400 |
| `GET /_zoo/verify` | signed like above; answers `key_fp`, `public_url`, `caller` |
| `GET /_zoo/trace/{id}` | hops of a trace from Postgres; a malformed id is 400 |
| `GET /_zoo/health` | name, stack, server, release, env, uptime, started_at, build (`runtime`, `built_at` from the binary's mtime) |
| `GET /_zoo/probe` | `postgres` (zoo_probe insert, read, delete), `redis` (SET EX 30, GET, TTL, DEL), `cache-path` (a fresh key misses Redis and reads Postgres, the second lookup hits Redis; both removed after) |

Every Postgres and Redis call has a 5 s limit. The probe runs one at a time (a second waits up to 5 s, then 429), 5 s per check, 20 s overall. CORS on health, probe, and trace answers only `ZOO_PANEL_ORIGIN`.

## Variables

| Variable | Who sets it | What |
|---|---|---|
| `DATABASE_URL`, `REDIS_URL` | ox, from `[services]` | probe role `service` (fp only) |
| `PORT`, `HOST`, `OX_ENV`, `OX_RELEASE`, `PUBLIC_HOST`, `PUBLIC_URL` | ox | listen address, release, server label, verify's `public_url` |
| `INTERNAL_TOKEN` | you, the shared secret | probe role `verifies` |
| `ZOO_PANEL_ORIGIN` | you | `https://zoo-control.s1.zoo.sorv.dev` |

## Tests

```sh
cargo test
```

Recorded on 2026-10-09: `test result: ok. 7 passed; 0 failed` (signing vectors and fp `915a`, every verify reason, guard trace and 64 KB body cap, trace id validation, server label and RFC 3339 dates, CORS for listed and unlisted origins, cache key validation).

A local run against Homebrew Postgres 18.6 and Redis (script in `/tmp/oxz-ac/it.sh`, not committed) answered: first lookup `source: postgres`, second `source: redis`; unknown key 404, `Bad_Key` 400, caller `mesh-shop` 401 `unknown caller`, unsigned 401 `missing signature`; verify `key_fp: 915a`; trace `found: true` with hop `signed-lookup`; bad trace 400; probe `ok: true` (3 checks, 6 ms); preflight 204 with the CORS headers; two concurrent probes both 200; Redis stopped gives 503 `cache unavailable`; SIGTERM logged `draining` then `stopped`.

## ox check

```
ox check . (manifest: ox.toml)

  app.start                  target/release/axum-cache                            detected:Cargo.toml
  app.health                 /_zoo/health                                         declared
  build.commands[0]          cargo build --release --locked                       detected:Cargo.lock
  tools.rust                 1.98                                                 detected:rust-toolchain.toml
  services.postgres          postgres 18 (shared)                                 default
  services.redis             redis 8 (only for this project)                      default

  Provided by ox: PORT, HOST, OX_ENV, OX_PROJECT, OX_RELEASE, OX_DATA_DIR, PUBLIC_URL, PUBLIC_HOST, DATABASE_URL, REDIS_URL
  Set on the dashboard before the first deploy: INTERNAL_TOKEN, ZOO_PANEL_ORIGIN

Ready to deploy.
```

Findings while getting there: with no `ox.toml` the check says "Ready to deploy." but nothing provides `DATABASE_URL` or `REDIS_URL`, so the app would exit at start. With `ox.toml` holding only `[services]`, the detected start command disappears and the check fails with "nothing to run"; adding `[app] health` brings it back.
