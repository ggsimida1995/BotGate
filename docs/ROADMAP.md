# Delivery Roadmap

## Phase 1 — complete

HTTP server, TOML configuration, exact Host routing, HTTP reverse proxy, forwarded headers, size limits, timeout handling and basic upstream SSRF validation.

Acceptance: browser and curl reach the configured upstream; unknown Hosts do not; a stopped upstream returns 502/504; `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test` pass.

## Phase 2 — complete

One-time JavaScript Challenge, Challenge TTL/attempt limits, HMAC-SHA256 signed cookies, Host-only verification and HTML/API response separation.

## Phase 3 — complete

Token-bucket rate limits, scanner heuristics, risk score, temporary bans and IP/CIDR whitelist.

## Phase 4 — complete

SQLite schema, asynchronous batched request/security logs, retention cleanup and persisted active bans.

## Phase 5 — complete

Completed: loopback-only admin UI, Argon2id password setup, signed sessions, dashboard, and SQLite-backed site/ban/whitelist management with immediate runtime application.

Completed: authenticated `POST /api/reload` safely validates TOML and atomically reloads sites and whitelist rules; listener and process-lifetime settings still require restart.

## Phase 6 — core complete

DNS-aware SSRF checks are complete. Domain upstreams are opt-in via `upstream.allow_dns`, resolved per request, and connected through the checked address. Optional Rustls HTTPS, redirects from HTTP for configured hosts, and certificate/key reload are implemented. WebSocket/SSE support and intentionally unbuffered large uploads remain separate future work.

## Phase 7

Windows Service commands, systemd/launchd examples, GitHub Actions release matrix, archives, checksums and cross-platform packaging.

## Deferred by design

No Docker, Node.js, Python, Java, Nginx, external CAPTCHA, cloud dependency, Redis, PostgreSQL, complex RBAC or plugin system.
