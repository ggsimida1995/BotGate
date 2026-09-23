# Delivery Roadmap

## Phase 1 — complete

HTTP server, TOML configuration, exact Host routing, HTTP reverse proxy, forwarded headers, size limits, timeout handling and basic upstream SSRF validation.

Acceptance: a browser reaches the configured upstream after the Challenge, while an unverified curl/API request is stopped before the upstream; unknown Hosts do not; a stopped upstream returns 502/504; from `backend/`, `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test` pass, and from `frontend/`, `npm run build` passes.

## Phase 2 — complete

One-time JavaScript Challenge, Challenge TTL/attempt limits, HMAC-SHA256 signed cookies, Host-only verification and HTML/API response separation.

## Phase 3 — complete

Token-bucket rate limits, scanner heuristics, risk score, temporary bans and IP/CIDR whitelist.

## Phase 4 — complete

SQLite schema, asynchronous batched request/security logs, retention cleanup and persisted active bans.

## Phase 5 — complete

Completed: loopback-only admin UI, dashboard, and SQLite-backed site/ban/whitelist management with immediate runtime application. The admin listener intentionally has no password login because it is restricted to loopback.

Completed: loopback-only `POST /api/reload` safely validates TOML and atomically reloads sites and whitelist rules; listener and process-lifetime settings still require restart.

## Phase 6 — core complete

DNS-aware SSRF checks are complete. Domain upstreams are opt-in via `upstream.allow_dns`, resolved per request, and connected through the checked address. Optional Rustls HTTPS, redirects from HTTP for configured hosts, and certificate/key reload are implemented. WebSocket/SSE support and intentionally unbuffered large uploads remain separate future work.

## Phase 7 — release pipeline complete

GitHub Actions builds Linux x64 archives, Windows x64, x86 and ARM64 MSI installers, plus a macOS arm64 disk image with SHA-256 checksums. The current workflow builds directly from this repository; source/release repository separation remains future work. Windows Service commands and systemd/launchd examples also remain future work.

## Deferred by design

No Docker, external CAPTCHA, cloud dependency, Redis, PostgreSQL, complex RBAC or plugin system. Bot Gate accepts any internal HTTP source server; it does not manage the source server configuration.
