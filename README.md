# Bot Gate

Cross-platform local web bot gate and reverse proxy, written in Rust.

## Current status

Phases 1–6 core features are implemented:

- TOML configuration
- Exact Host-based site routing
- HTTP reverse proxy
- Forwarded header generation
- Header/body size limits
- Upstream timeout handling
- Loopback-only upstream validation by default
- Optional per-request DNS resolution with SSRF address re-checking
- One-time browser challenge with a small local proof-of-work
- HMAC-SHA256 signed verification cookie
- HTML/API separation for unverified requests
- Challenge expiry, attempt limits and replay protection
- Token-bucket rate limiting
- IP/CIDR whitelist
- Scanner risk scoring and temporary in-memory bans
- SQLite WAL storage with batched request/security logging
- Log retention cleanup and persisted active bans
- Auditable blocked-request and Challenge-failure records
- Loopback-only management authentication and dashboard
- Site, active-ban and whitelist management APIs backed by SQLite
- Optional Rustls HTTPS listener, HTTP-to-HTTPS redirects and certificate/key reload

HTTPS is optional: enable `[tls]` with a PEM certificate and key, then use `tls.redirect_http = true` if the HTTP listener should redirect configured hosts. The authenticated reload API safely reloads TOML sites, whitelist rules, and an already enabled TLS certificate/key; listener, verification, security, storage and admin settings still require restart. Rate-limit/risk counters remain in memory; active bans and retained logs persist in SQLite. Do not expose this build to an untrusted network without understanding those limits.

## Management API

With `[admin]` enabled, open `http://127.0.0.1:9090`. Authenticated JSON endpoints are available at `/api/sites`, `/api/bans`, and `/api/whitelist`; each supports `GET` and `POST`, with matching `/delete` endpoints for removal. Managed data is seeded from TOML once and then retained in SQLite.

## Quick start

```text
cp config.example.toml config.toml
cargo run -- config.toml
```

Add hosts entries:

```text
127.0.0.1 project-a.test
127.0.0.1 project-b.test
```

`.test` is preferred for local development. `.local` may be handled by mDNS/Bonjour on macOS.

Open `http://project-a.test:8080` after the upstream on port 9001 is running. A normal HTML request is redirected to the local Browser Challenge; JSON/API requests receive a 403 until the signed cookie is present.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the phase gates and acceptance tests.

## Security

See [docs/SECURITY.md](docs/SECURITY.md). The project raises the cost of simple local-network scanning; it does not prove that a client is human and does not replace application security.
