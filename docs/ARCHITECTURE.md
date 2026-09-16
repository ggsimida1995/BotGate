# Bot Gate Architecture

## Scope

Bot Gate is a local reverse proxy with a Rust backend and a separately built React frontend. It sits in front of one or more local HTTP applications and progressively adds browser verification, request policy enforcement, persistence and a loopback-only management plane. The release process produces one Rust executable plus the `frontend/dist` assets it serves. Backend source, configuration, database and build output live under `backend/`.

## Runtime flow

```text
Public HTTP/TLS listener
  -> request limits and Host validation
  -> ban / whitelist decision
  -> rate limit and scanner risk rejection
  -> signed-cookie verification / Browser Challenge
  -> reverse proxy
  -> asynchronous request/security logging
```

When verification is enabled, a request without a valid site-bound HMAC cookie is stopped at the verification step. It is redirected to the Challenge for HTML navigation or returned as `403` for API/non-GET requests; it never reaches an upstream. Whitelist entries can change rate/risk policy only and cannot bypass this gate.

The admin listener is separate and defaults to `127.0.0.1:9090`. Process startup binds the admin listener only; the public HTTP/TLS listeners are owned by `GatewayController` and remain stopped until the operator starts the gateway from the dashboard. Gateway start checks the configured license first, so an enabled license that is missing, invalid or expired prevents any public listener from binding.

## Trust boundaries

- The public listener treats LAN clients as untrusted.
- The client-provided User-Agent, Referer, Origin and forwarded headers are untrusted.
- The upstream target is configuration data, never request data.
- The admin listener is a local trust boundary: it is loopback-only and intentionally has no password login.

## Component plan

| Component | Responsibility |
|---|---|
| `config` | Parse, validate and atomically reload TOML |
| `routing` | Normalize Host and select enabled site |
| `challenge` | One-time browser challenge store |
| `verification` | Challenge submission and cookie issuance |
| `cookie` | HMAC-SHA256 signed cookie encoding/verification |
| `ratelimit` | Token buckets for global/IP/Host/Path |
| `scanner` | 404, path diversity and sensitive-path risk scoring |
| `ban` / `whitelist` | Temporary bans and CIDR exceptions |
| `proxy` | Header-safe, streaming HTTP forwarding |
| `storage` | SQLite schema and batched writes |
| `admin` | Loopback-only dashboard and management API |

The source layout mirrors these boundaries: `backend/src/config.rs`, `backend/src/security.rs`, `backend/src/http.rs`, `backend/src/proxy.rs`, `backend/src/verification.rs`, `backend/src/storage.rs`, and `backend/src/admin.rs` keep configuration, enforcement, HTTP helpers, transport, challenge, persistence, and management code out of the request entry point. `backend/src/main.rs` focuses on wiring, request orchestration and lifecycle. The React + Ant Design management and challenge pages live under `frontend/src/` and build into `frontend/dist/`.

## Global verification

Host-only cookies are the default. For unrelated hosts, a configured verification broker issues a very short-lived, single-use exchange token. The token is bound to the configured site and opaque return state; arbitrary redirect URLs are never accepted.

In the current phase, the per-site flow is implemented locally: an unverified HTML request is redirected to `/__bot_verify/start`, the browser solves a small SHA-256 proof-of-work, and the gateway issues a Host-only HMAC-SHA256 cookie. Challenges are one-use, short-lived and bound to the connecting IP by default.

## Reverse proxy rules

- Phase 6 still supports HTTP upstreams only; optional DNS targets are resolved and SSRF-checked per request before connecting to the selected IP.
- Client `X-Forwarded-*`, `Forwarded`, `Connection` and other hop-by-hop headers are removed.
- Gate generates `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`.
- Unknown Hosts never reach an upstream.
- Upstream credentials, fragments, dangerous schemes and arbitrary request URLs are rejected.

## Persistence strategy

SQLite is used for configuration, bans, security events and retained logs. High-frequency request logging is queued in a bounded in-memory channel and flushed in batches by one writer thread. Request handling never performs a synchronous SQLite write. Ordinary request logs may be dropped when the queue is full; security and ban events use a separate blocking queue.
