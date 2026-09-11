# Bot Gate Architecture

## Scope

Bot Gate is a single-binary local reverse proxy. It sits in front of one or more local HTTP applications and progressively adds browser verification, request policy enforcement, persistence and a loopback-only management plane.

## Runtime flow

```text
Public HTTP/TLS listener
  -> request limits and Host validation
  -> ban / whitelist decision
  -> rate limit
  -> signed-cookie verification
  -> scanner risk decision
  -> reverse proxy
  -> asynchronous request/security logging
```

The admin listener is separate and defaults to `127.0.0.1`.

## Trust boundaries

- The public listener treats LAN clients as untrusted.
- The client-provided User-Agent, Referer, Origin and forwarded headers are untrusted.
- The upstream target is configuration data, never request data.
- The admin listener is a local trust boundary protected by Argon2id passwords and signed sessions.

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

The source layout mirrors these boundaries: `src/config.rs`, `src/security.rs`, `src/proxy.rs`, `src/storage.rs`, and `src/admin.rs` keep configuration, enforcement, transport, persistence, and management code out of the request entry point.

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

SQLite is used for configuration, bans, sessions, security events and retained logs. High-frequency request logging is queued in a bounded in-memory channel and flushed in batches by one writer thread. Request handling never performs a synchronous SQLite write. Ordinary request logs may be dropped when the queue is full; security and ban events use a separate blocking queue.
