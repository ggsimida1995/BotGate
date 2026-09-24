# Bot Gate Architecture

## Scope

Bot Gate is a front reverse proxy with a Rust backend and a separately built React frontend. It is the public entry point, while any internal HTTP web server (Vite, Nginx, Node, or another source service) serves HTML, static files, APIs and WebSockets. Bot Gate adds browser verification, request policy enforcement, persistence and a loopback-only management plane. The release process produces one Rust executable plus the `frontend/dist` assets it serves.

## Runtime flow

```text
Public HTTP/TLS listener (Bot Gate)
  -> request limits and Host validation
  -> ban / whitelist decision
  -> rate limit and scanner risk rejection
  -> signed-cookie verification / Browser Challenge
  -> reverse proxy to internal HTTP source
  -> asynchronous request/security logging
```

When verification is enabled, a request without a valid site-bound HMAC cookie is stopped at the verification step. It is redirected to the Challenge for HTML navigation or returned as `403` for API/non-GET requests; it never reaches an upstream. Whitelist entries can change rate/risk policy only and cannot bypass this gate.

The admin listener is separate and defaults to `127.0.0.1:9090`. The desktop starts `GatewayController` on a loopback-only ephemeral port by default; Nginx inline mode uses the actual bound port, so the gateway never claims the source web server's business port. Standalone proxy deployments can set an explicit public listener. Gateway start checks the configured license first, so an enabled license that is missing, invalid or expired prevents any public listener from binding.

## Trust boundaries

- The public listener treats LAN clients as untrusted.
- The client-provided User-Agent, Referer, Origin and forwarded headers are untrusted.
- The upstream target is configuration data, never request data.
- Source web-server listeners must be loopback/internal-only; exposing them publicly bypasses Bot Gate.
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

The source layout mirrors these boundaries: `backend/src/config.rs`, `backend/src/security.rs`, `backend/src/http.rs`, `backend/src/proxy.rs`, `backend/src/verification.rs`, `backend/src/storage.rs`, and `backend/src/admin.rs` keep configuration, enforcement, HTTP helpers, transport, challenge, persistence, and management code out of the request entry point. `backend/src/main.rs` focuses on wiring, request orchestration and lifecycle. The React + Ant Design management and challenge pages live under `frontend/src/` and build into `frontend/dist/`; Windows and macOS wrap that dashboard in the Tauri 2 client under `desktop/`.

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

## Nginx 内联防护

`mode = "nginx"` 的站点不经过 Bot Gate 转发源站。Bot Gate 自动在匹配 `server_name` 的 Nginx vhost 中插入一个受控 include；该 include 使用 `auth_request` 请求本机 Bot Gate。验证通过后 Nginx 继续处理原有静态文件、PHP、`/api/` 和 WebSocket 配置。验证页和提交路径位于 `/_bot_gate/`，由 Nginx 单独代理给 Bot Gate 并绕过 auth 子请求。

这和 `mode = "proxy"` 不同：proxy 模式仍需要一个不可公网绕过的 `target`。Nginx 内联模式的 `target` 必须为空。
