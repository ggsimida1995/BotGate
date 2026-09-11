# Security Boundaries

Bot Gate is designed to block simple local-network scanners and reduce accidental exposure. It is not a WAF, a CAPTCHA service or a guarantee that a request came from a human.

## Threats addressed

- Unsigned or modified verification cookies
- Challenge replay and brute-force submission
- High-rate requests
- Large numbers of 404s or distinct paths
- Common sensitive-path probing
- Accidental public exposure of the admin UI
- Basic Host-header and hop-by-hop-header abuse
- Configured-upstream SSRF

## Explicit limitations

- A headless browser can execute JavaScript and obtain a cookie.
- A stolen cookie can be replayed until it expires.
- A compromised local process can access local files and loopback services.
- Bot Gate does not fix vulnerabilities in the protected application.

## SSRF policy

HTTP upstreams using an IP literal or `localhost` remain the default. With `upstream.allow_dns = true`, domain names are resolved on every request, every returned address is checked against the loopback/private-network policy, and the proxy connects to the checked IP while preserving the configured Host header. Unix sockets, metadata-specific deny lists and TLS upstreams remain deferred.

## Current verification behavior

The Phase 2 challenge uses a short local SHA-256 proof-of-work. It is deliberately a friction mechanism for basic scanners, not a human test. The server signs the challenge parameters and consumes a successful challenge before issuing the cookie. The cookie is HMAC-SHA256 signed, Host-only, HttpOnly and bound to the client IP when `bind_ip = true`.

Phase 3 adds in-memory token buckets, IP/CIDR whitelist matching, risk scores and expiring temporary bans. Phase 4 persists active bans and security/request logs in SQLite; rate-limit and risk counters remain bounded in memory.

## Request safety

- Header and body limits are enforced before proxying.
- Upstream requests have a timeout.
- Hop-by-hop and client-supplied forwarding headers are stripped.
- Upstream failures become 502/504 responses and do not terminate the gateway.
- HTTPS terminates with Rustls when `[tls]` is enabled. The certificate and private key must be PEM files readable only by the service account. Redirects are issued only for configured, enabled hosts.

## Sensitive logging

Request logs do not store passwords, Authorization values, complete Cookies or complete tokens. The current request path is recorded without its query string; future fields must preserve the same redaction rule.
