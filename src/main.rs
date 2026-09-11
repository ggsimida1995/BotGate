use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod admin;
mod config;
mod proxy;
mod security;
mod storage;
mod verification;

use admin::{
    admin_dashboard, admin_delete_ban, admin_delete_site, admin_delete_whitelist, admin_list_bans,
    admin_list_sites, admin_list_whitelist, admin_login, admin_logout, admin_page,
    admin_reload_config, admin_save_ban, admin_save_site, admin_save_whitelist, admin_setup,
    admin_status, load_admin_password_hash,
};
use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, State},
    response::Response,
    routing::{get, post},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle as TlsHandle};
use config::*;
pub(crate) use config::{
    load_config, normalize_host, resolve_upstream_ip, validate_upstream,
};
use hyper::{header, Request, StatusCode};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use ipnet::IpNet;
use proxy::{header_bytes, https_redirect_response, proxy_request};
use security::{BanEntry, SecurityState, WhitelistRule};
use serde::Deserialize;
use storage::{ManagedSite, ManagedWhitelist, RequestLog, SecurityEvent, Storage};
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info, warn};
#[cfg(test)]
use url::Url;
pub(crate) use verification::{constant_time_eq, hmac_sha256, random_token};
use verification::{handle_verification, verification_redirect, verify_cookie, VerificationState};

const DEFAULT_CONFIG: &str = "config.toml";

struct AppState {
    sites: RwLock<HashMap<String, SiteConfig>>,
    client: Client<HttpConnector, Body>,
    request_timeout: Duration,
    max_header_bytes: usize,
    verification: Arc<VerificationState>,
    security: Arc<SecurityState>,
    storage: Arc<Storage>,
    upstream_policy: UpstreamPolicy,
    https_redirect_port: Option<u16>,
}

#[derive(Clone, Copy)]
struct RequestScheme(&'static str);

#[derive(Debug, Clone)]
struct AdminSession {
    expires_at: u64,
}

struct AdminState {
    config: AdminConfig,
    secret: Vec<u8>,
    password_hash: Mutex<Option<String>>,
    sessions: Mutex<HashMap<String, AdminSession>>,
    storage: Arc<Storage>,
    public_state: Arc<AppState>,
    config_path: PathBuf,
    loaded_config: Mutex<Config>,
    tls_config: Option<RustlsConfig>,
}

#[derive(Debug, Deserialize)]
struct AdminPasswordInput {
    password: String,
}

#[derive(Debug, Deserialize)]
struct AdminSiteInput {
    host: String,
    target: String,
    #[serde(default = "default_policy")]
    policy: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct AdminHostInput {
    host: String,
}

#[derive(Debug, Deserialize)]
struct AdminBanInput {
    ip: String,
    reason: String,
    duration_secs: u64,
}

#[derive(Debug, Deserialize)]
struct AdminIpInput {
    ip: String,
}

#[derive(Debug, Deserialize)]
struct AdminWhitelistInput {
    value: String,
    #[serde(default = "default_true")]
    skip_challenge: bool,
    #[serde(default)]
    skip_rate_limit: bool,
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminIdInput {
    id: i64,
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cookie_from_request(request: &Request<Body>, name: &str) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (key, value) = cookie.trim().split_once('=')?;
                (key == name).then(|| value.to_string())
            })
        })
}

pub(crate) fn is_api_request(request: &Request<Body>) -> bool {
    let path = request.uri().path();
    path == "/api"
        || path.starts_with("/api/")
        || request
            .headers()
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("application/json"))
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("application/json"))
}

fn response_with(
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("static response headers are valid")
}

pub(crate) fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body.to_string()))
        .expect("static JSON response headers are valid")
}

fn rate_limited_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::RETRY_AFTER, "1")
        .body(Body::from(
            serde_json::json!({"code": 429, "message": "rate limit exceeded"}).to_string(),
        ))
        .expect("rate limit response headers are valid")
}

fn note_challenge_failure(state: &AppState, ip: IpAddr, site: &str) {
    let risk = state.security.add_risk(ip, site, 30);
    state.storage.record_security(SecurityEvent {
        timestamp: unix_now(),
        remote_ip: ip.to_string(),
        host: site.to_string(),
        path: "/__bot_verify/submit".to_string(),
        event_type: "challenge_failure".to_string(),
        risk_score: risk,
        action: "challenge_rejected".to_string(),
        details_redacted: None,
    });
    if risk >= state.security.config.scanner_detection.risk_ban_threshold {
        state.security.ban(ip, format!("risk score {risk}"));
    }
}

#[allow(clippy::too_many_arguments)]
fn record_request_log(
    state: &AppState,
    started: Instant,
    remote: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    status: StatusCode,
    verified: bool,
    blocked: bool,
    reason: Option<&str>,
    user_agent: Option<&str>,
    risk_score: u32,
) {
    state.storage.record_request(RequestLog {
        timestamp: unix_now(),
        remote_ip: remote.ip().to_string(),
        host: host.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        status: status.as_u16(),
        verified,
        blocked,
        reason: reason.map(str::to_string),
        user_agent: user_agent.map(str::to_string),
        latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        risk_score,
    });
}

async fn handle_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    scheme: Option<Extension<RequestScheme>>,
    request: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let request_scheme = scheme.map_or("http", |scheme| scheme.0 .0);
    if header_bytes(&request) > state.max_header_bytes {
        return response_with(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "text/plain; charset=utf-8",
            "request headers too large",
        );
    }
    if request.headers().get_all(header::HOST).iter().count() != 1 {
        return response_with(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            "exactly one host header is required",
        );
    }
    let host = match request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => match normalize_host(value) {
            Ok(host) => host,
            Err(_) => {
                return response_with(
                    StatusCode::BAD_REQUEST,
                    "text/plain; charset=utf-8",
                    "invalid host",
                )
            }
        },
        None => {
            return response_with(
                StatusCode::BAD_REQUEST,
                "text/plain; charset=utf-8",
                "host header required",
            )
        }
    };
    let site = match state
        .sites
        .read()
        .ok()
        .and_then(|sites| sites.get(&host).cloned())
    {
        Some(site) if site.enabled => site,
        _ => {
            return response_with(
                StatusCode::MISDIRECTED_REQUEST,
                "text/plain; charset=utf-8",
                "unknown host",
            )
        }
    };
    if request_scheme == "http" {
        if let Some(port) = state.https_redirect_port {
            if let Some(response) = https_redirect_response(&request, port) {
                return response;
            }
        }
    }

    let path = request.uri().path().chars().take(256).collect::<String>();
    let method = request.method().clone();
    let method_name = method.to_string();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(256).collect::<String>());
    let whitelist = state.security.whitelist_rule(remote.ip());
    let whitelisted = whitelist.is_some();
    if let Some(reason) = state.security.active_ban(remote.ip()) {
        warn!(ip = %remote.ip(), %reason, "request rejected for active ban");
        let response = response_with(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            "temporarily blocked",
        );
        record_request_log(
            &state,
            started,
            remote,
            &host,
            &method_name,
            &path,
            response.status(),
            false,
            true,
            Some("active_ban"),
            user_agent.as_deref(),
            0,
        );
        return response;
    }
    if !state
        .security
        .allow_rate(remote.ip(), &host, &path, whitelist.as_ref())
    {
        let response = rate_limited_response();
        record_request_log(
            &state,
            started,
            remote,
            &host,
            &method_name,
            &path,
            response.status(),
            false,
            true,
            Some("rate_limit"),
            user_agent.as_deref(),
            0,
        );
        return response;
    }
    let mut risk = if whitelisted {
        0
    } else {
        state
            .security
            .observe_request(remote.ip(), &host, &method, &path)
    };
    if risk >= state.security.config.scanner_detection.risk_ban_threshold {
        state
            .security
            .ban(remote.ip(), format!("risk score {risk}"));
        let response = response_with(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            "temporarily blocked",
        );
        record_request_log(
            &state,
            started,
            remote,
            &host,
            &method_name,
            &path,
            response.status(),
            false,
            true,
            Some("risk_ban"),
            user_agent.as_deref(),
            risk,
        );
        return response;
    }
    if risk >= state.security.config.scanner_detection.risk_limit_threshold
        && (risk
            < state
                .security
                .config
                .scanner_detection
                .risk_challenge_threshold
            || !state.verification.config.enabled)
    {
        let response = rate_limited_response();
        record_request_log(
            &state,
            started,
            remote,
            &host,
            &method_name,
            &path,
            response.status(),
            false,
            true,
            Some("risk_limit"),
            user_agent.as_deref(),
            risk,
        );
        return response;
    }

    if state.verification.config.enabled && path.starts_with("/__bot_verify") {
        return handle_verification(state, remote, &host, request).await;
    }

    if state.verification.config.enabled {
        let cookie_verified = cookie_from_request(&request, &state.verification.config.cookie_name)
            .is_some_and(|value| {
                verify_cookie(
                    &value,
                    &state.verification.config,
                    &state.verification.secret,
                    &host,
                    remote.ip(),
                    unix_now(),
                )
            });
        let verified =
            cookie_verified || whitelist.as_ref().is_some_and(|rule| rule.skip_challenge);
        let force_challenge = risk
            >= state
                .security
                .config
                .scanner_detection
                .risk_challenge_threshold;
        if !verified || force_challenge {
            let response = if is_api_request(&request)
                || method != hyper::Method::GET && method != hyper::Method::HEAD
            {
                json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({"code": 403, "message": "browser verification required"}),
                )
            } else {
                verification_redirect(&request)
            };
            record_request_log(
                &state,
                started,
                remote,
                &host,
                &method_name,
                &path,
                response.status(),
                verified,
                true,
                Some("verification_required"),
                user_agent.as_deref(),
                risk,
            );
            return response;
        }
    }

    tracing::trace!(site = %site.host, policy = %site.policy, "proxying request");

    match proxy_request(&state, request, &site, remote, request_scheme).await {
        Ok(response) => {
            if !whitelisted {
                risk =
                    state
                        .security
                        .observe_response(remote.ip(), &host, &path, response.status());
                if risk >= state.security.config.scanner_detection.risk_ban_threshold {
                    state
                        .security
                        .ban(remote.ip(), format!("risk score {risk}"));
                }
            }
            record_request_log(
                &state,
                started,
                remote,
                &host,
                &method_name,
                &path,
                response.status(),
                true,
                false,
                None,
                user_agent.as_deref(),
                risk,
            );
            response
        }
        Err(error) => {
            warn!(host = %host, error = %error, "upstream request failed");
            record_request_log(
                &state,
                started,
                remote,
                &host,
                &method_name,
                &path,
                StatusCode::BAD_GATEWAY,
                true,
                false,
                Some("upstream_unavailable"),
                user_agent.as_deref(),
                risk,
            );
            response_with(
                StatusCode::BAD_GATEWAY,
                "text/plain; charset=utf-8",
                "upstream unavailable",
            )
        }
    }
}

fn build_state(config: &Config) -> Result<Arc<AppState>> {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let secret = verification::load_or_create_secret(Path::new(&config.verification.secret_file))?;
    let opened_storage = Storage::open(&config.storage)?;
    let storage = Arc::new(opened_storage.storage);
    let configured_sites = config
        .sites
        .iter()
        .map(|site| {
            Ok(ManagedSite {
                host: normalize_host(&site.host)?,
                target: site.target.clone(),
                policy: site.policy.clone(),
                enabled: site.enabled,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let configured_whitelist = config
        .security
        .whitelist
        .ips
        .iter()
        .map(|ip| ManagedWhitelist {
            id: 0,
            kind: "ip".to_string(),
            value: ip.clone(),
            skip_challenge: config.security.whitelist.skip_challenge,
            skip_rate_limit: config.security.whitelist.skip_rate_limit,
            note: None,
        })
        .chain(
            config
                .security
                .whitelist
                .networks
                .iter()
                .map(|network| ManagedWhitelist {
                    id: 0,
                    kind: "network".to_string(),
                    value: network.clone(),
                    skip_challenge: config.security.whitelist.skip_challenge,
                    skip_rate_limit: config.security.whitelist.skip_rate_limit,
                    note: None,
                }),
        )
        .collect::<Vec<_>>();
    let (managed_sites, managed_whitelist) = if storage.management_enabled() {
        storage.bootstrap_management(&configured_sites, &configured_whitelist)?;
        (storage.managed_sites()?, storage.managed_whitelist()?)
    } else {
        (configured_sites, configured_whitelist)
    };
    let mut sites = HashMap::new();
    for site in managed_sites {
        sites.insert(
            site.host.clone(),
            SiteConfig {
                host: site.host,
                target: site.target,
                policy: site.policy,
                enabled: site.enabled,
            },
        );
    }
    let whitelist = managed_whitelist
        .iter()
        .map(whitelist_rule_from_record)
        .collect::<Result<Vec<_>>>()?;
    let mut bans = HashMap::new();
    let monotonic_now = Instant::now();
    let wall_clock_now = unix_now();
    for ban in opened_storage.active_bans {
        let remaining = ban.expires_at.saturating_sub(wall_clock_now);
        bans.insert(
            ban.ip,
            BanEntry {
                expires_at: monotonic_now + Duration::from_secs(remaining),
                reason: ban.reason,
            },
        );
    }
    Ok(Arc::new(AppState {
        sites: RwLock::new(sites),
        client,
        request_timeout: Duration::from_secs(config.server.request_timeout_secs),
        max_header_bytes: config.server.max_header_bytes,
        verification: Arc::new(VerificationState {
            config: config.verification.clone(),
            secret,
            challenges: Mutex::new(HashMap::new()),
        }),
        security: Arc::new(SecurityState {
            config: config.security.clone(),
            buckets: Mutex::new(HashMap::new()),
            risks: Mutex::new(HashMap::new()),
            bans: Mutex::new(bans),
            whitelist: RwLock::new(whitelist),
            storage: storage.clone(),
        }),
        storage,
        upstream_policy: config.upstream.clone(),
        https_redirect_port: if config.tls.enabled && config.tls.redirect_http {
            Some(config.tls.listen.parse::<SocketAddr>()?.port())
        } else {
            None
        },
    }))
}

fn whitelist_rule_from_record(entry: &ManagedWhitelist) -> Result<WhitelistRule> {
    let network = match entry.kind.as_str() {
        "ip" => {
            let ip = entry
                .value
                .parse::<IpAddr>()
                .with_context(|| format!("invalid whitelist IP: {}", entry.value))?;
            IpNet::from(ip)
        }
        "network" => entry
            .value
            .parse::<IpNet>()
            .with_context(|| format!("invalid whitelist network: {}", entry.value))?,
        _ => bail!("invalid whitelist kind"),
    };
    Ok(WhitelistRule {
        network,
        skip_challenge: entry.skip_challenge,
        skip_rate_limit: entry.skip_rate_limit,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let config_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let config = load_config(&config_path)?;
    let state = build_state(&config)?;
    let tls_config = if config.tls.enabled {
        Some(
            RustlsConfig::from_pem_file(&config.tls.cert_file, &config.tls.key_file)
                .await
                .with_context(|| {
                    format!(
                        "failed to load TLS certificate {} and key {}",
                        config.tls.cert_file, config.tls.key_file
                    )
                })?,
        )
    } else {
        None
    };
    let admin_state = if config.admin.enabled {
        Some(Arc::new(AdminState {
            config: config.admin.clone(),
            secret: state.verification.secret.clone(),
            password_hash: Mutex::new(load_admin_password_hash(Path::new(
                &config.admin.password_file,
            ))?),
            sessions: Mutex::new(HashMap::new()),
            storage: state.storage.clone(),
            public_state: state.clone(),
            config_path: config_path.clone(),
            loaded_config: Mutex::new(config.clone()),
            tls_config: tls_config.clone(),
        }))
    } else {
        None
    };
    let listener = TcpListener::bind(&config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    let address = listener.local_addr()?;
    info!(%address, sites = state.sites.read().map(|sites| sites.len()).unwrap_or(0), "bot-gate phase 5 listening");
    let body_limit = usize::try_from(config.server.max_body_size)
        .context("server.max_body_size does not fit in usize")?;
    let app = Router::new()
        .fallback(handle_request)
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(Extension(RequestScheme("http")))
        .with_state(state.clone());
    if let Some(tls_config) = tls_config {
        let tls_addr: SocketAddr = config
            .tls
            .listen
            .parse()
            .with_context(|| format!("invalid tls.listen: {}", config.tls.listen))?;
        let tls_app = Router::new()
            .fallback(handle_request)
            .layer(RequestBodyLimitLayer::new(body_limit))
            .layer(Extension(RequestScheme("https")))
            .with_state(state.clone());
        let tls_handle = TlsHandle::new();
        let tls_shutdown_handle = tls_handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tls_shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });
        tokio::spawn(async move {
            if let Err(error) = axum_server::bind_rustls(tls_addr, tls_config)
                .handle(tls_handle.clone())
                .serve(tls_app.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                error!(error = %error, "TLS server failed");
            }
        });
    }
    if let Some(admin_state) = admin_state {
        let admin_listener = TcpListener::bind(&config.admin.listen)
            .await
            .with_context(|| format!("failed to bind admin listener {}", config.admin.listen))?;
        let admin_app = Router::new()
            .route("/", get(admin_page))
            .route("/api/status", get(admin_status))
            .route("/api/setup", post(admin_setup))
            .route("/api/login", post(admin_login))
            .route("/api/logout", post(admin_logout))
            .route("/api/dashboard", get(admin_dashboard))
            .route("/api/sites", get(admin_list_sites).post(admin_save_site))
            .route("/api/sites/delete", post(admin_delete_site))
            .route("/api/bans", get(admin_list_bans).post(admin_save_ban))
            .route("/api/bans/delete", post(admin_delete_ban))
            .route(
                "/api/whitelist",
                get(admin_list_whitelist).post(admin_save_whitelist),
            )
            .route("/api/whitelist/delete", post(admin_delete_whitelist))
            .route("/api/reload", post(admin_reload_config))
            .with_state(admin_state);
        info!(address = %admin_listener.local_addr()?, "bot-gate admin listening");
        tokio::spawn(async move {
            if let Err(error) = axum::serve(
                admin_listener,
                admin_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await
            {
                error!(error = %error, "admin server failed");
            }
        });
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server failed")?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install terminate handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    error!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_host_and_port() {
        assert_eq!(
            normalize_host("Project-A.TEST:8080").unwrap(),
            "project-a.test"
        );
        assert_eq!(normalize_host("project-a.test.").unwrap(), "project-a.test");
    }

    #[test]
    fn rejects_unsafe_upstream() {
        let policy = UpstreamPolicy::default();
        assert!(validate_upstream("file:///tmp/app", &policy).is_err());
        assert!(validate_upstream("http://192.168.1.10:9000", &policy).is_err());
        assert!(validate_upstream("http://backend.test:9000", &policy).is_err());
        let mut dns_policy = policy.clone();
        dns_policy.allow_dns = true;
        assert!(validate_upstream("http://backend.test:9000", &dns_policy).is_ok());
        assert!(validate_upstream("http://127.0.0.1:9000", &policy).is_ok());
    }

    #[tokio::test]
    async fn resolves_only_allowed_upstream_addresses() {
        let policy = UpstreamPolicy::default();
        let target = Url::parse("http://127.0.0.1:9000").unwrap();
        assert_eq!(
            resolve_upstream_ip(&target, &policy).await.unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        let target = Url::parse("http://localhost:9000").unwrap();
        assert!(resolve_upstream_ip(&target, &policy).await.is_ok());
        let target = Url::parse("http://backend.test:9000").unwrap();
        assert!(resolve_upstream_ip(&target, &policy).await.is_err());
    }

    #[test]
    fn parses_human_durations() {
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("1h").unwrap(), 3600);
        assert!(parse_duration_secs("500ms").is_err());
    }

    #[test]
    fn signed_cookie_rejects_tampering_and_wrong_site() {
        let config = VerificationConfig::default();
        let payload = verification::CookiePayload {
            version: 1,
            issued_at: 100,
            expires_at: 200,
            challenge_id: "challenge".to_string(),
            site: "project-a.test".to_string(),
            ip: Some("127.0.0.1".to_string()),
        };
        let secret = b"01234567890123456789012345678901";
        let cookie = verification::cookie_value(&payload, secret).unwrap();
        assert!(verify_cookie(
            &cookie,
            &config,
            secret,
            "project-a.test",
            "127.0.0.1".parse().unwrap(),
            150
        ));
        assert!(!verify_cookie(
            &format!("{}x", cookie),
            &config,
            secret,
            "project-a.test",
            "127.0.0.1".parse().unwrap(),
            150
        ));
        assert!(!verify_cookie(
            &cookie,
            &config,
            secret,
            "project-b.test",
            "127.0.0.1".parse().unwrap(),
            150
        ));
    }

    #[test]
    fn pow_and_return_path_are_bounded() {
        let challenge = verification::Challenge {
            id: "id".to_string(),
            nonce: "nonce".to_string(),
            site: "project-a.test".to_string(),
            remote_ip: "127.0.0.1".parse().unwrap(),
            return_path: "/".to_string(),
            issued_at: 1,
            expires_at: 2,
            signature: "signature".to_string(),
            attempts: 0,
        };
        assert!(verification::verify_pow(&challenge, 0, 0));
        assert_eq!(
            verification::valid_return_path(Some("https://evil.test")),
            "/"
        );
        assert_eq!(
            verification::valid_return_path(Some("/safe/path")),
            "/safe/path"
        );
    }

    #[test]
    fn token_bucket_enforces_burst() {
        let mut config = SecurityConfig::default();
        config.rate_limit.requests_per_second = 1.0;
        config.rate_limit.burst = 2;
        let security = SecurityState {
            config,
            buckets: Mutex::new(HashMap::new()),
            risks: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
            whitelist: RwLock::new(Vec::new()),
            storage: Arc::new(Storage::disabled()),
        };
        let ip = "127.0.0.1".parse().unwrap();
        assert!(security.allow_rate(ip, "project-a.test", "/", None));
        assert!(security.allow_rate(ip, "project-a.test", "/", None));
        assert!(!security.allow_rate(ip, "project-a.test", "/", None));
    }

    #[test]
    fn risk_score_counts_sensitive_paths_and_404s() {
        let mut config = SecurityConfig::default();
        config.scanner_detection.max_404_per_minute = 1;
        config.scanner_detection.sensitive_paths = vec!["/.env".to_string()];
        let security = SecurityState {
            config,
            buckets: Mutex::new(HashMap::new()),
            risks: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
            whitelist: RwLock::new(Vec::new()),
            storage: Arc::new(Storage::disabled()),
        };
        let ip = "127.0.0.1".parse().unwrap();
        assert_eq!(
            security.observe_request(ip, "project-a.test", &hyper::Method::GET, "/.env"),
            30
        );
        assert_eq!(
            security.observe_response(ip, "project-a.test", "/.env", StatusCode::NOT_FOUND),
            50
        );
    }

    #[test]
    fn whitelist_matches_ip_and_cidr() {
        let security = SecurityState {
            config: SecurityConfig::default(),
            buckets: Mutex::new(HashMap::new()),
            risks: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
            whitelist: RwLock::new(vec![
                WhitelistRule {
                    network: "127.0.0.1/32".parse().unwrap(),
                    skip_challenge: true,
                    skip_rate_limit: false,
                },
                WhitelistRule {
                    network: "192.168.1.0/24".parse().unwrap(),
                    skip_challenge: true,
                    skip_rate_limit: false,
                },
            ]),
            storage: Arc::new(Storage::disabled()),
        };
        assert!(security
            .whitelist_rule("127.0.0.1".parse().unwrap())
            .is_some());
        assert!(security
            .whitelist_rule("192.168.1.42".parse().unwrap())
            .is_some());
        assert!(security
            .whitelist_rule("10.0.0.1".parse().unwrap())
            .is_none());
    }
}
