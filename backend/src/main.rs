#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod admin;
mod config;
mod gateway;
mod http;
mod license;
mod nginx;
mod nginx_bridge;
mod proxy;
mod security;
mod storage;
#[cfg(test)]
mod tests;
mod tray;
mod updater;
mod verification;

use admin::{
    admin_activate_license, admin_clear_interceptions, admin_clear_requests, admin_dashboard,
    admin_delete_ban, admin_delete_site, admin_delete_whitelist, admin_gateway_start,
    admin_gateway_status, admin_gateway_stop, admin_interception_detail, admin_list_bans,
    admin_list_challenges, admin_list_interceptions, admin_list_requests, admin_list_sites,
    admin_list_whitelist, admin_page, admin_reload_config, admin_request_detail, admin_save_ban,
    admin_save_nginx, admin_save_site, admin_save_whitelist, admin_system, admin_toggle_site,
    admin_update_apply, admin_update_check, admin_update_progress,
};
use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, State},
    response::Response,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use config::*;
pub(crate) use config::{load_config, normalize_host, resolve_upstream_ip, validate_upstream};
use gateway::GatewayController;
pub(crate) use http::{
    cookie_from_request, is_api_request, is_static_asset_path, json_response,
    rate_limited_response, response_with,
};
use hyper::{header, Request, StatusCode};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use ipnet::IpNet;
use proxy::{header_bytes, https_redirect_response, proxy_request};
use security::{BanEntry, SecurityState, WhitelistRule};
use storage::{ManagedSite, ManagedWhitelist, RequestLog, SecurityEvent, Storage};
use tokio::{net::TcpListener, sync::mpsc};
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use verification::{
    handle_verification, is_verification_path, verification_redirect, verify_cookie,
    VerificationState,
};

const DEFAULT_CONFIG: &str = "config.toml";
const LOG_DIRECTORY: &str = "logs";
const LOG_FILE: &str = "bot-gate.log";
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
pub(crate) const NGINX_SETTINGS_KEY: &str = "nginx_config";
pub(crate) const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

fn startup_log_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(LOG_DIRECTORY)
        .join(LOG_FILE)
}

fn startup_error_message(error: &anyhow::Error, log_path: &Path) -> String {
    format!("{error:#}\n\n日志文件：{}", log_path.display())
}

fn init_logging(log_path: &Path) -> Result<()> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {}", parent.display()))?;
    }
    rotate_log(log_path)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("failed to open log file {}", log_path.display()))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(file)
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize file logging: {error}"))?;
    Ok(())
}

fn rotate_log(log_path: &Path) -> Result<()> {
    let Ok(metadata) = fs::metadata(log_path) else {
        return Ok(());
    };
    if metadata.len() < LOG_ROTATE_BYTES {
        return Ok(());
    }
    let rotated = log_path.with_extension("log.1");
    if rotated.exists() {
        fs::remove_file(&rotated)
            .with_context(|| format!("failed to remove old log {}", rotated.display()))?;
    }
    fs::rename(log_path, &rotated).with_context(|| {
        format!(
            "failed to rotate log {} to {}",
            log_path.display(),
            rotated.display()
        )
    })?;
    Ok(())
}

fn should_try_ephemeral_port(error: &std::io::Error, configured_port: u16) -> bool {
    configured_port != 0
        && matches!(
            error.kind(),
            ErrorKind::AddrInUse | ErrorKind::PermissionDenied
        )
}

pub(crate) async fn bind_listener(listen: &str, label: &str) -> Result<(TcpListener, SocketAddr)> {
    let configured: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid {label} listener address: {listen}"))?;
    match TcpListener::bind(configured).await {
        Ok(listener) => {
            let address = listener.local_addr()?;
            Ok((listener, address))
        }
        Err(error) if should_try_ephemeral_port(&error, configured.port()) => {
            let fallback = SocketAddr::new(configured.ip(), 0);
            let listener = TcpListener::bind(fallback).await.with_context(|| {
                format!(
                    "failed to bind {label} listener {listen} ({error}), and automatic port selection also failed"
                )
            })?;
            let address = listener.local_addr()?;
            warn!(
                configured = %configured,
                actual = %address,
                reason = %error,
                "configured listener is unavailable; using an automatic port"
            );
            Ok((listener, address))
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to bind {label} listener {listen}"))
        }
    }
}

fn default_config_path() -> PathBuf {
    let mut candidates = Vec::new();
    #[cfg(target_os = "macos")]
    if let Some(path) = macos_user_config_path() {
        candidates.push(path);
    }
    if let Ok(executable) = env::current_exe() {
        if let Some(directory) = executable.parent() {
            let mut current = Some(directory);
            for _ in 0..5 {
                if let Some(path) = current {
                    candidates.push(path.join(DEFAULT_CONFIG));
                    candidates.push(path.join("backend").join(DEFAULT_CONFIG));
                    current = path.parent();
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(path) = macos_resource_dir().map(|dir| dir.join(DEFAULT_CONFIG)) {
        candidates.push(path);
    }
    candidates.extend([
        PathBuf::from(DEFAULT_CONFIG),
        PathBuf::from("backend").join(DEFAULT_CONFIG),
    ]);
    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(DEFAULT_CONFIG)
}

#[cfg(target_os = "macos")]
fn macos_resource_dir() -> Option<PathBuf> {
    env::current_exe()
        .ok()?
        .parent()?
        .parent()
        .map(|contents| contents.join("Resources"))
}

#[cfg(target_os = "macos")]
fn macos_user_config_path() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support/BotGate/config.toml"))
}

fn prepare_config_path(config_path: PathBuf) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    if let (Some(resource_dir), Some(user_path)) = (macos_resource_dir(), macos_user_config_path())
    {
        if config_path.starts_with(&resource_dir) {
            if !user_path.exists() {
                if let Some(parent) = user_path.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create config directory {}", parent.display())
                    })?;
                }
                std::fs::copy(&config_path, &user_path).with_context(|| {
                    format!(
                        "failed to copy bundled config {} to {}",
                        config_path.display(),
                        user_path.display()
                    )
                })?;
            }
            return Ok(user_path);
        }
    }
    Ok(config_path)
}

pub(crate) struct AppState {
    sites: RwLock<HashMap<String, SiteConfig>>,
    client: Client<HttpConnector, Body>,
    frontend_dist: PathBuf,
    request_timeout: Duration,
    max_header_bytes: usize,
    verification: Arc<VerificationState>,
    security: Arc<SecurityState>,
    storage: Arc<Storage>,
    upstream_policy: UpstreamPolicy,
    update: UpdateConfig,
    license: LicenseConfig,
    https_redirect_port: Option<u16>,
}

#[derive(Clone, Copy)]
pub(crate) struct RequestScheme(pub(crate) &'static str);

struct AdminState {
    storage: Arc<Storage>,
    public_state: Arc<AppState>,
    config_path: PathBuf,
    tls_config: Option<RustlsConfig>,
    gateway: Arc<GatewayController>,
    update_progress: updater::UpdateProgressState,
    nginx: Arc<RwLock<NginxConfig>>,
    gate_listen: String,
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn effective_remote(remote: SocketAddr, request: &Request<Body>) -> SocketAddr {
    if !remote.ip().is_loopback() {
        return remote;
    }
    let Some(value) = request
        .headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
    else {
        return remote;
    };
    value
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, remote.port()))
        .unwrap_or(remote)
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
fn should_record_request_log(path: &str, status: StatusCode, blocked: bool) -> bool {
    !is_static_asset_path(path) || blocked || status.as_u16() >= 400
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
    if !should_record_request_log(path, status, blocked) {
        return;
    }
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

pub(crate) async fn handle_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    scheme: Option<Extension<RequestScheme>>,
    request: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let remote = effective_remote(remote, &request);
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
        Some(site) => site,
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
    if state.license.enabled && license::status(&state.license).status != "active" {
        let response = response_with(
            StatusCode::PAYMENT_REQUIRED,
            "text/plain; charset=utf-8",
            "a valid Bot Gate license is required",
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
            Some("license_required"),
            user_agent.as_deref(),
            0,
        );
        return response;
    }
    let cookie_verified = state.verification.config.enabled
        && cookie_from_request(&request, &state.verification.config.cookie_name).is_some_and(
            |value| {
                verify_cookie(
                    &value,
                    &state.verification.config,
                    &state.verification.secret,
                    &host,
                    remote.ip(),
                    unix_now(),
                )
            },
        );
    let whitelist = state.security.whitelist_rule(remote.ip());
    let whitelisted = whitelist.is_some();
    // A successful, valid browser verification is the admission decision for
    // this request. Scanner state is only enforced for unverified traffic so
    // a normal application's route and module burst cannot revoke a session.
    let protection_enabled = site.enabled;
    if protection_enabled && !cookie_verified {
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
    }
    // A valid short-lived signed cookie marks a browser session. Do not let
    // the normal page/module burst trip the scanner rate limiter; unverified
    // traffic remains rate-limited before it can reach the upstream.
    if protection_enabled
        && !cookie_verified
        && !state
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
    if protection_enabled
        && state.verification.config.enabled
        && is_verification_path(&state.verification, &path)
    {
        return handle_verification(state, remote, &host, request).await;
    }
    let mut risk = if !protection_enabled || whitelisted || cookie_verified {
        0
    } else {
        state
            .security
            .observe_request(remote.ip(), &host, &method, &path)
    };
    if protection_enabled
        && !cookie_verified
        && risk >= state.security.config.scanner_detection.risk_ban_threshold
    {
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
    if protection_enabled
        && !cookie_verified
        && risk >= state.security.config.scanner_detection.risk_limit_threshold
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

    if protection_enabled && state.verification.config.enabled {
        // Whitelists can affect rate/risk policy, but never bypass signed browser verification.
        let verified = cookie_verified;
        let static_asset = is_static_asset_path(&path);
        let force_challenge = !verified
            && risk
                >= state
                    .security
                    .config
                    .scanner_detection
                    .risk_challenge_threshold;
        if !verified || force_challenge {
            let response = if static_asset {
                response_with(
                    StatusCode::FORBIDDEN,
                    "text/plain; charset=utf-8",
                    "browser verification required",
                )
            } else if is_api_request(&request)
                || method != hyper::Method::GET && method != hyper::Method::HEAD
            {
                json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({"code": 403, "message": "browser verification required"}),
                )
            } else {
                verification_redirect(&state, remote.ip(), &host, &request)
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

    if site.mode == "nginx" {
        return response_with(
            StatusCode::CONFLICT,
            "text/plain; charset=utf-8",
            "nginx inline site must be reached through Nginx",
        );
    }

    tracing::trace!(site = %site.host, policy = %site.policy, "proxying request");

    match proxy_request(&state, request, &site, remote, request_scheme).await {
        Ok(response) => {
            if protection_enabled && !whitelisted && !cookie_verified {
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

fn effective_nginx_config(storage: &Storage, fallback: &NginxConfig) -> Result<NginxConfig> {
    if !storage.management_enabled() {
        return Ok(fallback.clone());
    }
    let Some(raw) = storage.get_setting(NGINX_SETTINGS_KEY)? else {
        return Ok(fallback.clone());
    };
    let persisted: NginxConfig =
        serde_json::from_str(&raw).context("failed to parse persisted Nginx settings")?;
    validate_nginx_config(&persisted)?;
    Ok(persisted)
}

fn build_state(config: &Config, frontend_dist: PathBuf) -> Result<Arc<AppState>> {
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
                mode: site.mode.clone(),
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
                mode: site.mode,
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
    let mut update = config.update.clone();
    if update.release_url.trim().is_empty() {
        update.enabled = true;
        update.release_url = DEFAULT_RELEASE_URL.to_string();
    }
    Ok(Arc::new(AppState {
        sites: RwLock::new(sites),
        client,
        frontend_dist,
        request_timeout: Duration::from_secs(config.server.request_timeout_secs),
        max_header_bytes: config.server.max_header_bytes,
        verification: Arc::new(VerificationState {
            config: config.verification.clone(),
            secret,
            challenges: Mutex::new(HashMap::new()),
            redirects: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
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
        update,
        license: config.license.clone(),
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

fn frontend_dist_path(config_path: &Path) -> PathBuf {
    if let Some(path) = env::var_os("BOT_GATE_FRONTEND_DIST").map(PathBuf::from) {
        if path.join("admin.html").exists() && path.join("challenge.html").exists() {
            return path;
        }
    }
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let mut candidates = vec![
        config_dir.join("frontend/dist"),
        config_dir.join("frontend\\dist"),
        config_dir.join("../frontend/dist"),
    ];
    #[cfg(target_os = "macos")]
    if let Some(resource_dir) = macos_resource_dir() {
        candidates.insert(0, resource_dir.join("frontend/dist"));
    }
    candidates
        .into_iter()
        .find(|path| path.join("admin.html").exists() && path.join("challenge.html").exists())
        .unwrap_or_else(|| config_dir.join("frontend/dist"))
}

#[tokio::main]
async fn main() {
    let (config_path, _) = startup_options();
    let log_path = startup_log_path(&config_path);
    if let Err(error) = run().await {
        report_startup_error(&error, &log_path);
    }
}

async fn run() -> Result<()> {
    let (config_path, headless) = startup_options();
    let log_path = startup_log_path(&config_path);
    init_logging(&log_path)?;
    info!(
        version = APP_VERSION,
        config = %config_path.display(),
        headless,
        log = %log_path.display(),
        "starting Bot Gate"
    );
    let config_path = prepare_config_path(config_path)?;
    info!(config = %config_path.display(), "loading configuration");
    let mut config = load_config(&config_path)
        .with_context(|| format!("failed to load configuration {}", config_path.display()))?;
    if let Ok(listen) = env::var("BOT_GATE_ADMIN_LISTEN") {
        info!(listen = %listen, "overriding admin listener from environment");
        config.admin.listen = listen;
    }
    let frontend_dist = frontend_dist_path(&config_path);
    info!(frontend = %frontend_dist.display(), "loading runtime state");
    let state = build_state(&config, frontend_dist.clone()).with_context(|| {
        format!(
            "failed to initialize runtime state from {}",
            config_path.display()
        )
    })?;
    let tls_config = if config.tls.enabled {
        info!(
            cert = %config.tls.cert_file,
            key = %config.tls.key_file,
            "loading TLS configuration"
        );
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
    let body_limit = usize::try_from(config.server.max_body_size)
        .context("server.max_body_size does not fit in usize")?;
    let gateway = GatewayController::new(
        state.clone(),
        config.server.listen.clone(),
        config.tls.enabled.then(|| config.tls.listen.clone()),
        tls_config.clone(),
        body_limit,
    );
    info!(
        listen = %config.server.listen,
        tls = config.tls.enabled,
        "starting Bot Gate front proxy"
    );
    let license = license::status(&state.license);
    if !state.license.enabled || license.status == "active" {
        gateway.start().await.with_context(|| {
            format!(
                "failed to start the Bot Gate front proxy on {}; see {}",
                config.server.listen,
                log_path.display()
            )
        })?;
        info!(status = ?gateway.status().await, "Bot Gate front proxy started");
    } else {
        warn!(
            status = license.status,
            "Bot Gate front proxy is waiting for a valid license"
        );
    }
    let nginx_config = effective_nginx_config(&state.storage, &config.nginx)?;
    let admin_state = if config.admin.enabled {
        Some(Arc::new(AdminState {
            storage: state.storage.clone(),
            public_state: state.clone(),
            config_path: config_path.clone(),
            tls_config: tls_config.clone(),
            gateway: gateway.clone(),
            update_progress: Arc::new(Mutex::new(updater::UpdateProgress::default())),
            nginx: Arc::new(RwLock::new(nginx_config)),
            gate_listen: config.server.listen.clone(),
        }))
    } else {
        None
    };
    if let Some(admin_state) = admin_state {
        let (admin_listener, admin_address) = bind_listener(&config.admin.listen, "admin").await?;
        let admin_url = format!("http://{admin_address}");
        info!(address = %admin_address, "starting Bot Gate management API");
        let (tray_handle, tray_events, tray_enabled) = if headless {
            let (_, events) = mpsc::unbounded_channel();
            (None, events, false)
        } else {
            match tray::start(admin_url.clone()) {
                Ok((handle, events)) => (Some(handle), events, true),
                Err(error) => {
                    warn!(error = %error, "system tray unavailable; management API remains available");
                    let (_, events) = mpsc::unbounded_channel();
                    (None, events, false)
                }
            }
        };
        let admin_app = Router::new()
            .route("/", get(admin_page))
            .nest_service(
                "/_bot_gate/assets",
                ServeDir::new(state.frontend_dist.join("assets")),
            )
            .route("/api/dashboard", get(admin_dashboard))
            .route("/api/system", get(admin_system))
            .route("/api/nginx/config", post(admin_save_nginx))
            .route("/api/update/check", get(admin_update_check))
            .route("/api/update/apply", post(admin_update_apply))
            .route("/api/update/progress", get(admin_update_progress))
            .route("/api/gateway/status", get(admin_gateway_status))
            .route("/api/gateway/start", post(admin_gateway_start))
            .route("/api/gateway/stop", post(admin_gateway_stop))
            .route("/api/license/activate", post(admin_activate_license))
            .route("/api/requests", get(admin_list_requests))
            .route("/api/requests/clear", post(admin_clear_requests))
            .route("/api/requests/{id}", get(admin_request_detail))
            .route("/api/interceptions", get(admin_list_interceptions))
            .route("/api/interceptions/clear", post(admin_clear_interceptions))
            .route("/api/interceptions/{id}", get(admin_interception_detail))
            .route("/api/challenges", get(admin_list_challenges))
            .route("/api/sites", get(admin_list_sites).post(admin_save_site))
            .route("/api/sites/toggle", post(admin_toggle_site))
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
        #[allow(unused_mut, unused_variables)]
        let mut admin_task = tokio::spawn(async move {
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
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            if !headless {
                bail!(
                    "Windows 和 macOS 请从 Bot Gate 桌面客户端启动；后端子进程需要 --headless 参数"
                );
            }
            let _tray_handle = tray_handle;
            let _tray_events = tray_events;
            let _tray_enabled = tray_enabled;
            shutdown_signal().await;
            admin_task.abort();
            gateway.stop().await;
            return Ok(());
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        if let Err(error) = tray::open_admin(&admin_url) {
            warn!(error = %error, "failed to open management dashboard automatically");
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let _tray_handle = tray_handle;
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let mut tray_events = tray_events;
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let shutdown = shutdown_signal();
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        tokio::pin!(shutdown);
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        loop {
            tokio::select! {
                result = &mut admin_task => {
                    if let Err(error) = result {
                        error!(error = %error, "admin task failed");
                    }
                    break;
                }
                _ = &mut shutdown => {
                    admin_task.abort();
                    break;
                }
                command = tray_events.recv(), if tray_enabled => {
                    match command {
                        Some(tray::TrayCommand::OpenAdmin) => {
                            if let Err(error) = tray::open_admin(&admin_url) {
                                warn!(error = %error, "failed to open management dashboard from tray");
                            }
                        }
                        Some(tray::TrayCommand::Exit) | None => {
                            admin_task.abort();
                            break;
                        }
                    }
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        gateway.stop().await;
    } else {
        warn!("admin listener is disabled; gateway must be started from the admin listener");
        shutdown_signal().await;
    }
    Ok(())
}

fn startup_options() -> (PathBuf, bool) {
    let mut config_path = None;
    let mut headless = false;
    for argument in env::args_os().skip(1) {
        if argument == "--headless" {
            headless = true;
        } else if config_path.is_none() {
            config_path = Some(PathBuf::from(argument));
        }
    }
    (config_path.unwrap_or_else(default_config_path), headless)
}

fn report_startup_error(error: &anyhow::Error, log_path: &Path) {
    let message = startup_error_message(error, log_path);
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        use std::io::Write;

        let _ = writeln!(file, "startup failed: {message}");
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

        let message: Vec<u16> = std::ffi::OsStr::new(&message)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let title: Vec<u16> = std::ffi::OsStr::new("Bot Gate Startup Failed")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            MessageBoxW(0, message.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }
    #[cfg(not(target_os = "windows"))]
    eprintln!("Bot Gate startup failed: {message}");
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
