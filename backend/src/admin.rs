use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    response::Response,
};
use hyper::{header, Request, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};

use crate::nginx::NginxSite;
use crate::storage::{BanRecord, LogFilter};
use crate::*;

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
struct AdminSiteToggleInput {
    host: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct AdminNginxScanInput {
    config_dir: String,
    binary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminNginxToggleInput {
    id: String,
    protected: bool,
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

#[derive(Debug, Deserialize)]
struct AdminLicenseInput {
    key: String,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct AdminLogQuery {
    search: Option<String>,
    host: Option<String>,
    ip: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    blocked: Option<bool>,
    verified: Option<bool>,
    event_type: Option<String>,
    from: Option<u64>,
    to: Option<u64>,
    page: Option<u32>,
    page_size: Option<u32>,
}

impl From<AdminLogQuery> for LogFilter {
    fn from(query: AdminLogQuery) -> Self {
        Self {
            search: query.search,
            host: query.host,
            remote_ip: query.ip,
            path: query.path,
            status: query.status,
            blocked: query.blocked,
            verified: query.verified,
            event_type: query.event_type,
            from: query.from,
            to: query.to,
            page: query.page.unwrap_or(1),
            page_size: query.page_size.unwrap_or(20),
        }
    }
}

fn admin_forbidden() -> Response<Body> {
    response_with(
        StatusCode::FORBIDDEN,
        "text/plain; charset=utf-8",
        "admin is loopback-only",
    )
}

pub(crate) async fn admin_page(State(state): State<Arc<AdminState>>) -> Response<Body> {
    match tokio::fs::read(state.public_state.frontend_dist.join("admin.html")).await {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .expect("admin page headers are valid"),
        Err(error) => {
            error!(error = %error, "failed to read admin frontend");
            response_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                "admin frontend unavailable",
            )
        }
    }
}

pub(crate) async fn admin_dashboard(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let stats = match state.storage.dashboard_stats() {
        Ok(stats) => stats,
        Err(error) => {
            error!(error = %error, "failed to read dashboard stats");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"dashboard unavailable"}),
            );
        }
    };
    let active_challenges = state
        .public_state
        .verification
        .challenges
        .lock()
        .map(|challenges| challenges.len())
        .unwrap_or(0);
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "today_requests": stats.today_requests,
            "today_verified": stats.today_verified,
            "today_blocked": stats.today_blocked,
            "today_not_found": stats.today_not_found,
            "today_challenge_failures": stats.today_challenge_failures,
            "active_bans": stats.active_bans,
            "active_challenges": active_challenges,
            "sites": state.public_state.sites.read().map(|sites| sites.len()).unwrap_or(0),
        }),
    )
}

pub(crate) async fn admin_system(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let gateway = state.gateway.status().await;
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "version": APP_VERSION,
            "update_enabled": state.public_state.update.enabled,
            "release_url": state.public_state.update.release_url,
            "license": crate::license::status(&state.public_state.license),
            "gateway": gateway
        }),
    )
}

pub(crate) async fn admin_update_check(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    match crate::updater::check(&state.public_state.update, APP_VERSION).await {
        Ok(update) => json_response(StatusCode::OK, serde_json::json!({"update": update})),
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({"message": error.to_string()}),
        ),
    }
}

pub(crate) async fn admin_update_apply(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    if request
        .headers()
        .get("x-bot-gate-action")
        .and_then(|value| value.to_str().ok())
        != Some("update")
    {
        return json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({"message":"invalid update request"}),
        );
    }
    let update_progress = state.update_progress.clone();
    let active = update_progress
        .lock()
        .map(|progress| {
            matches!(
                progress.status.as_str(),
                "checking" | "downloading" | "restarting"
            )
        })
        .unwrap_or(false);
    if active {
        return json_response(
            StatusCode::CONFLICT,
            serde_json::json!({"message":"更新正在进行中"}),
        );
    }
    if let Ok(mut progress) = update_progress.lock() {
        *progress = crate::updater::UpdateProgress {
            status: "checking".to_string(),
            percent: 0,
            message: "正在检查最新版本".to_string(),
            latest_version: None,
            release_notes: None,
        };
    }
    let update_config = state.public_state.update.clone();
    tokio::spawn(async move {
        if let Err(error) =
            crate::updater::apply(&update_config, APP_VERSION, update_progress).await
        {
            error!(error = %error, "background update failed");
        }
    });
    json_response(
        StatusCode::ACCEPTED,
        serde_json::json!({"accepted":true,"message":"更新已开始下载"}),
    )
}

pub(crate) async fn admin_update_progress(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let progress = state
        .update_progress
        .lock()
        .map(|progress| progress.clone())
        .unwrap_or_default();
    json_response(StatusCode::OK, serde_json::json!({"progress": progress}))
}

pub(crate) async fn admin_gateway_status(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "gateway": state.gateway.status().await,
            "license": crate::license::status(&state.public_state.license),
        }),
    )
}

pub(crate) async fn admin_gateway_start(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let license = crate::license::status(&state.public_state.license);
    if state.public_state.license.enabled && license.status != "active" {
        return json_response(
            StatusCode::PAYMENT_REQUIRED,
            serde_json::json!({"message":"a valid license is required before starting the gateway", "license":license}),
        );
    }
    match state.gateway.start().await {
        Ok(gateway) => {
            if state.public_state.caddy.enabled {
                let mut caddy = state.public_state.caddy.clone();
                caddy.gate_upstream = gateway.http_listen.clone();
                if let Ok(sites) = state.storage.managed_sites() {
                    for site in sites.into_iter().filter(|site| site.enabled) {
                        if let Err(error) = crate::caddy::set_site_protection(
                            &caddy,
                            &site.host,
                            &site.target,
                            true,
                        )
                        .await
                        {
                            error!(error = %error, host = %site.host, "failed to update Caddy route after gateway start");
                        }
                    }
                }
            }
            json_response(StatusCode::OK, serde_json::json!({"gateway": gateway}))
        }
        Err(error) => {
            error!(error = %error, "failed to start gateway");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":format!("failed to start gateway: {error:#}")}),
            )
        }
    }
}

pub(crate) async fn admin_gateway_stop(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({"gateway": state.gateway.stop().await}),
    )
}

pub(crate) async fn admin_activate_license(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminLicenseInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    match crate::license::activate(&state.public_state.license, &input.key) {
        Ok(status) => json_response(StatusCode::OK, serde_json::json!({"license": status})),
        Err(error) => json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"message": error.to_string()}),
        ),
    }
}

pub(crate) async fn admin_list_challenges(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let items = state
        .public_state
        .verification
        .challenges
        .lock()
        .map(|challenges| {
            challenges
                .values()
                .map(|challenge| {
                    serde_json::json!({
                        "id": challenge.id,
                        "site": challenge.site,
                        "remote_ip": challenge.remote_ip.to_string(),
                        "return_path": challenge.return_path,
                        "issued_at": challenge.issued_at,
                        "expires_at": challenge.expires_at,
                        "attempts": challenge.attempts,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json_response(
        StatusCode::OK,
        serde_json::json!({"items":items,"total":items.len()}),
    )
}

pub(crate) async fn admin_list_requests(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Query(query): Query<AdminLogQuery>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let filter: LogFilter = query.into();
    let (page, page_size, _) = filter.normalized_page();
    match state.storage.request_logs(&filter) {
        Ok((items, total)) => json_response(
            StatusCode::OK,
            serde_json::json!({"items":items,"total":total,"page":page,"page_size":page_size}),
        ),
        Err(error) => {
            error!(error = %error, "failed to list request logs");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"request logs unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_request_detail(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(id): Path<i64>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    match state.storage.request_log(id) {
        Ok(Some(item)) => json_response(StatusCode::OK, serde_json::json!({"item":item})),
        Ok(None) => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({"message":"request log not found"}),
        ),
        Err(error) => {
            error!(error = %error, id, "failed to load request log");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"request log unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_clear_requests(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminLogQuery = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    match state.storage.clear_request_logs(&input.into()) {
        Ok(deleted) => json_response(StatusCode::OK, serde_json::json!({"deleted": deleted})),
        Err(error) => {
            error!(error = %error, "failed to clear request logs");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"request logs unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_list_interceptions(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Query(query): Query<AdminLogQuery>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let filter: LogFilter = query.into();
    let (page, page_size, _) = filter.normalized_page();
    match state.storage.security_events(&filter) {
        Ok((items, total)) => json_response(
            StatusCode::OK,
            serde_json::json!({"items":items,"total":total,"page":page,"page_size":page_size}),
        ),
        Err(error) => {
            error!(error = %error, "failed to list security events");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"interception logs unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_interception_detail(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(id): Path<i64>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    match state.storage.security_event(id) {
        Ok(Some(item)) => json_response(StatusCode::OK, serde_json::json!({"item":item})),
        Ok(None) => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({"message":"interception log not found"}),
        ),
        Err(error) => {
            error!(error = %error, id, "failed to load security event");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"interception log unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_clear_interceptions(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminLogQuery = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    match state.storage.clear_security_events(&input.into()) {
        Ok(deleted) => json_response(StatusCode::OK, serde_json::json!({"deleted": deleted})),
        Err(error) => {
            error!(error = %error, "failed to clear interception logs");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"interception logs unavailable"}),
            )
        }
    }
}

fn admin_access(remote: SocketAddr) -> Option<Response<Body>> {
    if !remote.ip().is_loopback() {
        Some(admin_forbidden())
    } else {
        None
    }
}

async fn admin_input<T: DeserializeOwned>(
    request: Request<Body>,
) -> std::result::Result<T, Box<Response<Body>>> {
    let body = axum::body::to_bytes(request.into_body(), 16 * 1024)
        .await
        .map_err(|_| {
            Box::new(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"message":"payload too large"}),
            ))
        })?;
    serde_json::from_slice(&body).map_err(|_| {
        Box::new(json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"message":"invalid payload"}),
        ))
    })
}

fn managed_site(input: AdminSiteInput, policy: &UpstreamPolicy) -> Result<ManagedSite> {
    let host = normalize_host(&input.host)?;
    validate_upstream(&input.target, policy)?;
    let policy_name = input.policy.trim();
    if policy_name.is_empty() || policy_name.len() > 64 || policy_name.contains(['\r', '\n']) {
        bail!("policy must be 1-64 characters")
    }
    Ok(ManagedSite {
        host,
        target: input.target,
        policy: policy_name.to_string(),
        enabled: input.enabled,
    })
}

fn managed_whitelist(input: AdminWhitelistInput) -> Result<ManagedWhitelist> {
    let value = input.value.trim();
    let kind = if value.parse::<IpAddr>().is_ok() {
        "ip"
    } else {
        value
            .parse::<IpNet>()
            .context("whitelist value must be an IP or CIDR network")?;
        "network"
    };
    let note = input
        .note
        .map(|note| note.trim().to_string())
        .filter(|note| !note.is_empty());
    if note
        .as_ref()
        .is_some_and(|note| note.len() > 256 || note.contains(['\r', '\n']))
    {
        bail!("whitelist note must be at most 256 characters")
    }
    Ok(ManagedWhitelist {
        id: 0,
        kind: kind.to_string(),
        value: value.to_string(),
        skip_challenge: input.skip_challenge,
        skip_rate_limit: input.skip_rate_limit,
        note,
    })
}

fn refresh_managed_runtime(state: &AdminState) -> Result<()> {
    let managed_sites = state.storage.managed_sites()?;
    let managed_whitelist = state.storage.managed_whitelist()?;
    let sites = managed_sites
        .into_iter()
        .map(|site| {
            (
                site.host.clone(),
                SiteConfig {
                    host: site.host,
                    target: site.target,
                    policy: site.policy,
                    enabled: site.enabled,
                },
            )
        })
        .collect();
    let whitelist = managed_whitelist
        .iter()
        .map(whitelist_rule_from_record)
        .collect::<Result<Vec<_>>>()?;
    *state
        .public_state
        .sites
        .write()
        .map_err(|_| anyhow::anyhow!("site state is unavailable"))? = sites;
    *state
        .public_state
        .security
        .whitelist
        .write()
        .map_err(|_| anyhow::anyhow!("whitelist state is unavailable"))? = whitelist;
    Ok(())
}

fn sync_nginx_sites(state: &AdminState, sites: &[NginxSite]) -> Result<()> {
    for site in sites.iter().filter(|site| site.supported) {
        state.storage.upsert_site(&ManagedSite {
            host: site.host.clone(),
            target: site.target.clone(),
            policy: default_policy(),
            enabled: site.protected,
        })?;
    }
    refresh_managed_runtime(state)
}

fn scan_nginx(state: &AdminState) -> (Option<Vec<NginxSite>>, Option<String>) {
    let mut nginx = match state.nginx.lock() {
        Ok(nginx) => nginx,
        Err(_) => return (None, Some("Nginx 扫描状态不可用".to_string())),
    };
    if nginx.config_dir().is_none() {
        return (Some(Vec::new()), None);
    }
    match nginx.scan() {
        Ok(sites) => (Some(sites), None),
        Err(error) => (None, Some(error.to_string())),
    }
}

pub(crate) async fn admin_list_sites(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let (nginx_sites, nginx_error) = scan_nginx(&state);
    if let Some(sites) = nginx_sites.as_deref() {
        if let Err(error) = sync_nginx_sites(&state, sites) {
            error!(error = %error, "failed to sync Nginx sites");
        }
    }
    match state.storage.managed_sites() {
        Ok(sites) => {
            let discovered = nginx_sites.unwrap_or_default();
            let discovered_hosts = discovered
                .iter()
                .map(|site| site.host.clone())
                .collect::<std::collections::HashSet<_>>();
            let mut rows = discovered
                .iter()
                .map(|site| {
                    serde_json::json!({
                        "id": site.id,
                        "host": site.host,
                        "target": site.target,
                        "policy": "normal",
                        "enabled": site.protected,
                        "source": "nginx",
                        "config_file": site.config_file,
                        "supported": site.supported
                    })
                })
                .collect::<Vec<_>>();
            rows.extend(sites.into_iter().filter(|site| !discovered_hosts.contains(&site.host)).map(|site| {
                serde_json::json!({"id": format!("manual:{}", site.host), "host":site.host,"target":site.target,"policy":site.policy,"enabled":site.enabled,"source":"manual","supported":true})
            }));
            let nginx = state.nginx.lock().ok();
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "caddy_enabled": state.public_state.caddy.enabled,
                    "nginx": {
                        "configured": nginx.as_ref().is_some_and(|manager| manager.config_dir().is_some()),
                        "config_dir": nginx.as_ref().and_then(|manager| manager.config_dir()).map(|path| path.display().to_string()),
                        "binary": nginx.as_ref().and_then(|manager| manager.binary()).map(|path| path.display().to_string()),
                        "error": nginx_error
                    },
                    "sites": rows
                }),
            )
        }
        Err(error) => {
            error!(error = %error, "failed to list sites");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"site management unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_nginx_scan(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminNginxScanInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let sites = {
        let mut manager = match state.nginx.lock() {
            Ok(manager) => manager,
            Err(_) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"message":"Nginx 扫描状态不可用"}),
                )
            }
        };
        if let Err(error) = manager.configure(input.config_dir.clone(), input.binary.clone()) {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":error.to_string()}),
            );
        }
        if let Err(error) = state
            .storage
            .set_setting("nginx.config_dir", &input.config_dir)
        {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":format!("无法保存 Nginx 配置目录: {error}")}),
            );
        }
        if let Err(error) = state
            .storage
            .set_setting("nginx.binary", input.binary.as_deref().unwrap_or(""))
        {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":format!("无法保存 Nginx 程序路径: {error}")}),
            );
        }
        match manager.scan() {
            Ok(sites) => sites,
            Err(error) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"message":error.to_string()}),
                )
            }
        }
    };
    if let Err(error) = sync_nginx_sites(&state, &sites) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":format!("Nginx 站点同步失败: {error}")}),
        );
    }
    json_response(StatusCode::OK, serde_json::json!({"sites":sites}))
}

pub(crate) async fn admin_nginx_pick(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    match crate::nginx::pick_directory() {
        Ok(Some(path)) => json_response(StatusCode::OK, serde_json::json!({"path":path})),
        Ok(None) => json_response(StatusCode::OK, serde_json::json!({"path":null})),
        Err(error) => json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"message":error.to_string()}),
        ),
    }
}

pub(crate) async fn admin_nginx_toggle(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminNginxToggleInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let gateway = state.gateway.status().await;
    if !gateway.running {
        return json_response(
            StatusCode::CONFLICT,
            serde_json::json!({"message":"请先启动 Bot Gate 网关，再接管 Nginx 站点"}),
        );
    }
    let site = {
        let mut manager = match state.nginx.lock() {
            Ok(manager) => manager,
            Err(_) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"message":"Nginx 扫描状态不可用"}),
                )
            }
        };
        match manager.set_protected(&input.id, input.protected, &gateway.http_listen) {
            Ok(site) => site,
            Err(error) => {
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({"message":error.to_string()}),
                )
            }
        }
    };
    if let Err(error) = state
        .storage
        .upsert_site(&ManagedSite {
            host: site.host.clone(),
            target: site.target.clone(),
            policy: default_policy(),
            enabled: site.protected,
        })
        .and_then(|_| refresh_managed_runtime(&state))
    {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":format!("Nginx 状态已修改但运行路由同步失败: {error}")}),
        );
    }
    json_response(StatusCode::OK, serde_json::json!({"site":site}))
}

pub(crate) async fn admin_save_site(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let site = match managed_site(input, &state.public_state.upstream_policy) {
        Ok(site) => site,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":error.to_string()}),
            )
        }
    };
    if let Err(error) = state
        .storage
        .upsert_site(&site)
        .and_then(|_| refresh_managed_runtime(&state))
    {
        error!(error = %error, "failed to save site");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"failed to save site"}),
        );
    }
    json_response(StatusCode::OK, serde_json::json!({"ok":true}))
}

pub(crate) async fn admin_toggle_site(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    if !state.public_state.caddy.enabled {
        return json_response(
            StatusCode::CONFLICT,
            serde_json::json!({"message":"Caddy 接管未启用，请先配置 caddy.enabled = true"}),
        );
    }
    let input: AdminSiteToggleInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let mut sites = match state.storage.managed_sites() {
        Ok(sites) => sites,
        Err(error) => {
            error!(error = %error, "failed to load site for toggle");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"site management unavailable"}),
            );
        }
    };
    let Some(site) = sites.iter_mut().find(|site| site.host == input.host) else {
        return json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({"message":"site not found"}),
        );
    };
    if site.enabled == input.enabled {
        return json_response(StatusCode::OK, serde_json::json!({"ok":true}));
    }
    let gateway = state.gateway.status().await;
    let mut caddy = state.public_state.caddy.clone();
    if gateway.running {
        caddy.gate_upstream = gateway.http_listen;
    }
    if let Err(error) =
        crate::caddy::set_site_protection(&caddy, &site.host, &site.target, input.enabled).await
    {
        error!(error = %error, host = %site.host, "failed to switch Caddy site route");
        return json_response(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({"message":format!("Caddy 路由切换失败: {error}")}),
        );
    }
    site.enabled = input.enabled;
    let updated = site.clone();
    if let Err(error) = state
        .storage
        .upsert_site(&updated)
        .and_then(|_| refresh_managed_runtime(&state))
    {
        error!(error = %error, host = %updated.host, "failed to persist site toggle");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"站点状态保存失败，Caddy 路由已切换，请重试"}),
        );
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({"ok":true,"enabled":updated.enabled}),
    )
}

pub(crate) async fn admin_delete_site(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminHostInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let host = match normalize_host(&input.host) {
        Ok(host) => host,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":error.to_string()}),
            )
        }
    };
    match state
        .storage
        .delete_site(&host)
        .and_then(|deleted| refresh_managed_runtime(&state).map(|_| deleted))
    {
        Ok(deleted) => json_response(StatusCode::OK, serde_json::json!({"deleted":deleted})),
        Err(error) => {
            error!(error = %error, "failed to delete site");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"failed to delete site"}),
            )
        }
    }
}

pub(crate) async fn admin_list_bans(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    match state.storage.active_bans() {
        Ok(bans) => json_response(
            StatusCode::OK,
            serde_json::json!({"bans":bans.into_iter().map(|ban| serde_json::json!({"ip":ban.ip,"reason":ban.reason,"source":ban.source,"created_at":ban.created_at,"expires_at":ban.expires_at})).collect::<Vec<_>>() }),
        ),
        Err(error) => {
            error!(error = %error, "failed to list bans");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"ban management unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_save_ban(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminBanInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let ip = match input.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":"invalid IP address"}),
            )
        }
    };
    let reason = input.reason.trim();
    if reason.is_empty()
        || reason.len() > 256
        || reason.contains(['\r', '\n'])
        || input.duration_secs == 0
        || input.duration_secs > 30 * 24 * 60 * 60
    {
        return json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"message":"invalid ban reason or duration"}),
        );
    }
    let record = BanRecord {
        ip: ip.to_string(),
        reason: reason.to_string(),
        source: "admin".to_string(),
        created_at: unix_now(),
        expires_at: unix_now().saturating_add(input.duration_secs),
    };
    if let Err(error) = state.storage.set_ban(&record) {
        error!(error = %error, "failed to save ban");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"failed to save ban"}),
        );
    }
    state
        .public_state
        .security
        .set_manual_ban(ip, record.reason, record.expires_at);
    json_response(StatusCode::OK, serde_json::json!({"ok":true}))
}

pub(crate) async fn admin_delete_ban(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminIpInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let ip = match input.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":"invalid IP address"}),
            )
        }
    };
    match state.storage.clear_ban(&ip.to_string()) {
        Ok(deleted) => {
            state.public_state.security.clear_ban_entry(ip);
            json_response(StatusCode::OK, serde_json::json!({"deleted":deleted}))
        }
        Err(error) => {
            error!(error = %error, "failed to clear ban");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"failed to clear ban"}),
            )
        }
    }
}

pub(crate) async fn admin_list_whitelist(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    match state.storage.managed_whitelist() {
        Ok(entries) => json_response(
            StatusCode::OK,
            serde_json::json!({"whitelist":entries.into_iter().map(|entry| serde_json::json!({"id":entry.id,"kind":entry.kind,"value":entry.value,"skip_challenge":entry.skip_challenge,"skip_rate_limit":entry.skip_rate_limit,"note":entry.note})).collect::<Vec<_>>() }),
        ),
        Err(error) => {
            error!(error = %error, "failed to list whitelist");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"whitelist management unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_save_whitelist(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let input: AdminWhitelistInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let entry = match managed_whitelist(input) {
        Ok(entry) => entry,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":error.to_string()}),
            )
        }
    };
    if let Err(error) = state
        .storage
        .replace_whitelist(&entry)
        .and_then(|_| refresh_managed_runtime(&state))
    {
        error!(error = %error, "failed to save whitelist entry");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"failed to save whitelist entry"}),
        );
    }
    json_response(StatusCode::OK, serde_json::json!({"ok":true}))
}

pub(crate) async fn admin_delete_whitelist(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }

    let input: AdminIdInput = match admin_input(request).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if input.id <= 0 {
        return json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"message":"invalid whitelist id"}),
        );
    }
    match state
        .storage
        .delete_whitelist(input.id)
        .and_then(|deleted| refresh_managed_runtime(&state).map(|_| deleted))
    {
        Ok(deleted) => json_response(StatusCode::OK, serde_json::json!({"deleted":deleted})),
        Err(error) => {
            error!(error = %error, "failed to delete whitelist entry");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"failed to delete whitelist entry"}),
            )
        }
    }
}

pub(crate) async fn admin_reload_config(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if let Some(response) = admin_access(remote) {
        return response;
    }
    let candidate = match load_config(&state.config_path) {
        Ok(config) => config,
        Err(error) => {
            error!(error = %error, "config reload validation failed");
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message": format!("config validation failed: {error}")}),
            );
        }
    };
    if let Some(tls_config) = &state.tls_config {
        if candidate.tls.enabled {
            if let Err(error) = tls_config
                .reload_from_pem_file(&candidate.tls.cert_file, &candidate.tls.key_file)
                .await
            {
                error!(error = %error, "TLS config reload failed");
                return json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"message": format!("TLS reload failed: {error}")}),
                );
            }
        }
    } else if candidate.tls.enabled {
        return json_response(
            StatusCode::CONFLICT,
            serde_json::json!({"message":"enabling TLS requires a process restart"}),
        );
    }
    let sites = match candidate
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
        .collect::<Result<Vec<_>>>()
    {
        Ok(sites) => sites,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message": error.to_string()}),
            )
        }
    };
    let whitelist = candidate
        .security
        .whitelist
        .ips
        .iter()
        .map(|value| ManagedWhitelist {
            id: 0,
            kind: "ip".to_string(),
            value: value.clone(),
            skip_challenge: candidate.security.whitelist.skip_challenge,
            skip_rate_limit: candidate.security.whitelist.skip_rate_limit,
            note: None,
        })
        .chain(
            candidate
                .security
                .whitelist
                .networks
                .iter()
                .map(|value| ManagedWhitelist {
                    id: 0,
                    kind: "network".to_string(),
                    value: value.clone(),
                    skip_challenge: candidate.security.whitelist.skip_challenge,
                    skip_rate_limit: candidate.security.whitelist.skip_rate_limit,
                    note: None,
                }),
        )
        .collect::<Vec<_>>();
    if let Err(error) = state
        .storage
        .replace_management(&sites, &whitelist)
        .and_then(|_| refresh_managed_runtime(&state))
    {
        error!(error = %error, "config reload failed");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"config reload failed"}),
        );
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({"ok":true,"reloaded":["sites","whitelist"],"restart_required":["server","verification","security","storage","admin"]}),
    )
}
