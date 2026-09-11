use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    response::Response,
};
use hyper::{header, Request, StatusCode};
use serde::de::DeserializeOwned;

use crate::storage::BanRecord;
use crate::*;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::path::Path;

pub(crate) fn load_admin_password_hash(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(value) => {
            let value = value.trim().to_string();
            if value.is_empty() {
                Ok(None)
            } else if value.len() > 1024 {
                bail!("admin password hash is too large")
            } else {
                Ok(Some(value))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to read admin password hash {}", path.display())),
    }
}

fn save_admin_password_hash(path: &Path, hash: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create admin password directory {}",
                parent.display()
            )
        })?;
    }
    std::fs::write(path, format!("{hash}\n"))
        .with_context(|| format!("failed to write admin password hash {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn hash_admin_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("failed to hash admin password: {error}"))
}

fn verify_admin_password(hash: &str, password: &str) -> bool {
    let Ok(hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

const ADMIN_SESSION_COOKIE: &str = "bot_admin_session";

fn admin_session_value(token: &str, secret: &[u8]) -> String {
    let signature = URL_SAFE_NO_PAD.encode(hmac_sha256(secret, token.as_bytes()));
    format!("{token}.{signature}")
}

fn admin_session_token(value: &str, secret: &[u8]) -> Option<String> {
    let (token, signature) = value.split_once('.')?;
    let expected = URL_SAFE_NO_PAD.encode(hmac_sha256(secret, token.as_bytes()));
    if token.is_empty()
        || signature.len() != expected.len()
        || !constant_time_eq(signature.as_bytes(), expected.as_bytes())
    {
        return None;
    }
    Some(token.to_string())
}

fn admin_is_authenticated(state: &AdminState, request: &Request<Body>) -> bool {
    let Some(value) = cookie_from_request(request, ADMIN_SESSION_COOKIE) else {
        return false;
    };
    let Some(token) = admin_session_token(&value, &state.secret) else {
        return false;
    };
    let now = unix_now();
    let Ok(mut sessions) = state.sessions.lock() else {
        return false;
    };
    sessions.retain(|_, session| session.expires_at > now);
    sessions.contains_key(&token)
}

fn admin_cookie_response(
    status: StatusCode,
    body: serde_json::Value,
    cookie: &str,
) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::SET_COOKIE, cookie)
        .body(Body::from(body.to_string()))
        .expect("admin cookie response headers are valid")
}

fn admin_unauthorized() -> Response<Body> {
    json_response(
        StatusCode::UNAUTHORIZED,
        serde_json::json!({"code": 401, "message": "admin authentication required"}),
    )
}

fn admin_forbidden() -> Response<Body> {
    response_with(
        StatusCode::FORBIDDEN,
        "text/plain; charset=utf-8",
        "admin is loopback-only",
    )
}

pub(crate) async fn admin_page() -> Response<Body> {
    let page = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bot Gate 管理后台</title><style>
body{font:15px system-ui,sans-serif;max-width:54rem;margin:3rem auto;padding:0 1rem;color:#202124;background:#f6f7f9}
main{background:white;border:1px solid #dfe3e8;border-radius:12px;padding:1.5rem;box-shadow:0 4px 20px #0000000d}
input,button{font:inherit;padding:.65rem .8rem;border:1px solid #c7cdd4;border-radius:7px}button{cursor:pointer;background:#1f6feb;color:#fff;border:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:.8rem}.card{padding:1rem;background:#f2f5f8;border-radius:8px}.value{font-size:1.6rem;font-weight:650;margin-top:.35rem}.muted{color:#667085}.error{color:#b42318;min-height:1.4rem}
</style></head><body><main><h1>Bot Gate 管理后台</h1><p class="muted">仅供本机管理，管理端默认只监听 127.0.0.1。</p>
<section id="setup" hidden><h2>首次设置管理员密码</h2><p>密码至少 12 个字符，服务端只保存 Argon2id 哈希。</p><input id="setup-password" type="password" autocomplete="new-password"><button onclick="setup()">设置密码</button></section>
<section id="login" hidden><h2>登录</h2><input id="login-password" type="password" autocomplete="current-password"><button onclick="login()">登录</button></section>
<section id="dashboard" hidden><div style="display:flex;justify-content:space-between;align-items:center"><h2>运行概览</h2><button onclick="logout()">退出</button></div><div id="cards" class="grid"></div><p id="dash-error" class="error"></p>
<h2>站点</h2><p><input id="site-host" placeholder="project.test"><input id="site-target" placeholder="http://127.0.0.1:9001"><input id="site-policy" value="normal" placeholder="policy"><button onclick="saveSite()">保存站点</button></p><pre id="sites"></pre>
<h2>封禁</h2><p><input id="ban-ip" placeholder="IP"><input id="ban-reason" placeholder="原因"><input id="ban-duration" type="number" value="600" min="1"><button onclick="saveBan()">封禁</button></p><pre id="bans"></pre>
<h2>白名单</h2><p><input id="white-value" placeholder="IP 或 CIDR"><button onclick="saveWhitelist()">加入白名单</button></p><pre id="whitelist"></pre></section>
<p id="message" class="error"></p></main><script>
const $=id=>document.getElementById(id); const msg=t=>$("message").textContent=t||"";
async function api(url,opts={}){const r=await fetch(url,{headers:{"content-type":"application/json",...(opts.headers||{})},...opts});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||"请求失败");return d;}
async function setup(){try{const p=$("setup-password").value;if(p.length<12)throw Error("密码至少 12 个字符");await api("/api/setup",{method:"POST",body:JSON.stringify({password:p})});msg("设置成功，请登录");$("setup").hidden=true;$("login").hidden=false;}catch(e){msg(e.message)}}
async function login(){try{await api("/api/login",{method:"POST",body:JSON.stringify({password:$("login-password").value})});$("login").hidden=true;await dashboard();}catch(e){msg(e.message)}}
async function logout(){await api("/api/logout",{method:"POST"}).catch(()=>{});$("dashboard").hidden=true;$("login").hidden=false;}
async function dashboard(){try{const d=await api("/api/dashboard");$("dashboard").hidden=false;$("cards").innerHTML=Object.entries({"今日请求":d.today_requests,"验证通过":d.today_verified,"被拦截":d.today_blocked,"404":d.today_not_found,"Challenge 失败":d.today_challenge_failures,"活跃封禁":d.active_bans,"活跃 Challenge":d.active_challenges,"站点":d.sites}).map(([k,v])=>'<div class="card"><div class="muted">'+k+'</div><div class="value">'+v+'</div></div>').join("");await refreshManagement();}catch(e){if(e.message.includes("认证")){$("login").hidden=false;}else $("dash-error").textContent=e.message}}
async function refreshManagement(){const [s,b,w]=await Promise.all([api("/api/sites"),api("/api/bans"),api("/api/whitelist")]);$("sites").textContent=JSON.stringify(s.sites,null,2);$("bans").textContent=JSON.stringify(b.bans,null,2);$("whitelist").textContent=JSON.stringify(w.whitelist,null,2)}
async function saveSite(){await api("/api/sites",{method:"POST",body:JSON.stringify({host:$('site-host').value,target:$('site-target').value,policy:$('site-policy').value,enabled:true})});await refreshManagement()}
async function saveBan(){await api("/api/bans",{method:"POST",body:JSON.stringify({ip:$('ban-ip').value,reason:$('ban-reason').value,duration_secs:Number($('ban-duration').value)})});await refreshManagement()}
async function saveWhitelist(){await api("/api/whitelist",{method:"POST",body:JSON.stringify({value:$('white-value').value,skip_challenge:true,skip_rate_limit:false})});await refreshManagement()}
(async()=>{try{const s=await api("/api/status");if(s.configured){$("login").hidden=false;await dashboard();}else $("setup").hidden=false;}catch(e){msg(e.message)}})();
</script></body></html>"#;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(page))
        .expect("admin page headers are valid")
}

pub(crate) async fn admin_status(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return admin_forbidden();
    }
    let configured = state
        .password_hash
        .lock()
        .map(|hash| hash.is_some())
        .unwrap_or(false);
    json_response(
        StatusCode::OK,
        serde_json::json!({"configured": configured}),
    )
}

pub(crate) async fn admin_setup(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return admin_forbidden();
    }
    let body = match axum::body::to_bytes(request.into_body(), 16 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"message":"payload too large"}),
            )
        }
    };
    let input = match serde_json::from_slice::<AdminPasswordInput>(&body) {
        Ok(input) => input,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":"invalid payload"}),
            )
        }
    };
    if input.password.chars().count() < 12 || input.password.chars().count() > 256 {
        return json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"message":"password must be 12-256 characters"}),
        );
    }
    let mut hash = match state.password_hash.lock() {
        Ok(hash) => hash,
        Err(_) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"admin unavailable"}),
            )
        }
    };
    if hash.is_some() {
        return json_response(
            StatusCode::CONFLICT,
            serde_json::json!({"message":"admin password already configured"}),
        );
    }
    let password_hash = match hash_admin_password(&input.password) {
        Ok(value) => value,
        Err(_) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"password hashing failed"}),
            )
        }
    };
    if let Err(error) =
        save_admin_password_hash(Path::new(&state.config.password_file), &password_hash)
    {
        error!(error = %error, "failed to persist admin password hash");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"failed to persist admin password"}),
        );
    }
    *hash = Some(password_hash);
    json_response(StatusCode::CREATED, serde_json::json!({"ok":true}))
}

pub(crate) async fn admin_login(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return admin_forbidden();
    }
    let body = match axum::body::to_bytes(request.into_body(), 16 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"message":"payload too large"}),
            )
        }
    };
    let input = match serde_json::from_slice::<AdminPasswordInput>(&body) {
        Ok(input) => input,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"message":"invalid payload"}),
            )
        }
    };
    let configured_hash = state
        .password_hash
        .lock()
        .ok()
        .and_then(|hash| hash.clone());
    let Some(configured_hash) = configured_hash else {
        return json_response(
            StatusCode::PRECONDITION_REQUIRED,
            serde_json::json!({"message":"admin password is not configured"}),
        );
    };
    if !verify_admin_password(&configured_hash, &input.password) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"message":"invalid password"}),
        );
    }
    let token = random_token(32);
    let expires_at = unix_now().saturating_add(state.config.session_ttl_secs);
    if let Ok(mut sessions) = state.sessions.lock() {
        sessions.retain(|_, session| session.expires_at > unix_now());
        sessions.insert(token.clone(), AdminSession { expires_at });
    } else {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"message":"admin unavailable"}),
        );
    }
    let cookie = format!(
        "{ADMIN_SESSION_COOKIE}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict",
        admin_session_value(&token, &state.secret),
        state.config.session_ttl_secs
    );
    admin_cookie_response(StatusCode::OK, serde_json::json!({"ok":true}), &cookie)
}

pub(crate) async fn admin_logout(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return admin_forbidden();
    }
    if let Some(value) = cookie_from_request(&request, ADMIN_SESSION_COOKIE) {
        if let Some(token) = admin_session_token(&value, &state.secret) {
            if let Ok(mut sessions) = state.sessions.lock() {
                sessions.remove(&token);
            }
        }
    }
    let cookie = format!("{ADMIN_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
    admin_cookie_response(StatusCode::OK, serde_json::json!({"ok":true}), &cookie)
}

pub(crate) async fn admin_dashboard(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return admin_forbidden();
    }
    if !admin_is_authenticated(&state, &request) {
        return admin_unauthorized();
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

fn admin_access(
    state: &AdminState,
    remote: SocketAddr,
    request: &Request<Body>,
) -> Option<Response<Body>> {
    if !remote.ip().is_loopback() {
        Some(admin_forbidden())
    } else if !admin_is_authenticated(state, request) {
        Some(admin_unauthorized())
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

pub(crate) async fn admin_list_sites(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(&state, remote, &request) {
        return response;
    }
    match state.storage.managed_sites() {
        Ok(sites) => json_response(
            StatusCode::OK,
            serde_json::json!({"sites": sites.into_iter().map(|site| serde_json::json!({"host":site.host,"target":site.target,"policy":site.policy,"enabled":site.enabled})).collect::<Vec<_>>() }),
        ),
        Err(error) => {
            error!(error = %error, "failed to list sites");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message":"site management unavailable"}),
            )
        }
    }
}

pub(crate) async fn admin_save_site(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(&state, remote, &request) {
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

pub(crate) async fn admin_delete_site(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(&state, remote, &request) {
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
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(&state, remote, &request) {
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
    if let Some(response) = admin_access(&state, remote, &request) {
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
    if let Some(response) = admin_access(&state, remote, &request) {
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
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(&state, remote, &request) {
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
    if let Some(response) = admin_access(&state, remote, &request) {
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
    if let Some(response) = admin_access(&state, remote, &request) {
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
    request: Request<Body>,
) -> Response<Body> {
    if let Some(response) = admin_access(&state, remote, &request) {
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
    if let Ok(mut loaded) = state.loaded_config.lock() {
        *loaded = candidate;
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({"ok":true,"reloaded":["sites","whitelist"],"restart_required":["server","verification","security","storage","admin"]}),
    )
}
