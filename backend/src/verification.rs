use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use axum::{body::Body, response::Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use hyper::{header, Request, StatusCode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use url::form_urlencoded;

use crate::*;

const MAX_ACTIVE_CHALLENGES: usize = 10_000;

#[derive(Debug, Clone)]
pub(crate) struct RedirectState {
    pub(crate) site: String,
    pub(crate) remote_ip: IpAddr,
    pub(crate) return_path: String,
    pub(crate) verify_path: String,
    pub(crate) expires_at: u64,
    pub(crate) used: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Challenge {
    pub(crate) id: String,
    pub(crate) nonce: String,
    pub(crate) site: String,
    pub(crate) remote_ip: IpAddr,
    pub(crate) return_path: String,
    pub(crate) verify_path: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) signature: String,
    pub(crate) attempts: u32,
}

#[derive(Debug, Deserialize)]
struct ChallengeSubmit {
    challenge_id: String,
    counter: u64,
    pub(crate) signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CookiePayload {
    pub(crate) version: u8,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) challenge_id: String,
    pub(crate) site: String,
    #[serde(default)]
    pub(crate) ip: Option<String>,
}

pub(crate) struct VerificationState {
    pub(crate) config: VerificationConfig,
    pub(crate) secret: Vec<u8>,
    pub(crate) challenges: Mutex<HashMap<String, Challenge>>,
    pub(crate) redirects: Mutex<HashMap<String, RedirectState>>,
    pub(crate) routes: Mutex<HashMap<String, u64>>,
}

pub(crate) fn random_token(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

pub(crate) fn hmac_sha256(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn challenge_signature(secret: &[u8], challenge: &Challenge) -> String {
    let material = format!(
        "{}|{}|{}|{}|{}|{}",
        challenge.id,
        challenge.nonce,
        challenge.issued_at,
        challenge.expires_at,
        challenge.site,
        challenge.verify_path
    );
    URL_SAFE_NO_PAD.encode(hmac_sha256(secret, material.as_bytes()))
}

pub(crate) fn fnv1a32(value: &[u8]) -> u32 {
    value.iter().fold(2_166_136_261u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

pub(crate) fn verify_pow(challenge: &Challenge, counter: u64, difficulty: u8) -> bool {
    let material = format!("{}:{}:{}", challenge.id, challenge.nonce, counter);
    difficulty == 0 || (fnv1a32(material.as_bytes()) >> (32 - difficulty)) == 0
}

pub(crate) fn load_or_create_secret(path: &Path) -> Result<Vec<u8>> {
    if let Ok(secret) = std::fs::read(path) {
        if secret.len() >= 32 {
            return Ok(secret);
        }
        bail!("secret file {} is too short", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create secret directory {}", parent.display()))?;
    }
    let mut secret = vec![0u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to create secret file {}", path.display()))?;
    file.write_all(&secret)
        .with_context(|| format!("failed to write secret file {}", path.display()))?;
    Ok(secret)
}

pub(crate) fn cookie_value(payload: &CookiePayload, secret: &[u8]) -> Result<String> {
    let payload = serde_json::to_vec(payload)?;
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
    let signature = URL_SAFE_NO_PAD.encode(hmac_sha256(secret, encoded_payload.as_bytes()));
    Ok(format!("{encoded_payload}.{signature}"))
}

pub(crate) fn verify_cookie(
    value: &str,
    config: &VerificationConfig,
    secret: &[u8],
    site: &str,
    remote_ip: IpAddr,
    now: u64,
) -> bool {
    let Some((payload, signature)) = value.split_once('.') else {
        return false;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let expected = hmac_sha256(secret, payload.as_bytes());
    if signature.len() != expected.len() || !constant_time_eq(&signature, &expected) {
        return false;
    }
    let Ok(payload) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<CookiePayload>(&payload) else {
        return false;
    };
    payload.version == 1
        && payload.site == site
        && (!config.bind_ip || payload.ip.as_deref() == Some(&remote_ip.to_string()))
        && payload.expires_at > now
        && payload.issued_at <= now
        && payload.expires_at.saturating_sub(payload.issued_at) <= config.cookie_ttl_secs
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn create_redirect_state(
    verification: &VerificationState,
    site: &str,
    remote_ip: IpAddr,
    return_path: String,
) -> Option<String> {
    let now = unix_now();
    let token = random_token(24);
    let verify_path = format!("/{}", random_token(24));
    let mut redirects = verification.redirects.lock().ok()?;
    redirects.retain(|_, redirect| {
        redirect
            .expires_at
            .saturating_add(verification.config.challenge_ttl_secs)
            > now
    });
    if redirects.len() >= MAX_ACTIVE_CHALLENGES {
        return None;
    }
    let expires_at = now.saturating_add(verification.config.challenge_ttl_secs);
    redirects.insert(
        token.clone(),
        RedirectState {
            site: site.to_string(),
            remote_ip,
            return_path,
            verify_path: verify_path.clone(),
            expires_at,
            used: false,
        },
    );
    if let Ok(mut routes) = verification.routes.lock() {
        routes.retain(|_, route_expires_at| *route_expires_at > now);
        routes.insert(
            verify_path,
            expires_at.saturating_add(verification.config.challenge_ttl_secs * 2),
        );
    }
    Some(token)
}

pub(crate) fn is_verification_path(verification: &VerificationState, path: &str) -> bool {
    let Some((route, endpoint)) = path.rsplit_once('/') else {
        return false;
    };
    if route.is_empty() || !matches!(endpoint, "start" | "submit") {
        return false;
    }
    let now = unix_now();
    verification
        .routes
        .lock()
        .ok()
        .map(|mut routes| {
            routes.retain(|_, expires_at| *expires_at > now);
            routes.contains_key(route)
        })
        .unwrap_or(false)
}

fn redirect_response(
    state: &AppState,
    remote_ip: IpAddr,
    site: &str,
    return_path: String,
) -> Response<Body> {
    let Some(token) = create_redirect_state(&state.verification, site, remote_ip, return_path)
    else {
        return response_with(
            StatusCode::TOO_MANY_REQUESTS,
            "text/plain; charset=utf-8",
            "too many active verification requests",
        );
    };
    let verify_path = state
        .verification
        .redirects
        .lock()
        .ok()
        .and_then(|redirects| {
            redirects
                .get(&token)
                .map(|redirect| redirect.verify_path.clone())
        })
        .unwrap_or_else(|| format!("/{}", random_token(24)));
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &token)
        .finish();
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, format!("{verify_path}/start?{query}"))
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("verification redirect headers are valid")
}

pub(crate) fn verification_redirect(
    state: &AppState,
    remote_ip: IpAddr,
    site: &str,
    request: &Request<Body>,
) -> Response<Body> {
    let return_path = valid_return_path(
        request
            .uri()
            .path_and_query()
            .map(ToString::to_string)
            .as_deref(),
    );
    redirect_response(state, remote_ip, site, return_path)
}

pub(crate) fn valid_return_path(value: Option<&str>) -> String {
    let value = value.unwrap_or("/");
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['\r', '\n'])
        && !value.contains('\\')
        && !value.contains("://")
        && value.len() <= 2048
    {
        value.to_string()
    } else {
        "/".to_string()
    }
}

pub(crate) async fn challenge_page(
    challenge: &Challenge,
    config: &VerificationConfig,
    frontend_dist: &Path,
) -> Result<Response<Body>> {
    let template = tokio::fs::read_to_string(frontend_dist.join("challenge.html"))
        .await
        .context("failed to read challenge frontend")?;
    let page = template.replace(
        "__CHALLENGE_PAYLOAD__",
        &serde_json::json!({
            "id": challenge.id,
            "nonce": challenge.nonce,
            "signature": challenge.signature,
            "difficulty": config.pow_difficulty,
            "site": challenge.site,
            "verify_path": challenge.verify_path,
        })
        .to_string(),
    );
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(page))
        .expect("challenge page headers are valid"))
}

pub(crate) fn create_challenge(
    verification: &VerificationState,
    site: &str,
    remote_ip: IpAddr,
    return_path: String,
    verify_path: String,
) -> Challenge {
    let issued_at = unix_now();
    let mut challenge = Challenge {
        id: random_token(18),
        nonce: random_token(24),
        site: site.to_string(),
        remote_ip,
        return_path,
        verify_path,
        issued_at,
        expires_at: issued_at.saturating_add(verification.config.challenge_ttl_secs),
        signature: String::new(),
        attempts: 0,
    };
    challenge.signature = challenge_signature(&verification.secret, &challenge);
    challenge
}

pub(crate) fn issue_cookie_response(
    state: &AppState,
    site: &str,
    remote_ip: IpAddr,
    challenge_id: &str,
    return_path: &str,
) -> Response<Body> {
    let now = unix_now();
    let payload = CookiePayload {
        version: 1,
        issued_at: now,
        expires_at: now.saturating_add(state.verification.config.cookie_ttl_secs),
        challenge_id: challenge_id.to_string(),
        site: site.to_string(),
        ip: state
            .verification
            .config
            .bind_ip
            .then(|| remote_ip.to_string()),
    };
    let cookie = match cookie_value(&payload, &state.verification.secret) {
        Ok(cookie) => cookie,
        Err(error) => {
            error!(error = %error, "failed to sign verification cookie");
            return response_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                "verification unavailable",
            );
        }
    };
    let max_age = state.verification.config.cookie_ttl_secs;
    let value = format!(
        "{}={}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax",
        state.verification.config.cookie_name, cookie
    );
    json_response_with_cookie(
        StatusCode::OK,
        serde_json::json!({"ok": true, "redirect": return_path}),
        &value,
    )
}

fn json_response_with_cookie(
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
        .expect("verification cookie response headers are valid")
}

pub(crate) async fn handle_verification(
    state: Arc<AppState>,
    remote: SocketAddr,
    site: &str,
    request: Request<Body>,
) -> Response<Body> {
    let path = request.uri().path().to_string();
    if path.ends_with("/start") && request.method() == hyper::Method::GET {
        let verify_path = path.trim_end_matches("/start").to_string();
        let query = request.uri().query().unwrap_or_default();
        let params = form_urlencoded::parse(query.as_bytes()).collect::<HashMap<_, _>>();
        let Some(state_token) = params.get("state").map(|value| value.as_ref()) else {
            return response_with(
                StatusCode::FORBIDDEN,
                "text/plain; charset=utf-8",
                "invalid verification state",
            );
        };
        let redirect = state
            .verification
            .redirects
            .lock()
            .ok()
            .and_then(|mut redirects| {
                let redirect = redirects.get(state_token).cloned()?;
                if redirect.verify_path != verify_path {
                    return None;
                }
                if let Some(value) = redirects.get_mut(state_token) {
                    value.used = true;
                }
                Some(redirect)
            })
            .filter(|redirect| redirect.site == site && redirect.remote_ip == remote.ip());
        let Some(redirect) = redirect else {
            return redirect_response(&state, remote.ip(), site, valid_return_path(None));
        };
        if redirect.used || redirect.expires_at <= unix_now() {
            return redirect_response(&state, remote.ip(), site, redirect.return_path);
        }
        let return_path = redirect.return_path;
        let challenge = create_challenge(
            &state.verification,
            site,
            remote.ip(),
            return_path,
            verify_path,
        );
        if let Ok(mut challenges) = state.verification.challenges.lock() {
            challenges.retain(|_, challenge| challenge.expires_at > unix_now());
            if challenges.len() >= MAX_ACTIVE_CHALLENGES {
                return response_with(
                    StatusCode::TOO_MANY_REQUESTS,
                    "text/plain; charset=utf-8",
                    "too many active challenges",
                );
            }
            challenges.insert(challenge.id.clone(), challenge.clone());
        }
        return challenge_page(&challenge, &state.verification.config, &state.frontend_dist)
            .await
            .unwrap_or_else(|_| {
                response_with(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain; charset=utf-8",
                    "challenge unavailable",
                )
            });
    }

    if path.ends_with("/submit") && request.method() == hyper::Method::POST {
        let body = match axum::body::to_bytes(request.into_body(), 16 * 1024).await {
            Ok(body) => body,
            Err(_) => {
                return json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    serde_json::json!({"code": 413, "message": "challenge payload too large"}),
                )
            }
        };
        let submit = match serde_json::from_slice::<ChallengeSubmit>(&body) {
            Ok(submit) => submit,
            Err(_) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"code": 400, "message": "invalid challenge payload"}),
                )
            }
        };
        let mut challenges = match state.verification.challenges.lock() {
            Ok(challenges) => challenges,
            Err(_) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({"code": 500, "message": "verification unavailable"}),
                )
            }
        };
        let Some(challenge) = challenges.get_mut(&submit.challenge_id) else {
            return json_response(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": 400, "message": "invalid challenge"}),
            );
        };
        let now = unix_now();
        if challenge.attempts >= state.verification.config.max_attempts {
            note_challenge_failure(&state, remote.ip(), site);
            return json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({"code": 403, "message": "challenge rejected"}),
            );
        }
        challenge.attempts += 1;
        if !constant_time_eq(challenge.signature.as_bytes(), submit.signature.as_bytes())
            || challenge.expires_at <= now
            || challenge.site != site
            || challenge.verify_path != path.trim_end_matches("/submit")
            || (state.verification.config.bind_ip && challenge.remote_ip != remote.ip())
        {
            note_challenge_failure(&state, remote.ip(), site);
            return json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({"code": 403, "message": "challenge rejected"}),
            );
        }
        if !verify_pow(
            challenge,
            submit.counter,
            state.verification.config.pow_difficulty,
        ) {
            note_challenge_failure(&state, remote.ip(), site);
            return json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({"code": 403, "message": "challenge failed"}),
            );
        }
        let challenge = challenges
            .remove(&submit.challenge_id)
            .expect("challenge exists while locked");
        state.security.clear_risk(remote.ip(), site);
        return issue_cookie_response(
            &state,
            &challenge.site,
            remote.ip(),
            &challenge.id,
            &challenge.return_path,
        );
    }

    response_with(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        "not found",
    )
}
