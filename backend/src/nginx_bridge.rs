use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    response::Response,
};
use hyper::{header, Method, Request, StatusCode};

use crate::{
    cookie_from_request, effective_remote, is_api_request, json_response, response_with,
    verification::verification_redirect_for_path, verify_cookie, AppState,
};

pub(crate) async fn check(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return response_with(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found",
        );
    }
    let remote = effective_remote(remote, &request);
    let Some((host, path, method, site)) = context(&state, &request) else {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .expect("valid response");
    };
    if !site.enabled {
        return allow();
    }
    if state.license.enabled && crate::license::status(&state.license).status != "active" {
        return deny();
    }
    let verified = state.verification.config.enabled
        && cookie_from_request(&request, &state.verification.config.cookie_name).is_some_and(
            |value| {
                verify_cookie(
                    &value,
                    &state.verification.config,
                    &state.verification.secret,
                    &host,
                    remote.ip(),
                    crate::unix_now(),
                )
            },
        );
    if verified || !state.verification.config.enabled {
        return allow();
    }
    if state.security.active_ban(remote.ip()).is_some() {
        return deny();
    }
    let whitelist = state.security.whitelist_rule(remote.ip());
    if !state
        .security
        .allow_rate(remote.ip(), &host, &path, whitelist.as_ref())
    {
        return deny();
    }
    let risk = state
        .security
        .observe_request(remote.ip(), &host, &method, &path);
    if risk >= state.security.config.scanner_detection.risk_ban_threshold {
        state
            .security
            .ban(remote.ip(), format!("risk score {risk}"));
        return deny();
    }
    if risk >= state.security.config.scanner_detection.risk_limit_threshold {
        return deny();
    }
    if is_navigation(&request, &path, &method) {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .expect("valid response")
    } else {
        deny()
    }
}

pub(crate) async fn challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return response_with(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found",
        );
    }
    let remote = effective_remote(remote, &request);
    let Some((host, path, method, site)) = context(&state, &request) else {
        return deny();
    };
    if !site.enabled || !is_navigation(&request, &path, &method) {
        return deny();
    }
    verification_redirect_for_path(&state, remote.ip(), &host, path)
}

pub(crate) async fn deny_page(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !remote.ip().is_loopback() {
        return response_with(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found",
        );
    }
    let Some((_, path, method, _)) = context(&state, &request) else {
        return deny();
    };
    if is_navigation(&request, &path, &method) {
        response_with(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            "browser verification required",
        )
    } else {
        json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({"code":403,"message":"browser verification required"}),
        )
    }
}

fn context(
    state: &AppState,
    request: &Request<Body>,
) -> Option<(String, String, Method, crate::SiteConfig)> {
    let host = request
        .headers()
        .get(header::HOST)?
        .to_str()
        .ok()
        .and_then(|value| crate::normalize_host(value).ok())?;
    let site = state.sites.read().ok()?.get(&host).cloned()?;
    if site.mode != "nginx" {
        return None;
    }
    let path = request
        .headers()
        .get("x-bot-gate-original-uri")
        .and_then(|value| value.to_str().ok())
        .map(|value| crate::verification::valid_return_path(Some(value)))
        .unwrap_or_else(|| "/".to_string());
    let method = request
        .headers()
        .get("x-bot-gate-original-method")
        .and_then(|value| value.as_bytes().try_into().ok())
        .and_then(|value: &[u8]| Method::from_bytes(value).ok())
        .unwrap_or(Method::GET);
    Some((host, path, method, site))
}

fn is_navigation(request: &Request<Body>, path: &str, method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD)
        && !path.starts_with("/api")
        && !is_api_request(request)
}

fn allow() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .expect("valid response")
}

fn deny() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_is_only_safe_html_traffic() {
        let request = Request::builder()
            .header(header::ACCEPT, "text/html")
            .body(Body::empty())
            .unwrap();
        assert!(is_navigation(&request, "/login", &Method::GET));
        assert!(!is_navigation(&request, "/api/users", &Method::GET));
        assert!(!is_navigation(&request, "/login", &Method::POST));
    }
}
