use anyhow::{Context, Result};
use axum::{body::Body, response::Response};
use hyper::{
    body::Incoming,
    header::{self, HeaderName, HeaderValue},
    Request, StatusCode, Uri,
};
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
use url::Url;

use crate::{normalize_host, resolve_upstream_ip, AppState, SiteConfig};

pub(crate) fn header_bytes(request: &Request<Body>) -> usize {
    request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}

fn should_forward_request_header(name: &HeaderName, is_upgrade: bool) -> bool {
    !is_hop_by_hop(name)
        || (is_upgrade && (*name == header::CONNECTION || *name == header::UPGRADE))
}

fn sanitized_cookie(value: &HeaderValue, gate_cookie_name: &str) -> Option<HeaderValue> {
    let value = value.to_str().ok()?;
    let cookies = value
        .split(';')
        .filter_map(|item| {
            let item = item.trim();
            let (name, _) = item.split_once('=')?;
            (name != gate_cookie_name).then_some(item)
        })
        .collect::<Vec<_>>();
    if cookies.is_empty() {
        None
    } else {
        HeaderValue::from_str(&cookies.join("; ")).ok()
    }
}

pub(crate) fn https_redirect_response(
    request: &Request<Body>,
    port: u16,
) -> Option<Response<Body>> {
    let raw_host = request.headers().get(header::HOST)?.to_str().ok()?;
    let host = normalize_host(raw_host).ok()?;
    let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, format!("https://{authority}{path}"))
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .ok()
}

fn build_upstream_uri(target: &Url, request_uri: &Uri, connect_ip: IpAddr) -> Result<Uri> {
    let authority = match connect_ip {
        IpAddr::V4(host) => host.to_string(),
        IpAddr::V6(host) => format!("[{host}]"),
    };
    let default_port = if target.scheme() == "https" { 443 } else { 80 };
    let authority = match target.port() {
        Some(port) => format!("{authority}:{port}"),
        None => format!("{authority}:{default_port}"),
    };
    let path = request_uri
        .path_and_query()
        .map_or("/", |value| value.as_str());
    format!("{}://{}{}", target.scheme(), authority, path)
        .parse()
        .context("failed to construct upstream URI")
}

pub(crate) async fn proxy_request(
    state: &AppState,
    mut request: Request<Body>,
    site: &SiteConfig,
    remote: SocketAddr,
    scheme: &str,
) -> Result<Response<Body>> {
    let target = Url::parse(&site.target)?;
    let connect_ip = resolve_upstream_ip(&target, &state.upstream_policy).await?;
    let uri = build_upstream_uri(&target, request.uri(), connect_ip)?;
    let original_host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let is_upgrade = request.headers().contains_key(header::UPGRADE);
    let downstream_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut request));
    let mut builder = Request::builder().method(request.method()).uri(uri);
    let headers = builder
        .headers_mut()
        .context("failed to build proxy headers")?;
    for (name, value) in request.headers() {
        if *name != header::HOST && should_forward_request_header(name, is_upgrade) {
            if *name == header::COOKIE {
                if let Some(value) = sanitized_cookie(value, &state.verification.config.cookie_name)
                {
                    headers.append(name, value);
                }
            } else {
                headers.append(name, value.clone());
            }
        }
    }
    // The request Host has already been normalized and matched to a configured
    // site before this function is called. Preserve it so upstream dev servers
    // (for example Vite's allowedHosts) still see the public hostname.
    headers.insert(header::HOST, HeaderValue::from_str(&original_host)?);
    headers.insert(
        HeaderName::from_static("x-real-ip"),
        HeaderValue::from_str(&remote.ip().to_string())?,
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&remote.ip().to_string())?,
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_str(scheme)?,
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(&original_host)?,
    );

    let request = builder.body(request.into_body())?;
    let mut response = tokio::time::timeout(state.request_timeout, state.client.request(request))
        .await
        .context("upstream request timed out")??;
    let upstream_upgrade = (is_upgrade && response.status() == StatusCode::SWITCHING_PROTOCOLS)
        .then(|| hyper::upgrade::on(&mut response));
    if let (Some(downstream_upgrade), Some(upstream_upgrade)) =
        (downstream_upgrade, upstream_upgrade)
    {
        tokio::spawn(async move {
            let (Ok(downstream), Ok(upstream)) = tokio::join!(downstream_upgrade, upstream_upgrade)
            else {
                return;
            };
            let mut downstream = TokioIo::new(downstream);
            let mut upstream = TokioIo::new(upstream);
            let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
        });
    }
    Ok(strip_response_headers(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_upgrade_headers_only_for_upgraded_requests() {
        assert!(!should_forward_request_header(&header::UPGRADE, false));
        assert!(!should_forward_request_header(&header::CONNECTION, false));
        assert!(should_forward_request_header(&header::UPGRADE, true));
        assert!(should_forward_request_header(&header::CONNECTION, true));
        assert!(should_forward_request_header(&header::ACCEPT, false));
    }
}

fn strip_response_headers(response: hyper::Response<Incoming>) -> Response<Body> {
    let preserve_upgrade_headers = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let (parts, body) = response.into_parts();
    let mut response = Response::from_parts(parts, Body::new(body));
    let remove = response
        .headers()
        .keys()
        .filter(|name| {
            is_hop_by_hop(name)
                && !(preserve_upgrade_headers
                    && (*name == header::CONNECTION || *name == header::UPGRADE))
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in remove {
        response.headers_mut().remove(name);
    }
    response
}
