use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, client::conn::http1, header, Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpStream;
use url::Url;

use crate::config::CaddyConfig;

pub(crate) async fn set_site_protection(
    config: &CaddyConfig,
    host: &str,
    target: &str,
    protected: bool,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let routes_path = format!(
        "/config/apps/http/servers/{}/routes",
        config.server.trim_matches('/')
    );
    let routes = request_json(config, Method::GET, &routes_path, None).await?;
    let mut path = Vec::new();
    let upstream_path = find_upstreams(&routes, host, &mut path, false)
        .context("Caddy route for site was not found")?;
    let upstream = if protected {
        config.gate_upstream.clone()
    } else {
        upstream_dial(target)?
    };
    let patch_path = format!(
        "{}/{}",
        routes_path,
        upstream_path
            .into_iter()
            .map(|part| part.trim_matches('/').to_string())
            .collect::<Vec<_>>()
            .join("/")
    );
    request_json(
        config,
        Method::PATCH,
        &patch_path,
        Some(serde_json::json!([{ "dial": upstream }])),
    )
    .await?;
    Ok(())
}

fn upstream_dial(target: &str) -> Result<String> {
    let url = Url::parse(target).context("invalid site upstream URL")?;
    let host = url.host_str().context("site upstream host is missing")?;
    let port = url
        .port_or_known_default()
        .context("site upstream port is missing")?;
    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn find_upstreams(
    value: &Value,
    host: &str,
    path: &mut Vec<String>,
    matched: bool,
) -> Option<Vec<String>> {
    match value {
        Value::Object(object) => {
            let matched = matched || route_matches_host(object.get("match"), host);
            if matched
                && object.get("handler").and_then(Value::as_str) == Some("reverse_proxy")
                && object.get("upstreams").is_some_and(Value::is_array)
            {
                let mut result = path.clone();
                result.push("upstreams".to_string());
                return Some(result);
            }
            for (key, child) in object {
                path.push(key.clone());
                if let Some(result) = find_upstreams(child, host, path, matched) {
                    return Some(result);
                }
                path.pop();
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                path.push(index.to_string());
                if let Some(result) = find_upstreams(child, host, path, matched) {
                    return Some(result);
                }
                path.pop();
            }
        }
        _ => {}
    }
    None
}

fn route_matches_host(value: Option<&Value>, host: &str) -> bool {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|items| items.iter())
        .filter_map(|item| item.get("host").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .any(|value| value.eq_ignore_ascii_case(host))
}

async fn request_json(
    config: &CaddyConfig,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let body = body.map(|value| Bytes::from(value.to_string()));
    let response = if let Some(socket_path) = config.admin_api.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(socket_path)
                .await
                .with_context(|| format!("failed to connect to Caddy socket {socket_path}"))?;
            send_request(stream, method, path, body).await?
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            bail!("unix:// Caddy Admin API is only supported on Unix")
        }
    } else {
        let api = Url::parse(&config.admin_api).context("invalid Caddy Admin API URL")?;
        if api.scheme() != "http" {
            bail!("Caddy Admin API must use http:// or unix://")
        }
        let host = api.host_str().context("Caddy Admin API host is missing")?;
        let port = api.port_or_known_default().unwrap_or(2019);
        let stream = TcpStream::connect((host, port))
            .await
            .with_context(|| format!("failed to connect to Caddy Admin API {host}:{port}"))?;
        send_request(stream, method, path, body).await?
    };
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .context("failed to read Caddy Admin API response")?
        .to_bytes();
    if !status.is_success() {
        bail!(
            "Caddy Admin API returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&bytes).context("Caddy Admin API returned invalid JSON")
    }
}

async fn send_request<S>(
    stream: S,
    method: Method,
    path: &str,
    body: Option<Bytes>,
) -> Result<Response<Incoming>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http1::handshake(io)
        .await
        .context("Caddy Admin API HTTP handshake failed")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let body = body.map_or_else(|| Full::new(Bytes::new()), Full::new);
    let request = Request::builder()
        .method(method)
        .uri(
            path.parse::<Uri>()
                .context("invalid Caddy Admin API path")?,
        )
        .header(header::HOST, "127.0.0.1")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONNECTION, "close")
        .body(body)
        .context("failed to build Caddy Admin API request")?;
    sender
        .send_request(request)
        .await
        .context("Caddy Admin API request failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_host_route_upstreams() {
        let value = serde_json::json!([{
            "match": [{"host": ["cool.com"]}],
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8080"}]}]
        }]);
        let mut path = Vec::new();
        assert_eq!(
            find_upstreams(&value, "cool.com", &mut path, false),
            Some(
                vec!["0", "handle", "0", "upstreams"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
    }
}
