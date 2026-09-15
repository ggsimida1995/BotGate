use axum::{body::Body, response::Response};
use hyper::{header, Request, StatusCode};

pub(crate) fn cookie_from_request(request: &Request<Body>, name: &str) -> Option<String> {
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

pub(crate) fn is_static_asset_path(path: &str) -> bool {
    let extension = path
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension);
    matches!(
        extension,
        Some(
            "css"
                | "js"
                | "mjs"
                | "jsx"
                | "ts"
                | "tsx"
                | "map"
                | "wasm"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "webp"
                | "avif"
                | "ico"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "eot"
                | "mp3"
                | "mp4"
                | "webm"
        )
    ) || path.starts_with("/@vite/")
}

pub(crate) fn response_with(
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

pub(crate) fn rate_limited_response() -> Response<Body> {
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
