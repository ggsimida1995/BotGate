use super::*;
use url::Url;

#[test]
fn normalizes_host_and_port() {
    assert_eq!(
        normalize_host("Project-A.TEST:8080").unwrap(),
        "project-a.test"
    );
    assert_eq!(normalize_host("project-a.test.").unwrap(), "project-a.test");
}

#[test]
fn classifies_static_assets_without_treating_pages_as_assets() {
    assert!(is_static_asset_path("/assets/app.js"));
    assert!(is_static_asset_path("/assets/site.css"));
    assert!(is_static_asset_path("/@vite/client"));
    assert!(!is_static_asset_path("/"));
    assert!(!is_static_asset_path("/dashboard"));
    assert!(!is_static_asset_path("/api/user.json"));
}

#[test]
fn falls_back_for_unavailable_configured_listener_ports() {
    assert!(should_try_ephemeral_port(
        &std::io::Error::from(ErrorKind::AddrInUse),
        8080
    ));
    assert!(should_try_ephemeral_port(
        &std::io::Error::from(ErrorKind::PermissionDenied),
        8080
    ));
    assert!(!should_try_ephemeral_port(
        &std::io::Error::from(ErrorKind::PermissionDenied),
        0
    ));
    assert!(!should_try_ephemeral_port(
        &std::io::Error::from(ErrorKind::Other),
        8080
    ));
}

#[tokio::test]
async fn falls_back_when_configured_listener_is_already_bound() {
    let occupied = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let configured = occupied.local_addr().unwrap();
    let (_listener, actual) = bind_listener(&configured.to_string(), "test")
        .await
        .unwrap();
    assert_eq!(actual.ip(), configured.ip());
    assert_ne!(actual.port(), configured.port());
}

#[test]
fn logs_only_abnormal_static_asset_requests() {
    assert!(!should_record_request_log(
        "/assets/app.js",
        StatusCode::OK,
        false
    ));
    assert!(should_record_request_log(
        "/assets/app.js",
        StatusCode::FORBIDDEN,
        false
    ));
    assert!(should_record_request_log(
        "/assets/app.js",
        StatusCode::OK,
        true
    ));
    assert!(should_record_request_log(
        "/dashboard",
        StatusCode::OK,
        false
    ));
}

#[test]
fn validates_upstream_policy_boundaries() {
    let policy = UpstreamPolicy::default();
    assert!(validate_upstream("file:///tmp/app", &policy).is_err());
    assert!(validate_upstream("http://192.168.1.10:9000", &policy).is_ok());
    assert!(validate_upstream("http://backend.test:9000", &policy).is_ok());
    assert!(validate_upstream("http://8.8.8.8:53", &policy).is_err());
    let mut hardened_policy = policy.clone();
    hardened_policy.allow_private_networks = false;
    hardened_policy.allow_dns = false;
    assert!(validate_upstream("http://192.168.1.10:9000", &hardened_policy).is_err());
    assert!(validate_upstream("http://backend.test:9000", &hardened_policy).is_err());
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
        verify_path: "/random".to_string(),
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

#[test]
fn startup_log_path_is_next_to_the_config() {
    let config = std::path::Path::new("/tmp/BotGate/config.toml");
    assert_eq!(
        startup_log_path(config),
        std::path::PathBuf::from("/tmp/BotGate/logs/bot-gate.log")
    );
}

#[test]
fn startup_failure_message_points_to_full_log() {
    let error = anyhow::anyhow!("failed to bind gateway listener 127.0.0.1:8080");
    let message = startup_error_message(
        &error,
        std::path::Path::new(r"C:\ProgramData\BotGate\logs\bot-gate.log"),
    );
    assert!(message.contains("failed to bind gateway listener 127.0.0.1:8080"));
    assert!(message.contains(r"C:\ProgramData\BotGate\logs\bot-gate.log"));
}
