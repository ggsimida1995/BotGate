use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use url::Url;

use crate::storage::StorageConfig;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) server: ServerConfig,
    #[serde(default)]
    pub(crate) upstream: UpstreamPolicy,
    #[serde(default)]
    pub(crate) verification: VerificationConfig,
    #[serde(default)]
    pub(crate) security: SecurityConfig,
    #[serde(default)]
    pub(crate) storage: StorageConfig,
    #[serde(default)]
    pub(crate) admin: AdminConfig,
    #[serde(default)]
    pub(crate) update: UpdateConfig,
    #[serde(default)]
    pub(crate) license: LicenseConfig,
    #[serde(default)]
    pub(crate) tls: TlsConfig,
    #[serde(default)]
    pub(crate) nginx: NginxConfig,
    #[serde(default)]
    pub(crate) sites: Vec<SiteConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct UpdateConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) release_url: String,
}

pub(crate) const DEFAULT_RELEASE_URL: &str =
    "https://api.github.com/repos/ggsimida1995/BotGate/releases/latest";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LicenseConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) public_key: String,
    #[serde(default = "default_license_file")]
    pub(crate) file: String,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_key: String::new(),
            file: default_license_file(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TlsConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default = "default_tls_listen")]
    pub(crate) listen: String,
    #[serde(default = "default_tls_cert_file")]
    pub(crate) cert_file: String,
    #[serde(default = "default_tls_key_file")]
    pub(crate) key_file: String,
    #[serde(default)]
    pub(crate) redirect_http: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_tls_listen(),
            cert_file: default_tls_cert_file(),
            key_file: default_tls_key_file(),
            redirect_http: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AdminConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_admin_listen")]
    pub(crate) listen: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_admin_listen(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NginxConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default = "default_nginx_vhost_dir")]
    pub(crate) vhost_dir: String,
    #[serde(default = "default_nginx_binary")]
    pub(crate) binary: String,
    #[serde(default)]
    pub(crate) config_file: String,
    #[serde(default = "default_nginx_include_dir")]
    pub(crate) include_dir: String,
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vhost_dir: default_nginx_vhost_dir(),
            binary: default_nginx_binary(),
            config_file: String::new(),
            include_dir: default_nginx_include_dir(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ServerConfig {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    #[serde(default = "default_request_timeout")]
    pub(crate) request_timeout_secs: u64,
    #[serde(default = "default_header_bytes")]
    pub(crate) max_header_bytes: usize,
    #[serde(default = "default_body_bytes")]
    pub(crate) max_body_size: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            request_timeout_secs: default_request_timeout(),
            max_header_bytes: default_header_bytes(),
            max_body_size: default_body_bytes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UpstreamPolicy {
    #[serde(default = "default_true")]
    pub(crate) allow_loopback: bool,
    #[serde(default = "default_true")]
    pub(crate) allow_private_networks: bool,
    #[serde(default = "default_true")]
    pub(crate) allow_dns: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VerificationConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_cookie_name")]
    pub(crate) cookie_name: String,
    #[serde(
        rename = "cookie_ttl",
        alias = "cookie_ttl_secs",
        default = "default_cookie_ttl",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub(crate) cookie_ttl_secs: u64,
    #[serde(
        rename = "challenge_ttl",
        alias = "challenge_ttl_secs",
        default = "default_challenge_ttl",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub(crate) challenge_ttl_secs: u64,
    #[serde(default = "default_max_attempts")]
    pub(crate) max_attempts: u32,
    #[serde(default = "default_pow_difficulty")]
    pub(crate) pow_difficulty: u8,
    #[serde(default = "default_true")]
    pub(crate) bind_ip: bool,
    #[serde(default = "default_secret_file")]
    pub(crate) secret_file: String,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cookie_name: default_cookie_name(),
            cookie_ttl_secs: default_cookie_ttl(),
            challenge_ttl_secs: default_challenge_ttl(),
            max_attempts: default_max_attempts(),
            pow_difficulty: default_pow_difficulty(),
            bind_ip: true,
            secret_file: default_secret_file(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct SecurityConfig {
    #[serde(default)]
    pub(crate) rate_limit: RateLimitConfig,
    #[serde(default)]
    pub(crate) scanner_detection: ScannerConfig,
    #[serde(default)]
    pub(crate) ban: BanConfig,
    #[serde(default)]
    pub(crate) whitelist: WhitelistConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_requests_per_second")]
    pub(crate) requests_per_second: f64,
    #[serde(default = "default_burst")]
    pub(crate) burst: u32,
    #[serde(default)]
    pub(crate) skip_whitelist: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
            skip_whitelist: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ScannerConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_max_404_per_minute")]
    pub(crate) max_404_per_minute: u32,
    #[serde(default = "default_max_distinct_paths_per_minute")]
    pub(crate) max_distinct_paths_per_minute: u32,
    #[serde(default = "default_risk_limit_threshold")]
    pub(crate) risk_limit_threshold: u32,
    #[serde(default = "default_risk_challenge_threshold")]
    pub(crate) risk_challenge_threshold: u32,
    #[serde(default = "default_risk_ban_threshold")]
    pub(crate) risk_ban_threshold: u32,
    #[serde(default = "default_sensitive_paths")]
    pub(crate) sensitive_paths: Vec<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_404_per_minute: default_max_404_per_minute(),
            max_distinct_paths_per_minute: default_max_distinct_paths_per_minute(),
            risk_limit_threshold: default_risk_limit_threshold(),
            risk_challenge_threshold: default_risk_challenge_threshold(),
            risk_ban_threshold: default_risk_ban_threshold(),
            sensitive_paths: default_sensitive_paths(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BanConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(
        rename = "duration",
        alias = "duration_secs",
        default = "default_ban_duration",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub(crate) duration_secs: u64,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            duration_secs: default_ban_duration(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct WhitelistConfig {
    #[serde(default)]
    pub(crate) ips: Vec<String>,
    #[serde(default)]
    pub(crate) networks: Vec<String>,
    #[serde(default = "default_true")]
    pub(crate) skip_challenge: bool,
    #[serde(default)]
    pub(crate) skip_rate_limit: bool,
}

impl Default for WhitelistConfig {
    fn default() -> Self {
        Self {
            ips: Vec::new(),
            networks: Vec::new(),
            skip_challenge: true,
            skip_rate_limit: false,
        }
    }
}

impl Default for UpstreamPolicy {
    fn default() -> Self {
        Self {
            allow_loopback: true,
            allow_private_networks: true,
            allow_dns: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SiteConfig {
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default = "default_site_mode")]
    pub(crate) mode: String,
    #[serde(default = "default_policy")]
    pub(crate) policy: String,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

pub(crate) fn is_valid_site_mode(mode: &str) -> bool {
    matches!(mode, "proxy" | "nginx")
}

pub(crate) fn default_nginx_vhost_dir() -> String {
    // Empty means the adapter discovers the files loaded by `nginx -T`.
    // Never assume a panel or a platform-specific install layout here.
    String::new()
}

pub(crate) fn default_nginx_binary() -> String {
    "nginx".to_string()
}

pub(crate) fn default_nginx_include_dir() -> String {
    // Resolved relative to the Bot Gate config file.
    "data/nginx".to_string()
}

pub(crate) fn default_site_mode() -> String {
    "proxy".to_string()
}

pub(crate) fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

pub(crate) fn default_request_timeout() -> u64 {
    30
}

pub(crate) fn default_header_bytes() -> usize {
    64 * 1024
}

pub(crate) fn default_body_bytes() -> u64 {
    100 * 1024 * 1024
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_policy() -> String {
    "normal".to_string()
}

pub(crate) fn default_cookie_name() -> String {
    "bot_verified".to_string()
}

pub(crate) fn default_cookie_ttl() -> u64 {
    30 * 60
}

pub(crate) fn default_challenge_ttl() -> u64 {
    60
}

pub(crate) fn default_max_attempts() -> u32 {
    5
}

pub(crate) fn default_pow_difficulty() -> u8 {
    4
}

pub(crate) fn default_secret_file() -> String {
    "data/secret.key".to_string()
}

pub(crate) fn default_admin_listen() -> String {
    "127.0.0.1:8081".to_string()
}

pub(crate) fn default_tls_listen() -> String {
    "127.0.0.1:8443".to_string()
}

pub(crate) fn default_tls_cert_file() -> String {
    "data/tls/cert.pem".to_string()
}

pub(crate) fn default_tls_key_file() -> String {
    "data/tls/key.pem".to_string()
}

pub(crate) fn default_license_file() -> String {
    "data/license.key".to_string()
}

pub(crate) fn default_requests_per_second() -> f64 {
    10.0
}

pub(crate) fn default_burst() -> u32 {
    20
}

pub(crate) fn default_max_404_per_minute() -> u32 {
    30
}

pub(crate) fn default_max_distinct_paths_per_minute() -> u32 {
    60
}

pub(crate) fn default_risk_limit_threshold() -> u32 {
    50
}

pub(crate) fn default_risk_challenge_threshold() -> u32 {
    70
}

pub(crate) fn default_risk_ban_threshold() -> u32 {
    90
}

pub(crate) fn default_sensitive_paths() -> Vec<String> {
    [
        "/.env",
        "/.git/",
        "/wp-admin",
        "/phpmyadmin",
        "/admin",
        "/actuator",
        "/swagger",
        "/swagger-ui",
        "/api-docs",
        "/backup",
        "/config",
        "/test",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub(crate) fn default_ban_duration() -> u64 {
    10 * 60
}

pub(crate) fn deserialize_duration_secs<'de, D>(
    deserializer: D,
) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;

    impl<'de> de::Visitor<'de> for DurationVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a positive duration such as 7d or 30m")
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value == 0 {
                Err(E::custom("duration must be greater than zero"))
            } else {
                Ok(value)
            }
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_duration_secs(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

pub(crate) fn parse_duration_secs(value: &str) -> Result<u64> {
    let value = value.trim();
    let (number, multiplier) = if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 60 * 60)
    } else if let Some(value) = value.strip_suffix('d') {
        (value, 24 * 60 * 60)
    } else {
        bail!("duration must end with s, m, h or d")
    };
    let number: u64 = number.trim().parse().context("invalid duration number")?;
    if number == 0 {
        bail!("duration must be greater than zero");
    }
    number
        .checked_mul(multiplier)
        .context("duration is too large")
}

pub(crate) fn validate_tls(config: &Config) -> Result<()> {
    if !config.tls.enabled {
        if config.tls.redirect_http {
            bail!("tls.redirect_http requires tls.enabled = true");
        }
        return Ok(());
    }
    let tls_listen: SocketAddr = config
        .tls
        .listen
        .parse()
        .with_context(|| format!("invalid tls.listen: {}", config.tls.listen))?;
    let server_listen: SocketAddr = config
        .server
        .listen
        .parse()
        .with_context(|| format!("invalid server.listen: {}", config.server.listen))?;
    if tls_listen == server_listen {
        bail!("tls.listen must differ from server.listen");
    }
    if config.tls.cert_file.trim().is_empty() || config.tls.key_file.trim().is_empty() {
        bail!("tls.cert_file and tls.key_file must not be empty");
    }
    Ok(())
}

const MAX_COOKIE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_CHALLENGE_TTL_SECS: u64 = 10 * 60;

pub(crate) fn load_config(path: &Path) -> Result<Config> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let mut config: Config = toml::from_str(&source)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    resolve_relative_paths(&mut config, path);
    validate_config(&config)?;
    Ok(config)
}

fn resolve_relative_paths(config: &mut Config, config_path: &Path) {
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    for value in [
        &mut config.verification.secret_file,
        &mut config.storage.database,
        &mut config.license.file,
        &mut config.tls.cert_file,
        &mut config.tls.key_file,
        &mut config.nginx.config_file,
        &mut config.nginx.vhost_dir,
        &mut config.nginx.include_dir,
    ] {
        let path = Path::new(value.as_str());
        if !value.is_empty() && path.is_relative() {
            *value = base.join(path).to_string_lossy().into_owned();
        }
    }
}

pub(crate) fn validate_config(config: &Config) -> Result<()> {
    if config.server.max_header_bytes == 0 || config.server.max_header_bytes > 1024 * 1024 {
        bail!("server.max_header_bytes must be between 1 and 1048576");
    }
    if config.server.max_body_size == 0 {
        bail!("server.max_body_size must be greater than zero");
    }
    let admin_listen: SocketAddr = config
        .admin
        .listen
        .parse()
        .with_context(|| format!("invalid admin.listen: {}", config.admin.listen))?;
    if config.admin.enabled && !admin_listen.ip().is_loopback() {
        bail!("admin.listen must use a loopback address");
    }
    validate_tls(config)?;
    validate_nginx_config(&config.nginx)?;
    if config.verification.cookie_name.is_empty()
        || config.verification.cookie_name.len() > 64
        || config
            .verification
            .cookie_name
            .contains([';', ',', ' ', '\r', '\n'])
    {
        bail!("verification.cookie_name is invalid");
    }
    if config.verification.cookie_ttl_secs == 0
        || config.verification.challenge_ttl_secs == 0
        || config.verification.max_attempts == 0
    {
        bail!("verification TTLs and max_attempts must be greater than zero");
    }
    if config.verification.cookie_ttl_secs > MAX_COOKIE_TTL_SECS
        || config.verification.challenge_ttl_secs > MAX_CHALLENGE_TTL_SECS
    {
        bail!("verification TTL exceeds the safe configured maximum");
    }
    if config.verification.pow_difficulty > 24 {
        bail!("verification.pow_difficulty must be between 0 and 24");
    }
    if !config.security.rate_limit.requests_per_second.is_finite()
        || config.security.rate_limit.requests_per_second <= 0.0
        || config.security.rate_limit.burst == 0
    {
        bail!("security.rate_limit must have a positive finite rate and burst");
    }
    if config.security.scanner_detection.max_404_per_minute == 0
        || config
            .security
            .scanner_detection
            .max_distinct_paths_per_minute
            == 0
        || config.security.scanner_detection.risk_limit_threshold == 0
        || config.security.scanner_detection.risk_challenge_threshold == 0
        || config.security.scanner_detection.risk_ban_threshold == 0
        || config.security.scanner_detection.risk_limit_threshold
            >= config.security.scanner_detection.risk_challenge_threshold
        || config.security.scanner_detection.risk_challenge_threshold
            >= config.security.scanner_detection.risk_ban_threshold
    {
        bail!("scanner risk thresholds must be positive and ordered");
    }
    if config.security.ban.duration_secs == 0 {
        bail!("security.ban.duration must be greater than zero");
    }
    if config.license.enabled {
        if config.license.public_key.trim().is_empty() {
            bail!("license.public_key is required when license.enabled = true");
        }
        if config.license.file.trim().is_empty() {
            bail!("license.file must not be empty when license.enabled = true");
        }
    }
    for ip in &config.security.whitelist.ips {
        ip.parse::<IpAddr>()
            .with_context(|| format!("invalid whitelist IP: {ip}"))?;
    }
    for network in &config.security.whitelist.networks {
        network
            .parse::<IpNet>()
            .with_context(|| format!("invalid whitelist network: {network}"))?;
    }
    if config
        .security
        .scanner_detection
        .sensitive_paths
        .iter()
        .any(|path| {
            path.is_empty()
                || path.len() > 256
                || !path.starts_with('/')
                || path.contains(['\r', '\n'])
        })
    {
        bail!("scanner sensitive_paths must be short absolute paths");
    }

    let mut hosts = HashMap::new();
    for site in &config.sites {
        let host = normalize_host(&site.host).context("invalid site host")?;
        if !hosts.insert(host.clone(), ()).is_none() {
            bail!("duplicate site host: {host}");
        }
        if !is_valid_site_mode(&site.mode) {
            bail!("invalid site mode for {host}: {}", site.mode);
        }
        if site.mode == "proxy" {
            validate_upstream(&site.target, &config.upstream)
                .with_context(|| format!("invalid upstream for {host}"))?;
        } else if !site.target.trim().is_empty() {
            bail!("nginx mode must not define an upstream for {host}");
        }
    }
    Ok(())
}

pub(crate) fn validate_nginx_config(config: &NginxConfig) -> Result<()> {
    if config.enabled && (config.include_dir.trim().is_empty() || config.binary.trim().is_empty()) {
        bail!("nginx.include_dir and nginx.binary are required when nginx.enabled = true");
    }
    Ok(())
}

pub(crate) fn validate_upstream(target: &str, policy: &UpstreamPolicy) -> Result<()> {
    let url = Url::parse(target).context("target must be an absolute URL")?;
    if url.scheme() != "http" {
        bail!("phase 1 only supports http upstreams");
    }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        bail!("upstream credentials and fragments are not allowed");
    }
    if url.path() != "" && url.path() != "/" {
        bail!("upstream path prefixes are not supported in phase 1");
    }
    let host = url.host_str().context("upstream host is required")?;
    if host.eq_ignore_ascii_case("localhost") {
        if !policy.allow_loopback {
            bail!("loopback upstreams are disabled");
        }
        return Ok(());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if allowed_upstream_ip(ip, policy) {
            Ok(())
        } else {
            if is_private_or_link_local(ip) {
                bail!("upstream address is not allowed by the SSRF policy; enable upstream.allow_private_networks for LAN targets")
            }
            bail!("upstream address is not allowed by the SSRF policy")
        };
    }
    if !policy.allow_dns {
        bail!("DNS upstreams are disabled by the SSRF policy; enable upstream.allow_dns for local hostnames");
    }
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("invalid DNS upstream hostname");
    }
    Ok(())
}

fn allowed_upstream_ip(ip: IpAddr, policy: &UpstreamPolicy) -> bool {
    (ip.is_loopback() && policy.allow_loopback)
        || (is_private_or_link_local(ip) && policy.allow_private_networks)
}

pub(crate) async fn resolve_upstream_ip(target: &Url, policy: &UpstreamPolicy) -> Result<IpAddr> {
    let host = target.host_str().context("upstream host is required")?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if allowed_upstream_ip(ip, policy) {
            return Ok(ip);
        }
        if is_private_or_link_local(ip) {
            bail!("upstream address is not allowed by the SSRF policy; enable upstream.allow_private_networks for LAN targets");
        }
        bail!("upstream address is not allowed by the SSRF policy");
    }
    if !host.eq_ignore_ascii_case("localhost") && !policy.allow_dns {
        bail!("DNS upstreams are disabled by the SSRF policy; enable upstream.allow_dns for local hostnames");
    }
    let port = target
        .port_or_known_default()
        .context("upstream port is required")?;
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve upstream hostname {host}"))?;
    addresses
        .find_map(|address| allowed_upstream_ip(address.ip(), policy).then_some(address.ip()))
        .context("upstream DNS resolution returned no allowed address")
}

fn is_private_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

pub(crate) fn normalize_host(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 255 || raw.contains(['/', '\\', '\r', '\n']) {
        bail!("invalid host");
    }
    let host = if raw.starts_with('[') {
        let end = raw.find(']').context("invalid IPv6 host")?;
        &raw[1..end]
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            host
        } else {
            raw
        }
    } else {
        raw
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        bail!("invalid host");
    }
    if host.parse::<IpAddr>().is_err()
        && host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
        })
    {
        bail!("invalid host");
    }
    Ok(host)
}
