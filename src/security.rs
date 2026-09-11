use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use hyper::StatusCode;
use ipnet::IpNet;

use crate::{
    config::SecurityConfig,
    storage::{BanRecord, SecurityEvent, Storage},
    unix_now,
};

const MAX_RISK_ENTRIES: usize = 10_000;
const MAX_PATHS_PER_RISK_ENTRY: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Clone)]
pub(crate) struct RiskState {
    window_started: Instant,
    not_found: u32,
    distinct_paths: HashMap<String, ()>,
    score: u32,
    last_seen: Instant,
}

#[derive(Debug, Clone)]
pub(crate) struct BanEntry {
    pub(crate) expires_at: Instant,
    pub(crate) reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct WhitelistRule {
    pub(crate) network: IpNet,
    pub(crate) skip_challenge: bool,
    pub(crate) skip_rate_limit: bool,
}

pub(crate) struct SecurityState {
    pub(crate) config: SecurityConfig,
    pub(crate) buckets: Mutex<HashMap<String, TokenBucket>>,
    pub(crate) risks: Mutex<HashMap<String, RiskState>>,
    pub(crate) bans: Mutex<HashMap<IpAddr, BanEntry>>,
    pub(crate) whitelist: RwLock<Vec<WhitelistRule>>,
    pub(crate) storage: Arc<Storage>,
}

impl SecurityState {
    pub(crate) fn whitelist_rule(&self, ip: IpAddr) -> Option<WhitelistRule> {
        self.whitelist
            .read()
            .ok()?
            .iter()
            .find(|rule| rule.network.contains(&ip))
            .cloned()
    }
    pub(crate) fn set_manual_ban(&self, ip: IpAddr, reason: String, expires_at: u64) {
        let remaining = expires_at.saturating_sub(unix_now());
        if let Ok(mut bans) = self.bans.lock() {
            bans.insert(
                ip,
                BanEntry {
                    expires_at: Instant::now() + Duration::from_secs(remaining),
                    reason,
                },
            );
        }
    }
    pub(crate) fn clear_ban_entry(&self, ip: IpAddr) {
        if let Ok(mut bans) = self.bans.lock() {
            bans.remove(&ip);
        }
    }
    pub(crate) fn active_ban(&self, ip: IpAddr) -> Option<String> {
        let mut bans = self.bans.lock().ok()?;
        let now = Instant::now();
        bans.retain(|_, ban| ban.expires_at > now);
        bans.get(&ip).map(|ban| ban.reason.clone())
    }
    pub(crate) fn ban(&self, ip: IpAddr, reason: impl Into<String>) {
        if !self.config.ban.enabled {
            return;
        }
        let reason = reason.into();
        if let Ok(mut bans) = self.bans.lock() {
            bans.insert(
                ip,
                BanEntry {
                    expires_at: Instant::now() + Duration::from_secs(self.config.ban.duration_secs),
                    reason: reason.clone(),
                },
            );
        }
        self.storage.record_ban(BanRecord {
            ip: ip.to_string(),
            reason: reason.clone(),
            source: "automatic".to_string(),
            created_at: unix_now(),
            expires_at: unix_now().saturating_add(self.config.ban.duration_secs),
        });
        self.storage.record_security(SecurityEvent {
            timestamp: unix_now(),
            remote_ip: ip.to_string(),
            host: String::new(),
            path: String::new(),
            event_type: "ban".to_string(),
            risk_score: 0,
            action: "temporary_ban".to_string(),
            details_redacted: Some(reason),
        });
    }
    pub(crate) fn allow_rate(
        &self,
        ip: IpAddr,
        host: &str,
        path: &str,
        whitelist: Option<&WhitelistRule>,
    ) -> bool {
        let config = &self.config.rate_limit;
        if !config.enabled
            || whitelist.is_some_and(|rule| rule.skip_rate_limit || config.skip_whitelist)
        {
            return true;
        }
        let rate = config.requests_per_second;
        let burst = f64::from(config.burst.max(1));
        let path = path.chars().take(256).collect::<String>();
        let keys = [
            "global".to_string(),
            format!("ip:{ip}"),
            format!("host:{host}"),
            format!("path:{host}:{path}"),
        ];
        let now = Instant::now();
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < Duration::from_secs(300));
        for key in keys {
            let bucket = buckets.entry(key).or_insert(TokenBucket {
                tokens: burst,
                last_refill: now,
            });
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
            bucket.last_refill = now;
            if bucket.tokens < 1.0 {
                return false;
            }
            bucket.tokens -= 1.0;
        }
        true
    }
    pub(crate) fn observe_request(
        &self,
        ip: IpAddr,
        host: &str,
        method: &hyper::Method,
        path: &str,
    ) -> u32 {
        if !self.config.scanner_detection.enabled || path.starts_with("/__bot_verify") {
            return 0;
        }
        let key = format!("{ip}|{host}");
        let now = Instant::now();
        let Ok(mut risks) = self.risks.lock() else {
            return 0;
        };
        risks.retain(|_, risk| now.duration_since(risk.last_seen) < Duration::from_secs(300));
        if risks.len() >= MAX_RISK_ENTRIES && !risks.contains_key(&key) {
            return 0;
        }
        let risk = risks.entry(key).or_insert_with(|| RiskState {
            window_started: now,
            not_found: 0,
            distinct_paths: HashMap::new(),
            score: 0,
            last_seen: now,
        });
        if now.duration_since(risk.window_started) >= Duration::from_secs(60) {
            risk.window_started = now;
            risk.not_found = 0;
            risk.distinct_paths.clear();
            risk.score = 0;
        }
        risk.last_seen = now;
        let path = path.chars().take(256).collect::<String>();
        if risk.distinct_paths.len() < MAX_PATHS_PER_RISK_ENTRY {
            risk.distinct_paths.insert(path.clone(), ());
        }
        if self
            .config
            .scanner_detection
            .sensitive_paths
            .iter()
            .any(|rule| path == *rule || path.starts_with(rule))
        {
            risk.score = risk.score.saturating_add(30);
        }
        if *method == hyper::Method::HEAD || *method == hyper::Method::OPTIONS {
            risk.score = risk.score.saturating_add(10);
        }
        if risk.distinct_paths.len() as u32
            == self.config.scanner_detection.max_distinct_paths_per_minute
        {
            risk.score = risk.score.saturating_add(20);
        }
        risk.score
    }
    pub(crate) fn observe_response(
        &self,
        ip: IpAddr,
        host: &str,
        path: &str,
        status: StatusCode,
    ) -> u32 {
        if !self.config.scanner_detection.enabled || status != StatusCode::NOT_FOUND {
            return 0;
        }
        let key = format!("{ip}|{host}");
        let now = Instant::now();
        let Ok(mut risks) = self.risks.lock() else {
            return 0;
        };
        let Some(risk) = risks.get_mut(&key) else {
            return 0;
        };
        if now.duration_since(risk.window_started) >= Duration::from_secs(60) {
            risk.window_started = now;
            risk.not_found = 0;
            risk.distinct_paths.clear();
            risk.score = 0;
        }
        risk.last_seen = now;
        risk.not_found = risk.not_found.saturating_add(1);
        if risk.not_found == self.config.scanner_detection.max_404_per_minute {
            risk.score = risk.score.saturating_add(20);
        }
        if risk.distinct_paths.len() < MAX_PATHS_PER_RISK_ENTRY {
            risk.distinct_paths
                .insert(path.chars().take(256).collect(), ());
        }
        risk.score
    }
    pub(crate) fn add_risk(&self, ip: IpAddr, host: &str, points: u32) -> u32 {
        if !self.config.scanner_detection.enabled {
            return 0;
        }
        let key = format!("{ip}|{host}");
        let now = Instant::now();
        let Ok(mut risks) = self.risks.lock() else {
            return 0;
        };
        if risks.len() >= MAX_RISK_ENTRIES && !risks.contains_key(&key) {
            return 0;
        }
        let risk = risks.entry(key).or_insert_with(|| RiskState {
            window_started: now,
            not_found: 0,
            distinct_paths: HashMap::new(),
            score: 0,
            last_seen: now,
        });
        if now.duration_since(risk.window_started) >= Duration::from_secs(60) {
            risk.window_started = now;
            risk.not_found = 0;
            risk.distinct_paths.clear();
            risk.score = 0;
        }
        risk.last_seen = now;
        risk.score = risk.score.saturating_add(points);
        risk.score
    }
    pub(crate) fn clear_risk(&self, ip: IpAddr, host: &str) {
        if let Ok(mut risks) = self.risks.lock() {
            risks.remove(&format!("{ip}|{host}"));
        }
    }
}
