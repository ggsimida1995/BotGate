use std::{
    net::IpAddr,
    path::Path,
    sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use serde::{de, Deserialize, Deserializer, Serialize};

const REQUEST_QUEUE: usize = 4096;
const LOG_BATCH_SIZE: usize = 100;

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_database")]
    pub database: String,
    #[serde(
        rename = "log_retention",
        alias = "log_retention_secs",
        default = "default_retention",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub log_retention_secs: u64,
    #[serde(default = "default_true")]
    pub persist_request_logs: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database: default_database(),
            log_retention_secs: default_retention(),
            persist_request_logs: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedBan {
    pub ip: IpAddr,
    pub expires_at: u64,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RequestLog {
    pub timestamp: u64,
    pub remote_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub verified: bool,
    pub blocked: bool,
    pub reason: Option<String>,
    pub user_agent: Option<String>,
    pub latency_ms: u64,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestLogRecord {
    pub id: i64,
    pub timestamp: u64,
    pub remote_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub verified: bool,
    pub blocked: bool,
    pub reason: Option<String>,
    pub user_agent: Option<String>,
    pub latency_ms: u64,
    pub risk_score: u32,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub remote_ip: String,
    pub host: String,
    pub path: String,
    pub event_type: String,
    pub risk_score: u32,
    pub action: String,
    pub details_redacted: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEventRecord {
    pub id: i64,
    pub timestamp: u64,
    pub remote_ip: String,
    pub host: String,
    pub path: String,
    pub event_type: String,
    pub risk_score: u32,
    pub action: String,
    pub details_redacted: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub search: Option<String>,
    pub host: Option<String>,
    pub remote_ip: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub blocked: Option<bool>,
    pub verified: Option<bool>,
    pub event_type: Option<String>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub page: u32,
    pub page_size: u32,
}

impl LogFilter {
    pub fn normalized_page(&self) -> (u32, u32, u32) {
        let page = self.page.max(1);
        let page_size = self.page_size.clamp(10, 100);
        let offset = page.saturating_sub(1).saturating_mul(page_size);
        (page, page_size, offset)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DashboardStats {
    pub today_requests: u64,
    pub today_verified: u64,
    pub today_blocked: u64,
    pub today_not_found: u64,
    pub today_challenge_failures: u64,
    pub active_bans: u64,
}

#[derive(Debug, Clone)]
pub struct BanRecord {
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct ManagedSite {
    pub host: String,
    pub target: String,
    pub policy: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ManagedWhitelist {
    pub id: i64,
    pub kind: String,
    pub value: String,
    pub skip_challenge: bool,
    pub skip_rate_limit: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ActiveBan {
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub created_at: u64,
    pub expires_at: u64,
}

enum StorageEvent {
    Request(RequestLog),
    Security(SecurityEvent),
    Ban(BanRecord),
}

#[derive(Clone)]
pub struct Storage {
    request_tx: Option<SyncSender<StorageEvent>>,
    security_tx: Option<SyncSender<StorageEvent>>,
    persist_request_logs: bool,
    database: Option<String>,
}

pub struct OpenedStorage {
    pub storage: Storage,
    pub active_bans: Vec<LoadedBan>,
}

impl Storage {
    pub fn disabled() -> Self {
        Self {
            request_tx: None,
            security_tx: None,
            persist_request_logs: false,
            database: None,
        }
    }

    pub fn open(config: &StorageConfig) -> Result<OpenedStorage> {
        if !config.enabled {
            return Ok(OpenedStorage {
                storage: Self::disabled(),
                active_bans: Vec::new(),
            });
        }
        let path = Path::new(&config.database);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create database directory {}", parent.display())
            })?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
        initialize(&connection)?;
        let active_bans = load_active_bans(&connection)?;
        let (request_tx, request_rx) = sync_channel(REQUEST_QUEUE);
        let (security_tx, security_rx) = sync_channel(256);
        let database = config.database.clone();
        let retention = config.log_retention_secs;
        thread::Builder::new()
            .name("bot-gate-sqlite".to_string())
            .spawn(move || writer_loop(database, retention, request_rx, security_rx))
            .context("failed to start SQLite writer thread")?;
        Ok(OpenedStorage {
            storage: Self {
                request_tx: Some(request_tx),
                security_tx: Some(security_tx),
                persist_request_logs: config.persist_request_logs,
                database: Some(config.database.clone()),
            },
            active_bans,
        })
    }

    pub fn record_request(&self, log: RequestLog) {
        if !self.persist_request_logs {
            return;
        }
        let Some(sender) = &self.request_tx else {
            return;
        };
        if let Err(TrySendError::Disconnected(_)) | Err(TrySendError::Full(_)) =
            sender.try_send(StorageEvent::Request(log))
        {
            // ponytail: bounded queue drops ordinary request logs under pressure; security events use a separate blocking queue.
        }
    }

    pub fn record_security(&self, event: SecurityEvent) {
        if let Some(sender) = &self.security_tx {
            let _ = sender.send(StorageEvent::Security(event));
        }
    }

    pub fn record_ban(&self, record: BanRecord) {
        if let Some(sender) = &self.security_tx {
            let _ = sender.send(StorageEvent::Ban(record));
        }
    }

    pub fn dashboard_stats(&self) -> Result<DashboardStats> {
        let Some(database) = &self.database else {
            return Ok(DashboardStats::default());
        };
        let connection = Connection::open(database)
            .with_context(|| format!("failed to open SQLite database {database}"))?;
        let start_of_day = unix_now() / 86_400 * 86_400;
        let today_requests = scalar_count(
            &connection,
            "SELECT count(*) FROM request_logs WHERE timestamp >= ?1",
            start_of_day,
        )?;
        let today_verified = scalar_count(
            &connection,
            "SELECT count(*) FROM request_logs WHERE timestamp >= ?1 AND verified = 1",
            start_of_day,
        )?;
        let today_blocked = scalar_count(
            &connection,
            "SELECT count(*) FROM request_logs WHERE timestamp >= ?1 AND blocked = 1",
            start_of_day,
        )?;
        let today_not_found = scalar_count(
            &connection,
            "SELECT count(*) FROM request_logs WHERE timestamp >= ?1 AND status = 404",
            start_of_day,
        )?;
        let today_challenge_failures = scalar_count(
            &connection,
            "SELECT count(*) FROM security_events WHERE timestamp >= ?1 AND event_type = 'challenge_failure'",
            start_of_day,
        )?;
        let active_bans = scalar_count(
            &connection,
            "SELECT count(*) FROM bans WHERE active = 1 AND expires_at > ?1",
            unix_now(),
        )?;
        Ok(DashboardStats {
            today_requests,
            today_verified,
            today_blocked,
            today_not_found,
            today_challenge_failures,
            active_bans,
        })
    }

    pub fn request_logs(&self, filter: &LogFilter) -> Result<(Vec<RequestLogRecord>, u64)> {
        let connection = self.management_connection()?;
        let (where_sql, values) = request_log_filter_sql(filter);
        let total_sql = format!("SELECT count(*) FROM request_logs{where_sql}");
        let total: i64 =
            connection.query_row(&total_sql, params_from_iter(values.iter()), |row| {
                row.get(0)
            })?;
        let (_, page_size, offset) = filter.normalized_page();
        let filter_count = values.len();
        let mut query_values = values;
        query_values.push(Value::Integer(i64::from(page_size)));
        query_values.push(Value::Integer(i64::from(offset)));
        let query = format!(
            "SELECT id, timestamp, remote_ip, host, method, path, status, verified, blocked, reason, user_agent, latency_ms, risk_score FROM request_logs{where_sql} ORDER BY timestamp DESC, id DESC LIMIT ?{} OFFSET ?{}",
            filter_count + 1,
            filter_count + 2
        );
        let mut statement = connection.prepare(&query)?;
        let rows = statement
            .query_map(params_from_iter(query_values.iter()), |row| {
                Ok(RequestLogRecord {
                    id: row.get(0)?,
                    timestamp: row.get::<_, i64>(1)? as u64,
                    remote_ip: row.get(2)?,
                    host: row.get(3)?,
                    method: row.get(4)?,
                    path: row.get(5)?,
                    status: row.get::<_, i64>(6)? as u16,
                    verified: row.get(7)?,
                    blocked: row.get(8)?,
                    reason: row.get(9)?,
                    user_agent: row.get(10)?,
                    latency_ms: row.get::<_, i64>(11)? as u64,
                    risk_score: row.get::<_, i64>(12)? as u32,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to load request logs")?;
        Ok((rows, total as u64))
    }

    pub fn security_events(&self, filter: &LogFilter) -> Result<(Vec<SecurityEventRecord>, u64)> {
        let connection = self.management_connection()?;
        let (where_sql, values) = security_event_filter_sql(filter);
        let total_sql = format!("SELECT count(*) FROM security_events{where_sql}");
        let total: i64 =
            connection.query_row(&total_sql, params_from_iter(values.iter()), |row| {
                row.get(0)
            })?;
        let (_, page_size, offset) = filter.normalized_page();
        let filter_count = values.len();
        let mut query_values = values;
        query_values.push(Value::Integer(i64::from(page_size)));
        query_values.push(Value::Integer(i64::from(offset)));
        let query = format!(
            "SELECT id, timestamp, remote_ip, host, path, event_type, risk_score, action, details_redacted FROM security_events{where_sql} ORDER BY timestamp DESC, id DESC LIMIT ?{} OFFSET ?{}",
            filter_count + 1,
            filter_count + 2
        );
        let mut statement = connection.prepare(&query)?;
        let rows = statement
            .query_map(params_from_iter(query_values.iter()), |row| {
                Ok(SecurityEventRecord {
                    id: row.get(0)?,
                    timestamp: row.get::<_, i64>(1)? as u64,
                    remote_ip: row.get(2)?,
                    host: row.get(3)?,
                    path: row.get(4)?,
                    event_type: row.get(5)?,
                    risk_score: row.get::<_, i64>(6)? as u32,
                    action: row.get(7)?,
                    details_redacted: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to load security events")?;
        Ok((rows, total as u64))
    }

    pub fn clear_request_logs(&self, filter: &LogFilter) -> Result<u64> {
        let connection = self.management_connection()?;
        let (where_sql, values) = request_log_filter_sql(filter);
        let deleted = connection.execute(
            &format!("DELETE FROM request_logs{where_sql}"),
            params_from_iter(values.iter()),
        )?;
        Ok(deleted as u64)
    }

    pub fn clear_security_events(&self, filter: &LogFilter) -> Result<u64> {
        let connection = self.management_connection()?;
        let (where_sql, values) = security_event_filter_sql(filter);
        let deleted = connection.execute(
            &format!("DELETE FROM security_events{where_sql}"),
            params_from_iter(values.iter()),
        )?;
        Ok(deleted as u64)
    }

    pub fn request_log(&self, id: i64) -> Result<Option<RequestLogRecord>> {
        let connection = self.management_connection()?;
        connection
            .query_row(
                "SELECT id, timestamp, remote_ip, host, method, path, status, verified, blocked, reason, user_agent, latency_ms, risk_score FROM request_logs WHERE id = ?1",
                params![id],
                |row| {
                    Ok(RequestLogRecord {
                        id: row.get(0)?,
                        timestamp: row.get::<_, i64>(1)? as u64,
                        remote_ip: row.get(2)?,
                        host: row.get(3)?,
                        method: row.get(4)?,
                        path: row.get(5)?,
                        status: row.get::<_, i64>(6)? as u16,
                        verified: row.get(7)?,
                        blocked: row.get(8)?,
                        reason: row.get(9)?,
                        user_agent: row.get(10)?,
                        latency_ms: row.get::<_, i64>(11)? as u64,
                        risk_score: row.get::<_, i64>(12)? as u32,
                    })
                },
            )
            .optional()
            .context("failed to load request log")
    }

    pub fn security_event(&self, id: i64) -> Result<Option<SecurityEventRecord>> {
        let connection = self.management_connection()?;
        connection
            .query_row(
                "SELECT id, timestamp, remote_ip, host, path, event_type, risk_score, action, details_redacted FROM security_events WHERE id = ?1",
                params![id],
                |row| {
                    Ok(SecurityEventRecord {
                        id: row.get(0)?,
                        timestamp: row.get::<_, i64>(1)? as u64,
                        remote_ip: row.get(2)?,
                        host: row.get(3)?,
                        path: row.get(4)?,
                        event_type: row.get(5)?,
                        risk_score: row.get::<_, i64>(6)? as u32,
                        action: row.get(7)?,
                        details_redacted: row.get(8)?,
                    })
                },
            )
            .optional()
            .context("failed to load security event")
    }

    pub fn management_enabled(&self) -> bool {
        self.database.is_some()
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let connection = self.management_connection()?;
        connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load management setting")
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let connection = self.management_connection()?;
        connection.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, unix_now() as i64],
        )?;
        Ok(())
    }

    pub fn bootstrap_management(
        &self,
        sites: &[ManagedSite],
        whitelist: &[ManagedWhitelist],
    ) -> Result<()> {
        let mut connection = self.management_connection()?;
        let transaction = connection.transaction()?;
        let initialized: Option<String> = transaction
            .query_row(
                "SELECT value FROM settings WHERE key = 'management_bootstrapped'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let now = unix_now() as i64;
        for site in sites {
            transaction.execute(
                "INSERT OR IGNORE INTO sites (host, target, policy, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![site.host, site.target, site.policy, site.enabled, now],
            )?;
        }
        if initialized.is_none() {
            for entry in whitelist {
                transaction.execute(
                    "INSERT INTO whitelist (kind, value, skip_challenge, skip_rate_limit, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![entry.kind, entry.value, entry.skip_challenge, entry.skip_rate_limit, entry.note, now],
                )?;
            }
            transaction.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES ('management_bootstrapped', '1', ?1)",
                params![now],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn replace_management(
        &self,
        sites: &[ManagedSite],
        whitelist: &[ManagedWhitelist],
    ) -> Result<()> {
        let mut connection = self.management_connection()?;
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM sites", [])?;
        transaction.execute("DELETE FROM whitelist", [])?;
        let now = unix_now() as i64;
        for site in sites {
            transaction.execute(
                "INSERT INTO sites (host, target, policy, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![site.host, site.target, site.policy, site.enabled, now],
            )?;
        }
        for entry in whitelist {
            transaction.execute(
                "INSERT INTO whitelist (kind, value, skip_challenge, skip_rate_limit, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![entry.kind, entry.value, entry.skip_challenge, entry.skip_rate_limit, entry.note, now],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn managed_sites(&self) -> Result<Vec<ManagedSite>> {
        let connection = self.management_connection()?;
        let mut statement =
            connection.prepare("SELECT host, target, policy, enabled FROM sites ORDER BY host")?;
        let sites = statement
            .query_map([], |row| {
                Ok(ManagedSite {
                    host: row.get(0)?,
                    target: row.get(1)?,
                    policy: row.get(2)?,
                    enabled: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to load managed sites")?;
        Ok(sites)
    }

    pub fn upsert_site(&self, site: &ManagedSite) -> Result<()> {
        let connection = self.management_connection()?;
        connection.execute(
            "INSERT INTO sites (host, target, policy, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5) ON CONFLICT(host) DO UPDATE SET target = excluded.target, policy = excluded.policy, enabled = excluded.enabled, updated_at = excluded.updated_at",
            params![site.host, site.target, site.policy, site.enabled, unix_now() as i64],
        )?;
        Ok(())
    }

    pub fn delete_site(&self, host: &str) -> Result<bool> {
        Ok(self
            .management_connection()?
            .execute("DELETE FROM sites WHERE host = ?1", params![host])?
            > 0)
    }

    pub fn active_bans(&self) -> Result<Vec<ActiveBan>> {
        let connection = self.management_connection()?;
        let now = unix_now() as i64;
        let mut statement = connection.prepare(
            "SELECT ip, reason, source, created_at, expires_at FROM bans WHERE active = 1 AND expires_at > ?1 ORDER BY expires_at",
        )?;
        let bans = statement
            .query_map(params![now], |row| {
                Ok(ActiveBan {
                    ip: row.get(0)?,
                    reason: row.get(1)?,
                    source: row.get(2)?,
                    created_at: row.get::<_, i64>(3)? as u64,
                    expires_at: row.get::<_, i64>(4)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to load active bans")?;
        Ok(bans)
    }

    pub fn set_ban(&self, record: &BanRecord) -> Result<()> {
        let mut connection = self.management_connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE bans SET active = 0 WHERE ip = ?1 AND active = 1",
            params![record.ip],
        )?;
        transaction.execute(
            "INSERT INTO bans (ip, reason, source, created_at, expires_at, active) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![record.ip, record.reason, record.source, record.created_at as i64, record.expires_at as i64],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn clear_ban(&self, ip: &str) -> Result<bool> {
        Ok(self.management_connection()?.execute(
            "UPDATE bans SET active = 0 WHERE ip = ?1 AND active = 1",
            params![ip],
        )? > 0)
    }

    pub fn managed_whitelist(&self) -> Result<Vec<ManagedWhitelist>> {
        let connection = self.management_connection()?;
        let mut statement = connection.prepare(
            "SELECT id, kind, value, skip_challenge, skip_rate_limit, note FROM whitelist ORDER BY id",
        )?;
        let whitelist = statement
            .query_map([], |row| {
                Ok(ManagedWhitelist {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    value: row.get(2)?,
                    skip_challenge: row.get(3)?,
                    skip_rate_limit: row.get(4)?,
                    note: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to load whitelist")?;
        Ok(whitelist)
    }

    pub fn replace_whitelist(&self, entry: &ManagedWhitelist) -> Result<()> {
        let mut connection = self.management_connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM whitelist WHERE kind = ?1 AND value = ?2",
            params![entry.kind, entry.value],
        )?;
        transaction.execute(
            "INSERT INTO whitelist (kind, value, skip_challenge, skip_rate_limit, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![entry.kind, entry.value, entry.skip_challenge, entry.skip_rate_limit, entry.note, unix_now() as i64],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_whitelist(&self, id: i64) -> Result<bool> {
        Ok(self
            .management_connection()?
            .execute("DELETE FROM whitelist WHERE id = ?1", params![id])?
            > 0)
    }

    fn management_connection(&self) -> Result<Connection> {
        let database = self
            .database
            .as_deref()
            .context("SQLite storage is disabled")?;
        let connection = Connection::open(database)
            .with_context(|| format!("failed to open SQLite database {database}"))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(connection)
    }
}

fn scalar_count(connection: &Connection, sql: &str, value: u64) -> Result<u64> {
    let count: i64 = connection.query_row(sql, params![value as i64], |row| row.get(0))?;
    u64::try_from(count).context("SQLite count is negative")
}

fn request_log_filter_sql(filter: &LogFilter) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    add_search_filter(
        &mut clauses,
        &mut values,
        filter.search.as_deref(),
        &[
            "host",
            "remote_ip",
            "path",
            "method",
            "reason",
            "user_agent",
        ],
    );
    add_text_filter(&mut clauses, &mut values, "host", filter.host.as_deref());
    add_text_filter(
        &mut clauses,
        &mut values,
        "remote_ip",
        filter.remote_ip.as_deref(),
    );
    add_text_filter(&mut clauses, &mut values, "path", filter.path.as_deref());
    if let Some(status) = filter.status {
        clauses.push("status = ?".to_string());
        values.push(Value::Integer(i64::from(status)));
    }
    if let Some(blocked) = filter.blocked {
        clauses.push("blocked = ?".to_string());
        values.push(Value::Integer(i64::from(blocked)));
    }
    if let Some(verified) = filter.verified {
        clauses.push("verified = ?".to_string());
        values.push(Value::Integer(i64::from(verified)));
    }
    add_time_filters(&mut clauses, &mut values, filter);
    where_clause(clauses, values)
}

fn security_event_filter_sql(filter: &LogFilter) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    add_search_filter(
        &mut clauses,
        &mut values,
        filter.search.as_deref(),
        &[
            "host",
            "remote_ip",
            "path",
            "event_type",
            "action",
            "details_redacted",
        ],
    );
    add_text_filter(&mut clauses, &mut values, "host", filter.host.as_deref());
    add_text_filter(
        &mut clauses,
        &mut values,
        "remote_ip",
        filter.remote_ip.as_deref(),
    );
    add_text_filter(&mut clauses, &mut values, "path", filter.path.as_deref());
    add_text_filter(
        &mut clauses,
        &mut values,
        "event_type",
        filter.event_type.as_deref(),
    );
    add_time_filters(&mut clauses, &mut values, filter);
    where_clause(clauses, values)
}

fn add_time_filters(clauses: &mut Vec<String>, values: &mut Vec<Value>, filter: &LogFilter) {
    if let Some(from) = filter.from {
        clauses.push("timestamp >= ?".to_string());
        values.push(Value::Integer(from as i64));
    }
    if let Some(to) = filter.to {
        clauses.push("timestamp <= ?".to_string());
        values.push(Value::Integer(to as i64));
    }
}

fn add_text_filter(
    clauses: &mut Vec<String>,
    values: &mut Vec<Value>,
    column: &str,
    value: Option<&str>,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        clauses.push(format!("{column} LIKE ?"));
        values.push(Value::Text(format!("%{}%", value.trim())));
    }
}

fn add_search_filter(
    clauses: &mut Vec<String>,
    values: &mut Vec<Value>,
    value: Option<&str>,
    columns: &[&str],
) {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    let pattern = format!("%{}%", value.trim());
    clauses.push(format!(
        "({})",
        columns
            .iter()
            .map(|column| format!("{column} LIKE ?"))
            .collect::<Vec<_>>()
            .join(" OR ")
    ));
    values.extend(columns.iter().map(|_| Value::Text(pattern.clone())));
}

fn where_clause(clauses: Vec<String>, values: Vec<Value>) -> (String, Vec<Value>) {
    if clauses.is_empty() {
        (String::new(), values)
    } else {
        (format!(" WHERE {}", clauses.join(" AND ")), values)
    }
}

fn initialize(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.execute_batch(include_str!("../migrations/001_initial.sql"))?;
    Ok(())
}

fn load_active_bans(connection: &Connection) -> Result<Vec<LoadedBan>> {
    let now = unix_now();
    let mut statement = connection
        .prepare("SELECT ip, reason, expires_at FROM bans WHERE active = 1 AND expires_at > ?1")?;
    let rows = statement.query_map(params![now as i64], |row| {
        let ip: String = row.get(0)?;
        let reason: String = row.get(1)?;
        let expires_at: i64 = row.get(2)?;
        Ok((ip, reason, expires_at))
    })?;
    let mut bans = Vec::new();
    for row in rows {
        let (ip, reason, expires_at) = row?;
        let ip = ip
            .parse()
            .with_context(|| format!("invalid stored ban IP: {ip}"))?;
        bans.push(LoadedBan {
            ip,
            reason,
            expires_at: u64::try_from(expires_at).context("stored ban expiry is negative")?,
        });
    }
    Ok(bans)
}

fn writer_loop(
    database: String,
    retention: u64,
    request_rx: Receiver<StorageEvent>,
    security_rx: Receiver<StorageEvent>,
) {
    let Ok(connection) = Connection::open(&database) else {
        return;
    };
    if initialize(&connection).is_err() {
        return;
    }
    loop {
        let mut batch = Vec::with_capacity(LOG_BATCH_SIZE);
        if let Ok(event) = security_rx.recv_timeout(Duration::from_secs(1)) {
            batch.push(event);
        }
        while batch.len() < LOG_BATCH_SIZE {
            match security_rx.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        while batch.len() < LOG_BATCH_SIZE {
            match request_rx.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            let _ = write_batch(&connection, &batch);
        }
        let _ = cleanup(&connection, retention);
    }
}

fn write_batch(connection: &Connection, events: &[StorageEvent]) -> Result<()> {
    let transaction = connection.unchecked_transaction()?;
    for event in events {
        match event {
            StorageEvent::Request(log) => {
                transaction.execute(
                    "INSERT INTO request_logs (timestamp, remote_ip, host, method, path, status, verified, blocked, reason, user_agent, latency_ms, risk_score) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        log.timestamp as i64,
                        log.remote_ip,
                        log.host,
                        log.method,
                        log.path,
                        i64::from(log.status),
                        log.verified,
                        log.blocked,
                        log.reason,
                        log.user_agent,
                        log.latency_ms as i64,
                        log.risk_score as i64,
                    ],
                )?;
            }
            StorageEvent::Security(event) => {
                transaction.execute(
                    "INSERT INTO security_events (timestamp, remote_ip, host, path, event_type, risk_score, action, details_redacted) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        event.timestamp as i64,
                        event.remote_ip,
                        event.host,
                        event.path,
                        event.event_type,
                        event.risk_score as i64,
                        event.action,
                        event.details_redacted,
                    ],
                )?;
            }
            StorageEvent::Ban(record) => {
                transaction.execute(
                    "UPDATE bans SET active = 0 WHERE ip = ?1 AND active = 1",
                    params![record.ip],
                )?;
                transaction.execute(
                    "INSERT INTO bans (ip, reason, source, created_at, expires_at, active) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                    params![
                        record.ip,
                        record.reason,
                        record.source,
                        record.created_at as i64,
                        record.expires_at as i64,
                    ],
                )?;
            }
        }
    }
    transaction.commit()?;
    Ok(())
}

fn cleanup(connection: &Connection, retention: u64) -> Result<()> {
    let cutoff = unix_now().saturating_sub(retention) as i64;
    connection.execute(
        "DELETE FROM request_logs WHERE timestamp < ?1",
        params![cutoff],
    )?;
    connection.execute(
        "DELETE FROM security_events WHERE timestamp < ?1",
        params![cutoff],
    )?;
    connection.execute(
        "UPDATE bans SET active = 0 WHERE expires_at <= ?1",
        params![unix_now() as i64],
    )?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn default_true() -> bool {
    true
}

fn default_database() -> String {
    "data/bot-gate.db".to_string()
}

fn default_retention() -> u64 {
    7 * 24 * 60 * 60
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
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

fn parse_duration_secs(value: &str) -> Result<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_schema_and_parses_duration() {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'request_logs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(parse_duration_secs("7d").unwrap(), 7 * 24 * 60 * 60);
        assert!(parse_duration_secs("0m").is_err());
    }

    #[test]
    fn management_records_round_trip() {
        let path = std::env::temp_dir().join(format!("bot-gate-storage-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let connection = Connection::open(&path).unwrap();
        initialize(&connection).unwrap();
        drop(connection);
        let storage = Storage {
            request_tx: None,
            security_tx: None,
            persist_request_logs: false,
            database: Some(path.to_string_lossy().into_owned()),
        };
        let site = ManagedSite {
            host: "project-a.test".to_string(),
            target: "http://127.0.0.1:9001".to_string(),
            policy: "normal".to_string(),
            enabled: true,
        };
        storage.bootstrap_management(&[site.clone()], &[]).unwrap();
        assert_eq!(storage.managed_sites().unwrap().len(), 1);
        storage
            .bootstrap_management(
                &[ManagedSite {
                    host: "project-b.test".to_string(),
                    target: "http://127.0.0.1:9002".to_string(),
                    policy: "normal".to_string(),
                    enabled: true,
                }],
                &[],
            )
            .unwrap();
        assert_eq!(storage.managed_sites().unwrap().len(), 2);
        storage
            .upsert_site(&ManagedSite {
                enabled: false,
                ..site
            })
            .unwrap();
        assert!(!storage.managed_sites().unwrap()[0].enabled);
        let entry = ManagedWhitelist {
            id: 0,
            kind: "ip".to_string(),
            value: "127.0.0.1".to_string(),
            skip_challenge: true,
            skip_rate_limit: false,
            note: None,
        };
        storage.replace_whitelist(&entry).unwrap();
        let entry = storage.managed_whitelist().unwrap().pop().unwrap();
        assert!(storage.delete_whitelist(entry.id).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn log_queries_filter_and_paginate() {
        let path =
            std::env::temp_dir().join(format!("bot-gate-log-query-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let connection = Connection::open(&path).unwrap();
        initialize(&connection).unwrap();
        connection
            .execute(
                "INSERT INTO request_logs (timestamp, remote_ip, host, method, path, status, verified, blocked, reason, user_agent, latency_ms, risk_score) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                params![100_i64, "127.0.0.1", "cool.com", "GET", "/admin", 403_i64, false, true, "verification_required", "curl", 2_i64, 4_i64],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO request_logs (timestamp, remote_ip, host, method, path, status, verified, blocked, reason, user_agent, latency_ms, risk_score) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                params![101_i64, "127.0.0.1", "other.test", "GET", "/", 200_i64, true, false, Option::<String>::None, "browser", 3_i64, 0_i64],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO security_events (timestamp, remote_ip, host, path, event_type, risk_score, action, details_redacted) VALUES (?,?,?,?,?,?,?,?)",
                params![102_i64, "127.0.0.1", "cool.com", "/api/user", "rate_limit", 50_i64, "request_rejected", "burst exceeded"],
            )
            .unwrap();
        drop(connection);
        let storage = Storage {
            request_tx: None,
            security_tx: None,
            persist_request_logs: false,
            database: Some(path.to_string_lossy().into_owned()),
        };
        let (items, total) = storage
            .request_logs(&LogFilter {
                search: Some("/admin".to_string()),
                blocked: Some(true),
                page: 1,
                page_size: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(items[0].path, "/admin");
        let (events, event_total) = storage
            .security_events(&LogFilter {
                search: Some("request_rejected".to_string()),
                event_type: Some("rate_limit".to_string()),
                page: 1,
                page_size: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(event_total, 1);
        assert_eq!(events[0].action, "request_rejected");
        assert_eq!(
            storage
                .clear_request_logs(&LogFilter {
                    from: Some(101),
                    ..Default::default()
                })
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .clear_security_events(&LogFilter {
                    from: Some(102),
                    ..Default::default()
                })
                .unwrap(),
            1
        );
        let _ = std::fs::remove_file(path);
    }
}
