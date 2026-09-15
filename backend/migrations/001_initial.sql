CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    policy TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    skip_challenge INTEGER NOT NULL DEFAULT 1,
    skip_rate_limit INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    verified INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    reason TEXT,
    user_agent TEXT,
    latency_ms INTEGER NOT NULL,
    risk_score INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    event_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    action TEXT NOT NULL,
    details_redacted TEXT
);

CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_host_timestamp ON request_logs(host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip_timestamp ON request_logs(remote_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_blocked_timestamp ON request_logs(blocked, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_status_timestamp ON request_logs(status, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_host_timestamp ON security_events(host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_timestamp ON security_events(remote_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type_timestamp ON security_events(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_bans_expires_at ON bans(expires_at);
