-- events: log of all agent events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT,
    path TEXT,
    pid INTEGER,
    process_name TEXT,
    score INTEGER,
    details TEXT,
    resolved INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

-- threats: detected threats
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    name TEXT,
    path TEXT,
    pid INTEGER,
    process_name TEXT,
    hash_sha256 TEXT,
    hash_sha1 TEXT,
    hash_md5 TEXT,
    score INTEGER NOT NULL,
    detection_method TEXT,
    ioc_source TEXT,
    status TEXT NOT NULL DEFAULT 'Active',
    action_taken TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_hash ON threats(hash_sha256);

-- quarantine: quarantined files
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    quarantined_at TEXT NOT NULL,
    original_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    hash_sha256 TEXT,
    hash_sha1 TEXT,
    hash_md5 TEXT,
    file_size INTEGER,
    threat_name TEXT,
    score INTEGER,
    detection_method TEXT,
    status TEXT NOT NULL DEFAULT 'Quarantined',
    restored_at TEXT,
    deleted_at TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine(hash_sha256);

-- ioc_cache: IOCs downloaded from OSINT feeds
CREATE TABLE IF NOT EXISTS ioc_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER DEFAULT 50,
    first_seen TEXT,
    last_seen TEXT,
    tags TEXT,
    is_allowlist INTEGER DEFAULT 0,
    UNIQUE(ioc_type, value, source)
);

CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_cache(ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_source ON ioc_cache(source);
CREATE INDEX IF NOT EXISTS idx_ioc_allowlist ON ioc_cache(is_allowlist);

-- feed_status: status of each configured feed
CREATE TABLE IF NOT EXISTS feed_status (
    name TEXT PRIMARY KEY,
    last_updated TEXT,
    next_update TEXT,
    ioc_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'Pending',
    error_msg TEXT,
    checksum TEXT
);

-- process_snapshot: running processes with risk scores
CREATE TABLE IF NOT EXISTS process_snapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    name TEXT NOT NULL,
    path TEXT,
    cmdline TEXT,
    hash_sha256 TEXT,
    signed INTEGER,
    signer TEXT,
    score INTEGER DEFAULT 0,
    connections INTEGER DEFAULT 0,
    status TEXT DEFAULT 'Running',
    flags TEXT
);

CREATE INDEX IF NOT EXISTS idx_process_captured_at ON process_snapshot(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_process_pid ON process_snapshot(pid);

-- network_connections: observed TCP/UDP connections
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT,
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    protocol TEXT,
    state TEXT,
    score INTEGER DEFAULT 0,
    ioc_match TEXT,
    country TEXT,
    asn TEXT
);

CREATE INDEX IF NOT EXISTS idx_netconn_captured_at ON network_connections(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_netconn_remote ON network_connections(remote_addr);

-- config_store: key-value persistent configuration
CREATE TABLE IF NOT EXISTS config_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- yara_rules: YARA rules stored in DB
CREATE TABLE IF NOT EXISTS yara_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    last_match TEXT,
    match_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);
