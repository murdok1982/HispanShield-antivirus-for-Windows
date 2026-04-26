use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type DbConn = Arc<Mutex<Connection>>;

const SCHEMA_SQL: &str = include_str!("schema.sql");

/// Open (or create) the SQLite database, run migrations, and return a shared connection.
pub fn open(path: &Path) -> Result<DbConn> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;",
    )?;
    run_migrations(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Event {
    pub id: Option<i64>,
    pub timestamp: String,
    pub event_type: String,
    pub severity: String,
    pub source: Option<String>,
    pub path: Option<String>,
    pub pid: Option<i64>,
    pub process_name: Option<String>,
    pub score: Option<i64>,
    pub details: Option<String>,
    pub resolved: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Threat {
    pub id: Option<i64>,
    pub detected_at: String,
    pub threat_type: String,
    pub name: Option<String>,
    pub path: Option<String>,
    pub pid: Option<i64>,
    pub process_name: Option<String>,
    pub hash_sha256: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_md5: Option<String>,
    pub score: i64,
    pub detection_method: String,
    pub ioc_source: Option<String>,
    pub status: String,
    pub action_taken: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub quarantined_at: String,
    pub original_path: String,
    pub original_name: String,
    pub quarantine_path: String,
    pub hash_sha256: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_md5: Option<String>,
    pub file_size: Option<i64>,
    pub threat_name: Option<String>,
    pub score: Option<i64>,
    pub detection_method: Option<String>,
    pub status: String,
    pub restored_at: Option<String>,
    pub deleted_at: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IocEntry {
    pub id: Option<i64>,
    pub ioc_type: String,
    pub value: String,
    pub source: String,
    pub confidence: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub tags: Option<String>,
    pub is_allowlist: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FeedStatusRow {
    pub name: String,
    pub last_updated: Option<String>,
    pub next_update: Option<String>,
    pub ioc_count: i64,
    pub status: String,
    pub error_msg: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessSnapshot {
    pub id: Option<i64>,
    pub captured_at: String,
    pub pid: i64,
    pub ppid: Option<i64>,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub hash_sha256: Option<String>,
    pub signed: Option<bool>,
    pub signer: Option<String>,
    pub score: i64,
    pub connections: i64,
    pub status: String,
    pub flags: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConnection {
    pub id: Option<i64>,
    pub captured_at: String,
    pub pid: i64,
    pub process_name: Option<String>,
    pub local_addr: Option<String>,
    pub local_port: Option<i64>,
    pub remote_addr: Option<String>,
    pub remote_port: Option<i64>,
    pub protocol: Option<String>,
    pub state: Option<String>,
    pub score: i64,
    pub ioc_match: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Stats {
    pub threats: i64,
    pub quarantined: i64,
    pub ioc_count: i64,
    pub events_today: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct YaraRule {
    pub id: Option<i64>,
    pub name: String,
    pub source: String,
    pub content: String,
    pub enabled: bool,
    pub last_match: Option<String>,
    pub match_count: i64,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Database wrapper
// ---------------------------------------------------------------------------

pub struct Database {
    conn: DbConn,
}

impl Database {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }

    // --- Events ---

    /// Insert a new agent event and return its rowid.
    pub fn insert_event(&self, event: &Event) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (timestamp, event_type, severity, source, path, pid, process_name, score, details, resolved)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.timestamp, event.event_type, event.severity, event.source,
                event.path, event.pid, event.process_name, event.score,
                event.details, event.resolved as i64
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Query events ordered by timestamp descending.
    pub fn query_events(&self, limit: i64, offset: i64) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, severity, source, path, pid, process_name, score, details, resolved
             FROM events ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2",
        )?;
        let events = stmt
            .query_map(params![limit, offset], |row| {
                Ok(Event {
                    id: Some(row.get(0)?),
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    severity: row.get(3)?,
                    source: row.get(4)?,
                    path: row.get(5)?,
                    pid: row.get(6)?,
                    process_name: row.get(7)?,
                    score: row.get(8)?,
                    details: row.get(9)?,
                    resolved: row.get::<_, i64>(10)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(events)
    }

    /// Mark an event as resolved.
    pub fn mark_event_resolved(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE events SET resolved=1 WHERE id=?1", params![id])?;
        Ok(())
    }

    // --- Threats ---

    /// Insert a detected threat and return its rowid.
    pub fn insert_threat(&self, threat: &Threat) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO threats (detected_at, threat_type, name, path, pid, process_name,
             hash_sha256, hash_sha1, hash_md5, score, detection_method, ioc_source, status, action_taken, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                threat.detected_at, threat.threat_type, threat.name, threat.path, threat.pid,
                threat.process_name, threat.hash_sha256, threat.hash_sha1, threat.hash_md5,
                threat.score, threat.detection_method, threat.ioc_source, threat.status,
                threat.action_taken, threat.details
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Update the status and optional action of a threat record.
    pub fn update_threat_status(
        &self,
        id: i64,
        status: &str,
        action_taken: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE threats SET status=?1, action_taken=?2 WHERE id=?3",
            params![status, action_taken, id],
        )?;
        Ok(())
    }

    /// Query threats ordered by detection date descending.
    pub fn query_threats(&self, limit: i64, offset: i64) -> Result<Vec<Threat>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, detected_at, threat_type, name, path, pid, process_name,
             hash_sha256, hash_sha1, hash_md5, score, detection_method, ioc_source,
             status, action_taken, details
             FROM threats ORDER BY detected_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let threats = stmt
            .query_map(params![limit, offset], |row| {
                Ok(Threat {
                    id: Some(row.get(0)?),
                    detected_at: row.get(1)?,
                    threat_type: row.get(2)?,
                    name: row.get(3)?,
                    path: row.get(4)?,
                    pid: row.get(5)?,
                    process_name: row.get(6)?,
                    hash_sha256: row.get(7)?,
                    hash_sha1: row.get(8)?,
                    hash_md5: row.get(9)?,
                    score: row.get(10)?,
                    detection_method: row.get(11)?,
                    ioc_source: row.get(12)?,
                    status: row.get(13)?,
                    action_taken: row.get(14)?,
                    details: row.get(15)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(threats)
    }

    // --- Quarantine ---

    /// Insert a new quarantine record.
    pub fn insert_quarantine(&self, entry: &QuarantineEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO quarantine (id, quarantined_at, original_path, original_name, quarantine_path,
             hash_sha256, hash_sha1, hash_md5, file_size, threat_name, score, detection_method, status, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                entry.id, entry.quarantined_at, entry.original_path, entry.original_name,
                entry.quarantine_path, entry.hash_sha256, entry.hash_sha1, entry.hash_md5,
                entry.file_size, entry.threat_name, entry.score, entry.detection_method,
                entry.status, entry.details
            ],
        )?;
        Ok(())
    }

    /// Mark a quarantine entry as restored.
    pub fn restore_quarantine(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE quarantine SET status='Restored', restored_at=?1 WHERE id=?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Mark a quarantine entry as permanently deleted.
    pub fn delete_quarantine_entry(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE quarantine SET status='Deleted', deleted_at=?1 WHERE id=?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Query quarantine entries by status.
    pub fn query_quarantine(&self, limit: i64, offset: i64) -> Result<Vec<QuarantineEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, quarantined_at, original_path, original_name, quarantine_path,
             hash_sha256, hash_sha1, hash_md5, file_size, threat_name, score, detection_method,
             status, restored_at, deleted_at, details
             FROM quarantine ORDER BY quarantined_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt
            .query_map(params![limit, offset], |row| {
                Ok(QuarantineEntry {
                    id: row.get(0)?,
                    quarantined_at: row.get(1)?,
                    original_path: row.get(2)?,
                    original_name: row.get(3)?,
                    quarantine_path: row.get(4)?,
                    hash_sha256: row.get(5)?,
                    hash_sha1: row.get(6)?,
                    hash_md5: row.get(7)?,
                    file_size: row.get(8)?,
                    threat_name: row.get(9)?,
                    score: row.get(10)?,
                    detection_method: row.get(11)?,
                    status: row.get(12)?,
                    restored_at: row.get(13)?,
                    deleted_at: row.get(14)?,
                    details: row.get(15)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a single quarantine entry by UUID.
    pub fn get_quarantine_entry(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, quarantined_at, original_path, original_name, quarantine_path,
             hash_sha256, hash_sha1, hash_md5, file_size, threat_name, score, detection_method,
             status, restored_at, deleted_at, details
             FROM quarantine WHERE id=?1",
        )?;
        let result = stmt
            .query_row(params![id], |row| {
                Ok(QuarantineEntry {
                    id: row.get(0)?,
                    quarantined_at: row.get(1)?,
                    original_path: row.get(2)?,
                    original_name: row.get(3)?,
                    quarantine_path: row.get(4)?,
                    hash_sha256: row.get(5)?,
                    hash_sha1: row.get(6)?,
                    hash_md5: row.get(7)?,
                    file_size: row.get(8)?,
                    threat_name: row.get(9)?,
                    score: row.get(10)?,
                    detection_method: row.get(11)?,
                    status: row.get(12)?,
                    restored_at: row.get(13)?,
                    deleted_at: row.get(14)?,
                    details: row.get(15)?,
                })
            })
            .ok();
        Ok(result)
    }

    // --- IOC Cache ---

    /// Upsert an IOC entry (insert or update on conflict).
    pub fn upsert_ioc(&self, ioc: &IocEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO ioc_cache (ioc_type, value, source, confidence, first_seen, last_seen, tags, is_allowlist)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(ioc_type, value, source) DO UPDATE SET
               confidence=excluded.confidence,
               last_seen=excluded.last_seen,
               tags=excluded.tags",
            params![
                ioc.ioc_type, ioc.value, ioc.source, ioc.confidence,
                ioc.first_seen, ioc.last_seen, ioc.tags, ioc.is_allowlist as i64
            ],
        )?;
        Ok(())
    }

    /// Look up a single IOC by type and value (highest confidence wins).
    pub fn query_ioc_by_value(
        &self,
        ioc_type: &str,
        value: &str,
    ) -> Result<Option<IocEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ioc_type, value, source, confidence, first_seen, last_seen, tags, is_allowlist
             FROM ioc_cache WHERE ioc_type=?1 AND value=?2 ORDER BY confidence DESC LIMIT 1",
        )?;
        let result = stmt
            .query_row(params![ioc_type, value], |row| {
                Ok(IocEntry {
                    id: Some(row.get(0)?),
                    ioc_type: row.get(1)?,
                    value: row.get(2)?,
                    source: row.get(3)?,
                    confidence: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                    tags: row.get(7)?,
                    is_allowlist: row.get::<_, i64>(8)? != 0,
                })
            })
            .ok();
        Ok(result)
    }

    /// Delete all IOC entries from a specific feed (for full refresh).
    pub fn clear_feed_iocs(&self, source: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "DELETE FROM ioc_cache WHERE source=?1",
            params![source],
        )?;
        Ok(count)
    }

    // --- Feed Status ---

    /// Upsert the status row for a feed.
    pub fn update_feed_status(&self, row: &FeedStatusRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO feed_status (name, last_updated, next_update, ioc_count, status, error_msg, checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET
               last_updated=excluded.last_updated,
               next_update=excluded.next_update,
               ioc_count=excluded.ioc_count,
               status=excluded.status,
               error_msg=excluded.error_msg,
               checksum=excluded.checksum",
            params![
                row.name, row.last_updated, row.next_update, row.ioc_count,
                row.status, row.error_msg, row.checksum
            ],
        )?;
        Ok(())
    }

    /// Get all feed status rows.
    pub fn get_all_feed_status(&self) -> Result<Vec<FeedStatusRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT name, last_updated, next_update, ioc_count, status, error_msg, checksum
             FROM feed_status",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(FeedStatusRow {
                    name: row.get(0)?,
                    last_updated: row.get(1)?,
                    next_update: row.get(2)?,
                    ioc_count: row.get(3)?,
                    status: row.get(4)?,
                    error_msg: row.get(5)?,
                    checksum: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // --- Process Snapshot ---

    /// Save a batch of process snapshots.
    pub fn save_process_snapshot(&self, snap: &ProcessSnapshot) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO process_snapshot (captured_at, pid, ppid, name, path, cmdline, hash_sha256,
             signed, signer, score, connections, status, flags)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                snap.captured_at, snap.pid, snap.ppid, snap.name, snap.path, snap.cmdline,
                snap.hash_sha256, snap.signed.map(|b| b as i64), snap.signer,
                snap.score, snap.connections, snap.status, snap.flags
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get the most recent process snapshot batch (last captured_at timestamp).
    pub fn get_latest_process_snapshots(&self, limit: i64) -> Result<Vec<ProcessSnapshot>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, captured_at, pid, ppid, name, path, cmdline, hash_sha256,
             signed, signer, score, connections, status, flags
             FROM process_snapshot ORDER BY captured_at DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(ProcessSnapshot {
                    id: Some(row.get(0)?),
                    captured_at: row.get(1)?,
                    pid: row.get(2)?,
                    ppid: row.get(3)?,
                    name: row.get(4)?,
                    path: row.get(5)?,
                    cmdline: row.get(6)?,
                    hash_sha256: row.get(7)?,
                    signed: row.get::<_, Option<i64>>(8)?.map(|v| v != 0),
                    signer: row.get(9)?,
                    score: row.get(10)?,
                    connections: row.get(11)?,
                    status: row.get(12)?,
                    flags: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // --- Network Connections ---

    /// Save a network connection record.
    pub fn save_connection(&self, conn_row: &NetworkConnection) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO network_connections (captured_at, pid, process_name, local_addr, local_port,
             remote_addr, remote_port, protocol, state, score, ioc_match, country, asn)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                conn_row.captured_at, conn_row.pid, conn_row.process_name,
                conn_row.local_addr, conn_row.local_port, conn_row.remote_addr,
                conn_row.remote_port, conn_row.protocol, conn_row.state, conn_row.score,
                conn_row.ioc_match, conn_row.country, conn_row.asn
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get recent network connections.
    pub fn get_connections(&self, limit: i64) -> Result<Vec<NetworkConnection>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, captured_at, pid, process_name, local_addr, local_port,
             remote_addr, remote_port, protocol, state, score, ioc_match, country, asn
             FROM network_connections ORDER BY captured_at DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(NetworkConnection {
                    id: Some(row.get(0)?),
                    captured_at: row.get(1)?,
                    pid: row.get(2)?,
                    process_name: row.get(3)?,
                    local_addr: row.get(4)?,
                    local_port: row.get(5)?,
                    remote_addr: row.get(6)?,
                    remote_port: row.get(7)?,
                    protocol: row.get(8)?,
                    state: row.get(9)?,
                    score: row.get(10)?,
                    ioc_match: row.get(11)?,
                    country: row.get(12)?,
                    asn: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // --- YARA Rules ---

    /// Insert or replace a YARA rule.
    pub fn upsert_yara_rule(&self, rule: &YaraRule) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO yara_rules (name, source, content, enabled, last_match, match_count, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET
               content=excluded.content,
               source=excluded.source,
               enabled=excluded.enabled",
            params![
                rule.name, rule.source, rule.content, rule.enabled as i64,
                rule.last_match, rule.match_count, rule.created_at
            ],
        )?;
        Ok(())
    }

    /// Get all enabled YARA rules.
    pub fn get_yara_rules(&self) -> Result<Vec<YaraRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, source, content, enabled, last_match, match_count, created_at
             FROM yara_rules WHERE enabled=1",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(YaraRule {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    source: row.get(2)?,
                    content: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    last_match: row.get(5)?,
                    match_count: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Increment match count and update last_match timestamp for a YARA rule.
    pub fn record_yara_match(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE yara_rules SET match_count=match_count+1, last_match=?1 WHERE name=?2",
            params![now, name],
        )?;
        Ok(())
    }

    // --- Aggregated Stats ---

    /// Return a quick summary of current agent state.
    pub fn get_stats(&self) -> Result<Stats> {
        let conn = self.conn.lock().unwrap();
        let threats: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threats WHERE status='Active'",
            [],
            |r| r.get(0),
        )?;
        let quarantined: i64 = conn.query_row(
            "SELECT COUNT(*) FROM quarantine WHERE status='Quarantined'",
            [],
            |r| r.get(0),
        )?;
        let ioc_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ioc_cache WHERE is_allowlist=0",
            [],
            |r| r.get(0),
        )?;
        let events_today: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE timestamp >= date('now')",
            [],
            |r| r.get(0),
        )?;
        Ok(Stats {
            threats,
            quarantined,
            ioc_count,
            events_today,
        })
    }
}
