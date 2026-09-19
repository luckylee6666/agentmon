use crate::model::*;
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::time::Duration;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  vendor TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
  pid INTEGER NOT NULL,
  start_time INTEGER NOT NULL,
  agent_id TEXT,
  name TEXT NOT NULL,
  exe TEXT,
  cwd TEXT,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (pid, start_time)
);
CREATE INDEX IF NOT EXISTS idx_processes_agent ON processes(agent_id, last_seen);

CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  pid INTEGER NOT NULL,
  agent_id TEXT,
  remote_addr TEXT NOT NULL,
  remote_ip TEXT,
  remote_port INTEGER,
  remote_host TEXT,
  proto TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_connections_agent ON connections(agent_id, ts);

CREATE TABLE IF NOT EXISTS volumes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  pid INTEGER NOT NULL,
  agent_id TEXT,
  bytes_in INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  window_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_volumes_agent ON volumes(agent_id, ts);

CREATE TABLE IF NOT EXISTS file_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  pid INTEGER NOT NULL,
  agent_id TEXT,
  path TEXT NOT NULL,
  op TEXT NOT NULL,
  source TEXT NOT NULL,
  process_exe TEXT
);
CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events(ts);
CREATE INDEX IF NOT EXISTS idx_file_events_agent ON file_events(agent_id, ts);

CREATE TABLE IF NOT EXISTS http_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  pid INTEGER,
  agent_id TEXT,
  host TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  bytes_out INTEGER NOT NULL,
  body_sha256 TEXT,
  class TEXT NOT NULL,
  sample TEXT,
  body TEXT
);
CREATE INDEX IF NOT EXISTS idx_http_ts ON http_requests(ts);
CREATE INDEX IF NOT EXISTS idx_http_agent ON http_requests(agent_id, ts);

CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  agent_id TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  entropy REAL NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_agent ON artifacts(agent_id, ts);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  agent_id TEXT,
  pid INTEGER,
  evidence TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  dedupe_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id, dedupe_key, ts);
"#;

pub fn open(path: &Path) -> Result<Connection> {
    crate::paths::ensure_parent_dir(path)?;
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch(SCHEMA)?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn open_readonly(path: &Path) -> Result<Connection> {
    // A database written by an older build may be missing columns that current
    // queries select, and upgrading needs write access. Best effort: try a
    // short lived writable connection first, then open read-only regardless.
    if let Ok(conn) = Connection::open(path) {
        let _ = conn.busy_timeout(Duration::from_millis(1_000));
        let _ = migrate(&conn);
    }

    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(3_000))?;
    Ok(conn)
}

#[derive(Debug, Clone)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub last_seen: i64,
    pub bytes_out_24h: u64,
    pub open_findings: i64,
    pub worst_severity: Option<Severity>,
}

#[derive(Debug, Clone)]
pub struct DestinationSummary {
    pub agent_id: Option<String>,
    pub host: String,
    pub connections: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub allowed: bool,
}

#[derive(Debug, Clone)]
pub struct VolumePoint {
    pub bucket: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Default, Clone)]
pub struct FindingFilter {
    pub min_severity: Option<Severity>,
    pub agent_id: Option<String>,
    pub rule_id: Option<String>,
    pub include_ignored: bool,
    pub limit: i64,
}

pub fn upsert_agent(conn: &Connection, agent: &AgentRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO agents (id, name, vendor, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, vendor=excluded.vendor, last_seen=excluded.last_seen",
        params![agent.id, agent.name, agent.vendor, agent.first_seen, agent.last_seen],
    )?;
    Ok(())
}

pub fn insert_event(conn: &Connection, ev: &Event) -> Result<()> {
    match ev {
        Event::Process(p) => {
            conn.execute(
                "INSERT INTO processes (pid, start_time, agent_id, name, exe, cwd, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(pid, start_time) DO UPDATE SET last_seen=excluded.last_seen, agent_id=excluded.agent_id, cwd=excluded.cwd",
                params![
                    p.pid,
                    p.start_time as i64,
                    p.agent_id,
                    p.name,
                    p.exe.as_ref().map(|e| e.to_string_lossy().to_string()),
                    p.cwd.as_ref().map(|e| e.to_string_lossy().to_string()),
                    p.ts
                ],
            )?;
            if let Some(agent_id) = &p.agent_id {
                conn.execute(
                    "UPDATE agents SET last_seen = ?1 WHERE id = ?2",
                    params![p.ts, agent_id],
                )?;
            }
        }
        Event::Connection(c) => {
            conn.execute(
                "INSERT INTO connections (ts, pid, agent_id, remote_addr, remote_ip, remote_port, remote_host, proto)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![c.ts, c.pid, c.agent_id, c.remote_addr, c.remote_ip, c.remote_port, c.remote_host, c.proto],
            )?;
        }
        Event::Volume(v) => {
            conn.execute(
                "INSERT INTO volumes (ts, pid, agent_id, bytes_in, bytes_out, window_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    v.ts,
                    v.pid,
                    v.agent_id,
                    v.bytes_in as i64,
                    v.bytes_out as i64,
                    v.window_ms
                ],
            )?;
        }
        Event::File(f) => {
            conn.execute(
                "INSERT INTO file_events (ts, pid, agent_id, path, op, source, process_exe)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    f.ts,
                    f.pid,
                    f.agent_id,
                    f.path.to_string_lossy(),
                    f.op.as_str(),
                    f.source,
                    f.process_exe
                ],
            )?;
        }
        Event::Http(h) => {
            conn.execute(
                "INSERT INTO http_requests (ts, pid, agent_id, host, method, path, bytes_out, body_sha256, class, sample, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    h.ts,
                    h.pid,
                    h.agent_id,
                    h.host,
                    h.method,
                    h.path,
                    h.bytes_out as i64,
                    h.body_sha256,
                    h.class,
                    h.sample,
                    h.body
                ],
            )?;
        }
        Event::Artifact(a) => {
            conn.execute(
                "INSERT INTO artifacts (ts, agent_id, path, size, entropy, kind, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    a.ts,
                    a.agent_id,
                    a.path.to_string_lossy(),
                    a.size as i64,
                    a.entropy,
                    a.kind.as_str(),
                    a.detail
                ],
            )?;
        }
    }
    Ok(())
}

pub fn insert_finding(conn: &Connection, f: &Finding) -> Result<i64> {
    let evidence = serde_json::to_string(&f.evidence).unwrap_or_else(|_| "[]".into());
    conn.execute(
        "INSERT INTO findings (ts, rule_id, severity, title, detail, agent_id, pid, evidence, status, dedupe_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            f.ts,
            f.rule_id,
            f.severity.rank(),
            f.title,
            f.detail,
            f.agent_id,
            f.pid,
            evidence,
            f.status.as_str(),
            f.dedupe_key
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

const FINDING_COLUMNS: &str =
    "id, ts, severity, rule_id, title, detail, agent_id, pid, evidence, status, dedupe_key";

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let severity_rank: i64 = row.get(2)?;
    let severity = severity_from_rank(severity_rank);
    let evidence_json: String = row.get(8)?;
    let status_str: String = row.get(9)?;
    Ok(Finding {
        id: Some(row.get(0)?),
        ts: row.get(1)?,
        severity,
        rule_id: row.get(3)?,
        title: row.get(4)?,
        detail: row.get(5)?,
        agent_id: row.get(6)?,
        pid: row.get(7)?,
        evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
        status: FindingStatus::parse(&status_str).unwrap_or(FindingStatus::Open),
        dedupe_key: row.get(10)?,
    })
}

fn severity_from_rank(rank: i64) -> Severity {
    match rank {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

pub fn list_findings(conn: &Connection, filter: &FindingFilter) -> Result<Vec<Finding>> {
    let mut sql = format!("SELECT {FINDING_COLUMNS} FROM findings WHERE 1=1");
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(min) = filter.min_severity {
        sql.push_str(&format!(" AND severity >= {}", min.rank()));
    }
    if let Some(agent) = &filter.agent_id {
        args.push(Box::new(agent.clone()));
        sql.push_str(&format!(" AND agent_id = ?{}", args.len()));
    }
    if let Some(rule) = &filter.rule_id {
        args.push(Box::new(rule.clone()));
        sql.push_str(&format!(" AND rule_id = ?{}", args.len()));
    }
    if !filter.include_ignored {
        sql.push_str(" AND status = 'open'");
    }
    sql.push_str(" ORDER BY ts DESC");
    let limit = if filter.limit > 0 { filter.limit } else { 200 };
    args.push(Box::new(limit));
    sql.push_str(&format!(" LIMIT ?{}", args.len()));

    let mut stmt = conn.prepare(&sql)?;
    let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|a| a.as_ref()).collect();
    let rows = stmt.query_map(params.as_slice(), row_to_finding)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn set_finding_status(conn: &Connection, id: i64, status: FindingStatus) -> Result<()> {
    conn.execute(
        "UPDATE findings SET status = ?1 WHERE id = ?2",
        params![status.as_str(), id],
    )?;
    Ok(())
}

pub fn recent_finding_exists(
    conn: &Connection,
    rule_id: &str,
    dedupe_key: &str,
    since: i64,
) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT id FROM findings WHERE rule_id = ?1 AND dedupe_key = ?2 AND ts >= ?3 LIMIT 1",
            params![rule_id, dedupe_key, since],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

pub fn agent_summaries(conn: &Connection) -> Result<Vec<AgentSummary>> {
    let since = crate::util::now_ms() - 24 * 3600 * 1000;
    let mut stmt = conn.prepare(
        "SELECT a.id, a.name, a.vendor, a.last_seen,
                COALESCE((SELECT SUM(v.bytes_out) FROM volumes v WHERE v.agent_id = a.id AND v.ts >= ?1), 0),
                COALESCE((SELECT COUNT(*) FROM findings f WHERE f.agent_id = a.id AND f.status = 'open'), 0),
                (SELECT MAX(f.severity) FROM findings f WHERE f.agent_id = a.id AND f.status = 'open')
         FROM agents a ORDER BY a.last_seen DESC",
    )?;
    let rows = stmt.query_map(params![since], |row| {
        let worst: Option<i64> = row.get(6)?;
        Ok(AgentSummary {
            id: row.get(0)?,
            name: row.get(1)?,
            vendor: row.get(2)?,
            last_seen: row.get(3)?,
            bytes_out_24h: row.get::<_, i64>(4)?.max(0) as u64,
            open_findings: row.get(5)?,
            worst_severity: worst.map(|w| match w {
                0 => Severity::Info,
                1 => Severity::Low,
                2 => Severity::Medium,
                3 => Severity::High,
                _ => Severity::Critical,
            }),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn destinations(conn: &Connection, since: i64, limit: i64) -> Result<Vec<DestinationSummary>> {
    let mut stmt = conn.prepare(
        "SELECT agent_id, COALESCE(remote_host, remote_addr) AS host, COUNT(*), MIN(ts), MAX(ts)
         FROM connections WHERE ts >= ?1
         GROUP BY agent_id, host ORDER BY MAX(ts) DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![since, limit], |row| {
        Ok(DestinationSummary {
            agent_id: row.get(0)?,
            host: row.get(1)?,
            connections: row.get(2)?,
            first_seen: row.get(3)?,
            last_seen: row.get(4)?,
            allowed: false,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn volume_series(
    conn: &Connection,
    agent_id: Option<&str>,
    since: i64,
    bucket_ms: i64,
) -> Result<Vec<VolumePoint>> {
    let bucket = bucket_ms.max(1000);
    let mut stmt = conn.prepare(
        "SELECT (ts / ?1) * ?1 AS bucket, SUM(bytes_out), SUM(bytes_in)
         FROM volumes WHERE ts >= ?2 AND (?3 IS NULL OR agent_id = ?3)
         GROUP BY bucket ORDER BY bucket ASC",
    )?;
    let rows = stmt.query_map(params![bucket, since, agent_id], |row| {
        Ok(VolumePoint {
            bucket: row.get(0)?,
            bytes_out: row.get::<_, i64>(1)?.max(0) as u64,
            bytes_in: row.get::<_, i64>(2)?.max(0) as u64,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRow {
    pub id: i64,
    pub ts: i64,
    pub agent_id: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub bytes_out: u64,
    pub class: String,
    pub sample: Option<String>,
    /// Whether a body was stored, without shipping it with every listing.
    pub has_body: bool,
}

/// `CREATE TABLE IF NOT EXISTS` silently skips databases from earlier
/// versions, so columns added later need an explicit upgrade step.
pub fn migrate(conn: &Connection) -> Result<()> {
    let columns: Vec<String> = {
        let mut stmt = conn.prepare("PRAGMA table_info(http_requests)")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        rows.filter_map(Result::ok).collect()
    };
    if !columns.iter().any(|name| name == "body") {
        conn.execute_batch("ALTER TABLE http_requests ADD COLUMN body TEXT;")?;
        tracing::info!("migrated: added http_requests.body");
    }
    Ok(())
}

/// Host of a capture, used to tell "no such id" apart from "not stored".
pub fn http_capture_host(conn: &Connection, id: i64) -> Result<Option<String>> {
    let host = conn
        .query_row(
            "SELECT host FROM http_requests WHERE id = ?1",
            params![id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(host)
}

/// Fetched on demand: bodies are large and only opened deliberately.
pub fn http_body(conn: &Connection, id: i64) -> Result<Option<String>> {
    let body = conn
        .query_row(
            "SELECT body FROM http_requests WHERE id = ?1",
            params![id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?;
    Ok(body.flatten())
}

pub fn http_requests(conn: &Connection, since: i64, limit: i64) -> Result<Vec<HttpRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, agent_id, host, method, path, bytes_out, class, sample,
                body IS NOT NULL
         FROM http_requests WHERE ts >= ?1 ORDER BY ts DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![since, limit], |row| {
        Ok(HttpRow {
            id: row.get(0)?,
            ts: row.get(1)?,
            agent_id: row.get(2)?,
            host: row.get(3)?,
            method: row.get(4)?,
            path: row.get(5)?,
            bytes_out: row.get::<_, i64>(6)?.max(0) as u64,
            class: row.get(7)?,
            sample: row.get(8)?,
            has_body: row.get::<_, i64>(9)? != 0,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRow {
    pub ts: i64,
    pub agent_id: String,
    pub path: String,
    pub size: u64,
    pub entropy: f32,
    pub kind: String,
    pub detail: String,
}

pub fn artifacts(conn: &Connection, since: i64, limit: i64) -> Result<Vec<ArtifactRow>> {
    let mut stmt = conn.prepare(
        "SELECT ts, agent_id, path, size, entropy, kind, detail FROM artifacts
         WHERE ts >= ?1 ORDER BY size DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![since, limit], |row| {
        Ok(ArtifactRow {
            ts: row.get(0)?,
            agent_id: row.get(1)?,
            path: row.get(2)?,
            size: row.get::<_, i64>(3)?.max(0) as u64,
            entropy: row.get(4)?,
            kind: row.get(5)?,
            detail: row.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventRow {
    pub ts: i64,
    pub pid: u32,
    pub agent_id: Option<String>,
    pub path: String,
    pub op: String,
}

pub fn file_event_rows(
    conn: &Connection,
    agent_id: Option<&str>,
    since: i64,
    limit: i64,
) -> Result<Vec<FileEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT ts, pid, agent_id, path, op FROM file_events
         WHERE ts >= ?1 AND (?2 IS NULL OR agent_id = ?2)
         ORDER BY ts DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![since, agent_id, limit], |row| {
        Ok(FileEventRow {
            ts: row.get(0)?,
            pid: row.get(1)?,
            agent_id: row.get(2)?,
            path: row.get(3)?,
            op: row.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn counts(conn: &Connection, since: i64) -> Result<(i64, i64, i64, i64)> {
    let one = |table: &str| -> Result<i64> {
        let mut stmt = conn.prepare(&format!("SELECT COUNT(*) FROM {table} WHERE ts >= ?1"))?;
        Ok(stmt.query_row(params![since], |row| row.get(0))?)
    };
    Ok((
        one("connections")?,
        one("file_events")?,
        one("http_requests")?,
        one("volumes")?,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

pub fn finding_counts(conn: &Connection) -> Result<FindingCounts> {
    let mut stmt = conn.prepare(
        "SELECT severity, COUNT(*) FROM findings WHERE status = 'open' GROUP BY severity",
    )?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
    let mut counts = FindingCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };
    for row in rows {
        let (severity, count) = row?;
        match severity {
            0 | 1 => counts.low += count,
            2 => counts.medium += count,
            3 => counts.high += count,
            _ => counts.critical += count,
        }
    }
    Ok(counts)
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (k, v) VALUES (?1, ?2)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT v FROM meta WHERE k = ?1", params![key], |row| {
        row.get(0)
    })
    .ok()
}

pub fn prune(conn: &Connection, retention_days: u32) -> Result<u64> {
    let cutoff = crate::util::now_ms() - (retention_days as i64) * 24 * 3600 * 1000;
    let finding_cutoff = crate::util::now_ms() - (retention_days.max(30) as i64) * 24 * 3600 * 1000;
    let mut removed = 0u64;
    for table in [
        "connections",
        "volumes",
        "file_events",
        "http_requests",
        "artifacts",
        "processes",
    ] {
        let column = if table == "processes" {
            "last_seen"
        } else {
            "ts"
        };
        removed += conn.execute(
            &format!("DELETE FROM {table} WHERE {column} < ?1"),
            params![cutoff],
        )? as u64;
    }
    removed += conn.execute(
        "DELETE FROM findings WHERE ts < ?1",
        params![finding_cutoff],
    )? as u64;
    Ok(removed)
}

pub enum StoreMsg {
    Event(Box<Event>),
    Findings(Vec<Finding>),
    Agents(Vec<AgentRecord>),
    Meta(String, String),
    Shutdown,
}

/// Dedicated single-writer thread: batching keeps the WAL small and avoids
/// writer contention with the read-only GUI/CLI connections.
pub struct StoreWriter {
    tx: Sender<StoreMsg>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StoreWriter {
    pub fn spawn(path: PathBuf, retention_days: u32) -> Result<StoreWriter> {
        let (tx, rx) = channel::<StoreMsg>();
        let handle = std::thread::Builder::new()
            .name("agentmon-store".into())
            .spawn(move || writer_loop(path, retention_days, rx))
            .context("spawning store writer thread")?;
        Ok(StoreWriter {
            tx,
            handle: Some(handle),
        })
    }

    pub fn send_event(&self, ev: Event) {
        let _ = self.tx.send(StoreMsg::Event(Box::new(ev)));
    }

    pub fn send_findings(&self, findings: Vec<Finding>) {
        if !findings.is_empty() {
            let _ = self.tx.send(StoreMsg::Findings(findings));
        }
    }

    pub fn send_agents(&self, agents: Vec<AgentRecord>) {
        if !agents.is_empty() {
            let _ = self.tx.send(StoreMsg::Agents(agents));
        }
    }

    pub fn set_meta(&self, key: &str, value: &str) {
        let _ = self
            .tx
            .send(StoreMsg::Meta(key.to_string(), value.to_string()));
    }

    pub fn shutdown(mut self) {
        let _ = self.tx.send(StoreMsg::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn writer_loop(path: PathBuf, retention_days: u32, rx: Receiver<StoreMsg>) {
    let conn = match open(&path) {
        Ok(conn) => conn,
        Err(err) => {
            tracing::error!("store writer failed to open {}: {err:#}", path.display());
            return;
        }
    };
    let mut batch: Vec<StoreMsg> = Vec::new();
    let mut last_prune = crate::util::now_ms();
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(StoreMsg::Shutdown) => break,
            Ok(msg) => batch.push(msg),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        while batch.len() < 2000 {
            match rx.try_recv() {
                Ok(StoreMsg::Shutdown) => {
                    flush(&conn, &mut batch);
                    return;
                }
                Ok(msg) => batch.push(msg),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        flush(&conn, &mut batch);
        if crate::util::now_ms() - last_prune > 3600 * 1000 {
            match prune(&conn, retention_days) {
                Ok(removed) if removed > 0 => tracing::debug!("pruned {removed} rows"),
                Ok(_) => {}
                Err(err) => tracing::warn!("prune failed: {err:#}"),
            }
            last_prune = crate::util::now_ms();
        }
    }
}

fn flush(conn: &Connection, batch: &mut Vec<StoreMsg>) {
    if batch.is_empty() {
        return;
    }
    if let Err(err) = conn.execute_batch("BEGIN") {
        tracing::warn!("begin failed: {err:#}");
        batch.clear();
        return;
    }
    for msg in batch.iter() {
        let result = match msg {
            StoreMsg::Event(ev) => insert_event(conn, ev),
            StoreMsg::Findings(findings) => {
                let mut res = Ok(());
                for f in findings {
                    res = insert_finding(conn, f).map(|_| ());
                    if res.is_err() {
                        break;
                    }
                }
                res
            }
            StoreMsg::Agents(agents) => {
                let mut res = Ok(());
                for agent in agents {
                    res = upsert_agent(conn, agent);
                    if res.is_err() {
                        break;
                    }
                }
                res
            }
            StoreMsg::Meta(key, value) => set_meta(conn, key, value),
            StoreMsg::Shutdown => Ok(()),
        };
        if let Err(err) = result {
            tracing::warn!("store insert failed: {err:#}");
        }
    }
    if let Err(err) = conn.execute_batch("COMMIT") {
        tracing::warn!("commit failed: {err:#}");
    }
    batch.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (PathBuf, Connection) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("agentmon-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("test-{}-{unique}.db", crate::util::now_ms()));
        let conn = open(&path).unwrap();
        (path, conn)
    }

    #[test]
    fn stores_and_reads_findings() {
        let (path, conn) = test_store();
        let mut finding = Finding::new("egress.unknown_domain", Severity::High, "test", "detail");
        finding.agent_id = Some("zcode".into());
        finding.dedupe_key = Some("zcode|1.2.3.4".into());
        finding.evidence = vec![Evidence::new("connection", "to 1.2.3.4")];
        let id = insert_finding(&conn, &finding).unwrap();
        assert!(id > 0);

        let listed = list_findings(&conn, &FindingFilter::default()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].severity, Severity::High);
        assert_eq!(listed[0].evidence.len(), 1);

        assert!(recent_finding_exists(&conn, "egress.unknown_domain", "zcode|1.2.3.4", 0).unwrap());
        assert!(!recent_finding_exists(&conn, "egress.unknown_domain", "other", 0).unwrap());

        set_finding_status(&conn, id, FindingStatus::Ignored).unwrap();
        let open = list_findings(&conn, &FindingFilter::default()).unwrap();
        assert!(open.is_empty());
        let all = list_findings(
            &conn,
            &FindingFilter {
                include_ignored: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(all.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn aggregates_volume_series() {
        let (path, conn) = test_store();
        // Align to a bucket boundary so all samples land in one 10s bucket.
        let now = (crate::util::now_ms() / 10_000) * 10_000 + 1_000;
        for i in 0..5 {
            insert_event(
                &conn,
                &Event::Volume(VolumeSample {
                    ts: now + i * 1000,
                    pid: 42,
                    agent_id: Some("claude-code".into()),
                    bytes_in: 10,
                    bytes_out: 100,
                    window_ms: 1000,
                }),
            )
            .unwrap();
        }
        let series = volume_series(&conn, Some("claude-code"), now - 1000, 10_000).unwrap();
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].bytes_out, 500);

        let summaries = agent_summaries(&conn).unwrap();
        assert!(summaries.len() <= 1);
        let _ = std::fs::remove_file(path);
    }
}
