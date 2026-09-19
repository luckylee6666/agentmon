use super::super::CollectorCtx;
use super::FileAuditHandle;
use crate::model::{Event, FileEvent, FileOp};
use crate::sensitive::SensitiveMatcher;
use serde_json::Value;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

/// `eslogger` is Apple's own Endpoint Security consumer. Using it avoids the
/// restricted `com.apple.developer.endpoint-security.client` entitlement that
/// an open-source tool cannot obtain, at the cost of parsing its JSON output.
const ESLOGGER: &str = "/usr/bin/eslogger";
const EVENTS: &[&str] = &["open", "create", "write", "rename", "unlink"];
const MAX_EVENTS_PER_SECOND_PER_PID: u32 = 400;

pub struct EsloggerAudit {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    available: bool,
}

impl FileAuditHandle for EsloggerAudit {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    fn available(&self) -> bool {
        self.available
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub fn start(ctx: CollectorCtx) -> EsloggerAudit {
    if !is_root() {
        tracing::warn!("file read auditing needs root; run the daemon as root to enable it");
        return EsloggerAudit {
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
            available: false,
        };
    }
    if !std::path::Path::new(ESLOGGER).exists() {
        tracing::warn!("{ESLOGGER} not present; file read auditing disabled");
        return EsloggerAudit {
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
            available: false,
        };
    }

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let handle = std::thread::Builder::new()
        .name("agentmon-eslogger".into())
        .spawn(move || run(ctx, thread_stop))
        .ok();

    let available = handle.is_some();
    EsloggerAudit {
        stop,
        handle,
        available,
    }
}

fn run(ctx: CollectorCtx, stop: Arc<AtomicBool>) {
    let mut command = std::process::Command::new(ESLOGGER);
    command.args(EVENTS);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            tracing::error!("cannot start eslogger: {err:#}");
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return,
    };
    let reader = BufReader::new(stdout);
    let stream = serde_json::Deserializer::from_reader(reader).into_iter::<Value>();
    let matcher = SensitiveMatcher::new(&ctx.config.sensitive_globs);
    let mut limiter = RateLimiter::default();

    for value in stream {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let Ok(value) = value else {
            continue;
        };
        let Some(event) = parse_event(&value) else {
            continue;
        };
        let Some(agent_id) = ctx.agent_for(event.pid) else {
            continue;
        };

        let sensitivity = matcher.classify(&event.path);
        let under_cwd = ctx
            .registry
            .read()
            .ok()
            .and_then(|registry| {
                registry
                    .cwd(event.pid)
                    .map(|cwd| event.path.starts_with(cwd))
            })
            .unwrap_or(false);

        if sensitivity.is_none() && !under_cwd {
            continue;
        }
        if sensitivity.is_none() && !limiter.allow(event.pid, MAX_EVENTS_PER_SECOND_PER_PID) {
            continue;
        }

        ctx.emit(Event::File(FileEvent {
            ts: event.ts,
            pid: event.pid,
            agent_id: Some(agent_id),
            path: event.path,
            op: event.op,
            source: "eslogger".into(),
            process_exe: event.process_exe,
        }));
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Default)]
struct RateLimiter {
    window_start: i64,
    counts: std::collections::HashMap<u32, u32>,
}

impl RateLimiter {
    fn allow(&mut self, pid: u32, limit: u32) -> bool {
        let now = crate::util::now_ms();
        if now - self.window_start >= 1000 {
            self.window_start = now;
            self.counts.clear();
        }
        let count = self.counts.entry(pid).or_insert(0);
        *count += 1;
        *count <= limit
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEvent {
    pub ts: i64,
    pub pid: u32,
    pub path: PathBuf,
    pub op: FileOp,
    pub process_exe: Option<String>,
}

pub fn parse_event(value: &Value) -> Option<ParsedEvent> {
    let pid = value
        .pointer("/process/audit_token/pid")
        .or_else(|| value.pointer("/process/pid"))
        .and_then(|v| v.as_u64())? as u32;

    let process_exe = value
        .pointer("/process/executable/path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let ts = value
        .pointer("/time")
        .and_then(|v| v.as_str())
        .and_then(parse_timestamp)
        .unwrap_or_else(crate::util::now_ms);

    let (op, path) = extract_operation(value)?;
    Some(ParsedEvent {
        ts,
        pid,
        path,
        op,
        process_exe,
    })
}

fn extract_operation(value: &Value) -> Option<(FileOp, PathBuf)> {
    let event = value.get("event")?.as_object()?;
    for (name, payload) in event {
        let op = match name.as_str() {
            "open" => FileOp::Open,
            "create" => FileOp::Create,
            "write" => FileOp::Write,
            "rename" => FileOp::Rename,
            "unlink" => FileOp::Unlink,
            _ => continue,
        };
        if let Some(path) = find_path(payload) {
            return Some((op, path));
        }
    }
    None
}

fn find_path(value: &Value) -> Option<PathBuf> {
    for key in ["file", "target", "source", "destination"] {
        if let Some(path) = value
            .pointer(&format!("/{key}/path"))
            .and_then(|v| v.as_str())
        {
            return Some(PathBuf::from(path));
        }
    }
    if let Some(path) = value.get("path").and_then(|v| v.as_str()) {
        return Some(PathBuf::from(path));
    }
    None
}

fn parse_timestamp(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_open_event() {
        let value = json!({
            "time": "2026-09-19T10:00:00.000Z",
            "event": {"open": {"file": {"path": "/Users/me/proj/.git/config"}}},
            "process": {
                "audit_token": {"pid": 4321},
                "executable": {"path": "/Applications/ZCode.app/Contents/MacOS/ZCode"}
            }
        });
        let parsed = parse_event(&value).unwrap();
        assert_eq!(parsed.pid, 4321);
        assert_eq!(parsed.op, FileOp::Open);
        assert_eq!(parsed.path, PathBuf::from("/Users/me/proj/.git/config"));
        assert!(parsed.process_exe.unwrap().contains("ZCode"));
    }

    #[test]
    fn parses_rename_event_source() {
        let value = json!({
            "event": {"rename": {"source": {"path": "/tmp/a"}, "destination": {"path": "/tmp/b"}}},
            "process": {"pid": 7}
        });
        let parsed = parse_event(&value).unwrap();
        assert_eq!(parsed.op, FileOp::Rename);
        assert_eq!(parsed.path, PathBuf::from("/tmp/a"));
    }

    #[test]
    fn ignores_unrelated_events() {
        let value = json!({
            "event": {"exec": {"target": {"path": "/bin/ls"}}},
            "process": {"pid": 7}
        });
        assert!(parse_event(&value).is_none());
    }

    #[test]
    fn parses_concatenated_json_stream() {
        let raw = r#"{"event":{"open":{"file":{"path":"/a"}}},"process":{"pid":1}}
{"event":{"open":{"file":{"path":"/b"}}},"process":{"pid":2}}"#;
        let stream = serde_json::Deserializer::from_str(raw).into_iter::<Value>();
        let parsed: Vec<_> = stream.flatten().filter_map(|v| parse_event(&v)).collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].path, PathBuf::from("/b"));
    }
}
