use agentmon_core::collect::artifacts;
use agentmon_core::config::Config;
use agentmon_core::detect::{DetectCtx, Detector};
use agentmon_core::install;
use agentmon_core::model::{Event, Finding, FindingStatus, Severity};
use agentmon_core::paths;
use agentmon_core::profiles::ProfileSet;
use agentmon_core::registry::Registry;
use agentmon_core::store;
use agentmon_core::util;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[derive(Serialize)]
pub struct DbInfo {
    pub path: String,
    pub exists: bool,
    pub system: bool,
    pub daemon_active: bool,
    pub file_audit: bool,
    pub db_readable: bool,
    pub proxy_addr: Option<String>,
    pub db_size: u64,
    pub version: String,
}

#[derive(Serialize)]
pub struct Stats {
    pub agents_seen: i64,
    pub connections_24h: i64,
    pub file_events_24h: i64,
    pub http_requests_24h: i64,
    pub volume_samples_24h: i64,
    pub bytes_out_24h: u64,
}

#[derive(Serialize)]
pub struct Overview {
    pub info: DbInfo,
    pub stats: Stats,
    pub agents: Vec<AgentDto>,
    pub findings: Vec<Finding>,
    pub volume: Vec<VolumePointDto>,
    pub destinations: Vec<DestinationDto>,
    pub artifacts: Vec<store::ArtifactRow>,
}

#[derive(Serialize)]
pub struct AgentDto {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub last_seen: i64,
    pub bytes_out_24h: u64,
    pub open_findings: i64,
    pub worst_severity: Option<String>,
    pub installed: bool,
    pub data_dir_bytes: u64,
}

#[derive(Serialize)]
pub struct VolumePointDto {
    pub bucket: i64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Serialize)]
pub struct DestinationDto {
    pub agent_id: Option<String>,
    pub host: String,
    pub connections: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub allowed: bool,
}

fn open_readonly() -> CmdResult<(rusqlite::Connection, PathBuf)> {
    let path = paths::active_db_path();
    if !path.exists() {
        return Err(format!("数据库不存在: {}", path.display()));
    }
    let conn = store::open_readonly(&path).map_err(err)?;
    Ok((conn, path))
}

fn db_info() -> DbInfo {
    let system = paths::db_path(true);
    let active = paths::active_db_path();
    let exists = active.exists();
    let daemon_active = exists
        && std::fs::metadata(&active)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .map(|elapsed| elapsed.as_secs() < 120)
            .unwrap_or(false);
    let proxy_addr = if exists {
        store::open_readonly(&active)
            .ok()
            .and_then(|conn| store::get_meta(&conn, "proxy_addr"))
            .filter(|value| !value.is_empty())
    } else {
        None
    };
    let db_readable = exists && store::open_readonly(&active).is_ok();
    let file_audit = if exists {
        store::open_readonly(&active)
            .ok()
            .and_then(|conn| store::get_meta(&conn, "file_audit"))
            .map(|value| value == "1")
            .unwrap_or(false)
    } else {
        false
    };
    DbInfo {
        path: active.display().to_string(),
        exists,
        system: active == system,
        daemon_active,
        file_audit,
        db_readable,
        proxy_addr,
        db_size: std::fs::metadata(&active).map(|m| m.len()).unwrap_or(0),
        version: agentmon_core::VERSION.to_string(),
    }
}

/// The daemon ships inside the bundle; in a dev tree it is the sibling
/// `target/release/agentmond` next to `target/debug/agentmon-app`.
fn find_daemon_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let mut candidates = vec![dir.join("agentmond")];
    if let Some(contents) = dir.parent() {
        candidates.push(contents.join("Resources").join("agentmond"));
        candidates.push(contents.join("MacOS").join("agentmond"));
    }
    if let Some(target) = dir.parent() {
        candidates.push(target.join("release").join("agentmond"));
        candidates.push(target.join("debug").join("agentmond"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

/// Runs a shell script as root through the system authorisation dialog.
/// Everything in the script comes from a plan this crate built, never from the
/// UI, and it is passed as a single AppleScript argument so there is no
/// temporary file to race with.
fn run_privileged(script: &str) -> CmdResult<String> {
    let escaped = script.replace('\\', "\\\\").replace('"', "\\\"");
    let applescript = format!("do shell script \"{escaped}\" with administrator privileges");
    let output = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&applescript)
        .output()
        .map_err(|err| format!("无法调用 osascript: {err}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        return Ok(stdout);
    }
    if stderr.contains("-128") || stderr.contains("User canceled") {
        return Err("已取消授权".into());
    }
    Err(if stderr.is_empty() { stdout } else { stderr })
}

#[tauri::command]
fn daemon_status() -> CmdResult<install::ServiceStatus> {
    Ok(install::service_status())
}

#[tauri::command]
fn daemon_plan(action: String) -> CmdResult<Vec<String>> {
    let steps = match action.as_str() {
        "uninstall" => install::plan_uninstall(),
        _ => {
            let binary =
                find_daemon_binary().ok_or("找不到 agentmond（守护进程二进制），无法安装")?;
            install::plan_install(&install::InstallOptions {
                dry_run: false,
                user: None,
                binary: Some(binary),
                no_start: false,
            })
            .map_err(err)?
        }
    };
    Ok(install::describe(&steps))
}

#[tauri::command]
fn daemon_run(action: String) -> CmdResult<String> {
    let steps = match action.as_str() {
        "uninstall" => install::plan_uninstall(),
        _ => {
            let binary =
                find_daemon_binary().ok_or("找不到 agentmond（守护进程二进制），无法安装")?;
            install::plan_install(&install::InstallOptions {
                dry_run: false,
                user: None,
                binary: Some(binary),
                no_start: false,
            })
            .map_err(err)?
        }
    };
    run_privileged(&install::render_script(&steps))
}

#[tauri::command]
fn get_overview(since_ms: Option<i64>) -> CmdResult<Overview> {
    let info = db_info();
    let since = since_ms.unwrap_or_else(|| util::now_ms() - 24 * 3600 * 1000);

    let (profiles, agents) = match open_readonly() {
        Ok((conn, _)) => {
            let config = Arc::new(Config::load_or_default_path());
            let profiles = Arc::new(ProfileSet::load(&config).map_err(err)?);
            let summaries = store::agent_summaries(&conn).map_err(err)?;
            let installed: std::collections::HashSet<String> = profiles
                .installed_profiles()
                .iter()
                .map(|p| p.id.clone())
                .collect();
            let agents = summaries
                .into_iter()
                .map(|summary| AgentDto {
                    worst_severity: summary.worst_severity.map(|s| s.as_str().to_string()),
                    id: summary.id.clone(),
                    name: summary.name,
                    vendor: summary.vendor,
                    last_seen: summary.last_seen,
                    bytes_out_24h: summary.bytes_out_24h,
                    open_findings: summary.open_findings,
                    installed: installed.contains(&summary.id),
                    data_dir_bytes: 0,
                })
                .collect();
            (profiles, agents)
        }
        Err(_) => {
            let config = Arc::new(Config::load_or_default_path());
            let profiles = Arc::new(ProfileSet::load(&config).map_err(err)?);
            (profiles, Vec::new())
        }
    };
    let _ = profiles;

    let (stats, findings, volume, destinations, artifacts) = match open_readonly() {
        Ok((conn, _)) => {
            let counts = store::counts(&conn, since).map_err(err)?;
            let bytes_out: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(bytes_out), 0) FROM volumes WHERE ts >= ?1",
                    rusqlite::params![since],
                    |row| row.get(0),
                )
                .map_err(err)?;
            let findings = store::list_findings(
                &conn,
                &store::FindingFilter {
                    limit: 100,
                    ..Default::default()
                },
            )
            .map_err(err)?;
            let volume = store::volume_series(&conn, None, since, 15 * 60 * 1000)
                .map_err(err)?
                .into_iter()
                .map(|point| VolumePointDto {
                    bucket: point.bucket,
                    bytes_out: point.bytes_out,
                    bytes_in: point.bytes_in,
                })
                .collect();
            let destinations = store::destinations(&conn, since, 200)
                .map_err(err)?
                .into_iter()
                .map(|d| DestinationDto {
                    agent_id: d.agent_id,
                    host: d.host,
                    connections: d.connections,
                    first_seen: d.first_seen,
                    last_seen: d.last_seen,
                    allowed: false,
                })
                .collect();
            let artifacts = store::artifacts(&conn, 0, 100).map_err(err)?;
            (
                Stats {
                    agents_seen: agents.len() as i64,
                    connections_24h: counts.0,
                    file_events_24h: counts.1,
                    http_requests_24h: counts.2,
                    volume_samples_24h: counts.3,
                    bytes_out_24h: bytes_out.max(0) as u64,
                },
                findings,
                volume,
                destinations,
                artifacts,
            )
        }
        Err(_) => (
            Stats {
                agents_seen: agents.len() as i64,
                connections_24h: 0,
                file_events_24h: 0,
                http_requests_24h: 0,
                volume_samples_24h: 0,
                bytes_out_24h: 0,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
    };

    Ok(Overview {
        info,
        stats,
        agents,
        findings,
        volume,
        destinations,
        artifacts,
    })
}

#[tauri::command]
fn list_findings(
    limit: Option<i64>,
    severity: Option<String>,
    agent_id: Option<String>,
    include_ignored: Option<bool>,
) -> CmdResult<Vec<Finding>> {
    let (conn, _) = open_readonly()?;
    let filter = store::FindingFilter {
        min_severity: severity.as_deref().and_then(Severity::parse),
        agent_id,
        rule_id: None,
        include_ignored: include_ignored.unwrap_or(false),
        limit: limit.unwrap_or(200),
    };
    store::list_findings(&conn, &filter).map_err(err)
}

#[tauri::command]
fn set_finding_ignored(id: i64, ignored: bool) -> CmdResult<()> {
    let path = paths::active_db_path();
    let conn = store::open(&path).map_err(err)?;
    let status = if ignored {
        FindingStatus::Ignored
    } else {
        FindingStatus::Open
    };
    store::set_finding_status(&conn, id, status).map_err(err)
}

#[tauri::command]
fn list_file_events(
    agent_id: Option<String>,
    since_ms: Option<i64>,
    limit: Option<i64>,
) -> CmdResult<Vec<store::FileEventRow>> {
    let (conn, _) = open_readonly()?;
    let since = since_ms.unwrap_or_else(|| util::now_ms() - 24 * 3600 * 1000);
    store::file_event_rows(&conn, agent_id.as_deref(), since, limit.unwrap_or(300)).map_err(err)
}

#[tauri::command]
fn list_http_requests(since_ms: Option<i64>, limit: Option<i64>) -> CmdResult<Vec<store::HttpRow>> {
    let (conn, _) = open_readonly()?;
    let since = since_ms.unwrap_or_else(|| util::now_ms() - 24 * 3600 * 1000);
    store::http_requests(&conn, since, limit.unwrap_or(300)).map_err(err)
}

/// Bodies are fetched one at a time, never with the listing: they contain the
/// user's prompts and source code verbatim.
#[tauri::command]
fn http_body(id: i64) -> CmdResult<Option<String>> {
    let (conn, _) = open_readonly()?;
    store::http_body(&conn, id).map_err(err)
}

#[tauri::command]
fn list_artifacts(limit: Option<i64>) -> CmdResult<Vec<store::ArtifactRow>> {
    let (conn, _) = open_readonly()?;
    store::artifacts(&conn, 0, limit.unwrap_or(200)).map_err(err)
}

#[tauri::command]
fn egress(
    since_ms: Option<i64>,
    bucket_ms: Option<i64>,
    agent_id: Option<String>,
) -> CmdResult<Vec<VolumePointDto>> {
    let (conn, _) = open_readonly()?;
    let since = since_ms.unwrap_or_else(|| util::now_ms() - 6 * 3600 * 1000);
    let points = store::volume_series(
        &conn,
        agent_id.as_deref(),
        since,
        bucket_ms.unwrap_or(300_000),
    )
    .map_err(err)?;
    Ok(points
        .into_iter()
        .map(|point| VolumePointDto {
            bucket: point.bucket,
            bytes_out: point.bytes_out,
            bytes_in: point.bytes_in,
        })
        .collect())
}

#[tauri::command]
fn destinations(since_ms: Option<i64>, limit: Option<i64>) -> CmdResult<Vec<DestinationDto>> {
    let (conn, _) = open_readonly()?;
    let since = since_ms.unwrap_or_else(|| util::now_ms() - 24 * 3600 * 1000);
    let rows = store::destinations(&conn, since, limit.unwrap_or(200)).map_err(err)?;
    Ok(rows
        .into_iter()
        .map(|d| DestinationDto {
            agent_id: d.agent_id,
            host: d.host,
            connections: d.connections,
            first_seen: d.first_seen,
            last_seen: d.last_seen,
            allowed: false,
        })
        .collect())
}

/// Runs the static artifact scan on demand, returning the findings it produces.
#[tauri::command]
fn run_scan(deep: Option<bool>) -> CmdResult<Vec<Finding>> {
    let config = Arc::new(Config::load_or_default_path());
    let profiles = Arc::new(ProfileSet::load(&config).map_err(err)?);
    let outcome = artifacts::scan(&profiles, &config, deep.unwrap_or(true));
    let dns = agentmon_core::dns::DnsState::new();
    let mut detector = Detector::new(config, profiles, dns);
    let registry = Registry::new();
    let ctx = DetectCtx {
        registry: &registry,
    };
    let mut findings = Vec::new();
    for artifact in outcome
        .artifacts
        .iter()
        .cloned()
        .chain(artifacts::endpoint_artifacts(&outcome))
    {
        findings.extend(detector.evaluate(&Event::Artifact(artifact), ctx));
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    Ok(findings)
}

#[tauri::command]
fn list_agent_profiles() -> CmdResult<Vec<serde_json::Value>> {
    let config = Arc::new(Config::load_or_default_path());
    let profiles = ProfileSet::load(&config).map_err(err)?;
    Ok(profiles
        .all()
        .map(|profile| {
            serde_json::json!({
                "id": profile.id,
                "name": profile.name,
                "vendor": profile.vendor,
                "installed": profile.installed(),
                "data_dirs": profile.data_dirs,
                "allowed_domains": profile.allowed_domains,
                "telemetry_domains": profile.telemetry_domains,
                "notes": profile.notes,
            })
        })
        .collect())
}

#[tauri::command]
fn paths_info() -> CmdResult<serde_json::Value> {
    Ok(serde_json::json!({
        "config": paths::config_file().display().to_string(),
        "profiles_dir": paths::user_profiles_dir().display().to_string(),
        "db_user": paths::db_path(false).display().to_string(),
        "db_system": paths::db_path(true).display().to_string(),
        "data_dir_user": paths::data_dir(false).display().to_string(),
        "data_dir_system": paths::data_dir(true).display().to_string(),
    }))
}

#[tauri::command]
fn get_config() -> CmdResult<serde_json::Value> {
    let config = Config::load_or_default_path();
    serde_json::to_value(&config).map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_overview,
            list_findings,
            set_finding_ignored,
            list_file_events,
            list_http_requests,
            http_body,
            daemon_status,
            daemon_plan,
            daemon_run,
            list_artifacts,
            egress,
            destinations,
            run_scan,
            list_agent_profiles,
            paths_info,
            get_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
