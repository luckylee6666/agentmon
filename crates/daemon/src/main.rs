use agentmon_core::alert::Alerter;
use agentmon_core::config::Config;
use agentmon_core::detect::{DetectCtx, Detector};
use agentmon_core::model::AgentRecord;
use agentmon_core::pipeline::{Pipeline, PipelineAvailability};
use agentmon_core::profiles::ProfileSet;
use agentmon_core::store::StoreWriter;
use agentmon_core::{paths, util};
use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "agentmond",
    version,
    about = "agentmon daemon: collects, detects and stores AI agent upload activity"
)]
struct Args {
    /// Path to config.yaml
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the data directory (where agentmon.db lives)
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Force the per-user data directory even when running as root
    #[arg(long)]
    user_data_dir: bool,

    /// Exit after N seconds (useful for tests)
    #[arg(long)]
    duration: Option<u64>,

    /// Disable desktop notifications
    #[arg(long)]
    no_desktop: bool,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);
    harden_process();

    let config_path = args.config.clone().unwrap_or_else(paths::config_file);
    let mut config = Config::load(&config_path)?;
    if args.no_desktop {
        config.alert.desktop = false;
    }
    let config = Arc::new(config);
    let profiles = Arc::new(ProfileSet::load(&config)?);
    let root = agentmon_core::util::is_root();

    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(|| paths::data_dir(root && !args.user_data_dir));
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let db_path = data_dir.join("agentmon.db");

    let store = StoreWriter::spawn(db_path.clone(), config.retention_days)?;
    store.send_agents(agent_records(&profiles));

    let (mut pipeline, mut events) = Pipeline::start(config.clone(), profiles.clone()).await;
    let registry = pipeline.registry.clone();
    let mut detector = Detector::new(config.clone(), profiles.clone(), pipeline.dns.clone());
    let alerter = Alerter::new(config.clone());

    print_banner(&db_path, &pipeline.availability, root);
    store.set_meta("pid", &std::process::id().to_string());
    store.set_meta(
        "file_audit",
        if pipeline.availability.file_audit {
            "1"
        } else {
            "0"
        },
    );
    match pipeline.availability.proxy {
        Some(addr) => store.set_meta("proxy_addr", &addr.to_string()),
        None => store.set_meta("proxy_addr", ""),
    }

    let deadline = args
        .duration
        .map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs));

    loop {
        tokio::select! {
            maybe_event = events.recv() => {
                let Some(event) = maybe_event else { break };
                let findings = {
                    let registry = registry.read().unwrap_or_else(|e| e.into_inner());
                    detector.evaluate(&event, DetectCtx { registry: &registry })
                };
                if !findings.is_empty() {
                    store.send_findings(findings.clone());
                    alerter.dispatch(&findings).await;
                }
                store.send_event(event);
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("interrupted, shutting down");
                break;
            }
            _ = sleep_until(deadline) => {
                tracing::info!("duration elapsed, shutting down");
                break;
            }
        }
    }

    pipeline.stop();
    store.shutdown();
    Ok(())
}

async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(instant) => tokio::time::sleep_until(instant).await,
        None => std::future::pending::<()>().await,
    }
}

/// Only agents actually present on this machine are recorded; a profile that is
/// merely bundled must not show up as "seen 21s ago" in reports.
fn agent_records(profiles: &ProfileSet) -> Vec<AgentRecord> {
    let now = util::now_ms();
    profiles
        .installed_profiles()
        .into_iter()
        .map(|profile| AgentRecord {
            id: profile.id.clone(),
            name: profile.name.clone(),
            vendor: profile.vendor.clone(),
            first_seen: now,
            last_seen: now,
        })
        .collect()
}

/// When running as root, everything written must stay unreadable to other local
/// users: findings contain paths and destinations that are nobody else's
/// business. umask 027 keeps SQLite's own files at 0640 and the `agentmon`
/// group lets the desktop app read them.
fn harden_process() {
    #[cfg(unix)]
    {
        if !agentmon_core::util::is_root() {
            return;
        }
        // SAFETY: umask only changes a process-local setting.
        unsafe { libc::umask(0o027) };

        let data_dir = paths::data_dir(true);
        if let Err(err) = std::fs::create_dir_all(&data_dir) {
            eprintln!("cannot create {}: {err}", data_dir.display());
            return;
        }
        if let Some(gid) = lookup_group("agentmon") {
            let _ = std::process::Command::new("/usr/bin/chown")
                .arg(format!("root:{gid}"))
                .arg(&data_dir)
                .status();
            let _ = std::process::Command::new("/bin/chmod")
                .arg("0750")
                .arg(&data_dir)
                .status();
        } else {
            let _ = std::process::Command::new("/bin/chmod")
                .arg("0700")
                .arg(&data_dir)
                .status();
        }
    }
}

#[cfg(unix)]
fn lookup_group(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let c_name = CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer to a static buffer; the gid is copied
    // out immediately and the pointer is not retained.
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        None
    } else {
        Some(unsafe { (*group).gr_gid })
    }
}

fn print_banner(db: &std::path::Path, availability: &PipelineAvailability, root: bool) {
    println!("agentmon daemon {}", agentmon_core::VERSION);
    println!(
        "  mode          : {}",
        if root {
            "root (file read audit enabled)"
        } else {
            "user (run with sudo for file read audit)"
        }
    );
    println!("  database      : {}", db.display());
    println!(
        "  file audit    : {}",
        if availability.file_audit {
            "active"
        } else {
            "inactive"
        }
    );
    println!(
        "  byte counters : {}",
        if availability.byte_accounting {
            "per-process (nettop)"
        } else {
            "approximate"
        }
    );
    match availability.proxy {
        Some(addr) => {
            println!("  content proxy : http://{addr}");
            println!(
                "                  (use `agentmon wrap -- <cmd>` to route an agent through it)"
            );
        }
        None => println!("  content proxy : disabled"),
    }
}

fn init_logging(level: &str) {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| format!("agentmond={level},agentmon_core={level}"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
