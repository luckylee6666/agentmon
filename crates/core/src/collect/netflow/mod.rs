pub mod connections;
pub mod nettop;

use super::CollectorCtx;
use crate::dns::{DnsState, PtrResolver};
use crate::model::{ConnectionSample, Event, VolumeSample};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct NetflowCollector {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl NetflowCollector {
    pub fn start(ctx: CollectorCtx, dns: Arc<DnsState>, ptr: Arc<PtrResolver>) -> NetflowCollector {
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        threads.push(spawn_connection_poller(ctx.clone(), dns, ptr, stop.clone()));

        #[cfg(target_os = "macos")]
        threads.push(spawn_nettop(ctx.clone(), stop.clone()));

        #[cfg(target_os = "linux")]
        threads.push(spawn_ss(ctx.clone(), stop.clone()));

        #[cfg(target_os = "windows")]
        tracing::warn!("per-process byte accounting is not implemented on Windows yet");

        NetflowCollector { stop, threads }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in std::mem::take(&mut self.threads) {
            let _ = thread.join();
        }
    }
}

fn sleep_until_next(interval: Duration, stop: &AtomicBool) {
    let step = Duration::from_millis(200);
    let mut waited = Duration::ZERO;
    while waited < interval {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(step.min(interval - waited));
        waited += step;
    }
}

fn spawn_connection_poller(
    ctx: CollectorCtx,
    dns: Arc<DnsState>,
    ptr: Arc<PtrResolver>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("agentmon-conn".into())
        .spawn(move || {
            let interval = Duration::from_millis(ctx.config.connection_poll_ms.max(1_000));
            let mut warned = false;
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                match connections::sample_connections() {
                    Ok(conns) => {
                        let ts = crate::util::now_ms();
                        for conn in conns {
                            if crate::util::is_loopback_ip(&conn.remote_ip) {
                                continue;
                            }
                            let Some(agent_id) = ctx.agent_for(conn.pid) else {
                                continue;
                            };
                            let host = dns.ptr(&conn.remote_ip);
                            if host.is_none() {
                                ptr.enqueue(&conn.remote_ip);
                            }
                            ctx.emit(Event::Connection(ConnectionSample {
                                ts,
                                pid: conn.pid,
                                agent_id: Some(agent_id),
                                remote_addr: match conn.remote_port {
                                    Some(port) => format!("{}:{}", conn.remote_ip, port),
                                    None => conn.remote_ip.clone(),
                                },
                                remote_ip: Some(conn.remote_ip),
                                remote_port: conn.remote_port,
                                remote_host: host,
                                proto: "tcp".into(),
                            }));
                        }
                    }
                    Err(err) => {
                        if !warned {
                            tracing::warn!("connection sampling unavailable: {err:#}");
                            warned = true;
                        }
                    }
                }
                sleep_until_next(interval, &stop);
            }
        })
        .expect("spawning connection poller")
}

#[cfg(target_os = "macos")]
fn spawn_nettop(ctx: CollectorCtx, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("agentmon-nettop".into())
        .spawn(move || run_nettop(ctx, stop))
        .expect("spawning nettop reader")
}

/// nettop only produces output when attached to a terminal, hence the pty.
#[cfg(target_os = "macos")]
fn run_nettop(ctx: CollectorCtx, stop: Arc<AtomicBool>) {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::{BufRead, BufReader};

    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(PtySize {
        rows: 60,
        cols: 400,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::error!("cannot open pty for nettop: {err:#}");
            return;
        }
    };

    let mut command = CommandBuilder::new("/usr/bin/nettop");
    command.args([
        "-P",
        "-x",
        "-l",
        "0",
        "-s",
        "1",
        "-J",
        "state,bytes_in,bytes_out",
    ]);
    let mut child = match pair.slave.spawn_command(command) {
        Ok(child) => child,
        Err(err) => {
            tracing::error!("cannot start nettop: {err:#}");
            return;
        }
    };
    drop(pair.slave);

    let reader = match pair.master.try_clone_reader() {
        Ok(reader) => reader,
        Err(err) => {
            tracing::error!("cannot read nettop pty: {err:#}");
            let _ = child.kill();
            return;
        }
    };
    let mut reader = BufReader::new(reader);
    let mut tracker = nettop::DeltaTracker::default();
    let mut line = String::new();
    let mut seen: Vec<u32> = Vec::new();

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let Some(row) = nettop::parse_line(&line) else {
                    continue;
                };
                seen.push(row.pid);
                let Some((delta_in, delta_out)) = tracker.apply(&row) else {
                    continue;
                };
                if delta_in == 0 && delta_out == 0 {
                    continue;
                }
                let Some(agent_id) = ctx.agent_for(row.pid) else {
                    continue;
                };
                ctx.emit(Event::Volume(VolumeSample {
                    ts: crate::util::now_ms(),
                    pid: row.pid,
                    agent_id: Some(agent_id),
                    bytes_in: delta_in,
                    bytes_out: delta_out,
                    window_ms: 1_000,
                }));
            }
            Err(_) => break,
        }
    }

    tracker.forget_missing(&seen);
    let _ = child.kill();
}

#[cfg(target_os = "linux")]
fn spawn_ss(ctx: CollectorCtx, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("agentmon-ss".into())
        .spawn(move || {
            let interval = Duration::from_secs(2);
            let mut tracker = nettop::DeltaTracker::default();
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                match sample_ss() {
                    Ok(rows) => {
                        let ts = crate::util::now_ms();
                        for row in rows {
                            let nettop_row = nettop::NettopRow {
                                name: row.command.clone(),
                                pid: row.pid,
                                bytes_in: row.received,
                                bytes_out: row.sent,
                            };
                            let Some((delta_in, delta_out)) = tracker.apply(&nettop_row) else {
                                continue;
                            };
                            if delta_in == 0 && delta_out == 0 {
                                continue;
                            }
                            let Some(agent_id) = ctx.agent_for(row.pid) else {
                                continue;
                            };
                            ctx.emit(Event::Volume(VolumeSample {
                                ts,
                                pid: row.pid,
                                agent_id: Some(agent_id),
                                bytes_in: delta_in,
                                bytes_out: delta_out,
                                window_ms: 2_000,
                            }));
                        }
                    }
                    Err(err) => tracing::debug!("ss sampling unavailable: {err:#}"),
                }
                sleep_until_next(interval, &stop);
            }
        })
        .expect("spawning ss sampler")
}

#[cfg(target_os = "linux")]
pub struct SsRow {
    pub pid: u32,
    pub command: String,
    pub sent: u64,
    pub received: u64,
}

/// `ss -tinp` reports per-socket counters; summing per pid approximates
/// per-process traffic (Linux has no unprivileged per-process byte counter).
#[cfg(target_os = "linux")]
pub fn sample_ss() -> anyhow::Result<Vec<SsRow>> {
    let output = std::process::Command::new("ss")
        .args(["-tinp", "-H"])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ss(&text))
}

#[cfg(target_os = "linux")]
pub fn parse_ss(text: &str) -> Vec<SsRow> {
    use std::collections::HashMap;
    let mut totals: HashMap<u32, SsRow> = HashMap::new();
    let mut current: Option<u32> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_detail = line.starts_with(' ') || line.starts_with('\t');
        if !is_detail {
            current = extract_pid(line);
            if let Some(pid) = current {
                totals.entry(pid).or_insert_with(|| SsRow {
                    pid,
                    command: String::new(),
                    sent: 0,
                    received: 0,
                });
            }
            continue;
        }
        let (Some(pid), true) = (current, trimmed.contains("bytes_acked")) else {
            continue;
        };
        let sent = extract_counter(trimmed, "bytes_acked:").unwrap_or(0);
        let received = extract_counter(trimmed, "bytes_received:").unwrap_or(0);
        if let Some(entry) = totals.get_mut(&pid) {
            entry.sent = entry.sent.saturating_add(sent);
            entry.received = entry.received.saturating_add(received);
        }
    }
    totals.into_values().collect()
}

#[cfg(target_os = "linux")]
fn extract_pid(line: &str) -> Option<u32> {
    let start = line.find("pid=")?;
    let rest = &line[start + 4..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

#[cfg(target_os = "linux")]
fn extract_counter(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)?;
    let rest = &line[start + key.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}
