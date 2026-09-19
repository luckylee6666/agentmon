use super::CollectorCtx;
use crate::model::Event;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct ProcScanCollector {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProcScanCollector {
    pub fn start(ctx: CollectorCtx) -> ProcScanCollector {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let handle = std::thread::Builder::new()
            .name("agentmon-proc".into())
            .spawn(move || {
                let mut system = sysinfo::System::new_all();
                let interval = Duration::from_millis(ctx.config.poll_interval_ms.max(500));
                let mut first_pass = true;
                loop {
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let changes = match ctx.registry.write() {
                        Ok(mut registry) => {
                            let changes = registry.refresh(&mut system, &ctx.profiles);
                            registry.exclude_self();
                            changes
                        }
                        Err(_) => Vec::new(),
                    };
                    if first_pass {
                        let agents: std::collections::BTreeSet<&str> = changes
                            .iter()
                            .filter_map(|info| info.agent_id.as_deref())
                            .collect();
                        tracing::info!(
                            processes = changes.len(),
                            agents = agents.into_iter().collect::<Vec<_>>().join(", "),
                            "initial agent process scan"
                        );
                        first_pass = false;
                    } else {
                        for info in &changes {
                            tracing::info!(
                                pid = info.pid,
                                agent = info.agent_id.as_deref().unwrap_or("-"),
                                cwd = info
                                    .cwd
                                    .as_ref()
                                    .map(|c| c.display().to_string())
                                    .unwrap_or_default(),
                                "new agent process"
                            );
                        }
                    }
                    for info in changes {
                        ctx.emit(Event::Process(info));
                    }
                    sleep(interval, &thread_stop);
                }
            })
            .expect("spawning process scanner");
        ProcScanCollector {
            stop,
            handle: Some(handle),
        }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn sleep(interval: Duration, stop: &AtomicBool) {
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
