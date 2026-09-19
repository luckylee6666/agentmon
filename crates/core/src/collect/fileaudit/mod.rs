pub mod darwin;
pub mod fanotify;

use super::CollectorCtx;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

pub trait FileAuditHandle: Send {
    fn stop(&mut self);
    fn available(&self) -> bool;
}

/// Per-pid event budget for the noisy half of the file audit: sensitive paths
/// are always reported, everything else is rate limited.
#[derive(Default)]
pub struct RateLimiter {
    window_start: i64,
    counts: std::collections::HashMap<u32, u32>,
}

impl RateLimiter {
    pub fn allow(&mut self, pid: u32, limit: u32) -> bool {
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

#[cfg(target_os = "macos")]
pub fn start(ctx: CollectorCtx) -> Box<dyn FileAuditHandle> {
    Box::new(darwin::start(ctx))
}

#[cfg(target_os = "linux")]
pub fn start(ctx: CollectorCtx) -> Box<dyn FileAuditHandle> {
    Box::new(linux::start(ctx))
}

#[cfg(target_os = "windows")]
pub fn start(ctx: CollectorCtx) -> Box<dyn FileAuditHandle> {
    Box::new(windows::start(ctx))
}
