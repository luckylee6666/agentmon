pub mod darwin;

use super::CollectorCtx;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

pub trait FileAuditHandle: Send {
    fn stop(&mut self);
    fn available(&self) -> bool;
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
