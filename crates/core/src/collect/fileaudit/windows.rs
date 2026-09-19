use super::super::CollectorCtx;
use super::FileAuditHandle;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Windows file auditing will consume the `Microsoft-Windows-Kernel-File`
/// ETW provider (admin required), filtering by issuing pid.
pub struct EtwAudit {
    stop: Arc<AtomicBool>,
}

impl FileAuditHandle for EtwAudit {
    fn stop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn available(&self) -> bool {
        false
    }
}

pub fn start(_ctx: CollectorCtx) -> EtwAudit {
    tracing::warn!("file read auditing on Windows (ETW Kernel-File) is not implemented yet");
    EtwAudit {
        stop: Arc::new(AtomicBool::new(false)),
    }
}
