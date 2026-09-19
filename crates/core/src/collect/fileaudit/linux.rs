use super::super::CollectorCtx;
use super::FileAuditHandle;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Linux file auditing will use fanotify (`FAN_CLASS_NOTIF` + mount marks in
/// legacy fd mode, so no `CAP_DAC_READ_SEARCH` is needed to resolve paths).
pub struct FanotifyAudit {
    stop: Arc<AtomicBool>,
}

impl FileAuditHandle for FanotifyAudit {
    fn stop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn available(&self) -> bool {
        false
    }
}

pub fn start(_ctx: CollectorCtx) -> FanotifyAudit {
    tracing::warn!("file read auditing on Linux (fanotify) is not implemented yet");
    FanotifyAudit {
        stop: Arc::new(AtomicBool::new(false)),
    }
}
