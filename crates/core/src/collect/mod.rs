use super::model::Event;
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use std::sync::{Arc, RwLock};

pub type EventSink = tokio::sync::mpsc::UnboundedSender<Event>;

pub mod artifacts;
pub mod fileaudit;
pub mod netflow;
pub mod procscan;

pub type SharedRegistry = Arc<RwLock<Registry>>;

#[derive(Clone)]
pub struct CollectorCtx {
    pub sink: EventSink,
    pub registry: SharedRegistry,
    pub profiles: Arc<ProfileSet>,
    pub config: Arc<crate::config::Config>,
}

impl CollectorCtx {
    pub fn emit(&self, ev: Event) {
        let _ = self.sink.send(ev);
    }

    pub fn agent_for(&self, pid: u32) -> Option<String> {
        self.registry
            .read()
            .ok()
            .and_then(|r| r.agent_id(pid).map(|s| s.to_string()))
    }

    pub fn tracked_pids(&self) -> Vec<u32> {
        self.registry
            .read()
            .map(|r| r.tracked_pids().collect())
            .unwrap_or_default()
    }
}
