use crate::config::Config;
use crate::profiles::ProfileSet;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, mpsc};
use std::time::Duration;

#[derive(Default)]
pub struct DnsState {
    allowed_ips: RwLock<HashSet<String>>,
    ptr: RwLock<HashMap<String, Option<String>>>,
}

impl DnsState {
    pub fn new() -> Arc<DnsState> {
        Arc::new(DnsState::default())
    }

    pub fn allowed_ips(&self) -> HashSet<String> {
        self.allowed_ips
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn is_allowed_ip(&self, ip: &str) -> bool {
        self.allowed_ips
            .read()
            .map(|s| s.contains(ip))
            .unwrap_or(false)
    }

    pub fn ptr(&self, ip: &str) -> Option<String> {
        self.ptr
            .read()
            .ok()
            .and_then(|m| m.get(ip).cloned().flatten())
    }

    fn set_ptr(&self, ip: &str, name: Option<String>) {
        if let Ok(mut map) = self.ptr.write() {
            map.insert(ip.to_string(), name);
        }
    }

    fn set_allowed(&self, ips: HashSet<String>) {
        if let Ok(mut set) = self.allowed_ips.write() {
            *set = ips;
        }
    }
}

/// Reverse lookups can block for seconds, so they run on a small worker set
/// with a cache; callers only ever read the cache.
pub struct PtrResolver {
    tx: mpsc::Sender<String>,
}

impl PtrResolver {
    pub fn spawn(state: Arc<DnsState>, workers: usize) -> PtrResolver {
        let (tx, rx) = mpsc::channel::<String>();
        let rx = Arc::new(std::sync::Mutex::new(rx));
        for _ in 0..workers.max(1) {
            let state = state.clone();
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name("agentmon-ptr".into())
                .spawn(move || {
                    loop {
                        let ip = match rx.lock() {
                            Ok(guard) => match guard.recv() {
                                Ok(ip) => ip,
                                Err(_) => break,
                            },
                            Err(_) => break,
                        };
                        if state.ptr(&ip).is_some() {
                            continue;
                        }
                        let parsed: Result<std::net::IpAddr, _> = ip.parse();
                        let name = match parsed {
                            Ok(addr) => dns_lookup::lookup_addr(&addr).ok(),
                            Err(_) => None,
                        };
                        state.set_ptr(&ip, name);
                    }
                });
        }
        PtrResolver { tx }
    }

    pub fn enqueue(&self, ip: &str) {
        let _ = self.tx.send(ip.to_string());
    }
}

pub async fn refresh_allowed_ips(state: &Arc<DnsState>, profiles: &ProfileSet, config: &Config) {
    let mut domains: Vec<String> = Vec::new();
    for profile in profiles.all() {
        domains.extend(profile.allowed_domains.iter().cloned());
        domains.extend(profile.telemetry_domains.iter().cloned());
    }
    domains.extend(config.global_allowed_domains.iter().cloned());
    domains.sort();
    domains.dedup();

    let mut ips: HashSet<String> = HashSet::new();
    for domain in domains {
        let host = domain.trim_start_matches("*.").to_string();
        let lookup = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host.as_str(), 443)),
        )
        .await;
        if let Ok(Ok(addrs)) = lookup {
            for addr in addrs {
                ips.insert(addr.ip().to_string());
            }
        }
    }
    tracing::info!("resolved {} allowlisted IPs", ips.len());
    state.set_allowed(ips);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_negative_lookups() {
        let state = DnsState::new();
        assert!(state.ptr("192.0.2.1").is_none());
        state.set_ptr("192.0.2.1", None);
        assert!(state.ptr("192.0.2.1").is_none());
        state.set_ptr("192.0.2.1", Some("example.test".into()));
        assert_eq!(state.ptr("192.0.2.1").as_deref(), Some("example.test"));
    }

    #[test]
    fn allowed_ip_set_roundtrips() {
        let state = DnsState::new();
        let mut ips = HashSet::new();
        ips.insert("1.2.3.4".to_string());
        state.set_allowed(ips);
        assert!(state.is_allowed_ip("1.2.3.4"));
        assert!(!state.is_allowed_ip("5.6.7.8"));
    }
}
