use crate::model::ProcessInfo;
use crate::profiles::ProfileSet;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use sysinfo::{ProcessesToUpdate, System};

const MAX_ANCESTOR_DEPTH: usize = 12;

#[derive(Debug, Clone)]
pub struct ProcSnapshot {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub start_time: u64,
}

#[derive(Default)]
pub struct Registry {
    procs: HashMap<u32, ProcSnapshot>,
    agent_of: HashMap<u32, String>,
    excluded: HashSet<u32>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// Processes belonging to agentmon itself must never be flagged.
    pub fn exclude_self(&mut self) {
        let self_pid = std::process::id();
        self.excluded.insert(self_pid);
        if let Some(parent) = self.procs.get(&self_pid).and_then(|p| p.ppid) {
            self.excluded.insert(parent);
        }
    }

    pub fn refresh(&mut self, sys: &mut System, profiles: &ProfileSet) -> Vec<ProcessInfo> {
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let mut snapshots: HashMap<u32, ProcSnapshot> = HashMap::new();
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let exe = process.exe().map(|p| p.to_path_buf());
            let cmdline: Vec<String> = process
                .cmd()
                .iter()
                .map(|c| c.to_string_lossy().to_string())
                .collect();
            snapshots.insert(
                pid_u32,
                ProcSnapshot {
                    pid: pid_u32,
                    ppid: process.parent().map(|p| p.as_u32()),
                    name: process.name().to_string_lossy().to_string(),
                    exe,
                    cmdline,
                    cwd: process.cwd().map(|p| p.to_path_buf()),
                    start_time: process.start_time(),
                },
            );
        }

        let mut agent_of: HashMap<u32, String> = HashMap::new();
        let mut direct: HashMap<u32, String> = HashMap::new();
        for (pid, snap) in snapshots.iter() {
            if self.excluded.contains(pid) {
                continue;
            }
            if let Some(agent) =
                profiles.match_process(&snap.name, snap.exe.as_deref(), &snap.cmdline)
            {
                direct.insert(*pid, agent.to_string());
            }
        }

        for pid in snapshots.keys() {
            if self.excluded.contains(pid) {
                continue;
            }
            if let Some(agent) = direct.get(pid) {
                agent_of.insert(*pid, agent.clone());
                continue;
            }
            let mut cursor = snapshots.get(pid).and_then(|s| s.ppid);
            let mut depth = 0;
            while let Some(parent) = cursor {
                if depth > MAX_ANCESTOR_DEPTH {
                    break;
                }
                if let Some(agent) = direct.get(&parent) {
                    agent_of.insert(*pid, agent.clone());
                    break;
                }
                cursor = snapshots.get(&parent).and_then(|s| s.ppid);
                depth += 1;
            }
        }

        let ts = crate::util::now_ms();
        let mut changes = Vec::new();
        for (pid, agent) in agent_of.iter() {
            if let Some(snap) = snapshots.get(pid) {
                let changed = match self.procs.get(pid) {
                    Some(previous) => {
                        previous.start_time != snap.start_time
                            || self.agent_of.get(pid) != Some(agent)
                    }
                    None => true,
                };
                if changed {
                    changes.push(ProcessInfo {
                        pid: *pid,
                        ppid: snap.ppid,
                        name: snap.name.clone(),
                        exe: snap.exe.clone(),
                        cmdline: snap.cmdline.clone(),
                        cwd: snap.cwd.clone(),
                        agent_id: Some(agent.clone()),
                        start_time: snap.start_time,
                        ts,
                    });
                }
            }
        }

        self.procs = snapshots;
        self.agent_of = agent_of;
        changes
    }

    pub fn agent_id(&self, pid: u32) -> Option<&str> {
        self.agent_of.get(&pid).map(|s| s.as_str())
    }

    pub fn proc(&self, pid: u32) -> Option<&ProcSnapshot> {
        self.procs.get(&pid)
    }

    pub fn cwd(&self, pid: u32) -> Option<&Path> {
        self.procs.get(&pid).and_then(|p| p.cwd.as_deref())
    }

    pub fn exe(&self, pid: u32) -> Option<&Path> {
        self.procs.get(&pid).and_then(|p| p.exe.as_deref())
    }

    pub fn tracked_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.agent_of.keys().copied()
    }

    pub fn agent_count(&self) -> usize {
        self.agent_of.values().collect::<HashSet<_>>().len()
    }

    pub fn process_count(&self) -> usize {
        self.agent_of.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn attributes_child_processes_to_agent() {
        let mut registry = Registry::new();
        let profiles = ProfileSet::load(&Config::default()).unwrap();
        let mut sys = System::new_all();
        let changes = registry.refresh(&mut sys, &profiles);
        for change in changes {
            assert!(change.agent_id.is_some());
        }
    }
}
