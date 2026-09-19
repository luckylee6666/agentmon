use crate::config::Config;
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

macro_rules! builtin_profiles {
    ($($file:literal),* $(,)?) => {
        &[$(include_str!(concat!("../../../profiles/", $file)),)*]
    };
}

pub const BUILTIN_PROFILES: &[&str] = builtin_profiles![
    "aider.yaml",
    "claude-code.yaml",
    "codex-cli.yaml",
    "command-code.yaml",
    "copilot-cli.yaml",
    "crush.yaml",
    "cursor-agent.yaml",
    "droid.yaml",
    "gemini-cli.yaml",
    "goose.yaml",
    "iflow-cli.yaml",
    "kiro.yaml",
    "opencode.yaml",
    "qwen-code.yaml",
    "trae.yaml",
    "windsurf.yaml",
    "zcode.yaml",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessMatch {
    pub names: Vec<String>,
    pub exe: Vec<String>,
    pub cmdline_contains: Vec<String>,
    pub cmdline_regex: Vec<String>,
}

impl ProcessMatch {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.exe.is_empty()
            && self.cmdline_contains.is_empty()
            && self.cmdline_regex.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub process: ProcessMatch,
    #[serde(default)]
    pub data_dirs: Vec<String>,
    #[serde(default)]
    pub config_files: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub telemetry_domains: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl AgentProfile {
    pub fn data_dir_paths(&self) -> Vec<PathBuf> {
        self.data_dirs
            .iter()
            .map(|d| crate::util::expand_tilde(d))
            .collect()
    }

    pub fn config_file_paths(&self) -> Vec<PathBuf> {
        self.config_files
            .iter()
            .map(|d| crate::util::expand_tilde(d))
            .collect()
    }

    pub fn installed(&self) -> bool {
        self.data_dir_paths().iter().any(|p| p.exists())
            || self.config_file_paths().iter().any(|p| p.exists())
    }
}

pub struct CompiledProfile {
    pub raw: AgentProfile,
    exe: Option<GlobSet>,
    cmdline_regex: Vec<regex::Regex>,
    domains: Option<GlobSet>,
    telemetry: Option<GlobSet>,
}

impl CompiledProfile {
    pub fn matches_process(&self, name: &str, exe: Option<&Path>, cmdline: &[String]) -> bool {
        let name_lower = name.to_ascii_lowercase();

        for candidate in &self.raw.process.names {
            let candidate = candidate.to_ascii_lowercase();
            if name_lower == candidate || name_lower.trim_end_matches(".exe") == candidate {
                return true;
            }
        }

        if let Some(set) = &self.exe
            && let Some(exe) = exe
        {
            let path = exe.to_string_lossy();
            if set.is_match(path.as_ref()) {
                return true;
            }
            if let Some(base) = exe.file_name().and_then(|b| b.to_str())
                && set.is_match(base)
            {
                return true;
            }
        }

        if !self.raw.process.cmdline_contains.is_empty() {
            let joined = cmdline.join(" ").to_ascii_lowercase();
            for needle in &self.raw.process.cmdline_contains {
                if joined.contains(&needle.to_ascii_lowercase()) {
                    return true;
                }
            }
        }

        if !self.cmdline_regex.is_empty() {
            let joined = cmdline.join(" ");
            for re in &self.cmdline_regex {
                if re.is_match(&joined) {
                    return true;
                }
            }
        }

        false
    }

    pub fn domain_allowed(&self, host: &str, include_telemetry: bool) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(set) = &self.domains
            && set.is_match(&host)
        {
            return true;
        }
        if include_telemetry
            && let Some(set) = &self.telemetry
            && set.is_match(&host)
        {
            return true;
        }
        false
    }

    pub fn matches_domain_list(&self, host: &str) -> bool {
        self.domain_allowed(host, true)
    }
}

pub struct ProfileSet {
    profiles: Vec<CompiledProfile>,
    global_domains: Option<GlobSet>,
}

impl ProfileSet {
    pub fn load(config: &Config) -> Result<ProfileSet> {
        let mut raw: Vec<AgentProfile> = Vec::new();
        for text in BUILTIN_PROFILES {
            let profile: AgentProfile =
                serde_norway::from_str(text).context("parsing builtin agent profile")?;
            raw.push(profile);
        }

        let user_dir = crate::paths::user_profiles_dir();
        if user_dir.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&user_dir)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension()
                        .map(|e| e == "yaml" || e == "yml")
                        .unwrap_or(false)
                })
                .collect();
            entries.sort();
            for path in entries {
                let text = std::fs::read_to_string(&path)?;
                let parsed: AgentProfile = serde_norway::from_str(&text)
                    .with_context(|| format!("parsing profile {}", path.display()))?;
                raw.retain(|p| p.id != parsed.id);
                raw.push(parsed);
            }
        }

        let mut profiles = Vec::with_capacity(raw.len());
        for profile in raw {
            profiles.push(compile(profile)?);
        }

        let mut builder = GlobSetBuilder::new();
        let mut any = false;
        for pattern in &config.global_allowed_domains {
            for variant in domain_variants(pattern) {
                if let Ok(glob) = Glob::new(&variant) {
                    builder.add(glob);
                    any = true;
                }
            }
        }
        let global_domains = if any { builder.build().ok() } else { None };

        Ok(ProfileSet {
            profiles,
            global_domains,
        })
    }

    pub fn all(&self) -> impl Iterator<Item = &AgentProfile> {
        self.profiles.iter().map(|p| &p.raw)
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&CompiledProfile> {
        self.profiles.iter().find(|p| p.raw.id == id)
    }

    pub fn match_process(
        &self,
        name: &str,
        exe: Option<&Path>,
        cmdline: &[String],
    ) -> Option<&str> {
        self.profiles
            .iter()
            .find(|p| p.matches_process(name, exe, cmdline))
            .map(|p| p.raw.id.as_str())
    }

    pub fn domain_allowed(&self, agent_id: Option<&str>, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(set) = &self.global_domains
            && set.is_match(&host)
        {
            return true;
        }
        match agent_id.and_then(|id| self.get(id)) {
            Some(profile) => profile.domain_allowed(&host, true),
            None => false,
        }
    }

    /// Telemetry endpoints are allowlisted for connectivity, but sending source
    /// code or credentials there is never legitimate.
    pub fn is_telemetry_domain(&self, agent_id: Option<&str>, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match agent_id.and_then(|id| self.get(id)) {
            Some(profile) => profile
                .telemetry
                .as_ref()
                .map(|set| set.is_match(&host))
                .unwrap_or(false),
            None => false,
        }
    }

    pub fn installed_profiles(&self) -> Vec<&AgentProfile> {
        self.profiles
            .iter()
            .map(|p| &p.raw)
            .filter(|p| p.installed())
            .collect()
    }

    pub fn by_id(&self) -> BTreeMap<&str, &AgentProfile> {
        self.profiles
            .iter()
            .map(|p| (p.raw.id.as_str(), &p.raw))
            .collect()
    }
}

fn compile(profile: AgentProfile) -> Result<CompiledProfile> {
    let mut exe_builder = GlobSetBuilder::new();
    let mut exe_any = false;
    for pattern in &profile.process.exe {
        if let Ok(glob) = Glob::new(pattern) {
            exe_builder.add(glob);
            exe_any = true;
        }
    }
    let exe = if exe_any {
        exe_builder.build().ok()
    } else {
        None
    };

    let mut cmdline_regex = Vec::new();
    for pattern in &profile.process.cmdline_regex {
        let re = regex::Regex::new(pattern)
            .with_context(|| format!("invalid cmdline_regex in profile {}", profile.id))?;
        cmdline_regex.push(re);
    }

    let domains = build_domain_set(&profile.allowed_domains);
    let telemetry = build_domain_set(&profile.telemetry_domains);

    Ok(CompiledProfile {
        raw: profile,
        exe,
        cmdline_regex,
        domains,
        telemetry,
    })
}

fn build_domain_set(patterns: &[String]) -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut any = false;
    for pattern in patterns {
        for variant in domain_variants(pattern) {
            if let Ok(glob) = Glob::new(&variant) {
                builder.add(glob);
                any = true;
            }
        }
    }
    if any { builder.build().ok() } else { None }
}

/// `*.example.com` also matches the bare domain, so profiles can use a single entry.
fn domain_variants(pattern: &str) -> Vec<String> {
    let trimmed = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut out = vec![trimmed.clone()];
    if let Some(rest) = trimmed.strip_prefix("*.") {
        out.push(rest.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> ProfileSet {
        ProfileSet::load(&Config::default()).unwrap()
    }

    #[test]
    fn loads_builtin_profiles() {
        let set = set();
        assert!(
            set.len() >= 15,
            "expected builtin profiles, got {}",
            set.len()
        );
    }

    #[test]
    fn matches_known_processes() {
        let set = set();
        assert_eq!(
            set.match_process("claude", Some(Path::new("/usr/local/bin/claude")), &[]),
            Some("claude-code")
        );
        assert_eq!(
            set.match_process(
                "node",
                None,
                &["node".into(), "/opt/claude-code/cli.js".into()]
            ),
            Some("claude-code")
        );
        assert_eq!(
            set.match_process(
                "zcode",
                Some(Path::new("/Applications/ZCode.app/Contents/MacOS/ZCode")),
                &[]
            ),
            Some("zcode")
        );
        assert_eq!(
            set.match_process("bash", Some(Path::new("/bin/bash")), &[]),
            None
        );
    }

    #[test]
    fn domain_wildcards_match_subdomains_and_bare() {
        let set = set();
        assert!(set.domain_allowed(Some("zcode"), "api.z.ai"));
        assert!(set.domain_allowed(Some("zcode"), "z.ai"));
        assert!(!set.domain_allowed(Some("zcode"), "evil.example.com"));
        assert!(set.domain_allowed(Some("claude-code"), "api.anthropic.com"));
    }

    #[test]
    fn global_allowlist_applies_to_every_agent() {
        let set = set();
        assert!(set.domain_allowed(Some("opencode"), "registry.npmjs.org"));
    }
}
