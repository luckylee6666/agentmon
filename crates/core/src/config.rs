use crate::model::Severity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub retention_days: u32,
    pub poll_interval_ms: u64,
    pub connection_poll_ms: u64,
    pub artifact_scan_interval_ms: u64,
    pub thresholds: Thresholds,
    pub global_allowed_domains: Vec<String>,
    pub sensitive_globs: Vec<String>,
    pub watch_roots: Vec<String>,
    pub alert: AlertConfig,
    pub capture: CaptureConfig,
    pub proxy: ProxySection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub volume_spike_bytes: u64,
    pub volume_spike_window_ms: i64,
    pub bulk_read_files: usize,
    pub bulk_read_window_ms: i64,
    pub exfil_correlation_ms: i64,
    pub hidden_blob_bytes: u64,
    pub hidden_blob_entropy: f32,
    pub artifact_min_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    pub desktop: bool,
    pub min_severity: Severity,
    pub webhook_url: Option<String>,
    pub dedupe_window_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub capture_bodies: bool,
    pub max_body_bytes: usize,
    pub max_samples: usize,
}

/// Local MITM proxy used to classify what agents actually send.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxySection {
    /// The proxy only ever sees traffic that is explicitly routed to it
    /// (`agentmon wrap`, or proxy env vars pointing at the listen address).
    pub enabled: bool,
    pub listen: String,
    /// Bytes of each request body inspected for classification.
    pub capture_bytes: usize,
}

impl Default for ProxySection {
    fn default() -> Self {
        ProxySection {
            enabled: true,
            listen: "127.0.0.1:8899".into(),
            capture_bytes: 1024 * 1024,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            retention_days: 7,
            poll_interval_ms: 3_000,
            connection_poll_ms: 8_000,
            artifact_scan_interval_ms: 600_000,
            thresholds: Thresholds::default(),
            global_allowed_domains: vec![
                "*.apple.com".into(),
                "*.icloud.com".into(),
                "*.github.com".into(),
                "*.githubusercontent.com".into(),
                "*.npmjs.org".into(),
                "*.npmjs.com".into(),
                "*.crates.io".into(),
                "*.pypi.org".into(),
                "*.rust-lang.org".into(),
                "*.microsoft.com".into(),
                "*.windowsupdate.com".into(),
                "*.googleapis.com".into(),
                "*.gstatic.com".into(),
                "*.sentry.io".into(),
                "*.statsig.com".into(),
                "*.cloudflare.com".into(),
                "*.amazonaws.com".into(),
            ],
            sensitive_globs: Vec::new(),
            watch_roots: Vec::new(),
            alert: AlertConfig::default(),
            capture: CaptureConfig::default(),
            proxy: ProxySection::default(),
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            volume_spike_bytes: 20 * 1024 * 1024,
            volume_spike_window_ms: 5 * 60 * 1000,
            bulk_read_files: 200,
            bulk_read_window_ms: 60 * 1000,
            exfil_correlation_ms: 120 * 1000,
            hidden_blob_bytes: 50 * 1024 * 1024,
            hidden_blob_entropy: 7.5,
            artifact_min_bytes: 1024 * 1024,
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        AlertConfig {
            desktop: true,
            min_severity: Severity::High,
            webhook_url: None,
            dedupe_window_ms: 600_000,
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            capture_bodies: false,
            max_body_bytes: 64 * 1024,
            max_samples: 2048,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            let cfg = Config::default();
            cfg.save(path)?;
            return Ok(cfg);
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = serde_norway::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        Ok(cfg)
    }

    pub fn load_or_default() -> Config {
        let path = crate::paths::config_file();
        Config::load(&path).unwrap_or_default()
    }

    /// Loads the user config, creating it with defaults on first run.
    pub fn load_or_default_path() -> Config {
        let path = crate::paths::config_file();
        if path.exists() {
            return Config::load(&path).unwrap_or_default();
        }
        let config = Config::default();
        let _ = config.save(&path);
        config
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::paths::ensure_parent_dir(path)?;
        let text = serde_norway::to_string(self)?;
        std::fs::write(path, text).with_context(|| format!("writing config {}", path.display()))?;
        Ok(())
    }

    pub fn save_default(&self) -> Result<PathBuf> {
        let path = crate::paths::config_file();
        self.save(&path)?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrips_yaml() {
        let cfg = Config::default();
        let text = serde_norway::to_string(&cfg).unwrap();
        let parsed: Config = serde_norway::from_str(&text).unwrap();
        assert_eq!(parsed.retention_days, cfg.retention_days);
        assert_eq!(
            parsed.thresholds.volume_spike_bytes,
            cfg.thresholds.volume_spike_bytes
        );
    }
}
