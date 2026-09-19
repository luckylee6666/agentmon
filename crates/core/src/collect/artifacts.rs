use crate::config::Config;
use crate::model::{Artifact, ArtifactKind, Event};
use crate::profiles::ProfileSet;
use crate::util;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MAX_DEPTH: usize = 8;
const MAX_ENTRIES: usize = 60_000;
const ENTROPY_SAMPLE_BYTES: usize = 1024 * 1024;
const ENDPOINT_SCAN_MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENDPOINT_FINDINGS_PER_AGENT: usize = 15;
const TEXT_EXTENSIONS: &[&str] = &[
    "json", "yaml", "yml", "toml", "js", "mjs", "cjs", "ts", "log", "cfg", "conf", "ini", "txt",
    "env",
];

/// Directories that are plugin/skill/doc bundles rather than agent configuration.
/// Scanning them produced mostly license and documentation URLs, so they are
/// walked for size accounting but skipped for endpoint extraction.
const SKIP_SCAN_DIRS: &[&str] = &[
    "plugins",
    "marketplaces",
    "marketplace",
    "extensions",
    "node_modules",
    ".git",
    "templates",
    ".github",
    "skills",
    "skill",
    "cache",
    "caches",
    "tmp",
    "temp",
    "logs",
    "sessions",
    "history",
    "projects",
    "tool-results",
    "conversations",
    "threads",
    "chats",
    "vendor",
    "dist",
    "site-packages",
];

#[derive(Debug, Clone)]
pub struct DirUsage {
    pub agent_id: String,
    pub path: PathBuf,
    pub size: u64,
    pub files: u64,
}

#[derive(Debug, Clone)]
pub struct EndpointFinding {
    pub agent_id: String,
    pub path: PathBuf,
    pub host: String,
    pub url: String,
    pub context: String,
}

#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub artifacts: Vec<Artifact>,
    pub dir_usage: Vec<DirUsage>,
    pub endpoints: Vec<EndpointFinding>,
    pub errors: Vec<String>,
    pub duration_ms: u128,
}

pub fn scan(profiles: &ProfileSet, config: &Config, deep: bool) -> ScanOutcome {
    scan_with_cache(profiles, config, deep, &mut HashMap::new())
}

/// `entropy_cache` maps path -> (mtime, size) of already-inspected files so a
/// periodic rescan does not re-read gigabytes of unchanged data.
pub fn scan_with_cache(
    profiles: &ProfileSet,
    config: &Config,
    deep: bool,
    entropy_cache: &mut HashMap<PathBuf, (u64, u64)>,
) -> ScanOutcome {
    let started = std::time::Instant::now();
    let mut outcome = ScanOutcome::default();
    for profile in profiles.installed_profiles() {
        let allowed_hosts = collect_allowed_hosts(profiles, config, &profile.id);
        let mut seen_hosts: HashSet<String> = HashSet::new();
        let mut endpoint_count = 0usize;

        for dir in profile.data_dir_paths() {
            if !dir.exists() {
                continue;
            }
            let usage = walk_dir(
                &profile.id,
                &dir,
                config,
                deep,
                &allowed_hosts,
                &mut seen_hosts,
                &mut endpoint_count,
                entropy_cache,
                &mut outcome,
            );
            outcome.dir_usage.push(usage);
        }

        if deep {
            for file in profile.config_file_paths() {
                if file.is_file() {
                    scan_text_file(
                        &profile.id,
                        &file,
                        &allowed_hosts,
                        &mut seen_hosts,
                        &mut endpoint_count,
                        &mut outcome,
                    );
                }
            }
        }
    }
    outcome.duration_ms = started.elapsed().as_millis();
    outcome
}

pub fn events_from(outcome: &ScanOutcome) -> Vec<Event> {
    outcome
        .artifacts
        .iter()
        .cloned()
        .map(Event::Artifact)
        .collect()
}

pub fn endpoint_artifacts(outcome: &ScanOutcome) -> Vec<Artifact> {
    outcome
        .endpoints
        .iter()
        .map(|endpoint| Artifact {
            ts: util::now_ms(),
            agent_id: endpoint.agent_id.clone(),
            path: endpoint.path.clone(),
            size: 0,
            entropy: 0.0,
            kind: ArtifactKind::UnexpectedEndpoint,
            detail: format!(
                "配置项 {} 指向白名单外地址 {}（{}）",
                endpoint.context,
                endpoint.host,
                endpoint.path.display()
            ),
        })
        .collect()
}

pub struct ArtifactScanner {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ArtifactScanner {
    pub fn start(ctx: super::CollectorCtx) -> ArtifactScanner {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let handle = std::thread::Builder::new()
            .name("agentmon-artifacts".into())
            .spawn(move || {
                let interval =
                    Duration::from_millis(ctx.config.artifact_scan_interval_ms.max(30_000));
                let mut cache: HashMap<PathBuf, (u64, u64)> = HashMap::new();
                loop {
                    let outcome = scan_with_cache(&ctx.profiles, &ctx.config, true, &mut cache);
                    tracing::debug!(
                        artifacts = outcome.artifacts.len(),
                        endpoints = outcome.endpoints.len(),
                        duration_ms = outcome.duration_ms as u64,
                        "artifact scan finished"
                    );
                    for artifact in outcome.artifacts.iter().cloned() {
                        ctx.emit(Event::Artifact(artifact));
                    }
                    for artifact in endpoint_artifacts(&outcome) {
                        ctx.emit(Event::Artifact(artifact));
                    }
                    if wait_or_stop(interval, &thread_stop) {
                        return;
                    }
                }
            })
            .expect("spawning artifact scanner");
        ArtifactScanner {
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

fn wait_or_stop(interval: Duration, stop: &AtomicBool) -> bool {
    let step = Duration::from_millis(500);
    let mut waited = Duration::ZERO;
    while waited < interval {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(step.min(interval - waited));
        waited += step;
    }
    false
}

fn collect_allowed_hosts(profiles: &ProfileSet, config: &Config, agent_id: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    if let Some(profile) = profiles.get(agent_id) {
        hosts.extend(profile.raw.allowed_domains.iter().cloned());
        hosts.extend(profile.raw.telemetry_domains.iter().cloned());
    }
    hosts.extend(config.global_allowed_domains.iter().cloned());
    hosts
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    agent_id: &str,
    root: &Path,
    config: &Config,
    deep: bool,
    allowed_hosts: &[String],
    seen_hosts: &mut HashSet<String>,
    endpoint_count: &mut usize,
    entropy_cache: &mut HashMap<PathBuf, (u64, u64)>,
    outcome: &mut ScanOutcome,
) -> DirUsage {
    let mut usage = DirUsage {
        agent_id: agent_id.to_string(),
        path: root.to_path_buf(),
        size: 0,
        files: 0,
    };
    let mut stack: Vec<(PathBuf, usize, bool)> = vec![(root.to_path_buf(), 0, true)];
    let mut entries_seen = 0usize;

    while let Some((dir, depth, scannable)) = stack.pop() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(err) => {
                outcome.errors.push(format!("{}: {err}", dir.display()));
                continue;
            }
        };
        for entry in read_dir.flatten() {
            entries_seen += 1;
            if entries_seen > MAX_ENTRIES {
                outcome
                    .errors
                    .push(format!("{}: entry limit reached", root.display()));
                return usage;
            }
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                if depth < MAX_DEPTH {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    let child_scannable = scannable && !SKIP_SCAN_DIRS.contains(&name);
                    stack.push((path, depth + 1, child_scannable));
                }
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let size = metadata.len();
            usage.size += size;
            usage.files += 1;

            if size >= config.thresholds.hidden_blob_bytes && !is_known_compressed(&path) {
                let stamp = stamp_of(&metadata);
                let changed = entropy_cache
                    .get(&path)
                    .map(|cached| *cached != stamp)
                    .unwrap_or(true);
                if changed {
                    entropy_cache.insert(path.clone(), stamp);
                    let entropy = file_entropy(&path);
                    if entropy >= config.thresholds.hidden_blob_entropy {
                        outcome.artifacts.push(Artifact {
                            ts: util::now_ms(),
                            agent_id: agent_id.to_string(),
                            path: path.clone(),
                            size,
                            entropy,
                            kind: ArtifactKind::HiddenBlob,
                            detail: format!(
                                "{} 高熵文件（entropy {:.2}），疑似本地打包/加密的数据块",
                                util::format_bytes(size),
                                entropy
                            ),
                        });
                    }
                }
            }

            if deep
                && scannable
                && size > 0
                && size <= ENDPOINT_SCAN_MAX_BYTES
                && *endpoint_count < MAX_ENDPOINT_FINDINGS_PER_AGENT
                && is_text_candidate(&path)
            {
                scan_text_file(
                    agent_id,
                    &path,
                    allowed_hosts,
                    seen_hosts,
                    endpoint_count,
                    outcome,
                );
            }
        }
    }

    usage
}

fn stamp_of(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::time::UNIX_EPOCH;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (mtime, metadata.len())
}

fn is_text_candidate(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => TEXT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

fn scan_text_file(
    agent_id: &str,
    path: &Path,
    allowed_hosts: &[String],
    seen_hosts: &mut HashSet<String>,
    endpoint_count: &mut usize,
    outcome: &mut ScanOutcome,
) {
    if *endpoint_count >= MAX_ENDPOINT_FINDINGS_PER_AGENT {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for candidate in extract_endpoints(&text) {
        if *endpoint_count >= MAX_ENDPOINT_FINDINGS_PER_AGENT {
            break;
        }
        let host = candidate.host.to_ascii_lowercase();
        if host_matches_any(allowed_hosts, &host) || is_benign_host(&host) {
            continue;
        }
        if !seen_hosts.insert(host.clone()) {
            continue;
        }
        *endpoint_count += 1;
        outcome.endpoints.push(EndpointFinding {
            agent_id: agent_id.to_string(),
            path: path.to_path_buf(),
            host,
            url: candidate.url,
            context: candidate.key,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCandidate {
    pub key: String,
    pub host: String,
    pub url: String,
}

/// Only URLs bound to an endpoint-shaped configuration key are reported.
/// Plain URLs in documentation, license headers or templates are not evidence
/// of telemetry, and reporting them drowned the real signal.
pub fn extract_endpoints(text: &str) -> Vec<EndpointCandidate> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)["']?([a-z0-9_]*(?:base_?url|api_?url|endpoint|upload|ingest|telemetry|report_?url|api_?host|server_?url|collector|beacon)[a-z0-9_]*|url)["']?\s*[:=]\s*["'](https?://([A-Za-z0-9][A-Za-z0-9._-]{2,253}))"#,
        )
        .expect("endpoint regex")
    });
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for capture in re.captures_iter(text) {
        let Some(key) = capture.get(1) else { continue };
        let Some(host_capture) = capture.get(3) else {
            continue;
        };
        let host = host_capture
            .as_str()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let key = key.as_str().to_ascii_lowercase();
        if key == "url"
            && !host.contains("api")
            && !host.contains("upload")
            && !host.contains("ingest")
        {
            continue;
        }
        let url = capture
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if !seen.insert(host.clone()) {
            continue;
        }
        out.push(EndpointCandidate { key, host, url });
        if out.len() > 100 {
            break;
        }
    }
    out
}

fn host_matches_any(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|pattern| host_matches(pattern, host))
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

fn is_benign_host(host: &str) -> bool {
    const BENIGN_SUFFIXES: &[&str] = &[
        "w3.org",
        "schema.org",
        "localhost",
        "example.com",
        "gnu.org",
        "opensource.org",
        "openfontlicense.org",
        "creativecommons.org",
        "apache.org",
        "mozilla.org",
        "python.org",
        "rust-lang.org",
        "go.dev",
        "golang.org",
        "nodejs.org",
        "npmjs.com",
        "npmjs.org",
        "github.com",
        "githubusercontent.com",
        "adoptium.net",
        "unicode.org",
        "json-schema.org",
        "mitre.org",
        "nist.gov",
        "cve.org",
        "ietf.org",
        "rfc-editor.org",
        "tailwindcss.com",
        "google.com",
        "chromium.org",
        "stackoverflow.com",
        "wikipedia.org",
        "fontawesome.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "json.org",
        "yaml.org",
        "toml.io",
        "sqlite.org",
        "docker.com",
        "kubernetes.io",
        "cncf.io",
        "vercel.com",
        "netlify.com",
        "cloudflare.com",
    ];
    host == "localhost"
        || host.starts_with("127.")
        || host.starts_with("www.")
        || BENIGN_SUFFIXES
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

/// Formats that are legitimately high entropy: compressed media, archives and
/// container binaries. Without this the rule fires on videos and git packfiles.
const SKIP_ENTROPY_EXTENSIONS: &[&str] = &[
    "mp4", "mov", "m4v", "avi", "mkv", "webm", "mp3", "m4a", "wav", "flac", "aac", "ogg", "opus",
    "png", "jpg", "jpeg", "gif", "webp", "heic", "avif", "ico", "bmp", "tiff", "psd", "svgz",
    "zip", "gz", "tgz", "xz", "bz2", "7z", "rar", "zst", "lz4", "br", "jar", "war", "apk", "ipa",
    "pdf", "epub", "mobi", "docx", "xlsx", "pptx", "db", "sqlite", "sqlite3", "db-wal", "db-shm",
    "ldb", "sst", "pack", "idx", "bitmap", "dylib", "so", "dll", "a", "o", "obj", "lib", "exe",
    "wasm", "node", "rlib", "rmeta", "woff", "woff2", "ttf", "otf", "eot", "icns", "class",
];

fn is_known_compressed(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| SKIP_ENTROPY_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
    {
        return true;
    }
    let text = path.to_string_lossy();
    text.contains("/objects/pack/") || text.contains("/.git/") || text.contains("/node_modules/")
}

fn file_entropy(path: &Path) -> f32 {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return 0.0;
    };
    let mut buffer = vec![0u8; ENTROPY_SAMPLE_BYTES];
    let read = file.read(&mut buffer).unwrap_or(0);
    buffer.truncate(read);
    util::shannon_entropy(&buffer)
}

pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![(path.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return total;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((entry.path(), depth + 1));
                }
            } else if metadata.is_file() {
                total += metadata.len();
            }
        }
    }
    total
}

pub fn agent_dir_usage(profiles: &ProfileSet) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for profile in profiles.installed_profiles() {
        let total: u64 = profile.data_dir_paths().iter().map(|p| dir_size(p)).sum();
        if total > 0 {
            map.insert(profile.id.clone(), total);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_endpoint_shaped_config_entries() {
        let text = r#"
        {"baseURL": "https://api.anthropic.com/v1", "telemetryEndpoint": "https://collect.unknown-vendor.example/ingest"}
        "#;
        let found = extract_endpoints(text);
        assert!(found.iter().any(|c| c.host == "api.anthropic.com"));
        assert!(
            found
                .iter()
                .any(|c| c.host == "collect.unknown-vendor.example")
        );
    }

    #[test]
    fn ignores_documentation_urls() {
        let text = r#"
        # See https://www.gnu.org/licenses/lgpl.html and https://opensource.org/licenses/MIT
        <link href="https://fonts.googleapis.com/css?family=Outfit">
        "homepage": "https://github.com/someone/project",
        "#;
        assert!(extract_endpoints(text).is_empty());
    }

    #[test]
    fn wildcard_host_matching() {
        assert!(host_matches("*.z.ai", "api.z.ai"));
        assert!(host_matches("*.z.ai", "z.ai"));
        assert!(!host_matches("*.z.ai", "notz.ai"));
    }

    #[test]
    fn benign_hosts_are_filtered() {
        assert!(is_benign_host("www.w3.org"));
        assert!(is_benign_host("localhost"));
        assert!(is_benign_host("cdn.tailwindcss.com"));
        assert!(!is_benign_host("collect.evil.example"));
    }
}
