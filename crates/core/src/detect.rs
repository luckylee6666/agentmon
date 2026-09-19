use crate::config::Config;
use crate::dns::DnsState;
use crate::model::*;
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use crate::sensitive::{SensitiveMatcher, Sensitivity};
use crate::util;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

pub const RULE_UNKNOWN_DOMAIN: &str = "egress.unknown_domain";
pub const RULE_VOLUME_SPIKE: &str = "egress.volume_spike";
pub const RULE_SENSITIVE_PAYLOAD: &str = "egress.sensitive_payload";
pub const RULE_SENSITIVE_READ: &str = "fs.sensitive_read";
pub const RULE_BULK_READ: &str = "fs.bulk_read";
pub const RULE_HIDDEN_BLOB: &str = "artifact.hidden_blob";
pub const RULE_UNEXPECTED_ENDPOINT: &str = "artifact.unexpected_endpoint";
pub const RULE_EXFIL_CHAIN: &str = "exfil.chain";

const SIGNIFICANT_UPLOAD_BYTES: u64 = 1024 * 1024;
const DEDUPE_WINDOW_MS: i64 = 60 * 60 * 1000;

#[derive(Clone, Copy)]
pub struct DetectCtx<'a> {
    pub registry: &'a Registry,
}

pub struct Detector {
    config: Arc<Config>,
    profiles: Arc<ProfileSet>,
    sensitive: SensitiveMatcher,
    dns: Arc<DnsState>,
    volume: HashMap<String, VecDeque<(i64, u64)>>,
    reads: HashMap<String, VecDeque<(i64, PathBuf)>>,
    read_signal: HashMap<String, (i64, Vec<Evidence>)>,
    dedupe: HashMap<String, i64>,
    last_gc: i64,
    warned_fake_ip: bool,
}

impl Detector {
    pub fn new(config: Arc<Config>, profiles: Arc<ProfileSet>, dns: Arc<DnsState>) -> Detector {
        let sensitive = SensitiveMatcher::new(&config.sensitive_globs);
        Detector {
            config,
            profiles,
            sensitive,
            dns,
            volume: HashMap::new(),
            reads: HashMap::new(),
            read_signal: HashMap::new(),
            dedupe: HashMap::new(),
            last_gc: util::now_ms(),
            warned_fake_ip: false,
        }
    }

    pub fn evaluate(&mut self, event: &Event, ctx: DetectCtx<'_>) -> Vec<Finding> {
        self.gc();
        match event {
            Event::Connection(conn) => self.on_connection(conn),
            Event::Volume(volume) => self.on_volume(volume),
            Event::File(file) => self.on_file(file, ctx),
            Event::Http(http) => self.on_http(http),
            Event::Artifact(artifact) => self.on_artifact(artifact),
            Event::Process(_) => Vec::new(),
        }
    }

    fn on_connection(&mut self, conn: &ConnectionSample) -> Vec<Finding> {
        let Some(agent_id) = conn.agent_id.clone() else {
            return Vec::new();
        };
        let Some(ip) = conn.remote_ip.clone() else {
            return Vec::new();
        };
        if util::is_private_ip(&ip) {
            return Vec::new();
        }
        if util::is_reserved_ip(&ip) {
            if !self.warned_fake_ip {
                self.warned_fake_ip = true;
                tracing::warn!(
                    "destination {ip} is in a reserved range used by fake-ip proxies; \
                     hostname-level attribution needs `agentmon wrap` (transparent proxy)"
                );
            }
            return Vec::new();
        }
        if self.dns.is_allowed_ip(&ip) {
            return Vec::new();
        }
        if let Some(host) = &conn.remote_host
            && self.profiles.domain_allowed(Some(&agent_id), host)
        {
            return Vec::new();
        }
        let key = format!("{agent_id}|{ip}");
        if !self.should_emit(&format!("{RULE_UNKNOWN_DOMAIN}|{key}"), DEDUPE_WINDOW_MS) {
            return Vec::new();
        }

        let label = conn
            .remote_host
            .clone()
            .unwrap_or_else(|| conn.remote_addr.clone());
        let finding = Finding::new(
            RULE_UNKNOWN_DOMAIN,
            Severity::Low,
            format!("{agent_id} 连接到白名单外的地址 {label}"),
            format!(
                "目标 {} 不在 {} 的允许域名或全局白名单内，也不匹配已解析的厂商 IP。可能是正常的多提供商调用，也可能是隐蔽遥测。",
                conn.remote_addr,
                self.profiles
                    .get(&agent_id)
                    .map(|p| p.raw.name.clone())
                    .unwrap_or_else(|| agent_id.clone())
            ),
        )
        .with_agent(Some(agent_id.clone()))
        .with_pid(Some(conn.pid))
        .with_dedupe(key)
        .with_evidence(vec![Evidence::at(
            conn.ts,
            "connection",
            format!("连接到 {}", conn.remote_addr),
        )]);

        vec![finding]
    }

    fn on_volume(&mut self, volume: &VolumeSample) -> Vec<Finding> {
        let Some(agent_id) = volume.agent_id.clone() else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        let window = self.volume.entry(agent_id.clone()).or_default();
        window.push_back((volume.ts, volume.bytes_out));
        let cutoff = volume.ts - self.config.thresholds.volume_spike_window_ms;
        while window.front().map(|(ts, _)| *ts < cutoff).unwrap_or(false) {
            window.pop_front();
        }
        let total: u64 = window.iter().map(|(_, bytes)| *bytes).sum();

        if total >= self.config.thresholds.volume_spike_bytes
            && self.should_emit(
                &format!("{RULE_VOLUME_SPIKE}|{agent_id}"),
                self.config.alert.dedupe_window_ms,
            )
        {
            findings.push(
                Finding::new(
                    RULE_VOLUME_SPIKE,
                    Severity::Medium,
                    format!("{agent_id} 上传量突增"),
                    format!(
                        "{} 分钟窗口内该 agent 出站 {}，超过阈值 {}",
                        self.config.thresholds.volume_spike_window_ms / 60_000,
                        util::format_bytes(total),
                        util::format_bytes(self.config.thresholds.volume_spike_bytes)
                    ),
                )
                .with_agent(Some(agent_id.clone()))
                .with_pid(Some(volume.pid))
                .with_dedupe(agent_id.clone())
                .with_evidence(vec![Evidence::at(
                    volume.ts,
                    "upload",
                    format!("本窗口出站 {}", util::format_bytes(total)),
                )]),
            );
        }

        if volume.bytes_out >= SIGNIFICANT_UPLOAD_BYTES
            && let Some(finding) = self.correlate_upload(
                &agent_id,
                volume.ts,
                volume.bytes_out,
                Some(volume.pid),
                "upload",
            )
        {
            findings.push(finding);
        }

        findings
    }

    /// The core rule: a sensitive/bulk read followed closely by a significant
    /// upload is the signature of "pack the repository, then send it".
    fn correlate_upload(
        &mut self,
        agent_id: &str,
        ts: i64,
        bytes_out: u64,
        pid: Option<u32>,
        kind: &str,
    ) -> Option<Finding> {
        let (signal_ts, evidence) = self.read_signal.get(agent_id).cloned()?;
        let elapsed = ts - signal_ts;
        if elapsed < 0 || elapsed > self.config.thresholds.exfil_correlation_ms {
            return None;
        }
        if !self.should_emit(
            &format!("{RULE_EXFIL_CHAIN}|{agent_id}"),
            self.config.alert.dedupe_window_ms,
        ) {
            return None;
        }
        let mut chain = evidence;
        chain.push(Evidence::at(
            ts,
            kind,
            format!(
                "读取后 {} 秒内出站 {}",
                elapsed / 1000,
                util::format_bytes(bytes_out)
            ),
        ));
        Some(
            Finding::new(
                RULE_EXFIL_CHAIN,
                Severity::Critical,
                format!("{agent_id} 疑似外传：先批量读取，随后立即上传"),
                format!(
                    "{} 秒内先出现敏感/批量读取，紧接着出站 {}。这与「本地打包后上传」的行为特征一致。",
                    elapsed / 1000,
                    util::format_bytes(bytes_out)
                ),
            )
            .with_agent(Some(agent_id.to_string()))
            .with_pid(pid)
            .with_dedupe(agent_id.to_string())
            .with_evidence(chain),
        )
    }

    fn on_file(&mut self, file: &FileEvent, ctx: DetectCtx<'_>) -> Vec<Finding> {
        let Some(agent_id) = file.agent_id.clone() else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        match self.sensitive.classify(&file.path) {
            Some(Sensitivity::Secret) => {
                if self.should_emit(
                    &format!("{RULE_SENSITIVE_READ}|{agent_id}|{}", file.path.display()),
                    DEDUPE_WINDOW_MS,
                ) {
                    findings.push(
                        Finding::new(
                            RULE_SENSITIVE_READ,
                            Severity::Medium,
                            format!("{agent_id} 读取敏感文件"),
                            format!("{} 读取了 {}", agent_id, file.path.display()),
                        )
                        .with_agent(Some(agent_id.clone()))
                        .with_pid(Some(file.pid))
                        .with_dedupe(file.path.to_string_lossy().to_string())
                        .with_evidence(vec![Evidence::at(
                            file.ts,
                            "file-read",
                            format!("读取 {}", file.path.display()),
                        )]),
                    );
                }
                self.record_read_signal(
                    &agent_id,
                    file.ts,
                    vec![Evidence::at(
                        file.ts,
                        "file-read",
                        format!("读取敏感文件 {}", file.path.display()),
                    )],
                );
            }
            Some(Sensitivity::GitMetadata) => {
                self.record_git_read(&agent_id, file);
            }
            None => {}
        }

        let repo_root = ctx
            .registry
            .cwd(file.pid)
            .and_then(util::git_repo_root)
            .map(|root| root.to_string_lossy().to_string());
        let key = format!(
            "{agent_id}|{}",
            repo_root.clone().unwrap_or_else(|| "-".into())
        );
        let window = self.reads.entry(key).or_default();
        window.push_back((file.ts, file.path.clone()));
        let cutoff = file.ts - self.config.thresholds.bulk_read_window_ms;
        while window.front().map(|(ts, _)| *ts < cutoff).unwrap_or(false) {
            window.pop_front();
        }
        let distinct: std::collections::HashSet<&PathBuf> = window.iter().map(|(_, p)| p).collect();
        let distinct_count = distinct.len();

        if distinct_count >= self.config.thresholds.bulk_read_files {
            let samples: Vec<String> = distinct
                .iter()
                .take(5)
                .map(|p| p.display().to_string())
                .collect();
            let evidence = vec![
                Evidence::at(
                    file.ts,
                    "bulk-read",
                    format!(
                        "{} 秒内读取 {} 个不同文件（仓库 {}）",
                        self.config.thresholds.bulk_read_window_ms / 1000,
                        distinct_count,
                        repo_root.clone().unwrap_or_else(|| "未知".into())
                    ),
                )
                .with_detail(samples.join("\n")),
            ];
            self.record_read_signal(&agent_id, file.ts, evidence.clone());
            if self.should_emit(
                &format!("{RULE_BULK_READ}|{agent_id}|{distinct_count}"),
                self.config.alert.dedupe_window_ms,
            ) {
                findings.push(
                    Finding::new(
                        RULE_BULK_READ,
                        Severity::Medium,
                        format!("{agent_id} 批量读取仓库文件"),
                        format!(
                            "{} 秒内读取 {} 个不同文件，可能存在本地打包行为",
                            self.config.thresholds.bulk_read_window_ms / 1000,
                            distinct_count
                        ),
                    )
                    .with_agent(Some(agent_id.clone()))
                    .with_pid(Some(file.pid))
                    .with_dedupe(format!("{distinct_count}"))
                    .with_evidence(evidence),
                );
            }
        }

        findings
    }

    fn record_git_read(&mut self, agent_id: &str, file: &FileEvent) {
        let count = {
            let key = format!("{agent_id}|git");
            let window = self.reads.entry(key).or_default();
            window.push_back((file.ts, file.path.clone()));
            let cutoff = file.ts - self.config.thresholds.bulk_read_window_ms;
            while window.front().map(|(ts, _)| *ts < cutoff).unwrap_or(false) {
                window.pop_front();
            }
            window.len()
        };
        if count >= 20 {
            self.record_read_signal(
                agent_id,
                file.ts,
                vec![Evidence::at(
                    file.ts,
                    "git-read",
                    format!(
                        "{} 秒内读取 {} 个 .git 文件",
                        self.config.thresholds.bulk_read_window_ms / 1000,
                        count
                    ),
                )],
            );
        }
    }

    fn record_read_signal(&mut self, agent_id: &str, ts: i64, evidence: Vec<Evidence>) {
        match self.read_signal.get_mut(agent_id) {
            Some(entry) => {
                if ts - entry.0 <= self.config.thresholds.exfil_correlation_ms {
                    entry.1.extend(evidence);
                    entry.1.truncate(8);
                    entry.0 = ts;
                } else {
                    *entry = (ts, evidence);
                }
            }
            None => {
                self.read_signal
                    .insert(agent_id.to_string(), (ts, evidence));
            }
        }
    }

    fn on_http(&mut self, http: &HttpCapture) -> Vec<Finding> {
        let agent_id = http
            .agent_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let mut findings = Vec::new();
        let sensitive = http.class == "secret" || http.class == "source_code";

        // Correlation works from the capture too, so the chain rule still fires
        // on platforms without reliable per-process byte counters.
        if (sensitive || http.bytes_out >= SIGNIFICANT_UPLOAD_BYTES)
            && let Some(finding) =
                self.correlate_upload(&agent_id, http.ts, http.bytes_out, http.pid, "http-upload")
        {
            findings.push(finding);
        }

        if !sensitive {
            return findings;
        }
        // Source code legitimately goes to the model API; sending it to a
        // telemetry endpoint never is.
        let telemetry = self
            .profiles
            .is_telemetry_domain(Some(&agent_id), &http.host);
        if !telemetry && self.profiles.domain_allowed(Some(&agent_id), &http.host) {
            return findings;
        }
        if !self.should_emit(
            &format!("{RULE_SENSITIVE_PAYLOAD}|{agent_id}|{}", http.host),
            DEDUPE_WINDOW_MS,
        ) {
            return findings;
        }
        let severity = if telemetry {
            Severity::Critical
        } else {
            Severity::High
        };
        let what = if http.class == "secret" {
            "密钥/凭证"
        } else {
            "源码"
        };
        let mut finding = Finding::new(
            RULE_SENSITIVE_PAYLOAD,
            severity,
            if telemetry {
                format!("{agent_id} 把{what}发到了遥测端点 {}", http.host)
            } else {
                format!("{agent_id} 向 {} 发送了疑似{what}内容", http.host)
            },
            format!(
                "{} {} → {}，请求体被判定为 {}（{}）{}",
                http.method,
                http.host,
                http.path,
                http.class,
                if http.bytes_out > 0 {
                    util::format_bytes(http.bytes_out)
                } else {
                    "大小未知".into()
                },
                if telemetry {
                    "。该域名属于遥测/统计端点，正常只应上报匿名事件。"
                } else {
                    "。该域名不在允许列表中。"
                }
            ),
        )
        .with_agent(Some(agent_id))
        .with_pid(http.pid)
        .with_dedupe(http.host.clone())
        .with_evidence(vec![
            Evidence::at(
                http.ts,
                "http",
                format!("{} {}{}", http.method, http.host, http.path),
            )
            .with_detail(http.sample.clone().unwrap_or_default()),
        ]);
        finding.severity = severity;
        findings.push(finding);
        findings
    }

    fn on_artifact(&mut self, artifact: &Artifact) -> Vec<Finding> {
        let (rule, severity, title) = match artifact.kind {
            ArtifactKind::HiddenBlob => (
                RULE_HIDDEN_BLOB,
                Severity::Medium,
                format!("{} 数据目录出现高熵大文件", artifact.agent_id),
            ),
            ArtifactKind::UnexpectedEndpoint => (
                RULE_UNEXPECTED_ENDPOINT,
                Severity::Low,
                format!("{} 配置中出现白名单外端点", artifact.agent_id),
            ),
            ArtifactKind::LargeFile => (
                RULE_HIDDEN_BLOB,
                Severity::Info,
                format!("{} 数据目录出现大文件", artifact.agent_id),
            ),
            ArtifactKind::DataDirGrowth => (
                RULE_HIDDEN_BLOB,
                Severity::Low,
                format!("{} 数据目录体积异常增长", artifact.agent_id),
            ),
        };
        if !self.should_emit(
            &format!("{rule}|{}|{}", artifact.agent_id, artifact.path.display()),
            DEDUPE_WINDOW_MS,
        ) {
            return Vec::new();
        }
        let summary = if artifact.size > 0 {
            format!(
                "{} ({})",
                artifact.path.display(),
                util::format_bytes(artifact.size)
            )
        } else {
            artifact.path.display().to_string()
        };
        vec![
            Finding::new(rule, severity, title, artifact.detail.clone())
                .with_agent(Some(artifact.agent_id.clone()))
                .with_dedupe(artifact.path.to_string_lossy().to_string())
                .with_evidence(vec![
                    Evidence::at(artifact.ts, "artifact", summary)
                        .with_detail(format!("entropy {:.2}", artifact.entropy)),
                ]),
        ]
    }

    fn should_emit(&mut self, key: &str, window_ms: i64) -> bool {
        let now = util::now_ms();
        if let Some(last) = self.dedupe.get(key)
            && now - *last < window_ms
        {
            return false;
        }
        self.dedupe.insert(key.to_string(), now);
        true
    }

    fn gc(&mut self) {
        let now = util::now_ms();
        if now - self.last_gc < 60_000 {
            return;
        }
        self.last_gc = now;
        let ttl = 4 * DEDUPE_WINDOW_MS;
        self.dedupe.retain(|_, ts| now - *ts < ttl);
        self.read_signal
            .retain(|_, (ts, _)| now - *ts < self.config.thresholds.exfil_correlation_ms * 4);
        for window in self.reads.values_mut() {
            let cutoff = now - self.config.thresholds.bulk_read_window_ms * 4;
            while window.front().map(|(ts, _)| *ts < cutoff).unwrap_or(false) {
                window.pop_front();
            }
        }
        for window in self.volume.values_mut() {
            let cutoff = now - self.config.thresholds.volume_spike_window_ms;
            while window.front().map(|(ts, _)| *ts < cutoff).unwrap_or(false) {
                window.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> Detector {
        let config = Arc::new(Config::default());
        let profiles = Arc::new(ProfileSet::load(&config).unwrap());
        let dns = DnsState::new();
        Detector::new(config, profiles, dns)
    }

    fn connection(agent: &str, ip: &str, ts: i64) -> Event {
        Event::Connection(ConnectionSample {
            ts,
            pid: 100,
            agent_id: Some(agent.into()),
            remote_addr: format!("{ip}:443"),
            remote_ip: Some(ip.into()),
            remote_port: Some(443),
            remote_host: None,
            proto: "tcp".into(),
        })
    }

    fn volume(agent: &str, bytes_out: u64, ts: i64) -> Event {
        Event::Volume(VolumeSample {
            ts,
            pid: 100,
            agent_id: Some(agent.into()),
            bytes_in: 0,
            bytes_out,
            window_ms: 1000,
        })
    }

    fn file(agent: &str, path: &str, ts: i64) -> Event {
        Event::File(FileEvent {
            ts,
            pid: 100,
            agent_id: Some(agent.into()),
            path: PathBuf::from(path),
            op: FileOp::Open,
            source: "test".into(),
            process_exe: None,
        })
    }

    #[test]
    fn flags_unknown_destination_once() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        let findings = detector.evaluate(&connection("zcode", "1.2.3.4", now), ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_UNKNOWN_DOMAIN);
        assert_eq!(findings[0].severity, Severity::Low);

        let again = detector.evaluate(&connection("zcode", "1.2.3.4", now + 1000), ctx);
        assert!(again.is_empty(), "dedupe should suppress repeats");
    }

    #[test]
    fn skips_reserved_and_fake_ip_ranges() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        for ip in ["198.18.0.85", "203.0.113.9", "100.64.1.2", "192.0.2.5"] {
            assert!(
                detector
                    .evaluate(&connection("zcode", ip, now), ctx)
                    .is_empty(),
                "{ip} should not raise a finding"
            );
        }
    }

    #[test]
    fn ignores_private_and_loopback_destinations() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        assert!(
            detector
                .evaluate(&connection("zcode", "192.168.1.20", now), ctx)
                .is_empty()
        );
        assert!(
            detector
                .evaluate(&connection("zcode", "127.0.0.1", now), ctx)
                .is_empty()
        );
    }

    #[test]
    fn flags_volume_spike() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        let mut findings = Vec::new();
        for i in 0..3 {
            findings.extend(detector.evaluate(
                &volume("claude-code", 10 * 1024 * 1024, now + i * 1000),
                ctx,
            ));
        }
        assert!(findings.iter().any(|f| f.rule_id == RULE_VOLUME_SPIKE));
    }

    #[test]
    fn flags_sensitive_file_reads() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        let findings = detector.evaluate(&file("zcode", "/Users/me/proj/.env", now), ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_SENSITIVE_READ);
    }

    #[test]
    fn correlates_bulk_read_with_upload() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        for i in 0..250 {
            detector.evaluate(
                &file("zcode", &format!("/Users/me/proj/src/file{i}.rs"), now + i),
                ctx,
            );
        }
        let findings = detector.evaluate(&volume("zcode", 5 * 1024 * 1024, now + 5_000), ctx);
        let chain = findings
            .iter()
            .find(|f| f.rule_id == RULE_EXFIL_CHAIN)
            .expect("expected exfil.chain to fire");
        assert_eq!(chain.severity, Severity::Critical);
        assert!(!chain.evidence.is_empty());
    }

    #[test]
    fn does_not_correlate_outside_window() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let now = util::now_ms();
        for i in 0..250 {
            detector.evaluate(
                &file("zcode", &format!("/Users/me/proj/src/file{i}.rs"), now + i),
                ctx,
            );
        }
        let late = now + 10 * 60 * 1000;
        let findings = detector.evaluate(&volume("zcode", 5 * 1024 * 1024, late), ctx);
        assert!(findings.iter().all(|f| f.rule_id != RULE_EXFIL_CHAIN));
    }

    #[test]
    fn flags_high_entropy_artifact() {
        let mut detector = detector();
        let registry = Registry::new();
        let ctx = DetectCtx {
            registry: &registry,
        };
        let findings = detector.evaluate(
            &Event::Artifact(Artifact {
                ts: util::now_ms(),
                agent_id: "zcode".into(),
                path: PathBuf::from("/Users/me/Library/Application Support/ZCode/blob.bin"),
                size: 300 * 1024 * 1024,
                entropy: 7.9,
                kind: ArtifactKind::HiddenBlob,
                detail: "high entropy".into(),
            }),
            ctx,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_HIDDEN_BLOB);
    }
}
