use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        Some(match s.to_ascii_lowercase().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }

    pub fn rank(self) -> i64 {
        self as i64
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub agent_id: Option<String>,
    pub start_time: u64,
    pub ts: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOp {
    Open,
    Write,
    Create,
    Rename,
    Unlink,
}

impl FileOp {
    pub fn as_str(self) -> &'static str {
        match self {
            FileOp::Open => "open",
            FileOp::Write => "write",
            FileOp::Create => "create",
            FileOp::Rename => "rename",
            FileOp::Unlink => "unlink",
        }
    }

    pub fn parse(s: &str) -> Option<FileOp> {
        Some(match s.to_ascii_lowercase().as_str() {
            "open" => FileOp::Open,
            "write" => FileOp::Write,
            "create" => FileOp::Create,
            "rename" => FileOp::Rename,
            "unlink" => FileOp::Unlink,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub ts: i64,
    pub pid: u32,
    pub agent_id: Option<String>,
    pub path: PathBuf,
    pub op: FileOp,
    pub source: String,
    pub process_exe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSample {
    pub ts: i64,
    pub pid: u32,
    pub agent_id: Option<String>,
    pub remote_addr: String,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub remote_host: Option<String>,
    pub proto: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSample {
    pub ts: i64,
    pub pid: u32,
    pub agent_id: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub window_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    HiddenBlob,
    LargeFile,
    UnexpectedEndpoint,
    DataDirGrowth,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::HiddenBlob => "hidden_blob",
            ArtifactKind::LargeFile => "large_file",
            ArtifactKind::UnexpectedEndpoint => "unexpected_endpoint",
            ArtifactKind::DataDirGrowth => "data_dir_growth",
        }
    }

    pub fn parse(s: &str) -> Option<ArtifactKind> {
        Some(match s {
            "hidden_blob" => ArtifactKind::HiddenBlob,
            "large_file" => ArtifactKind::LargeFile,
            "unexpected_endpoint" => ArtifactKind::UnexpectedEndpoint,
            "data_dir_growth" => ArtifactKind::DataDirGrowth,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub ts: i64,
    pub agent_id: String,
    pub path: PathBuf,
    pub size: u64,
    pub entropy: f32,
    pub kind: ArtifactKind,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCapture {
    pub ts: i64,
    pub pid: Option<u32>,
    pub agent_id: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub bytes_out: u64,
    pub body_sha256: Option<String>,
    pub class: String,
    pub sample: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Process(ProcessInfo),
    Connection(ConnectionSample),
    Volume(VolumeSample),
    File(FileEvent),
    Http(HttpCapture),
    Artifact(Artifact),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub ts: i64,
    pub kind: String,
    pub summary: String,
    pub detail: Option<String>,
}

impl Evidence {
    pub fn new(kind: impl Into<String>, summary: impl Into<String>) -> Self {
        Evidence {
            ts: crate::util::now_ms(),
            kind: kind.into(),
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn at(ts: i64, kind: impl Into<String>, summary: impl Into<String>) -> Self {
        Evidence {
            ts,
            kind: kind.into(),
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Open,
    Ignored,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::Ignored => "ignored",
        }
    }

    pub fn parse(s: &str) -> Option<FindingStatus> {
        Some(match s {
            "open" => FindingStatus::Open,
            "ignored" => FindingStatus::Ignored,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(default)]
    pub id: Option<i64>,
    pub ts: i64,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub agent_id: Option<String>,
    pub pid: Option<u32>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default = "default_status")]
    pub status: FindingStatus,
    #[serde(default)]
    pub dedupe_key: Option<String>,
}

fn default_status() -> FindingStatus {
    FindingStatus::Open
}

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Finding {
            id: None,
            ts: crate::util::now_ms(),
            rule_id: rule_id.into(),
            severity,
            title: title.into(),
            detail: detail.into(),
            agent_id: None,
            pid: None,
            evidence: Vec::new(),
            status: FindingStatus::Open,
            dedupe_key: None,
        }
    }

    pub fn with_agent(mut self, agent_id: Option<String>) -> Self {
        self.agent_id = agent_id;
        self
    }

    pub fn with_pid(mut self, pid: Option<u32>) -> Self {
        self.pid = pid;
        self
    }

    pub fn with_dedupe(mut self, key: impl Into<String>) -> Self {
        self.dedupe_key = Some(key.into());
        self
    }

    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub first_seen: i64,
    pub last_seen: i64,
}
