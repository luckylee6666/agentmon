//! End-to-end check of the core promise: a process that reads a repository in
//! bulk and then uploads a packed payload must produce an `exfil.chain` finding
//! with a complete evidence trail.
//!
//! The upload half is real: it goes through the actual MITM proxy over a real
//! TCP connection, so the classifier, the capture pipeline and the rule engine
//! are all exercised. The file-read half is fed as events, because producing
//! real Endpoint Security events would require root.

use agentmon_core::collect::SharedRegistry;
use agentmon_core::config::Config;
use agentmon_core::detect::{
    DetectCtx, Detector, RULE_BULK_READ, RULE_EXFIL_CHAIN, RULE_SENSITIVE_READ,
};
use agentmon_core::model::{Event, FileEvent, FileOp, Severity};
use agentmon_core::profiles::ProfileSet;
use agentmon_core::proxy::ca::Ca;
use agentmon_core::proxy::{MitmProxy, ProxyOptions};
use agentmon_core::registry::Registry;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AGENT: &str = "zcode";

async fn start_sink() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let addr = listener.local_addr().expect("sink addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                let mut received = Vec::new();
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(read) => {
                            received.extend_from_slice(&buffer[..read]);
                            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn fake_repo_source(files: usize) -> String {
    let mut out = String::new();
    for index in 0..files {
        out.push_str(&format!(
            "use std::collections::HashMap;\n\npub struct Module{index} {{\n    pub name: String,\n}}\n\nimpl Module{index} {{\n    pub fn run(&self) -> u8 {{\n        let mut map = HashMap::new();\n        map.insert(self.name.clone(), {index});\n        {index} as u8\n    }}\n}}\n\n"
        ));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_read_then_packed_upload_raises_exfil_chain() {
    let sink = start_sink().await;

    let config = Arc::new(Config::default());
    let profiles = Arc::new(ProfileSet::load(&config).expect("profiles"));
    let registry: SharedRegistry = Arc::new(RwLock::new(Registry::new()));

    let ca_dir = std::env::temp_dir().join(format!("agentmon-e2e-ca-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ca_dir);
    let ca = Arc::new(Ca::load_or_create(&ca_dir).expect("ca"));

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let proxy = MitmProxy::start(
        ProxyOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            default_agent: Some(AGENT.to_string()),
            capture_bytes: 4 * 1024 * 1024,
            store_bodies: true,
            max_body_bytes: 1024 * 1024,
        },
        ca.clone(),
        Some(tx),
        registry.clone(),
        profiles.clone(),
    )
    .await
    .expect("proxy start");

    // The "agent": packs a repository (source + .git metadata) and posts it to
    // an endpoint that is not in its profile.
    let payload = gzip(format!("{}{}", fake_repo_source(60), ".git/config\n").as_bytes());
    assert!(
        payload.len() > 256,
        "payload should be a realistic packed blob, got {} bytes",
        payload.len()
    );

    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", proxy.addr)).expect("proxy url"))
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    let response = http
        .post(format!("http://{sink}/v1/index/upload"))
        .header("content-type", "application/octet-stream")
        .body(payload.clone())
        .send()
        .await
        .expect("upload through proxy");
    assert_eq!(response.status(), 200);

    let capture = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = rx.recv().await {
            if let Event::Http(capture) = event {
                return capture;
            }
        }
        panic!("no capture event");
    })
    .await
    .expect("capture arrived");

    assert_eq!(
        capture.host,
        sink.ip().to_string(),
        "host is the sink address"
    );
    assert_eq!(
        capture.class, "source_code",
        "the packed repository must be classified as source code, got {}",
        capture.class
    );
    assert_eq!(capture.agent_id.as_deref(), Some(AGENT));
    let stored = capture
        .body
        .as_deref()
        .expect("store_bodies is on, so the uploaded payload should be kept");
    assert!(
        stored.contains("pub struct Module"),
        "the stored body should be the *decompressed* repository text, not the gzip bytes"
    );

    // Now replay the read half of the chain: bulk reads inside a repo, including
    // the git metadata that makes it a "full repository" upload.
    let mut detector = Detector::new(
        config.clone(),
        profiles.clone(),
        agentmon_core::dns::DnsState::new(),
    );
    let registry_snapshot = registry.read().expect("registry");
    let ctx = DetectCtx {
        registry: &registry_snapshot,
    };

    let base = agentmon_core::util::now_ms() - 5_000;
    let mut findings = Vec::new();
    for index in 0..260usize {
        let path = if index % 40 == 0 {
            PathBuf::from(format!(
                "/Users/dev/project/.git/objects/{index:02x}/abcdef"
            ))
        } else {
            PathBuf::from(format!("/Users/dev/project/src/module{index}.rs"))
        };
        findings.extend(detector.evaluate(
            &Event::File(FileEvent {
                ts: base + index as i64,
                pid: 4242,
                agent_id: Some(AGENT.into()),
                path,
                op: FileOp::Open,
                source: "e2e".into(),
                process_exe: None,
            }),
            ctx,
        ));
    }
    findings.extend(detector.evaluate(&Event::Http(capture.clone()), ctx));
    drop(registry_snapshot);

    let rules: Vec<&str> = findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(
        rules.contains(&RULE_BULK_READ),
        "expected fs.bulk_read, got {rules:?}"
    );

    let chain = findings
        .iter()
        .find(|finding| finding.rule_id == RULE_EXFIL_CHAIN)
        .unwrap_or_else(|| panic!("expected exfil.chain, got {rules:?}"));
    assert_eq!(chain.severity, Severity::Critical);
    assert_eq!(chain.agent_id.as_deref(), Some(AGENT));
    assert!(
        chain.evidence.len() >= 2,
        "evidence chain must contain the read and the upload, got {:?}",
        chain.evidence
    );
    assert!(
        chain.evidence.iter().any(|item| item.kind == "http-upload"),
        "evidence must include the upload step: {:?}",
        chain.evidence
    );

    // A sensitive file read on its own must also be reported.
    let secret_findings = detector.evaluate(
        &Event::File(FileEvent {
            ts: agentmon_core::util::now_ms(),
            pid: 4242,
            agent_id: Some(AGENT.into()),
            path: PathBuf::from("/Users/dev/project/.env"),
            op: FileOp::Open,
            source: "e2e".into(),
            process_exe: None,
        }),
        DetectCtx {
            registry: &Registry::new(),
        },
    );
    assert!(
        secret_findings
            .iter()
            .any(|finding| finding.rule_id == RULE_SENSITIVE_READ),
        "expected fs.sensitive_read for .env"
    );

    proxy.stop();
    let _ = std::fs::remove_dir_all(&ca_dir);
}

/// A well-behaved upload (small, non-sensitive, to an allowlisted endpoint)
/// must not produce findings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benign_api_call_is_not_flagged() {
    let sink = start_sink().await;
    let config = Arc::new(Config::default());
    let profiles = Arc::new(ProfileSet::load(&config).expect("profiles"));
    let registry: SharedRegistry = Arc::new(RwLock::new(Registry::new()));

    let ca_dir =
        std::env::temp_dir().join(format!("agentmon-e2e-ca-benign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ca_dir);
    let ca = Arc::new(Ca::load_or_create(&ca_dir).expect("ca"));

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let proxy = MitmProxy::start(
        ProxyOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            default_agent: Some("claude-code".to_string()),
            capture_bytes: 1024 * 1024,
            store_bodies: false,
            max_body_bytes: 64 * 1024,
        },
        ca.clone(),
        Some(tx),
        registry,
        profiles.clone(),
    )
    .await
    .expect("proxy start");

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", proxy.addr)).expect("proxy url"))
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    let response = client
        .post(format!("http://{sink}/v1/messages"))
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"总结一下这个函数"}]}"#)
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    let capture = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = rx.recv().await {
            if let Event::Http(capture) = event {
                return capture;
            }
        }
        panic!("no capture event");
    })
    .await
    .expect("capture arrived");

    assert_eq!(capture.class, "text", "a chat request is not source code");
    assert!(
        capture.body.is_none(),
        "with capture_bodies off nothing is retained"
    );

    let mut detector = Detector::new(config, profiles, agentmon_core::dns::DnsState::new());
    let findings = detector.evaluate(
        &Event::Http(capture),
        DetectCtx {
            registry: &Registry::new(),
        },
    );
    assert!(
        findings.is_empty(),
        "benign chat traffic must stay quiet, got {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );

    proxy.stop();
    let _ = std::fs::remove_dir_all(&ca_dir);
}
