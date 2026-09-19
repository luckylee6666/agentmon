use crate::collect::artifacts::ArtifactScanner;
use crate::collect::fileaudit::{self, FileAuditHandle};
use crate::collect::netflow::NetflowCollector;
use crate::collect::procscan::ProcScanCollector;
use crate::collect::{CollectorCtx, SharedRegistry};
use crate::config::Config;
use crate::dns::{DnsState, PtrResolver, refresh_allowed_ips};
use crate::model::Event;
use crate::profiles::ProfileSet;
use crate::registry::Registry;
use std::sync::Arc;
use std::sync::RwLock;

pub struct PipelineAvailability {
    pub file_audit: bool,
    pub byte_accounting: bool,
    pub proxy: Option<std::net::SocketAddr>,
}

pub struct Pipeline {
    pub registry: SharedRegistry,
    pub event_tx: tokio::sync::mpsc::UnboundedSender<Event>,
    pub dns: Arc<DnsState>,
    pub availability: PipelineAvailability,
    procscan: ProcScanCollector,
    netflow: NetflowCollector,
    fileaudit: Box<dyn FileAuditHandle>,
    artifacts: ArtifactScanner,
    proxy: Option<crate::proxy::MitmProxy>,
}

impl Pipeline {
    pub async fn start(
        config: Arc<Config>,
        profiles: Arc<ProfileSet>,
    ) -> (Pipeline, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let (sink, events) = tokio::sync::mpsc::unbounded_channel::<Event>();
        let event_tx = sink.clone();
        let registry: SharedRegistry = Arc::new(RwLock::new(Registry::new()));
        let dns = DnsState::new();
        let ptr = Arc::new(PtrResolver::spawn(dns.clone(), 2));

        let ctx = CollectorCtx {
            sink,
            registry: registry.clone(),
            profiles: profiles.clone(),
            config: config.clone(),
        };

        refresh_allowed_ips(&dns, &profiles, &config).await;
        {
            let dns = dns.clone();
            let profiles = profiles.clone();
            let config = config.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    refresh_allowed_ips(&dns, &profiles, &config).await;
                }
            });
        }

        let procscan = ProcScanCollector::start(ctx.clone());
        // Give the process scanner a first pass so attribution is ready
        // before network samples arrive.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let netflow = NetflowCollector::start(ctx.clone(), dns.clone(), ptr);
        let fileaudit = fileaudit::start(ctx.clone());
        let artifacts = ArtifactScanner::start(ctx.clone());

        let proxy = if config.proxy.enabled {
            match start_proxy(&config, &profiles, &ctx).await {
                Ok(proxy) => Some(proxy),
                Err(err) => {
                    tracing::warn!("content proxy disabled: {err:#}");
                    None
                }
            }
        } else {
            None
        };
        let proxy_addr = proxy.as_ref().map(|proxy| proxy.addr);

        let availability = PipelineAvailability {
            file_audit: fileaudit.available(),
            byte_accounting: cfg!(target_os = "macos"),
            proxy: proxy_addr,
        };

        let pipeline = Pipeline {
            registry,
            event_tx,
            dns,
            availability,
            procscan,
            netflow,
            fileaudit,
            artifacts,
            proxy,
        };
        (pipeline, events)
    }

    pub fn stop(&mut self) {
        if let Some(proxy) = self.proxy.take() {
            proxy.stop();
        }
        self.artifacts.stop();
        self.fileaudit.stop();
        self.netflow.stop();
        self.procscan.stop();
    }
}

async fn start_proxy(
    config: &Arc<Config>,
    profiles: &Arc<ProfileSet>,
    ctx: &CollectorCtx,
) -> anyhow::Result<crate::proxy::MitmProxy> {
    let listen: std::net::SocketAddr =
        config.proxy.listen.parse().map_err(|err| {
            anyhow::anyhow!("invalid proxy.listen {}: {err}", config.proxy.listen)
        })?;
    let ca = Arc::new(crate::proxy::ca::Ca::load_or_create(
        &crate::paths::ca_dir(),
    )?);
    let options = crate::proxy::ProxyOptions {
        listen,
        default_agent: None,
        capture_bytes: config.proxy.capture_bytes,
        store_bodies: config.capture.capture_bodies,
        max_body_bytes: config.capture.max_body_bytes,
    };
    let proxy = crate::proxy::MitmProxy::start(
        options,
        ca,
        Some(ctx.sink.clone()),
        ctx.registry.clone(),
        profiles.clone(),
    )
    .await?;
    tracing::info!("content proxy listening on {}", proxy.addr);
    Ok(proxy)
}
