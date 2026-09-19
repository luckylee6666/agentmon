pub mod ca;
pub mod classify;

use crate::collect::SharedRegistry;
use crate::model::{Event, HttpCapture};
use crate::profiles::ProfileSet;
use anyhow::{Context, Result};
use bytes::Bytes;
use ca::Ca;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, BodyStream, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct ProxyOptions {
    pub listen: SocketAddr,
    /// Attribution fallback when the source port cannot be mapped to a pid.
    pub default_agent: Option<String>,
    /// How many bytes of each request body are inspected for classification.
    pub capture_bytes: usize,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        ProxyOptions {
            listen: "127.0.0.1:8899".parse().expect("valid default listen addr"),
            default_agent: None,
            capture_bytes: 1024 * 1024,
        }
    }
}

pub struct ProxyContext {
    pub opts: ProxyOptions,
    pub ca: Arc<Ca>,
    pub server_config: Arc<ServerConfig>,
    pub client: reqwest::Client,
    pub sink: Option<tokio::sync::mpsc::UnboundedSender<Event>>,
    pub registry: SharedRegistry,
    pub profiles: Arc<ProfileSet>,
    /// local port -> (pid, observed_at). Ephemeral ports get reused, so entries
    /// are timestamped and stale ones are ignored rather than misattributed.
    pub port_owner: Arc<RwLock<HashMap<u16, (u32, i64)>>>,
}

impl ProxyContext {
    pub fn agent_for_port(&self, port: u16) -> Option<String> {
        let owner = self
            .port_owner
            .read()
            .ok()
            .and_then(|map| map.get(&port).copied())
            .filter(|(_, observed)| crate::util::now_ms() - observed < PORT_MAP_TTL_MS);
        if let Some((pid, _)) = owner
            && let Some(agent) = self
                .registry
                .read()
                .ok()
                .and_then(|registry| registry.agent_id(pid).map(|s| s.to_string()))
            {
                return Some(agent);
            }
        self.opts.default_agent.clone()
    }

    pub fn pid_for_port(&self, port: u16) -> Option<u32> {
        self.port_owner
            .read()
            .ok()
            .and_then(|map| map.get(&port).copied())
            .filter(|(_, observed)| crate::util::now_ms() - observed < PORT_MAP_TTL_MS)
            .map(|(pid, _)| pid)
    }
}

const PORT_MAP_TTL_MS: i64 = 6_000;

pub struct MitmProxy {
    pub addr: SocketAddr,
    pub ca_cert: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    accept_task: tokio::task::JoinHandle<()>,
    port_map_task: tokio::task::JoinHandle<()>,
}

impl MitmProxy {
    pub async fn start(
        opts: ProxyOptions,
        ca: Arc<Ca>,
        sink: Option<tokio::sync::mpsc::UnboundedSender<Event>>,
        registry: SharedRegistry,
        profiles: Arc<ProfileSet>,
    ) -> Result<MitmProxy> {
        let listener = TcpListener::bind(opts.listen)
            .await
            .with_context(|| format!("binding proxy listener on {}", opts.listen))?;
        let addr = listener.local_addr()?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .danger_accept_invalid_certs(false)
            .build()
            .context("building upstream http client")?;

        let server_config = ca.server_config();
        let port_owner: Arc<RwLock<HashMap<u16, (u32, i64)>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let ctx = Arc::new(ProxyContext {
            opts,
            ca: ca.clone(),
            server_config,
            client,
            sink,
            registry,
            profiles,
            port_owner: port_owner.clone(),
        });

        let (tx, _rx) = tokio::sync::oneshot::channel();
        let accept_task = tokio::spawn(accept_loop(listener, ctx));
        let port_map_task = tokio::spawn(port_map_loop(port_owner));

        Ok(MitmProxy {
            addr,
            ca_cert: ca.cert_path(),
            shutdown: Some(tx),
            accept_task,
            port_map_task,
        })
    }

    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.accept_task.abort();
        self.port_map_task.abort();
    }
}

async fn accept_loop(listener: TcpListener, ctx: Arc<ProxyContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, peer, ctx).await {
                        tracing::debug!("proxy connection error: {err:#}");
                    }
                });
            }
            Err(err) => {
                tracing::debug!("proxy accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn port_map_loop(port_owner: Arc<RwLock<HashMap<u16, (u32, i64)>>>) {
    loop {
        match crate::collect::netflow::connections::sample_connections() {
            Ok(connections) => {
                let now = crate::util::now_ms();
                if let Ok(mut map) = port_owner.write() {
                    map.clear();
                    for connection in connections {
                        if let Some(port) = connection.local_port {
                            map.insert(port, (connection.pid, now));
                        }
                    }
                }
            }
            Err(err) => tracing::debug!("port map sampling failed: {err:#}"),
        }
        // Refreshed often: a closed connection disappears quickly, which keeps
        // a reused ephemeral port from being attributed to the previous owner.
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { handle_plaintext(req, peer, ctx).await }
    });
    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .context("serving client connection")?;
    Ok(())
}

/// Splits `host:port` / `[v6]:port` into a bare host and an optional port.
/// The authority keeps its port for the upstream URL, while rules and allowlists
/// compare against the bare hostname.
pub fn split_authority(authority: &str) -> (String, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((ip, port)) = rest.split_once("]:") {
            return (ip.to_string(), port.parse().ok());
        }
        if let Some(ip) = rest.strip_suffix(']') {
            return (ip.to_string(), None);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host.to_string(), port.parse().ok())
        }
        _ => (authority.to_string(), None),
    }
}

async fn handle_plaintext(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> anyhow::Result<Response<BoxBody<Bytes, BoxError>>> {
    if req.method() == Method::CONNECT {
        let authority = req.uri().authority().map(|authority| authority.to_string());
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let io = TokioIo::new(upgraded);
                    if let Err(err) = serve_intercepted(io, authority, peer, ctx).await {
                        tracing::debug!("intercepted session ended: {err:#}");
                    }
                }
                Err(err) => tracing::debug!("proxy upgrade failed: {err}"),
            }
        });
        return Ok(Response::new(empty_body()));
    }

    // Plain HTTP through the proxy (no TLS to intercept).
    let authority = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .or_else(|| req.uri().authority().map(|authority| authority.to_string()))
        .unwrap_or_else(|| "unknown".into());
    forward(req, authority, "http", peer, ctx).await
}

async fn serve_intercepted(
    io: TokioIo<hyper::upgrade::Upgraded>,
    authority: Option<String>,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(ctx.server_config.clone());
    let tls = acceptor
        .accept(io)
        .await
        .context("tls handshake with client")?;
    let io = TokioIo::new(tls);
    let authority_for_service = authority.clone();
    let ctx_for_service = ctx.clone();
    let service = service_fn(move |req| {
        let authority = authority_for_service
            .clone()
            .or_else(|| {
                req.headers()
                    .get(hyper::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string())
            })
            .unwrap_or_else(|| "unknown".into());
        let ctx = ctx_for_service.clone();
        async move { forward(req, authority, "https", peer, ctx).await }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(io, service)
        .await
        .context("serving intercepted connection")?;
    Ok(())
}

async fn forward(
    req: Request<Incoming>,
    authority: String,
    scheme: &str,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> anyhow::Result<Response<BoxBody<Bytes, BoxError>>> {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // Keep the port: dropping it broke forwarding to anything not on 443/80.
    let (host, _port) = split_authority(&authority);
    let url = format!("{scheme}://{authority}{path_and_query}");

    let content_length = parts
        .headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let content_type = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let limit = ctx.opts.capture_bytes;
    let tee = {
        let captured = captured.clone();
        move |frame: Frame<Bytes>| {
            let data = frame.into_data().unwrap_or_default();
            if let Ok(mut guard) = captured.lock() {
                let remaining = limit.saturating_sub(guard.len());
                if remaining > 0 {
                    let take = remaining.min(data.len());
                    guard.extend_from_slice(&data[..take]);
                }
            }
            data
        }
    };

    // The body is streamed upstream (never fully buffered) while the first
    // `capture_bytes` are teed off for classification.
    let body_stream = BodyStream::new(body).map_ok(tee).map_ok(Frame::data);
    let upstream_body = reqwest::Body::wrap(StreamBody::new(body_stream));
    let method = parts.method.clone();
    let mut request = ctx.client.request(method.clone(), &url).body(upstream_body);

    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        request = request.header(name, value);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            emit_capture(
                &ctx,
                &peer,
                &host,
                &method,
                &path_and_query,
                content_type.as_deref(),
                content_length,
                &captured,
            );
            tracing::debug!("upstream request to {url} failed: {err:#}");
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(full_body(format!("agentmon: upstream error: {err}")))
                .expect("building error response"));
        }
    };

    emit_capture(
        &ctx,
        &peer,
        &host,
        &method,
        &path_and_query,
        content_type.as_deref(),
        content_length,
        &captured,
    );

    let status = response.status();
    let headers = response.headers().clone();
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let stream = response
        .bytes_stream()
        .map_ok(Frame::data)
        .map_err(|err| Box::new(err) as BoxError);
    Ok(builder.body(StreamBody::new(stream).boxed())?)
}

#[allow(clippy::too_many_arguments)]
fn emit_capture(
    ctx: &Arc<ProxyContext>,
    peer: &SocketAddr,
    host: &str,
    method: &Method,
    path: &str,
    content_type: Option<&str>,
    content_length: Option<u64>,
    captured: &Arc<Mutex<Vec<u8>>>,
) {
    let Some(sink) = &ctx.sink else { return };
    let bytes = captured
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let query = path.split_once('?').map(|(_, query)| query).unwrap_or("");

    // A body is the obvious channel; a long query string is the less obvious
    // one (data smuggled into GET parameters), so it gets inspected too.
    let body_empty = bytes.is_empty();
    if body_empty && query.len() < 100 {
        return;
    }
    let classification = if body_empty {
        classify::classify(query.as_bytes(), content_type)
    } else {
        classify::classify(&bytes, content_type)
    };
    if classification.class == classify::PayloadClass::Empty {
        return;
    }

    let agent_id = ctx.agent_for_port(peer.port());
    let pid = ctx.pid_for_port(peer.port());
    let digest = Sha256::digest(&bytes);
    let body_sha256: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

    let _ = sink.send(Event::Http(HttpCapture {
        ts: crate::util::now_ms(),
        pid,
        agent_id,
        host: host.to_string(),
        method: method.as_str().to_string(),
        path: path.to_string(),
        bytes_out: content_length.unwrap_or(if body_empty {
            query.len() as u64
        } else {
            bytes.len() as u64
        }),
        body_sha256: Some(body_sha256),
        class: classification.class.as_str().to_string(),
        sample: classification.sample,
    }));
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "te"
            | "trailer"
    )
}

fn empty_body() -> BoxBody<Bytes, BoxError> {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(text: String) -> BoxBody<Bytes, BoxError> {
    http_body_util::Full::new(Bytes::from(text))
        .map_err(|never| match never {})
        .boxed()
}
