use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

#[cfg(feature = "access-control")]
use axum::extract::connect_info::Connected;
use axum::extract::State;
use axum::http::Method;
use axum::response::{IntoResponse, Response};
#[cfg(feature = "access-control")]
use axum::serve::IncomingStream;
use axum::serve::Listener as AxumListener;
use axum::Router;
#[cfg(feature = "acme")]
use futures::Stream;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_listener::{Listener, SystemOptions, UserOptions};
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::info;

use crate::config::{Config, ConnectionConfig};
use crate::ohttp_relay::SentinelTag;

#[cfg(feature = "access-control")]
pub mod access_control;
pub mod cli;
pub mod config;
pub mod db;
pub mod directory;
pub mod key_config;
pub mod metrics;
pub mod middleware;
pub mod ohttp_relay;

use crate::metrics::MetricsService;
use crate::middleware::track_metrics;

type DirectoryService =
    crate::directory::Service<crate::db::MetricsDb<crate::db::DbServiceAdapter>>;

const CONNECTION_SHED_GLOBAL: &str = "global";
const CONNECTION_SHED_SOURCE: &str = "source";

#[derive(Clone)]
struct Services {
    directory: DirectoryService,
    relay: crate::ohttp_relay::Service,
    metrics: MetricsService,
    #[cfg(feature = "access-control")]
    geoip: Option<std::sync::Arc<access_control::IpFilter>>,
}

pub async fn serve(config: Config, meter_provider: Option<SdkMeterProvider>) -> anyhow::Result<()> {
    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new(meter_provider);
    let connection_limits = ConnectionLimits::from_config(&config.connection, metrics.clone())?;

    #[cfg(feature = "access-control")]
    let geoip = init_geoip(&config).await?;

    let directory = init_directory(&config, sentinel_tag, &metrics).await?;

    let services = Services {
        directory,
        relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
        metrics,
        #[cfg(feature = "access-control")]
        geoip,
    };

    let app = build_app(services);

    // EMFILE/ENFILE (file-descriptor exhaustion) is transient. Without
    // sleep_on_errors, tokio_listener treats it as fatal and the axum08
    // accept loop hangs forever (std::future::pending), so a momentary FD
    // spike permanently downs the service until it is manually restarted.
    // Backing off 1s and retrying lets the listener self-heal once
    // descriptors free up (long-polls time out, tunnels close).
    let mut system_options = SystemOptions::default();
    system_options.sleep_on_errors = true;
    let listener =
        Listener::bind(&config.listener, &system_options, &UserOptions::default()).await?;
    info!("Payjoin service listening on {:?}", listener.local_addr());
    serve_with_listener(
        limit_connections(listener, connection_limits),
        app,
        config.connection.header_read_timeout,
    )
    .await?;

    Ok(())
}

/// Serves payjoin-mailroom with manual TLS configuration.
///
/// Binds to `config.listener` (use port 0 to let the OS assign a free port) and returns
/// the actual bound port and a task handle.
///
/// If `tls_config` is provided, the server will use TLS for incoming connections.
/// The `root_store` is used for outgoing relay connections to the gateway.
#[cfg(feature = "_manual-tls")]
pub async fn serve_manual_tls(
    config: Config,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
    root_store: rustls::RootCertStore,
    default_gateway: Option<crate::ohttp_relay::GatewayUri>,
) -> anyhow::Result<(u16, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    use std::net::SocketAddr;

    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new(None);
    let connection_limits = ConnectionLimits::from_config(&config.connection, metrics.clone())?;

    #[cfg(feature = "access-control")]
    let geoip = init_geoip(&config).await?;

    let directory = init_directory(&config, sentinel_tag, &metrics).await?;

    let services = Services {
        directory,
        relay: crate::ohttp_relay::Service::new_with_roots(
            sentinel_tag,
            root_store,
            default_gateway,
        )
        .await,
        metrics,
        #[cfg(feature = "access-control")]
        geoip,
    };
    let app = build_app(services);

    let addr: SocketAddr = config
        .listener
        .to_string()
        .parse()
        .map_err(|_| anyhow::anyhow!("TLS mode requires a TCP address (e.g., '[::]:8080')"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();

    let handle = match tls_config {
        Some(tls) => {
            // The manual TLS path delegates TLS accept/serving to axum-server.
            // Production deployments use the plain listener behind external TLS
            // or ACME, both of which use the connection-hygiene serve loop above.
            info!("Payjoin service listening on port {} with TLS", port);
            tokio::spawn(async move {
                axum_server::from_tcp_rustls(listener.into_std()?, tls)?
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .map_err(Into::into)
            })
        }
        None => {
            info!("Payjoin service listening on port {} without TLS", port);
            tokio::spawn(async move {
                serve_with_listener(
                    limit_connections(listener, connection_limits),
                    app,
                    config.connection.header_read_timeout,
                )
                .await
            })
        }
    };

    Ok((port, handle))
}

/// Serves payjoin-mailroom with ACME-managed TLS certificates.
///
/// Uses `tokio-rustls-acme` to automatically obtain and renew TLS
/// certificates from Let's Encrypt via the TLS-ALPN-01 challenge.
#[cfg(feature = "acme")]
pub async fn serve_acme(
    config: Config,
    meter_provider: Option<SdkMeterProvider>,
) -> anyhow::Result<()> {
    let acme_config = config
        .acme
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ACME configuration is required for serve_acme"))?;

    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new(meter_provider);
    let connection_limits = ConnectionLimits::from_config(&config.connection, metrics.clone())?;

    #[cfg(feature = "access-control")]
    let geoip = init_geoip(&config).await?;

    let directory = init_directory(&config, sentinel_tag, &metrics).await?;

    let services = Services {
        directory,
        relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
        metrics,
        #[cfg(feature = "access-control")]
        geoip,
    };
    let app = build_app(services);

    let addr: SocketAddr = config
        .listener
        .to_string()
        .parse()
        .map_err(|_| anyhow::anyhow!("ACME mode requires a TCP address (e.g., '[::]:443')"))?;

    let acme = acme_config.into_rustls_config(&config.storage_dir);
    let state = acme.state();
    let rustls_config =
        rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(state.resolver());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let listener = AcmeListener::new(listener, state, rustls_config, connection_limits)?;

    info!("Payjoin service listening on {} with ACME TLS", addr);
    serve_with_listener(listener, app, config.connection.header_read_timeout).await?;
    Ok(())
}

async fn serve_with_listener<L>(
    mut listener: L,
    app: Router,
    header_read_timeout: std::time::Duration,
) -> anyhow::Result<()>
where
    L: AxumListener + Send + 'static,
    L::Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    L::Addr: PeerIp + Debug + Send + 'static,
{
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(header_read_timeout))
        .keep_alive_timeout(header_read_timeout);
    let builder = Arc::new(builder);
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = result {
                    tracing::trace!("connection task failed: {err:#}");
                }
            }
            (io, remote_addr) = listener.accept() => {
                let peer_ip = remote_addr.peer_ip();
                let app = app.clone();
                let builder = builder.clone();

                connections.spawn(async move {
                    let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let app = app.clone();
                        async move { serve_hyper_request(app, req, peer_ip).await }
                    });

                    let io = TokioIo::new(io);
                    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                        tracing::trace!("failed to serve connection: {err:#}");
                    }
                });
            }
        }
    }
}

#[cfg(feature = "access-control")]
async fn serve_hyper_request(
    app: Router,
    mut req: hyper::Request<hyper::body::Incoming>,
    peer_ip: Option<IpAddr>,
) -> Result<Response, Infallible> {
    req.extensions_mut().insert(axum::extract::ConnectInfo(middleware::MaybePeerIp(peer_ip)));
    app.oneshot(req.map(axum::body::Body::new)).await
}

#[cfg(not(feature = "access-control"))]
async fn serve_hyper_request(
    app: Router,
    req: hyper::Request<hyper::body::Incoming>,
    _peer_ip: Option<IpAddr>,
) -> Result<Response, Infallible> {
    app.oneshot(req.map(axum::body::Body::new)).await
}

fn limit_connections<L>(listener: L, limits: ConnectionLimits) -> LimitedListener<L> {
    LimitedListener { inner: listener, limits }
}

struct LimitedListener<L> {
    inner: L,
    limits: ConnectionLimits,
}

struct LimitedIo<I> {
    inner: I,
    _permit: ConnectionPermit,
}

#[cfg(feature = "acme")]
struct AddrIo<I> {
    inner: I,
    addr: SocketAddr,
}

#[derive(Clone)]
struct ConnectionLimits {
    inner: Arc<ConnectionLimitState>,
}

struct ConnectionLimitState {
    global: Arc<Semaphore>,
    max_global: usize,
    max_per_source: usize,
    ipv6_source_prefix: u8,
    per_source: Mutex<HashMap<SourceKey, usize>>,
    metrics: MetricsService,
}

struct ConnectionPermit {
    global: Option<OwnedSemaphorePermit>,
    source: Option<SourceKey>,
    limits: ConnectionLimits,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct SourceKey(IpAddr);

trait PeerIp {
    fn peer_ip(&self) -> Option<IpAddr>;
}

impl PeerIp for SocketAddr {
    fn peer_ip(&self) -> Option<IpAddr> { Some(self.ip()) }
}

impl PeerIp for tokio_listener::SomeSocketAddr {
    fn peer_ip(&self) -> Option<IpAddr> {
        match self {
            tokio_listener::SomeSocketAddr::Tcp(addr) => Some(addr.ip()),
            _ => None,
        }
    }
}

impl ConnectionLimits {
    fn from_config(config: &ConnectionConfig, metrics: MetricsService) -> anyhow::Result<Self> {
        let max_global = effective_connection_cap(config)?;
        metrics.record_active_connections(0);
        Ok(Self {
            inner: Arc::new(ConnectionLimitState {
                global: Arc::new(Semaphore::new(max_global)),
                max_global,
                max_per_source: config.max_connections_per_source,
                ipv6_source_prefix: config.ipv6_source_prefix.min(128),
                per_source: Mutex::new(HashMap::new()),
                metrics,
            }),
        })
    }

    fn try_admit(&self, source: Option<IpAddr>) -> Option<ConnectionPermit> {
        let global = match self.inner.global.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.inner.metrics.record_connection_shed(CONNECTION_SHED_GLOBAL);
                self.record_active_connections();
                return None;
            }
        };

        let source = source.map(|ip| SourceKey::new(ip, self.inner.ipv6_source_prefix));
        if let Some(source) = source {
            let mut per_source = self.inner.per_source.lock().expect("source limits lock poisoned");
            let count = per_source.entry(source).or_insert(0);
            if *count >= self.inner.max_per_source {
                self.inner.metrics.record_connection_shed(CONNECTION_SHED_SOURCE);
                drop(per_source);
                drop(global);
                self.record_active_connections();
                return None;
            }
            *count += 1;
        }

        self.inner.metrics.record_connection_accepted(self.active_connections());
        Some(ConnectionPermit { global: Some(global), source, limits: self.clone() })
    }

    fn release_source(&self, source: SourceKey) {
        let mut per_source = self.inner.per_source.lock().expect("source limits lock poisoned");
        if let Some(count) = per_source.get_mut(&source) {
            *count -= 1;
            if *count == 0 {
                per_source.remove(&source);
            }
        }
    }

    fn active_connections(&self) -> usize {
        self.inner.max_global - self.inner.global.available_permits()
    }

    fn record_active_connections(&self) {
        self.inner.metrics.record_active_connections(self.active_connections());
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            self.limits.release_source(source);
        }
        drop(self.global.take());
        self.limits.record_active_connections();
    }
}

impl SourceKey {
    fn new(ip: IpAddr, ipv6_prefix: u8) -> Self {
        match ip {
            IpAddr::V4(ip) => Self(IpAddr::V4(ip)),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => Self(IpAddr::V4(ip)),
                None => Self(IpAddr::V6(mask_ipv6(ip, ipv6_prefix))),
            },
        }
    }
}

fn mask_ipv6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let prefix = prefix.min(128);
    let bits = u128::from_be_bytes(ip.octets());
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    Ipv6Addr::from((bits & mask).to_be_bytes())
}

fn effective_connection_cap(config: &ConnectionConfig) -> anyhow::Result<usize> {
    if config.max_inbound_connections == 0 {
        anyhow::bail!("connection.max_inbound_connections must be greater than zero");
    }
    if config.max_connections_per_source == 0 {
        anyhow::bail!("connection.max_connections_per_source must be greater than zero");
    }

    let configured = config.max_inbound_connections;
    match soft_open_file_limit() {
        Some(limit) if limit > config.fd_reserve => Ok(configured.min(limit - config.fd_reserve)),
        Some(limit) => anyhow::bail!(
            "connection.fd_reserve ({}) must be lower than RLIMIT_NOFILE ({limit})",
            config.fd_reserve
        ),
        None => Ok(configured),
    }
}

#[cfg(unix)]
fn soft_open_file_limit() -> Option<usize> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if ret == 0 && limit.rlim_cur != libc::RLIM_INFINITY {
        Some(limit.rlim_cur as usize)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn soft_open_file_limit() -> Option<usize> { None }

impl<L> AxumListener for LimitedListener<L>
where
    L: AxumListener,
    L::Addr: PeerIp,
{
    type Io = LimitedIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (inner, addr) = self.inner.accept().await;
            let Some(permit) = self.limits.try_admit(addr.peer_ip()) else {
                drop(inner);
                continue;
            };
            return (LimitedIo { inner, _permit: permit }, addr);
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> { self.inner.local_addr() }
}

#[cfg(feature = "acme")]
struct LimitedTcpIncoming {
    listener: tokio::net::TcpListener,
    local_addr: SocketAddr,
    limits: ConnectionLimits,
}

#[cfg(feature = "acme")]
impl LimitedTcpIncoming {
    fn new(listener: tokio::net::TcpListener, limits: ConnectionLimits) -> std::io::Result<Self> {
        let local_addr = listener.local_addr()?;
        Ok(Self { listener, local_addr, limits })
    }

    fn local_addr(&self) -> SocketAddr { self.local_addr }
}

#[cfg(feature = "acme")]
impl Stream for LimitedTcpIncoming {
    type Item = std::io::Result<AddrIo<LimitedIo<tokio::net::TcpStream>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.listener.poll_accept(cx) {
                Poll::Ready(Ok((inner, addr))) => {
                    let Some(permit) = self.limits.try_admit(Some(addr.ip())) else {
                        drop(inner);
                        continue;
                    };
                    let inner = LimitedIo { inner, _permit: permit };
                    return Poll::Ready(Some(Ok(AddrIo { inner, addr })));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(feature = "acme")]
struct AcmeListener<EC: std::fmt::Debug + 'static, EA: std::fmt::Debug + 'static> {
    incoming: tokio_rustls_acme::Incoming<
        AddrIo<LimitedIo<tokio::net::TcpStream>>,
        std::io::Error,
        LimitedTcpIncoming,
        EC,
        EA,
    >,
    local_addr: SocketAddr,
}

#[cfg(feature = "acme")]
impl<EC: std::fmt::Debug + 'static, EA: std::fmt::Debug + 'static> AcmeListener<EC, EA> {
    fn new(
        listener: tokio::net::TcpListener,
        state: tokio_rustls_acme::AcmeState<EC, EA>,
        rustls_config: rustls::ServerConfig,
        limits: ConnectionLimits,
    ) -> std::io::Result<Self> {
        let incoming = LimitedTcpIncoming::new(listener, limits)?;
        let local_addr = incoming.local_addr();
        let incoming = state.incoming_with_server(incoming, rustls_config);
        Ok(Self { incoming, local_addr })
    }
}

#[cfg(feature = "acme")]
impl<EC: std::fmt::Debug + 'static, EA: std::fmt::Debug + 'static> AxumListener
    for AcmeListener<EC, EA>
{
    type Io = tokio_rustls_acme::tokio_rustls::server::TlsStream<
        AddrIo<LimitedIo<tokio::net::TcpStream>>,
    >;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        use futures::StreamExt;

        loop {
            match self.incoming.next().await {
                Some(Ok(tls)) => {
                    let addr = tls.get_ref().0.addr;
                    return (tls, addr);
                }
                Some(Err(err)) => {
                    tracing::error!("ACME TCP accept failed, retrying: {err:?}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                None => std::future::pending().await,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> { Ok(self.local_addr) }
}

impl<I> AsyncRead for LimitedIo<I>
where
    I: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I> AsyncWrite for LimitedIo<I>
where
    I: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "acme")]
impl<I> AsyncRead for AddrIo<I>
where
    I: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "acme")]
impl<I> AsyncWrite for AddrIo<I>
where
    I: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Generate random sentinel tag at startup.
/// The relay and directory share this tag in a best-effort attempt
/// at detecting self loops.
fn generate_sentinel_tag() -> SentinelTag { SentinelTag::new(rand::thread_rng().gen()) }

#[cfg(feature = "access-control")]
impl Connected<IncomingStream<'_, LimitedListener<Listener>>> for middleware::MaybePeerIp {
    fn connect_info(stream: IncomingStream<'_, LimitedListener<Listener>>) -> Self {
        let ip = match stream.remote_addr() {
            tokio_listener::SomeSocketAddr::Tcp(addr) => Some(addr.ip()),
            _ => None,
        };
        Self(ip)
    }
}

#[cfg(all(feature = "access-control", feature = "_manual-tls"))]
impl Connected<IncomingStream<'_, LimitedListener<tokio::net::TcpListener>>>
    for middleware::MaybePeerIp
{
    fn connect_info(stream: IncomingStream<'_, LimitedListener<tokio::net::TcpListener>>) -> Self {
        Self(Some(stream.remote_addr().ip()))
    }
}

#[cfg(all(feature = "access-control", feature = "acme"))]
impl<EC: std::fmt::Debug + 'static, EA: std::fmt::Debug + 'static>
    Connected<IncomingStream<'_, AcmeListener<EC, EA>>> for middleware::MaybePeerIp
{
    fn connect_info(stream: IncomingStream<'_, AcmeListener<EC, EA>>) -> Self {
        Self(Some(stream.remote_addr().ip()))
    }
}

async fn init_directory(
    config: &Config,
    sentinel_tag: SentinelTag,
    metrics: &MetricsService,
) -> anyhow::Result<DirectoryService> {
    let files_db =
        crate::db::FilesDb::init(config.timeout, config.storage_dir.clone(), config.mailbox_ttl)
            .await?;
    files_db.spawn_background_prune().await;
    let db = crate::db::MetricsDb::new(crate::db::DbServiceAdapter::new(files_db), metrics.clone());

    let ohttp_keys_dir = config.storage_dir.join("ohttp-keys");
    let ohttp_config = init_ohttp_config(&ohttp_keys_dir)?;

    let v1 = if config.v1.is_some() {
        #[cfg(feature = "access-control")]
        let blocked = init_blocked_addresses(config).await?;
        #[cfg(not(feature = "access-control"))]
        let blocked = None;
        Some(crate::directory::V1::new(blocked))
    } else {
        None
    };
    Ok(crate::directory::Service::new(db, ohttp_config.into(), sentinel_tag, v1))
}

#[cfg(feature = "access-control")]
async fn init_geoip(
    config: &Config,
) -> anyhow::Result<Option<std::sync::Arc<access_control::IpFilter>>> {
    match &config.access_control {
        Some(ac_config) => {
            let gi = access_control::IpFilter::from_config(ac_config, &config.storage_dir).await?;
            info!("GeoIP access control enabled");
            Ok(Some(std::sync::Arc::new(gi)))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "access-control")]
async fn init_blocked_addresses(
    config: &Config,
) -> anyhow::Result<Option<crate::directory::BlockedAddresses>> {
    let v1_config = match &config.v1 {
        Some(c) => c,
        None => return Ok(None),
    };

    // Neither file nor URL configured
    if v1_config.blocked_addresses_path.is_none() && v1_config.blocked_addresses_url.is_none() {
        return Ok(None);
    }

    // Load initial addresses from file if available
    let blocked = match &v1_config.blocked_addresses_path {
        Some(path) => {
            let text = access_control::load_blocked_address_text(path)?;
            let ba = crate::directory::BlockedAddresses::from_address_lines(&text);
            info!("Loaded blocked addresses from {}", path.display());
            ba
        }
        None => crate::directory::BlockedAddresses::empty(),
    };

    // If URL configured, try initial fetch and spawn background updater
    if let Some(url) = &v1_config.blocked_addresses_url {
        let cache_path = config.storage_dir.join("blocked_addresses_cache.txt");
        let refresh = std::time::Duration::from_secs(
            v1_config.blocked_addresses_refresh_secs.unwrap_or(86400),
        );

        // Try initial fetch; fall back to cache on failure
        match reqwest::get(url).await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.text().await {
                Ok(body) => {
                    if let Err(e) = std::fs::write(&cache_path, &body) {
                        tracing::warn!("Failed to write address cache: {e}");
                    }
                    let count = blocked.update_from_lines(&body).await;
                    info!("Fetched {count} blocked addresses from URL");
                }
                Err(e) => {
                    tracing::warn!("Failed to read address list response: {e}");
                    load_address_cache(&cache_path, &blocked).await;
                }
            },
            Err(e) => {
                tracing::warn!("Failed to fetch address list: {e}");
                load_address_cache(&cache_path, &blocked).await;
            }
        }

        access_control::spawn_address_list_updater(
            url.clone(),
            refresh,
            cache_path,
            blocked.clone(),
        );
    }

    Ok(Some(blocked))
}

#[cfg(feature = "access-control")]
async fn load_address_cache(
    cache_path: &std::path::Path,
    blocked: &crate::directory::BlockedAddresses,
) {
    if cache_path.exists() {
        match access_control::load_blocked_address_text(cache_path) {
            Ok(text) => {
                let count = blocked.update_from_lines(&text).await;
                info!("Loaded {count} blocked addresses from cache");
            }
            Err(e) => tracing::warn!("Failed to load address cache: {e}"),
        }
    }
}

fn init_ohttp_config(
    ohttp_keys_dir: &std::path::Path,
) -> anyhow::Result<crate::key_config::ServerKeyConfig> {
    std::fs::create_dir_all(ohttp_keys_dir)?;
    match crate::key_config::read_server_config(ohttp_keys_dir) {
        Ok(config) => Ok(config),
        Err(_) => {
            let config = crate::key_config::gen_ohttp_server_config()?;
            crate::key_config::persist_new_key_config(config.clone(), ohttp_keys_dir)?;
            Ok(config)
        }
    }
}

fn build_app(services: Services) -> Router {
    let metrics = services.metrics.clone();

    #[cfg(feature = "access-control")]
    let geoip = services.geoip.clone();

    #[allow(unused_mut)]
    let mut router = Router::new()
        .fallback(route_request)
        .layer(
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn_with_state(metrics.clone(), track_metrics)),
        )
        .with_state(services);

    #[cfg(feature = "access-control")]
    {
        router = router
            .layer(axum::middleware::from_fn(middleware::check_geoip))
            .layer(axum::Extension(geoip));
    }

    router
}

async fn route_request(
    State(mut services): State<Services>,
    req: axum::extract::Request,
) -> Response {
    if is_relay_request(&req) {
        match services.relay.call(req).await {
            Ok(res) => res.into_response(),
            Err(e) => (axum::http::StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        }
    } else {
        // The directory service handles all other requests (including 404)
        match services.directory.call(req).await {
            Ok(res) => res.into_response(),
            Err(e) =>
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

/// Determines if a request should be routed to the OHTTP relay service.
///
/// Routing rules:
/// - `(OPTIONS, _)` => CORS preflight handling
/// - `(CONNECT, _)` => OHTTP bootstrap tunneling
/// - `(POST, "/")` => relay to default gateway (needed for backwards-compatibility only)
/// - `(POST, /http(s)://...)` => RFC 9540 opt-in gateway specified in path
/// - `(GET, /http(s)://...)` => OHTTP bootstrap via WebSocket with opt-in gateway
fn is_relay_request(req: &axum::extract::Request) -> bool {
    let method = req.method();
    let path = req.uri().path();

    match (method, path) {
        (&Method::OPTIONS, _) | (&Method::CONNECT, _) | (&Method::POST, "/") => true,
        (&Method::POST, p) | (&Method::GET, p)
            if p.starts_with("/http://") || p.starts_with("/https://") =>
            true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use axum_server::tls_rustls::RustlsConfig;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use payjoin_test_utils::{http_agent, local_cert_key, wait_for_service_ready};
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::metrics::{ACTIVE_CONNECTIONS, CONNECTION_SHEDS, HTTP_REQUESTS};

    async fn start_service(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> (u16, tokio::task::JoinHandle<anyhow::Result<()>>, tempfile::TempDir) {
        let tempdir = tempdir().unwrap();
        let mut config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
            None,
        );
        config.connection.fd_reserve = 0;

        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der.clone())).unwrap();
        let tls_config = RustlsConfig::from_der(vec![cert_der], key_der).await.unwrap();

        let (port, handle) =
            serve_manual_tls(config, Some(tls_config), root_store, None).await.unwrap();
        (port, handle, tempdir)
    }

    async fn read_until(
        stream: &mut tokio::net::TcpStream,
        needle: &[u8],
        timeout: Duration,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        tokio::time::timeout(timeout, async {
            let mut chunk = [0u8; 1024];
            loop {
                let n = stream.read(&mut chunk).await.expect("read should succeed");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(needle.len()).any(|window| window == needle) {
                    break;
                }
            }
        })
        .await
        .expect("expected bytes before timeout");
        buf
    }

    async fn spawn_test_router(
        app: Router,
        header_read_timeout: Duration,
    ) -> (u16, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = ConnectionConfig { fd_reserve: 0, ..Default::default() };
        let limits = ConnectionLimits::from_config(&config, MetricsService::new(None)).unwrap();
        let handle = tokio::spawn(serve_with_listener(
            limit_connections(listener, limits),
            app,
            header_read_timeout,
        ));
        (port, handle)
    }

    #[tokio::test]
    async fn self_loop_request_is_rejected() {
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let (port, _handle, _tempdir) = start_service(cert_der.clone(), key_der).await;

        let client = Arc::new(http_agent(cert_der.clone()).unwrap());
        let base_url = format!("https://localhost:{}", port);
        wait_for_service_ready(&base_url, client.clone()).await.unwrap();

        // Make a request through the relay that targets this same instance's directory.
        // The path format is /{gateway_url} where gateway_url points back to ourselves.
        let ohttp_req_url = format!("{base_url}/{base_url}");

        let response = client
            .post(&ohttp_req_url)
            .header("Content-Type", "message/ohttp-req")
            .body(vec![0u8; 100])
            .send()
            .await
            .expect("request should complete");

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "self-loop request should be rejected with 403 Forbidden"
        );
    }

    #[tokio::test]
    async fn cross_instance_request_is_accepted() {
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let (relay_port, _relay_handle, _relay_tempdir) =
            start_service(cert_der.clone(), key_der.clone()).await;
        let (directory_port, _directory_handle, _directory_tempdir) =
            start_service(cert_der.clone(), key_der).await;

        let client = Arc::new(http_agent(cert_der).unwrap());
        let relay_url = format!("https://localhost:{}", relay_port);
        let directory_url = format!("https://localhost:{}", directory_port);

        wait_for_service_ready(&relay_url, client.clone()).await.unwrap();
        wait_for_service_ready(&directory_url, client.clone()).await.unwrap();

        // Make a request through the relay instance to the directory instance.
        // Since they're different instances with different sentinel tags, this should work.
        let ohttp_req_url = format!("{}/{}", relay_url, directory_url);

        let response = client
            .post(&ohttp_req_url)
            .header("Content-Type", "message/ohttp-req")
            .body(vec![0u8; 100])
            .send()
            .await
            .expect("request should complete");

        // The request may fail for other reasons (invalid OHTTP body), but not due to self-loop.
        assert_ne!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "cross-instance request should not be rejected as forbidden"
        );
    }

    #[tokio::test]
    async fn middleware_records_metrics() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();

        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
            None,
        );

        let sentinel_tag = generate_sentinel_tag();
        let metrics = MetricsService::new(Some(provider.clone()));
        let services = Services {
            directory: init_directory(&config, sentinel_tag, &metrics).await.unwrap(),
            relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
            metrics,
            #[cfg(feature = "access-control")]
            geoip: None,
        };

        let app = build_app(services);

        let request = Request::builder().method("GET").uri("/health").body(Body::empty()).unwrap();
        let response = ServiceExt::<Request<Body>>::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), 200);

        provider.force_flush().expect("flush failed");

        let finished = exporter.get_finished_metrics().expect("metrics");
        let metric_names: Vec<&str> = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .map(|m| m.name())
            .collect();
        assert!(metric_names.contains(&HTTP_REQUESTS), "missing http_request_total");
    }

    #[tokio::test]
    async fn connection_limits_record_active_and_shed_metrics() {
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let metrics = MetricsService::new(Some(provider.clone()));
        let config = ConnectionConfig {
            max_inbound_connections: 1,
            fd_reserve: 0,
            max_connections_per_source: 1,
            ..Default::default()
        };
        let limits = ConnectionLimits::from_config(&config, metrics).unwrap();

        let first = limits.try_admit(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap();
        assert!(limits.try_admit(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))).is_none());

        provider.force_flush().expect("flush failed");
        let finished = exporter.get_finished_metrics().expect("metrics");
        let active = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == ACTIVE_CONNECTIONS)
            .and_then(|m| match m.data() {
                AggregatedMetrics::U64(MetricData::Gauge(gauge)) =>
                    gauge.data_points().next().map(|point| point.value()),
                _ => None,
            })
            .expect("active gauge");
        assert_eq!(active, 1);

        let sheds = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == CONNECTION_SHEDS)
            .and_then(|m| match m.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) =>
                    sum.data_points().next().map(|point| point.value()),
                _ => None,
            })
            .expect("shed counter");
        assert_eq!(sheds, 1);

        drop(first);
    }

    #[test]
    fn source_cap_sheds_without_consuming_global_permit() {
        let config = ConnectionConfig {
            max_inbound_connections: 2,
            fd_reserve: 0,
            max_connections_per_source: 1,
            ..Default::default()
        };
        let limits = ConnectionLimits::from_config(&config, MetricsService::new(None)).unwrap();

        let first = limits.try_admit(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap();
        assert!(limits.try_admit(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))).is_none());
        assert_eq!(limits.active_connections(), 1);

        let second = limits.try_admit(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))).unwrap();
        assert_eq!(limits.active_connections(), 2);

        drop(first);
        drop(second);
        assert_eq!(limits.active_connections(), 0);
    }

    #[test]
    fn source_key_normalizes_ipv4_mapped_and_aggregates_ipv6() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mapped = IpAddr::V6("::ffff:203.0.113.7".parse().unwrap());
        assert_eq!(SourceKey::new(ipv4, 64), SourceKey::new(mapped, 64));

        let a = IpAddr::V6("2001:db8:abcd:12::1".parse().unwrap());
        let b = IpAddr::V6("2001:db8:abcd:12::dead:beef".parse().unwrap());
        assert_eq!(
            SourceKey::new(a, 64),
            SourceKey(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xabcd, 0x0012, 0, 0, 0, 0)))
        );
        assert_eq!(SourceKey::new(a, 64), SourceKey::new(b, 64));
    }

    #[tokio::test]
    async fn header_read_timeout_does_not_cancel_in_flight_long_poll() {
        let app = Router::new().route(
            "/long-poll",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(250)).await;
                "done"
            }),
        );
        let (port, _handle) = spawn_test_router(app, Duration::from_millis(100)).await;
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(b"GET /long-poll HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

        let response = read_until(&mut stream, b"done", Duration::from_secs(1)).await;
        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("200 OK"), "long poll response was not successful: {response}");
        assert!(response.contains("done"), "long poll payload missing: {response}");
    }

    #[tokio::test]
    async fn header_read_timeout_closes_idle_keep_alive_connection() {
        let app = Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        let (port, _handle) = spawn_test_router(app, Duration::from_millis(100)).await;
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let response = read_until(&mut stream, b"ok", Duration::from_secs(1)).await;
        assert!(String::from_utf8_lossy(&response).contains("200 OK"));

        tokio::time::sleep(Duration::from_millis(250)).await;
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("idle connection should close")
            .expect("read should succeed");
        assert_eq!(n, 0, "idle keep-alive connection should be closed");
    }

    #[tokio::test]
    async fn middleware_sanitizes_short_id_in_metrics() {
        use axum::body::Body;
        use axum::http::Request;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
        use tower::ServiceExt;

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();

        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
            None,
        );

        let sentinel_tag = generate_sentinel_tag();
        let metrics = MetricsService::new(Some(provider.clone()));
        let services = Services {
            directory: init_directory(&config, sentinel_tag, &metrics).await.unwrap(),
            relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
            metrics,
            #[cfg(feature = "access-control")]
            geoip: None,
        };

        let app = build_app(services);

        let short_id = payjoin::directory::ShortId([0u8; 8]).to_string();
        let uri = format!("/{short_id}");
        let request = Request::builder().method("GET").uri(&uri).body(Body::empty()).unwrap();
        let _response = ServiceExt::<Request<Body>>::oneshot(app, request).await.unwrap();

        provider.force_flush().expect("flush failed");

        let finished = exporter.get_finished_metrics().expect("metrics");
        println!("finished: {:?}", finished);
        let endpoint_attrs: Vec<String> = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .filter(|m| m.name() == HTTP_REQUESTS)
            .flat_map(|m| match m.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .flat_map(|dp| dp.attributes())
                    .filter_map(|kv| {
                        if kv.key.as_str() == "endpoint" {
                            Some(kv.value.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect();

        println!("endpoint_attrs: {:?}", endpoint_attrs);

        assert!(
            endpoint_attrs.iter().all(|ep| ep == "/{mailbox}"),
            "short ID must be sanitized in metrics, got: {endpoint_attrs:?}"
        );
        assert!(
            endpoint_attrs.iter().all(|ep| !ep.contains(&short_id)),
            "actual short ID value must not appear in metrics"
        );
    }
}
