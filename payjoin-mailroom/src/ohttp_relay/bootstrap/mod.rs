use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tokio::sync::Semaphore;
use tracing::instrument;

use crate::ohttp_relay::error::Error;
use crate::ohttp_relay::GatewayUri;

#[cfg(feature = "connect-bootstrap")]
pub mod connect;

#[cfg(feature = "ws-bootstrap")]
pub mod ws;

/// Maximum number of concurrent OHTTP bootstrap tunnels. Each tunnel pins two
/// file descriptors (the inbound upgraded socket and the outbound TCP stream),
/// so an unbounded number of them can exhaust the process descriptor limit.
pub(crate) const MAX_CONCURRENT_TUNNELS: usize = 1024;

/// Maximum lifetime of a single bootstrap tunnel. OHTTP key bootstrap is a
/// short request/response exchange, so a tunnel still open after this is
/// assumed stalled and is torn down to release its descriptors.
pub(crate) const TUNNEL_TIMEOUT: Duration = Duration::from_secs(60);

/// Resource bounds shared by the CONNECT and WebSocket bootstrap tunnels.
///
/// Bootstrap tunnels pin one inbound upgraded socket plus one outbound gateway
/// socket. The semaphore caps tunnel concurrency and the timeout caps tunnel
/// lifetime; separate listener-level limits cap inbound HTTP connections.
#[derive(Debug, Clone)]
pub(crate) struct TunnelLimits {
    /// Caps the number of concurrent tunnels.
    pub(crate) semaphore: Arc<Semaphore>,
    /// Caps the lifetime of each tunnel.
    pub(crate) timeout: Duration,
}

impl Default for TunnelLimits {
    fn default() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TUNNELS)),
            timeout: TUNNEL_TIMEOUT,
        }
    }
}

#[instrument(skip(limits))]
pub(crate) async fn handle_ohttp_keys<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    limits: &TunnelLimits,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + Debug + 'static,
{
    #[cfg(feature = "connect-bootstrap")]
    if connect::is_connect_request(&req) {
        return connect::try_upgrade(req, gateway_origin, limits).await;
    }

    #[cfg(feature = "ws-bootstrap")]
    if ws::is_websocket_request(&req) {
        return ws::try_upgrade(req, gateway_origin, limits).await;
    }

    Err(Error::BadRequest("Not a supported proxy upgrade request".to_string()))
}
