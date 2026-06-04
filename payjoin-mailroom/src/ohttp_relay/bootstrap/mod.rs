use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};
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
/// Bootstrap tunnels are the only relay path that holds descriptors open for an
/// unbounded time without these limits: a stalled or malicious client can pin
/// two descriptors per tunnel indefinitely. The semaphore caps concurrency and
/// the timeout caps lifetime, so total descriptor use stays bounded.
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

/// Proxy bytes between the two tunnel endpoints, tearing the tunnel down if it
/// stays open longer than `timeout`. Returns an error of kind
/// `std::io::ErrorKind::TimedOut` on teardown so callers can distinguish an
/// intentionally closed tunnel from a genuine I/O failure.
pub(crate) async fn copy_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    timeout: Duration,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, tokio::io::copy_bidirectional(a, b)).await {
        Ok(result) => result.map(|_| ()),
        Err(_elapsed) => Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::copy_bidirectional_with_timeout;

    #[tokio::test(start_paused = true)]
    async fn tunnel_times_out_when_idle() {
        // Two duplex pipes stand in for the tunnel endpoints. Their peers are
        // held open and never written to, so copy_bidirectional can never make
        // progress and the timeout must tear the tunnel down.
        let (mut a, _a_peer) = tokio::io::duplex(64);
        let (mut b, _b_peer) = tokio::io::duplex(64);

        let err = copy_bidirectional_with_timeout(&mut a, &mut b, Duration::from_secs(30))
            .await
            .expect_err("idle tunnel should time out");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
