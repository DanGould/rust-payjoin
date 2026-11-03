//! A mailroom on localhost: an OHTTP relay and a directory, as two
//! payjoin-mailroom instances, the same split a deployment has.
//!
//! Both run as tasks of the calling process, bound to ephemeral localhost
//! ports, and stop when the [`Mailroom`] is dropped. Requests built by the
//! payjoin library go to the relay over HTTP and on to the directory over TLS
//! with a self-signed certificate, so the OHTTP encapsulation, the gateway,
//! the admission hook and the storage all run their production code paths.
//!
//! The process's HTTP proxy settings are ignored, since every request stays
//! on localhost. A mailroom can also answer for a public host name (see
//! [`Mailroom::answer_as`]), so URIs read like a deployment's while every
//! request still goes to the local directory.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use payjoin::OhttpKeys;
use payjoin_mailroom::config::Config;
use payjoin_test_utils::{local_cert_key, wait_for_service_ready};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use tokio::task::AbortHandle;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// How long the directory holds a long-poll open. Contact log reads don't
/// wait, so this only bounds v2 mailbox polls.
const DIRECTORY_TIMEOUT: Duration = Duration::from_secs(2);

/// A running relay and directory.
pub struct Mailroom {
    relay_url: String,
    /// The directory's URL as URIs carry it.
    directory_url: String,
    /// Where the directory actually listens.
    local_directory_url: String,
    /// Requests passed to the relay so far.
    requests: AtomicU64,
    client: reqwest::Client,
    ohttp_keys: OhttpKeys,
    servers: Vec<AbortHandle>,
    _storage: Vec<tempfile::TempDir>,
}

impl Mailroom {
    /// Start a relay and a directory. With `contact_logs` the directory gives
    /// its append-only logs mailbox semantics.
    pub async fn start(contact_logs: bool) -> Result<Self, Error> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der.clone()))?;

        let directory_dir = tempfile::tempdir()?;
        let mut config = Config::new(
            "127.0.0.1:0".parse()?,
            directory_dir.path().to_path_buf(),
            DIRECTORY_TIMEOUT,
            None,
        );
        config.contact_logs = contact_logs;
        let tls = RustlsConfig::from_der(vec![cert_der.clone()], key_der).await?;
        let (directory_port, directory) =
            payjoin_mailroom::serve_manual_tls(config, Some(tls), root_store.clone(), None)
                .await
                .map_err(|e| e.to_string())?;

        let relay_dir = tempfile::tempdir()?;
        let config = Config::new(
            "127.0.0.1:0".parse()?,
            relay_dir.path().to_path_buf(),
            DIRECTORY_TIMEOUT,
            None,
        );
        let (relay_port, relay) =
            payjoin_mailroom::serve_manual_tls(config, None, root_store, None)
                .await
                .map_err(|e| e.to_string())?;

        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .use_rustls_tls()
            .add_root_certificate(reqwest::tls::Certificate::from_der(&cert_der)?)
            .build()?;
        let relay_url = format!("http://localhost:{relay_port}");
        let directory_url = format!("https://localhost:{directory_port}");
        let shared = Arc::new(client.clone());
        wait_for_service_ready(&relay_url, shared.clone()).await?;
        wait_for_service_ready(&directory_url, shared).await?;

        let keys = client
            .get(format!("{directory_url}/.well-known/ohttp-gateway"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let ohttp_keys = OhttpKeys::decode(&keys)?;

        let servers = vec![directory.abort_handle(), relay.abort_handle()];
        Ok(Self {
            relay_url,
            local_directory_url: directory_url.clone(),
            directory_url,
            requests: AtomicU64::new(0),
            client,
            ohttp_keys,
            servers,
            _storage: vec![directory_dir, relay_dir],
        })
    }

    pub fn relay_url(&self) -> &str { &self.relay_url }

    /// The directory's URL for URIs: its local one, or the public origin
    /// given to [`Mailroom::answer_as`].
    pub fn directory_url(&self) -> &str { &self.directory_url }

    /// Put `origin` (such as `https://payjo.in`) in every URI built from now
    /// on in place of the local directory's URL. Requests addressed to it are
    /// sent to the local directory by [`Mailroom::send`], so nothing leaves
    /// the machine.
    pub fn answer_as(&mut self, origin: &str) {
        self.directory_url = origin.trim_end_matches('/').to_string();
    }

    /// How many requests [`Mailroom::send`] has passed to the relay. Every
    /// one of them went to the local relay and on to the local directory.
    pub fn requests(&self) -> u64 { self.requests.load(Ordering::SeqCst) }

    /// The directory's OHTTP gateway keys.
    pub fn ohttp_keys(&self) -> &OhttpKeys { &self.ohttp_keys }

    /// Send a request built by the payjoin library and return the response
    /// body for its `process_response`. A status other than 200 from the
    /// relay is an error.
    ///
    /// The relay forwards to the directory named in the request's path. A
    /// request naming the public origin is pointed at the local directory,
    /// and one naming any other directory is refused before it is sent.
    pub async fn send(&self, request: &payjoin::Request) -> Result<Vec<u8>, Error> {
        let url = local_route(
            &request.url,
            &self.relay_url,
            &self.directory_url,
            &self.local_directory_url,
        )?;
        self.requests.fetch_add(1, Ordering::SeqCst);
        let response = self
            .client
            .post(url)
            .header("Content-Type", request.content_type)
            .body(request.body.clone())
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(Box::new(RelayStatus(status.as_u16())));
        }
        Ok(body)
    }
}

/// The relay URL for a request to `url`, a relay URL whose path names the
/// directory (RFC 9540), with `public` replaced by `local`. Any other relay
/// or directory is an error. Origins compare without case, since a sender
/// may copy the directory from an upper-case URI.
fn local_route(url: &str, relay: &str, public: &str, local: &str) -> Result<String, Error> {
    let gateway = url
        .strip_prefix(relay)
        .and_then(|rest| rest.strip_prefix('/'))
        .ok_or_else(|| format!("{url} is not for the local relay {relay}"))?;
    let gateway = gateway.trim_end_matches('/');
    if gateway.eq_ignore_ascii_case(local) || gateway.eq_ignore_ascii_case(public) {
        Ok(format!("{relay}/{local}/"))
    } else {
        Err(format!("{gateway} is not this mailroom's directory").into())
    }
}

impl Drop for Mailroom {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}

/// A non-success status from the relay. The directory answers refused
/// requests outside the OHTTP envelope, so the relay sees and forwards the
/// status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStatus(pub u16);

impl std::fmt::Display for RelayStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay returned HTTP {}", self.0)
    }
}

impl std::error::Error for RelayStatus {}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "http://localhost:4100";
    const LOCAL: &str = "https://localhost:4200";

    #[test]
    fn requests_for_the_public_origin_go_to_the_local_directory() {
        let route = |url| local_route(url, RELAY, "https://payjo.in", LOCAL);
        let local = "http://localhost:4100/https://localhost:4200/";
        assert_eq!(route("http://localhost:4100/https://payjo.in/").unwrap(), local);
        assert_eq!(route(local).unwrap(), local);
        assert_eq!(route("http://localhost:4100/HTTPS://PAYJO.IN/").unwrap(), local);
        assert!(route("http://localhost:4100/https://example.com/").is_err());
        assert!(route("http://localhost:4100/https://payjo.in.example.com/").is_err());
        assert!(route("https://payjo.in/https://payjo.in/").is_err());
    }
}
