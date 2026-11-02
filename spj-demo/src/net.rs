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
//! on localhost.

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
    directory_url: String,
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
            directory_url,
            client,
            ohttp_keys,
            servers,
            _storage: vec![directory_dir, relay_dir],
        })
    }

    pub fn relay_url(&self) -> &str { &self.relay_url }

    pub fn directory_url(&self) -> &str { &self.directory_url }

    /// The directory's OHTTP gateway keys.
    pub fn ohttp_keys(&self) -> &OhttpKeys { &self.ohttp_keys }

    /// Send a request built by the payjoin library and return the response
    /// body for its `process_response`. A status other than 200 from the
    /// relay is an error.
    pub async fn send(&self, request: &payjoin::Request) -> Result<Vec<u8>, Error> {
        let response = self
            .client
            .post(&request.url)
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
