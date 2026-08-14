use std::path::{Path, PathBuf};
use std::time::Duration;

use config::{ConfigError, File};
use serde::Deserialize;
use tokio_listener::ListenerAddress;

/// Default maximum frames per queue mailbox.
const DEFAULT_QUEUE_FRAME_CAP: usize = 64;

/// Default proof-of-work target for board submissions, in leading zero
/// bits: about a million hashes per submission, cheap for a wallet
/// posting an announcement and costly for a flood.
const DEFAULT_BOARD_POW_BITS: u8 = 20;

/// Default maximum live board entries: 4096 entries of 512 bytes bound
/// the board at 2 MiB.
const DEFAULT_BOARD_CAP: usize = 4096;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listener: ListenerAddress,
    pub storage_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub timeout: Duration,
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub mailbox_ttl: Duration,
    /// Serve queue mailbox endpoints (`/q/{id}`) through the OHTTP
    /// gateway. Off by default. Enabling only adds routes; existing
    /// endpoint behavior is unchanged.
    pub queue_mailboxes: bool,
    /// Maximum frames one queue mailbox holds. Appends beyond the cap
    /// are rejected until the queue expires.
    pub queue_frame_cap: usize,
    /// Require queue appends to carry a token minted by the mailbox
    /// owner's key. Off by default: without it, any party that knows a
    /// queue id may append to it. See
    /// [`TokenAdmission`](crate::admission::TokenAdmission) for the
    /// token scheme and its key-reuse caveat.
    pub queue_requires_token: bool,
    /// Serve bulletin board endpoints (`/board`) through the OHTTP
    /// gateway. Off by default. Enabling only adds routes; existing
    /// endpoint behavior is unchanged.
    pub board: bool,
    /// Proof-of-work target for board submissions, in leading zero
    /// bits.
    pub board_pow_bits: u8,
    /// Maximum live board entries. Submissions to a full board are
    /// rejected until entries expire.
    pub board_cap: usize,
    /// Require board submissions to carry a zero-knowledge credential
    /// in addition to proof of work. Absent by default: without it,
    /// work alone admits a submission. See
    /// [`ZkAdmission`](crate::admission::ZkAdmission).
    pub board_zk: Option<ZkAdmissionConfig>,
    pub v1: Option<V1Config>,
    #[cfg(feature = "telemetry")]
    pub telemetry: Option<TelemetryConfig>,
    #[cfg(feature = "acme")]
    pub acme: Option<AcmeConfig>,
    #[cfg(feature = "access-control")]
    pub access_control: Option<AccessControlConfig>,
}

/// Zero-knowledge credential admission for the bulletin board.
///
/// Verification runs in a sidecar process the operator starts
/// separately, holding the key set named here. This section says how
/// to reach it and under which context label; the sidecar must be
/// started with the same label, since it fixes its labels at startup.
#[derive(Debug, Clone, Deserialize)]
pub struct ZkAdmissionConfig {
    /// Path to the `autct` executable that talks to the sidecar.
    pub autct_exe: PathBuf,
    /// Path to the key set the sidecar serves, as the sidecar was
    /// started with it.
    pub keyset_path: PathBuf,
    /// The component of the context label that names this deployment.
    pub deployment_label: String,
    /// The component of the context label that names the current
    /// epoch. Changing it retires every credential spent under the
    /// old one, and the sidecar must already serve the new label.
    pub epoch: String,
    /// Host the sidecar listens on.
    #[serde(default = "default_zk_host")]
    pub host: String,
    /// Port the sidecar listens on.
    pub port: u16,
}

fn default_zk_host() -> String { "127.0.0.1".to_string() }

/// Characters the sidecar's key set syntax reserves as separators, so
/// a label containing one would be read as several.
const LABEL_SEPARATORS: [char; 2] = [',', ':'];

impl ZkAdmissionConfig {
    /// The context label credentials are scoped by.
    ///
    /// The context label determines the key-image generator J, so it
    /// scopes both one-show state and linkage. It must contain a
    /// deployment-unique component in addition to the epoch: two
    /// deployments sharing a label and key set produce identical key
    /// images for the same key, which would let their operators link
    /// one wallet's posts across deployments by comparing tags.
    pub fn context_label(&self) -> String { format!("{}.{}", self.deployment_label, self.epoch) }

    /// The context label and key set together, as the sidecar's
    /// client takes them.
    pub fn keyset_spec(&self) -> String {
        format!("{}:{}", self.context_label(), self.keyset_path.display())
    }
}

/// V1 protocol configuration.
///
/// Present in [`Config`] to enable the V1 fallback path.
/// Contains optional address-screening settings that only apply to V1.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct V1Config {
    #[cfg(feature = "access-control")]
    pub blocked_addresses_path: Option<PathBuf>,
    #[cfg(feature = "access-control")]
    pub blocked_addresses_url: Option<String>,
    #[cfg(feature = "access-control")]
    pub blocked_addresses_refresh_secs: Option<u64>,
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    pub endpoint: String,
    pub auth_token: String,
    pub operator_domain: String,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contact: Vec<String>,
    #[serde(default)]
    pub directory_url: Option<String>,
}

#[cfg(feature = "access-control")]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AccessControlConfig {
    pub geo_db_path: Option<PathBuf>,
    pub blocked_regions: Vec<String>,
    pub blocked_ips: Vec<String>,
}

#[cfg(feature = "acme")]
impl AcmeConfig {
    pub fn into_rustls_config(
        self,
        storage_dir: &Path,
    ) -> tokio_rustls_acme::AcmeConfig<std::io::Error, std::io::Error> {
        let cache_dir = storage_dir.join("acme");
        let config = tokio_rustls_acme::AcmeConfig::new(self.domains)
            .contact(self.contact)
            .cache(tokio_rustls_acme::caches::DirCache::new(cache_dir));
        match self.directory_url {
            Some(url) => config.directory(url),
            None => config.directory_lets_encrypt(true),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listener: "[::]:8080".parse().expect("valid default listener address"),
            storage_dir: PathBuf::from("./data"),
            timeout: Duration::from_secs(30),
            mailbox_ttl: Duration::from_secs(60 * 60 * 24 * 7), // 1 week
            queue_mailboxes: false,
            queue_frame_cap: DEFAULT_QUEUE_FRAME_CAP,
            queue_requires_token: false,
            board: false,
            board_pow_bits: DEFAULT_BOARD_POW_BITS,
            board_cap: DEFAULT_BOARD_CAP,
            board_zk: None,
            v1: None,
            #[cfg(feature = "telemetry")]
            telemetry: None,
            #[cfg(feature = "acme")]
            acme: None,
            #[cfg(feature = "access-control")]
            access_control: None,
        }
    }
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

impl Config {
    pub fn new(
        listener: ListenerAddress,
        storage_dir: PathBuf,
        timeout: Duration,
        v1: Option<V1Config>,
    ) -> Self {
        Self {
            listener,
            storage_dir,
            timeout,
            mailbox_ttl: Duration::from_secs(60 * 60 * 24 * 7), // 1 week
            queue_mailboxes: false,
            queue_frame_cap: DEFAULT_QUEUE_FRAME_CAP,
            queue_requires_token: false,
            board: false,
            board_pow_bits: DEFAULT_BOARD_POW_BITS,
            board_cap: DEFAULT_BOARD_CAP,
            board_zk: None,
            v1,
            #[cfg(feature = "telemetry")]
            telemetry: None,
            #[cfg(feature = "acme")]
            acme: None,
            #[cfg(feature = "access-control")]
            access_control: None,
        }
    }

    /// Check the invariants no single field can carry.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let Some(zk) = &self.board_zk else {
            return Ok(());
        };
        if !self.board {
            return Err(ConfigError::Message(
                "board_zk is set but board is off, so nothing would use it".to_string(),
            ));
        }
        if self.board_pow_bits == 0 {
            // Work is what prices credential verification, which any
            // keypair at all can force. A zero target is a gate in
            // name only.
            return Err(ConfigError::Message(
                "board_zk requires a board_pow_bits target above zero".to_string(),
            ));
        }
        for (name, part) in [("deployment_label", &zk.deployment_label), ("epoch", &zk.epoch)] {
            if part.is_empty() || part.contains(LABEL_SEPARATORS) {
                return Err(ConfigError::Message(format!(
                    "board_zk.{name} must be non-empty and free of {LABEL_SEPARATORS:?}"
                )));
            }
        }
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        config::Config::builder()
            // Add from optional config file
            .add_source(File::from(path).required(false))
            // Add from the environment (with a prefix of PJ)
            // Nested values are separated with a double underscore,
            // e.g. `PJ_ACME__DOMAINS=payjo.in`
            .add_source(
                config::Environment::with_prefix("PJ")
                    .separator("__")
                    .prefix_separator("_")
                    .list_separator(",")
                    .with_list_parse_key("acme.domains")
                    .with_list_parse_key("acme.contact")
                    .with_list_parse_key("access_control.blocked_regions")
                    .with_list_parse_key("access_control.blocked_ips")
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zk_config() -> ZkAdmissionConfig {
        ZkAdmissionConfig {
            autct_exe: PathBuf::from("/usr/local/bin/autct"),
            keyset_path: PathBuf::from("/var/lib/payjoin-mailroom/outputs.aks"),
            deployment_label: "mailroom.example.com".to_string(),
            epoch: "2026-w33".to_string(),
            host: default_zk_host(),
            port: 23333,
        }
    }

    fn credentialed() -> Config {
        Config { board: true, board_zk: Some(zk_config()), ..Config::default() }
    }

    #[test]
    fn test_context_label_carries_deployment_and_epoch() {
        let zk = zk_config();
        assert_eq!(zk.context_label(), "mailroom.example.com.2026-w33");
        assert_eq!(
            zk.keyset_spec(),
            "mailroom.example.com.2026-w33:/var/lib/payjoin-mailroom/outputs.aks"
        );
    }

    #[test]
    fn test_validate_accepts_a_configured_board() {
        assert!(Config::default().validate().is_ok(), "no board, nothing to check");
        assert!(credentialed().validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_credentials_the_board_would_not_use() {
        let config = Config { board: false, ..credentialed() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_unpriced_credentials() {
        let config = Config { board_pow_bits: 0, ..credentialed() };
        assert!(config.validate().is_err(), "work is what prices verification");
    }

    #[test]
    fn test_validate_rejects_labels_the_sidecar_would_resplit() {
        for label in ["", "epoch:with-colon", "epoch,with-comma"] {
            let zk = ZkAdmissionConfig { epoch: label.to_string(), ..zk_config() };
            let config = Config { board_zk: Some(zk), ..credentialed() };
            assert!(config.validate().is_err(), "{label:?} must not be accepted as an epoch");
        }
    }
}
