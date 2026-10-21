//! OHTTP relay and payjoin directory selection / key bootstrapping for the payjoin-cli.
//!
//! Thin wrapper around [`payjoin::request_handler::RequestHandler`], shared by
//! every session behind an `Arc`. The handler holds no failure state across
//! calls, so sessions can post concurrently without affecting each other's
//! failover.
//!
//! Once a directory is chosen for a session it must not change: the
//! directory is embedded in the BIP21 URI at session creation and recovered
//! from the session event log on resume.
use std::sync::Arc;

use anyhow::{anyhow, Result};
use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler::RequestHandler;
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct MailroomManager(Arc<RequestHandler>);

impl MailroomManager {
    pub fn new(config: Config) -> Result<Self> {
        let v2 = config.v2()?;
        let mailroom = RequestHandler::new(v2.ohttp_relays.clone(), v2.pj_directories.clone());
        // Configured OHTTP keys belong to one directory, taken to be the
        // first configured one, so sessions never pair them with another.
        if let Some(ohttp_keys) = v2.ohttp_keys.clone() {
            let directory = v2
                .pj_directories
                .first()
                .ok_or_else(|| anyhow!("ohttp_keys requires a pj_directories entry"))?;
            mailroom.set_ohttp_keys(directory.clone(), ohttp_keys);
        }
        #[cfg(feature = "_manual-tls")]
        if let Some(cert_path) = config.root_certificate.as_ref() {
            mailroom.set_cert_der(std::fs::read(cert_path)?);
        }
        Ok(Self(Arc::new(mailroom)))
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<(Url, payjoin::OhttpKeys)> {
        // OsRng rather than thread_rng: ThreadRng is !Send and must not be
        // held across the fetch's await points.
        self.0.fetch_ohttp_keys(&mut OsRng).await.map_err(Into::into)
    }

    pub fn relay_order(&self, directory: &Url) -> Vec<Url> {
        self.0.relay_order(directory, &mut OsRng)
    }
}

#[cfg(test)]
mod tests {
    use payjoin::OhttpKeys;

    use super::*;
    use crate::app::config::{BitcoindConfig, V2Config, VersionConfig};

    fn config(pj_directories: Vec<Url>) -> Config {
        let ohttp_keys =
            OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).expect("valid keys");
        Config {
            db_path: "unused".into(),
            max_fee_rate: None,
            bitcoind: BitcoindConfig {
                rpchost: Url::parse("http://localhost:18443").unwrap(),
                cookie: None,
                rpcuser: String::new(),
                rpcpassword: String::new(),
            },
            version: Some(VersionConfig::V2(V2Config {
                ohttp_keys: Some(ohttp_keys),
                ohttp_relays: Vec::new(),
                pj_directories,
            })),
            #[cfg(feature = "_manual-tls")]
            root_certificate: None,
            #[cfg(feature = "_manual-tls")]
            certificate_key: None,
            expire_in_secs: None,
        }
    }

    #[tokio::test]
    async fn configured_ohttp_keys_belong_to_first_directory() {
        let directories: Vec<Url> = ["https://first.example", "https://second.example"]
            .iter()
            .map(|s| Url::parse(s).unwrap())
            .collect();
        let manager = MailroomManager::new(config(directories.clone())).unwrap();
        for _ in 0..20 {
            let (directory, _) = manager.fetch_ohttp_keys().await.unwrap();
            assert_eq!(directory, directories[0]);
        }
    }

    #[test]
    fn configured_ohttp_keys_without_directory_is_an_error() {
        assert!(MailroomManager::new(config(Vec::new())).is_err());
    }
}
