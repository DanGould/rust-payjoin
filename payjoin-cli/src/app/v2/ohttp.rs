//! OHTTP relay and payjoin directory selection / key bootstrapping for the payjoin-cli.
//!
//! Wraps [`payjoin::request_handler::RequestHandler`], which chooses relays and
//! directories, and supplies the HTTP client, the configured OHTTP keys and the
//! optional test certificate that the handler leaves to its caller. Every
//! session shares one copy, and since the handler holds no failure state,
//! sessions can post concurrently without affecting each other's failover.
//!
//! Once a directory is chosen for a session it must not change: the
//! directory is embedded in the BIP21 URI at session creation and recovered
//! from the session event log on resume.
use anyhow::{anyhow, Result};
use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler::RequestHandler;
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct MailroomManager {
    handler: RequestHandler,
    /// Configured OHTTP keys and the directory they belong to.
    ohttp_keys: Option<(Url, payjoin::OhttpKeys)>,
    #[cfg(feature = "_manual-tls")]
    cert_der: Option<Vec<u8>>,
}

impl MailroomManager {
    pub fn new(config: Config) -> Result<Self> {
        let v2 = config.v2()?;
        let handler = RequestHandler::new(v2.ohttp_relays.clone(), v2.pj_directories.clone());
        // Configured OHTTP keys belong to one directory, taken to be the
        // first configured one, so sessions never pair them with another.
        let ohttp_keys = match v2.ohttp_keys.clone() {
            Some(keys) => {
                let directory = v2
                    .pj_directories
                    .first()
                    .ok_or_else(|| anyhow!("ohttp_keys requires a pj_directories entry"))?;
                Some((directory.clone(), keys))
            }
            None => None,
        };
        Ok(Self {
            handler,
            ohttp_keys,
            #[cfg(feature = "_manual-tls")]
            cert_der: config.root_certificate.as_ref().map(std::fs::read).transpose()?,
        })
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<(Url, payjoin::OhttpKeys)> {
        if let Some(configured) = &self.ohttp_keys {
            return Ok(configured.clone());
        }
        #[cfg(feature = "_manual-tls")]
        let cert_der = self.cert_der.clone();
        #[cfg(not(feature = "_manual-tls"))]
        let cert_der: Option<Vec<u8>> = None;
        // OsRng rather than thread_rng: ThreadRng is !Send and must not be
        // held across the fetch's await points.
        self.handler
            .fetch_ohttp_keys_with(&mut OsRng, move |relay, directory| {
                let cert_der = cert_der.clone();
                async move { fetch_via_relay(cert_der.as_deref(), &relay, &directory).await }
            })
            .await
            .map_err(Into::into)
    }

    pub fn relay_order(&self, directory: &Url) -> Vec<Url> {
        self.handler.relay_order(directory, &mut OsRng)
    }
}

async fn fetch_via_relay(
    cert_der: Option<&[u8]>,
    relay: &Url,
    directory: &Url,
) -> Result<payjoin::OhttpKeys, payjoin::io::Error> {
    #[cfg(feature = "_manual-tls")]
    if let Some(cert_der) = cert_der {
        return payjoin::io::fetch_ohttp_keys_with_cert(
            relay.as_str(),
            directory.as_str(),
            cert_der,
        )
        .await;
    }
    #[cfg(not(feature = "_manual-tls"))]
    let _ = cert_der;
    payjoin::io::fetch_ohttp_keys(relay.as_str(), directory.as_str()).await
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
