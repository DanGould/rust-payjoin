//! Contact logs: one receiver key serving many senders.
//!
//! A standard BIP 77 session uses a fresh receiver key and mailbox for each
//! payment. A contact log lets a receiver hand one long-lived string to a
//! counterparty and be paid through it many times. Each sender encrypts its
//! message A to the same receiver key and appends it as one frame to an
//! append-only log on the directory, and the receiver reads the log frame by
//! frame. From there each payment is an ordinary v2 session: the receiver
//! replies to the sender's own reply mailbox, as in BIP 77.
//!
//! The directory gives the log mailbox semantics. Only its owner creates and
//! reads it, and appends to a log its owner hasn't created are refused. The
//! owner proves itself with a token derived from the receiver key, sent as an
//! `authorization: Owner <hex>` header inside the OHTTP envelope, and the log's
//! id is the first 8 bytes of the token's SHA-256. A sender learns the id from
//! the contact string and never sees the token.

use bitcoin::hashes::{sha256, Hash, HashEngine};

use crate::core::Url;
use crate::directory::ShortId;
use crate::{HpkeKeyPair, HpkePublicKey, OhttpKeys};

/// The authorization scheme that carries an owner token.
pub const OWNER_SCHEME: &str = "Owner";

/// Domain separation for deriving an owner token from a receiver key.
const OWNER_TOKEN_TAG: &[u8] = b"payjoin/contact-log/owner-token";

/// The token that proves ownership of the contact log for `receiver_key`.
pub fn owner_token(receiver_key: &HpkeKeyPair) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(OWNER_TOKEN_TAG);
    engine.input(&receiver_key.secret_key().to_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// The id of the contact log for `receiver_key`.
pub fn log_id(receiver_key: &HpkeKeyPair) -> ShortId {
    log_id_for_token(&owner_token(receiver_key))
}

fn log_id_for_token(owner_token: &[u8; 32]) -> ShortId {
    let hash = sha256::Hash::hash(owner_token).to_byte_array();
    ShortId(hash[..8].try_into().expect("a sha256 hash is longer than 8 bytes"))
}

/// The `authorization` header value that proves ownership of the contact log
/// for `receiver_key`.
pub(crate) fn owner_authorization(receiver_key: &HpkeKeyPair) -> String {
    use bitcoin::hex::DisplayHex;
    format!("{OWNER_SCHEME} {}", owner_token(receiver_key).as_hex())
}

/// The `OH1…-RK1…` fragment a contact string carries: the directory's OHTTP
/// keys and the receiver key, encoded as in a BIP 77 URI. A contact string has
/// no expiration; the sender chooses how long it waits.
pub fn fragment(ohttp_keys: &OhttpKeys, receiver_pubkey: &HpkePublicKey) -> String {
    crate::uri::v2::contact_fragment(ohttp_keys, receiver_pubkey)
}

/// Parse the fragment [`fragment`] produces.
pub fn parse_fragment(fragment: &str) -> Result<(OhttpKeys, HpkePublicKey), ParseFragmentError> {
    crate::uri::v2::parse_contact_fragment(fragment)
}

/// A contact string fragment that doesn't hold valid OHTTP keys and a
/// receiver key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFragmentError(pub(crate) String);

impl std::fmt::Display for ParseFragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid contact fragment: {}", self.0)
    }
}

impl std::error::Error for ParseFragmentError {}

/// `POST` target for appending a frame to log `id`.
pub(crate) fn append_target(directory: &Url, id: &ShortId) -> Url {
    let mut url = directory.clone();
    {
        let mut segments = url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
        segments.push("log");
        segments.push(&id.to_string());
    }
    url
}

/// `GET` target that reads frame `index` of log `id` without waiting for it.
pub(crate) fn read_target(directory: &Url, id: &ShortId, index: usize) -> Url {
    let mut url = append_target(directory, id);
    url.path_segments_mut()
        .expect("Payjoin Directory URL cannot be a base")
        .push(&index.to_string());
    url.query_pairs_mut().append_pair("wait", "0");
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_id_commits_to_owner_token() {
        let key = HpkeKeyPair::gen_keypair();
        let token = owner_token(&key);
        assert_eq!(log_id(&key), log_id_for_token(&token));
        assert_eq!(owner_token(&key), token, "the token is a function of the key");
        assert_ne!(log_id(&HpkeKeyPair::gen_keypair()), log_id(&key));
        assert_ne!(
            log_id(&key),
            ShortId::from(key.public_key()),
            "the log id is not the receiver's v2 mailbox id"
        );
    }

    #[test]
    fn targets() {
        let id = ShortId([1, 2, 3, 4, 5, 6, 7, 8]);
        for directory in ["https://example.com", "https://example.com/"] {
            let directory = Url::parse(directory).unwrap();
            assert_eq!(
                append_target(&directory, &id).as_str(),
                format!("https://example.com/log/{id}")
            );
            assert_eq!(
                read_target(&directory, &id, 7).as_str(),
                format!("https://example.com/log/{id}/7?wait=0")
            );
        }
    }

    #[test]
    fn fragment_round_trip() {
        let ohttp_keys = <OhttpKeys as std::str::FromStr>::from_str(
            "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC",
        )
        .expect("valid OHTTP keys");
        let receiver_key = HpkeKeyPair::gen_keypair();
        let fragment = fragment(&ohttp_keys, receiver_key.public_key());
        assert!(fragment.starts_with("OH1") || fragment.starts_with("RK1"), "{fragment}");
        assert!(!fragment.contains("EX1"), "a contact string has no expiration");

        let (parsed_keys, parsed_rk) = parse_fragment(&fragment).expect("round trip");
        assert_eq!(parsed_keys, ohttp_keys);
        assert_eq!(&parsed_rk, receiver_key.public_key());

        assert!(parse_fragment(&fragment.to_lowercase()).is_err());
        let without_rk: String = fragment.split('-').filter(|p| !p.starts_with("RK1")).collect();
        assert!(parse_fragment(&without_rk).is_err());
    }

    #[test]
    fn owner_authorization_format() {
        let key = HpkeKeyPair::gen_keypair();
        let value = owner_authorization(&key);
        let (scheme, hex) = value.split_once(' ').unwrap();
        assert_eq!(scheme, OWNER_SCHEME);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
