//! The contact URI and the receiver side of it.
//!
//! A contact URI has no address, so a wallet that can't pay a silent payment
//! address can't pay it at all, and it names a contact log instead of a
//! one-time mailbox. `pjv2=` is a proposed parameter, unknown to BIP 77 senders,
//! and its fragment has no `EX1` because a contact string doesn't expire:
//!
//! ```text
//! bitcoin:?sp=<sp1…>&pjv2=<directory>/<log id>%23OH1…-RK1…
//! ```
//!
//! A [`ContactLog`] holds the receiver key behind one contact URI and the
//! index of the next frame to read from its log. Each frame is read by a
//! fresh BIP 77 receiver session built with that key. A frame that decrypts
//! becomes a session holding the sender's Original, which then follows the
//! standard receiver flow and replies to that sender's own mailbox. A frame
//! that doesn't decrypt, such as one written by a party that doesn't follow
//! the protocol, is skipped.

use std::fmt;
use std::time::Duration;

use bitcoin::{Address, Network};
use payjoin::directory::ShortId;
use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
use payjoin::receive::v2::{
    Initialized, Receiver, ReceiverBuilder, SessionEvent, UncheckedOriginalPayload,
};
use payjoin::receive::ProtocolError;
use payjoin::uri::v2::PjParam as V2PjParam;
use payjoin::{contact_log, HpkeKeyPair, HpkePublicKey, OhttpKeys, Url};

use crate::net::{Error, Mailroom};
use crate::sp_address::SpAddress;
use crate::uri::{err, single_param, UriError};

/// A contact URI: one receiver key and contact log for many payments.
#[derive(Debug, Clone)]
pub struct ContactUri {
    pub sp: SpAddress,
    /// The directory holding the contact log.
    pub directory: Url,
    pub log_id: ShortId,
    pub ohttp_keys: OhttpKeys,
    pub receiver_pubkey: HpkePublicKey,
}

impl ContactUri {
    /// The contact URI for `receiver_key`'s contact log on `directory`.
    pub fn new(
        sp: SpAddress,
        directory: Url,
        ohttp_keys: OhttpKeys,
        receiver_key: &HpkeKeyPair,
    ) -> Self {
        Self {
            sp,
            directory,
            log_id: contact_log::log_id(receiver_key),
            ohttp_keys,
            receiver_pubkey: receiver_key.public_key().clone(),
        }
    }

    /// Parse a contact URI whose silent payment address is for `network`.
    pub fn parse(s: &str, network: Network) -> Result<Self, UriError> {
        let (scheme, rest) = s.split_once(':').ok_or_else(|| err("not a URI"))?;
        if !scheme.eq_ignore_ascii_case("bitcoin") {
            return Err(err("not a bitcoin URI"));
        }
        if !rest.starts_with('?') {
            return Err(err("a contact URI has no address"));
        }
        let sp: SpAddress = single_param(s, "sp")?
            .ok_or_else(|| err("missing sp parameter"))?
            .parse()
            .map_err(err)?;
        if !sp.network.is_valid_for(network) {
            return Err(err(format!("sp address {sp} is not for {network}")));
        }
        let pjv2 = percent_decode(
            &single_param(s, "pjv2")?.ok_or_else(|| err("missing pjv2 parameter"))?,
        )?;
        let (endpoint, fragment) =
            pjv2.split_once('#').ok_or_else(|| err("pjv2 has no fragment"))?;
        let (directory, id) = endpoint.rsplit_once('/').ok_or_else(|| err("pjv2 has no log id"))?;
        let log_id: ShortId = id.parse().map_err(err)?;
        let directory = Url::parse(directory).map_err(err)?;
        let (ohttp_keys, receiver_pubkey) = contact_log::parse_fragment(fragment).map_err(err)?;
        Ok(Self { sp, directory, log_id, ohttp_keys, receiver_pubkey })
    }

    /// The BIP 77 parameters a sender uses to pay this contact, waiting at
    /// most `patience` for the receiver's proposal.
    pub fn sender_pj_param(&self, patience: Duration) -> Result<V2PjParam, UriError> {
        V2PjParam::for_contact_log(
            self.directory.clone(),
            self.ohttp_keys.clone(),
            self.receiver_pubkey.clone(),
            patience,
        )
        .map_err(err)
    }
}

impl fmt::Display for ContactUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Upper case where it's case-insensitive keeps QR codes in alphanumeric mode.
        let directory = self.directory.as_str().trim_end_matches('/');
        let (scheme, rest) = directory.split_once("://").unwrap_or(("", directory));
        let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
        let path = if path.is_empty() { String::new() } else { format!("/{path}") };
        write!(
            f,
            "bitcoin:?sp={}&pjv2={}://{}{path}/{}%23{}",
            self.sp,
            scheme.to_uppercase(),
            authority.to_uppercase(),
            self.log_id,
            contact_log::fragment(&self.ohttp_keys, &self.receiver_pubkey),
        )
    }
}

fn percent_decode(s: &str) -> Result<String, UriError> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex: String = bytes.by_ref().take(2).map(char::from).collect();
            out.push(u8::from_str_radix(&hex, 16).map_err(|_| err("bad percent escape"))?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).map_err(err)
}

/// One payment read from a contact log.
pub struct Inbound {
    /// The frame's index in the log.
    pub index: usize,
    /// The receiver session holding the sender's Original.
    pub receiver: Receiver<UncheckedOriginalPayload>,
    /// The session's event log. Keep it to resume or audit the session.
    pub persister: InMemoryPersister<SessionEvent>,
}

/// A receiver's contact log and its read cursor.
pub struct ContactLog {
    receiver_key: HpkeKeyPair,
    address: Address,
    directory: Url,
    next_index: usize,
}

impl ContactLog {
    /// A contact log for `receiver_key` on `directory`. `address` is the
    /// fallback receiving address each per-payment session starts with.
    pub fn new(receiver_key: HpkeKeyPair, address: Address, directory: Url) -> Self {
        Self { receiver_key, address, directory, next_index: 0 }
    }

    /// The contact URI senders pay this log through.
    pub fn uri(&self, sp: SpAddress, mailroom: &Mailroom) -> ContactUri {
        ContactUri::new(
            sp,
            self.directory.clone(),
            mailroom.ohttp_keys().clone(),
            &self.receiver_key,
        )
    }

    pub fn receiver_key(&self) -> &HpkeKeyPair { &self.receiver_key }

    /// The index of the next frame [`ContactLog::next`] reads.
    pub fn next_index(&self) -> usize { self.next_index }

    /// A fresh receiver session for one frame of this log.
    fn session(
        &self,
        mailroom: &Mailroom,
    ) -> Result<(Receiver<Initialized>, InMemoryPersister<SessionEvent>), Error> {
        let persister = InMemoryPersister::default();
        let receiver = ReceiverBuilder::new(
            self.address.clone(),
            self.directory.as_str(),
            mailroom.ohttp_keys().clone(),
        )?
        .with_receiver_key(self.receiver_key.clone())
        .build()
        .save(&persister)?;
        Ok((receiver, persister))
    }

    /// Create the log on the directory, so that senders' appends are
    /// accepted. Any read by the owner creates it. This one reads frame 0
    /// and discards the answer, leaving the cursor where it was.
    pub async fn create(&self, mailroom: &Mailroom) -> Result<(), Error> {
        let (session, _) = self.session(mailroom)?;
        let (request, _) = session.create_contact_log_request(mailroom.relay_url(), 0)?;
        mailroom.send(&request).await?;
        Ok(())
    }

    /// Read the log from the cursor until a frame decrypts or the log ends.
    /// Returns `None` at the end of the log.
    pub async fn next(&mut self, mailroom: &Mailroom) -> Result<Option<Inbound>, Error> {
        loop {
            let index = self.next_index;
            let (session, persister) = self.session(mailroom)?;
            let (request, context) =
                session.create_contact_log_request(mailroom.relay_url(), index)?;
            let response = mailroom.send(&request).await?;
            match session.process_response(&response, context).save(&persister) {
                Ok(OptionalTransitionOutcome::Progress(receiver)) => {
                    self.next_index += 1;
                    return Ok(Some(Inbound { index, receiver, persister }));
                }
                Ok(OptionalTransitionOutcome::Stasis(_)) => return Ok(None),
                Err(e) if e.api_error_ref().is_some_and(is_foreign_frame) => self.next_index += 1,
                Err(e) => return Err(e.to_string().into()),
            }
        }
    }
}

/// Whether a log read failed because the frame isn't a valid message A for
/// this receiver key, as opposed to a directory or transport failure.
fn is_foreign_frame(error: &ProtocolError) -> bool {
    match error {
        ProtocolError::V2(e) => e.is_undecryptable(),
        ProtocolError::OriginalPayload(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    use super::*;

    fn ohttp_keys() -> OhttpKeys {
        OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap()
    }

    fn sp_address() -> SpAddress {
        let secp = Secp256k1::new();
        let key = |byte| SecretKey::from_slice(&[byte; 32]).unwrap().public_key(&secp);
        SpAddress::new(key(1), key(2), Network::Regtest)
    }

    fn address() -> Address {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[3; 32]).unwrap().x_only_public_key(&secp).0;
        Address::p2tr(&secp, key, None, Network::Regtest)
    }

    fn contact_uri() -> (ContactUri, HpkeKeyPair) {
        let key = HpkeKeyPair::gen_keypair();
        let uri = ContactUri::new(
            sp_address(),
            Url::parse("https://payjo.in").unwrap(),
            ohttp_keys(),
            &key,
        );
        (uri, key)
    }

    #[test]
    fn contact_uri_round_trip() {
        let (uri, key) = contact_uri();
        let s = uri.to_string();
        assert!(s.starts_with(&format!("bitcoin:?sp={}&pjv2=HTTPS://PAYJO.IN/", sp_address())));
        assert!(!s.contains("EX1"), "{s}");

        let parsed = ContactUri::parse(&s, Network::Regtest).unwrap();
        assert_eq!(parsed.sp, sp_address());
        assert_eq!(parsed.log_id, contact_log::log_id(&key));
        assert_eq!(&parsed.receiver_pubkey, key.public_key());
        assert_eq!(parsed.ohttp_keys, uri.ohttp_keys);
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn stock_parser_cannot_pay_contact_uri() {
        let (uri, _) = contact_uri();
        assert!(payjoin::Uri::try_from(uri.to_string()).is_err(), "no address to pay");
    }

    #[test]
    fn contact_uri_rejects_malformed() {
        let (uri, _) = contact_uri();
        let s = uri.to_string();
        let addr = address().to_string();
        for bad in [
            s.replace("bitcoin:?", &format!("bitcoin:{addr}?")),
            s.replace("%23", "%2"),
            s.replace("pjv2=", "pj="),
            format!("{s}&sp={}", sp_address()),
            s.replace("sprt1", "sp1"),
        ] {
            assert!(ContactUri::parse(&bad, Network::Regtest).is_err(), "{bad}");
        }
    }

    #[test]
    fn contact_sender_param_targets_directory() {
        let (uri, _) = contact_uri();
        let pj = uri.sender_pj_param(Duration::from_secs(600)).unwrap();
        assert_eq!(pj.receiver_pubkey(), &uri.receiver_pubkey);
    }
}
