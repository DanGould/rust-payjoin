//! Payment strings for silent payjoin.
//!
//! A one-time URI is an ordinary BIP 77 URI with an `sp=` parameter added:
//!
//! ```text
//! bitcoin:<addr>?amount=…&pjos=0&sp=<sp1…>&pj=<directory>/<id>%23EX1…-OH1…-RK1…
//! ```
//!
//! A wallet without silent payments ignores `sp=` and pays the address with
//! ordinary payjoin. A receiver that won't add a coin leaves out `pj=`.

use std::fmt;

use bitcoin::{Address, Amount, Network};
use payjoin::PjUri;

use crate::sp_address::SpAddress;

/// A malformed or unusable payment string.
#[derive(Debug)]
pub struct UriError(pub(crate) String);

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

impl std::error::Error for UriError {}

pub(crate) fn err(msg: impl fmt::Display) -> UriError { UriError(msg.to_string()) }

/// A one-time silent payjoin URI.
#[derive(Debug, Clone)]
pub struct OneTimeUri {
    pub address: Address,
    pub amount: Option<Amount>,
    pub sp: SpAddress,
    /// The BIP 77 parameters, absent if the receiver won't add a coin.
    pub payjoin: Option<PjUri>,
}

impl OneTimeUri {
    /// Add `sp` to the URI of a BIP 77 receiver session.
    pub fn new(payjoin: PjUri, sp: SpAddress) -> Self {
        Self {
            address: payjoin.address().clone(),
            amount: payjoin.amount(),
            sp,
            payjoin: Some(payjoin),
        }
    }

    /// A one-time URI with no payjoin, for a receiver that won't add a coin.
    pub fn without_payjoin(address: Address, amount: Option<Amount>, sp: SpAddress) -> Self {
        Self { address, amount, sp, payjoin: None }
    }

    /// Parse a one-time URI whose address and silent payment address are for
    /// `network`.
    pub fn parse(s: &str, network: Network) -> Result<Self, UriError> {
        let sp: SpAddress = single_param(s, "sp")?
            .ok_or_else(|| err("missing sp parameter"))?
            .parse()
            .map_err(err)?;
        if !sp.network.is_valid_for(network) {
            return Err(err(format!("sp address {sp} is not for {network}")));
        }
        let uri = payjoin::Uri::try_from(s).map_err(err)?.require_network(network).map_err(err)?;
        let (address, amount) = (uri.address().clone(), uri.amount());
        let payjoin = uri.check_pj_supported().ok();
        Ok(Self { address, amount, sp, payjoin })
    }
}

impl fmt::Display for OneTimeUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sp = format!("sp={}", self.sp);
        let Some(payjoin) = &self.payjoin else {
            write!(f, "bitcoin:{}?", self.address)?;
            if let Some(amount) = self.amount {
                write!(f, "amount={}&", amount.to_btc())?;
            }
            return f.write_str(&sp);
        };
        // BIP 77's parameters stay last, with `sp` just before `pj`.
        let stock = payjoin.to_string();
        let (base, query) = stock.split_once('?').expect("a payjoin URI has a query");
        let mut params: Vec<&str> = query.split('&').collect();
        let pj = params.iter().position(|p| p.starts_with("pj=")).unwrap_or(params.len());
        params.insert(pj, &sp);
        write!(f, "{base}?{}", params.join("&"))
    }
}

/// The value of query parameter `key`, if present once. Present more than
/// once is an error.
pub(crate) fn single_param(uri: &str, key: &str) -> Result<Option<String>, UriError> {
    let Some((_, query)) = uri.split_once('?') else { return Ok(None) };
    let mut values = query
        .split('&')
        .filter_map(|param| param.split_once('='))
        .filter(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.to_string());
    let value = values.next();
    if values.next().is_some() {
        return Err(err(format!("duplicate {key} parameter")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use payjoin::receive::v2::ReceiverBuilder;
    use payjoin::{OhttpKeys, PjParam};

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

    fn receiver_pj_uri() -> PjUri {
        let ohttp_keys = ohttp_keys();
        let session = ReceiverBuilder::new(address(), "https://payjo.in", ohttp_keys)
            .unwrap()
            .with_amount(Amount::from_sat(50_000))
            .build()
            .save(&payjoin::persist::InMemoryPersister::default())
            .unwrap();
        session.pj_uri()
    }

    #[test]
    fn one_time_uri_round_trip() {
        let uri = OneTimeUri::new(receiver_pj_uri(), sp_address());
        let s = uri.to_string();
        let query = s.split_once('?').unwrap().1;
        let keys: Vec<&str> = query.split('&').map(|p| p.split_once('=').unwrap().0).collect();
        assert_eq!(keys, ["amount", "pjos", "sp", "pj"], "{s}");

        let parsed = OneTimeUri::parse(&s, Network::Regtest).unwrap();
        assert_eq!(parsed.address, uri.address);
        assert_eq!(parsed.amount, Some(Amount::from_sat(50_000)));
        assert_eq!(parsed.sp, sp_address());
        let (parsed_pj, pj) = (
            parsed.payjoin.as_ref().unwrap().extras().pj_param(),
            uri.payjoin.as_ref().unwrap().extras().pj_param(),
        );
        assert_eq!(parsed_pj.endpoint().to_uppercase(), pj.endpoint().to_uppercase());
        let (PjParam::V2(parsed_pj), PjParam::V2(pj)) = (parsed_pj, pj) else {
            panic!("v2 endpoints");
        };
        assert_eq!(parsed_pj.receiver_pubkey(), pj.receiver_pubkey());
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn stock_parser_ignores_sp() {
        let uri = OneTimeUri::new(receiver_pj_uri(), sp_address());
        let stock = payjoin::Uri::try_from(uri.to_string())
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .check_pj_supported()
            .expect("a BIP 77 parser sees a payjoin URI");
        assert_eq!(stock.address(), &uri.address);
        assert_eq!(stock.to_string(), uri.payjoin.unwrap().to_string(), "sp is dropped");
    }

    #[test]
    fn one_time_uri_without_payjoin() {
        let uri =
            OneTimeUri::without_payjoin(address(), Some(Amount::from_sat(50_000)), sp_address());
        let s = uri.to_string();
        assert!(!s.contains("pj"), "{s}");
        let parsed = OneTimeUri::parse(&s, Network::Regtest).unwrap();
        assert!(parsed.payjoin.is_none());
        assert_eq!(parsed.sp, sp_address());
        assert_eq!(parsed.amount, Some(Amount::from_sat(50_000)));
    }

    #[test]
    fn one_time_uri_rejects_bad_sp() {
        let s = OneTimeUri::new(receiver_pj_uri(), sp_address()).to_string();
        let mainnet_sp = SpAddress { network: Network::Bitcoin.into(), ..sp_address() };
        for bad in [
            s.replace(&format!("&sp={}", sp_address()), ""),
            s.replace(&sp_address().to_string(), &mainnet_sp.to_string()),
            s.replace("&pj=", &format!("&sp={}&pj=", sp_address())),
        ] {
            assert!(OneTimeUri::parse(&bad, Network::Regtest).is_err(), "{bad}");
        }
    }
}
