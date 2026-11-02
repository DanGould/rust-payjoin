//! BIP 352 silent payment addresses.
//!
//! An address is bech32m with human-readable part `sp` (mainnet), `tsp`
//! (testnet and signet) or `sprt` (regtest), a version symbol, then the
//! 33-byte compressed scan key followed by the 33-byte compressed spend key.
//! At 117 characters it is longer than BIP 173's 90-character limit, so it is
//! decoded without that limit.

use std::fmt;
use std::str::FromStr;

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, NetworkKind};

/// The only address version this module reads and writes.
const VERSION: Fe32 = Fe32::Q;

/// A BIP 352 silent payment address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
    /// Which chain the address is for, as told by its prefix.
    pub network: SpNetwork,
}

/// The chains a silent payment address prefix distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl SpNetwork {
    fn hrp(self) -> Hrp {
        let hrp = match self {
            SpNetwork::Mainnet => "sp",
            SpNetwork::Testnet => "tsp",
            SpNetwork::Regtest => "sprt",
        };
        Hrp::parse(hrp).expect("constant HRPs are valid")
    }

    fn from_hrp(hrp: &Hrp) -> Option<Self> {
        [SpNetwork::Mainnet, SpNetwork::Testnet, SpNetwork::Regtest]
            .into_iter()
            .find(|network| network.hrp() == *hrp)
    }

    /// Whether addresses with this prefix may be paid on `network`.
    pub fn is_valid_for(self, network: Network) -> bool {
        match (self, network) {
            (SpNetwork::Mainnet, Network::Bitcoin) | (SpNetwork::Regtest, Network::Regtest) => true,
            (SpNetwork::Testnet, network) =>
                NetworkKind::from(network) == NetworkKind::Test && network != Network::Regtest,
            _ => false,
        }
    }
}

impl From<Network> for SpNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => SpNetwork::Testnet,
        }
    }
}

impl SpAddress {
    pub fn new(scan: PublicKey, spend: PublicKey, network: impl Into<SpNetwork>) -> Self {
        Self { scan, spend, network: network.into() }
    }
}

impl fmt::Display for SpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = self.network.hrp();
        let payload = self.scan.serialize().into_iter().chain(self.spend.serialize());
        let chars = payload
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(VERSION)
            .chars();
        for c in chars {
            fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

/// A string that is not a version 0 silent payment address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSpAddressError(String);

impl fmt::Display for ParseSpAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid silent payment address: {}", self.0)
    }
}

impl std::error::Error for ParseSpAddressError {}

impl FromStr for SpAddress {
    type Err = ParseSpAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |msg: &str| ParseSpAddressError(msg.to_string());
        let mut parsed =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|e| ParseSpAddressError(e.to_string()))?;
        let network = SpNetwork::from_hrp(&parsed.hrp()).ok_or_else(|| err("unknown prefix"))?;
        if parsed.remove_witness_version() != Some(VERSION) {
            return Err(err("unsupported version"));
        }
        let payload: Vec<u8> = parsed.byte_iter().collect();
        if payload.len() != 66 {
            return Err(err("payload must be two 33-byte keys"));
        }
        let scan = PublicKey::from_slice(&payload[..33]).map_err(|_| err("invalid scan key"))?;
        let spend = PublicKey::from_slice(&payload[33..]).map_err(|_| err("invalid spend key"))?;
        Ok(Self { scan, spend, network })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    use super::*;

    /// The first receiving case of BIP 352's `send_and_receive_test_vectors.json`.
    const VECTOR_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const VECTOR_SCAN_KEY: &str =
        "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
    const VECTOR_SPEND_KEY: &str =
        "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3";

    fn pubkey(secret_hex: &str) -> PublicKey {
        SecretKey::from_str(secret_hex).unwrap().public_key(&Secp256k1::new())
    }

    #[test]
    fn bip352_vector_address() {
        let expected =
            SpAddress::new(pubkey(VECTOR_SCAN_KEY), pubkey(VECTOR_SPEND_KEY), SpNetwork::Mainnet);
        assert_eq!(expected.to_string(), VECTOR_ADDRESS);
        assert_eq!(VECTOR_ADDRESS.parse::<SpAddress>().unwrap(), expected);
        assert_eq!(VECTOR_ADDRESS.to_uppercase().parse::<SpAddress>().unwrap(), expected);
    }

    #[test]
    fn network_prefixes() {
        let address = VECTOR_ADDRESS.parse::<SpAddress>().unwrap();
        for (network, prefix) in
            [(Network::Bitcoin, "sp1q"), (Network::Signet, "tsp1q"), (Network::Regtest, "sprt1q")]
        {
            let address = SpAddress::new(address.scan, address.spend, network);
            let encoded = address.to_string();
            assert!(encoded.starts_with(prefix), "{encoded}");
            let parsed: SpAddress = encoded.parse().unwrap();
            assert_eq!(parsed, address);
            assert!(parsed.network.is_valid_for(network));
        }
        assert!(!SpNetwork::Regtest.is_valid_for(Network::Bitcoin));
        assert!(!SpNetwork::Testnet.is_valid_for(Network::Regtest));
        assert!(SpNetwork::Testnet.is_valid_for(Network::Testnet4));
    }

    #[test]
    fn rejects_malformed() {
        let mut flipped = VECTOR_ADDRESS.to_string();
        flipped.replace_range(20..21, if &flipped[20..21] == "q" { "p" } else { "q" });
        let bc1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        for bad in [flipped.as_str(), bc1, "", "sp1"] {
            assert!(bad.parse::<SpAddress>().is_err(), "{bad}");
        }
    }
}
