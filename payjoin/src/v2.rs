use std::ops::{Deref, DerefMut};
use std::{error, fmt};

use bitcoin::base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bitcoin::base64::Engine;
use bitcoin::key::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::SecpK256HkdfSha256;
use hpke::rand_core::OsRng;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};

pub const PADDED_MESSAGE_BYTES: usize = 7168;
pub const PADDED_PLAINTEXT_A_LENGTH: usize =
    PADDED_MESSAGE_BYTES - UNCOMPRESSED_PUBLIC_KEY_SIZE * 2;
pub const PADDED_PLAINTEXT_B_LENGTH: usize = PADDED_MESSAGE_BYTES - UNCOMPRESSED_PUBLIC_KEY_SIZE;
pub const INFO_A: &[u8] = b"PjV2MsgA";
pub const INFO_B: &[u8] = b"PjV2MsgB";

pub type SecretKey = <SecpK256HkdfSha256 as hpke::Kem>::PrivateKey;
pub type PublicKey = <SecpK256HkdfSha256 as hpke::Kem>::PublicKey;
pub type EncappedKey = <SecpK256HkdfSha256 as hpke::Kem>::EncappedKey;

fn sk_to_pk(sk: &SecretKey) -> PublicKey { <SecpK256HkdfSha256 as hpke::Kem>::sk_to_pk(sk) }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeKeyPair(pub HpkeSecretKey, pub HpkePublicKey);

impl From<HpkeKeyPair> for (HpkeSecretKey, HpkePublicKey) {
    fn from(value: HpkeKeyPair) -> Self { (value.0, value.1) }
}

impl HpkeKeyPair {
    pub fn gen_keypair() -> Self {
        let (sk, pk) = <SecpK256HkdfSha256 as hpke::Kem>::gen_keypair(&mut OsRng);
        Self(HpkeSecretKey(sk), HpkePublicKey(pk))
    }
    pub fn secret_key(self) -> HpkeSecretKey { self.0 }
    pub fn public_key(self) -> HpkePublicKey { self.1 }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HpkeSecretKey(pub SecretKey);

impl Deref for HpkeSecretKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::fmt::Debug for HpkeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecpHpkeSecretKey({:?})", self.0.to_bytes())
    }
}

impl serde::Serialize for HpkeSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HpkeSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(HpkeSecretKey(
            SecretKey::from_bytes(&bytes)
                .map_err(|_| serde::de::Error::custom("Invalid secret key"))?,
        ))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HpkePublicKey(pub PublicKey);

impl HpkePublicKey {
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let compressed_key = bitcoin::secp256k1::PublicKey::from_slice(&self.0.to_bytes())
            .expect("Invalid public key from known valid bytes");
        compressed_key.serialize()
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        let compressed_key = bitcoin::secp256k1::PublicKey::from_slice(bytes)?;
        Ok(HpkePublicKey(PublicKey::from_bytes(
            compressed_key.serialize_uncompressed().as_slice(),
        )?))
    }
}

impl Deref for HpkePublicKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::fmt::Debug for HpkePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecpHpkePublicKey({:?})", self.0)
    }
}

impl serde::Serialize for HpkePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HpkePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(HpkePublicKey(
            PublicKey::from_bytes(&bytes)
                .map_err(|_| serde::de::Error::custom("Invalid public key"))?,
        ))
    }
}

/// Message A is sent from the sender to the receiver containing an Original PSBT payload
#[cfg(feature = "send")]
pub fn encrypt_message_a_hpke(
    mut plaintext: Vec<u8>,
    pj_s_sk_e: &HpkeSecretKey,
    pj_r_pk_s: &HpkePublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let pk = sk_to_pk(&pj_s_sk_e.0);
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, SecpK256HkdfSha256, _>(
            &OpModeS::Auth((pj_s_sk_e.0.clone(), pk.clone())),
            &pj_r_pk_s.0,
            INFO_A,
            &mut OsRng,
        )?;
    let aad = pk.to_bytes().to_vec();
    let plaintext = pad_plaintext(&mut plaintext, PADDED_PLAINTEXT_A_LENGTH)?;
    let ciphertext = encryption_context.seal(plaintext, &aad)?;
    let mut message_a = encapsulated_key.to_bytes().to_vec();
    message_a.extend(&aad);
    message_a.extend(&ciphertext);
    Ok(message_a.to_vec())
}

#[cfg(feature = "receive")]
pub fn decrypt_message_a_hpke(
    message_a: &[u8],
    pj_r_sk_s: HpkeSecretKey,
) -> Result<(Vec<u8>, HpkePublicKey), HpkeError> {
    let enc = message_a.get(..65).ok_or(HpkeError::PayloadTooShort)?;
    let enc = EncappedKey::from_bytes(enc)?;
    let aad = message_a.get(65..130).ok_or(HpkeError::PayloadTooShort)?;
    let pk_s = PublicKey::from_bytes(aad)?;
    let mut decryption_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        SecpK256HkdfSha256,
    >(&OpModeR::Auth(pk_s.clone()), &pj_r_sk_s.0, &enc, INFO_A)?;
    let ciphertext = message_a.get(130..).ok_or(HpkeError::PayloadTooShort)?;
    let plaintext = decryption_ctx.open(ciphertext, aad)?;
    Ok((plaintext, HpkePublicKey(pk_s)))
}

/// Message B is sent from the receiver to the sender containing a Payjoin PSBT payload or an error
#[cfg(feature = "receive")]
pub fn encrypt_message_b_hpke(
    mut plaintext: Vec<u8>,
    pj_r_s: &HpkeKeyPair,
    pj_s_pk_re: &HpkePublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, SecpK256HkdfSha256, _>(
            &OpModeS::Auth((pj_r_s.clone().secret_key().0, pj_r_s.clone().public_key().0)),
            &pj_s_pk_re.0,
            INFO_B,
            &mut OsRng,
        )?;
    let plaintext = pad_plaintext(&mut plaintext, PADDED_PLAINTEXT_B_LENGTH)?;
    let ciphertext = encryption_context.seal(plaintext, &[])?;
    let mut message_b = encapsulated_key.to_bytes().to_vec();
    message_b.extend(&ciphertext);
    Ok(message_b.to_vec())
}

#[cfg(feature = "send")]
pub fn decrypt_message_b_hpke(
    message_b: &[u8],
    rs: HpkePublicKey,
    s: HpkeSecretKey,
) -> Result<Vec<u8>, HpkeError> {
    let enc = message_b.get(..65).ok_or(HpkeError::PayloadTooShort)?;
    let enc = EncappedKey::from_bytes(enc)?;
    let mut decryption_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        SecpK256HkdfSha256,
    >(&OpModeR::Auth(rs.0), &s.0, &enc, INFO_B)?;
    let plaintext =
        decryption_ctx.open(message_b.get(65..).ok_or(HpkeError::PayloadTooShort)?, &[])?;
    Ok(plaintext)
}

fn pad_plaintext(msg: &mut Vec<u8>, padded_length: usize) -> Result<&[u8], HpkeError> {
    if msg.len() > padded_length {
        return Err(HpkeError::PayloadTooLarge { actual: msg.len(), max: padded_length });
    }
    msg.resize(padded_length, 0);
    Ok(msg)
}

/// Error from de/encrypting a v2 Hybrid Public Key Encryption payload.
#[derive(Debug)]
pub enum HpkeError {
    Secp256k1(bitcoin::secp256k1::Error),
    Hpke(hpke::HpkeError),
    InvalidKeyLength,
    PayloadTooLarge { actual: usize, max: usize },
    PayloadTooShort,
}

impl From<hpke::HpkeError> for HpkeError {
    fn from(value: hpke::HpkeError) -> Self { Self::Hpke(value) }
}

impl From<bitcoin::secp256k1::Error> for HpkeError {
    fn from(value: bitcoin::secp256k1::Error) -> Self { Self::Secp256k1(value) }
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HpkeError::*;

        match &self {
            Hpke(e) => e.fmt(f),
            InvalidKeyLength => write!(f, "Invalid Length"),
            PayloadTooLarge { actual, max } => {
                write!(
                    f,
                    "Plaintext too large, max size is {} bytes, actual size is {} bytes",
                    max, actual
                )
            }
            PayloadTooShort => write!(f, "Payload too small"),
            Secp256k1(e) => e.fmt(f),
        }
    }
}

impl error::Error for HpkeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use HpkeError::*;

        match &self {
            Hpke(e) => Some(e),
            PayloadTooLarge { .. } => None,
            InvalidKeyLength | PayloadTooShort => None,
            Secp256k1(e) => Some(e),
        }
    }
}

pub fn ohttp_encapsulate(
    ohttp_keys: &mut ohttp::KeyConfig,
    method: &str,
    target_resource: &str,
    body: Option<&[u8]>,
) -> Result<(Vec<u8>, ohttp::ClientResponse), OhttpEncapsulationError> {
    use std::fmt::Write;

    let ctx = ohttp::ClientRequest::from_config(ohttp_keys)?;
    let url = url::Url::parse(target_resource)?;
    let authority_bytes = url.host().map_or_else(Vec::new, |host| {
        let mut authority = host.to_string();
        if let Some(port) = url.port() {
            write!(authority, ":{}", port).unwrap();
        }
        authority.into_bytes()
    });
    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        authority_bytes,
        url.path().as_bytes().to_vec(),
    );
    // None of our messages include headers, so we don't add them
    if let Some(body) = body {
        bhttp_message.write_content(body);
    }
    let mut bhttp_req = Vec::new();
    let _ = bhttp_message.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req);
    let encapsulated = ctx.encapsulate(&bhttp_req)?;
    Ok(encapsulated)
}

/// decapsulate ohttp, bhttp response and return http response body and status code
pub fn ohttp_decapsulate(
    res_ctx: ohttp::ClientResponse,
    ohttp_body: &[u8],
) -> Result<http::Response<Vec<u8>>, OhttpEncapsulationError> {
    let bhttp_body = res_ctx.decapsulate(ohttp_body)?;
    let mut r = std::io::Cursor::new(bhttp_body);
    let m: bhttp::Message = bhttp::Message::read_bhttp(&mut r)?;
    let mut builder = http::Response::builder();
    for field in m.header().iter() {
        builder = builder.header(field.name(), field.value());
    }
    builder
        .status(m.control().status().unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR.into()))
        .body(m.content().to_vec())
        .map_err(OhttpEncapsulationError::Http)
}

/// Error from de/encapsulating an Oblivious HTTP request or response.
#[derive(Debug)]
pub enum OhttpEncapsulationError {
    Http(http::Error),
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(url::ParseError),
}

impl From<http::Error> for OhttpEncapsulationError {
    fn from(value: http::Error) -> Self { Self::Http(value) }
}

impl From<ohttp::Error> for OhttpEncapsulationError {
    fn from(value: ohttp::Error) -> Self { Self::Ohttp(value) }
}

impl From<bhttp::Error> for OhttpEncapsulationError {
    fn from(value: bhttp::Error) -> Self { Self::Bhttp(value) }
}

impl From<url::ParseError> for OhttpEncapsulationError {
    fn from(value: url::ParseError) -> Self { Self::ParseUrl(value) }
}

impl fmt::Display for OhttpEncapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use OhttpEncapsulationError::*;

        match &self {
            Http(e) => e.fmt(f),
            Ohttp(e) => e.fmt(f),
            Bhttp(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
        }
    }
}

impl error::Error for OhttpEncapsulationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use OhttpEncapsulationError::*;

        match &self {
            Http(e) => Some(e),
            Ohttp(e) => Some(e),
            Bhttp(e) => Some(e),
            ParseUrl(e) => Some(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OhttpKeys(pub ohttp::KeyConfig);

impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: &[u8]) -> Result<Self, ohttp::Error> {
        ohttp::KeyConfig::decode(bytes).map(Self)
    }
}

const KEM_ID: &[u8] = b"\x00\x16"; // DHKEM(secp256k1, HKDF-SHA256)
const SYMMETRIC_LEN: &[u8] = b"\x00\x04"; // 4 bytes
const SYMMETRIC_KDF_AEAD: &[u8] = b"\x00\x01\x00\x03"; // KDF(HKDF-SHA256), AEAD(ChaCha20Poly1305)

impl fmt::Display for OhttpKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.encode().map_err(|_| fmt::Error)?;
        let key_id = bytes[0];
        let pubkey = &bytes[3..68];

        let compressed_pubkey =
            bitcoin::secp256k1::PublicKey::from_slice(pubkey).map_err(|_| fmt::Error)?.serialize();

        let mut buf = vec![key_id];
        buf.extend_from_slice(&compressed_pubkey);

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(buf);
        write!(f, "{}", encoded)
    }
}

impl std::str::FromStr for OhttpKeys {
    type Err = ParseOhttpKeysError;

    /// Parses a base64URL-encoded string into OhttpKeys.
    /// The string format is: key_id || compressed_public_key
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(s).map_err(ParseOhttpKeysError::DecodeBase64)?;

        let key_id = *bytes.first().ok_or(ParseOhttpKeysError::InvalidFormat)?;
        let compressed_pk = bytes.get(1..34).ok_or(ParseOhttpKeysError::InvalidFormat)?;

        let pubkey = bitcoin::secp256k1::PublicKey::from_slice(compressed_pk)
            .map_err(|_| ParseOhttpKeysError::InvalidPublicKey)?;

        let mut buf = vec![key_id];
        buf.extend_from_slice(KEM_ID);
        buf.extend_from_slice(&pubkey.serialize_uncompressed());
        buf.extend_from_slice(SYMMETRIC_LEN);
        buf.extend_from_slice(SYMMETRIC_KDF_AEAD);

        ohttp::KeyConfig::decode(&buf).map(Self).map_err(ParseOhttpKeysError::DecodeKeyConfig)
    }
}

impl PartialEq for OhttpKeys {
    fn eq(&self, other: &Self) -> bool {
        match (self.encode(), other.encode()) {
            (Ok(self_encoded), Ok(other_encoded)) => self_encoded == other_encoded,
            // If OhttpKeys::encode(&self) is Err, return false
            _ => false,
        }
    }
}

impl Eq for OhttpKeys {}

impl Deref for OhttpKeys {
    type Target = ohttp::KeyConfig;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for OhttpKeys {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<'de> serde::Deserialize<'de> for OhttpKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        OhttpKeys::decode(&bytes).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for OhttpKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.encode().map_err(serde::ser::Error::custom)?;
        bytes.serialize(serializer)
    }
}

#[derive(Debug)]
pub enum ParseOhttpKeysError {
    InvalidFormat,
    InvalidPublicKey,
    DecodeBase64(bitcoin::base64::DecodeError),
    DecodeKeyConfig(ohttp::Error),
}

impl std::fmt::Display for ParseOhttpKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseOhttpKeysError::InvalidFormat => write!(f, "Invalid format"),
            ParseOhttpKeysError::InvalidPublicKey => write!(f, "Invalid public key"),
            ParseOhttpKeysError::DecodeBase64(e) => write!(f, "Failed to decode base64: {}", e),
            ParseOhttpKeysError::DecodeKeyConfig(e) =>
                write!(f, "Failed to decode KeyConfig: {}", e),
        }
    }
}

impl std::error::Error for ParseOhttpKeysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseOhttpKeysError::DecodeBase64(e) => Some(e),
            ParseOhttpKeysError::DecodeKeyConfig(e) => Some(e),
            ParseOhttpKeysError::InvalidFormat | ParseOhttpKeysError::InvalidPublicKey => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ohttp_keys_roundtrip() {
        use std::str::FromStr;

        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::K256Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];
        let keys = OhttpKeys(ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized = &keys.to_string();
        let deserialized = OhttpKeys::from_str(serialized).unwrap();
        assert_eq!(keys.encode().unwrap(), deserialized.encode().unwrap());
    }
}
