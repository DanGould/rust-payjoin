//! BIP 352 silent payments without labels.
//!
//! A sender combines the keys of the inputs it spends with the
//! receiver's scan key to derive fresh taproot outputs only the receiver
//! can find and spend. The receiver repeats the derivation from the
//! public input keys and its scan secret.
//!
//! Notation follows BIP 352: `a`/`A` are input secret/public keys,
//! `b_scan`/`B_scan` and `b_spend`/`B_spend` the receiver's key pairs,
//! and `t_k` the tweak of the receiver's k-th output in a transaction.

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bitcoin::bech32::{Bech32m, Fe32, Hrp};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::{
    PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey,
};
use bitcoin::{OutPoint, Script, Transaction, TxOut, Witness};

use crate::tagged_hash;

/// The most outputs a transaction may pay to one scan key. Senders
/// refuse to create more and receivers stop scanning there, which
/// bounds a receiver's work per transaction.
pub const K_MAX: u32 = 2323;

/// BIP 341's provably unspendable internal key. A script-path spend
/// from it has no key a sender could have used, so it is not eligible.
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// The spent output types whose key BIP 352 can read from the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    P2pkh,
    P2shP2wpkh,
    P2wpkh,
    P2tr,
}

/// The key a receiver reads from an input spending `prevout`, or `None`
/// when the input is not eligible and does not take part in the
/// derivation.
///
/// Only compressed keys count. For P2TR this is the output key with
/// even y, so the sender must use [`input_secret_key`] for it.
pub fn input_public_key(
    script_sig: &Script,
    witness: &Witness,
    prevout: &Script,
) -> Option<(InputKind, PublicKey)> {
    if prevout.is_p2pkh() {
        // The key is normally the last push of the scriptSig, but a
        // third party can malleate the scriptSig without invalidating
        // it, so search every 33-byte window for the committed hash.
        let hash = &prevout.as_bytes()[3..23];
        let sig = script_sig.as_bytes();
        return (33..=sig.len()).rev().find_map(|end| {
            let candidate = &sig[end - 33..end];
            (hash160::Hash::hash(candidate).as_byte_array() == hash)
                .then(|| PublicKey::from_slice(candidate).ok())
                .flatten()
                .map(|key| (InputKind::P2pkh, key))
        });
    }
    if prevout.is_p2sh() {
        let redeem_script = script_sig.as_bytes().get(1..)?;
        if !Script::from_bytes(redeem_script).is_p2wpkh() {
            return None;
        }
        return compressed_key(witness.last()?).map(|key| (InputKind::P2shP2wpkh, key));
    }
    if prevout.is_p2wpkh() {
        return compressed_key(witness.last()?).map(|key| (InputKind::P2wpkh, key));
    }
    if prevout.is_p2tr() {
        let mut stack: Vec<&[u8]> = witness.iter().collect();
        if stack.len() > 1 && stack.last().and_then(|item| item.first()) == Some(&0x50) {
            stack.pop(); // annex
        }
        if stack.is_empty() {
            return None;
        }
        if stack.len() > 1 {
            let control_block = stack.last()?;
            if control_block.get(1..33) == Some(&NUMS_H[..]) {
                return None;
            }
        }
        let x_only = XOnlyPublicKey::from_slice(&prevout.as_bytes()[2..]).ok()?;
        return Some((InputKind::P2tr, x_only.public_key(bitcoin::secp256k1::Parity::Even)));
    }
    None
}

fn compressed_key(bytes: &[u8]) -> Option<PublicKey> {
    (bytes.len() == 33).then(|| PublicKey::from_slice(bytes).ok()).flatten()
}

/// The secret matching [`input_public_key`] for an input of `kind`. A
/// P2TR output commits to an x-only key, which receivers read as the
/// even-y point, so a secret whose point has odd y is negated to match.
/// Senders sum these, and an input's owner proves its BIP 375 share with
/// it.
pub fn input_secret_key<C: Signing>(
    secp: &Secp256k1<C>,
    secret: &SecretKey,
    kind: InputKind,
) -> SecretKey {
    let (_, parity) = secret.x_only_public_key(secp);
    if kind == InputKind::P2tr && parity == bitcoin::secp256k1::Parity::Odd {
        secret.negate()
    } else {
        *secret
    }
}

/// `input_hash = hash_BIP0352/Inputs(outpoint_L || A)`, where
/// `outpoint_L` is the smallest outpoint by serialization. Committing to
/// an outpoint makes the derivation unique to this transaction even when
/// the same keys pay the same receiver again.
pub fn input_hash(outpoints: &[OutPoint], a_sum: &PublicKey) -> Option<Scalar> {
    let mut msg = outpoints.iter().map(bitcoin::consensus::serialize).min()?;
    msg.extend_from_slice(&a_sum.serialize());
    Scalar::from_be_bytes(tagged_hash("BIP0352/Inputs", &msg)).ok()
}

/// The receiver-independent half of the shared secret,
/// `input_hash·A`. A receiver completes the scan from this point alone,
/// which is what lets a server index it per transaction. `None` when no
/// input is eligible or the keys sum to the point at infinity, in which
/// case the transaction pays no silent payment.
pub fn public_tweak<C: Verification>(
    secp: &Secp256k1<C>,
    outpoints: &[OutPoint],
    input_keys: &[PublicKey],
) -> Option<PublicKey> {
    let refs: Vec<&PublicKey> = input_keys.iter().collect();
    let a_sum = PublicKey::combine_keys(&refs).ok()?;
    let input_hash = input_hash(outpoints, &a_sum)?;
    a_sum.mul_tweak(secp, &input_hash).ok()
}

/// [`public_tweak`] for a whole transaction, reading the input keys with
/// [`input_public_key`]. `prevouts` are the spent outputs in input order.
/// `None` also covers transactions BIP 352 tells receivers to skip: any
/// input spending a segwit version 2 or higher output, or no taproot
/// output to pay.
pub fn transaction_tweak<C: Verification>(
    secp: &Secp256k1<C>,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Option<PublicKey> {
    if tx.input.len() != prevouts.len() || !tx.output.iter().any(|o| o.script_pubkey.is_p2tr()) {
        return None;
    }
    if prevouts.iter().any(|p| p.script_pubkey.witness_version().is_some_and(|v| v.to_num() > 1)) {
        return None;
    }
    let keys: Vec<PublicKey> = tx
        .input
        .iter()
        .zip(prevouts)
        .filter_map(|(input, prevout)| {
            input_public_key(&input.script_sig, &input.witness, &prevout.script_pubkey)
        })
        .map(|(_, key)| key)
        .collect();
    let outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
    public_tweak(secp, &outpoints, &keys)
}

/// The sum of the sender's eligible input secrets, each already passed
/// through [`input_secret_key`]. `None` if there are none or they sum
/// to zero. Partial sums may be zero.
pub fn input_secret_sum(secrets: &[SecretKey]) -> Option<SecretKey> {
    // `None` stands for zero, which SecretKey cannot hold.
    secrets.iter().fold(None, |acc: Option<SecretKey>, secret| match acc {
        None => Some(*secret),
        Some(sum) => sum.add_tweak(&Scalar::from(*secret)).ok(),
    })
}

/// The tweak `t_k = hash_BIP0352/SharedSecret(ecdh || ser32(k))` of the
/// k-th output paying one scan key.
pub fn output_tweak(ecdh_shared_secret: &PublicKey, k: u32) -> Option<Scalar> {
    let mut msg = ecdh_shared_secret.serialize().to_vec();
    msg.extend_from_slice(&k.to_be_bytes());
    Scalar::from_be_bytes(tagged_hash("BIP0352/SharedSecret", &msg)).ok()
}

/// A receiver's published key pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    Bech32m,
    Version(u8),
    Length(usize),
    Key,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressError::Bech32m => write!(f, "not a valid bech32m string"),
            AddressError::Version(v) => write!(f, "unsupported silent payment version {v}"),
            AddressError::Length(n) => write!(f, "expected 66 key bytes, got {n}"),
            AddressError::Key => write!(f, "invalid public key"),
        }
    }
}

impl std::error::Error for AddressError {}

impl SpAddress {
    /// Bech32m with a version 0 prefix. BIP 352 uses the HRP `sp` on
    /// mainnet and `tsp` on test networks; it does not assign one to
    /// regtest, and `sprt` is the common choice.
    pub fn encode(&self, hrp: &str) -> String {
        let hrp = Hrp::parse(hrp).expect("caller passes a valid HRP");
        let mut payload = self.scan.serialize().to_vec();
        payload.extend_from_slice(&self.spend.serialize());
        payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::Q)
            .chars()
            .collect()
    }

    /// Parse an address of any HRP, returned alongside. Versions 1 to 30
    /// are read as version 0, ignoring extra data, which BIP 352 asks of
    /// version 0 parsers for forward compatibility.
    pub fn decode(address: &str) -> Result<(Hrp, Self), AddressError> {
        let checked =
            CheckedHrpstring::new::<Bech32m>(address).map_err(|_| AddressError::Bech32m)?;
        let fes: Vec<Fe32> = checked.fe32_iter::<std::iter::Empty<u8>>().collect();
        let version = fes.first().ok_or(AddressError::Length(0))?.to_u8();
        let payload: Vec<u8> = fes[1..].iter().copied().fes_to_bytes().collect();
        let keys = match version {
            0 if payload.len() == 66 => &payload[..],
            0 => return Err(AddressError::Length(payload.len())),
            1..=30 if payload.len() >= 66 => &payload[..66],
            1..=30 => return Err(AddressError::Length(payload.len())),
            _ => return Err(AddressError::Version(version)),
        };
        let scan = PublicKey::from_slice(&keys[..33]).map_err(|_| AddressError::Key)?;
        let spend = PublicKey::from_slice(&keys[33..]).map_err(|_| AddressError::Key)?;
        Ok((checked.hrp(), SpAddress { scan, spend }))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// No eligible inputs, or their keys sum to zero.
    NoInputKey,
    /// More than [`K_MAX`] recipients share one scan key.
    TooManyOutputs,
    /// A hash landed outside the scalar range, which has negligible
    /// probability.
    Hash,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::NoInputKey => write!(f, "no eligible input key, or the keys sum to zero"),
            SendError::TooManyOutputs => write!(f, "more than {K_MAX} outputs for one scan key"),
            SendError::Hash => write!(f, "hash out of scalar range"),
        }
    }
}

impl std::error::Error for SendError {}

/// The ECDH shared secret `input_hash·a·B_scan` a sender computes for one
/// scan key, where `a` is [`input_secret_sum`].
pub fn sender_shared_secret<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    a_sum: &SecretKey,
    outpoints: &[OutPoint],
    scan: &PublicKey,
) -> Result<PublicKey, SendError> {
    let input_hash = input_hash(outpoints, &a_sum.public_key(secp)).ok_or(SendError::Hash)?;
    let scalar = a_sum.mul_tweak(&input_hash).map_err(|_| SendError::Hash)?;
    scan.mul_tweak(secp, &Scalar::from(scalar)).map_err(|_| SendError::Hash)
}

/// Derive one output key per recipient, in recipient order.
///
/// `input_secrets` are the secrets of every eligible input, each passed
/// through [`input_secret_key`]; `outpoints` are all of the
/// transaction's inputs, eligible or not. Recipients sharing a scan key
/// get consecutive `k` in the order they appear.
pub fn sender_outputs<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    input_secrets: &[SecretKey],
    outpoints: &[OutPoint],
    recipients: &[SpAddress],
) -> Result<Vec<XOnlyPublicKey>, SendError> {
    let a_sum = input_secret_sum(input_secrets).ok_or(SendError::NoInputKey)?;
    let mut groups: Vec<(PublicKey, PublicKey, u32)> = Vec::new(); // (scan, shared, next k)
    let mut outputs = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let position = match groups.iter().position(|(scan, _, _)| *scan == recipient.scan) {
            Some(position) => position,
            None => {
                let shared = sender_shared_secret(secp, &a_sum, outpoints, &recipient.scan)?;
                groups.push((recipient.scan, shared, 0));
                groups.len() - 1
            }
        };
        let (_, shared, k) = &mut groups[position];
        if *k >= K_MAX {
            return Err(SendError::TooManyOutputs);
        }
        let t_k = output_tweak(shared, *k).ok_or(SendError::Hash)?;
        let output = recipient.spend.add_exp_tweak(secp, &t_k).map_err(|_| SendError::Hash)?;
        outputs.push(output.x_only_public_key().0);
        *k += 1;
    }
    Ok(outputs)
}

/// One output a scan found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoundOutput {
    pub output_key: XOnlyPublicKey,
    /// `t_k`. The output's secret is `b_spend + t_k`, see [`spend_key`].
    pub tweak: Scalar,
    pub k: u32,
}

/// Find the outputs among `output_keys` that pay `B_spend`, given the
/// transaction's [`public_tweak`]. Outputs for one scan key are found in
/// `k` order and the scan stops at the first `k` with no match, so a
/// match is removed from consideration before looking for the next.
pub fn scan<C: Verification>(
    secp: &Secp256k1<C>,
    scan_secret: &SecretKey,
    spend: &PublicKey,
    tweak: &PublicKey,
    output_keys: &[XOnlyPublicKey],
) -> Vec<FoundOutput> {
    let Ok(shared) = tweak.mul_tweak(secp, &Scalar::from(*scan_secret)) else {
        return Vec::new();
    };
    let mut remaining = output_keys.to_vec();
    let mut found = Vec::new();
    for k in 0..K_MAX {
        let Some(t_k) = output_tweak(&shared, k) else { break };
        let Ok(p_k) = spend.add_exp_tweak(secp, &t_k) else { break };
        let p_k = p_k.x_only_public_key().0;
        let Some(position) = remaining.iter().position(|key| *key == p_k) else { break };
        remaining.swap_remove(position);
        found.push(FoundOutput { output_key: p_k, tweak: t_k, k });
    }
    found
}

/// The secret key spending a found output.
pub fn spend_key(spend_secret: &SecretKey, found: &FoundOutput) -> Option<SecretKey> {
    spend_secret.add_tweak(&found.tweak).ok()
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::key::TapTweak;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Txid};

    use super::*;

    fn key(byte: u8) -> SecretKey { SecretKey::from_slice(&[byte; 32]).unwrap() }

    #[test]
    fn address_round_trips() {
        let secp = Secp256k1::new();
        let address = SpAddress { scan: key(1).public_key(&secp), spend: key(2).public_key(&secp) };
        let encoded = address.encode("sprt");
        assert!(encoded.starts_with("sprt1q"));
        let (hrp, decoded) = SpAddress::decode(&encoded).unwrap();
        assert_eq!(hrp.as_str(), "sprt");
        assert_eq!(decoded, address);
    }

    #[test]
    fn transaction_with_a_p2tr_input_is_found_and_spendable() {
        let secp = Secp256k1::new();
        let (b_scan, b_spend) = (key(0x10), key(0x20));
        let address =
            SpAddress { scan: b_scan.public_key(&secp), spend: b_spend.public_key(&secp) };

        // An odd-y taproot input exercises the negation both sides must agree on.
        let input_secret = (1u8..)
            .map(key)
            .find(|k| k.x_only_public_key(&secp).1 == bitcoin::secp256k1::Parity::Odd)
            .unwrap();
        let x_only = input_secret.x_only_public_key(&secp).0;
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(x_only.dangerous_assume_tweaked()),
        };
        let outpoint = OutPoint { txid: Txid::all_zeros(), vout: 3 };
        let secret = input_secret_key(&secp, &input_secret, InputKind::P2tr);
        let [output] = sender_outputs(&secp, &[secret], &[outpoint], &[address]).unwrap()[..]
            .try_into()
            .unwrap();

        let mut witness = Witness::new();
        witness.push([0u8; 64]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(output.dangerous_assume_tweaked()),
            }],
        };
        let tweak = transaction_tweak(&secp, &tx, &[prevout]).unwrap();
        let found = scan(&secp, &b_scan, &address.spend, &tweak, &[output]);
        assert_eq!(found.len(), 1);
        let sk = spend_key(&b_spend, &found[0]).unwrap();
        assert_eq!(sk.x_only_public_key(&secp).0, output);
    }
}
