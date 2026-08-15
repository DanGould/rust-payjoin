//! Silent payment derivation, demo-side.
//!
//! The unique fallback output each sender derives from the receiver's
//! published keys uses the BIP 352 shared-secret construction, done
//! directly with secp256k1 group operations. This is a demonstration
//! stub standing in for a wallet's silent payments implementation: it
//! covers exactly one payment output per transaction (k = 0) and reads
//! sender input keys from in-process wallets. It exists so the demo can
//! prove the recovery property — a receiver restored from seed finds
//! every fallback payment by scanning the chain — without new
//! dependencies.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};

/// The receiver's long-lived silent payment keys, both derived from
/// one seed so a restore only needs that seed.
pub struct SpKeys {
    b_scan: SecretKey,
    b_spend: SecretKey,
}

/// The two public keys a receiver publishes; everything a sender needs
/// to derive a fresh output only the receiver can find and spend.
#[derive(Clone, Copy)]
pub struct SpAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
}

impl SpKeys {
    pub fn from_seed(seed: &[u8]) -> Self {
        let b_scan = SecretKey::from_slice(&tagged_hash("SilentPaymentsDemo/scan", seed))
            .expect("hash output is a valid scalar with overwhelming probability");
        let b_spend = SecretKey::from_slice(&tagged_hash("SilentPaymentsDemo/spend", seed))
            .expect("hash output is a valid scalar with overwhelming probability");
        Self { b_scan, b_spend }
    }

    pub fn address(&self, secp: &Secp256k1<All>) -> SpAddress {
        SpAddress { scan: self.b_scan.public_key(secp), spend: self.b_spend.public_key(secp) }
    }

    /// Scan one transaction: with the sum of its eligible input public
    /// keys, recompute the shared secret and check whether any output
    /// pays the derived key. Returns the paying output index and the
    /// keypair that spends it.
    ///
    /// This is [`tweak_from_tx`] followed by [`Self::scan_with_tweak`]:
    /// everything the scan needs from the transaction itself is the
    /// 33-byte tweak and its taproot output keys, which is what lets a
    /// tweak index scan without the transaction.
    pub fn scan_tx(
        &self,
        secp: &Secp256k1<All>,
        tx: &Transaction,
        input_pubkeys: &[PublicKey],
    ) -> Option<(usize, Keypair)> {
        let tweak = tweak_from_tx(secp, tx, input_pubkeys)?;
        let outputs = taproot_output_keys(tx);
        let keys: Vec<XOnlyPublicKey> = outputs.iter().map(|(_, key)| *key).collect();
        let (index, keypair) = self.scan_with_tweak(secp, &tweak, &keys)?;
        Some((outputs[index].0, keypair))
    }

    /// The receiver half of the scan: ECDH the tweak against the scan
    /// key, derive the expected output key, and look for it among
    /// `output_keys`. Returns the position of the paying key in
    /// `output_keys` and the keypair that spends it.
    pub fn scan_with_tweak(
        &self,
        secp: &Secp256k1<All>,
        tweak: &PublicKey,
        output_keys: &[XOnlyPublicKey],
    ) -> Option<(usize, Keypair)> {
        let shared = tweak.mul_tweak(secp, &scalar(self.b_scan.secret_bytes()).ok()?).ok()?;
        let (expected, keypair) = self.derive_spend(secp, &shared)?;
        output_keys.iter().position(|key| *key == expected).map(|index| (index, keypair))
    }

    /// ECDH of an ephemeral public key against the scan key, used by
    /// the demo's board notification box.
    pub fn scan_shared_point(&self, secp: &Secp256k1<All>, eph: &PublicKey) -> Option<PublicKey> {
        eph.mul_tweak(secp, &scalar(self.b_scan.secret_bytes()).ok()?).ok()
    }

    fn derive_spend(
        &self,
        secp: &Secp256k1<All>,
        shared: &PublicKey,
    ) -> Option<(XOnlyPublicKey, Keypair)> {
        let t0 = shared_secret_tweak(shared)?;
        let spend_sk = self.b_spend.add_tweak(&t0).ok()?;
        let keypair = Keypair::from_secret_key(secp, &spend_sk);
        Some((keypair.x_only_public_key().0, keypair))
    }
}

/// The scan tweak of one transaction: `input_hash · A_sum`, the public
/// part of the BIP 352 shared secret. It needs no receiver keys, so a
/// third party can compute it for every transaction in a block and
/// serve the 33-byte results as an index; a receiver completes the
/// scan from those alone via [`SpKeys::scan_with_tweak`].
pub fn tweak_from_tx(
    secp: &Secp256k1<All>,
    tx: &Transaction,
    input_pubkeys: &[PublicKey],
) -> Option<PublicKey> {
    if input_pubkeys.is_empty() {
        return None;
    }
    let a_sum = sum_pubkeys(input_pubkeys)?;
    let outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
    let input_hash = input_hash(&outpoints, &a_sum)?;
    a_sum.mul_tweak(secp, &input_hash).ok()
}

/// The x-only keys of a transaction's taproot outputs, each with its
/// output index.
pub fn taproot_output_keys(tx: &Transaction) -> Vec<(usize, XOnlyPublicKey)> {
    tx.output
        .iter()
        .enumerate()
        .filter_map(|(vout, output)| {
            if !output.script_pubkey.is_p2tr() {
                return None;
            }
            XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..])
                .ok()
                .map(|key| (vout, key))
        })
        .collect()
}

/// Sender-side derivation: from the sender's own input keys and
/// outpoints, compute the output key only this (inputs, receiver) pair
/// produces.
pub fn sender_derive_output(
    secp: &Secp256k1<All>,
    input_keys: &[SecretKey],
    outpoints: &[OutPoint],
    address: &SpAddress,
) -> Option<XOnlyPublicKey> {
    let mut keys = input_keys.iter();
    let first = *keys.next()?;
    let a_sum =
        keys.try_fold(first, |acc, key| acc.add_tweak(&scalar(key.secret_bytes()).ok()?).ok())?;
    let a_pub_sum = a_sum.public_key(secp);
    let input_hash = input_hash(outpoints, &a_pub_sum)?;
    let shared = address
        .scan
        .mul_tweak(secp, &scalar(a_sum.mul_tweak(&input_hash).ok()?.secret_bytes()).ok()?)
        .ok()?;
    let t0 = shared_secret_tweak(&shared)?;
    let output = address.spend.add_exp_tweak(secp, &t0).ok()?;
    Some(output.x_only_public_key().0)
}

/// The taproot script paying a derived silent payment output key.
pub fn output_script(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(key.dangerous_assume_tweaked())
}

/// Eligible input public keys, read from P2WPKH witnesses (the only
/// input type demo wallets produce). A production scanner would cover
/// every eligible input type per BIP 352.
pub fn input_pubkeys_from_witnesses(tx: &Transaction) -> Vec<PublicKey> {
    tx.input
        .iter()
        .filter_map(|input| {
            let witness = &input.witness;
            if witness.len() != 2 {
                return None;
            }
            PublicKey::from_slice(witness.nth(1)?).ok()
        })
        .collect()
}

/// Sweep one derived output with a key-path spend.
pub fn sweep_keyspend(
    secp: &Secp256k1<All>,
    outpoint: OutPoint,
    prevout: &TxOut,
    keypair: &Keypair,
    destination: ScriptBuf,
    fee: Amount,
) -> Option<Transaction> {
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: prevout.value.checked_sub(fee)?, script_pubkey: destination }],
    };
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .ok()?;
    let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&msg, keypair);
    tx.input[0].witness.push(signature.as_ref());
    Some(tx)
}

fn sum_pubkeys(keys: &[PublicKey]) -> Option<PublicKey> {
    let refs: Vec<&PublicKey> = keys.iter().collect();
    PublicKey::combine_keys(&refs).ok()
}

/// BIP 352 input hash: committing to the smallest spent outpoint binds
/// the derivation to this transaction, so no two payments derive the
/// same output even from the same keys.
fn input_hash(outpoints: &[OutPoint], a_sum: &PublicKey) -> Option<Scalar> {
    let smallest = outpoints.iter().map(bitcoin::consensus::serialize).min()?;
    let mut msg = smallest;
    msg.extend_from_slice(&a_sum.serialize());
    scalar(tagged_hash("BIP0352/Inputs", &msg)).ok().map(Some)?
}

fn shared_secret_tweak(shared: &PublicKey) -> Option<Scalar> {
    let mut msg = shared.serialize().to_vec();
    msg.extend_from_slice(&0u32.to_be_bytes());
    scalar(tagged_hash("BIP0352/SharedSecret", &msg)).ok()
}

fn scalar(bytes: [u8; 32]) -> Result<Scalar, bitcoin::secp256k1::scalar::OutOfRangeError> {
    Scalar::from_be_bytes(bytes)
}

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_outpoint(n: u8) -> OutPoint {
        OutPoint { txid: bitcoin::Txid::from_byte_array([n; 32]), vout: u32::from(n) }
    }

    /// A transaction paying the receiver's derived output, with
    /// P2WPKH-shaped witnesses carrying the sender input keys.
    fn crafted_payment(
        secp: &Secp256k1<All>,
        address: &SpAddress,
    ) -> (Transaction, XOnlyPublicKey) {
        let input_keys = vec![
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
            SecretKey::from_slice(&[5u8; 32]).unwrap(),
        ];
        let outpoints = vec![fake_outpoint(1), fake_outpoint(2)];
        let output_key =
            sender_derive_output(secp, &input_keys, &outpoints, address).expect("derivation");
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: outpoints
                .iter()
                .zip(&input_keys)
                .map(|(outpoint, key)| {
                    let mut witness = Witness::new();
                    witness.push([0u8; 71]);
                    witness.push(key.public_key(secp).serialize());
                    TxIn {
                        previous_output: *outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness,
                    }
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: output_script(output_key),
            }],
        };
        (tx, output_key)
    }

    #[test]
    fn receiver_finds_and_can_spend_what_sender_derives() {
        let secp = Secp256k1::new();
        let receiver = SpKeys::from_seed(b"demo seed");
        let address = receiver.address(&secp);
        let (tx, output_key) = crafted_payment(&secp, &address);

        let pubkeys = input_pubkeys_from_witnesses(&tx);
        assert_eq!(pubkeys.len(), 2);
        let (vout, keypair) = receiver.scan_tx(&secp, &tx, &pubkeys).expect("scan finds payment");
        assert_eq!(vout, 0);
        assert_eq!(keypair.x_only_public_key().0, output_key);
    }

    #[test]
    fn scan_decomposes_into_tweak_then_key_match() {
        let secp = Secp256k1::new();
        let receiver = SpKeys::from_seed(b"demo seed");
        let address = receiver.address(&secp);
        let (tx, _) = crafted_payment(&secp, &address);
        let pubkeys = input_pubkeys_from_witnesses(&tx);

        // The tweak and the taproot output keys are all the scan needs
        // from the transaction: composing the two halves over them must
        // equal scanning the transaction directly.
        let tweak = tweak_from_tx(&secp, &tx, &pubkeys).expect("tweak");
        assert_eq!(tweak.serialize().len(), 33);
        let outputs = taproot_output_keys(&tx);
        let keys: Vec<XOnlyPublicKey> = outputs.iter().map(|(_, key)| *key).collect();
        let (index, keypair) =
            receiver.scan_with_tweak(&secp, &tweak, &keys).expect("tweak scan finds payment");
        let (vout, direct) = receiver.scan_tx(&secp, &tx, &pubkeys).expect("direct scan");
        assert_eq!(outputs[index].0, vout);
        assert_eq!(keypair.x_only_public_key().0, direct.x_only_public_key().0);

        // Keys that pay someone else never match.
        let stranger = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let stranger_key = stranger.x_only_public_key(&secp).0;
        assert!(receiver.scan_with_tweak(&secp, &tweak, &[stranger_key]).is_none());
    }

    #[test]
    fn different_outpoints_derive_different_outputs() {
        let secp = Secp256k1::new();
        let receiver = SpKeys::from_seed(b"demo seed");
        let address = receiver.address(&secp);
        let keys = vec![SecretKey::from_slice(&[7u8; 32]).unwrap()];
        let first = sender_derive_output(&secp, &keys, &[fake_outpoint(1)], &address).unwrap();
        let second = sender_derive_output(&secp, &keys, &[fake_outpoint(2)], &address).unwrap();
        assert_ne!(first, second, "reusing keys must still derive per-payment outputs");
    }
}
