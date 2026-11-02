//! BIP 352 derivation as both sides of a silent payjoin use it: the sender
//! derives the receiver's outputs to check a proposal, and the receiver scans
//! for its outputs and re-derives them over the inputs of the payjoin.

use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut};
use spj_crypto::{bip352, tagged_hash};

use crate::sp_address::SpAddress;

/// The P2TR script paying output key `key` directly. Silent payment outputs
/// are already tweaked, so no BIP 341 tweak is applied.
pub fn p2tr_script(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

/// The scripts of the outputs `k = 0..n` paying `spend` under shared secret
/// `ecdh`. `None` only for a hash that isn't a valid scalar.
pub fn output_scripts(
    secp: &Secp256k1<All>,
    ecdh: &PublicKey,
    spend: &PublicKey,
    n: u32,
) -> Option<Vec<ScriptBuf>> {
    (0..n)
        .map(|k| {
            let t_k = bip352::output_tweak(ecdh, k)?;
            let key = spend.add_exp_tweak(secp, &t_k).ok()?;
            Some(p2tr_script(key.x_only_public_key().0))
        })
        .collect()
}

/// The x-only keys of a transaction's taproot outputs, with their indices.
pub fn taproot_outputs(tx: &Transaction) -> Vec<(usize, XOnlyPublicKey)> {
    tx.output
        .iter()
        .enumerate()
        .filter(|(_, out)| out.script_pubkey.is_p2tr())
        .filter_map(|(vout, out)| {
            XOnlyPublicKey::from_slice(&out.script_pubkey.as_bytes()[2..]).ok().map(|k| (vout, k))
        })
        .collect()
}

/// The sum of `keys`, or `None` for an empty list or the point at infinity.
pub fn sum(keys: &[PublicKey]) -> Option<PublicKey> {
    let refs: Vec<&PublicKey> = keys.iter().collect();
    PublicKey::combine_keys(&refs).ok()
}

/// A receiver's BIP 352 secrets.
#[derive(Clone, Copy)]
pub struct SpKeys {
    pub scan: SecretKey,
    pub spend: SecretKey,
}

impl SpKeys {
    /// The keys a wallet restored from `seed` would hold.
    pub fn from_seed(seed: &str) -> Self {
        let key = |role: &str| {
            SecretKey::from_slice(&tagged_hash(
                "spj-demo/sp-key",
                format!("{seed}/{role}").as_bytes(),
            ))
            .expect("a hash is a valid secret key with overwhelming probability")
        };
        Self { scan: key("scan"), spend: key("spend") }
    }

    pub fn address(&self, secp: &Secp256k1<All>) -> SpAddress {
        SpAddress::new(self.scan.public_key(secp), self.spend.public_key(secp), Network::Regtest)
    }
}

/// An output of the Original that pays the receiver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub vout: usize,
    pub k: u32,
    pub value: Amount,
}

/// The outputs of `tx` that pay `keys`, by the same scan a restore runs.
pub fn scan(
    secp: &Secp256k1<All>,
    keys: &SpKeys,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Vec<Found> {
    let Some(tweak) = bip352::transaction_tweak(secp, tx, prevouts) else { return Vec::new() };
    let outputs = taproot_outputs(tx);
    let output_keys: Vec<_> = outputs.iter().map(|(_, key)| *key).collect();
    bip352::scan(secp, &keys.scan, &keys.spend.public_key(secp), &tweak, &output_keys)
        .into_iter()
        .map(|hit| {
            let (vout, _) =
                outputs.iter().find(|(_, key)| *key == hit.output_key).expect("scanned key");
            Found { vout: *vout, k: hit.k, value: tx.output[*vout].value }
        })
        .collect()
}

/// The receiver's outputs `k = 0..n` for a transaction spending `outpoints`
/// whose eligible inputs have keys `input_keys`: `B_spend + t_k·G` from
/// `b_scan·input_hash·A`.
pub fn receiver_outputs(
    secp: &Secp256k1<All>,
    keys: &SpKeys,
    input_keys: &[PublicKey],
    outpoints: &[OutPoint],
    n: u32,
) -> Option<Vec<ScriptBuf>> {
    let tweak = bip352::public_tweak(secp, outpoints, input_keys)?;
    let ecdh = tweak.mul_tweak(secp, &Scalar::from(keys.scan)).ok()?;
    output_scripts(secp, &ecdh, &keys.spend.public_key(secp), n)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{absolute, transaction, Txid, Witness};

    use super::*;

    /// A sender's derivation and the receiver's, from public data and its
    /// scan key, give the same output, and a scan finds it.
    #[test]
    fn sender_and_receiver_derive_the_same_output() {
        let secp = Secp256k1::new();
        let keys = SpKeys::from_seed("derive test");
        let input = SecretKey::from_slice(&[7; 32]).unwrap();
        let bip352_input = bip352::input_secret_key(&secp, &input, bip352::InputKind::P2tr);
        let outpoint = OutPoint { txid: Txid::all_zeros(), vout: 3 };
        let address = keys.address(&secp);
        let recipient = bip352::SpAddress { scan: address.scan, spend: address.spend };
        let sent =
            bip352::sender_outputs(&secp, &[bip352_input], &[outpoint], &[recipient]).unwrap();
        let derived =
            receiver_outputs(&secp, &keys, &[bip352_input.public_key(&secp)], &[outpoint], 1)
                .unwrap();
        assert_eq!(derived, vec![p2tr_script(sent[0])]);

        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: p2tr_script(input.x_only_public_key(&secp).0),
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: outpoint,
                witness: Witness::from_slice(&[[0u8; 64]]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: derived[0].clone(),
            }],
        };
        assert_eq!(
            scan(&secp, &keys, &tx, &[prevout]),
            vec![Found { vout: 0, k: 0, value: Amount::from_sat(9_000) }]
        );
    }
}
