//! What the demo reads from its regtest node: transactions, prevouts,
//! confirmation state, and a per-transaction tweak index.
//!
//! The tweak index is what a BlindBit-style server publishes for light
//! silent payment wallets: for every transaction a scan could match, the
//! public tweak `input_hash·A` and its taproot outputs. A wallet restored
//! from its seed checks each entry with its scan key and spend key alone,
//! and the labels it searches for, which is how the demo decides whether
//! a restore finds a payment.

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Amount, BlockHash, OutPoint, Transaction, TxOut, Txid};
use payjoin_test_utils::bitcoind;
use serde_json::{json, Value};
use spj_crypto::bip352::{self, Labels};

use crate::derive;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A transaction by id: from the mempool, a wallet, or with `-txindex` any
/// confirmed one.
pub fn raw_tx(node: &bitcoind::Client, txid: Txid) -> Result<Transaction, Error> {
    let hex: String = node.call("getrawtransaction", &[json!(txid), json!(false)])?;
    Ok(deserialize_hex(&hex)?)
}

/// The outputs `tx` spends, in input order.
pub fn prevouts(node: &bitcoind::Client, tx: &Transaction) -> Result<Vec<TxOut>, Error> {
    tx.input
        .iter()
        .map(|input| {
            let parent = raw_tx(node, input.previous_output.txid)?;
            parent
                .output
                .get(input.previous_output.vout as usize)
                .cloned()
                .ok_or_else(|| "prevout index out of range".into())
        })
        .collect()
}

/// The outputs `tx` spends if every one is unspent in the node's UTXO set,
/// mempool included. `None` if any is spent or never existed.
pub fn unspent_prevouts(
    node: &bitcoind::Client,
    tx: &Transaction,
) -> Result<Option<Vec<TxOut>>, Error> {
    let mut prevouts = Vec::with_capacity(tx.input.len());
    for input in &tx.input {
        let OutPoint { txid, vout } = input.previous_output;
        let utxo: Value = node.call("gettxout", &[json!(txid), json!(vout), json!(true)])?;
        if utxo.is_null() {
            return Ok(None);
        }
        let amount = Amount::from_btc(utxo["value"].as_f64().ok_or("gettxout value")?)?;
        let script = utxo["scriptPubKey"]["hex"].as_str().ok_or("gettxout script")?;
        prevouts
            .push(TxOut { value: amount, script_pubkey: bitcoin::ScriptBuf::from_hex(script)? });
    }
    Ok(Some(prevouts))
}

/// Broadcast through the node. The error is the node's reason for refusing.
pub fn broadcast(node: &bitcoind::Client, tx: &Transaction) -> Result<Txid, Error> {
    let txid: Txid = node.call("sendrawtransaction", &[json!(serialize_hex(tx))])?;
    Ok(txid)
}

/// Whether `tx` would enter the node's mempool.
pub fn mempool_accepts(node: &bitcoind::Client, tx: &Transaction) -> Result<bool, Error> {
    let result: Value = node.call("testmempoolaccept", &[json!([serialize_hex(tx)])])?;
    Ok(result[0]["allowed"].as_bool().unwrap_or(false))
}

/// `Some(0)` in the mempool, `Some(n)` with n confirmations, `None` if the
/// node knows neither. Needs `-txindex` for transactions outside its wallets.
pub fn confirmations(node: &bitcoind::Client, txid: Txid) -> Result<Option<u64>, Error> {
    let entry: Result<Value, _> = node.call("getmempoolentry", &[json!(txid)]);
    if entry.is_ok() {
        return Ok(Some(0));
    }
    match node.call::<Value>("getrawtransaction", &[json!(txid), json!(true)]) {
        Ok(tx) => Ok(tx["confirmations"].as_u64().filter(|n| *n > 0)),
        Err(_) => Ok(None),
    }
}

/// Mine `blocks` blocks paying `to`.
pub fn mine(node: &bitcoind::Client, blocks: u64, to: &Address) -> Result<Vec<BlockHash>, Error> {
    Ok(node.call("generatetoaddress", &[json!(blocks), json!(to.to_string())])?)
}

pub fn height(node: &bitcoind::Client) -> Result<u64, Error> {
    Ok(node.call("getblockcount", &[])?)
}

/// The transactions of the block at `height`.
pub fn block(node: &bitcoind::Client, height: u64) -> Result<Vec<Transaction>, Error> {
    let hash: BlockHash = node.call("getblockhash", &[json!(height)])?;
    let hex: String = node.call("getblock", &[json!(hash), json!(0)])?;
    let block: bitcoin::Block = deserialize_hex(&hex)?;
    Ok(block.txdata)
}

/// One transaction a silent payment scan could match.
#[derive(Clone, Debug)]
pub struct TweakEntry {
    pub height: u64,
    pub txid: Txid,
    pub tweak: PublicKey,
    /// Taproot outputs: index, key and value.
    pub outputs: Vec<(u32, XOnlyPublicKey, Amount)>,
}

/// The tweak index over blocks `from..=to`.
pub fn tweak_index(
    secp: &Secp256k1<All>,
    node: &bitcoind::Client,
    from: u64,
    to: u64,
) -> Result<Vec<TweakEntry>, Error> {
    let mut index = Vec::new();
    for height in from..=to {
        for tx in block(node, height)? {
            if tx.is_coinbase() {
                continue;
            }
            let outputs = derive::taproot_outputs(&tx);
            if outputs.is_empty() {
                continue;
            }
            let prevouts = prevouts(node, &tx)?;
            let Some(tweak) = bip352::transaction_tweak(secp, &tx, &prevouts) else { continue };
            index.push(TweakEntry {
                height,
                txid: tx.compute_txid(),
                tweak,
                outputs: outputs
                    .into_iter()
                    .map(|(vout, key)| (vout as u32, key, tx.output[vout].value))
                    .collect(),
            });
        }
    }
    Ok(index)
}

/// An output a restore found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restored {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub k: u32,
    /// The label it pays, or `None` for the unlabelled address.
    pub label: Option<u32>,
}

/// How many labels past the highest one found a restore searches for.
///
/// Backup words hold the keys, not how many labels the wallet handed out,
/// and a restore only finds outputs on labels it searches for. 20 is BIP
/// 44's address gap limit, with the same trade-off: after more than 20
/// contacts in a row that never pay, a restore misses what the next ones
/// send. A full-node scan pays at most one point addition per label
/// per transaction, but a light client tests one candidate key per label
/// against block filters, and pays per label in downloads and false
/// positives, which is what keeps the number small.
pub const LABEL_LOOKAHEAD: u32 = 20;

/// What a wallet restored from `scan_secret` and `spend` finds in `index`.
///
/// It searches labels `0..=LABEL_LOOKAHEAD`, and each time it finds one
/// higher than any before, widens the search to that label plus
/// [`LABEL_LOOKAHEAD`] and scans again.
pub fn restore(
    secp: &Secp256k1<All>,
    scan_secret: &SecretKey,
    spend: &PublicKey,
    index: &[TweakEntry],
) -> Vec<Restored> {
    let mut searched = LABEL_LOOKAHEAD;
    loop {
        let labels = Labels::new(secp, scan_secret, 0..=searched);
        let found = scan_index(secp, scan_secret, spend, &labels, index);
        let highest = found.iter().filter_map(|f| f.label).max().unwrap_or(0);
        match highest.checked_add(LABEL_LOOKAHEAD) {
            Some(wider) if wider > searched => searched = wider,
            _ => return found,
        }
    }
}

/// What a wallet holding `scan_secret` and `spend` and searching for
/// `labels` finds in `index`.
pub fn scan_index(
    secp: &Secp256k1<All>,
    scan_secret: &SecretKey,
    spend: &PublicKey,
    labels: &Labels,
    index: &[TweakEntry],
) -> Vec<Restored> {
    let mut found = Vec::new();
    for entry in index {
        let keys: Vec<XOnlyPublicKey> = entry.outputs.iter().map(|(_, key, _)| *key).collect();
        for hit in bip352::scan(secp, scan_secret, spend, &entry.tweak, &keys, labels) {
            let (vout, _, value) = entry
                .outputs
                .iter()
                .find(|(_, key, _)| *key == hit.output_key)
                .expect("scan only returns keys it was given");
            found.push(Restored {
                outpoint: OutPoint { txid: entry.txid, vout: *vout },
                value: *value,
                k: hit.k,
                label: hit.label,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Scalar;

    use super::*;
    use crate::derive::SpKeys;

    /// One transaction paying `keys` on label `m`, or unlabelled, at `k = 0`.
    fn paying(secp: &Secp256k1<All>, keys: &SpKeys, n: u8, m: Option<u32>) -> TweakEntry {
        let tweak = SecretKey::from_slice(&[n; 32]).unwrap().public_key(secp);
        let ecdh = tweak.mul_tweak(secp, &Scalar::from(keys.scan)).unwrap();
        let t_0 = bip352::output_tweak(&ecdh, 0).unwrap();
        let output = keys.spend_for(secp, m).unwrap().add_exp_tweak(secp, &t_0).unwrap();
        TweakEntry {
            height: n.into(),
            txid: Txid::from_byte_array([n; 32]),
            tweak,
            outputs: vec![(0, output.x_only_public_key().0, Amount::from_sat(1_000))],
        }
    }

    /// A restore finds the unlabelled address and labels within the
    /// lookahead of the highest one it has found, however far that has
    /// climbed, and none beyond.
    #[test]
    fn restore_searches_past_each_label_it_finds() {
        let secp = Secp256k1::new();
        let keys = SpKeys::from_seed("restore test");
        let spend = keys.spend.public_key(&secp);
        let reach = LABEL_LOOKAHEAD;
        let index: Vec<TweakEntry> =
            [(1, None), (2, Some(reach)), (3, Some(2 * reach)), (4, Some(3 * reach + 1))]
                .into_iter()
                .map(|(n, m)| paying(&secp, &keys, n, m))
                .collect();
        let labels: Vec<_> =
            restore(&secp, &keys.scan, &spend, &index).iter().map(|f| f.label).collect();
        assert_eq!(labels, [None, Some(reach), Some(2 * reach)]);
    }
}
