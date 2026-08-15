//! Toy silent payment tweak index.
//!
//! One record per eligible transaction: height, txid, the 33-byte scan
//! tweak, and the taproot output keys. This is the record shape silent
//! payment light clients consume from tweak servers: an indexer with
//! chain access computes the public half of every scan once, and a
//! receiver completes detection from the records alone, one ECDH per
//! record, downloading no block data until it finds a match. It is a
//! toy in the same sense as the rest of this demo's silent payment
//! code: it reads only the input types the demo wallets produce and
//! exists to demonstrate the shape, not to serve as a protocol.

use std::path::Path;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::{Transaction, Txid, XOnlyPublicKey};

use crate::sp;

type BoxError = Box<dyn std::error::Error>;

/// Everything a scan needs from one eligible transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TweakRecord {
    pub height: u32,
    pub txid: Txid,
    pub tweak: PublicKey,
    pub output_keys: Vec<XOnlyPublicKey>,
}

/// The index record for one transaction, or nothing when the
/// transaction cannot pay a silent payment: no eligible input keys to
/// sum, or no taproot output to pay one to.
pub fn record_from_tx(secp: &Secp256k1<All>, height: u32, tx: &Transaction) -> Option<TweakRecord> {
    let input_pubkeys = sp::input_pubkeys_from_witnesses(tx);
    if input_pubkeys.is_empty() {
        return None;
    }
    let output_keys: Vec<XOnlyPublicKey> =
        sp::taproot_output_keys(tx).into_iter().map(|(_, key)| key).collect();
    if output_keys.is_empty() {
        return None;
    }
    let tweak = sp::tweak_from_tx(secp, tx, &input_pubkeys)?;
    Some(TweakRecord { height, txid: tx.compute_txid(), tweak, output_keys })
}

/// Write records to a flat file and return its size in bytes. Each
/// record is height (4 bytes little endian), txid (32), tweak (33),
/// output key count (1), then 32 bytes per key.
pub fn write_index(path: &Path, records: &[TweakRecord]) -> Result<u64, BoxError> {
    let mut buf = Vec::new();
    for record in records {
        buf.extend_from_slice(&record.height.to_le_bytes());
        buf.extend_from_slice(&record.txid.to_byte_array());
        buf.extend_from_slice(&record.tweak.serialize());
        buf.push(u8::try_from(record.output_keys.len()).map_err(|_| "too many taproot outputs")?);
        for key in &record.output_keys {
            buf.extend_from_slice(&key.serialize());
        }
    }
    std::fs::write(path, &buf)?;
    Ok(buf.len() as u64)
}

/// Read an index file back into records.
pub fn read_index(path: &Path) -> Result<Vec<TweakRecord>, BoxError> {
    let bytes = std::fs::read(path)?;
    let mut cursor = &bytes[..];
    let mut records = Vec::new();
    while !cursor.is_empty() {
        let height = u32::from_le_bytes(take(&mut cursor, 4)?.try_into()?);
        let txid = Txid::from_byte_array(take(&mut cursor, 32)?.try_into()?);
        let tweak = PublicKey::from_slice(take(&mut cursor, 33)?)?;
        let count = usize::from(take(&mut cursor, 1)?[0]);
        let mut output_keys = Vec::with_capacity(count);
        for _ in 0..count {
            output_keys.push(XOnlyPublicKey::from_slice(take(&mut cursor, 32)?)?);
        }
        records.push(TweakRecord { height, txid, tweak, output_keys });
    }
    Ok(records)
}

fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8], BoxError> {
    if cursor.len() < n {
        return Err("truncated index record".into());
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    use super::*;

    fn eligible_tx(secp: &Secp256k1<All>, taproot_outputs: usize) -> Transaction {
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let mut witness = Witness::new();
        witness.push([0u8; 71]);
        witness.push(key.public_key(secp).serialize());
        let output = |n: u8| {
            let output_key = SecretKey::from_slice(&[n; 32]).unwrap().x_only_public_key(secp).0;
            TxOut { value: Amount::from_sat(50_000), script_pubkey: sp::output_script(output_key) }
        };
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: (2..2 + taproot_outputs as u8).map(output).collect(),
        }
    }

    #[test]
    fn eligible_transaction_yields_a_record() {
        let secp = Secp256k1::new();
        let tx = eligible_tx(&secp, 2);
        let record = record_from_tx(&secp, 42, &tx).expect("eligible");
        assert_eq!(record.height, 42);
        assert_eq!(record.txid, tx.compute_txid());
        assert_eq!(record.output_keys.len(), 2);
        let pubkeys = sp::input_pubkeys_from_witnesses(&tx);
        assert_eq!(Some(record.tweak), sp::tweak_from_tx(&secp, &tx, &pubkeys));
    }

    #[test]
    fn ineligible_transactions_yield_nothing() {
        let secp = Secp256k1::new();

        // No taproot output to pay a silent payment to.
        let mut no_taproot = eligible_tx(&secp, 1);
        no_taproot.output[0].script_pubkey = ScriptBuf::new();
        assert!(record_from_tx(&secp, 0, &no_taproot).is_none());

        // No witness carrying an eligible input key.
        let mut no_keys = eligible_tx(&secp, 1);
        no_keys.input[0].witness = Witness::new();
        assert!(record_from_tx(&secp, 0, &no_keys).is_none());
    }

    #[test]
    fn records_round_trip_through_the_flat_file() {
        let secp = Secp256k1::new();
        let records: Vec<TweakRecord> = (1..=3)
            .map(|n| record_from_tx(&secp, n, &eligible_tx(&secp, n as usize)).expect("eligible"))
            .collect();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tweaks.bin");
        let written = write_index(&path, &records).expect("write");
        assert_eq!(written, std::fs::metadata(&path).expect("metadata").len());
        assert_eq!(read_index(&path).expect("read"), records);
    }
}
