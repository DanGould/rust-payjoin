//! Scene 7: lazy audit from a tweak index. With the mailbox doing
//! payment detection, chain scanning is left with audit and repair:
//! senders who only ever had the bare address, restores beyond the
//! mailbox retention window, directory outage. A tweak index makes
//! that job one ECDH per eligible transaction, with no block downloads
//! until something is found.

use bitcoin::{Amount, FeeRate, OutPoint};

use super::{build_tweak_index, sweep_to_wallet, BoxError, Demo};
use crate::wallet::DemoWallet;
use crate::{index, sp};

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        7,
        "Lazy audit from a tweak index",
        "Cooperating senders are detected in the mailbox, so scanning \
         becomes an audit job. A sender holding only the bare address \
         pays on chain; a receiver restored from seed finds the payment \
         from a flat tweak index, one ECDH per eligible transaction, \
         and fetches exactly one block to claim it.",
    );

    demo.narrator.step(
        "Oscar holds only the bare silent payment address: no payjoin \
         endpoint, no mailbox, no notice",
    );
    let mut oscar = DemoWallet::new(&demo.secp, "Oscar");
    oscar.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;
    let amount = Amount::from_btc(0.45)?;
    let (outpoint, prevout) = oscar
        .select_utxo(amount + Amount::from_sat(2_000))
        .ok_or("Oscar lacks a large enough coin")?;
    let output_key =
        sp::sender_derive_output(&demo.secp, &oscar.input_keys(), &[outpoint], &demo.sp_address)
            .ok_or("silent payment derivation failed")?;
    let psbt = oscar.build_original_from(
        outpoint,
        &prevout,
        sp::output_script(output_key),
        amount,
        FeeRate::BROADCAST_MIN,
    )?;
    let tx = psbt.extract_tx()?;
    demo.broadcast(&tx)?;
    demo.mine(1)?;
    oscar.credit_outputs(&tx);
    demo.narrator.result("on-chain payment", &tx.compute_txid().to_string());
    demo.narrator.note("no notice exists for this payment; only scanning can find it");

    demo.narrator
        .step("an indexer with chain access walks the blocks once and emits the tweak index");
    let build = build_tweak_index(demo)?;
    let index_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts").join("tweak-index.bin");
    let index_bytes = index::write_index(&index_path, &build.records)?;
    demo.narrator.result("blocks walked", &build.blocks.to_string());
    demo.narrator.result("eligible transactions indexed", &build.records.len().to_string());
    demo.narrator.result("entries dropped as fully spent (cut-through)", &build.cut.to_string());
    demo.narrator.result("index file", "artifacts/tweak-index.bin");
    demo.narrator.note(
        "each record is a transaction's 33-byte tweak plus its taproot \
         output keys, the record shape deployed tweak servers hand light \
         clients. This indexer is a toy standing in for that \
         infrastructure, like the demo's other silent payment code",
    );

    demo.narrator.step(
        "a receiver restored from seed audits the index alone: one ECDH \
         per record, no block downloads",
    );
    let records = index::read_index(&index_path)?;
    let mut ecdh_ops = 0;
    let mut matches = Vec::new();
    for record in &records {
        ecdh_ops += 1;
        if demo.sp_keys.scan_with_tweak(&demo.secp, &record.tweak, &record.output_keys).is_some() {
            matches.push(record);
        }
    }
    demo.narrator.result("records scanned", &records.len().to_string());
    demo.narrator.result("unclaimed payments found", &matches.len().to_string());

    demo.narrator.step("fetch the one matching block and build the claim");
    let mut blocks_fetched = 0;
    let mut swept = Vec::new();
    let mut sweep_ok = true;
    for record in &matches {
        let hash = demo.bitcoind.client.get_block_hash(u64::from(record.height))?.into_model()?.0;
        let block = demo.bitcoind.client.get_block(hash)?;
        blocks_fetched += 1;
        let found = block
            .txdata
            .iter()
            .find(|candidate| candidate.compute_txid() == record.txid)
            .ok_or("indexed transaction missing from its block")?;
        let (vout, keypair) = demo
            .sp_keys
            .scan_tx(&demo.secp, found, &sp::input_pubkeys_from_witnesses(found))
            .ok_or("full transaction data must confirm the index match")?;
        let claim = OutPoint { txid: record.txid, vout: vout as u32 };
        match sweep_to_wallet(demo, claim, &found.output[vout], &keypair) {
            Ok(txid) => {
                demo.narrator.result("sweep txid", &txid.to_string());
                swept.push(record.txid);
            }
            Err(e) => {
                sweep_ok = false;
                demo.narrator.result("sweep failed", &e.to_string());
            }
        }
    }

    demo.narrator.ledger(
        "lazy audit",
        &[
            ("index bytes".into(), index_bytes.to_string()),
            ("full-chain bytes, same range".into(), build.chain_bytes.to_string()),
            ("records scanned".into(), records.len().to_string()),
            ("ECDH operations".into(), ecdh_ops.to_string()),
            ("unclaimed payments found".into(), matches.len().to_string()),
            ("blocks fetched to claim".into(), blocks_fetched.to_string()),
        ],
    );
    demo.narrator.note(
        "mainnet economics, quoted rather than demonstrated: Sparrow's \
         Frigate server publishes measured benchmarks of 127,804 eligible \
         transactions in a day of mainnet, a tweak feed of about 4.2 MB \
         per day at 33 bytes each, and a full day scanned end to end in \
         2.7 seconds on a laptop CPU",
    );

    let pass = matches.len() == 1
        && swept == vec![tx.compute_txid()]
        && blocks_fetched == 1
        && index_bytes < build.chain_bytes
        && sweep_ok;
    demo.narrator.verdict(
        pass,
        "the restored receiver found the one payment the mailbox could \
         never know about by reading a flat index a fraction of the \
         chain's size, and downloaded exactly one block to claim it.",
    );
    if !pass {
        return Err("scene 7 assertions failed".into());
    }
    Ok(())
}
