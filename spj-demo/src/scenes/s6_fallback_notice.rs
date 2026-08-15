//! Scene 6: the fallback notice. When patience runs out the sender
//! broadcasts the original and posts the same fully signed transaction
//! back to the queue, so the receiver's next drain detects the settled
//! payment without scanning any chain transaction. Verification is the
//! same silent payment math applied to one candidate: a notice whose
//! transaction pays anyone else is rejected.

use std::time::Duration;

use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction};
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::static_session::StaticSessionEvent as ReceiverStaticEvent;
use payjoin::send::v2::static_session::{
    StaticSenderBuilder, StaticSessionEvent as SenderStaticEvent,
};
use payjoin::Uri;

use super::{
    fall_back, original_tx_from_proposal, send_message_a, sweep_to_wallet, uri_with_address,
    BoxError, Demo, RELAY_URL,
};
use crate::persist::JsonlPersister;
use crate::sp;
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        6,
        "The fallback notice",
        "A sender whose patience runs out broadcasts the original and \
         posts the same signed transaction back to the queue. The \
         receiver detects the settled payment from its mailbox alone, \
         scanning zero chain transactions, and the math that finds it \
         rejects a notice paying anyone else.",
    );

    demo.publish_endpoint()?;

    let mut ivan = DemoWallet::new(&demo.secp, "Ivan");
    ivan.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;

    demo.narrator.step("Ivan pays the string; the receiver is away");
    let payment =
        send_message_a(demo, &ivan, Amount::from_btc(0.35)?, Some(Duration::from_secs(1))).await?;
    let sp_script = payment.sp_script.clone();
    let original_psbt = payment.original_psbt.clone();

    demo.narrator.step("patience runs out: Ivan broadcasts the original, a plain silent payment");
    std::thread::sleep(Duration::from_millis(1200));
    let fallback = fall_back(demo, &mut ivan, payment).await?;
    demo.narrator.result("fallback txid", &fallback.compute_txid().to_string());

    demo.narrator.step(
        "at broadcast time Ivan also posts the signed transaction to the \
         same queue as a fallback notice",
    );
    post_notice(demo, original_psbt, &sp_script, "notice-ivan").await?;
    demo.narrator.result("notice", "posted");
    demo.narrator.note(
        "nothing new rides the wire: the notice is the same fully signed \
         original, posted through the same client path and under the same \
         admission as the payment attempt",
    );

    demo.narrator
        .step("an attacker posts a well-formed notice whose transaction pays the attacker");
    let mut judy = DemoWallet::new(&demo.secp, "Judy");
    judy.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;
    let foreign_txid = post_foreign_notice(demo, &judy).await?;
    demo.narrator.result("foreign notice", &format!("posted, carrying {foreign_txid}"));

    demo.narrator.step("the receiver wakes and drains its queue; no chain scan is running");
    let proposals = demo.receiver_poll().await?;
    let frames = frames_processed(demo)?;
    let mut candidates: Vec<Transaction> = Vec::new();
    for (i, proposal) in proposals.into_iter().enumerate() {
        let tx = original_tx_from_proposal(demo, proposal, &format!("notice-{i}"))?;
        if !candidates.iter().any(|c| c.compute_txid() == tx.compute_txid()) {
            candidates.push(tx);
        }
    }
    demo.narrator.result("mailbox frames processed", &frames.to_string());
    demo.narrator.result("distinct candidate transactions", &candidates.len().to_string());
    demo.narrator.note(
        "the payment attempt and the notice carry the same transaction, so \
         they collapse into one candidate by txid",
    );

    demo.narrator.step(
        "apply the scanning math to each candidate alone, then one \
         targeted lookup for the match",
    );
    let mut detected = Vec::new();
    let mut rejected = 0;
    let mut lookups = 0;
    for tx in &candidates {
        let Some((vout, keypair)) =
            demo.sp_keys.scan_tx(&demo.secp, tx, &sp::input_pubkeys_from_witnesses(tx))
        else {
            rejected += 1;
            continue;
        };
        let outpoint = OutPoint { txid: tx.compute_txid(), vout: vout as u32 };
        lookups += 1;
        let utxo: serde_json::Value = demo.miner.call(
            "gettxout",
            &[serde_json::json!(outpoint.txid.to_string()), serde_json::json!(outpoint.vout)],
        )?;
        if utxo.is_null() {
            continue;
        }
        let confirmations = utxo["confirmations"].as_u64().unwrap_or(0);
        demo.narrator.result(
            "payment detected",
            &format!(
                "{} pays {} ({confirmations} confirmation(s))",
                outpoint.txid, tx.output[vout].value
            ),
        );
        detected.push((outpoint, tx.output[vout].clone(), keypair));
    }
    demo.narrator.result("foreign candidates rejected", &rejected.to_string());

    demo.narrator.step("the receiver records the payment and sweeps it into its wallet");
    let mut sweep_ok = true;
    for (outpoint, prevout, keypair) in &detected {
        match sweep_to_wallet(demo, *outpoint, prevout, keypair) {
            Ok(txid) => demo.narrator.result("sweep txid", &txid.to_string()),
            Err(e) => {
                sweep_ok = false;
                demo.narrator.result("sweep failed", &e.to_string());
            }
        }
    }

    demo.narrator.ledger(
        "fallback notice",
        &[
            ("mailbox frames processed".into(), frames.to_string()),
            ("distinct candidate transactions".into(), candidates.len().to_string()),
            ("payments detected".into(), detected.len().to_string()),
            ("foreign notices rejected".into(), rejected.to_string()),
            ("chain transactions scanned".into(), "0".into()),
            ("targeted chain lookups (gettxout)".into(), lookups.to_string()),
            ("blocks downloaded".into(), "0".into()),
        ],
    );

    let pass = frames == 3
        && candidates.len() == 2
        && detected.len() == 1
        && detected[0].0.txid == fallback.compute_txid()
        && rejected == 1
        && lookups == 1
        && sweep_ok;
    demo.narrator.verdict(
        pass,
        "the receiver detected and claimed a settled payment from its \
         mailbox alone. A notice is self-verifying: one that fails the \
         math is dropped for free, and one that passes is not a forgery \
         but a payment.",
    );
    if !pass {
        return Err("scene 6 assertions failed".into());
    }
    Ok(())
}

/// How many queue frames the receiver's current session has handled:
/// every skipped frame plus every retrieved proposal in its log.
fn frames_processed(demo: &Demo) -> Result<usize, BoxError> {
    Ok(demo
        .receiver_log
        .load()?
        .filter(|event| {
            matches!(
                event,
                ReceiverStaticEvent::SkippedUndecryptable(_)
                    | ReceiverStaticEvent::SkippedInvalidPayload(_)
                    | ReceiverStaticEvent::RetrievedProposal { .. }
            )
        })
        .count())
}

/// Post a fully signed original to the receiver's queue as a fallback
/// notice, through the stock sender path.
async fn post_notice(
    demo: &mut Demo,
    psbt: Psbt,
    payment_script: &ScriptBuf,
    label: &str,
) -> Result<(), BoxError> {
    let pay_to = Address::from_script(payment_script, Network::Regtest)?;
    let uri = uri_with_address(&demo.static_uri, &pay_to)?;
    let uri = Uri::try_from(uri.as_str())
        .map_err(|e| format!("notice uri: {e}"))?
        .assume_checked()
        .check_pj_supported()
        .map_err(|e| format!("notice uri lost payjoin support: {e}"))?;
    let log = JsonlPersister::<SenderStaticEvent>::new(
        demo.state_dir.join(format!("sender-{label}.jsonl")),
    );
    let sender = StaticSenderBuilder::new(psbt, uri)
        .build_recommended(FeeRate::BROADCAST_MIN)?
        .save(&log)?;
    let (req, ctx) = sender.create_v2_post_request(RELAY_URL)?;
    let body = demo.mailroom.deliver(&req).await?;
    sender
        .process_response(&body, ctx)
        .save(&log)
        .map_err(|e| format!("posting notice failed: {e:?}"))?;
    Ok(())
}

/// A plausible-looking notice from an attacker: a real signed
/// transaction that pays the attacker's own key. It clears every
/// client-side check because the attacker also writes the address slot
/// of the URI it validates against; only the receiver's derivation
/// check can tell it is not a payment.
async fn post_foreign_notice(
    demo: &mut Demo,
    attacker: &DemoWallet,
) -> Result<bitcoin::Txid, BoxError> {
    let amount = Amount::from_btc(0.3)?;
    let (outpoint, prevout) = attacker
        .select_utxo(amount + Amount::from_sat(2_000))
        .ok_or("attacker lacks a large enough coin")?;
    let self_key = attacker.input_keys()[0].x_only_public_key(&demo.secp).0;
    let self_script = ScriptBuf::new_p2tr(&demo.secp, self_key, None);
    let psbt = attacker.build_original_from(
        outpoint,
        &prevout,
        self_script.clone(),
        amount,
        FeeRate::BROADCAST_MIN,
    )?;
    let txid = psbt.unsigned_tx.compute_txid();
    post_notice(demo, psbt, &self_script, "notice-judy").await?;
    Ok(txid)
}
