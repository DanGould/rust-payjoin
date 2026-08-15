//! Scene 5: the spam gauntlet. Each class of junk an attacker can throw
//! at the endpoint meets a mechanism that prices or drops it, printed as
//! an attacker-versus-receiver ledger.
//!
//! Honest-demo constraint: regtest coins are free, so this proves the
//! mechanisms (proof of work, trial decryption, one-show abort, seen-
//! outpoint dedupe, board cap) and quotes mainnet economics in the
//! narration. It never claims to demonstrate the capital wall itself.

use std::time::Instant;

use bitcoin::secp256k1::rand::RngCore;
use bitcoin::{Amount, OutPoint};

use super::{
    respond_with_original_broadcast, seal_notification, send_message_a, sweep_to_wallet, BoxError,
    Demo, QUEUE_FRAME_BYTES,
};
use crate::net::BLOB_BYTES;
use crate::sp;
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        5,
        "The spam gauntlet",
        "Every class of junk an attacker can send meets a mechanism that \
         drops or prices it. Regtest coins are free, so this proves the \
         mechanisms and quotes mainnet economics; it does not pretend to \
         buy the capital wall.",
    );

    // A clean directory so the board and queue counts reflect this
    // scene alone.
    demo.reset_mailroom(super::MailroomOpts {
        board_pow_bits: 12,
        board_cap: 20,
        queue_frame_cap: 64,
        queue_requires_token: false,
    })
    .await?;

    class_a_board_garbage(demo).await?;
    class_b_addressed_garbage(demo).await?;
    class_c_decoy_probe(demo).await?;
    class_f_board_flood(demo).await?;

    demo.narrator.verdict(
        true,
        "each spam class was dropped or priced. The mechanisms hold: proof \
         of work per board post, trial decryption for addressed junk, a \
         one-show abort that turns probes into revenue, seen-outpoint \
         dedupe, and a board cap that at worst downgrades one upgrade to \
         vanilla silent payment. Zero payments failed.",
    );
    Ok(())
}

/// (a) Board garbage: rejected without work, admitted only with it. The
/// receiver's cost to find one real notification among the noise.
async fn class_a_board_garbage(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.step("class (a): garbage notifications flung at the board");

    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let mut rejected_without_work = 0;
    for _ in 0..8 {
        let mut blob = [0u8; BLOB_BYTES];
        rng.fill_bytes(&mut blob);
        let bad_nonce = [0u8; 8];
        if demo.mailroom.board_post(&bad_nonce, &blob).await? == 429 {
            rejected_without_work += 1;
        }
    }

    // Plant one real notification, then flood with worked garbage.
    let real = seal_notification(&demo.secp, &demo.sp_address.scan);
    let (nonce, _) = demo.mailroom.mine_pow(&real);
    demo.mailroom.board_post(&nonce, &real).await?;

    let mut worked_admitted = 0;
    let mut attacker_hashes = 0u64;
    for _ in 0..12 {
        let mut blob = [0u8; BLOB_BYTES];
        rng.fill_bytes(&mut blob);
        let (nonce, hashes) = demo.mailroom.mine_pow(&blob);
        attacker_hashes += hashes;
        if demo.mailroom.board_post(&nonce, &blob).await? == 200 {
            worked_admitted += 1;
        }
    }

    // The receiver reads the whole board and trial-opens each blob.
    let start = Instant::now();
    let (blobs, _) = demo.mailroom.board_read(0).await?;
    let mut mine = 0;
    for blob in &blobs {
        if super::open_notification(demo, blob) {
            mine += 1;
        }
    }
    let elapsed = start.elapsed();
    let downloaded = blobs.len() * BLOB_BYTES;

    demo.narrator.ledger(
        "(a) board garbage",
        &[
            ("attacker: unworked posts rejected".into(), format!("{rejected_without_work} / 8")),
            ("attacker: worked posts admitted".into(), format!("{worked_admitted} / 12")),
            ("attacker: hashes burned for admission".into(), attacker_hashes.to_string()),
            ("receiver: blobs scanned".into(), blobs.len().to_string()),
            ("receiver: bytes downloaded".into(), downloaded.to_string()),
            ("receiver: scan time".into(), format!("{elapsed:?}")),
            ("receiver: real notifications found".into(), mine.to_string()),
        ],
    );
    demo.narrator.note(
        "on mainnet the board post is gated by a real cost, and the \
         receiver's scan is a cheap trial-decryption per blob. Here it is \
         microseconds; the mechanism, not the free regtest scale, is the \
         point",
    );
    if rejected_without_work != 8 || mine < 1 {
        return Err("class (a) assertions failed".into());
    }
    Ok(())
}

/// (b) Addressed garbage: frames posted straight to the queue that do
/// not decrypt to a payment. The receiver skips them by trial
/// decryption and still finds the one real message.
async fn class_b_addressed_garbage(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.step("class (b): garbage frames posted directly to the queue");

    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let queue_id = demo.queue_id.clone();
    let mut injected = 0;
    for _ in 0..6 {
        let mut frame = vec![0u8; QUEUE_FRAME_BYTES];
        rng.fill_bytes(&mut frame);
        if demo.mailroom.queue_post_raw(&queue_id, &frame).await? == 200 {
            injected += 1;
        }
    }

    // One real payment among the noise.
    let mut grace = DemoWallet::new(&demo.secp, "Grace");
    grace.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;
    let payment = send_message_a(demo, &grace, Amount::from_btc(0.2)?, None).await?;

    let start = Instant::now();
    let proposals = demo.receiver_poll().await?;
    let elapsed = start.elapsed();

    demo.narrator.ledger(
        "(b) addressed garbage",
        &[
            ("attacker: garbage frames injected".into(), injected.to_string()),
            ("receiver: frames trial-decrypted".into(), (injected + 1).to_string()),
            ("receiver: drain time".into(), format!("{elapsed:?}")),
            ("receiver: real proposals recovered".into(), proposals.len().to_string()),
        ],
    );
    // Respond so the real payment is not left hanging.
    let [proposal]: [_; 1] =
        proposals.try_into().map_err(|_| "class (b): expected exactly one real proposal")?;
    super::respond_with_payjoin(demo, proposal, &payment.sp_script, "gauntlet-grace").await?;
    super::complete_payment(demo, &mut grace, payment).await?;
    Ok(())
}

/// (c) Valid-decoy probe: a well-formed message A meant to extract a
/// response. The receiver's one-show abort broadcasts the probe's own
/// original, turning it into revenue; a re-probe of the same coin is
/// dropped by seen-outpoint dedupe.
async fn class_c_decoy_probe(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.step("class (c): a valid probe crafted to extract a response");

    let mut mallory = DemoWallet::new(&demo.secp, "Mallory");
    mallory.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;

    // First probe: a valid message A. The receiver aborts by
    // broadcasting the prober's own original, recording the spent coin.
    let amount = Amount::from_btc(0.3)?;
    let probe1 = send_message_a(demo, &mallory, amount, None).await?;
    let probe_script = probe1.sp_script.clone();
    let [proposal]: [_; 1] =
        demo.receiver_poll().await?.try_into().map_err(|_| "expected one probe")?;
    let original = match respond_with_original_broadcast(demo, proposal, "probe-1")? {
        Some(original) => original,
        None => return Err("class (c): first probe should have been broadcast".into()),
    };
    let broadcast_value = original
        .output
        .iter()
        .find(|o| o.script_pubkey == probe_script)
        .map(|o| o.value)
        .unwrap_or(Amount::ZERO);

    // The broadcast pays the receiver's derived output; bank it like
    // any other silent payment so the revenue lands in the wallet.
    let (vout, keypair) = demo
        .sp_keys
        .scan_tx(&demo.secp, &original, &sp::input_pubkeys_from_witnesses(&original))
        .ok_or("class (c): the probe's own transaction must pay the receiver")?;
    let revenue_outpoint = OutPoint { txid: original.compute_txid(), vout: vout as u32 };
    let revenue_sweep = sweep_to_wallet(demo, revenue_outpoint, &original.output[vout], &keypair)?;

    // Re-probe with the same coin. The receiver has recorded the
    // outpoint, so the abort policy drops it without a broadcast.
    let probe2 = send_message_a(demo, &mallory, amount, None).await?;
    let deduped = match demo.receiver_poll().await?.into_iter().next() {
        Some(proposal) => match respond_with_original_broadcast(demo, proposal, "probe-2")? {
            Some(_) => 0,
            None => 1,
        },
        None => return Err("class (c): re-probe frame was not queued".into()),
    };
    let _ = (probe1, probe2);

    demo.narrator.ledger(
        "(c) valid-decoy probe",
        &[
            ("attacker: probe cost (spent to receiver)".into(), broadcast_value.to_string()),
            ("receiver: on-chain revenue".into(), broadcast_value.to_string()),
            ("receiver: revenue swept to wallet".into(), revenue_sweep.to_string()),
            ("attacker: re-probes of the same coin".into(), "1".into()),
            ("receiver: re-probes dropped by dedupe".into(), deduped.to_string()),
        ],
    );
    demo.narrator.note(
        "the abort broadcasts the prober's own transaction, so a probe is \
         never free: it either gets no response or pays the receiver. The \
         same coin cannot be shown twice",
    );
    if broadcast_value == Amount::ZERO || deduped != 1 {
        return Err("class (c) assertions failed".into());
    }
    Ok(())
}

/// (f) Sustained flood to the board cap: an honest first-contact sender
/// cannot post a notification, times out, and completes as vanilla
/// silent payment. The flood never touches the queue, so the receiver
/// still recovers the payment from the sender's frame. No payment
/// fails.
async fn class_f_board_flood(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.step("class (f): flood the board to its cap");

    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let mut posts = 0;
    let mut hashes = 0u64;
    // Fill until the board reports full (503) or a generous bound.
    let mut hit_cap = false;
    for _ in 0..128 {
        let mut blob = [0u8; BLOB_BYTES];
        rng.fill_bytes(&mut blob);
        let (nonce, tried) = demo.mailroom.mine_pow(&blob);
        hashes += tried;
        match demo.mailroom.board_post(&nonce, &blob).await? {
            200 => posts += 1,
            503 => {
                hit_cap = true;
                break;
            }
            _ => {}
        }
    }

    demo.narrator.step("an honest stranger tries to announce, but the board is full");
    let mut heidi = DemoWallet::new(&demo.secp, "Heidi");
    heidi.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;
    let note = seal_notification(&demo.secp, &demo.sp_address.scan);
    let (nonce, _) = demo.mailroom.mine_pow(&note);
    let honest_status = demo.mailroom.board_post(&nonce, &note).await?;

    // The stranger cannot get a notification through, so it pays without
    // an upgrade: broadcast the original, a plain silent payment.
    let payment = send_message_a(
        demo,
        &heidi,
        Amount::from_btc(0.2)?,
        Some(std::time::Duration::from_secs(1)),
    )
    .await?;
    let sp_script = payment.sp_script.clone();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let tx = super::fall_back(demo, &mut heidi, payment).await?;
    let downgraded_ok = tx.output.iter().any(|o| o.script_pubkey == sp_script);

    // The flood only silenced the board, the wake-up channel. Heidi's
    // payment frame reached the queue before her patience ran out, so
    // the receiver's next drain still hands it the settled payment.
    demo.narrator
        .step("the receiver's next drain finds Heidi's frame; the flood only cost the upgrade");
    let [proposal]: [_; 1] = demo
        .receiver_poll()
        .await?
        .try_into()
        .map_err(|_| "class (f): expected Heidi's frame in the queue")?;
    let queued_tx = super::original_tx_from_proposal(demo, proposal, "flood-heidi")?;
    let recovered_ok = queued_tx.compute_txid() == tx.compute_txid();
    let (vout, keypair) = demo
        .sp_keys
        .scan_tx(&demo.secp, &queued_tx, &sp::input_pubkeys_from_witnesses(&queued_tx))
        .ok_or("class (f): Heidi's transaction must pay the receiver")?;
    let heidi_outpoint = OutPoint { txid: queued_tx.compute_txid(), vout: vout as u32 };
    let heidi_sweep = sweep_to_wallet(demo, heidi_outpoint, &queued_tx.output[vout], &keypair)?;

    demo.narrator.ledger(
        "(f) board-cap flood",
        &[
            ("attacker: board posts to reach cap".into(), posts.to_string()),
            ("attacker: hashes burned".into(), hashes.to_string()),
            ("attacker: regtest coin cost".into(), "0 (free on regtest)".into()),
            ("honest sender: board post status".into(), honest_status.to_string()),
            ("honest sender: payment outcome".into(), "completed as vanilla silent payment".into()),
            ("receiver: payment recovered from its queue".into(), heidi_sweep.to_string()),
            ("payments failed".into(), "0".into()),
        ],
    );
    demo.narrator.note(
        "on mainnet reaching the anonymity set means holding roughly 238K \
         taproot keys of at least 500K sats each behind per-post work. The \
         attacker here spent free regtest coins to downgrade exactly one \
         stranger's upgrade; nobody lost a payment",
    );
    if !(hit_cap && honest_status == 503 && downgraded_ok && recovered_ok) {
        return Err("class (f) assertions failed".into());
    }
    Ok(())
}
