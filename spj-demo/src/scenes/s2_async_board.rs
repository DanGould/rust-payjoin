//! Scene 2: first contact when the receiver is offline. The sender
//! leaves a notification on the bulletin board among decoys; the
//! receiver comes back later, finds its one message, and completes.

use bitcoin::Amount;

use super::{
    complete_payment, open_notification, respond_with_payjoin, seal_notification, send_message_a,
    BoxError, Demo,
};
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        2,
        "Async first contact via the board",
        "A sender reaches a receiver who is not online. It posts to the \
         board while the receiver process is down; the receiver starts \
         later, finds its one real notification among decoys, and \
         completes the payment. The directory sees only sized ciphertext.",
    );

    demo.publish_endpoint()?;

    let mut carol = DemoWallet::new(&demo.secp, "Carol");
    carol.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;

    // Decoys already resident on the board: other senders' first
    // contacts to other receivers, indistinguishable to anyone without
    // the matching scan key.
    demo.narrator.step("the board already holds decoy notifications from unrelated senders");
    let mut decoys = 0;
    for i in 0..6u8 {
        let stranger_scan = DemoWallet::new(&demo.secp, "stranger")
            .input_keys()
            .first()
            .copied()
            .expect("one key")
            .public_key(&demo.secp);
        // A distinct decoy per iteration by tweaking the target key.
        let decoy_target =
            stranger_scan.mul_tweak(&demo.secp, &decoy_scalar(i)).unwrap_or(stranger_scan);
        let blob = seal_notification(&demo.secp, &decoy_target);
        let (nonce, _) = demo.mailroom.mine_pow(&blob);
        if demo.mailroom.board_post(&nonce, &blob).await? == 200 {
            decoys += 1;
        }
    }
    demo.narrator.result("decoys resident", &decoys.to_string());

    demo.narrator.step("the receiver process is DOWN — no poll loop is running");

    // Carol posts message A to the queue and a board notification. The
    // receiver is not polling, so nothing is consumed yet.
    demo.narrator.step("Carol posts her payment to the queue and a notification to the board");
    let payment = send_message_a(demo, &carol, Amount::from_btc(0.25)?, None).await?;
    let note = seal_notification(&demo.secp, &demo.sp_address.scan);
    let (nonce, attempts) = demo.mailroom.mine_pow(&note);
    let status = demo.mailroom.board_post(&nonce, &note).await?;
    demo.narrator.result("board post status", &status.to_string());
    demo.narrator.result("proof-of-work hashes", &attempts.to_string());

    // What the operator sees.
    demo.narrator.step("show everything the directory operator can observe");
    let listing = demo.mailroom.storage_listing();
    let total: u64 = listing.iter().map(|(_, size)| size).sum();
    demo.narrator.result("stored objects", &listing.len().to_string());
    demo.narrator.result("total bytes at rest", &total.to_string());
    demo.narrator.note(
        "the operator sees opaque ids and byte counts. It cannot tell a real \
         notification from a decoy, cannot read a queue frame, and cannot \
         link a board entry to a queue mailbox",
    );

    // The receiver wakes hours later. Advance the chain to make the gap
    // concrete, then drain the board and find its message.
    demo.narrator.step("hours pass (advance the chain), then the receiver starts back up");
    demo.mine(6)?;
    let (blobs, _next) = demo.mailroom.board_read(0).await?;
    let mine: Vec<_> = blobs.iter().filter(|blob| open_notification(demo, blob)).collect();
    demo.narrator.result("board entries scanned", &blobs.len().to_string());
    demo.narrator.result("notifications addressed to me", &mine.len().to_string());

    demo.narrator.step("the notification says to poll; the receiver drains its queue");
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    respond_with_payjoin(demo, proposal, &payment.sp_script, "async-carol").await?;
    let tx = complete_payment(demo, &mut carol, payment).await?;
    demo.narrator.result("completed payjoin txid", &tx.compute_txid().to_string());

    let pass = mine.len() == 1 && status == 200;
    demo.narrator.verdict(
        pass,
        "the receiver was offline when the payment began and still \
         completed it, having found exactly one real notification among \
         the decoys. The directory never saw anything but sized blobs.",
    );
    if !pass {
        return Err("scene 2 assertions failed".into());
    }
    Ok(())
}

fn decoy_scalar(seed: u8) -> bitcoin::secp256k1::Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.wrapping_add(1);
    bitcoin::secp256k1::Scalar::from_be_bytes(bytes).expect("small scalar is valid")
}
