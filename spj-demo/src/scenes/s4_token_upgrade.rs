//! Scene 4: a returning sender skips the board. First contact leaves a
//! board notification and pays proof of work. The mailroom then turns
//! on its queue token requirement: the receiver mints a token under
//! the key its queue id is derived from, the sender's next payment
//! presents it and reaches the queue directly, and the mailroom, not
//! the demo, refuses un-tokened posts and token replays.

use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::Amount;
use payjoin_mailroom::admission::{mint_queue_token, TOKEN_NONCE_BYTES};

use super::{
    complete_payment, respond_with_payjoin, seal_notification, send_message_a,
    send_message_a_with_token, BoxError, Demo, MailroomOpts, QUEUE_FRAME_BYTES,
};
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        4,
        "Token upgrade for a returning sender",
        "The board carries first contact only. After one payment the \
         receiver mints a token with its mailbox key; the next payment \
         presents it and reaches the queue directly, with no board entry \
         and no proof of work, while the mailroom refuses posts that \
         carry no token.",
    );

    demo.publish_endpoint()?;

    let mut frank = DemoWallet::new(&demo.secp, "Frank");
    frank.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    frank.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;

    // First contact: board notification, then a full round.
    demo.narrator.step("first payment: Frank is a stranger, so he announces on the board");
    let note = seal_notification(&demo.secp, &demo.sp_address.scan);
    let (nonce, work) = demo.mailroom.mine_pow(&note);
    demo.mailroom.board_post(&nonce, &note).await?;
    demo.narrator.result("board notification", "posted");
    demo.narrator.result("proof-of-work hashes", &work.to_string());

    let p1 = send_message_a(demo, &frank, Amount::from_btc(0.3)?, None).await?;
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    respond_with_payjoin(demo, proposal, &p1.sp_script, "token-first").await?;
    let tx1 = complete_payment(demo, &mut frank, p1).await?;
    demo.narrator.result("first payjoin txid", &tx1.compute_txid().to_string());

    // Earlier scenes ran the queue open to any append. For the return
    // visit the operator requires tokens, so the directory refuses
    // appends that carry none.
    demo.narrator.step("the mailroom turns on its queue token requirement");
    demo.reset_mailroom(MailroomOpts {
        board_pow_bits: 12,
        board_cap: 24,
        queue_frame_cap: 64,
        queue_requires_token: true,
    })
    .await?;

    // A token is an ECDSA signature under the key the queue id is
    // derived from, verified by the mailroom offline. In production the
    // receiver would hand it to a served sender in its payjoin reply.
    demo.narrator.step("the receiver mints a queue token with its mailbox key");
    let owner_key = demo.queue_owner_key.ok_or("no endpoint published")?;
    let mut token_nonce = [0u8; TOKEN_NONCE_BYTES];
    thread_rng().fill_bytes(&mut token_nonce);
    let token = mint_queue_token(&owner_key, token_nonce);
    demo.narrator.result(
        "token issued",
        &format!("{}\u{2026} ({} bytes)", &token.to_lower_hex_string()[..16], token.len()),
    );

    demo.narrator.step("a stranger posts to the queue without a token");
    let mut junk = vec![0u8; QUEUE_FRAME_BYTES];
    thread_rng().fill_bytes(&mut junk);
    let stranger_status = demo.mailroom.queue_post_raw(&demo.queue_id, &junk).await?;
    demo.narrator.result("un-tokened post", &format!("rejected, inner status {stranger_status}"));

    demo.narrator.step("second payment: Frank presents the token and skips the board");
    let p2 = send_message_a_with_token(demo, &frank, Amount::from_btc(0.2)?, &token).await?;
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    respond_with_payjoin(demo, proposal, &p2.sp_script, "token-second").await?;
    let tx2 = complete_payment(demo, &mut frank, p2).await?;
    demo.narrator.result("second payjoin txid", &tx2.compute_txid().to_string());

    // One show: the spent token cannot admit another frame.
    let mut replay = token.to_vec();
    replay.extend_from_slice(&junk);
    let replay_status = demo.mailroom.queue_post_raw(&demo.queue_id, &replay).await?;
    demo.narrator.result("replaying the spent token", &format!("inner status {replay_status}"));

    let (board_entries, _) = demo.mailroom.board_read(0).await?;
    demo.narrator
        .result("board entries since the token requirement", &board_entries.len().to_string());

    let pass = stranger_status != 200 && replay_status == 409 && board_entries.is_empty();
    demo.narrator.verdict(
        pass,
        "the mailroom refused the stranger's un-tokened post, admitted \
         Frank's tokened frame once, refused the replay, and the return \
         payment left no board entry. The token is minted and verified \
         at the mailroom; the demo transport splices it into the queue \
         post because the stock sender cannot attach one yet.",
    );
    if !pass {
        return Err("scene 4 assertions failed".into());
    }
    Ok(())
}
