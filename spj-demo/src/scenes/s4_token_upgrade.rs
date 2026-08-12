//! Scene 4: a returning sender skips the board. First contact leaves a
//! board notification; the receiver issues a token in its reply, and
//! the sender's next payment presents the token and goes straight to
//! the queue. No second board entry, no proof of work.

use bitcoin::Amount;

use super::{
    complete_payment, respond_with_payjoin, seal_notification, send_message_a, BoxError, Demo,
};
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        4,
        "Token upgrade for a returning sender",
        "The board carries first contact only. After one payment the \
         receiver hands the sender a token; the next payment presents it \
         and reaches the queue directly, with no board entry and no proof \
         of work.",
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
    let (_, board_after_first) = demo.mailroom.board_read(0).await?;

    let p1 = send_message_a(demo, &frank, Amount::from_btc(0.3)?, None).await?;
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    respond_with_payjoin(demo, proposal, &p1.sp_script, "token-first").await?;
    let tx1 = complete_payment(demo, &mut frank, p1).await?;
    demo.narrator.result("first payjoin txid", &tx1.compute_txid().to_string());

    // The receiver issues a token to a sender it has served. Production
    // carries this in the payjoin response and the mailroom validates it
    // on the queue POST; here the demo mints and checks it in-process.
    let token = format!("tkn-{}", tx1.compute_txid());
    demo.tokens.insert(token.clone());
    demo.narrator.step("the receiver includes a queue token in its reply");
    demo.narrator.result("token issued", &token);

    // Second payment: present the token, skip the board entirely.
    demo.narrator.step("second payment: Frank presents the token and skips the board");
    let board_before_second = board_after_first;
    let present_token = demo.tokens.contains(&token);
    if !present_token {
        return Err("token was not recognized".into());
    }
    let p2 = send_message_a(demo, &frank, Amount::from_btc(0.2)?, None).await?;
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    respond_with_payjoin(demo, proposal, &p2.sp_script, "token-second").await?;
    let tx2 = complete_payment(demo, &mut frank, p2).await?;
    demo.narrator.result("second payjoin txid", &tx2.compute_txid().to_string());

    let (_, board_after_second) = demo.mailroom.board_read(0).await?;
    demo.narrator.result(
        "board entries before / after second payment",
        &format!("{board_before_second} / {board_after_second}"),
    );

    let no_new_board = board_after_second == board_before_second;
    let pass = present_token && no_new_board;
    demo.narrator.verdict(
        pass,
        "the returning payment reached the queue with a token and left no \
         board entry. Demo-side token; production gates it at the mailroom \
         queue, which this branch does not yet enforce.",
    );
    if !pass {
        return Err("scene 4 assertions failed".into());
    }
    Ok(())
}
