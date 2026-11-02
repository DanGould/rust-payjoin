//! Scene 6: the funder pays Bob's contact URI while Bob's phone sleeps past
//! the reply-by. The funder broadcasts its Original, a plain silent payment.
//! When Bob's wallet wakes it reads the Original, finds its inputs already
//! spent, and posts nothing; a restore finds the payment.

use std::time::{Duration, Instant};

use bitcoin::Amount;

use super::{bob_answers, restored_in, Demo};
use crate::narrate::{sats, short};
use crate::net::Error;
use crate::persist::EventLog;
use crate::{chain, flow};

const AMOUNT: Amount = Amount::from_sat(100_000);
/// A short reply-by, as an unattended payer sets it.
const REPLY_BY: Duration = Duration::from_secs(4);

pub async fn run(demo: &mut Demo) -> Result<(), Error> {
    demo.n.scene(6, "Bob's phone sleeps past the reply-by");
    let start = demo.height()?;
    let (mut log, contact) = demo.contact.take().ok_or("scene 5 created the contact log")?;
    let original = flow::sp_original(&demo.secp, &mut demo.funder, &contact.sp, AMOUNT)?;
    let posted = Instant::now();
    let sending = flow::post_to_contact(
        &demo.regtest.mailroom,
        &contact,
        &original.psbt,
        &original.payee_address(),
        AMOUNT,
        REPLY_BY,
    )
    .await?;
    demo.n.say(
        "Funder",
        &format!(
            "month 4: appends a signed Original for {} with a reply-by {} s away, then waits",
            sats(AMOUNT),
            REPLY_BY.as_secs()
        ),
    );
    demo.n.say("Bob", "the phone is asleep and posts nothing, not even \"no coin\"");

    let mut proposal = flow::poll_proposal(&demo.regtest.mailroom, &sending).await.ok().flatten();
    if proposal.is_none() {
        tokio::time::sleep(REPLY_BY.saturating_sub(posted.elapsed())).await;
        proposal = flow::poll_proposal(&demo.regtest.mailroom, &sending).await.ok().flatten();
    }
    let original_tx = original.tx();
    let txid = original_tx.compute_txid();
    demo.n.say(
        "Funder",
        &format!(
            "no proposal by reply-by: broadcasts the Original {}, a plain silent payment",
            short(&txid.to_string())
        ),
    );
    chain::broadcast(demo.client(), &original_tx)?;
    let height = demo.regtest.confirm(&[txid])?;
    demo.funder.credit(&original_tx);
    demo.n.say("Chain", &format!("the Original confirms in block {height}"));

    let inbound = log.next(&demo.regtest.mailroom).await?.ok_or("Bob's log has the Original")?;
    demo.n.say("Bob", &format!("wakes and reads frame {} of the contact log", inbound.index));
    let session_log = EventLog::copy_of(&inbound.persister)?;
    let answered = bob_answers(
        &demo.n,
        &demo.regtest,
        &mut demo.bob,
        &mut demo.bob_contact,
        "the separate BIP 86 keychain",
        "the funder",
        inbound.receiver,
        &session_log,
        None,
    )
    .await?;
    let restored = demo.restore_since(start)?;
    let found = restored_in(&restored, txid, AMOUNT);
    demo.n.check(
        "Bob",
        "the watch on the Original's inputs: spent by the Original itself, and a standard scan \
         finds the payment: paid",
        found,
    );
    demo.contact = Some((log, contact));
    demo.n.verdict(
        proposal.is_none() && answered.is_none() && demo.confirmed(txid)? && found,
        &format!(
            "no proposal before reply-by; Original {} confirmed as a plain silent payment of {}, and \
             Bob's restore finds it",
            short(&txid.to_string()),
            sats(AMOUNT)
        ),
    );
    Ok(())
}
