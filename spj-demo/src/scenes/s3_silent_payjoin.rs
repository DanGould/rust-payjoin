//! Scene 3: a silent payment wallet pays Bob's one-time URI. Bob adds a coin
//! with its proof, Alice derives Bob's output before signing, and a
//! restore from the transaction's tweak finds the payment.

use bitcoin::{Amount, Network};

use super::{bob_answers, payer_settles, restored_in, Demo, Settled};
use crate::flow;
use crate::narrate::{sats, short};
use crate::net::Error;
use crate::sender::{attempt_gate, Change, Gate, Payment};
use crate::uri::OneTimeUri;

const AMOUNT: Amount = Amount::from_sat(50_000);

pub async fn run(demo: &mut Demo) -> Result<(), Error> {
    demo.n.scene(3, "A one-time URI paid by a silent payment wallet");
    let start = demo.height()?;
    let body = demo.bob_hot.address();
    let one_time =
        flow::one_time(&demo.regtest.mailroom, demo.bob.address(), body.clone(), AMOUNT)?;
    demo.n.say(
        "Bob",
        "shows a one-time URI to Alice, a payer Bob chose. One-time URIs add a coin, one session \
         at a time",
    );
    let uri = OneTimeUri::parse(&one_time.uri.to_string(), Network::Regtest)?;

    let gate = attempt_gate(&uri.sp, &[Payment::SilentPayment(uri.sp)], Change::Ordinary);
    demo.n.check(
        "Alice",
        "attempt gate (S1): every silent payment output pays this sp1 and the change is ordinary \
         BIP 86",
        gate == Gate::AttemptPayjoin,
    );
    let original = flow::sp_original(&demo.secp, &mut demo.alice, &uri.sp, AMOUNT)?;
    let sending = flow::post_original(
        &demo.regtest.mailroom,
        &original.psbt,
        &flow::one_time_param(&uri)?,
        &original.payee_address(),
        AMOUNT,
        false,
    )
    .await?;
    demo.n.say(
        "Alice",
        &format!(
            "derives Bob's output {} from the inputs it spends, posts the signed Original to Bob's mailbox \
             and keeps it ready to broadcast",
            short(&original.payee.to_hex_string()[4..])
        ),
    );

    let received = flow::poll_original(&demo.regtest.mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("the Original should be waiting")?;
    let proposal = bob_answers(
        &demo.n,
        &demo.regtest,
        &mut demo.bob,
        &mut demo.bob_hot,
        "the one-time coins",
        "Alice",
        received,
        &one_time.log,
        Some(&body.script_pubkey()),
    )
    .await?
    .ok_or("Bob should answer")?;

    let settled = payer_settles(
        &demo.n,
        &demo.regtest,
        &demo.secp,
        "Alice",
        "Bob",
        &mut demo.alice,
        &uri.sp,
        &original,
        &sending,
    )
    .await?;
    let Settled::Payjoin(payjoin) = settled else {
        demo.n.verdict(false, "Alice fell back to the Original");
        return Ok(());
    };
    let txid = payjoin.compute_txid();
    demo.bob_hot.credit(&payjoin);

    let index = crate::chain::tweak_index(&demo.secp, demo.client(), start + 1, demo.height()?)?;
    let entry = index.iter().find(|entry| entry.txid == txid);
    if let Some(entry) = entry {
        demo.n.say(
            "Index",
            &format!(
                "a BlindBit-style server publishes this transaction's tweak input_hash·A = {}",
                short(&entry.tweak.to_string())
            ),
        );
    }
    let restored = demo.restore_since(start)?;
    let found = restored_in(&restored, txid, AMOUNT);
    let value = restored.iter().find(|f| f.outpoint.txid == txid).map(|f| f.value);
    demo.n.check(
        "Bob",
        &format!(
            "a restore from seed, checking each published tweak with the scan key, finds {}",
            value.map(sats).unwrap_or_else(|| "nothing".into())
        ),
        found,
    );
    let confirmed = demo.tx(txid)?;
    let pays_derived = confirmed.output.iter().any(|out| out.script_pubkey == proposal.derived[0]);
    let has_bob_coin =
        confirmed.input.iter().any(|input| input.previous_output == proposal.coin.outpoint);

    let contact = demo.alice_contacts.save_one_time("Bob", &uri);
    demo.n.say("Alice", &format!("saves Bob's sp1 as a contact: {}", contact.sp));
    let note = contact.note();
    demo.n.say("Alice", &format!("note: {}", note.unwrap_or("none")));
    demo.n.why(
        "Alice learns one of Bob's coins, BIP 78's normal cost, acceptable because Bob chose who got \
         the URI",
    );
    demo.to_film.push(("scene3-silent-payjoin".into(), txid));
    demo.n.verdict(
        demo.confirmed(txid)? && has_bob_coin && pays_derived && found && note.is_some(),
        &format!(
            "silent payjoin {} confirmed with Bob's coin and Bob's re-derived output, and a restore \
             from the tweak index finds it",
            short(&txid.to_string())
        ),
    );
    Ok(())
}
