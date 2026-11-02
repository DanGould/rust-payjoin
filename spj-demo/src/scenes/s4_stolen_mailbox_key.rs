//! Scene 4: Mallory holds the mailbox key of Bob's one-time URI, reads
//! Alice's Original and answers before Bob does, three times over three
//! payments: redirecting the payment, proving a share with a key the coin
//! doesn't have, and shrinking Bob's output. Each proposal fails Alice's
//! check, each Original goes out, and Bob is paid every time.

use bitcoin::{Amount, ScriptBuf, TxOut};
use payjoin::receive::v2::{PayjoinProposal, Receiver, UncheckedOriginalPayload};
use payjoin::ImplementationError;
use spj_crypto::carriage;

use super::{payer_settles, restored_in, Demo, Settled};
use crate::narrate::{sats, short};
use crate::net::Error;
use crate::persist::EventLog;
use crate::sender::{attempt_gate, Change, Gate, Payment};
use crate::wallet::Keychain;
use crate::{chain, flow};

const AMOUNT: Amount = Amount::from_sat(50_000);

#[derive(Clone, Copy)]
enum Attack {
    /// Add a coin of Mallory's with an honest proof and pay Mallory instead.
    Redirect,
    /// Add a coin of Mallory's with a share and proof made with another key.
    ForeignProof,
    /// Add nothing and cut Bob's output.
    Shrink,
}

pub async fn run(demo: &mut Demo) -> Result<(), Error> {
    demo.n.scene(4, "Mallory stole the mailbox key and answers first");
    let start = demo.height()?;
    let mallory_script = demo.mallory.address().script_pubkey();
    let mut originals = Vec::new();
    let mut expected = Vec::new();
    for (attack, reason) in [
        (Attack::Redirect, "an output derived for the sp1 is missing"),
        (Attack::ForeignProof, "BIP 374 proof fails"),
        (Attack::Shrink, "amount rule"),
    ] {
        let one_time = flow::one_time(
            &demo.regtest.mailroom,
            demo.bob.address(),
            demo.bob_hot.address(),
            AMOUNT,
        )?;
        let sp = one_time.uri.sp;
        let gate = attempt_gate(&sp, &[Payment::SilentPayment(sp)], Change::Ordinary);
        if gate != Gate::AttemptPayjoin {
            return Err("the attempt gate should open for a payment to the URI's sp1".into());
        }
        let original = flow::sp_original(&demo.secp, &mut demo.alice, &sp, AMOUNT)?;
        let sending = flow::post_original(
            &demo.regtest.mailroom,
            &original.psbt,
            &flow::one_time_param(&one_time.uri)?,
            &original.payee_address(),
            AMOUNT,
            false,
        )
        .await?;
        demo.n.say("Alice", "posts a signed Original to Bob's one-time URI");

        // Whoever holds the mailbox key reads what Bob would read; reads
        // don't delete, so Bob can still read it later.
        let (session, log) = flow::session_with_key(
            &demo.regtest.mailroom,
            &one_time.key,
            demo.mallory.address(),
            Some(AMOUNT),
        )?;
        let received = flow::poll_original(&demo.regtest.mailroom, session, &log)
            .await?
            .ok_or("the Original should be waiting")?;
        let proposal = answer(demo, attack, received, &log, &original.payee, &mallory_script)?;
        flow::post_proposal(&demo.regtest.mailroom, &proposal, &log).await?;
        demo.n.say(
            "Mallory",
            match attack {
                Attack::Redirect =>
                    "adds a coin Mallory owns, with an honest proof for it, and redirects Bob's 50,000 sat to Mallory",
                Attack::ForeignProof =>
                    "adds a coin Mallory owns, but with a share and proof made from a different key",
                Attack::Shrink => "adds nothing, cuts Bob's output and adds one paying Mallory",
            },
        );
        demo.n.say("Bob", "the phone is asleep and hasn't answered yet");

        let settled = payer_settles(
            &demo.n,
            &demo.regtest,
            &demo.secp,
            "Alice",
            "Bob",
            &mut demo.alice,
            &sp,
            &original,
            &sending,
        )
        .await?;
        let ok = matches!(&settled, Settled::Original(_, why) if why.contains(reason));
        demo.n.check("Alice", &format!("expected rejection: {reason}"), ok);
        originals.push(settled.tx().compute_txid());
        expected.push(ok);
    }

    let restored = demo.restore_since(start)?;
    let all_paid = originals.iter().all(|txid| restored_in(&restored, *txid, AMOUNT));
    demo.n.check(
        "Bob",
        &format!("a restore from seed finds all three Originals' payments, {} each", sats(AMOUNT)),
        all_paid,
    );
    let mut mallory_paid = Amount::ZERO;
    let mut all_confirmed = true;
    for txid in &originals {
        all_confirmed &= demo.confirmed(*txid)?;
        mallory_paid += demo
            .tx(*txid)?
            .output
            .iter()
            .filter(|out| out.script_pubkey == mallory_script)
            .map(|out| out.value)
            .sum::<Amount>();
    }
    demo.n.check(
        "Mallory",
        &format!("receives {}", sats(mallory_paid)),
        mallory_paid == Amount::ZERO,
    );
    demo.n.why(
        "the mailbox key lets Mallory read Originals and answer, but every proposal must pay the \
         outputs Alice derives from the Original's keys and the proven shares",
    );
    demo.n.verdict(
        expected.iter().all(|ok| *ok) && all_confirmed && all_paid && mallory_paid == Amount::ZERO,
        &format!(
            "three forged proposals rejected (missing output, foreign proof, amount); Originals {} \
             confirmed and Bob's restore finds each",
            originals.iter().map(|t| short(&t.to_string())).collect::<Vec<_>>().join(", ")
        ),
    );
    Ok(())
}

/// Mallory's proposal, built with the payjoin receiver like Bob's.
fn answer(
    demo: &mut Demo,
    attack: Attack,
    received: Receiver<UncheckedOriginalPayload>,
    log: &EventLog,
    payee: &ScriptBuf,
    mallory: &ScriptBuf,
) -> Result<Receiver<PayjoinProposal>, Error> {
    let client = demo.regtest.client();
    let original_tx = received.extract_tx_to_check_broadcast_suitability();
    let paid = original_tx
        .output
        .iter()
        .find(|out| out.script_pubkey == *payee)
        .map(|out| out.value)
        .ok_or("the Original pays Bob")?;
    let wants_outputs = received
        .check_broadcast_suitability(None, |tx| {
            chain::mempool_accepts(client, tx)
                .map_err(|e| ImplementationError::from(e.to_string().as_str()))
        })
        .save(log)?
        .check_inputs_not_owned(&mut |_| Ok(false))
        .save(log)?
        .check_no_inputs_seen_before(&mut |_| Ok(false))
        .save(log)?
        .identify_receiver_outputs(&mut |script| Ok(script == payee.as_script()))
        .save(log)?;
    let coins: &mut Keychain = &mut demo.mallory;
    let (outputs, drain) = match attack {
        Attack::Redirect | Attack::ForeignProof =>
            (vec![TxOut { value: paid, script_pubkey: mallory.clone() }], mallory.clone()),
        Attack::Shrink => (
            vec![
                TxOut { value: paid - Amount::from_sat(1_000), script_pubkey: payee.clone() },
                TxOut { value: Amount::from_sat(1_000), script_pubkey: mallory.clone() },
            ],
            payee.clone(),
        ),
    };
    let wants_inputs =
        wants_outputs.replace_receiver_outputs(outputs, &drain)?.commit_outputs().save(log)?;
    let coin = match attack {
        Attack::Shrink => None,
        _ => Some(coins.spendable().into_iter().next().ok_or("Mallory has a coin")?),
    };
    let wants_inputs = match &coin {
        Some(coin) => wants_inputs.contribute_inputs([coins.input_pair(coin)?])?,
        None => wants_inputs,
    };
    let provisional = wants_inputs
        .commit_inputs()
        .save(log)?
        .apply_fee_range(Some(demo.bob.fee_range.0), Some(demo.bob.fee_range.1))
        .save(log)?;
    let mut psbt = provisional.psbt_to_sign();
    coins.sign(&mut psbt)?;
    let finalized = provisional.finalize_signed_proposal(&psbt).save(log)?;
    let Some(coin) = coin else { return Ok(finalized) };

    let scan = demo.bob.address().scan;
    let prover = match attack {
        Attack::Redirect => coins.bip352_secret(&coin.txout.script_pubkey),
        _ => coins
            .spendable()
            .iter()
            .find(|other| other.outpoint != coin.outpoint)
            .and_then(|other| coins.bip352_secret(&other.txout.script_pubkey)),
    }
    .ok_or("Mallory holds the key")?;
    let aux: [u8; 32] = bitcoin::secp256k1::rand::random();
    let (share, proof) =
        carriage::share_and_proof(&demo.secp, &prover, &scan, &aux).ok_or("provable")?;
    let proposal = log.edit_proposal(|psbt| {
        let index = psbt
            .unsigned_tx
            .input
            .iter()
            .position(|input| input.previous_output == coin.outpoint)
            .expect("contributed");
        carriage::set_share_and_proof(&mut psbt.inputs[index], &scan, &share, &proof);
    })?;
    Ok(proposal)
}
