//! Scene 1: why wallets switch one feature off today. Alice pays Bob's
//! silent payment address, Bob answers as a plain payjoin receiver does, and
//! the payment confirms in an output a restore from Bob's seed can't find.

use bitcoin::{Amount, OutPoint, ScriptBuf};
use payjoin::receive::v2::{Receiver, UncheckedOriginalPayload};
use payjoin::ImplementationError;

use super::Demo;
use crate::narrate::{sats, short};
use crate::net::Error;
use crate::persist::EventLog;
use crate::wallet::Keychain;
use crate::{chain, flow};

const AMOUNT: Amount = Amount::from_sat(50_000);

pub async fn run(demo: &mut Demo) -> Result<(), Error> {
    demo.n.scene(1, "Today: a plain payjoin to a silent payment address");
    let start = demo.height()?;
    let one_time =
        flow::one_time(&demo.regtest.mailroom, demo.bob.address(), demo.bob_hot.address(), AMOUNT)?;
    let original = flow::sp_original(&demo.secp, &mut demo.alice, &one_time.uri.sp, AMOUNT)?;
    let original_tx = original.tx();
    let prevouts = chain::prevouts(demo.client(), &original_tx)?;
    let found_in_original = crate::derive::scan(
        &demo.secp,
        &demo.bob.keys,
        demo.bob.labels.table(),
        &original_tx,
        &prevouts,
    );
    demo.n.say(
        "Alice",
        &format!(
            "pays Bob's sp1 the usual BIP 352 way: output {} for {}",
            short(&original.payee.to_hex_string()[4..]),
            sats(AMOUNT)
        ),
    );
    demo.n.check("Bob", "a scan of that Original finds the payment", found_in_original.len() == 1);

    let sending = flow::post_original(
        &demo.regtest.mailroom,
        &original.psbt,
        &flow::one_time_param(&one_time.uri)?,
        &original.payee_address(),
        AMOUNT,
        false,
    )
    .await?;
    let received = flow::poll_original(&demo.regtest.mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("the Original should be waiting")?;
    let coin = plain_payjoin(demo, received, &one_time.log, &original.payee).await?;
    demo.n.say(
        "Bob",
        &format!(
            "plain payjoin: adds coin {} and leaves the output as it was",
            crate::sender::short_outpoint(&coin)
        ),
    );

    // Today's sender has no proposal check for silent payments; PDK's BIP 78
    // checks pass, since the payee output is unchanged.
    let mut psbt = flow::poll_proposal(&demo.regtest.mailroom, &sending)
        .await?
        .ok_or("the proposal should be waiting")?;
    demo.alice.sign(&mut psbt)?;
    let payjoin = crate::wallet::extract(&psbt);
    let txid = chain::broadcast(demo.client(), &payjoin)?;
    let height = demo.regtest.confirm(&[txid])?;
    demo.alice.credit(&payjoin);
    demo.bob_hot.credit(&payjoin);
    demo.n.say(
        "Alice",
        &format!(
            "PDK's checks pass; signs and broadcasts the payjoin {}, confirmed in block {height}",
            short(&txid.to_string())
        ),
    );

    let confirmed = demo.tx(txid)?;
    let pays_original_output =
        confirmed.output.iter().any(|out| out.script_pubkey == original.payee);
    let has_bob_coin = confirmed.input.iter().any(|input| input.previous_output == coin);
    let restored = demo.restore_since(start)?;
    let found = restored.iter().any(|f| f.outpoint.txid == txid);
    demo.n.check(
        "Bob",
        "a restore from seed scans the new blocks and finds nothing, because the output depends \
         on every input's key",
        !found,
    );
    demo.n.why("the key to the output exists, but nothing in Bob's seed leads a scan to it");
    demo.n.verdict(
        demo.confirmed(txid)? && pays_original_output && has_bob_coin && !found,
        &format!(
            "payjoin {} confirmed with Bob's coin and the Original's output, and a restore from \
             Bob's seed finds nothing in it",
            short(&txid.to_string())
        ),
    );
    Ok(())
}

/// Answer as a payjoin receiver without silent payment rules: identify the
/// payee output by script, keep it, and add a coin.
async fn plain_payjoin(
    demo: &mut Demo,
    received: Receiver<UncheckedOriginalPayload>,
    log: &EventLog,
    payee: &ScriptBuf,
) -> Result<OutPoint, Error> {
    let client = demo.regtest.client();
    let coins: &mut Keychain = &mut demo.bob_hot;
    let coin = coins.spendable().into_iter().next().ok_or("Bob has a coin")?;
    let proposal = received
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
        .save(log)?
        .commit_outputs()
        .save(log)?
        .contribute_inputs([coins.input_pair(&coin)?])?
        .commit_inputs()
        .save(log)?
        .apply_fee_range(Some(demo.bob.fee_range.0), Some(demo.bob.fee_range.1))
        .save(log)?;
    let mut psbt = proposal.psbt_to_sign();
    coins.sign(&mut psbt)?;
    let proposal = proposal.finalize_signed_proposal(&psbt).save(log)?;
    flow::post_proposal(&demo.regtest.mailroom, &proposal, log).await?;
    Ok(coin.outpoint)
}
