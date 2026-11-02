//! Scene 2: a wallet without silent payments pays Bob's one-time URI with
//! PDK's stock BIP 77 sender. It ignores `sp=`, pays the address in the
//! body, and Bob's coin makes it an ordinary payjoin.

use bitcoin::{Amount, Network};
use payjoin::send::v2::SenderBuilder;
use payjoin::PjParam;

use super::{bob_answers, Demo};
use crate::flow::{self, Sending};
use crate::narrate::{sats, short};
use crate::net::Error;
use crate::{chain, regtest};

const AMOUNT: Amount = Amount::from_sat(40_000);

pub async fn run(demo: &mut Demo) -> Result<(), Error> {
    demo.n.scene(2, "A one-time URI paid by a wallet without silent payments");
    let body = demo.bob_hot.address();
    let one_time =
        flow::one_time(&demo.regtest.mailroom, demo.bob.address(), body.clone(), AMOUNT)?;
    let uri = one_time.uri.to_string();
    demo.n.say("Bob", &format!("shows a one-time URI: {uri}"));

    let pj_uri = payjoin::Uri::try_from(uri.as_str())?
        .require_network(Network::Regtest)?
        .check_pj_supported()
        .map_err(|_| "a BIP 77 URI")?;
    let PjParam::V2(pj_param) = pj_uri.extras().pj_param() else {
        return Err("a BIP 77 endpoint".into());
    };
    demo.n.say(
        "Carol",
        &format!(
            "the wallet's BIP 21 parser ignores sp= and sees a payjoin URI for {}",
            short(&pj_uri.address().to_string())
        ),
    );
    let original = regtest::original_psbt(&demo.carol, pj_uri.address(), AMOUNT)?;
    let persister = Default::default();
    let session =
        SenderBuilder::from_parts(original.clone(), pj_param, pj_uri.address(), pj_uri.amount())
            .build_recommended(bitcoin::FeeRate::BROADCAST_MIN)?
            .save(&persister)?;
    let (request, context) = session.create_v2_post_request(demo.regtest.mailroom.relay_url())?;
    let response = demo.regtest.mailroom.send(&request).await?;
    let session = session.process_response(&response, context).save(&persister)?;
    let sending = Sending { session, persister };
    demo.n.say("Carol", "posts a signed Original to Bob's mailbox with PDK's stock BIP 77 sender");

    let received = flow::poll_original(&demo.regtest.mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("the Original should be waiting")?;
    let proposal = bob_answers(
        &demo.n,
        &demo.regtest,
        &mut demo.bob,
        &mut demo.bob_hot,
        "the one-time coins",
        "Carol",
        received,
        &one_time.log,
        Some(&body.script_pubkey()),
    )
    .await?
    .ok_or("Bob should answer")?;

    let psbt = flow::poll_proposal(&demo.regtest.mailroom, &sending)
        .await?
        .ok_or("the proposal should be waiting")?;
    let payjoin = regtest::sign_proposal(&demo.carol, psbt)?;
    let txid = chain::broadcast(demo.client(), &payjoin)?;
    let height = demo.regtest.confirm(&[txid])?;
    // A payment Bob received isn't offered to later payers, who would
    // learn of it from the coin.
    demo.bob_hot.forget_spent(&payjoin);
    demo.n.say(
        "Carol",
        &format!(
            "PDK's checks pass; Bitcoin Core signs and broadcasts payjoin {}, confirmed in block {height}",
            short(&txid.to_string())
        ),
    );

    let confirmed = demo.tx(txid)?;
    let has_bob_coin =
        confirmed.input.iter().any(|input| input.previous_output == proposal.coin.outpoint);
    let to_body = confirmed
        .output
        .iter()
        .find(|out| out.script_pubkey == body.script_pubkey())
        .map(|out| out.value);
    demo.n.check(
        "Bob",
        &format!(
            "the address in the URI body receives {}",
            to_body.map(sats).unwrap_or_else(|| "nothing".into())
        ),
        to_body.is_some_and(|value| value >= AMOUNT),
    );
    demo.n.verdict(
        demo.confirmed(txid)? && has_bob_coin && to_body.is_some_and(|value| value >= AMOUNT),
        &format!(
            "payjoin {} confirmed with Bob's coin, paying the URI's address at least {}",
            short(&txid.to_string()),
            sats(AMOUNT)
        ),
    );
    Ok(())
}
