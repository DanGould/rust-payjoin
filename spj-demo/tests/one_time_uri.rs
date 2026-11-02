//! A stock BIP 77 sender pays a one-time silent payjoin URI.

mod common;

use bitcoin::{Amount, FeeRate, Network};
use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
use payjoin::receive::v2::ReceiverBuilder;
use payjoin::send::v2::SenderBuilder;
use payjoin::PjParam;
use payjoin_test_utils::init_bitcoind_sender_receiver;
use spj_demo::net::{Error, Mailroom};
use spj_demo::regtest;
use spj_demo::uri::OneTimeUri;

#[tokio::test(flavor = "multi_thread")]
async fn stock_sender_ignores_sp_and_payjoins_to_the_address() -> Result<(), Error> {
    let (bitcoind, sender, receiver) =
        init_bitcoind_sender_receiver(None, None).map_err(|e| e.to_string())?;
    let mailroom = Mailroom::start(false).await?;
    let amount = Amount::from_sat(50_000);

    let address = receiver.new_address()?;
    let recv_persister = InMemoryPersister::default();
    let session = ReceiverBuilder::new(
        address.clone(),
        mailroom.directory_url(),
        mailroom.ohttp_keys().clone(),
    )?
    .with_amount(amount)
    .build()
    .save(&recv_persister)?;
    let uri = OneTimeUri::new(session.pj_uri(), common::sp_address()).to_string();
    assert!(uri.contains(&format!("&sp={}&pj=", common::sp_address())), "{uri}");

    // The sender is the stock BIP 77 path from payjoin's documentation.
    let pj_uri = payjoin::Uri::try_from(uri.as_str())?
        .require_network(Network::Regtest)?
        .check_pj_supported()
        .map_err(|_| "a BIP 77 sender sees a payjoin URI")?;
    let PjParam::V2(pj_param) = pj_uri.extras().pj_param() else {
        return Err("a BIP 77 endpoint".into());
    };
    assert_eq!(pj_uri.address(), &address);
    let original = regtest::original_psbt(&sender, pj_uri.address(), amount)?;
    let send_persister = InMemoryPersister::default();
    let sending =
        SenderBuilder::from_parts(original.clone(), pj_param, pj_uri.address(), pj_uri.amount())
            .build_recommended(FeeRate::BROADCAST_MIN)?
            .save(&send_persister)?;
    let (request, context) = sending.create_v2_post_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    let polling = sending.process_response(&response, context).save(&send_persister)?;

    let (request, context) = session.create_poll_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    let OptionalTransitionOutcome::Progress(received) =
        session.process_response(&response, context).save(&recv_persister)?
    else {
        return Err("the Original should be waiting".into());
    };
    assert_eq!(
        received.extract_tx_to_check_broadcast_suitability().compute_txid(),
        original.unsigned_tx.compute_txid()
    );

    let payjoin = common::complete_payjoin(
        &mailroom,
        &receiver,
        received,
        &recv_persister,
        &sender,
        polling,
        &send_persister,
    )
    .await?;
    common::confirm(&bitcoind, &[payjoin.compute_txid()])?;
    assert!(payjoin.input.len() > original.unsigned_tx.input.len(), "the receiver added a coin");
    assert!(payjoin
        .output
        .iter()
        .any(|out| out.script_pubkey == address.script_pubkey() && out.value >= amount));
    Ok(())
}
