//! Two senders pay one contact URI through a contact log on a localhost
//! mailroom, and each payment completes as a payjoin.

mod common;

use std::time::Duration;

use bitcoin::{Address, Amount, FeeRate, Network, Psbt};
use payjoin::persist::InMemoryPersister;
use payjoin::send::v2::{Sender, SenderBuilder, SessionEvent, WithReplyKey};
use payjoin::{HpkeKeyPair, OhttpResponse, Url};
use payjoin_test_utils::init_bitcoind_multi_sender_single_receiver;
use spj_demo::contact::{ContactLog, ContactUri};
use spj_demo::net::{Error, Mailroom, RelayStatus};
use spj_demo::regtest;

const AMOUNT: Amount = Amount::from_sat(50_000);

/// A sender's session for an Original paying `address`, encrypted to the
/// receiver key named in `contact`.
fn sender_session(
    original: &Psbt,
    contact: &ContactUri,
    address: &Address,
) -> Result<(Sender<WithReplyKey>, InMemoryPersister<SessionEvent>), Error> {
    let pj_param = contact.sender_pj_param(Duration::from_secs(600))?;
    let persister = InMemoryPersister::default();
    let session = SenderBuilder::from_parts(original.clone(), &pj_param, address, Some(AMOUNT))
        .build_recommended(FeeRate::BROADCAST_MIN)?
        .save(&persister)?;
    Ok((session, persister))
}

/// Append a sender's Original to the contact's log.
async fn append(
    mailroom: &Mailroom,
    contact: &ContactUri,
    session: &Sender<WithReplyKey>,
) -> Result<(Vec<u8>, OhttpResponse), Error> {
    let (request, context) =
        session.create_contact_log_post_request(mailroom.relay_url(), &contact.log_id)?;
    Ok((mailroom.send(&request).await?, context))
}

#[tokio::test(flavor = "multi_thread")]
async fn contact_log_serves_two_senders() -> Result<(), Error> {
    let (bitcoind, senders, receiver) =
        init_bitcoind_multi_sender_single_receiver(2).map_err(|e| e.to_string())?;
    // One confirmed receiver coin for each payjoin.
    let coinbase = receiver.new_address()?;
    bitcoind.client.generate_to_address(2, &coinbase)?;
    bitcoind.client.generate_to_address(100, &bitcoind.client.new_address()?)?;
    let mailroom = Mailroom::start(true).await?;
    let mut log = ContactLog::new(
        HpkeKeyPair::gen_keypair(),
        receiver.new_address()?,
        Url::parse(mailroom.directory_url())?,
    );
    let contact = log.uri(common::sp_address(), &mailroom).to_string();
    let contact = ContactUri::parse(&contact, Network::Regtest)?;

    // Each sender pays its own receiver address. With silent payments the
    // sender would derive it from the contact's sp address instead.
    let addresses: Vec<Address> =
        senders.iter().map(|_| receiver.new_address()).collect::<Result<_, _>>()?;
    let originals: Vec<Psbt> = senders
        .iter()
        .zip(&addresses)
        .map(|(sender, address)| regtest::original_psbt(sender, address, AMOUNT))
        .collect::<Result<_, _>>()?;
    let mut sessions: Vec<_> = originals
        .iter()
        .zip(&addresses)
        .map(|(original, address)| sender_session(original, &contact, address))
        .collect::<Result<_, _>>()?;

    // Before the receiver creates its log, an append is refused outright.
    let (request, _) =
        sessions[0].0.create_contact_log_post_request(mailroom.relay_url(), &contact.log_id)?;
    let refused = mailroom.send(&request).await.expect_err("the log doesn't exist yet");
    assert_eq!(refused.downcast_ref::<RelayStatus>(), Some(&RelayStatus(403)));

    log.create(&mailroom).await?;
    assert!(log.next(&mailroom).await?.is_none(), "a new log is empty");

    // A writer that doesn't hold the receiver key's public half encrypts to
    // another key. The directory takes its frame, and the receiver skips it.
    let stranger = ContactUri {
        receiver_pubkey: HpkeKeyPair::gen_keypair().public_key().clone(),
        ..contact.clone()
    };
    let (stranger, _) = sender_session(&originals[0], &stranger, &addresses[0])?;

    let (first, first_persister) = sessions.remove(0);
    let (second, second_persister) = sessions.remove(0);
    let (response, context) = append(&mailroom, &contact, &first).await?;
    let first = first.process_response(&response, context).save(&first_persister)?;
    append(&mailroom, &contact, &stranger).await?;
    let (response, context) = append(&mailroom, &contact, &second).await?;
    let second = second.process_response(&response, context).save(&second_persister)?;
    let polling = [(first, first_persister), (second, second_persister)];

    let mut inbound = Vec::new();
    while let Some(payment) = log.next(&mailroom).await? {
        inbound.push(payment);
    }
    let indices: Vec<usize> = inbound.iter().map(|payment| payment.index).collect();
    assert_eq!(indices, [0, 2], "the stranger's frame at 1 is skipped");
    assert_eq!(log.next_index(), 3);

    let mut payjoins = Vec::new();
    for ((payment, (session, send_persister)), (sender, original)) in
        inbound.into_iter().zip(polling).zip(senders.iter().zip(&originals))
    {
        assert_eq!(
            payment.receiver.extract_tx_to_check_broadcast_suitability().compute_txid(),
            original.unsigned_tx.compute_txid(),
            "frames arrive in the order sent"
        );
        let payjoin = common::complete_payjoin(
            &mailroom,
            &receiver,
            payment.receiver,
            &payment.persister,
            sender,
            session,
            &send_persister,
        )
        .await?;
        assert!(
            payjoin.input.len() > original.unsigned_tx.input.len(),
            "the receiver added a coin"
        );
        payjoins.push(payjoin);
    }

    let txids: Vec<_> = payjoins.iter().map(|tx| tx.compute_txid()).collect();
    common::confirm(&bitcoind, &txids)?;
    for (payjoin, address) in payjoins.iter().zip(&addresses) {
        assert!(payjoin
            .output
            .iter()
            .any(|out| out.script_pubkey == address.script_pubkey() && out.value >= AMOUNT));
    }
    let receiver_inputs: Vec<Vec<_>> = payjoins
        .iter()
        .zip(&originals)
        .map(|(payjoin, original)| {
            payjoin
                .input
                .iter()
                .map(|input| input.previous_output)
                .filter(|outpoint| {
                    original.unsigned_tx.input.iter().all(|i| i.previous_output != *outpoint)
                })
                .collect()
        })
        .collect();
    assert_eq!(receiver_inputs[0].len(), 1);
    assert_eq!(receiver_inputs[1].len(), 1);
    assert_ne!(receiver_inputs[0], receiver_inputs[1], "each payment gets its own receiver coin");
    Ok(())
}
