//! Steps both end-to-end tests share.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Network, Transaction, Txid};
use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
use payjoin::receive::v2::{Receiver, SessionEvent, UncheckedOriginalPayload};
use payjoin::send::v2::{PollingForProposal, Sender, SessionEvent as SendEvent};
use payjoin_test_utils::bitcoind;
use spj_demo::net::{Error, Mailroom};
use spj_demo::regtest;
use spj_demo::sp_address::SpAddress;

/// A regtest silent payment address. These tests never derive an output from
/// it; it only has to survive the payment string.
pub fn sp_address() -> SpAddress {
    let secp = Secp256k1::new();
    let key = |byte| SecretKey::from_slice(&[byte; 32]).unwrap().public_key(&secp);
    SpAddress::new(key(0x51), key(0x52), Network::Regtest)
}

/// Complete one payjoin from a received Original: the receiver adds a coin
/// and posts the proposal, and the sender signs and broadcasts it.
pub async fn complete_payjoin(
    mailroom: &Mailroom,
    receiver: &bitcoind::Client,
    original: Receiver<UncheckedOriginalPayload>,
    recv_persister: &InMemoryPersister<SessionEvent>,
    sender: &bitcoind::Client,
    session: Sender<PollingForProposal>,
    send_persister: &InMemoryPersister<SendEvent>,
) -> Result<Transaction, Error> {
    let proposal = regtest::propose(receiver, original, recv_persister)?;
    let (request, context) = proposal.create_post_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    proposal.process_response(&response, context).save(recv_persister)?;

    let (request, context) = session.create_poll_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    let OptionalTransitionOutcome::Progress(psbt) =
        session.process_response(&response, context).save(send_persister)?
    else {
        return Err("the receiver's proposal should be waiting".into());
    };
    let tx = regtest::sign_proposal(sender, psbt)?;
    sender.send_raw_transaction(&tx)?;
    Ok(tx)
}

/// Mine a block and check that each of `txids` is in it.
pub fn confirm(bitcoind: &bitcoind::BitcoinD, txids: &[Txid]) -> Result<(), Error> {
    let address = bitcoind.client.new_address()?;
    let block_hash = bitcoind.client.generate_to_address(1, &address)?.into_model()?.0[0];
    let block = bitcoind.client.get_block(block_hash)?;
    for txid in txids {
        if !block.txdata.iter().any(|tx| tx.compute_txid() == *txid) {
            return Err(format!("{txid} was not mined").into());
        }
    }
    Ok(())
}
