//! Payment flows over a regtest node and a localhost mailroom: funding the
//! parties' keychains, the receiver's one-time sessions, and each message a
//! sender or receiver posts or polls for.

use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
use payjoin::receive::v2::{
    Initialized, PayjoinProposal, Receiver, ReceiverBuilder, UncheckedOriginalPayload,
};
use payjoin::send::v2::{
    PollingForProposal, Sender, SenderBuilder, SessionEvent as SendEvent, WithReplyKey,
};
use payjoin::uri::v2::PjParam as V2PjParam;
use payjoin::{HpkeKeyPair, PjParam};
use payjoin_test_utils::bitcoind;
use spj_crypto::bip352;

use crate::contact::ContactUri;
use crate::net::{Error, Mailroom};
use crate::persist::EventLog;
use crate::sp_address::SpAddress;
use crate::uri::OneTimeUri;
use crate::wallet::Keychain;
use crate::{chain, derive};

/// The fee rate every Original in the demo pays.
pub const ORIGINAL_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_u32(2);

/// A regtest node with a transaction index and a funded wallet, and a
/// mailroom. Both stop when this is dropped.
pub struct Regtest {
    pub node: bitcoind::BitcoinD,
    pub mailroom: Mailroom,
    mine_to: Address,
}

impl Regtest {
    pub async fn start() -> Result<Self, Error> {
        let mut conf = bitcoind::Conf::default();
        // Restores and the explorer look up confirmed transactions by txid.
        conf.args.push("-txindex");
        let node = bitcoind::BitcoinD::with_conf(bitcoind::exe_path()?, &conf)?;
        let mine_to = node.client.new_address()?;
        chain::mine(&node.client, 101, &mine_to)?;
        let mailroom = Mailroom::start(true).await?;
        Ok(Self { node, mailroom, mine_to })
    }

    pub fn client(&self) -> &bitcoind::Client { &self.node.client }

    pub fn mine(&self, blocks: u64) -> Result<(), Error> {
        chain::mine(self.client(), blocks, &self.mine_to)?;
        Ok(())
    }

    /// Mine a block and check each of `txids` is in it.
    pub fn confirm(&self, txids: &[Txid]) -> Result<u64, Error> {
        self.mine(1)?;
        let height = chain::height(self.client())?;
        let block: Vec<Txid> =
            chain::block(self.client(), height)?.iter().map(Transaction::compute_txid).collect();
        for txid in txids {
            if !block.contains(txid) {
                return Err(format!("{txid} was not mined").into());
            }
        }
        Ok(height)
    }

    /// Pay each of `amounts` to a fresh address of `keychain` and confirm.
    pub fn fund(&self, keychain: &mut Keychain, amounts: &[Amount]) -> Result<(), Error> {
        let mut txids = Vec::new();
        for amount in amounts {
            let address = keychain.address();
            let txid = self.client().send_to_address(&address, *amount)?.txid()?;
            txids.push(txid);
        }
        self.confirm(&txids)?;
        for txid in txids {
            keychain.credit(&chain::raw_tx(self.client(), txid)?);
        }
        Ok(())
    }
}

/// A receiver's session behind one one-time URI.
pub struct OneTime {
    pub uri: OneTimeUri,
    pub session: Receiver<Initialized>,
    pub log: EventLog,
    /// The session's mailbox key. Whoever holds it can read the Original and
    /// answer in the receiver's place.
    pub key: HpkeKeyPair,
}

/// Open a one-time session for `amount` to `sp`, with `body` as the address a
/// sender without silent payments pays.
pub fn one_time(
    mailroom: &Mailroom,
    sp: SpAddress,
    body: Address,
    amount: Amount,
) -> Result<OneTime, Error> {
    let key = HpkeKeyPair::gen_keypair();
    let (session, log) = session_with_key(mailroom, &key, body, Some(amount))?;
    let uri = OneTimeUri::new(session.pj_uri(), sp);
    Ok(OneTime { uri, session, log, key })
}

/// A receiver session under an existing mailbox key, as a second holder of
/// that key opens it.
pub fn session_with_key(
    mailroom: &Mailroom,
    key: &HpkeKeyPair,
    body: Address,
    amount: Option<Amount>,
) -> Result<(Receiver<Initialized>, EventLog), Error> {
    let log = EventLog::default();
    let mut builder =
        ReceiverBuilder::new(body, mailroom.directory_url(), mailroom.ohttp_keys().clone())?
            .with_receiver_key(key.clone());
    if let Some(amount) = amount {
        builder = builder.with_amount(amount);
    }
    let session = builder.build().save(&log)?;
    Ok((session, log))
}

/// Read a one-time mailbox. `None` if no Original is waiting.
pub async fn poll_original(
    mailroom: &Mailroom,
    session: Receiver<Initialized>,
    log: &EventLog,
) -> Result<Option<Receiver<UncheckedOriginalPayload>>, Error> {
    let (request, context) = session.create_poll_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    match session.process_response(&response, context).save(log)? {
        OptionalTransitionOutcome::Progress(original) => Ok(Some(original)),
        OptionalTransitionOutcome::Stasis(_) => Ok(None),
    }
}

/// Post a proposal to the sender's reply mailbox.
pub async fn post_proposal(
    mailroom: &Mailroom,
    proposal: &Receiver<PayjoinProposal>,
    log: &EventLog,
) -> Result<(), Error> {
    let (request, context) = proposal.create_post_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    proposal.clone().process_response(&response, context).save(log)?;
    Ok(())
}

/// An Original paying a silent payment address, and what the sender keeps
/// to check proposals against it.
pub struct SpOriginal {
    pub psbt: Psbt,
    /// The BIP 352 secret of each input, keyed by outpoint.
    pub own: BTreeMap<OutPoint, SecretKey>,
    /// The output derived for the recipient.
    pub payee: ScriptBuf,
}

impl SpOriginal {
    pub fn tx(&self) -> Transaction { crate::wallet::extract(&self.psbt) }

    pub fn payee_address(&self) -> Address {
        Address::from_script(&self.payee, Network::Regtest).expect("a P2TR script")
    }
}

/// Build and sign an Original from `keychain` paying `amount` to `sp`.
pub fn sp_original(
    secp: &Secp256k1<All>,
    keychain: &mut Keychain,
    sp: &SpAddress,
    amount: Amount,
) -> Result<SpOriginal, Error> {
    sp_original_at(secp, keychain, sp, amount, ORIGINAL_FEE_RATE)
}

/// [`sp_original`] at another fee rate.
pub fn sp_original_at(
    secp: &Secp256k1<All>,
    keychain: &mut Keychain,
    sp: &SpAddress,
    amount: Amount,
    fee_rate: FeeRate,
) -> Result<SpOriginal, Error> {
    let coins = keychain
        .select(amount + Amount::from_sat(2_000))
        .ok_or_else(|| format!("{} can't fund {amount}", keychain.name))?;
    let own: BTreeMap<OutPoint, SecretKey> = coins
        .iter()
        .map(|coin| {
            let secret = keychain.bip352_secret(&coin.txout.script_pubkey).expect("own coin");
            (coin.outpoint, secret)
        })
        .collect();
    let secrets: Vec<SecretKey> = own.values().copied().collect();
    let outpoints: Vec<OutPoint> = coins.iter().map(|coin| coin.outpoint).collect();
    let recipient = bip352::SpAddress { scan: sp.scan, spend: sp.spend };
    let [key] = bip352::sender_outputs(secp, &secrets, &outpoints, &[recipient])?[..] else {
        return Err("one recipient, one output".into());
    };
    let payee = derive::p2tr_script(key);
    let psbt = keychain.original(
        &coins,
        vec![TxOut { value: amount, script_pubkey: payee.clone() }],
        fee_rate,
    )?;
    Ok(SpOriginal { psbt, own, payee })
}

/// A sender's session, from posting the Original to reading the proposal.
pub struct Sending {
    pub session: Sender<PollingForProposal>,
    pub persister: InMemoryPersister<SendEvent>,
}

fn sender_session(
    original: &Psbt,
    pj_param: &V2PjParam,
    payee: &Address,
    amount: Amount,
    disable_substitution: bool,
) -> Result<(Sender<WithReplyKey>, InMemoryPersister<SendEvent>), Error> {
    let persister = InMemoryPersister::default();
    let mut builder = SenderBuilder::from_parts(original.clone(), pj_param, payee, Some(amount));
    if disable_substitution {
        builder = builder.always_disable_output_substitution();
    }
    let session = builder.build_recommended(FeeRate::BROADCAST_MIN)?.save(&persister)?;
    Ok((session, persister))
}

/// The BIP 77 parameters of a one-time URI.
pub fn one_time_param(uri: &OneTimeUri) -> Result<V2PjParam, Error> {
    match uri.payjoin.as_ref().ok_or("the URI has no pj=")?.extras().pj_param() {
        PjParam::V2(param) => Ok(param.clone()),
        _ => Err("a BIP 77 endpoint".into()),
    }
}

/// Post an Original to a one-time mailbox.
pub async fn post_original(
    mailroom: &Mailroom,
    original: &Psbt,
    pj_param: &V2PjParam,
    payee: &Address,
    amount: Amount,
    disable_substitution: bool,
) -> Result<Sending, Error> {
    let (session, persister) =
        sender_session(original, pj_param, payee, amount, disable_substitution)?;
    let (request, context) = session.create_v2_post_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    let session = session.process_response(&response, context).save(&persister)?;
    Ok(Sending { session, persister })
}

/// Append an Original to a contact's log, asking for a reply within
/// `reply_by`.
pub async fn post_to_contact(
    mailroom: &Mailroom,
    contact: &ContactUri,
    original: &Psbt,
    payee: &Address,
    amount: Amount,
    reply_by: Duration,
) -> Result<Sending, Error> {
    let pj_param = contact.sender_pj_param(reply_by)?;
    let (session, persister) = sender_session(original, &pj_param, payee, amount, false)?;
    let (request, context) =
        session.create_contact_log_post_request(mailroom.relay_url(), &contact.log_id)?;
    let response = mailroom.send(&request).await?;
    let session = session.process_response(&response, context).save(&persister)?;
    Ok(Sending { session, persister })
}

/// The receiver's proposal, if one is waiting in the reply mailbox, after
/// PDK's BIP 78 checks.
pub async fn poll_proposal(mailroom: &Mailroom, sending: &Sending) -> Result<Option<Psbt>, Error> {
    let (request, context) = sending.session.create_poll_request(mailroom.relay_url())?;
    let response = mailroom.send(&request).await?;
    match sending.session.clone().process_response(&response, context).save(&sending.persister)? {
        OptionalTransitionOutcome::Progress(psbt) => Ok(Some(psbt)),
        OptionalTransitionOutcome::Stasis(_) => Ok(None),
    }
}
