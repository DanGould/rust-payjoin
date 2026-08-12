//! Shared scene machinery: the cast of wallets, the payment engine
//! that walks a full static payjoin round, and the receiver's response
//! policy. Scenes stay short by leaning on these.

pub mod s1_static_reuse;
pub mod s2_async_board;
pub mod s3_floor;
pub mod s4_token_upgrade;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut};
use payjoin::receive::v2::static_session::{
    replay_static_event_log as replay_receiver_log, InboundProposal, StaticReceiveSession,
    StaticReceiver, StaticReceiverBuilder, StaticSessionEvent as ReceiverStaticEvent,
};
use payjoin::receive::v2::{
    PayjoinProposal, Receiver, SessionEvent as ReceiverSessionEvent, UncheckedOriginalPayload,
};
use payjoin::receive::InputPair;
use payjoin::send::v2::static_session::{
    replay_static_event_log as replay_sender_log, StaticSendSession, StaticSenderBuilder,
    StaticSessionEvent as SenderStaticEvent,
};
use payjoin::{ImplementationError, OhttpKeys, Uri};
use payjoin_test_utils::corepc_node::{self, AddressType, Client};

use crate::narrate::Narrator;
use crate::net::{Mailroom, MailroomOpts, BLOB_BYTES};
use crate::persist::JsonlPersister;
use crate::sp::{self, SpAddress, SpKeys};
use crate::wallet::DemoWallet;

/// The relay a production client would deliver through. In this demo
/// its role is played by the in-process gateway, so the value is only a
/// label in requests.
pub const RELAY_URL: &str = "https://relay.localhost";

/// The directory address baked into the receiver's published string.
pub const DIRECTORY_URL: &str = "https://mailroom.localhost";

/// Weight of a keyspend taproot input, for receiver contributions.
const P2TR_INPUT_WEIGHT: u64 = 230;

pub type BoxError = Box<dyn std::error::Error>;

/// Everything scenes share: the node, the directory, the receiver's
/// keys and session log, and the record of inputs seen across
/// payments.
pub struct Demo {
    pub narrator: Narrator,
    pub mailroom: Mailroom,
    pub secp: Secp256k1<All>,
    pub bitcoind: corepc_node::Node,
    pub miner: Client,
    pub receiver_wallet: Client,
    pub sp_keys: SpKeys,
    pub sp_address: SpAddress,
    pub static_uri: String,
    pub receiver_log: JsonlPersister<ReceiverStaticEvent>,
    pub state_dir: PathBuf,
    pub seen_outpoints: HashSet<OutPoint>,
    pub scan_from_height: u64,
    /// Demo-side repeat-sender tokens. Production gates these at the
    /// mailroom queue; here the demo enforces them at delivery time.
    pub tokens: HashSet<String>,
    /// Monotonic id giving every payment a unique session-log path.
    payment_seq: std::cell::Cell<u64>,
    /// Monotonic id for each freshly published static endpoint.
    endpoint_seq: std::cell::Cell<u64>,
}

pub async fn setup(narrator: Narrator) -> Result<Demo, BoxError> {
    let secp = Secp256k1::new();
    let bitcoind = payjoin_test_utils::init_bitcoind()?;
    let miner = bitcoind.create_wallet("miner")?;
    let miner_address = miner.new_address()?;
    bitcoind.client.generate_to_address(110, &miner_address)?;

    let receiver_wallet = bitcoind.create_wallet("receiver-hd")?;
    let receiver_funding = receiver_wallet
        .get_new_address(None, Some(AddressType::Bech32m))?
        .into_model()?
        .0
        .assume_checked();
    miner.send_to_address(&receiver_funding, Amount::from_btc(5.0)?)?;
    bitcoind.client.generate_to_address(1, &miner_address)?;

    let mailroom =
        Mailroom::start(MailroomOpts { board_pow_bits: 14, board_cap: 64, queue_frame_cap: 64 })
            .await?;

    let sp_keys = SpKeys::from_seed(b"static payjoin demo receiver seed");
    let sp_address = sp_keys.address(&secp);

    let state_dir = tempfile::tempdir()?.keep();
    let scan_from_height = block_count(&bitcoind.client)?;

    let mut demo = Demo {
        narrator,
        mailroom,
        secp,
        bitcoind,
        miner,
        receiver_wallet,
        sp_keys,
        sp_address,
        static_uri: String::new(),
        receiver_log: JsonlPersister::new(state_dir.join("receiver-0.jsonl")),
        state_dir,
        seen_outpoints: HashSet::new(),
        scan_from_height,
        tokens: HashSet::new(),
        payment_seq: std::cell::Cell::new(0),
        endpoint_seq: std::cell::Cell::new(0),
    };
    demo.publish_endpoint()?;
    Ok(demo)
}

impl Demo {
    pub fn mine(&self, blocks: usize) -> Result<(), BoxError> {
        let address = self.miner.new_address()?;
        self.bitcoind.client.generate_to_address(blocks, &address)?;
        Ok(())
    }

    /// Replay the receiver's static session from its on-disk log.
    pub fn wake_receiver(&self) -> Result<StaticReceiver, BoxError> {
        match replay_receiver_log(&self.receiver_log)?.0 {
            StaticReceiveSession::Live(receiver) => Ok(receiver),
            StaticReceiveSession::Closed => Err("static session closed".into()),
        }
    }

    /// One receiver poll of the static queue: returns the proposals
    /// retrieved, if any.
    pub async fn receiver_poll(&mut self) -> Result<Vec<InboundProposal>, BoxError> {
        let receiver = self.wake_receiver()?;
        let (req, ctx) = receiver.create_poll_request(RELAY_URL)?;
        let body = self.mailroom.deliver(&req).await?;
        let (_, proposals) = receiver
            .process_response(&body, ctx)
            .save(&self.receiver_log)
            .map_err(|e| format!("static poll failed: {e:?}"))?;
        Ok(proposals)
    }

    /// Fresh taproot address from the receiver's bitcoind wallet.
    pub fn fresh_receiver_address(&self) -> Result<Address, BoxError> {
        Ok(self
            .receiver_wallet
            .get_new_address(None, Some(AddressType::Bech32m))?
            .into_model()?
            .0
            .assume_checked())
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<bitcoin::Txid, BoxError> {
        let txid = tx.compute_txid();
        self.miner.send_raw_transaction(tx)?;
        Ok(txid)
    }

    fn next_payment_id(&self) -> u64 {
        let id = self.payment_seq.get();
        self.payment_seq.set(id + 1);
        id
    }

    /// Publish a fresh static endpoint: a new receiver HPKE key, hence a
    /// new queue, on its own session log. Scenes call this so one
    /// scene's queue traffic never leaks into the next. The silent
    /// payment keys stay fixed, since they are the receiver's on-chain
    /// identity, not per-endpoint.
    pub fn publish_endpoint(&mut self) -> Result<(), BoxError> {
        let id = self.endpoint_seq.get();
        self.endpoint_seq.set(id + 1);
        self.receiver_log =
            JsonlPersister::new(self.state_dir.join(format!("receiver-{id}.jsonl")));
        let placeholder = Address::p2tr(
            &self.secp,
            self.sp_address.spend.x_only_public_key().0,
            None,
            Network::Regtest,
        );
        let ohttp_keys = OhttpKeys::decode(self.mailroom.ohttp_keys())?;
        let receiver = StaticReceiverBuilder::new(
            placeholder,
            DIRECTORY_URL,
            ohttp_keys,
            payjoin::HpkeKeyPair::gen_keypair(),
        )?
        .build()
        .save(&self.receiver_log)?;
        self.static_uri = receiver.pj_uri().to_string();
        Ok(())
    }
}

fn block_count(client: &Client) -> Result<u64, BoxError> {
    Ok(client.get_block_count()?.into_model().0)
}

/// Swap the address slot of a payjoin URI for a per-payment one; every
/// other parameter (endpoint, keys) stays the receiver's static set.
pub fn uri_with_address(static_uri: &str, address: &Address) -> Result<String, BoxError> {
    let (_, params) = static_uri.split_once('?').ok_or("static string carries no parameters")?;
    Ok(format!("bitcoin:{address}?{params}"))
}

/// A payment in flight: the sender posted its original transaction to
/// the receiver's queue and is polling for a proposal.
pub struct InFlightPayment {
    pub sender_name: &'static str,
    pub sp_script: ScriptBuf,
    pub log: JsonlPersister<SenderStaticEvent>,
}

/// Derive the per-payment fallback output, build and sign the original
/// transaction, and post it to the receiver's static queue.
pub async fn send_message_a(
    demo: &mut Demo,
    wallet: &DemoWallet,
    amount: Amount,
    patience: Option<Duration>,
) -> Result<InFlightPayment, BoxError> {
    let fee_headroom = Amount::from_sat(2_000);
    let (outpoint, prevout) =
        wallet.select_utxo(amount + fee_headroom).ok_or("sender lacks a large enough coin")?;
    let output_key =
        sp::sender_derive_output(&demo.secp, &wallet.input_keys(), &[outpoint], &demo.sp_address)
            .ok_or("silent payment derivation failed")?;
    let sp_script = sp::output_script(output_key);
    let pay_to = Address::from_script(&sp_script, Network::Regtest)?;

    let uri = uri_with_address(&demo.static_uri, &pay_to)?;
    let uri = Uri::try_from(uri.as_str())
        .map_err(|e| format!("per-payment uri: {e}"))?
        .assume_checked()
        .check_pj_supported()
        .map_err(|e| format!("per-payment uri lost payjoin support: {e}"))?;

    let psbt = wallet.build_original_from(
        outpoint,
        &prevout,
        sp_script.clone(),
        amount,
        FeeRate::BROADCAST_MIN,
    )?;

    let log = JsonlPersister::<SenderStaticEvent>::new(demo.state_dir.join(format!(
        "sender-{}-{}.jsonl",
        wallet.name,
        demo.next_payment_id()
    )));
    let mut builder = StaticSenderBuilder::new(psbt, uri);
    if let Some(patience) = patience {
        builder = builder.with_patience(patience);
    }
    let sender = builder.build_recommended(FeeRate::BROADCAST_MIN)?.save(&log)?;

    let (req, ctx) = sender.create_v2_post_request(RELAY_URL)?;
    let body = demo.mailroom.deliver(&req).await?;
    sender
        .process_response(&body, ctx)
        .save(&log)
        .map_err(|e| format!("posting original failed: {e:?}"))?;

    Ok(InFlightPayment { sender_name: wallet.name, sp_script, log })
}

/// The sender's side of finishing: poll the reply mailbox, sign the
/// proposal, broadcast, and confirm.
pub async fn complete_payment(
    demo: &mut Demo,
    wallet: &mut DemoWallet,
    payment: InFlightPayment,
) -> Result<Transaction, BoxError> {
    // Replayed from disk rather than held in memory: every step of the
    // sender machine works from its persisted log.
    let StaticSendSession::PollingForProposal(session) = replay_sender_log(&payment.log)?.0 else {
        return Err("sender is not polling for a proposal".into());
    };
    let (req, ctx) = session.create_poll_request(RELAY_URL)?;
    let body = demo.mailroom.deliver(&req).await?;
    let outcome = session
        .process_response(&body, ctx)
        .save(&payment.log)
        .map_err(|e| format!("sender poll failed: {e:?}"))?;
    let psbt: Psbt = match outcome {
        payjoin::persist::OptionalTransitionOutcome::Progress(psbt) => psbt,
        payjoin::persist::OptionalTransitionOutcome::Stasis(_) =>
            return Err("no proposal waiting in the reply mailbox".into()),
    };
    let tx = wallet.sign_proposal(psbt)?;
    demo.broadcast(&tx)?;
    demo.mine(1)?;
    wallet.credit_outputs(&tx);
    Ok(tx)
}

/// The sender's floor: give up on the receiver and broadcast the
/// original transaction, which pays the derived silent payment output.
pub async fn fall_back(
    demo: &mut Demo,
    wallet: &mut DemoWallet,
    payment: InFlightPayment,
) -> Result<Transaction, BoxError> {
    let session = match replay_sender_log(&payment.log)?.0 {
        StaticSendSession::PollingForProposal(session) => session.cancel().save(&payment.log)?,
        StaticSendSession::PendingFallback(session) => session,
        _ => return Err("sender has nothing to fall back from".into()),
    };
    let tx = session.fallback_tx().clone();
    demo.broadcast(&tx)?;
    demo.mine(1)?;
    wallet.credit_outputs(&tx);
    Ok(tx)
}

/// The receiver's response policy for a legitimate-looking proposal:
/// run every validation, substitute a fresh wallet address for the
/// derived output, contribute an input, and post the signed proposal to
/// the sender's reply mailbox. Returns the substituted script.
pub async fn respond_with_payjoin(
    demo: &mut Demo,
    proposal: InboundProposal,
    expected_script: &ScriptBuf,
    label: &str,
) -> Result<ScriptBuf, BoxError> {
    let log = JsonlPersister::<ReceiverSessionEvent>::new(
        demo.state_dir.join(format!("receiver-payment-{label}.jsonl")),
    );
    let receiver = proposal.save(&log)?;
    let checked = run_receiver_checks(demo, receiver, expected_script, &log)?;
    let fresh_script = checked.1;
    let payjoin = checked.0;
    let (req, ctx) = payjoin.create_post_request(RELAY_URL)?;
    let body = demo.mailroom.deliver(&req).await?;
    payjoin
        .process_response(&body, ctx)
        .save(&log)
        .map_err(|e| format!("posting proposal failed: {e:?}"))?;
    Ok(fresh_script)
}

/// The receiver's abort policy for a proposal it declines to engage
/// with: broadcast the sender's own original transaction. The payment
/// still completes; the prober's coins end up paying the receiver.
pub fn respond_with_original_broadcast(
    demo: &mut Demo,
    proposal: InboundProposal,
    label: &str,
) -> Result<Transaction, BoxError> {
    let log = JsonlPersister::<ReceiverSessionEvent>::new(
        demo.state_dir.join(format!("receiver-abort-{label}.jsonl")),
    );
    let receiver = proposal.save(&log)?;
    let receiver = check_broadcastable(demo, receiver, &log)?;
    let original = receiver.extract_tx_to_schedule_broadcast();
    demo.broadcast(&original)?;
    demo.mine(1)?;
    Ok(original)
}

fn check_broadcastable(
    demo: &Demo,
    receiver: Receiver<UncheckedOriginalPayload>,
    log: &JsonlPersister<ReceiverSessionEvent>,
) -> Result<Receiver<payjoin::receive::v2::MaybeInputsOwned>, BoxError> {
    let miner = &demo.miner;
    Ok(receiver
        .check_broadcast_suitability(None, |tx| {
            Ok(miner
                .test_mempool_accept(std::slice::from_ref(tx))
                .map_err(ImplementationError::new)?
                .0
                .first()
                .ok_or(ImplementationError::from("testmempoolaccept returned nothing"))?
                .allowed)
        })
        .save(log)
        .map_err(|e| format!("broadcast suitability: {e:?}"))?)
}

type CheckedProposal = (Receiver<PayjoinProposal>, ScriptBuf);

fn run_receiver_checks(
    demo: &mut Demo,
    receiver: Receiver<UncheckedOriginalPayload>,
    expected_script: &ScriptBuf,
    log: &JsonlPersister<ReceiverSessionEvent>,
) -> Result<CheckedProposal, BoxError> {
    let receiver = check_broadcastable(demo, receiver, log)?;

    let receiver_wallet = &demo.receiver_wallet;
    let receiver = receiver
        .check_inputs_not_owned(&mut |outpoint| {
            let tx_out = receiver_wallet
                .get_tx_out(outpoint.txid, u64::from(outpoint.vout))
                .map_err(ImplementationError::new)?
                .into_model()
                .map_err(ImplementationError::new)?;
            let address = Address::from_script(&tx_out.tx_out.script_pubkey, Network::Regtest)
                .map_err(ImplementationError::new)?;
            receiver_wallet
                .get_address_info(&address)
                .map(|info| info.is_mine)
                .map_err(ImplementationError::new)
        })
        .save(log)
        .map_err(|e| format!("input ownership: {e:?}"))?;

    let seen = &mut demo.seen_outpoints;
    let receiver = receiver
        .check_no_inputs_seen_before(&mut |outpoint| Ok(!seen.insert(*outpoint)))
        .save(log)
        .map_err(|e| format!("seen inputs: {e:?}"))?;

    let receiver = receiver
        .identify_receiver_outputs(&mut |script| Ok(script == expected_script.as_script()))
        .save(log)
        .map_err(|e| format!("identify outputs: {e:?}"))?;

    // Move the payment from the derived one-time output to a fresh
    // wallet address, so on-chain funds land where an ordinary restore
    // finds them without any scanning.
    let fresh = demo.fresh_receiver_address()?;
    let fresh_script = fresh.script_pubkey();
    let receiver = receiver
        .substitute_receiver_script(&fresh_script)
        .map_err(|e| format!("substitution: {e:?}"))?
        .commit_outputs()
        .save(log)
        .map_err(|e| format!("commit outputs: {e:?}"))?;

    let candidate_inputs = demo
        .receiver_wallet
        .list_unspent()
        .map_err(ImplementationError::new)?
        .0
        .into_iter()
        .map(input_pair_from_list_unspent);
    let selected = receiver
        .try_preserving_privacy(candidate_inputs)
        .map_err(|e| format!("input selection: {e:?}"))?;
    let receiver = receiver
        .contribute_inputs(vec![selected])
        .map_err(|e| format!("contribute inputs: {e:?}"))?
        .commit_inputs()
        .save(log)
        .map_err(|e| format!("commit inputs: {e:?}"))?;

    let receiver = receiver
        .apply_fee_range(Some(FeeRate::BROADCAST_MIN), Some(FeeRate::from_sat_per_vb_u32(2)))
        .save(log)
        .map_err(|e| format!("apply fee range: {e:?}"))?;

    let receiver_wallet = &demo.receiver_wallet;
    let receiver = receiver
        .finalize_proposal(|psbt: &Psbt| {
            receiver_wallet
                .call::<corepc_node::vtype::WalletProcessPsbt>(
                    "walletprocesspsbt",
                    &[
                        serde_json::json!(psbt.to_string()),
                        serde_json::json!(None as Option<bool>),
                        serde_json::json!(None as Option<&str>),
                        serde_json::json!(Some(true)),
                    ],
                )
                .map(|res| res.psbt.parse::<Psbt>().expect("node returns a valid psbt"))
                .map_err(ImplementationError::new)
        })
        .save(log)
        .map_err(|e| format!("finalize: {e:?}"))?;

    Ok((receiver, fresh_script))
}

fn input_pair_from_list_unspent(utxo: corepc_node::vtype::ListUnspentItem) -> InputPair {
    let utxo = utxo.into_model().expect("listunspent items convert to model");
    let script_pubkey = utxo.script_pubkey.clone();
    let psbtin = bitcoin::psbt::Input {
        witness_utxo: Some(TxOut { value: utxo.amount, script_pubkey: utxo.script_pubkey }),
        redeem_script: utxo.redeem_script,
        ..Default::default()
    };
    let txin = bitcoin::TxIn {
        previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
        ..Default::default()
    };
    let expected_weight = if script_pubkey.is_p2tr() {
        Some(bitcoin::Weight::from_wu(P2TR_INPUT_WEIGHT))
    } else {
        None
    };
    InputPair::new(txin, psbtin, expected_weight).expect("valid input pair")
}

/// Scan the chain from the demo's start height for outputs the
/// receiver's silent payment keys can find, with only those keys.
pub fn scan_chain_for_sp(
    demo: &Demo,
) -> Result<Vec<(OutPoint, TxOut, bitcoin::key::Keypair)>, BoxError> {
    let mut found = Vec::new();
    let tip = block_count(&demo.bitcoind.client)?;
    for height in demo.scan_from_height..=tip {
        let hash = demo.bitcoind.client.get_block_hash(height)?.into_model()?.0;
        let block = demo.bitcoind.client.get_block(hash)?;
        for tx in &block.txdata {
            let pubkeys = sp::input_pubkeys_from_witnesses(tx);
            if pubkeys.is_empty() {
                continue;
            }
            if let Some((vout, keypair)) = demo.sp_keys.scan_tx(&demo.secp, tx, &pubkeys) {
                let outpoint = OutPoint { txid: tx.compute_txid(), vout: vout as u32 };
                found.push((outpoint, tx.output[vout].clone(), keypair));
            }
        }
    }
    Ok(found)
}

/// Demo notification sealing for board blobs. Payjoin messages are
/// sealed by the payjoin crate; the board note that says "you have
/// mail" is demo protocol, so it gets a demo-grade sealed box: an
/// ephemeral ECDH against the receiver's scan key and a hash keystream.
/// The property on display is the mailroom's view (uniform sized
/// blobs), not this cipher.
const NOTE_MAGIC: &[u8; 8] = b"YOUVEGOT";

pub fn seal_notification(secp: &Secp256k1<All>, scan: &PublicKey) -> [u8; BLOB_BYTES] {
    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let eph = bitcoin::secp256k1::SecretKey::new(&mut rng);
    let shared = scan
        .mul_tweak(
            secp,
            &bitcoin::secp256k1::Scalar::from_be_bytes(eph.secret_bytes()).expect("valid"),
        )
        .expect("point multiplication");
    let mut blob = [0u8; BLOB_BYTES];
    rng.fill_bytes(&mut blob);
    blob[..33].copy_from_slice(&eph.public_key(secp).serialize());
    let stream = keystream(&shared);
    for (i, byte) in NOTE_MAGIC.iter().enumerate() {
        blob[33 + i] = byte ^ stream[i];
    }
    blob
}

pub fn open_notification(demo: &Demo, blob: &[u8]) -> bool {
    if blob.len() < 41 {
        return false;
    }
    let Ok(eph) = PublicKey::from_slice(&blob[..33]) else {
        return false;
    };
    let Some(shared) = demo.sp_keys.scan_shared_point(&demo.secp, &eph) else {
        return false;
    };
    let stream = keystream(&shared);
    (0..NOTE_MAGIC.len()).all(|i| blob[33 + i] ^ stream[i] == NOTE_MAGIC[i])
}

fn keystream(shared: &PublicKey) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(&shared.serialize()).to_byte_array()
}
