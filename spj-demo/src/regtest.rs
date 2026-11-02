//! Bitcoin Core wallet glue for driving payjoin sessions on regtest.
//!
//! The receiver steps here are the plain BIP 78 checks with a Bitcoin Core
//! wallet answering ownership questions and signing. They carry no silent
//! payment rules.

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE;
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Transaction, TxIn, TxOut, Weight};
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::{PayjoinProposal, Receiver, SessionEvent, UncheckedOriginalPayload};
use payjoin::receive::InputPair;
use payjoin::ImplementationError;
use payjoin_test_utils::bitcoind;
use payjoin_test_utils::bitcoind::vtype::ListUnspentItem;
use serde_json::json;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Spending a P2TR key path input, which a PSBT input can't show before it's
/// signed.
const P2TR_INPUT_WEIGHT: Weight = Weight::from_wu(230);

/// A signed Original PSBT from `sender`'s wallet paying `amount` to
/// `address`, its inputs locked so later Originals don't reuse them.
pub fn original_psbt(
    sender: &bitcoind::Client,
    address: &Address,
    amount: Amount,
) -> Result<Psbt, Error> {
    let outputs = HashMap::from([(address.to_string(), amount.to_btc())]);
    let options = json!({
        "lockUnspents": true,
        "feeRate": Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into()).to_btc(),
    });
    let funded = sender
        .call::<bitcoind::vtype::WalletCreateFundedPsbt>(
            "walletcreatefundedpsbt",
            &[json!([]), json!(outputs), json!(null), json!(options), json!(true)],
        )?
        .psbt;
    let signed = sender.wallet_process_psbt(&Psbt::from_str(&funded)?)?.psbt;
    Ok(Psbt::from_str(&signed)?)
}

/// Run a received Original through the BIP 78 receiver checks, add one of
/// `receiver`'s coins and sign, returning the proposal ready to post.
pub fn propose(
    receiver: &bitcoind::Client,
    original: Receiver<UncheckedOriginalPayload>,
    persister: &impl SessionPersister<SessionEvent = SessionEvent>,
) -> Result<Receiver<PayjoinProposal>, Error> {
    let is_mine = |script: &bitcoin::Script| {
        let address =
            Address::from_script(script, Network::Regtest).map_err(ImplementationError::new)?;
        receiver
            .get_address_info(&address)
            .map(|info| info.is_mine)
            .map_err(ImplementationError::new)
    };
    let proposal = original
        .check_broadcast_suitability(None, |tx| {
            Ok(receiver
                .test_mempool_accept(std::slice::from_ref(tx))
                .map_err(ImplementationError::new)?
                .0
                .first()
                .ok_or(ImplementationError::from("testmempoolaccept returned no result"))?
                .allowed)
        })
        .save(persister)?
        .check_inputs_not_owned(&mut |outpoint| {
            let tx_out = receiver
                .get_tx_out(outpoint.txid, u64::from(outpoint.vout))
                .map_err(ImplementationError::new)?
                .into_model()
                .map_err(ImplementationError::new)?;
            is_mine(&tx_out.tx_out.script_pubkey)
        })
        .save(persister)?
        .check_no_inputs_seen_before(&mut |_| Ok(false))
        .save(persister)?
        .identify_receiver_outputs(&mut |script| is_mine(script))
        .save(persister)?
        .commit_outputs()
        .save(persister)?;

    // Bitcoin Core's coins rarely pass the privacy-preserving selection on
    // regtest, where every coin is a 50 BTC coinbase. Fall back to any coin.
    let candidates: Vec<InputPair> =
        receiver.list_unspent()?.0.into_iter().map(input_pair).collect();
    let selected = proposal
        .try_preserving_privacy(candidates.clone())
        .ok()
        .or_else(|| candidates.into_iter().next())
        .ok_or("the receiver has no confirmed coin to add")?;
    let proposal = proposal
        .contribute_inputs([selected])
        .map_err(|e| format!("can't contribute input: {e:?}"))?
        .commit_inputs()
        .save(persister)?
        .apply_fee_range(Some(FeeRate::BROADCAST_MIN), Some(FeeRate::from_sat_per_vb_u32(2)))
        .save(persister)?
        .finalize_proposal(|psbt: &Psbt| {
            let signed = receiver
                .call::<bitcoind::vtype::WalletProcessPsbt>(
                    "walletprocesspsbt",
                    &[json!(psbt.to_string()), json!(null), json!(null), json!(true)],
                )
                .map_err(ImplementationError::new)?;
            Psbt::from_str(&signed.psbt).map_err(ImplementationError::new)
        })
        .save(persister)?;
    Ok(proposal)
}

/// Sign `sender`'s inputs in a proposal and extract the transaction.
pub fn sign_proposal(sender: &bitcoind::Client, proposal: Psbt) -> Result<Transaction, Error> {
    let signed = sender.wallet_process_psbt(&proposal)?.psbt;
    let finalized = sender
        .finalize_psbt(&Psbt::from_str(&signed)?)?
        .psbt
        .ok_or("finalizepsbt returned no PSBT")?;
    Ok(Psbt::from_str(&finalized)?.extract_tx()?)
}

fn input_pair(utxo: ListUnspentItem) -> InputPair {
    let utxo = utxo.into_model().expect("listunspent entries convert to the model type");
    let expected_weight = utxo.script_pubkey.is_p2tr().then_some(P2TR_INPUT_WEIGHT);
    let psbtin = PsbtInput {
        witness_utxo: Some(TxOut { value: utxo.amount, script_pubkey: utxo.script_pubkey }),
        redeem_script: utxo.redeem_script,
        ..Default::default()
    };
    let txin = TxIn {
        previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
        ..Default::default()
    };
    InputPair::new(txin, psbtin, expected_weight).expect("wallet coins make valid input pairs")
}
