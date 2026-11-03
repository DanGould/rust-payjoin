//! The receiver's rules for answering an Original that pays its silent
//! payment address.
//!
//! Adding an input changes the BIP 352 derivation of every output in the
//! transaction, so a receiver that adds a coin and keeps the Original's
//! output leaves a payment its own restore can't find. [`SpReceiver::propose`]
//! instead:
//!
//! 1. scans the Original for outputs paying it, and checks the Original's
//!    inputs against its own node (unspent, not seen in an earlier Original);
//! 2. picks the coin it will add before touching the outputs, then re-derives
//!    each of its outputs over the Original's inputs plus that coin, keeping
//!    each output's `k` and label;
//! 3. attaches a BIP 375 share `a·B_scan` and a BIP 374 proof for the coin, so
//!    the sender can derive the same outputs without trusting the receiver;
//! 4. scans the finished proposal as a restore would and runs the sender's
//!    share check on it ([`self_check`]), and sends it only if both pass.
//!
//! The receiver declines, and the sender's Original settles as a plain silent
//! payment, whenever it can't follow these rules.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1};
use bitcoin::{FeeRate, OutPoint, Script, ScriptBuf, Transaction, TxOut};
use payjoin::receive::v2::{PayjoinProposal, Receiver, UncheckedOriginalPayload};
use payjoin::{ImplementationError, OutputSubstitution};
use payjoin_test_utils::bitcoind;
use spj_crypto::{bip352, carriage};

use crate::chain;
pub use crate::derive::SpKeys;
use crate::derive::{self, scan, Found};
use crate::labels::LabelBook;
use crate::persist::EventLog;
use crate::sp_address::SpAddress;
use crate::wallet::{Coin, Keychain};

/// Why the receiver sends no proposal.
#[derive(Debug)]
pub enum Decline {
    /// Nothing in the Original pays this receiver.
    NotPaid,
    /// An input of the Original is spent or unknown to the receiver's node.
    InputsUnavailable,
    /// The receiver's node wouldn't accept the Original.
    Unbroadcastable,
    /// An input of the Original was in an earlier Original, to any of the
    /// receiver's URIs. Answering would show one more coin per URI for the
    /// price of one input.
    SeenInput,
    /// The sender forbids changing the payee output, and adding a coin
    /// without re-deriving it loses the payment to a restore.
    SubstitutionDisabled,
    /// A BIP 78 Original reaches the directory in the clear, where it can be
    /// altered, and its sender doesn't check shares.
    NotV2,
    /// No coin the receiver can prove a share for.
    NoCoin,
    /// The coin the receiver would add is a silent payment output.
    SilentPaymentCoin(OutPoint),
    /// The finished proposal failed the receiver's own check.
    SelfCheck(SelfCheckError),
    /// The payjoin session refused a step.
    Session(String),
}

impl fmt::Display for Decline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decline::NotPaid => write!(f, "the Original doesn't pay me"),
            Decline::InputsUnavailable =>
                write!(f, "an input of the Original is already spent or doesn't exist"),
            Decline::Unbroadcastable => write!(f, "my node wouldn't accept the Original"),
            Decline::SeenInput => write!(f, "an input appeared in an earlier Original"),
            Decline::SubstitutionDisabled => write!(f, "the sender disallowed output substitution"),
            Decline::NotV2 => write!(f, "the Original came from a BIP 78 sender"),
            Decline::NoCoin => write!(f, "no coin to add"),
            Decline::SilentPaymentCoin(op) =>
                write!(f, "the coin to add, {op}, is a silent payment output"),
            Decline::SelfCheck(e) => write!(f, "self-check failed: {e}"),
            Decline::Session(e) => write!(f, "session: {e}"),
        }
    }
}

impl std::error::Error for Decline {}

fn session(e: impl fmt::Display) -> Decline { Decline::Session(e.to_string()) }

/// A proposal ready to post to the sender.
pub struct Proposal {
    pub receiver: Receiver<PayjoinProposal>,
    /// The coin added. It stays reserved in its keychain until the payment
    /// settles.
    pub coin: Coin,
    /// The receiver's outputs in the Original.
    pub found: Vec<Found>,
    /// Their replacements, in `k` order.
    pub derived: Vec<ScriptBuf>,
    /// The coin's BIP 375 share, if any output was re-derived.
    pub share: Option<PublicKey>,
}

/// A silent payment receiver answering payjoin Originals.
pub struct SpReceiver {
    secp: Secp256k1<All>,
    pub keys: SpKeys,
    /// The labels handed out, which the receiver scans for.
    pub labels: LabelBook,
    /// Inputs of every Original received, across all of this receiver's URIs.
    seen: BTreeSet<OutPoint>,
    /// Silent payment outputs the receiver holds, which it never adds to a
    /// payjoin.
    silent_coins: BTreeSet<OutPoint>,
    /// The fee rates the receiver accepts paying for its own input.
    pub fee_range: (FeeRate, FeeRate),
}

impl SpReceiver {
    pub fn new(keys: SpKeys) -> Self {
        let secp = Secp256k1::new();
        Self {
            labels: LabelBook::new(&secp, &keys),
            secp,
            keys,
            seen: BTreeSet::new(),
            silent_coins: BTreeSet::new(),
            fee_range: (FeeRate::BROADCAST_MIN, FeeRate::from_sat_per_vb_u32(2)),
        }
    }

    pub fn address(&self) -> SpAddress { self.keys.address(&self.secp) }

    /// Record that `outpoint` is a silent payment output paying this
    /// receiver, so that [`Self::propose`] refuses to add it.
    pub fn record_silent_coin(&mut self, outpoint: OutPoint) { self.silent_coins.insert(outpoint); }

    /// The address and label of the contact named `name`, the same each
    /// time it is asked for.
    pub fn contact_address(&mut self, name: &str) -> (u32, SpAddress) {
        self.labels
            .contact_address(&self.secp, &self.keys, name)
            .expect("label tweaks are valid scalars")
    }

    /// Answer an Original with a coin from `coins`. `body` is the URI's
    /// ordinary address, if it has one, which a sender without silent
    /// payments pays instead.
    pub fn propose(
        &mut self,
        node: &bitcoind::Client,
        original: Receiver<UncheckedOriginalPayload>,
        log: &EventLog,
        coins: &mut Keychain,
        body: Option<&Script>,
    ) -> Result<Proposal, Decline> {
        let secp = &self.secp;
        let original_tx = original.extract_tx_to_check_broadcast_suitability();
        let prevouts = chain::unspent_prevouts(node, &original_tx)
            .map_err(session)?
            .ok_or(Decline::InputsUnavailable)?;
        let found = scan(secp, &self.keys, self.labels.table(), &original_tx, &prevouts);
        let found_scripts: Vec<ScriptBuf> =
            found.iter().map(|f| original_tx.output[f.vout].script_pubkey.clone()).collect();
        let pays_body = body
            .is_some_and(|body| original_tx.output.iter().any(|out| out.script_pubkey == *body));
        if found.is_empty() && !pays_body {
            return Err(Decline::NotPaid);
        }

        // Record the inputs before judging them, so one Original reusing an
        // input of another can't buy a coin from each URI.
        let earlier = self.seen.clone();
        self.seen.extend(original_tx.input.iter().map(|input| input.previous_output));
        let spent: BTreeMap<OutPoint, ScriptBuf> = original_tx
            .input
            .iter()
            .zip(&prevouts)
            .map(|(input, prevout)| (input.previous_output, prevout.script_pubkey.clone()))
            .collect();

        let checked = original
            .check_broadcast_suitability(None, |tx| {
                chain::mempool_accepts(node, tx)
                    .map_err(|e| ImplementationError::from(e.to_string().as_str()))
            })
            .save(log)
            .map_err(|_| Decline::Unbroadcastable)?
            .check_inputs_not_owned(&mut |outpoint| {
                Ok(spent.get(outpoint).is_some_and(|script| coins.owns(script)))
            })
            .save(log)
            .map_err(session)?
            .check_no_inputs_seen_before(&mut |outpoint| Ok(earlier.contains(outpoint)))
            .save(log)
            .map_err(|_| Decline::SeenInput)?
            .identify_receiver_outputs(&mut |script| {
                Ok(found_scripts.iter().any(|s| s.as_script() == script) || body == Some(script))
            })
            .save(log)
            .map_err(session)?;

        if !found.is_empty() && checked.output_substitution() == OutputSubstitution::Disabled {
            return Err(Decline::SubstitutionDisabled);
        }
        if log.from_v2_sender() != Some(true) {
            return Err(Decline::NotV2);
        }
        let coin = pick_coin(coins, &self.silent_coins)?;
        let coin_secret = coins.bip352_secret(&coin.txout.script_pubkey).ok_or(Decline::NoCoin)?;

        // The coin is chosen, so the final input set is known: re-derive each
        // output paying the receiver over it, in the order its `k` was found
        // and on the label it was paid to, where the payer's check looks.
        let labels: Vec<Option<u32>> = found.iter().map(|f| f.label).collect();
        let mut derived = Vec::new();
        let outputs = if found.is_empty() {
            checked
        } else {
            let mut keys = original_keys(&original_tx, &prevouts);
            keys.push(coin_secret.public_key(secp));
            let mut outpoints: Vec<OutPoint> =
                original_tx.input.iter().map(|input| input.previous_output).collect();
            outpoints.push(coin.outpoint);
            derived = derive::receiver_outputs(secp, &self.keys, &keys, &outpoints, &labels)
                .ok_or_else(|| session("no shared secret over the final inputs"))?;
            let mut replacements: Vec<TxOut> = found
                .iter()
                .map(|f| TxOut { value: f.value, script_pubkey: derived[f.k as usize].clone() })
                .collect();
            if let Some(body) = body {
                replacements.extend(
                    original_tx.output.iter().filter(|out| out.script_pubkey == *body).cloned(),
                );
            }
            checked.replace_receiver_outputs(replacements, &derived[0]).map_err(session)?
        };

        let input = coins.input_pair(&coin).map_err(session)?;
        let provisional = outputs
            .commit_outputs()
            .save(log)
            .map_err(session)?
            .contribute_inputs([input])
            .map_err(session)?
            .commit_inputs()
            .save(log)
            .map_err(session)?
            .apply_fee_range(Some(self.fee_range.0), Some(self.fee_range.1))
            .save(log)
            .map_err(session)?;
        let mut psbt = provisional.psbt_to_sign();
        coins.sign(&mut psbt).map_err(session)?;
        let finalized = provisional.finalize_signed_proposal(&psbt).save(log).map_err(session)?;

        let (receiver, share) = if derived.is_empty() {
            (finalized, None)
        } else {
            let aux_rand: [u8; 32] = bitcoin::secp256k1::rand::random();
            let scan = self.keys.scan.public_key(secp);
            let (share, proof) = carriage::share_and_proof(secp, &coin_secret, &scan, &aux_rand)
                .ok_or_else(|| session("can't prove a share for the coin"))?;
            let receiver = log
                .edit_proposal(|psbt| {
                    let index = psbt
                        .unsigned_tx
                        .input
                        .iter()
                        .position(|input| input.previous_output == coin.outpoint)
                        .expect("the coin was contributed");
                    carriage::set_share_and_proof(&mut psbt.inputs[index], &scan, &share, &proof);
                })
                .map_err(session)?;
            self_check(
                secp,
                &self.keys,
                &original_tx,
                &prevouts,
                receiver.psbt(),
                &derived,
                &labels,
            )
            .map_err(Decline::SelfCheck)?;
            (receiver, Some(share))
        };
        coins.reserve(coin.outpoint);
        Ok(Proposal { receiver, coin, found, derived, share })
    }
}

/// The coin to add to a payjoin from `coins`, refusing one in `silent`.
fn pick_coin(coins: &Keychain, silent: &BTreeSet<OutPoint>) -> Result<Coin, Decline> {
    let coin = coins.spendable().into_iter().next().ok_or(Decline::NoCoin)?;
    // A payer who knows a silent payment coin's tweak learns b_scan·B_spend from its share.
    if silent.contains(&coin.outpoint) {
        return Err(Decline::SilentPaymentCoin(coin.outpoint));
    }
    Ok(coin)
}

/// The BIP 352 keys of a transaction's eligible inputs.
fn original_keys(tx: &Transaction, prevouts: &[TxOut]) -> Vec<PublicKey> {
    tx.input
        .iter()
        .zip(prevouts)
        .filter_map(|(input, prevout)| {
            bip352::input_public_key(&input.script_sig, &input.witness, &prevout.script_pubkey)
        })
        .map(|(_, key)| key)
        .collect()
}

/// What the receiver's check of its own proposal found wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfCheckError {
    /// A restore would skip the whole transaction.
    Unscannable,
    /// A restore wouldn't find this re-derived output.
    RestoreMisses(ScriptBuf),
    /// An eligible receiver input carries no share.
    MissingShare(OutPoint),
    /// A share's proof doesn't verify against its input's key.
    ProofInvalid(OutPoint),
    /// The shares don't add up to `b_scan` times the receiver's input keys,
    /// so the sender would derive other outputs.
    SharesDisagree,
    /// The sender, deriving from the shares, wouldn't find each output
    /// exactly once.
    SenderMisses,
}

impl fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelfCheckError::Unscannable => write!(f, "a restore would skip the transaction"),
            SelfCheckError::RestoreMisses(script) =>
                write!(f, "a restore wouldn't find {}", &script.to_hex_string()[4..14]),
            SelfCheckError::MissingShare(op) => write!(f, "no share for {op}"),
            SelfCheckError::ProofInvalid(op) => write!(f, "the proof for {op} doesn't verify"),
            SelfCheckError::SharesDisagree => write!(f, "the shares don't match the inputs' keys"),
            SelfCheckError::SenderMisses =>
                write!(f, "the sender's derivation wouldn't find each output once"),
        }
    }
}

/// Check a finished proposal the way a restore and the sender will.
///
/// The restore half rebuilds the transaction as it will confirm, with the
/// sender's inputs spent as in the Original, and requires its scan to find
/// every output in `derived`. That catches a derivation over any input set
/// other than the final one. A restore never reads the shares, so the second
/// half recomputes what the sender will derive from them: each eligible
/// receiver input needs a share whose proof verifies against its prevout's
/// key, the shares must add up to `b_scan` times those keys, and the outputs
/// derived from them must each appear once. That catches a share made with
/// the wrong key, such as a BIP 86 coin's internal key instead of its
/// tweaked one. `labels` holds the label each of `derived` pays.
pub fn self_check(
    secp: &Secp256k1<All>,
    keys: &SpKeys,
    original: &Transaction,
    original_prevouts: &[TxOut],
    proposal: &Psbt,
    derived: &[ScriptBuf],
    labels: &[Option<u32>],
) -> Result<(), SelfCheckError> {
    let from_original: BTreeMap<OutPoint, (&bitcoin::TxIn, &TxOut)> = original
        .input
        .iter()
        .zip(original_prevouts)
        .map(|(input, prevout)| (input.previous_output, (input, prevout)))
        .collect();
    let mut view = proposal.unsigned_tx.clone();
    let mut prevouts = Vec::with_capacity(view.input.len());
    let mut theirs = Vec::new();
    for (index, (txin, psbtin)) in view.input.iter_mut().zip(&proposal.inputs).enumerate() {
        if let Some((spent, prevout)) = from_original.get(&txin.previous_output) {
            txin.script_sig = spent.script_sig.clone();
            txin.witness = spent.witness.clone();
            prevouts.push((*prevout).clone());
        } else {
            txin.script_sig = psbtin.final_script_sig.clone().unwrap_or_default();
            txin.witness = psbtin.final_script_witness.clone().unwrap_or_default();
            prevouts.push(
                psbtin
                    .witness_utxo
                    .clone()
                    .ok_or(SelfCheckError::MissingShare(txin.previous_output))?,
            );
            theirs.push(index);
        }
    }

    let table = keys.labels(secp, labels.iter().flatten().copied());
    let found = scan(secp, keys, &table, &view, &prevouts);
    if bip352::transaction_tweak(secp, &view, &prevouts).is_none() {
        return Err(SelfCheckError::Unscannable);
    }
    for script in derived {
        if !found.iter().any(|f| view.output[f.vout].script_pubkey == *script) {
            return Err(SelfCheckError::RestoreMisses(script.clone()));
        }
    }

    let scan_public = keys.scan.public_key(secp);
    let scalar = Scalar::from(keys.scan);
    let mut sender_part = Vec::new();
    let mut shares = Vec::new();
    let mut receiver_keys = Vec::new();
    let mut all_keys = Vec::new();
    for (index, (txin, prevout)) in view.input.iter().zip(&prevouts).enumerate() {
        let Some((_, key)) =
            bip352::input_public_key(&txin.script_sig, &txin.witness, &prevout.script_pubkey)
        else {
            continue;
        };
        all_keys.push(key);
        if !theirs.contains(&index) {
            sender_part.push(key);
            continue;
        }
        let (share, proof) = carriage::get_share_and_proof(&proposal.inputs[index], &scan_public)
            .ok()
            .flatten()
            .ok_or(SelfCheckError::MissingShare(txin.previous_output))?;
        if !carriage::verify_share(secp, &key, &scan_public, &share, &proof) {
            return Err(SelfCheckError::ProofInvalid(txin.previous_output));
        }
        shares.push(share);
        receiver_keys.push(key);
    }
    if !receiver_keys.is_empty() {
        let expected =
            derive::sum(&receiver_keys).and_then(|sum| sum.mul_tweak(secp, &scalar).ok());
        if expected != derive::sum(&shares) {
            return Err(SelfCheckError::SharesDisagree);
        }
    }

    // The sender holds a_s rather than b_scan; b_scan·A_s is the same point.
    let mut partial = shares;
    if let Some(sender_sum) = derive::sum(&sender_part) {
        partial
            .push(sender_sum.mul_tweak(secp, &scalar).map_err(|_| SelfCheckError::SenderMisses)?);
    }
    let outpoints: Vec<OutPoint> = view.input.iter().map(|input| input.previous_output).collect();
    let sender_derived = derive::sum(&all_keys)
        .and_then(|a| bip352::input_hash(&outpoints, &a))
        .and_then(|input_hash| derive::sum(&partial)?.mul_tweak(secp, &input_hash).ok())
        .and_then(|ecdh| {
            let spends: Vec<PublicKey> =
                labels.iter().map(|label| keys.spend_for(secp, *label)).collect::<Option<_>>()?;
            derive::labelled_output_scripts(secp, &ecdh, &spends)
        })
        .ok_or(SelfCheckError::SenderMisses)?;
    let once = |script: &ScriptBuf| {
        view.output.iter().filter(|out| out.script_pubkey == *script).count() == 1
    };
    if sender_derived != derived || !sender_derived.iter().all(once) {
        return Err(SelfCheckError::SenderMisses);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction, Amount};

    use super::*;
    use crate::wallet::KeyKind;

    #[test]
    fn a_silent_payment_coin_is_never_added() {
        let mut coins = Keychain::new("test", "pick coin test", KeyKind::P2tr, 0);
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: coins.address().script_pubkey(),
            }],
        };
        coins.credit(&funding);
        let coin = coins.coins()[0].clone();

        let mut receiver = SpReceiver::new(SpKeys::from_seed("pick coin test"));
        assert_eq!(pick_coin(&coins, &receiver.silent_coins).ok(), Some(coin.clone()));
        receiver.record_silent_coin(coin.outpoint);
        assert!(matches!(
            pick_coin(&coins, &receiver.silent_coins),
            Err(Decline::SilentPaymentCoin(op)) if op == coin.outpoint
        ));
    }
}
