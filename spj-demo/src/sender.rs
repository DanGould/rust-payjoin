//! The payer's rules for paying a silent payment address with payjoin.
//!
//! - [`attempt_gate`]: attempt a payjoin only if every silent payment output
//!   in the Original pays this URI's address and the change is ordinary.
//! - [`check_proposal`]: on every proposal, check the receiver's inputs and
//!   their BIP 375 shares, derive the receiver's outputs from the sender's own
//!   keys and the verified shares, and require each derived output exactly
//!   once, paying at least what the Original paid.
//!
//! A sender that fails any rule broadcasts its Original, which is an ordinary
//! silent payment the receiver finds by scanning.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use bitcoin::hashes::{hash160, Hash};
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::secp256k1::{All, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache};
use bitcoin::taproot::ControlBlock;
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Script, ScriptBuf, TapSighashType, Transaction, TxOut,
    Witness,
};
use spj_crypto::{bip352, carriage};

use crate::derive;
use crate::sp_address::SpAddress;

/// One payment the sender put in its Original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payment {
    /// An output derived for a silent payment address.
    SilentPayment(SpAddress),
    /// An output paying an ordinary script.
    Script(ScriptBuf),
}

/// What kind of change the Original has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    None,
    /// BIP 86, or BIP 84 for a P2WPKH wallet.
    Ordinary,
    /// Change to the sender's own silent payment address.
    SilentPayment,
}

/// The attempt gate's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    AttemptPayjoin,
    /// Broadcast the Original as a plain silent payment instead.
    BroadcastOriginal(&'static str),
}

/// Whether to attempt a payjoin for an Original making `payments` with
/// `change`, given the URI's silent payment address.
///
/// Adding a receiver input changes every silent payment output's derivation.
/// The receiver re-derives its own outputs, but any other silent payment
/// output, including the sender's own silent payment change, would be lost to
/// its owner's restore. Outputs to ordinary scripts don't depend on the inputs.
pub fn attempt_gate(uri_sp: &SpAddress, payments: &[Payment], change: Change) -> Gate {
    if change == Change::SilentPayment {
        return Gate::BroadcastOriginal("the change is a silent payment");
    }
    let mut pays_uri = false;
    for payment in payments {
        if let Payment::SilentPayment(sp) = payment {
            if sp != uri_sp {
                return Gate::BroadcastOriginal("another silent payment address is paid");
            }
            pays_uri = true;
        }
    }
    if pays_uri {
        Gate::AttemptPayjoin
    } else {
        Gate::BroadcastOriginal("the Original doesn't pay this URI's silent payment address")
    }
}

/// A proposal the sender may sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// Indices of the outputs derived for the URI's address.
    pub payee_vouts: Vec<usize>,
    /// What they pay together.
    pub paid: Amount,
    /// Inputs the receiver added.
    pub receiver_inputs: usize,
    /// Receiver inputs that carried a verified share.
    pub shares_verified: usize,
}

/// Why a proposal was rejected. Every rejection means: broadcast the Original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The Original pays no output derived for the URI's address, so there
    /// is nothing to check against.
    OriginalDoesNotPay,
    /// The proposal drops an input of the Original.
    OriginalInputMissing(OutPoint),
    /// A receiver input doesn't describe the output it spends.
    MissingPrevout(OutPoint),
    /// A receiver input spends a segwit version 2 or later output. BIP 352
    /// skips such a transaction, so a restore would find nothing in it.
    Unscannable(OutPoint),
    /// Receiver inputs whose type isn't P2TR, P2WPKH or P2SH-P2WPKH with a
    /// canonical scriptSig, or that aren't finalized.
    InputTypeNotAllowed(Vec<OutPoint>),
    /// A receiver input's witness or signature isn't valid for the prevout it
    /// describes.
    InvalidSpend(OutPoint),
    /// A share or proof field that doesn't parse.
    MalformedShare(OutPoint),
    /// Eligible receiver inputs without a share and proof.
    MissingShares(Vec<OutPoint>),
    /// A BIP 374 proof that doesn't verify against its input's key.
    ProofFails(OutPoint),
    /// The keys sum to the point at infinity.
    NoSharedSecret,
    /// An output derived for the URI's address isn't in the proposal.
    MissingDerivedOutput,
    /// A derived output appears more than once. A scan matches one output per
    /// `k`, so the copies after the first would be lost.
    DuplicateDerivedOutput,
    /// The derived outputs pay less than the Original paid.
    AmountRule { paid: Amount, required: Amount },
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |ops: &[OutPoint]| ops.iter().map(short_outpoint).collect::<Vec<_>>().join(", ");
        match self {
            Rejection::OriginalDoesNotPay =>
                write!(f, "the Original pays nothing derived for this address"),
            Rejection::OriginalInputMissing(op) =>
                write!(f, "the proposal drops Original input {}", short_outpoint(op)),
            Rejection::MissingPrevout(op) =>
                write!(f, "receiver input {} doesn't describe its prevout", short_outpoint(op)),
            Rejection::Unscannable(op) => write!(
                f,
                "receiver input {} is segwit v2 or later, so a scan skips the transaction",
                short_outpoint(op)
            ),
            Rejection::InputTypeNotAllowed(ops) => write!(
                f,
                "receiver input type not allowed, or scriptSig not canonical, for {}",
                list(ops)
            ),
            Rejection::InvalidSpend(op) => write!(
                f,
                "receiver input {}'s spend isn't valid for its prevout",
                short_outpoint(op)
            ),
            Rejection::MalformedShare(op) =>
                write!(f, "malformed share or proof on {}", short_outpoint(op)),
            Rejection::MissingShares(ops) =>
                write!(f, "no share for eligible input(s) {}", list(ops)),
            Rejection::ProofFails(op) =>
                write!(f, "BIP 374 proof fails for {}", short_outpoint(op)),
            Rejection::NoSharedSecret => write!(f, "the input keys sum to infinity"),
            Rejection::MissingDerivedOutput =>
                write!(f, "an output derived for the sp1 is missing"),
            Rejection::DuplicateDerivedOutput =>
                write!(f, "a derived payee script appears more than once"),
            Rejection::AmountRule { paid, required } =>
                write!(f, "amount rule ({} < {})", paid.to_sat(), required.to_sat()),
        }
    }
}

impl std::error::Error for Rejection {}

/// An outpoint as `txid-prefix:vout`, short enough to narrate.
pub fn short_outpoint(op: &OutPoint) -> String {
    format!("{}…:{}", &op.txid.to_string()[..10], op.vout)
}

/// The outputs the sender derives for `sp` under shared secret `ecdh` that
/// `tx` pays, in `k` order, stopping at the first `k` it doesn't pay.
fn paid_outputs(
    secp: &Secp256k1<All>,
    ecdh: &PublicKey,
    sp: &SpAddress,
    tx: &Transaction,
) -> Vec<ScriptBuf> {
    let mut scripts = Vec::new();
    for k in 0..bip352::K_MAX {
        let Some(t_k) = bip352::output_tweak(ecdh, k) else { break };
        let Ok(key) = sp.spend.add_exp_tweak(secp, &t_k) else { break };
        let script = derive::p2tr_script(key.x_only_public_key().0);
        if !tx.output.iter().any(|out| out.script_pubkey == script) {
            break;
        }
        scripts.push(script);
    }
    scripts
}

/// Check a payjoin proposal for an Original paying `sp`.
///
/// `own` holds the BIP 352 secret of each eligible input the sender spends
/// (see [`bip352::input_secret_key`]); the sender's ineligible inputs are
/// absent but still hashed through their outpoints. Every input the proposal
/// adds is the receiver's. This runs on every proposal, including one that
/// adds no input, since a proposal may substitute the payee output whether or
/// not it adds one.
pub fn check_proposal(
    secp: &Secp256k1<All>,
    sp: &SpAddress,
    original: &Psbt,
    own: &BTreeMap<OutPoint, SecretKey>,
    proposal: &Psbt,
) -> Result<Accepted, Rejection> {
    let original_tx = &original.unsigned_tx;
    let original_outpoints: Vec<OutPoint> =
        original_tx.input.iter().map(|input| input.previous_output).collect();
    let secrets: Vec<SecretKey> = own.values().copied().collect();
    let a_s = bip352::input_secret_sum(&secrets).ok_or(Rejection::NoSharedSecret)?;
    let original_ecdh = bip352::sender_shared_secret(secp, &a_s, &original_outpoints, &sp.scan)
        .map_err(|_| Rejection::NoSharedSecret)?;
    let original_payee = paid_outputs(secp, &original_ecdh, sp, original_tx);
    if original_payee.is_empty() {
        return Err(Rejection::OriginalDoesNotPay);
    }
    let required: Amount = original_tx
        .output
        .iter()
        .filter(|out| original_payee.contains(&out.script_pubkey))
        .map(|out| out.value)
        .sum();

    let tx = &proposal.unsigned_tx;
    let outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
    let present: BTreeSet<&OutPoint> = outpoints.iter().collect();
    if let Some(missing) = original_outpoints.iter().find(|op| !present.contains(op)) {
        return Err(Rejection::OriginalInputMissing(*missing));
    }
    let original_prevouts: BTreeMap<OutPoint, &TxOut> = original_outpoints
        .iter()
        .zip(&original.inputs)
        .filter_map(|(op, input)| input.witness_utxo.as_ref().map(|txout| (*op, txout)))
        .collect();
    let mut prevouts = Vec::with_capacity(outpoints.len());
    let mut theirs = Vec::new();
    for (index, (op, input)) in outpoints.iter().zip(&proposal.inputs).enumerate() {
        if original_outpoints.contains(op) {
            let prevout = original_prevouts.get(op).ok_or(Rejection::OriginalInputMissing(*op))?;
            prevouts.push((*prevout).clone());
        } else {
            prevouts.push(described_prevout(op, input).ok_or(Rejection::MissingPrevout(*op))?);
            theirs.push(index);
        }
    }

    for &index in &theirs {
        if prevouts[index].script_pubkey.witness_version().is_some_and(|v| v.to_num() > 1) {
            return Err(Rejection::Unscannable(outpoints[index]));
        }
    }
    let not_allowed: Vec<OutPoint> = theirs
        .iter()
        .filter(|&&index| {
            !input_type_allowed(&prevouts[index].script_pubkey, &proposal.inputs[index])
        })
        .map(|&index| outpoints[index])
        .collect();
    if !not_allowed.is_empty() {
        return Err(Rejection::InputTypeNotAllowed(not_allowed));
    }
    for &index in &theirs {
        if !spend_is_valid(secp, tx, index, &prevouts, &proposal.inputs[index]) {
            return Err(Rejection::InvalidSpend(outpoints[index]));
        }
    }

    // Eligibility comes from the validated spend, the same data a scanner
    // reads once the transaction confirms.
    let mut keys = vec![a_s.public_key(secp)];
    let mut partial =
        vec![sp.scan.mul_tweak(secp, &Scalar::from(a_s)).map_err(|_| Rejection::NoSharedSecret)?];
    let mut missing = Vec::new();
    for &index in &theirs {
        let input = &proposal.inputs[index];
        let (script_sig, witness) = finals(input);
        let Some((_, key)) =
            bip352::input_public_key(&script_sig, &witness, &prevouts[index].script_pubkey)
        else {
            continue;
        };
        match carriage::get_share_and_proof(input, &sp.scan) {
            Ok(None) => missing.push(outpoints[index]),
            Err(_) => return Err(Rejection::MalformedShare(outpoints[index])),
            Ok(Some((share, proof))) => {
                if !carriage::verify_share(secp, &key, &sp.scan, &share, &proof) {
                    return Err(Rejection::ProofFails(outpoints[index]));
                }
                keys.push(key);
                partial.push(share);
            }
        }
    }
    if !missing.is_empty() {
        return Err(Rejection::MissingShares(missing));
    }
    let shares_verified = partial.len() - 1;

    let a_sum = derive::sum(&keys).ok_or(Rejection::NoSharedSecret)?;
    let input_hash = bip352::input_hash(&outpoints, &a_sum).ok_or(Rejection::NoSharedSecret)?;
    let ecdh = derive::sum(&partial)
        .and_then(|point| point.mul_tweak(secp, &input_hash).ok())
        .ok_or(Rejection::NoSharedSecret)?;
    let expected = derive::output_scripts(secp, &ecdh, &sp.spend, original_payee.len() as u32)
        .ok_or(Rejection::NoSharedSecret)?;

    let mut payee_vouts = Vec::new();
    for script in &expected {
        let vouts: Vec<usize> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, out)| out.script_pubkey == *script)
            .map(|(vout, _)| vout)
            .collect();
        match vouts.as_slice() {
            [] => return Err(Rejection::MissingDerivedOutput),
            [vout] => payee_vouts.push(*vout),
            _ => return Err(Rejection::DuplicateDerivedOutput),
        }
    }
    let paid: Amount = payee_vouts.iter().map(|&vout| tx.output[vout].value).sum();
    if paid < required {
        return Err(Rejection::AmountRule { paid, required });
    }
    Ok(Accepted { payee_vouts, paid, receiver_inputs: theirs.len(), shares_verified })
}

/// The output a PSBT input says it spends.
fn described_prevout(outpoint: &OutPoint, input: &PsbtInput) -> Option<TxOut> {
    if let Some(txout) = &input.witness_utxo {
        return Some(txout.clone());
    }
    let tx = input.non_witness_utxo.as_ref()?;
    (tx.compute_txid() == outpoint.txid)
        .then(|| tx.output.get(outpoint.vout as usize).cloned())
        .flatten()
}

fn finals(input: &PsbtInput) -> (ScriptBuf, Witness) {
    (
        input.final_script_sig.clone().unwrap_or_default(),
        input.final_script_witness.clone().unwrap_or_default(),
    )
}

/// The data pushes of a push-only script, or `None` if it has any other
/// opcode.
fn pushes(script: &Script) -> Option<Vec<&[u8]>> {
    script
        .instructions()
        .map(|instruction| match instruction {
            Ok(bitcoin::script::Instruction::PushBytes(bytes)) if !bytes.is_empty() =>
                Some(bytes.as_bytes()),
            _ => None,
        })
        .collect()
}

/// The input-type list. No signature covers another input's scriptSig, and
/// BIP 352 reads a P2PKH input's key, and a P2SH input's eligibility, from it.
/// So a receiver could rewrite one after the sender signs and change what a
/// scan derives. P2TR and P2WPKH spends have an empty scriptSig, and the one
/// P2SH form allowed is a single push of a P2WPKH redeem script.
fn input_type_allowed(prevout: &Script, input: &PsbtInput) -> bool {
    let (script_sig, witness) = finals(input);
    if prevout.is_p2tr() {
        return script_sig.is_empty() && !witness.is_empty();
    }
    if prevout.is_p2wpkh() {
        return script_sig.is_empty()
            && witness.len() == 2
            && witness_key_matches(&witness, prevout);
    }
    if prevout.is_p2sh() {
        let Some(pushes) = pushes(&script_sig) else { return false };
        let [redeem] = pushes.as_slice() else { return false };
        let redeem = Script::from_bytes(redeem);
        return redeem.is_p2wpkh()
            && hash160::Hash::hash(redeem.as_bytes()).as_byte_array()
                == &prevout.as_bytes()[2..22]
            && witness.len() == 2
            && witness_key_matches(&witness, redeem);
    }
    false
}

/// Whether a P2WPKH witness's key hashes to `program`'s key hash.
fn witness_key_matches(witness: &Witness, program: &Script) -> bool {
    witness
        .last()
        .is_some_and(|key| hash160::Hash::hash(key).as_byte_array() == &program.as_bytes()[2..22])
}

/// Whether a finalized receiver input is a valid spend of its described
/// prevout. Key-path and P2WPKH signatures are verified, and must commit to
/// every input and output. For a taproot script path the control block must
/// commit to the output key; the script itself isn't run, so an invalid one
/// makes the payjoin unbroadcastable, and the sender then broadcasts its
/// Original.
fn spend_is_valid(
    secp: &Secp256k1<All>,
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    input: &PsbtInput,
) -> bool {
    let prevout = &prevouts[index];
    let (script_sig, witness) = finals(input);
    let mut cache = SighashCache::new(tx);
    if prevout.script_pubkey.is_p2tr() {
        let Ok(output_key) = XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..])
        else {
            return false;
        };
        let mut stack: Vec<&[u8]> = witness.iter().collect();
        let annex = (stack.len() > 1 && stack.last().and_then(|item| item.first()) == Some(&0x50))
            .then(|| stack.pop())
            .flatten();
        match stack.as_slice() {
            [signature] => {
                let Ok(signature) = bitcoin::taproot::Signature::from_slice(signature) else {
                    return false;
                };
                if !matches!(signature.sighash_type, TapSighashType::Default | TapSighashType::All)
                {
                    return false;
                }
                let annex = match annex.map(Annex::new) {
                    None => None,
                    Some(Ok(annex)) => Some(annex),
                    Some(Err(_)) => return false,
                };
                let Ok(sighash) = cache.taproot_signature_hash(
                    index,
                    &Prevouts::All(prevouts),
                    annex,
                    None,
                    signature.sighash_type,
                ) else {
                    return false;
                };
                secp.verify_schnorr(
                    &signature.signature,
                    &Message::from_digest(sighash.to_byte_array()),
                    &output_key,
                )
                .is_ok()
            }
            [.., script, control] => ControlBlock::decode(control).is_ok_and(|control| {
                control.verify_taproot_commitment(secp, output_key, Script::from_bytes(script))
            }),
            [] => false,
        }
    } else {
        let program = if prevout.script_pubkey.is_p2wpkh() {
            prevout.script_pubkey.clone()
        } else {
            match pushes(&script_sig).as_deref() {
                Some([redeem]) => ScriptBuf::from_bytes(redeem.to_vec()),
                _ => return false,
            }
        };
        let (Some(signature), Some(key)) = (witness.nth(0), witness.nth(1)) else {
            return false;
        };
        let (Ok(signature), Ok(key)) =
            (bitcoin::ecdsa::Signature::from_slice(signature), PublicKey::from_slice(key))
        else {
            return false;
        };
        if signature.sighash_type != EcdsaSighashType::All {
            return false;
        }
        let Ok(sighash) =
            cache.p2wpkh_signature_hash(index, &program, prevout.value, EcdsaSighashType::All)
        else {
            return false;
        };
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signature.signature,
            &key,
        )
        .is_ok()
    }
}
