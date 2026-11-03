//! The silent payjoin harness's parties and inputs, rebuilt from the same
//! labels so a rule test runs the case its harness scenario runs.
//!
//! Keys are `tagged_hash("SPJ/test-key", label)` and outpoint hashes are an
//! ordering byte followed by `tagged_hash("SPJ/txid", label)[1..]`, as in the
//! harness's `spj/core.py`. The harness stands in placeholder bytes for
//! signatures; here every input a test hands to the sender check is really
//! signed, because the check verifies signatures.

#![allow(dead_code)] // each test file uses a different part

use std::collections::BTreeMap;

use bitcoin::hashes::{hash160, Hash};
use bitcoin::key::Keypair;
use bitcoin::psbt::Psbt;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{
    All, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    absolute, transaction, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use spj_crypto::{bip352, carriage, tagged_hash};
use spj_demo::derive;
use spj_demo::derive::SpKeys;
use spj_demo::sp_address::SpAddress;

pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub fn secp() -> Secp256k1<All> { Secp256k1::new() }

pub fn sk(label: &str) -> SecretKey {
    SecretKey::from_slice(&tagged_hash("SPJ/test-key", label.as_bytes())).expect("valid key")
}

/// The first key in the label's sequence whose point has the requested y parity.
pub fn sk_parity(label: &str, even: bool) -> SecretKey {
    let secp = secp();
    (0..)
        .map(|i| sk(&format!("{label}/{i}")))
        .find(|key| (key.public_key(&secp).x_only_public_key().1 == Parity::Even) == even)
        .expect("half of all keys qualify")
}

pub fn rnd32(label: &str) -> [u8; 32] { tagged_hash("SPJ/aux", label.as_bytes()) }

/// A harness silent payment wallet.
pub struct Wallet {
    pub keys: SpKeys,
}

impl Wallet {
    pub fn new(name: &str) -> Self {
        Self {
            keys: SpKeys { scan: sk(&format!("{name}/scan")), spend: sk(&format!("{name}/spend")) },
        }
    }

    pub fn address(&self) -> SpAddress { self.keys.address(&secp()) }

    /// The address for label `m`: `B_spend + hash_BIP0352/Label(b_scan || m)·G`.
    pub fn labelled(&self, m: u32) -> SpAddress {
        let secp = secp();
        let mut msg = self.keys.scan.secret_bytes().to_vec();
        msg.extend_from_slice(&m.to_be_bytes());
        let tweak = Scalar::from_be_bytes(tagged_hash("BIP0352/Label", &msg)).expect("valid");
        let spend = self.keys.spend.public_key(&secp).add_exp_tweak(&secp, &tweak).expect("valid");
        SpAddress::new(self.keys.scan.public_key(&secp), spend, Network::Regtest)
    }
}

pub fn bob() -> Wallet { Wallet::new("bob") }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    P2tr,
    P2wpkh,
    P2pkh,
    P2shP2wpkh,
    P2wsh,
    /// A taproot script path from BIP 341's unspendable internal key.
    NumsScript,
    SegwitV2,
}

/// One input as the harness builds it.
#[derive(Clone, Debug)]
pub struct In {
    pub label: String,
    pub kind: Kind,
    pub outpoint: OutPoint,
    pub secret: Option<SecretKey>,
    pub prevout: TxOut,
    /// The leaf script and control block of a script-path spend.
    pub script_path: Option<(ScriptBuf, Vec<u8>)>,
}

impl In {
    pub fn new(
        label: &str,
        kind: Kind,
        order: u8,
        vout: u32,
        secret: Option<SecretKey>,
        value: u64,
    ) -> Self {
        let secp = secp();
        let mut hash = tagged_hash("SPJ/txid", label.as_bytes());
        hash[0] = order;
        let outpoint = OutPoint { txid: Txid::from_byte_array(hash), vout };
        let public = secret.map(|s| s.public_key(&secp));
        let mut script_path = None;
        let script_pubkey = match kind {
            Kind::P2tr => derive::p2tr_script(public.expect("keyed").x_only_public_key().0),
            Kind::P2wpkh => ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                &public.expect("keyed").serialize(),
            )),
            Kind::P2pkh => ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::hash(
                &public.expect("keyed").serialize(),
            )),
            Kind::P2shP2wpkh => ScriptBuf::new_p2sh(&bitcoin::ScriptHash::hash(
                redeem_script(&public.expect("keyed")).as_bytes(),
            )),
            Kind::P2wsh => {
                let key = |role: &str| sk(&format!("{label}/{role}")).public_key(&secp);
                let script = bitcoin::blockdata::script::Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_2)
                    .push_key(&bitcoin::PublicKey::new(key("ms1")))
                    .push_key(&bitcoin::PublicKey::new(key("ms2")))
                    .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_2)
                    .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
                    .into_script();
                script_path = Some((script.clone(), Vec::new()));
                ScriptBuf::new_p2wsh(&script.wscript_hash())
            }
            Kind::NumsScript => {
                let (script, control, output) = nums_leaf(label, &NUMS_H);
                script_path = Some((script, control));
                derive::p2tr_script(output)
            }
            Kind::SegwitV2 => {
                let mut bytes = vec![0x52, 0x20];
                bytes.extend_from_slice(&rnd32(&format!("{label}/prog")));
                ScriptBuf::from_bytes(bytes)
            }
        };
        Self {
            label: label.to_string(),
            kind,
            outpoint,
            secret,
            prevout: TxOut { value: Amount::from_sat(value), script_pubkey },
            script_path,
        }
    }

    /// The secret BIP 352 sums for this input, if it is eligible.
    pub fn bip352_secret(&self) -> Option<SecretKey> {
        let secret = self.secret?;
        let kind = match self.kind {
            Kind::P2tr => bip352::InputKind::P2tr,
            Kind::P2wpkh => bip352::InputKind::P2wpkh,
            Kind::P2pkh => bip352::InputKind::P2pkh,
            Kind::P2shP2wpkh => bip352::InputKind::P2shP2wpkh,
            _ => return None,
        };
        Some(bip352::input_secret_key(&secp(), &secret, kind))
    }
}

pub fn redeem_script(key: &PublicKey) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(&key.serialize()))
}

/// A one-leaf `<key> OP_CHECKSIG` tree under `internal`: the leaf script, its
/// control block and the output key.
pub fn nums_leaf(label: &str, internal: &[u8; 32]) -> (ScriptBuf, Vec<u8>, XOnlyPublicKey) {
    let secp = secp();
    let leaf_key = sk(&format!("{label}/leaf")).x_only_public_key(&secp).0;
    let script = bitcoin::blockdata::script::Builder::new()
        .push_x_only_key(&leaf_key)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();
    let internal = XOnlyPublicKey::from_slice(internal).expect("valid x-only key");
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("one leaf")
        .finalize(&secp, internal)
        .expect("complete tree");
    let control = info.control_block(&(script.clone(), LeafVersion::TapScript)).expect("leaf");
    (script, control.serialize(), info.output_key().to_x_only_public_key())
}

/// The harness's sender: an odd-y P2TR input and a P2WPKH input.
pub fn sender_inputs() -> Vec<In> {
    vec![
        In::new("alice-tr", Kind::P2tr, 0x80, 0, Some(sk_parity("alice/tr", false)), 60_000),
        In::new("alice-wpkh", Kind::P2wpkh, 0x90, 1, Some(sk("alice/wpkh")), 40_000),
    ]
}

pub fn recv_input(label: &str, order: u8, even: bool, kind: Kind) -> In {
    In::new(label, kind, order, 0, Some(sk_parity(&format!("bob/{label}"), even)), 25_000)
}

/// The harness's default receiver coin: an odd-y P2TR input.
pub fn bob_tr() -> In { recv_input("bob-tr", 0xA0, false, Kind::P2tr) }

/// A P2TR script for the x-only key of `secret`, with no BIP 341 tweak.
pub fn tr_key(secret: &SecretKey) -> ScriptBuf {
    derive::p2tr_script(secret.x_only_public_key(&secp()).0)
}

/// The sender's ordinary BIP 86 change, as the harness models it.
pub fn alice_change() -> ScriptBuf { tr_key(&sk("alice/hd/0")) }

pub fn out(script: &ScriptBuf, sat: u64) -> TxOut {
    TxOut { value: Amount::from_sat(sat), script_pubkey: script.clone() }
}

/// The outputs `inputs` derive for `sp`, one per entry, as a sender holding
/// every input key derives them.
pub fn sender_outputs(inputs: &[In], recipients: &[SpAddress]) -> Vec<ScriptBuf> {
    let secrets: Vec<SecretKey> = inputs.iter().filter_map(In::bip352_secret).collect();
    let outpoints: Vec<OutPoint> = inputs.iter().map(|i| i.outpoint).collect();
    let recipients: Vec<bip352::SpAddress> =
        recipients.iter().map(|sp| bip352::SpAddress { scan: sp.scan, spend: sp.spend }).collect();
    bip352::sender_outputs(&secp(), &secrets, &outpoints, &recipients)
        .expect("derivable")
        .into_iter()
        .map(derive::p2tr_script)
        .collect()
}

/// The harness's Original: 50,000 sat to Bob's sp1 and 49,000 sat of
/// ordinary change.
pub fn orig_paying_bob(sender: &[In]) -> Vec<TxOut> {
    let payee = sender_outputs(sender, &[bob().address()]).remove(0);
    vec![out(&payee, 50_000), out(&alice_change(), 49_000)]
}

fn unsigned(inputs: &[&In], outputs: &[TxOut]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs.to_vec(),
    }
}

/// The sender's Original as a PSBT: its inputs with their prevouts.
pub fn original_psbt(sender: &[In], outputs: &[TxOut]) -> Psbt {
    let inputs: Vec<&In> = sender.iter().collect();
    let mut psbt = Psbt::from_unsigned_tx(unsigned(&inputs, outputs)).expect("unsigned");
    for (psbtin, input) in psbt.inputs.iter_mut().zip(sender) {
        psbtin.witness_utxo = Some(input.prevout.clone());
    }
    psbt
}

/// The BIP 352 secrets of the sender's eligible inputs, as the sender check takes them.
pub fn own_secrets(sender: &[In]) -> BTreeMap<OutPoint, SecretKey> {
    sender.iter().filter_map(|i| Some((i.outpoint, i.bip352_secret()?))).collect()
}

/// The finalized spend of input `index` of `tx`.
pub fn spend(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    input: &In,
) -> (ScriptBuf, Witness) {
    let secp = secp();
    let mut cache = SighashCache::new(tx);
    let ecdsa =
        |cache: &mut SighashCache<&Transaction>, program: &ScriptBuf, secret: &SecretKey| {
            let sighash = cache
                .p2wpkh_signature_hash(index, program, prevouts[index].value, EcdsaSighashType::All)
                .expect("in range");
            let signature = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), secret);
            Witness::p2wpkh(
                &bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All },
                &secret.public_key(&secp),
            )
        };
    match input.kind {
        Kind::P2tr => {
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(prevouts),
                    TapSighashType::Default,
                )
                .expect("in range");
            let keypair = Keypair::from_secret_key(&secp, &input.secret.expect("keyed"));
            let signature = secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &keypair);
            (
                ScriptBuf::new(),
                Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                }),
            )
        }
        Kind::P2wpkh => {
            let secret = input.secret.expect("keyed");
            (ScriptBuf::new(), ecdsa(&mut cache, &input.prevout.script_pubkey, &secret))
        }
        Kind::P2shP2wpkh => {
            let secret = input.secret.expect("keyed");
            let redeem = redeem_script(&secret.public_key(&secp));
            let script_sig = bitcoin::blockdata::script::Builder::new()
                .push_slice(PushBytesBuf::try_from(redeem.to_bytes()).expect("short"))
                .into_script();
            (script_sig, ecdsa(&mut cache, &redeem, &secret))
        }
        Kind::P2pkh => {
            let secret = input.secret.expect("keyed");
            let sighash = cache
                .legacy_signature_hash(
                    index,
                    &input.prevout.script_pubkey,
                    EcdsaSighashType::All.to_u32(),
                )
                .expect("in range");
            let signature = bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &secret),
                sighash_type: EcdsaSighashType::All,
            };
            let script_sig = bitcoin::blockdata::script::Builder::new()
                .push_slice(PushBytesBuf::try_from(signature.to_vec()).expect("short"))
                .push_key(&bitcoin::PublicKey::new(secret.public_key(&secp)))
                .into_script();
            (script_sig, Witness::new())
        }
        Kind::P2wsh => {
            let (script, _) = input.script_path.clone().expect("witness script");
            let placeholder = rnd32(&format!("{}/s1", input.label));
            let items: Vec<Vec<u8>> = vec![
                vec![],
                [placeholder, placeholder].concat(),
                [placeholder, placeholder].concat(),
                script.to_bytes(),
            ];
            (ScriptBuf::new(), Witness::from_slice(&items))
        }
        Kind::NumsScript => {
            // The leaf's signature isn't checked by the sender, which checks
            // only the control block's commitment for a script path.
            let (script, control) = input.script_path.clone().expect("leaf");
            let placeholder = rnd32(&format!("{}/sig", input.label));
            let items: Vec<Vec<u8>> =
                vec![[placeholder, placeholder].concat(), script.to_bytes(), control];
            (ScriptBuf::new(), Witness::from_slice(&items))
        }
        Kind::SegwitV2 => (ScriptBuf::new(), Witness::from_slice(&[[1u8]])),
    }
}

/// A receiver input's BIP 375 share and BIP 374 proof, made as the harness's
/// receiver signer step makes them. `parity: false` skips BIP 352's
/// negation of an odd-y taproot key.
pub fn share(input: &In, scan: &PublicKey, tag: &str, parity: bool) -> (PublicKey, [u8; 64]) {
    let secret = if parity {
        input.bip352_secret().expect("eligible")
    } else {
        input.secret.expect("keyed")
    };
    carriage::share_and_proof(&secp(), &secret, scan, &rnd32(&format!("{tag}/{}", input.label)))
        .expect("provable")
}

/// A share and proof to place on one receiver input.
pub struct Attach {
    pub label: String,
    pub share: PublicKey,
    pub proof: [u8; 64],
}

impl Attach {
    pub fn honest(input: &In, tag: &str) -> Self {
        let (share, proof) = share(input, &bob().address().scan, tag, true);
        Self { label: input.label.clone(), share, proof }
    }
}

/// A proposal adding `receiver` inputs to the sender's Original, paying
/// `outputs`, with each receiver input finalized and carrying the shares in
/// `attach`.
pub fn proposal_psbt(sender: &[In], receiver: &[In], outputs: &[TxOut], attach: &[Attach]) -> Psbt {
    let inputs: Vec<&In> = sender.iter().chain(receiver).collect();
    let tx = unsigned(&inputs, outputs);
    let prevouts: Vec<TxOut> = inputs.iter().map(|i| i.prevout.clone()).collect();
    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).expect("unsigned");
    let scan = bob().address().scan;
    for (index, input) in inputs.iter().enumerate() {
        psbt.inputs[index].witness_utxo = Some(input.prevout.clone());
        if index < sender.len() {
            continue;
        }
        let (script_sig, witness) = spend(&tx, index, &prevouts, input);
        psbt.inputs[index].final_script_sig = (!script_sig.is_empty()).then_some(script_sig);
        psbt.inputs[index].final_script_witness = Some(witness);
        if let Some(a) = attach.iter().find(|a| a.label == input.label) {
            carriage::set_share_and_proof(&mut psbt.inputs[index], &scan, &a.share, &a.proof);
        }
    }
    psbt
}

/// The transaction with every input signed, as it would confirm.
pub fn signed_tx(inputs: &[In], outputs: &[TxOut]) -> Transaction {
    let refs: Vec<&In> = inputs.iter().collect();
    let mut tx = unsigned(&refs, outputs);
    let prevouts: Vec<TxOut> = inputs.iter().map(|i| i.prevout.clone()).collect();
    let template = tx.clone();
    for (index, input) in inputs.iter().enumerate() {
        let (script_sig, witness) = spend(&template, index, &prevouts, input);
        tx.input[index].script_sig = script_sig;
        tx.input[index].witness = witness;
    }
    tx
}

/// The receiver's honest proposal outputs for `contrib`: the payee output
/// re-derived over the final inputs and credited with the added value less
/// `fee`, the change untouched. Returns the outputs and the new payee script.
pub fn honest_outputs(
    sender: &[In],
    original: &[TxOut],
    contrib: &[In],
    fee: u64,
) -> (Vec<TxOut>, ScriptBuf) {
    let all: Vec<&In> = sender.iter().chain(contrib).collect();
    let new = rederive(&all);
    let added: u64 = contrib.iter().map(|i| i.prevout.value.to_sat()).sum();
    let outputs = vec![out(&new, original[0].value.to_sat() + added - fee), original[1].clone()];
    (outputs, new)
}

/// Bob's k = 0 output over `inputs`, from public data and his scan key.
pub fn rederive(inputs: &[&In]) -> ScriptBuf {
    let secp = secp();
    let keys: Vec<PublicKey> =
        inputs.iter().filter_map(|i| i.bip352_secret().map(|s| s.public_key(&secp))).collect();
    let outpoints: Vec<OutPoint> = inputs.iter().map(|i| i.outpoint).collect();
    spj_demo::derive::receiver_outputs(&secp, &bob().keys, &keys, &outpoints, &[None])
        .expect("derivable")
        .remove(0)
}

/// The x-only key of a P2TR script, as hex.
pub fn key_hex(script: &ScriptBuf) -> String { script.to_hex_string()[4..].to_string() }

pub fn hash160_of(bytes: &[u8]) -> [u8; 20] { hash160::Hash::hash(bytes).to_byte_array() }
