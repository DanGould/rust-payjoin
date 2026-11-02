//! Shares and proofs in a version 0 PSBT, cross-checked against the
//! silent payjoin harness vectors in `vectors/per_input_proofs.json`
//! (scenarios S26a and S26b), which fix every key and aux value.

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use serde_json::Value;
use spj_crypto::bip352::{input_public_key, input_secret_key, InputKind};
use spj_crypto::carriage::{
    get_share_and_proof, set_share_and_proof, share_and_proof, verify_share,
};
use spj_crypto::tagged_hash;

const VECTORS: &str = include_str!("vectors/per_input_proofs.json");

/// The harness derives every test key and aux value from a label.
fn harness_key(label: &str) -> SecretKey {
    SecretKey::from_slice(&tagged_hash("SPJ/test-key", label.as_bytes())).unwrap()
}

fn harness_aux(label: &str) -> [u8; 32] { tagged_hash("SPJ/aux", label.as_bytes()) }

/// The first key in a label's sequence whose point has the given parity.
fn harness_key_with_parity(label: &str, parity: Parity) -> SecretKey {
    let secp = Secp256k1::signing_only();
    (0..)
        .map(|i| harness_key(&format!("{label}/{i}")))
        .find(|key| key.x_only_public_key(&secp).1 == parity)
        .unwrap()
}

fn scenario(id: &str) -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    vectors["scenarios"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap().clone()
}

fn hex(value: &Value) -> Vec<u8> { Vec::<u8>::from_hex(value.as_str().unwrap()).unwrap() }

fn one_input_psbt() -> Psbt {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() }],
    };
    Psbt::from_unsigned_tx(tx).unwrap()
}

/// S26a: the receiver's two P2TR inputs, one with an odd-y key. Every
/// share and proof matches byte for byte, verifies against the key read
/// from the input, and the shares sum to `b_scan·A`.
#[test]
fn per_input_shares_match_the_harness() {
    let secp = Secp256k1::new();
    let s26a = scenario("S26a");
    let b_scan = harness_key("bob/scan");
    let scan = b_scan.public_key(&secp);

    let mut shares = Vec::new();
    let mut input_keys = Vec::new();
    let inputs = s26a["receiver_inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 2);
    for input in inputs {
        let label = input["label"].as_str().unwrap();
        let prevout = ScriptBuf::from_bytes(hex(&input["scriptPubKey"]));
        let witness = Witness::from_slice(
            &input["txinwitness_stack"].as_array().unwrap().iter().map(hex).collect::<Vec<_>>(),
        );
        let (kind, input_key) =
            input_public_key(&ScriptBuf::new(), &witness, &prevout).expect("eligible");
        assert_eq!(kind, InputKind::P2tr);
        assert_eq!(input_key.serialize().to_vec(), hex(&input["bip352_pubkey"]), "{label}");

        let secret = SecretKey::from_slice(&hex(&input["private_key"])).unwrap();
        let secret = input_secret_key(&secp, &secret, kind);
        let aux = harness_aux(&format!("s26a/{label}"));
        let (share, proof) = share_and_proof(&secp, &secret, &scan, &aux).unwrap();
        assert_eq!(share.serialize().to_vec(), hex(&s26a["shares"][label]), "{label} share");
        assert_eq!(proof.to_vec(), hex(&s26a["proofs"][label]), "{label} proof");
        assert!(verify_share(&secp, &input_key, &scan, &share, &proof), "{label}");
        shares.push(share);
        input_keys.push(input_key);
    }
    assert!(inputs.iter().any(|i| i["label"] == "bob-tr-odd"), "the odd-y case is covered");

    let share_refs: Vec<&PublicKey> = shares.iter().collect();
    let key_refs: Vec<&PublicKey> = input_keys.iter().collect();
    let aggregate = PublicKey::combine_keys(&key_refs)
        .unwrap()
        .mul_tweak(&secp, &Scalar::from(b_scan))
        .unwrap();
    assert_eq!(PublicKey::combine_keys(&share_refs).unwrap(), aggregate);
}

/// S26b: the exact bytes of one input's pairs, and a round trip through
/// a serialized PSBT.
#[test]
fn psbt_v0_carriage_matches_the_harness_and_round_trips() {
    let secp = Secp256k1::new();
    let s26b = scenario("S26b");
    let scan = harness_key("bob/scan").public_key(&secp);
    let secret = input_secret_key(
        &secp,
        &harness_key_with_parity("bob/bob-tr", Parity::Odd),
        InputKind::P2tr,
    );
    let (share, proof) =
        share_and_proof(&secp, &secret, &scan, &harness_aux("s26b/bob-tr")).unwrap();

    let mut psbt = one_input_psbt();
    set_share_and_proof(&mut psbt.inputs[0], &scan, &share, &proof);
    let serialized = psbt.serialize();

    let pairs = hex(&s26b["input_map_pairs"]);
    assert_eq!(pairs.len(), 179);
    assert_eq!(pairs[..40], hex(&s26b["share_key"])[..]);
    assert!(
        serialized.windows(pairs.len()).any(|w| w == pairs),
        "serialized PSBT lacks the harness pairs: {}",
        serialized.to_lower_hex_string()
    );

    let parsed = Psbt::deserialize(&serialized).unwrap();
    let (got_share, got_proof) = get_share_and_proof(&parsed.inputs[0], &scan).unwrap().unwrap();
    assert_eq!((got_share, got_proof), (share, proof));
    let input_key = secret.public_key(&secp);
    assert!(verify_share(&secp, &input_key, &scan, &got_share, &got_proof));

    let other_scan = harness_key("carol/scan").public_key(&secp);
    assert_eq!(get_share_and_proof(&parsed.inputs[0], &other_scan), Ok(None));
}
