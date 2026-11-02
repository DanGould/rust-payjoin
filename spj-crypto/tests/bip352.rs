//! The BIP 352 send and receive test vectors, except receiving with
//! labels, which this crate does not implement.

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, Txid, Witness, XOnlyPublicKey};
use serde_json::Value;
use spj_crypto::bip352::{
    input_public_key, input_secret_key, input_secret_sum, public_tweak, scan, sender_outputs,
    sender_shared_secret, spend_key, SpAddress,
};

const VECTORS: &str = include_str!("vectors/send_and_receive_test_vectors.json");

struct Vin {
    outpoint: OutPoint,
    script_sig: ScriptBuf,
    witness: Witness,
    prevout: ScriptBuf,
    secret: Option<SecretKey>,
}

fn bytes(value: &Value) -> Vec<u8> { Vec::<u8>::from_hex(value.as_str().unwrap()).unwrap() }

fn hex_list(value: &Value) -> Vec<String> {
    value.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect()
}

fn vins(given: &Value) -> Vec<Vin> {
    given["vin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vin| {
            let witness = bytes(&vin["txinwitness"]);
            Vin {
                outpoint: OutPoint {
                    txid: Txid::from_str(vin["txid"].as_str().unwrap()).unwrap(),
                    vout: vin["vout"].as_u64().unwrap() as u32,
                },
                script_sig: ScriptBuf::from_bytes(bytes(&vin["scriptSig"])),
                witness: if witness.is_empty() {
                    Witness::new()
                } else {
                    bitcoin::consensus::deserialize(&witness).unwrap()
                },
                prevout: ScriptBuf::from_bytes(bytes(&vin["prevout"]["scriptPubKey"]["hex"])),
                secret: vin.get("private_key").map(|k| SecretKey::from_slice(&bytes(k)).unwrap()),
            }
        })
        .collect()
}

#[derive(Default, Debug)]
struct Counts {
    send: usize,
    receive: usize,
    receive_skipped_labels: usize,
}

#[test]
fn send_and_receive_vectors() {
    let secp = Secp256k1::new();
    let cases: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut counts = Counts::default();
    for case in &cases {
        let comment = case["comment"].as_str().unwrap();
        for test in case["sending"].as_array().unwrap() {
            check_sending(&secp, &test["given"], &test["expected"], comment);
            counts.send += 1;
        }
        for test in case["receiving"].as_array().unwrap() {
            let labels = test["given"]["labels"].as_array().map_or(0, Vec::len);
            if labels > 0 {
                counts.receive_skipped_labels += 1;
                continue;
            }
            check_receiving(&secp, &test["given"], &test["expected"], comment);
            counts.receive += 1;
        }
    }
    eprintln!("{} cases: {counts:?}", cases.len());
    assert_eq!(cases.len(), 28);
    assert_eq!(counts.send, 28);
    assert_eq!(counts.receive, 21);
    assert_eq!(counts.receive_skipped_labels, 8);
}

fn check_sending(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    given: &Value,
    expected: &Value,
    comment: &str,
) {
    let vins = vins(given);
    let mut input_keys = Vec::new();
    let mut secrets = Vec::new();
    for vin in &vins {
        if let Some((kind, key)) = input_public_key(&vin.script_sig, &vin.witness, &vin.prevout) {
            input_keys.push(key.serialize().to_lower_hex_string());
            secrets.push(input_secret_key(secp, &vin.secret.unwrap(), kind));
        }
    }
    assert_eq!(input_keys, hex_list(&expected["input_pub_keys"]), "{comment}: input keys");

    let mut recipients = Vec::new();
    for entry in given["recipients"].as_array().unwrap() {
        let (hrp, address) = SpAddress::decode(entry["address"].as_str().unwrap()).unwrap();
        assert_eq!(hrp.as_str(), "sp");
        assert_eq!(address.scan.serialize().to_vec(), bytes(&entry["scan_pub_key"]), "{comment}");
        assert_eq!(address.spend.serialize().to_vec(), bytes(&entry["spend_pub_key"]), "{comment}");
        let count = entry.get("count").map_or(1, |c| c.as_u64().unwrap() as usize);
        recipients.extend(std::iter::repeat_n(address, count));
    }

    let expected_sets: Vec<BTreeSet<String>> = expected["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|set| hex_list(set).into_iter().collect())
        .collect();
    if secrets.is_empty() {
        assert!(expected_sets[0].is_empty(), "{comment}: no eligible input must mean no outputs");
        return;
    }
    if let Some(sum) = expected.get("input_private_key_sum") {
        let a_sum = input_secret_sum(&secrets).expect("non-zero sum");
        assert_eq!(a_sum.secret_bytes().to_vec(), bytes(sum), "{comment}: secret sum");
    }
    let outpoints: Vec<OutPoint> = vins.iter().map(|vin| vin.outpoint).collect();
    let actual: BTreeSet<String> = match sender_outputs(secp, &secrets, &outpoints, &recipients) {
        Ok(outputs) => {
            let a_sum = input_secret_sum(&secrets).unwrap();
            let shared = hex_list(&expected["shared_secrets"]);
            for (index, recipient) in recipients.iter().enumerate() {
                if recipients[..index].iter().any(|r| r.scan == recipient.scan) {
                    continue;
                }
                let secret =
                    sender_shared_secret(secp, &a_sum, &outpoints, &recipient.scan).unwrap();
                assert_eq!(secret.serialize().to_lower_hex_string(), shared[index], "{comment}");
            }
            outputs.iter().map(|key| key.serialize().to_lower_hex_string()).collect()
        }
        Err(_) => BTreeSet::new(),
    };
    assert!(expected_sets.contains(&actual), "{comment}: outputs {actual:?}");
}

fn check_receiving(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    given: &Value,
    expected: &Value,
    comment: &str,
) {
    let b_scan = SecretKey::from_slice(&bytes(&given["key_material"]["scan_priv_key"])).unwrap();
    let b_spend = SecretKey::from_slice(&bytes(&given["key_material"]["spend_priv_key"])).unwrap();
    let address = SpAddress { scan: b_scan.public_key(secp), spend: b_spend.public_key(secp) };
    assert_eq!(vec![address.encode("sp")], hex_list(&expected["addresses"]), "{comment}");

    let vins = vins(given);
    let keys: Vec<PublicKey> = vins
        .iter()
        .filter_map(|vin| input_public_key(&vin.script_sig, &vin.witness, &vin.prevout))
        .map(|(_, key)| key)
        .collect();
    let outpoints: Vec<OutPoint> = vins.iter().map(|vin| vin.outpoint).collect();
    // An output key that is not a curve point can never be a derived
    // key, so dropping it before the scan changes nothing.
    let outputs: Vec<XOnlyPublicKey> = hex_list(&given["outputs"])
        .iter()
        .filter_map(|hex| XOnlyPublicKey::from_slice(&Vec::<u8>::from_hex(hex).unwrap()).ok())
        .collect();

    let msg = Message::from_digest(sha256::Hash::hash(b"message").to_byte_array());
    let aux = sha256::Hash::hash(b"random auxiliary data").to_byte_array();
    let found: BTreeSet<(String, String, String)> = match public_tweak(secp, &outpoints, &keys) {
        None => BTreeSet::new(),
        Some(tweak) => {
            let refs: Vec<&PublicKey> = keys.iter().collect();
            let a_sum = PublicKey::combine_keys(&refs).unwrap();
            assert_eq!(
                a_sum.serialize().to_vec(),
                bytes(&expected["input_pub_key_sum"]),
                "{comment}"
            );
            assert_eq!(tweak.serialize().to_vec(), bytes(&expected["tweak"]), "{comment}");
            let shared = tweak.mul_tweak(secp, &Scalar::from(b_scan)).unwrap();
            assert_eq!(shared.serialize().to_vec(), bytes(&expected["shared_secret"]), "{comment}");
            scan(secp, &b_scan, &address.spend, &tweak, &outputs)
                .iter()
                .map(|found| {
                    let keypair =
                        Keypair::from_secret_key(secp, &spend_key(&b_spend, found).unwrap());
                    assert_eq!(keypair.x_only_public_key().0, found.output_key);
                    let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux);
                    (
                        found.output_key.serialize().to_lower_hex_string(),
                        found.tweak.to_be_bytes().to_lower_hex_string(),
                        signature.as_ref().to_lower_hex_string(),
                    )
                })
                .collect()
        }
    };

    if let Some(n) = expected.get("n_outputs") {
        assert_eq!(found.len() as u64, n.as_u64().unwrap(), "{comment}");
        return;
    }
    let expected: BTreeSet<(String, String, String)> = expected["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let field = |name: &str| o[name].as_str().unwrap().to_owned();
            (field("pub_key"), field("priv_key_tweak"), field("signature"))
        })
        .collect();
    assert_eq!(found, expected, "{comment}: found outputs");
}
