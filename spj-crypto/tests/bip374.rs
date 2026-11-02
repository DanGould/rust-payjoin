//! Every row of the BIP 374 test vectors.

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use spj_crypto::dleq::{generate_proof, verify_proof, Proof};

const GENERATE: &str = include_str!("vectors/test_vectors_generate_proof.csv");
const VERIFY: &str = include_str!("vectors/test_vectors_verify_proof.csv");

fn rows(csv: &str, columns: usize) -> Vec<Vec<&str>> {
    let rows: Vec<Vec<&str>> = csv
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim_end_matches('\r').split(',').collect())
        .collect();
    assert!(rows.iter().all(|r| r.len() == columns), "unexpected column count");
    rows
}

/// `None` stands for the point at infinity, which `PublicKey` cannot hold.
fn point(hex: &str) -> Option<PublicKey> {
    if hex == "INFINITY" {
        return None;
    }
    Some(PublicKey::from_slice(&Vec::<u8>::from_hex(hex).unwrap()).unwrap())
}

fn bytes32(hex: &str) -> [u8; 32] { <[u8; 32]>::from_hex(hex).unwrap() }

fn message(hex: &str) -> Option<[u8; 32]> { (!hex.is_empty()).then(|| bytes32(hex)) }

#[test]
fn generate_proof_vectors() {
    let secp = Secp256k1::new();
    let rows = rows(GENERATE, 8);
    assert_eq!(rows.len(), 11);
    for row in &rows {
        let [index, g, a, b, aux, m, expected, comment] = row[..] else { unreachable!() };
        let expected: Option<Proof> =
            (expected != "INVALID").then(|| <[u8; 64]>::from_hex(expected).unwrap());
        let m = message(m);
        // A secret outside [1, n-1] or an infinite point has no Rust
        // representation, so those rows can only produce no proof.
        let actual = match (point(g), SecretKey::from_slice(&bytes32(a)), point(b)) {
            (Some(g), Ok(a), Some(b)) =>
                generate_proof(&secp, &a, &b, &bytes32(aux), &g, m.as_ref()),
            _ => None,
        };
        assert_eq!(actual, expected, "generate row {index} ({comment})");
    }
}

#[test]
fn verify_proof_vectors() {
    let secp = Secp256k1::new();
    let rows = rows(VERIFY, 9);
    assert_eq!(rows.len(), 17);
    for row in &rows {
        let [index, g, a, b, c, proof, m, expected, comment] = row[..] else { unreachable!() };
        let expected = match expected {
            "TRUE" => true,
            "FALSE" => false,
            other => panic!("row {index}: unexpected result {other}"),
        };
        let proof = <[u8; 64]>::from_hex(proof).unwrap();
        let m = message(m);
        let actual = match (point(g), point(a), point(b), point(c)) {
            (Some(g), Some(a), Some(b), Some(c)) =>
                verify_proof(&secp, &a, &b, &c, &proof, &g, m.as_ref()),
            _ => false,
        };
        assert_eq!(actual, expected, "verify row {index} ({comment})");
    }
}
