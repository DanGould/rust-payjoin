//! BIP 374 discrete log equality (DLEQ) proofs.
//!
//! A proof shows that `A = a·G` and `C = a·B` share the discrete log
//! `a` without revealing it. BIP 375 uses this so that a party who did
//! not hold `a` can still check that an ECDH share `C` was computed from
//! the key behind a known public key `A`.
//!
//! The generator `G` is a parameter because the BIP 374 test vectors
//! vary it. Protocol code passes [`generator`].

use bitcoin::secp256k1::constants::GENERATOR_X;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification};

use crate::{reduce_mod_order, tagged_hash};

/// `e || s`, both 32-byte big-endian scalars.
pub type Proof = [u8; 64];

const TAG_AUX: &str = "BIP0374/aux";
const TAG_NONCE: &str = "BIP0374/nonce";
const TAG_CHALLENGE: &str = "BIP0374/challenge";

/// The secp256k1 base point.
pub fn generator() -> PublicKey {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(&GENERATOR_X);
    PublicKey::from_slice(&bytes).expect("the base point is a valid curve point")
}

/// Prove that `a·g` and `a·b` share the discrete log `a`.
///
/// `aux_rand` should be fresh randomness; the nonce is derived from it,
/// the secret and the statement, so a weak `aux_rand` does not leak `a`.
/// `m` optionally binds the proof to a 32-byte message. Returns `None`
/// in the cases BIP 374 calls failure, which a valid `SecretKey` and
/// `PublicKey` reach only with negligible probability.
pub fn generate_proof<C: Verification>(
    secp: &Secp256k1<C>,
    a: &SecretKey,
    b: &PublicKey,
    aux_rand: &[u8; 32],
    g: &PublicKey,
    m: Option<&[u8; 32]>,
) -> Option<Proof> {
    let a_scalar = Scalar::from(*a);
    let a_point = g.mul_tweak(secp, &a_scalar).ok()?;
    let c_point = b.mul_tweak(secp, &a_scalar).ok()?;

    let mask = tagged_hash(TAG_AUX, aux_rand);
    let mut nonce_input = Vec::with_capacity(32 + 33 + 33 + 32);
    nonce_input.extend(a.secret_bytes().iter().zip(mask).map(|(x, y)| x ^ y));
    nonce_input.extend_from_slice(&a_point.serialize());
    nonce_input.extend_from_slice(&c_point.serialize());
    if let Some(m) = m {
        nonce_input.extend_from_slice(m);
    }
    let k = SecretKey::from_slice(&reduce_mod_order(tagged_hash(TAG_NONCE, &nonce_input))).ok()?;
    let k_scalar = Scalar::from(k);
    let r1 = g.mul_tweak(secp, &k_scalar).ok()?;
    let r2 = b.mul_tweak(secp, &k_scalar).ok()?;

    let e = challenge(&a_point, b, &c_point, g, &r1, &r2, m);
    let e_scalar = Scalar::from_be_bytes(e).expect("reduced below the order");
    // s = k + e·a. SecretKey arithmetic refuses a zero operand or result,
    // so the e = 0 and s = 0 cases are spelled out.
    let s = if e_scalar == Scalar::ZERO {
        k.secret_bytes()
    } else {
        let ea = a.mul_tweak(&e_scalar).expect("product of non-zero scalars mod a prime");
        ea.add_tweak(&k_scalar).map(|s| s.secret_bytes()).unwrap_or([0u8; 32])
    };

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&e);
    proof[32..].copy_from_slice(&s);
    verify_proof(secp, &a_point, b, &c_point, &proof, g, m).then_some(proof)
}

/// Check a proof that `a_point = a·g` and `c_point = a·b` for some `a`.
pub fn verify_proof<C: Verification>(
    secp: &Secp256k1<C>,
    a_point: &PublicKey,
    b: &PublicKey,
    c_point: &PublicKey,
    proof: &Proof,
    g: &PublicKey,
    m: Option<&[u8; 32]>,
) -> bool {
    let e_bytes: [u8; 32] = proof[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = proof[32..].try_into().expect("32 bytes");
    let (Ok(e), Ok(s)) = (Scalar::from_be_bytes(e_bytes), Scalar::from_be_bytes(s_bytes)) else {
        return false;
    };
    let Some(r1) = mul_sub(secp, g, &s, a_point, &e) else { return false };
    let Some(r2) = mul_sub(secp, b, &s, c_point, &e) else { return false };
    challenge(a_point, b, c_point, g, &r1, &r2, m) == e_bytes
}

/// `s·p - e·q`, or `None` at the point at infinity.
fn mul_sub<C: Verification>(
    secp: &Secp256k1<C>,
    p: &PublicKey,
    s: &Scalar,
    q: &PublicKey,
    e: &Scalar,
) -> Option<PublicKey> {
    let mut terms = Vec::with_capacity(2);
    if *s != Scalar::ZERO {
        terms.push(p.mul_tweak(secp, s).ok()?);
    }
    if *e != Scalar::ZERO {
        terms.push(q.mul_tweak(secp, e).ok()?.negate(secp));
    }
    let refs: Vec<&PublicKey> = terms.iter().collect();
    PublicKey::combine_keys(&refs).ok()
}

fn challenge(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    g: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
    m: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(6 * 33 + 32);
    for point in [a, b, c, g, r1, r2] {
        msg.extend_from_slice(&point.serialize());
    }
    if let Some(m) = m {
        msg.extend_from_slice(m);
    }
    reduce_mod_order(tagged_hash(TAG_CHALLENGE, &msg))
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::Secp256k1;

    use super::*;

    #[test]
    fn a_proof_does_not_transfer_to_another_statement() {
        let secp = Secp256k1::new();
        let g = generator();
        let a = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let b = SecretKey::from_slice(&[0x22; 32]).unwrap().public_key(&secp);
        let a_point = a.public_key(&secp);
        let c_point = b.mul_tweak(&secp, &Scalar::from(a)).unwrap();
        let proof = generate_proof(&secp, &a, &b, &[0x33; 32], &g, None).unwrap();
        assert!(verify_proof(&secp, &a_point, &b, &c_point, &proof, &g, None));

        let other = SecretKey::from_slice(&[0x44; 32]).unwrap();
        let wrong_c = b.mul_tweak(&secp, &Scalar::from(other)).unwrap();
        assert!(!verify_proof(&secp, &a_point, &b, &wrong_c, &proof, &g, None));
        assert!(!verify_proof(&secp, &a_point, &b, &c_point, &proof, &g, Some(&[0u8; 32])));
    }
}
