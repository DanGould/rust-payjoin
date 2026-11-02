//! BIP 375 per-input ECDH shares with DLEQ proofs, carried in a version
//! 0 PSBT.
//!
//! The owner of an input proves it contributed the share `C = a·B_scan`
//! for its input key `A = a·G`, so anyone holding the PSBT can complete
//! the BIP 352 derivation for that scan key without the input secret,
//! and can check the share instead of trusting it.
//!
//! BIP 375 defines `PSBT_IN_SP_ECDH_SHARE` (0x1d) and `PSBT_IN_SP_DLEQ`
//! (0x1e) for PSBT version 2 only, while BIP 78 and BIP 77 payjoin
//! exchange version 0 PSBTs. So the same key data and values travel as
//! `PSBT_IN_PROPRIETARY` pairs: identifier `spj`, subtype = the BIP 375
//! type number, key data = the 33-byte scan key. Serialized, one input's
//! pair of entries is
//!
//! ```text
//! 27 fc 03 73706a 1d <B_scan 33>   21 <C 33>
//! 27 fc 03 73706a 1e <B_scan 33>   40 <proof 64>
//! ```
//!
//! BIP 174 reserves proprietary types for private use, so this layout is
//! not an interoperable format. Moving to PSBT version 2 would change
//! only the keys.

use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::psbt::{self};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification};

use crate::dleq::{self, Proof};

/// Proprietary identifier for these pairs.
pub const IDENTIFIER: &[u8] = b"spj";
/// BIP 375 `PSBT_IN_SP_ECDH_SHARE`.
pub const SUBTYPE_ECDH_SHARE: u8 = 0x1d;
/// BIP 375 `PSBT_IN_SP_DLEQ`.
pub const SUBTYPE_DLEQ: u8 = 0x1e;

/// The ECDH share `a·B_scan` of one input and its BIP 374 proof.
///
/// `input_secret` is the secret as BIP 352 uses it, from
/// [`input_secret_key`](crate::bip352::input_secret_key), so that the
/// proof verifies against the key a verifier reads from the chain.
/// `aux_rand` should be fresh randomness. As in BIP 375 the proof binds
/// no message.
pub fn share_and_proof<C: Verification>(
    secp: &Secp256k1<C>,
    input_secret: &SecretKey,
    scan: &PublicKey,
    aux_rand: &[u8; 32],
) -> Option<(PublicKey, Proof)> {
    let share = scan.mul_tweak(secp, &Scalar::from(*input_secret)).ok()?;
    let proof = dleq::generate_proof(secp, input_secret, scan, aux_rand, &dleq::generator(), None)?;
    Some((share, proof))
}

/// Check that `share` is `a·scan` for the `a` behind `input_key`, the
/// key [`input_public_key`](crate::bip352::input_public_key) reads.
pub fn verify_share<C: Verification>(
    secp: &Secp256k1<C>,
    input_key: &PublicKey,
    scan: &PublicKey,
    share: &PublicKey,
    proof: &Proof,
) -> bool {
    dleq::verify_proof(secp, input_key, scan, share, proof, &dleq::generator(), None)
}

fn key(subtype: u8, scan: &PublicKey) -> ProprietaryKey {
    ProprietaryKey { prefix: IDENTIFIER.to_vec(), subtype, key: scan.serialize().to_vec() }
}

/// Add an input's share and proof for one scan key, replacing any
/// already there for that key.
pub fn set_share_and_proof(
    input: &mut psbt::Input,
    scan: &PublicKey,
    share: &PublicKey,
    proof: &Proof,
) {
    input.proprietary.insert(key(SUBTYPE_ECDH_SHARE, scan), share.serialize().to_vec());
    input.proprietary.insert(key(SUBTYPE_DLEQ, scan), proof.to_vec());
}

#[derive(Debug, PartialEq, Eq)]
pub enum CarriageError {
    /// A share without a proof, or a proof without a share.
    Incomplete,
    /// A value of the wrong length, or a share that is not a valid point.
    Malformed,
}

impl std::fmt::Display for CarriageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarriageError::Incomplete => write!(f, "share and proof must come together"),
            CarriageError::Malformed => write!(f, "malformed share or proof"),
        }
    }
}

impl std::error::Error for CarriageError {}

/// An input's share and proof for one scan key, `None` if it carries
/// neither. This only parses; call [`verify_share`] before using them.
pub fn get_share_and_proof(
    input: &psbt::Input,
    scan: &PublicKey,
) -> Result<Option<(PublicKey, Proof)>, CarriageError> {
    let share = input.proprietary.get(&key(SUBTYPE_ECDH_SHARE, scan));
    let proof = input.proprietary.get(&key(SUBTYPE_DLEQ, scan));
    match (share, proof) {
        (None, None) => Ok(None),
        (Some(share), Some(proof)) => {
            let share = (share.len() == 33)
                .then(|| PublicKey::from_slice(share).ok())
                .flatten()
                .ok_or(CarriageError::Malformed)?;
            let proof: Proof = proof.as_slice().try_into().map_err(|_| CarriageError::Malformed)?;
            Ok(Some((share, proof)))
        }
        _ => Err(CarriageError::Incomplete),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_for_one_input_does_not_vouch_for_another() {
        let secp = Secp256k1::new();
        let scan = SecretKey::from_slice(&[0x55; 32]).unwrap().public_key(&secp);
        let mine = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let theirs = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let (share, proof) = share_and_proof(&secp, &mine, &scan, &[0u8; 32]).unwrap();
        assert!(verify_share(&secp, &mine.public_key(&secp), &scan, &share, &proof));
        assert!(!verify_share(&secp, &theirs.public_key(&secp), &scan, &share, &proof));

        let other_scan = SecretKey::from_slice(&[0x66; 32]).unwrap().public_key(&secp);
        assert!(!verify_share(&secp, &mine.public_key(&secp), &other_scan, &share, &proof));
    }

    #[test]
    fn half_a_pair_is_an_error() {
        let secp = Secp256k1::new();
        let scan = SecretKey::from_slice(&[0x55; 32]).unwrap().public_key(&secp);
        let mut input = psbt::Input::default();
        assert_eq!(get_share_and_proof(&input, &scan), Ok(None));
        input.proprietary.insert(key(SUBTYPE_ECDH_SHARE, &scan), scan.serialize().to_vec());
        assert_eq!(get_share_and_proof(&input, &scan), Err(CarriageError::Incomplete));
        input.proprietary.insert(key(SUBTYPE_DLEQ, &scan), vec![0u8; 63]);
        assert_eq!(get_share_and_proof(&input, &scan), Err(CarriageError::Malformed));
    }
}
