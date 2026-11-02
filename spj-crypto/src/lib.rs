//! Cryptography for silent payjoin: BIP 352 silent payments, BIP 374
//! discrete-log-equality proofs, and BIP 375's per-input ECDH share
//! carried in a version 0 PSBT.
//!
//! Everything is built on the group operations `bitcoin::secp256k1`
//! already exposes. Points at infinity cannot be represented by
//! [`PublicKey`](bitcoin::secp256k1::PublicKey), so functions whose BIP
//! reference would produce one return `None` or an error instead.

pub mod bip352;
pub mod carriage;
pub mod dleq;

use bitcoin::hashes::{sha256, Hash, HashEngine};

/// BIP 340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// The secp256k1 group order, big-endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Interpret 32 big-endian bytes as an integer and reduce it modulo the
/// group order. Any 256-bit value is below twice the order, so at most
/// one subtraction is needed.
fn reduce_mod_order(bytes: [u8; 32]) -> [u8; 32] {
    if bytes < ORDER {
        return bytes;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut diff = i16::from(bytes[i]) - i16::from(ORDER[i]) - borrow;
        borrow = 0;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        }
        out[i] = diff as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_wraps_values_at_or_above_the_order() {
        assert_eq!(reduce_mod_order([0u8; 32]), [0u8; 32]);
        assert_eq!(reduce_mod_order(ORDER), [0u8; 32]);
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut order_plus_one = ORDER;
        order_plus_one[31] += 1;
        assert_eq!(reduce_mod_order(order_plus_one), one);

        let mut below = ORDER;
        below[31] -= 1;
        assert_eq!(reduce_mod_order(below), below);

        // 2^256 - 1 - n = 0x14551231950b75fc4402da1732fc9bebe
        let mut expected = [0u8; 32];
        expected[15..].copy_from_slice(&[
            0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x73, 0x2f,
            0xc9, 0xbe, 0xbe,
        ]);
        assert_eq!(reduce_mod_order([0xff; 32]), expected);
    }
}
