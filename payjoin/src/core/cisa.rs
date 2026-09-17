//! PSBT fields for cross-input signature aggregation.
//!
//! BIP 460 lets the key path spends of witness version 2 inputs share one
//! signature. The PSBT carries the per-input signing material in the fields of
//! the draft "CISA Fields for PSBT" (Fabian Jahr), all per-input with no key
//! data:
//!
//! | type | name | value |
//! |------|------|-------|
//! | 0x21 | `PSBT_IN_CISA_MODE` | one byte: 0x00 opted out, 0xbc half, 0xbd full |
//! | 0x22 | `PSBT_IN_CISA_HALFAGG_SIG` | 64 or 65 bytes |
//! | 0x23 | `PSBT_IN_CISA_FULLAGG_PUB_NONCE` | 66 bytes |
//! | 0x24 | `PSBT_IN_CISA_FULLAGG_PARTIAL_SIG` | 32 bytes |
//!
//! Payjoin has to let these fields pass between the parties where it would
//! otherwise strip unknown fields, and it has to accept a full-aggregation
//! input that carries its partial signature as complete even though it is not
//! finalized: the group's final witnesses can only be built once every partial
//! signature exists, which for a two-party payjoin happens at the sender.
//!
//! The field numbers are a draft and may change before the BIP is merged.
//! Every use in this crate goes through this module so that such a change is
//! one edit.

use std::collections::BTreeMap;

use bitcoin::psbt::raw;
use bitcoin::{psbt, Script};

/// The input's aggregation mode, one byte.
pub const PSBT_IN_CISA_MODE: u8 = 0x21;
/// The input's BIP 340 signature for half aggregation, 64 or 65 bytes.
pub const PSBT_IN_CISA_HALFAGG_SIG: u8 = 0x22;
/// The input's BIP 459 public nonce, 66 bytes.
pub const PSBT_IN_CISA_FULLAGG_PUB_NONCE: u8 = 0x23;
/// The input's BIP 459 partial signature, 32 bytes.
pub const PSBT_IN_CISA_FULLAGG_PARTIAL_SIG: u8 = 0x24;

/// The BIP 460 marker byte of the half-aggregation group.
pub const MODE_HALFAGG: u8 = 0xbc;
/// The BIP 460 marker byte of the full-aggregation group.
pub const MODE_FULLAGG: u8 = 0xbd;

/// Length of a BIP 459 public nonce.
pub const PUB_NONCE_LEN: usize = 66;
/// Length of a BIP 459 partial signature.
pub const PARTIAL_SIG_LEN: usize = 32;

/// Length of the witness element of a full-aggregation group's final input with
/// `SIGHASH_DEFAULT`: the 64-byte aggregate signature and the marker byte.
pub const FULLAGG_FINAL_WITNESS_LEN: usize = 65;

fn key(type_value: u8) -> raw::Key { raw::Key { type_value, key: vec![] } }

/// Whether `key` is one of the per-input CISA types.
pub fn is_cisa_key(key: &raw::Key) -> bool {
    key.key.is_empty()
        && matches!(
            key.type_value,
            PSBT_IN_CISA_MODE
                | PSBT_IN_CISA_HALFAGG_SIG
                | PSBT_IN_CISA_FULLAGG_PUB_NONCE
                | PSBT_IN_CISA_FULLAGG_PARTIAL_SIG
        )
}

/// Whether `script` is a witness version 2 output with a 32-byte program, the
/// only output type whose key path spends BIP 460 aggregates.
pub fn is_witness_v2_keypath(script: &Script) -> bool {
    script.witness_version() == Some(bitcoin::WitnessVersion::V2) && script.len() == 34
}

fn field(input: &psbt::Input, type_value: u8, len: impl Fn(usize) -> bool) -> Option<&[u8]> {
    input.unknown.get(&key(type_value)).map(Vec::as_slice).filter(|value| len(value.len()))
}

/// The input's aggregation mode, if it carries a well-formed one.
pub fn mode(input: &psbt::Input) -> Option<u8> {
    field(input, PSBT_IN_CISA_MODE, |len| len == 1).map(|value| value[0])
}

/// The input's BIP 459 public nonce, if it carries a well-formed one.
pub fn fullagg_pub_nonce(input: &psbt::Input) -> Option<&[u8]> {
    field(input, PSBT_IN_CISA_FULLAGG_PUB_NONCE, |len| len == PUB_NONCE_LEN)
}

/// The input's BIP 459 partial signature, if it carries a well-formed one.
pub fn fullagg_partial_sig(input: &psbt::Input) -> Option<&[u8]> {
    field(input, PSBT_IN_CISA_FULLAGG_PARTIAL_SIG, |len| len == PARTIAL_SIG_LEN)
}

/// Whether the input is a member of the full-aggregation group.
pub fn is_fullagg(input: &psbt::Input) -> bool { mode(input) == Some(MODE_FULLAGG) }

/// Whether the input is a full-aggregation member that has signed.
///
/// The draft calls such an input complete. It cannot be finalized on its own,
/// since the group's final witnesses need every partial signature of the
/// group, so a signer that is not the last one hands it on in this state.
pub fn is_complete_fullagg(input: &psbt::Input) -> bool {
    is_fullagg(input) && fullagg_pub_nonce(input).is_some() && fullagg_partial_sig(input).is_some()
}

/// Mark the input as a full-aggregation member with the given public nonce.
///
/// This is the Updater and first Signer step of the draft in one: the mode may
/// not be set once a nonce is present, so the two always travel together.
pub fn set_fullagg(input: &mut psbt::Input, pub_nonce: [u8; PUB_NONCE_LEN]) {
    input.unknown.insert(key(PSBT_IN_CISA_MODE), vec![MODE_FULLAGG]);
    input.unknown.insert(key(PSBT_IN_CISA_FULLAGG_PUB_NONCE), pub_nonce.to_vec());
}

/// The CISA fields of the input, and nothing else.
pub fn fields(input: &psbt::Input) -> BTreeMap<raw::Key, Vec<u8>> {
    input
        .unknown
        .iter()
        .filter(|(k, _)| is_cisa_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::str::FromStr;

    use bitcoin::Psbt;

    use super::*;

    /// "Full-aggregation group with an opted-out input", stage "With all
    /// partial signatures", from the draft's test vectors. Input 0 is opted
    /// out, inputs 1 and 2 form the group.
    pub(crate) const FULLAGG_ALL_PARTIAL_SIGS: &str = "cHNidP8BALACAAAAA+nzRWpGuA5nRR9a2aOVOW8ko6g5kJhibk/Zy7l1OO24AAAAAAD/////R0oakAQJxzEqoYcd2kuKP8nNOAURw3fcSPWanA4PhFUAAAAAAP////9BXNM/Ukj+1RJmHEZNT/03MwMidOUBLhfYNGBzvubgHwAAAAAA/////wGYiVsAAAAAACJSILcdHrklCEkS2CeS2r1H1rhOzI0O2b7wdt952VTvWsO4AAAAAAABAStAQg8AAAAAACJSIEGN91Ii2xfAlFJEsPOhEA1JR/rjpBrkEoiDDmkAuEbfARNADyU8j+VM3ovApzLqjJI9ET2FUdiaXTcUoppj0il7eyYIy2/wHnSHHZZkMSqMhaL4vbWzqj8WQB9CLnSOGxb6FwEXIN2GZvyc2hSouA3crraTMWyEL0QIp/r2+BJH0xhJOdscASEBAAABASuAhB4AAAAAACJSIPH6hmIAaHi8HpwOni1ZriCL+X8l/5JwtnBJY8iJoh3JARcg30rhHldf8ZwzCfrifEkAOaMJLGp32V78T2tcw1U+CX4BIQG9ASNCA+icZz5Nlqsag/4Xfa/5ZxyIB06iYYlXEKbnPu6HyHuGAla9XOQofq6BHXkuYwNVgEeqzKPGvyv1EORs0fZn4mszASQgGFXfPNHXcoGGpSUm6ZeWwq/jO232aht2n6UtHU2AeuYAAQErwMYtAAAAAAAiUiDfPMNFtjcuEuZheVWfK0CoY+y+g6/oFvDEFES7dEfhVwEDBAEAAAABFyCtRhTGtZbURd2+yCp7QRUX1j5p9UZgO/fPXisvRaCGQgEhAb0BI0ICbd3XQxwNFUpHuaih8x23Zzi71OJaF6r1x5zxMTNOSt8DzC0RaXHf4SOOTDZSnB/+f28PMvof+nCw/H9o8shDXr0BJCBzP/KQwv4rJm1qyhvjYjhqa93rmvnDW4qOcDACROQ+hAAA";

    /// The same case, stage "Finalized". Input 1 carries the empty member
    /// witness, input 2 the 65-byte final witness.
    pub(crate) const FULLAGG_FINALIZED: &str = "cHNidP8BALACAAAAA+nzRWpGuA5nRR9a2aOVOW8ko6g5kJhibk/Zy7l1OO24AAAAAAD/////R0oakAQJxzEqoYcd2kuKP8nNOAURw3fcSPWanA4PhFUAAAAAAP////9BXNM/Ukj+1RJmHEZNT/03MwMidOUBLhfYNGBzvubgHwAAAAAA/////wGYiVsAAAAAACJSILcdHrklCEkS2CeS2r1H1rhOzI0O2b7wdt952VTvWsO4AAAAAAABAStAQg8AAAAAACJSIEGN91Ii2xfAlFJEsPOhEA1JR/rjpBrkEoiDDmkAuEbfAQhCAUAPJTyP5Uzei8CnMuqMkj0RPYVR2JpdNxSimmPSKXt7JgjLb/AedIcdlmQxKoyFovi9tbOqPxZAH0IudI4bFvoXAAEBK4CEHgAAAAAAIlIg8fqGYgBoeLwenA6eLVmuIIv5fyX/knC2cEljyImiHckBCAIBAAABASvAxi0AAAAAACJSIN88w0W2Ny4S5mF5VZ8rQKhj7L6Dr+gW8MQURLt0R+FXAQhEAULyUMo9nDHJhyKoV77AMZMtii3DNKhZtnBVYKCWgzf74YuV0c2U1Z2n9A/vQsz5zy0bwScI8C13AS4VXR+SZLlqAb0AAA==";

    #[test]
    fn reads_draft_vector_fields() {
        let psbt = Psbt::from_str(FULLAGG_ALL_PARTIAL_SIGS).expect("vector parses");
        let [opted_out, member, last] = psbt.inputs.as_slice() else { panic!("three inputs") };
        for input in &psbt.inputs {
            let spk = &input.witness_utxo.as_ref().expect("witness utxo").script_pubkey;
            assert!(is_witness_v2_keypath(spk));
        }

        assert_eq!(mode(opted_out), Some(0x00));
        assert!(!is_fullagg(opted_out));
        assert!(!is_complete_fullagg(opted_out));
        assert!(fields(opted_out).contains_key(&key(PSBT_IN_CISA_MODE)));

        for input in [member, last] {
            assert!(is_fullagg(input));
            assert_eq!(fullagg_pub_nonce(input).map(<[u8]>::len), Some(PUB_NONCE_LEN));
            assert_eq!(fullagg_partial_sig(input).map(<[u8]>::len), Some(PARTIAL_SIG_LEN));
            assert!(is_complete_fullagg(input));
            assert_eq!(fields(input).len(), 3);
        }
    }

    #[test]
    fn set_fullagg_makes_an_incomplete_member() {
        let mut input = psbt::Input::default();
        input.unknown.insert(raw::Key { type_value: 0xfc, key: vec![1] }, vec![2]);
        set_fullagg(&mut input, [7; PUB_NONCE_LEN]);
        assert!(is_fullagg(&input));
        assert_eq!(fullagg_pub_nonce(&input), Some(&[7u8; PUB_NONCE_LEN][..]));
        assert!(!is_complete_fullagg(&input));
        assert_eq!(fields(&input).len(), 2, "foreign unknown keys are not CISA fields");
    }

    #[test]
    fn malformed_fields_are_ignored() {
        let mut input = psbt::Input::default();
        input.unknown.insert(key(PSBT_IN_CISA_MODE), vec![MODE_FULLAGG, 0]);
        input.unknown.insert(key(PSBT_IN_CISA_FULLAGG_PUB_NONCE), vec![0; PUB_NONCE_LEN - 1]);
        input.unknown.insert(key(PSBT_IN_CISA_FULLAGG_PARTIAL_SIG), vec![]);
        assert_eq!(mode(&input), None);
        assert_eq!(fullagg_pub_nonce(&input), None);
        assert_eq!(fullagg_partial_sig(&input), None);
        assert!(!is_fullagg(&input));
        assert!(!is_cisa_key(&raw::Key { type_value: PSBT_IN_CISA_MODE, key: vec![0] }));
    }
}
