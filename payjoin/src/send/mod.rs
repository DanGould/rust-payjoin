//! Send Payjoin
//!
//! This module contains types and methods used to implement sending via Payjoin.
//!
//! For most use cases, it is recommended to start with the [`v2`] module, as it is
//! backwards compatible and provides the latest features. If you specifically need to use
//! version 1, refer to the [`v1`] module documentation.

use std::str::FromStr;

use bitcoin::{Amount, FeeRate, Script, TxOut};
pub use error::BuildSenderError;
pub(crate) use error::InternalBuildSenderError;
use url::Url;

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

fn serialize_url(
    endpoint: Url,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    version: &str,
) -> Result<Url, url::ParseError> {
    let mut url = endpoint;
    url.query_pairs_mut().append_pair("v", version);
    if disable_output_substitution {
        url.query_pairs_mut().append_pair("disableoutputsubstitution", "1");
    }
    if let Some((amount, index)) = fee_contribution {
        url.query_pairs_mut()
            .append_pair("additionalfeeoutputindex", &index.to_string())
            .append_pair("maxadditionalfeecontribution", &amount.to_sat().to_string());
    }
    if min_fee_rate > FeeRate::ZERO {
        // TODO serialize in rust-bitcoin <https://github.com/rust-bitcoin/rust-bitcoin/pull/1787/files#diff-c2ea40075e93ccd068673873166cfa3312ec7439d6bc5a4cbc03e972c7e045c4>
        let float_fee_rate = min_fee_rate.to_sat_per_kwu() as f32 / 250.0_f32;
        url.query_pairs_mut().append_pair("minfeerate", &float_fee_rate.to_string());
    }
    Ok(url)
}

#[cfg(test)]
pub(crate) mod test {
    use std::str::FromStr;

    use bitcoin::psbt::Psbt;
    use bitcoin::FeeRate;

    use crate::psbt::PsbtExt;
    use crate::send::error::WellKnownError;
    use crate::send::v1::ResponseError;

    pub(crate) const ORIGINAL_PSBT: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
    const PAYJOIN_PROPOSAL: &str = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcBBBYAFMeKRXJTVYKNVlgHTdUmDV/LaYUwIgYDFZrAGqDVh1TEtNi300ntHt/PCzYrT2tVEGcjooWPhRYYSFzWUDEAAIABAACAAAAAgAEAAAAAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUIgICygvBWB5prpfx61y1HDAwo37kYP3YRJBvAjtunBAur3wYSFzWUDEAAIABAACAAAAAgAEAAAABAAAAAAA=";

    fn create_v1_context() -> super::v1::PsbtContext {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        super::v1::PsbtContext {
            original_psbt,
            disable_output_substitution: false,
            fee_contribution: Some((bitcoin::Amount::from_sat(182), 0)),
            min_fee_rate: FeeRate::ZERO,
            payee,
            allow_mixed_input_scripts: false,
        }
    }

    #[test]
    fn official_vectors() {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let ctx = create_v1_context();
        let mut proposal = Psbt::from_str(PAYJOIN_PROPOSAL).unwrap();
        eprintln!("proposal: {:#?}", proposal);
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        ctx.process_proposal(proposal).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_receiver_steals_sender_change() {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let ctx = create_v1_context();
        let mut proposal = Psbt::from_str(PAYJOIN_PROPOSAL).unwrap();
        eprintln!("proposal: {:#?}", proposal);
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        // Steal 0.5 BTC from the sender output and add it to the receiver output
        proposal.unsigned_tx.output[0].value -= bitcoin::Amount::from_btc(0.5).unwrap();
        proposal.unsigned_tx.output[1].value += bitcoin::Amount::from_btc(0.5).unwrap();
        ctx.process_proposal(proposal).unwrap();
    }

    #[test]
    fn handle_json_errors() {
        let ctx = create_v1_context();
        let known_json_error = serde_json::json!({
            "errorCode": "version-unsupported",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut known_json_error.as_bytes()) {
            Err(ResponseError::WellKnown(WellKnownError::VersionUnsupported { .. })) => (),
            _ => panic!("Expected WellKnownError"),
        }

        let ctx = create_v1_context();
        let invalid_json_error = serde_json::json!({
            "err": "random",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut invalid_json_error.as_bytes()) {
            Err(ResponseError::Validation(_)) => (),
            _ => panic!("Expected unrecognized JSON error"),
        }
    }
}
