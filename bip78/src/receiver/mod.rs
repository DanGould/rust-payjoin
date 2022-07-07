use bitcoin::{Script, TxOut, AddressType, util::psbt::PartiallySignedTransaction as Psbt};
use std::marker::PhantomData;

mod error;

pub use error::RequestError;
use error::InternalRequestError;

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

mod sealed {
    pub trait CheckState {}

}
pub enum Checked {}
pub enum Unchecked {}
impl sealed::CheckState for Checked {}
impl sealed::CheckState for Unchecked {}
pub trait CheckState: sealed::CheckState {}

impl<T: sealed::CheckState> CheckState for T {}


pub struct UncheckedProposal<
    MaybeUnbroadcastable: CheckState,
    MaybeInputsOwned: CheckState,
    MaybeScriptsSupported: CheckState,
    MaybePrevoutsSeen: CheckState,
> {
    psbt: Psbt,
    _phantom: PhantomData<(MaybeUnbroadcastable, MaybeInputsOwned, MaybeScriptsSupported, MaybePrevoutsSeen)>
}

// Completely Unchecked
impl UncheckedProposal<Unchecked, Unchecked, Unchecked, Unchecked> {
    pub fn from_request(body: impl std::io::Read, query: &str, headers: impl Headers) -> Result<Self, RequestError> {
        use crate::bitcoin::consensus::Decodable;

        let content_type = headers.get_header("content-type").ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
        if content_type != "text/plain" {
            return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
        }
        let content_length = headers
            .get_header("content-length")
            .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
            .parse::<u64>()
            .map_err(InternalRequestError::InvalidContentLength)?;
        // 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
        if content_length > 4_000_000 * 4 / 3 {
            return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
        }

        // enforce the limit
        let mut limited = body.take(content_length);
        let reader = base64::read::DecoderReader::new(&mut limited, base64::STANDARD);
        let psbt = Psbt::consensus_decode(reader).map_err(InternalRequestError::Decode)?;

        Ok(UncheckedProposal {
            psbt,
            _phantom: PhantomData,
        })
    }
}

/// MaybeUnBroadcastible
impl<C1: CheckState, C2: CheckState, C3: CheckState> UncheckedProposal<Unchecked, C1, C2, C3> {
    /// The Sender's Original PSBT
    pub fn get_transaction_to_check_broadcast(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx()
    }

    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `get_transaction_to_check_broadcast()` before calling this method.
    ///
    /// Check this if you generate bitcoin uri to receive PayJoin on sender request without manual human approval, like a payment processor.
    /// Such so called "interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn attest_tested_and_scheduled_broadcast(self) -> UncheckedProposal<Checked, C1, C2, C3> {
        UncheckedProposal {
            psbt: self.psbt,
            _phantom: PhantomData,
        }
    }

    /// Call this method if the only way to initiate a PayJoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `get_transaction_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn attest_manual_receive_endpoint(self) -> UncheckedProposal<Checked, C1, C2, C3> {
        UncheckedProposal {
            psbt: self.psbt,
            _phantom: PhantomData,
        }
    }
}

/// MaybeInputsOwned
impl<C0: CheckState, C2: CheckState, C3: CheckState> UncheckedProposal<C0, Unchecked, C2, C3> {
    /// The receiver should not be able to sign for any of the Original PSBT's inputs.
    /// Check that none of them are owned by the receiver downstream before proceeding.
    pub fn input_script_pubkeys(&self) -> Vec<Result<&Script, RequestError>> {
        todo!();
    }

    /// If the sender included inputs that the receiver could sign for in the original PSBT,
    /// the receiver must either return error original-psbt-rejected or make sure they do not sign those inputs in the payjoin proposal.
    ///
    /// Call this after checking downstream.
    pub fn attest_inputs_not_owned(self) -> UncheckedProposal<C0, Checked, C2, C3> {
        UncheckedProposal {
            psbt: self.psbt,
            _phantom: PhantomData,
        }
    }
}

/// MaybeScriptsSupported
impl<C0: CheckState, C1: CheckState, C3: CheckState> UncheckedProposal<C0, C1, Unchecked, C3> {
    pub fn input_script_types(&self, network: bitcoin::Network) -> Vec<Option<AddressType>> {
        todo!();
    }

    /// If the sender's inputs are all from the same scriptPubKey type, the receiver must match the same type.
    /// If the receiver can't match the type, they must return error unavailable.
    ///
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends are not necessarily indicative of distinct wallet fingerprints but they can be.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn attest_scripts_are_supported(self) -> UncheckedProposal<C0, C1, Checked, C3> {
        UncheckedProposal {
            psbt: self.psbt,
            _phantom: PhantomData,
        }
    }
}

/// MaybePrevoutsSeen
impl<C0: CheckState, C1: CheckState, C2: CheckState> UncheckedProposal<C0, C1, C2, Unchecked> {
    pub fn prevouts(&self) -> Vec<Result<&TxOut, RequestError>> {
        todo!();
    }

    /// Make sure that the inputs included in the original transaction have never been seen before.
    /// - This prevents probing attacks.
    /// - This prevent reentrant payjoin, where a sender attempts to use payjoin transaction as a new original transaction for a new payjoin.
    ///
    /// Call this after checking downstream.
    pub fn attest_no_prevouts_seen_before(self) -> UncheckedProposal<C0, C1, C2, Checked> {
        UncheckedProposal {
            psbt: self.psbt,
            _phantom: PhantomData,
        }
    }
}

impl UncheckedProposal<Checked, Checked, Checked, Checked> {
    /// Once all the checks are done the proposal can be unlocked for coin selection
    pub fn unlock(self) -> UnlockedProposal {
        UnlockedProposal { psbt: self.psbt }
    }
}

pub struct UnlockedProposal {
    psbt: Psbt,
}

impl UnlockedProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item=&bitcoin::OutPoint> {
        self.psbt.global.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn assume_locked(self) -> Proposal {
        Proposal {
            psbt: self.psbt,
        }
    }
}

/// Transaction that must be broadcasted.
#[must_use = "The transaction must be broadcasted to prevent abuse"]
pub struct MustBroadcast(pub bitcoin::Transaction);

pub struct Proposal {
    psbt: Psbt,
}

/*
impl Proposal {
    pub fn replace_output_script(&mut self, new_output_script: Script, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn replace_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn insert_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn expected_missing_fee_for_replaced_output(&self, output_type: OutputType) -> bitcoin::Amount {
    }
}
*/

pub struct ReceiverOptions {
    dust_limit: bitcoin::Amount,
}

pub enum BumpFeePolicy {
    FailOnInsufficient,
    SubtractOurFeeOutput,
}

pub struct NewOutputOptions {
    set_as_fee_output: bool,
    subtract_fees_from_this: bool,
}

mod test {
    use super::*;

    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        #[cfg(test)]
        fn new(length: u64) -> MockHeaders {
            MockHeaders { length: length.to_string() }
        }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    #[cfg(test)]
    fn get_proposal_from_test_vector() -> Result<UncheckedProposal<Unchecked, Unchecked, Unchecked, Unchecked>, RequestError> {

        // OriginalPSBT Test Vector from BIP
        // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
        // |-----------------|-----------------------|------------------------------|-------------------------|
        // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
        let original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        let body = original_psbt.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        UncheckedProposal::from_request(body, "", headers)
    }

    #[test]
    fn can_get_proposal_from_request() {
        let proposal = get_proposal_from_test_vector();
        assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        let proposal = get_proposal_from_test_vector().unwrap();
        let unlocked = proposal
            .attest_tested_and_scheduled_broadcast()
            .attest_inputs_not_owned()
            .attest_scripts_are_supported()
            .attest_no_prevouts_seen_before()
            .unlock();
    }
}