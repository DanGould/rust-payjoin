use core::fmt;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{AddressType, Sequence};

use crate::send::error::WellKnownError;

/// Error that may occur when the response from receiver is malformed.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct ValidationError {
    internal: InternalValidationError,
}

#[derive(Debug)]
pub(crate) enum InternalValidationError {
    Parse,
    Io(std::io::Error),
    InvalidAddressType(crate::psbt::AddressTypeError),
    NoInputs,
    PrevTxOut(crate::psbt::PrevTxOutError),
    InputWeight(crate::psbt::InputWeightError),
    VersionsDontMatch { proposed: Version, original: Version },
    LockTimesDontMatch { proposed: LockTime, original: LockTime },
    SenderTxinSequenceChanged { proposed: Sequence, original: Sequence },
    SenderTxinContainsNonWitnessUtxo,
    SenderTxinContainsWitnessUtxo,
    SenderTxinContainsFinalScriptSig,
    SenderTxinContainsFinalScriptWitness,
    TxInContainsKeyPaths,
    ContainsPartialSigs,
    ReceiverTxinNotFinalized,
    ReceiverTxinMissingUtxoInfo,
    MixedSequence,
    MixedInputTypes { proposed: AddressType, original: AddressType },
    MissingOrShuffledInputs,
    TxOutContainsKeyPaths,
    FeeContributionExceedsMaximum,
    DisallowedOutputSubstitution,
    OutputValueDecreased,
    MissingOrShuffledOutputs,
    AbsoluteFeeDecreased,
    PayeeTookContributedFee,
    FeeContributionPaysOutputSizeIncrease,
    FeeRateBelowMinimum,
    Psbt(bitcoin::psbt::Error),
}

impl From<InternalValidationError> for ValidationError {
    fn from(value: InternalValidationError) -> Self { ValidationError { internal: value } }
}

impl From<crate::psbt::AddressTypeError> for InternalValidationError {
    fn from(value: crate::psbt::AddressTypeError) -> Self {
        InternalValidationError::InvalidAddressType(value)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.internal) }
}

impl fmt::Display for InternalValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalValidationError::*;

        match &self {
            Parse => write!(f, "couldn't decode as PSBT or JSON",),
            Io(e) => write!(f, "couldn't read PSBT: {}", e),
            InvalidAddressType(e) => write!(f, "invalid input address type: {}", e),
            NoInputs => write!(f, "PSBT doesn't have any inputs"),
            PrevTxOut(e) => write!(f, "missing previous txout information: {}", e),
            InputWeight(e) => write!(f, "can not determine expected input weight: {}", e),
            VersionsDontMatch { proposed, original, } => write!(f, "proposed transaction version {} doesn't match the original {}", proposed, original),
            LockTimesDontMatch { proposed, original, } => write!(f, "proposed transaction lock time {} doesn't match the original {}", proposed, original),
            SenderTxinSequenceChanged { proposed, original, } => write!(f, "proposed transaction sequence number {} doesn't match the original {}", proposed, original),
            SenderTxinContainsNonWitnessUtxo => write!(f, "an input in proposed transaction belonging to the sender contains non-witness UTXO information"),
            SenderTxinContainsWitnessUtxo => write!(f, "an input in proposed transaction belonging to the sender contains witness UTXO information"),
            SenderTxinContainsFinalScriptSig => write!(f, "an input in proposed transaction belonging to the sender contains finalized non-witness signature"),
            SenderTxinContainsFinalScriptWitness => write!(f, "an input in proposed transaction belonging to the sender contains finalized witness signature"),
            TxInContainsKeyPaths => write!(f, "proposed transaction inputs contain key paths"),
            ContainsPartialSigs => write!(f, "an input in proposed transaction belonging to the sender contains partial signatures"),
            ReceiverTxinNotFinalized => write!(f, "an input in proposed transaction belonging to the receiver is not finalized"),
            ReceiverTxinMissingUtxoInfo => write!(f, "an input in proposed transaction belonging to the receiver is missing UTXO information"),
            MixedSequence => write!(f, "inputs of proposed transaction contain mixed sequence numbers"),
            MixedInputTypes { proposed, original, } => write!(f, "proposed transaction contains input of type {:?} while original contains inputs of type {:?}", proposed, original),
            MissingOrShuffledInputs => write!(f, "proposed transaction is missing inputs of the sender or they are shuffled"),
            TxOutContainsKeyPaths => write!(f, "proposed transaction outputs contain key paths"),
            FeeContributionExceedsMaximum => write!(f, "fee contribution exceeds allowed maximum"),
            DisallowedOutputSubstitution => write!(f, "the receiver change output despite it being disallowed"),
            OutputValueDecreased => write!(f, "the amount in our non-fee output was decreased"),
            MissingOrShuffledOutputs => write!(f, "proposed transaction is missing outputs of the sender or they are shuffled"),
            AbsoluteFeeDecreased => write!(f, "abslute fee of proposed transaction is lower than original"),
            PayeeTookContributedFee => write!(f, "payee tried to take fee contribution for himself"),
            FeeContributionPaysOutputSizeIncrease => write!(f, "fee contribution pays for additional outputs"),
            FeeRateBelowMinimum =>  write!(f, "the fee rate of proposed transaction is below minimum"),
            Psbt(e) => write!(f, "psbt error: {}", e),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.internal) }
}

impl std::error::Error for InternalValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalValidationError::*;

        match &self {
            Parse => None,
            Io(error) => Some(error),
            InvalidAddressType(error) => Some(error),
            NoInputs => None,
            PrevTxOut(error) => Some(error),
            InputWeight(error) => Some(error),
            VersionsDontMatch { proposed: _, original: _ } => None,
            LockTimesDontMatch { proposed: _, original: _ } => None,
            SenderTxinSequenceChanged { proposed: _, original: _ } => None,
            SenderTxinContainsNonWitnessUtxo => None,
            SenderTxinContainsWitnessUtxo => None,
            SenderTxinContainsFinalScriptSig => None,
            SenderTxinContainsFinalScriptWitness => None,
            TxInContainsKeyPaths => None,
            ContainsPartialSigs => None,
            ReceiverTxinNotFinalized => None,
            ReceiverTxinMissingUtxoInfo => None,
            MixedSequence => None,
            MixedInputTypes { .. } => None,
            MissingOrShuffledInputs => None,
            TxOutContainsKeyPaths => None,
            FeeContributionExceedsMaximum => None,
            DisallowedOutputSubstitution => None,
            OutputValueDecreased => None,
            MissingOrShuffledOutputs => None,
            AbsoluteFeeDecreased => None,
            PayeeTookContributedFee => None,
            FeeContributionPaysOutputSizeIncrease => None,
            FeeRateBelowMinimum => None,
            Psbt(error) => Some(error),
        }
    }
}

/// Represent an error returned by Payjoin receiver.
pub enum ResponseError {
    /// `WellKnown` Errors are defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is safe to display `WellKnown` errors to end users.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    WellKnown(WellKnownError),
    /// `Unrecognized` Errors are NOT defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// Its not safe to display `Unrecognized` errors to end users as they could be used
    /// maliciously to phish a non technical user. Only display them in debug logs.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    Unrecognized { error_code: String, message: String },
    /// Errors caused by malformed responses.
    ///
    /// These errors are only displayed in debug logs.
    Validation(ValidationError),
}

impl ResponseError {
    pub(crate) fn from_json(json: serde_json::Value) -> Self {
        // we try to find the errorCode field and
        // if it exists we try to parse it as a well known error
        // if its an unknown error we return the error code and message
        // from original response
        // if errorCode field doesn't exist we return parse error
        let message = json
            .as_object()
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if let Some(error_code) =
            json.as_object().and_then(|v| v.get("errorCode")).and_then(|v| v.as_str())
        {
            match error_code {
                "version-unsupported" => {
                    let supported = json
                        .as_object()
                        .and_then(|v| v.get("supported"))
                        .and_then(|v| v.as_array())
                        .map(|array| array.iter().filter_map(|v| v.as_u64()).collect::<Vec<u64>>())
                        .unwrap_or_default();
                    WellKnownError::VersionUnsupported { message, supported }.into()
                }
                "unavailable" => WellKnownError::Unavailable(message).into(),
                "not-enough-money" => WellKnownError::NotEnoughMoney(message).into(),
                "original-psbt-rejected" => WellKnownError::OriginalPsbtRejected(message).into(),
                _ => Self::Unrecognized { error_code: error_code.to_string(), message },
            }
        } else {
            InternalValidationError::Parse.into()
        }
    }

    /// Parse a response from the receiver.
    ///
    /// response must be valid JSON string.
    pub fn parse(response: &str) -> Self {
        match serde_json::from_str(response) {
            Ok(json) => Self::from_json(json),
            Err(_) => InternalValidationError::Parse.into(),
        }
    }
}

impl std::error::Error for ResponseError {}

impl From<WellKnownError> for ResponseError {
    fn from(value: WellKnownError) -> Self { Self::WellKnown(value) }
}

impl From<InternalValidationError> for ResponseError {
    fn from(value: InternalValidationError) -> Self {
        Self::Validation(ValidationError { internal: value })
    }
}

// It is imperative to carefully display pre-defined messages to end users and the details in debug.
impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WellKnown(e) => e.fmt(f),
            // Don't display unknowns to end users, only debug logs
            Self::Unrecognized { .. } => write!(f, "The receiver sent an unrecognized error."),
            Self::Validation(_) => write!(f, "The receiver sent an invalid response."),
        }
    }
}

impl fmt::Debug for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WellKnown(e) => write!(
                f,
                r#"Well known error: {{ "errorCode": "{}",
                "message": "{}" }}"#,
                e.error_code(),
                e.message()
            ),
            Self::Unrecognized { error_code, message } => write!(
                f,
                r#"Unrecognized error: {{ "errorCode": "{}", "message": "{}" }}"#,
                error_code, message
            ),
            Self::Validation(e) => write!(f, "Validation({:?})", e),
        }
    }
}
