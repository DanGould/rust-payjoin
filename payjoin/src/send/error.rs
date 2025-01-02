use std::fmt;

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug)]
pub struct BuildSenderError(InternalBuildSenderError);

#[derive(Debug)]
pub(crate) enum InternalBuildSenderError {
    InvalidOriginalInput(crate::psbt::PsbtInputsError),
    InconsistentOriginalPsbt(crate::psbt::InconsistentPsbt),
    NoInputs,
    PayeeValueNotEqual,
    NoOutputs,
    MultiplePayeeOutputs,
    MissingPayeeOutput,
    FeeOutputValueLowerThanFeeContribution,
    AmbiguousChangeOutput,
    ChangeIndexOutOfBounds,
    ChangeIndexPointsAtPayee,
    InputWeight(crate::psbt::InputWeightError),
    AddressType(crate::psbt::AddressTypeError),
}

impl From<InternalBuildSenderError> for BuildSenderError {
    fn from(value: InternalBuildSenderError) -> Self { BuildSenderError(value) }
}

impl From<crate::psbt::AddressTypeError> for BuildSenderError {
    fn from(value: crate::psbt::AddressTypeError) -> Self {
        BuildSenderError(InternalBuildSenderError::AddressType(value))
    }
}

impl fmt::Display for BuildSenderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalBuildSenderError::*;

        match &self.0 {
            InvalidOriginalInput(e) => write!(f, "an input in the original transaction is invalid: {:#?}", e),
            InconsistentOriginalPsbt(e) => write!(f, "the original transaction is inconsistent: {:#?}", e),
            NoInputs => write!(f, "the original transaction has no inputs"),
            PayeeValueNotEqual => write!(f, "the value in original transaction doesn't equal value requested in the payment link"),
            NoOutputs => write!(f, "the original transaction has no outputs"),
            MultiplePayeeOutputs => write!(f, "the original transaction has more than one output belonging to the payee"),
            MissingPayeeOutput => write!(f, "the output belonging to payee is missing from the original transaction"),
            FeeOutputValueLowerThanFeeContribution => write!(f, "the value of fee output is lower than maximum allowed contribution"),
            AmbiguousChangeOutput => write!(f, "can not determine which output is change because there's more than two outputs"),
            ChangeIndexOutOfBounds => write!(f, "fee output index is points out of bounds"),
            ChangeIndexPointsAtPayee => write!(f, "fee output index is points at output belonging to the payee"),
            AddressType(e) => write!(f, "can not determine input address type: {}", e),
            InputWeight(e) => write!(f, "can not determine expected input weight: {}", e),
        }
    }
}

impl std::error::Error for BuildSenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalBuildSenderError::*;

        match &self.0 {
            InvalidOriginalInput(error) => Some(error),
            InconsistentOriginalPsbt(error) => Some(error),
            NoInputs => None,
            PayeeValueNotEqual => None,
            NoOutputs => None,
            MultiplePayeeOutputs => None,
            MissingPayeeOutput => None,
            FeeOutputValueLowerThanFeeContribution => None,
            AmbiguousChangeOutput => None,
            ChangeIndexOutOfBounds => None,
            ChangeIndexPointsAtPayee => None,
            AddressType(error) => Some(error),
            InputWeight(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WellKnownError {
    Unavailable(String),
    NotEnoughMoney(String),
    VersionUnsupported { message: String, supported: Vec<u64> },
    OriginalPsbtRejected(String),
}

impl WellKnownError {
    pub fn error_code(&self) -> &str {
        match self {
            WellKnownError::Unavailable(_) => "unavailable",
            WellKnownError::NotEnoughMoney(_) => "not-enough-money",
            WellKnownError::VersionUnsupported { .. } => "version-unsupported",
            WellKnownError::OriginalPsbtRejected(_) => "original-psbt-rejected",
        }
    }
    pub fn message(&self) -> &str {
        match self {
            WellKnownError::Unavailable(m) => m,
            WellKnownError::NotEnoughMoney(m) => m,
            WellKnownError::VersionUnsupported { message: m, .. } => m,
            WellKnownError::OriginalPsbtRejected(m) => m,
        }
    }
}

impl fmt::Display for WellKnownError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unavailable(_) => write!(f, "The payjoin endpoint is not available for now."),
            Self::NotEnoughMoney(_) => write!(f, "The receiver added some inputs but could not bump the fee of the payjoin proposal."),
            Self::VersionUnsupported { supported: v, .. }=> write!(f, "This version of payjoin is not supported. Use version {:?}.", v),
            Self::OriginalPsbtRejected(_) => write!(f, "The receiver rejected the original PSBT."),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoind::bitcoincore_rpc::jsonrpc::serde_json::json;

    #[test]
    fn test_parse_json() {
        let known_str_error = r#"{"errorCode":"version-unsupported", "message":"custom message here", "supported": [1, 2]}"#;
        match crate::send::v1::ResponseError::parse(known_str_error) {
            crate::send::v1::ResponseError::WellKnown(e) => {
                assert_eq!(e.error_code(), "version-unsupported");
                assert_eq!(e.message(), "custom message here");
                assert_eq!(
                    e.to_string(),
                    "This version of payjoin is not supported. Use version [1, 2]."
                );
            }
            _ => panic!("Expected WellKnown error"),
        };
        let unrecognized_error = r#"{"errorCode":"random", "message":"random"}"#;
        assert_eq!(
            crate::send::v1::ResponseError::parse(unrecognized_error).to_string(),
            "The receiver sent an unrecognized error."
        );
        let invalid_json_error = json!({
            "err": "random",
            "message": "This version of payjoin is not supported."
        });
        assert_eq!(
            crate::send::v1::ResponseError::from_json(invalid_json_error).to_string(),
            "The receiver sent an invalid response."
        );
    }
}
