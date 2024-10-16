use std::error;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum Error {
    /// To be returned as HTTP 400
    BadRequest(RequestError),
    // To be returned as HTTP 500
    Server(Box<dyn error::Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::BadRequest(e) => e.fmt(f),
            Self::Server(e) => write!(f, "Internal Server Error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::BadRequest(_) => None,
            Self::Server(e) => Some(e.as_ref()),
        }
    }
}

impl From<RequestError> for Error {
    fn from(e: RequestError) -> Self { Error::BadRequest(e) }
}

/// Error that may occur when the request from sender is malformed.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct RequestError(InternalRequestError);

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    Psbt(bitcoin::psbt::Error),
    Base64(bitcoin::base64::DecodeError),
    Io(std::io::Error),
    MissingHeader(&'static str),
    InvalidContentType(String),
    InvalidContentLength(std::num::ParseIntError),
    ContentLengthTooLarge(u64),
    SenderParams(super::optional_parameters::Error),
    /// The raw PSBT fails bip78-specific validation.
    InconsistentPsbt(crate::psbt::InconsistentPsbt),
    /// The prevtxout is missing
    PrevTxOut(crate::psbt::PrevTxOutError),
    /// The Original PSBT has no output for the receiver.
    MissingPayment,
    /// The original PSBT transaction fails the broadcast check
    OriginalPsbtNotBroadcastable,
    /// The sender is trying to spend the receiver input
    InputOwned(bitcoin::ScriptBuf),
    /// The original psbt has mixed input address types that could harm privacy
    MixedInputScripts(crate::input_type::InputType, crate::input_type::InputType),
    /// Unrecognized input type
    InputType(crate::input_type::InputTypeError),
    /// Original PSBT input has been seen before. Only automatic receivers, aka "interactive" in the spec
    /// look out for these to prevent probing attacks.
    InputSeen(bitcoin::OutPoint),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn write_error(f: &mut fmt::Formatter, code: &str, message: impl Display) -> fmt::Result {
            write!(f, r#"{{ "errorCode": "{}", "message": "{}" }}"#, code, message)
        }

        match &self.0 {
            InternalRequestError::Psbt(e) => write_error(f, "psbt-error", e),
            InternalRequestError::Base64(e) => write_error(f, "base64-decode-error", e),
            InternalRequestError::Io(e) => write_error(f, "io-error", e),
            InternalRequestError::MissingHeader(header) =>
                write_error(f, "missing-header", &format!("Missing header: {}", header)),
            InternalRequestError::InvalidContentType(content_type) => write_error(
                f,
                "invalid-content-type",
                &format!("Invalid content type: {}", content_type),
            ),
            InternalRequestError::InvalidContentLength(e) =>
                write_error(f, "invalid-content-length", e),
            InternalRequestError::ContentLengthTooLarge(length) => write_error(
                f,
                "content-length-too-large",
                &format!("Content length too large: {}.", length),
            ),
            InternalRequestError::SenderParams(e) => match e {
                super::optional_parameters::Error::UnknownVersion => write_error(
                    f,
                    "version-unsupported",
                    "This version of payjoin is not supported.",
                ),
                _ => write_error(f, "sender-params-error", e),
            },
            InternalRequestError::InconsistentPsbt(e) =>
                write_error(f, "original-psbt-rejected", e),
            InternalRequestError::PrevTxOut(e) =>
                write_error(f, "original-psbt-rejected", &format!("PrevTxOut Error: {}", e)),
            InternalRequestError::MissingPayment =>
                write_error(f, "original-psbt-rejected", "Missing payment."),
            InternalRequestError::OriginalPsbtNotBroadcastable => write_error(
                f,
                "original-psbt-rejected",
                "Can't broadcast. PSBT rejected by mempool.",
            ),
            InternalRequestError::InputOwned(_) =>
                write_error(f, "original-psbt-rejected", "The receiver rejected the original PSBT."),
            InternalRequestError::MixedInputScripts(type_a, type_b) => write_error(
                f,
                "original-psbt-rejected",
                &format!("Mixed input scripts: {}; {}.", type_a, type_b),
            ),
            InternalRequestError::InputType(e) =>
                write_error(f, "original-psbt-rejected", &format!("Input Type Error: {}.", e)),
            InternalRequestError::InputSeen(_) =>
                write_error(f, "original-psbt-rejected", "The receiver rejected the original PSBT."),
        }
    }
}

/// Error that may occur when coin selection fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct SelectionError(InternalSelectionError);

#[derive(Debug)]
pub(crate) enum InternalSelectionError {
    /// No candidates available for selection
    Empty,
    /// Current privacy selection implementation only supports 2-output transactions
    TooManyOutputs,
    /// No selection candidates improve privacy
    NotFound,
}

impl From<InternalSelectionError> for SelectionError {
    fn from(value: InternalSelectionError) -> Self { SelectionError(value) }
}
