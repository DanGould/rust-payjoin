use core::fmt;

use crate::send::error::WellKnownError;
use crate::send::v1;
use crate::uri::url_ext::ParseReceiverPubkeyParamError;

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
    Url(url::ParseError),
    Hpke(crate::hpke::HpkeError),
    OhttpEncapsulation(crate::ohttp::OhttpEncapsulationError),
    ParseReceiverPubkey(ParseReceiverPubkeyParamError),
    MissingOhttpConfig,
    Expired(std::time::SystemTime),
}

impl fmt::Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(e) => write!(f, "cannot parse url: {:#?}", e),
            Hpke(e) => write!(f, "v2 error: {}", e),
            OhttpEncapsulation(e) => write!(f, "v2 error: {}", e),
            ParseReceiverPubkey(e) => write!(f, "cannot parse receiver public key: {}", e),
            MissingOhttpConfig =>
                write!(f, "no ohttp configuration with which to make a v2 request available"),
            Expired(expiry) => write!(f, "session expired at {:?}", expiry),
        }
    }
}

impl std::error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(error) => Some(error),
            Hpke(error) => Some(error),
            OhttpEncapsulation(error) => Some(error),
            ParseReceiverPubkey(error) => Some(error),
            MissingOhttpConfig => None,
            Expired(_) => None,
        }
    }
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

impl From<ParseReceiverPubkeyParamError> for CreateRequestError {
    fn from(value: ParseReceiverPubkeyParamError) -> Self {
        CreateRequestError(InternalCreateRequestError::ParseReceiverPubkey(value))
    }
}

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
    V1(v1::InternalValidationError),
    Hpke(crate::hpke::HpkeError),
    OhttpEncapsulation(crate::ohttp::OhttpEncapsulationError),
    UnexpectedStatusCode,
    UnexpectedResponseSize(usize),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalValidationError::*;

        match &self.internal {
            V1(e) => write!(f, "{}", e),
            Hpke(e) => write!(f, "v2 error: {}", e),
            OhttpEncapsulation(e) => write!(f, "Ohttp encapsulation error: {}", e),
            UnexpectedStatusCode => write!(f, "unexpected status code"),
            UnexpectedResponseSize(size) => write!(
                f,
                "unexpected response size {}, expected {} bytes",
                size,
                crate::ohttp::ENCAPSULATED_MESSAGE_BYTES
            ),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalValidationError::*;

        match &self.internal {
            V1(e) => Some(e),
            Hpke(error) => Some(error),
            OhttpEncapsulation(error) => Some(error),
            UnexpectedStatusCode => None,
            UnexpectedResponseSize(_) => None,
        }
    }
}

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

impl From<InternalValidationError> for ResponseError {
    fn from(value: InternalValidationError) -> Self {
        ResponseError::Validation(ValidationError { internal: value })
    }
}

impl From<v1::InternalValidationError> for ResponseError {
    fn from(value: v1::InternalValidationError) -> Self {
        ResponseError::Validation(ValidationError { internal: InternalValidationError::V1(value) })
    }
}
