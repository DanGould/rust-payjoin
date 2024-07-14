use core::fmt;
use std::error;

use crate::v2::OhttpEncapsulationError;

#[derive(Debug)]
pub struct SessionError(InternalSessionError);

#[derive(Debug)]
pub(crate) enum InternalSessionError {
    /// The session has expired
    Expired(std::time::SystemTime),
    /// OHTTP Encapsulation failed
    OhttpEncapsulationError(OhttpEncapsulationError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalSessionError::Expired(expiry) => write!(f, "Session expired at {:?}", expiry),
            InternalSessionError::OhttpEncapsulationError(e) =>
                write!(f, "OHTTP Encapsulation Error: {}", e),
        }
    }
}

impl error::Error for SessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalSessionError::Expired(_) => None,
            InternalSessionError::OhttpEncapsulationError(e) => Some(e),
        }
    }
}

impl From<InternalSessionError> for SessionError {
    fn from(e: InternalSessionError) -> Self { SessionError(e) }
}

impl From<OhttpEncapsulationError> for SessionError {
    fn from(e: OhttpEncapsulationError) -> Self {
        SessionError(InternalSessionError::OhttpEncapsulationError(e))
    }
}
