/// Error returned when parsing a [`Uri`](crate::Uri) fails.
///
/// This is payjoin's own error type. The BIP 21 parser payjoin builds on is an
/// implementation detail and never appears in this crate's public API; inspect the cause
/// with [`std::error::Error::source`] instead.
#[derive(Debug)]
pub struct UriParseError(pub(super) InternalUriParseError);

#[derive(Debug)]
pub(super) enum InternalUriParseError {
    /// The BIP 21 URI is malformed, e.g. bad scheme, address or amount.
    Bip21(bitcoin_uri::de::UriError),
    /// The BIP 21 URI is well formed but its payjoin parameters are not.
    PjParam(PjParseError),
}

impl From<InternalUriParseError> for UriParseError {
    fn from(value: InternalUriParseError) -> Self { UriParseError(value) }
}

impl From<bitcoin_uri::de::Error<PjParseError>> for UriParseError {
    fn from(value: bitcoin_uri::de::Error<PjParseError>) -> Self {
        match value {
            bitcoin_uri::de::Error::Uri(e) => InternalUriParseError::Bip21(e).into(),
            bitcoin_uri::de::Error::Extras(e) => InternalUriParseError::PjParam(e).into(),
        }
    }
}

impl std::error::Error for UriParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalUriParseError::Bip21(e) => Some(e),
            InternalUriParseError::PjParam(e) => Some(e),
        }
    }
}

impl std::fmt::Display for UriParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalUriParseError::Bip21(e) => write!(f, "Invalid BIP 21 URI: {e}"),
            InternalUriParseError::PjParam(e) => write!(f, "Invalid payjoin parameters: {e}"),
        }
    }
}

#[derive(Debug)]
pub struct PjParseError(pub(super) InternalPjParseError);

#[derive(Debug)]
pub(super) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    IntoUrl(crate::into_url::Error),
    #[cfg(feature = "v1")]
    UnsecureEndpoint,
    #[cfg(feature = "v2")]
    V2(super::v2::PjParseError),
}

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl std::error::Error for PjParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => None,
            DuplicateParams(_) => None,
            MissingEndpoint => None,
            NotUtf8 => None,
            IntoUrl(e) => Some(e),
            #[cfg(feature = "v1")]
            UnsecureEndpoint => None,
            #[cfg(feature = "v2")]
            V2(e) => Some(e),
        }
    }
}

impl std::fmt::Display for PjParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => write!(f, "Bad pjos parameter"),
            DuplicateParams(param) => {
                write!(f, "Multiple instances of parameter '{param}'")
            }
            MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            IntoUrl(e) => write!(f, "Endpoint is not valid: {e:?}"),
            #[cfg(feature = "v1")]
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
            #[cfg(feature = "v2")]
            V2(e) => write!(f, "Invalid v2 parameter: {e:?}"),
        }
    }
}
