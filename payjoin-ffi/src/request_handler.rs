use std::sync::Arc;

use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler;

pub use crate::uri::error::UrlParseError;
use crate::Url;

/// One OHTTP key fetch to attempt: `directory`'s keys, requested through
/// `relay`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyFetch {
    pub relay: Arc<Url>,
    pub directory: Arc<Url>,
}

impl From<request_handler::KeyFetch> for KeyFetch {
    fn from(fetch: request_handler::KeyFetch) -> Self {
        Self { relay: Arc::new(fetch.relay.into()), directory: Arc::new(fetch.directory.into()) }
    }
}

/// Selects OHTTP relays and payjoin directories.
///
/// Returns the order to try them in as plain data. Make every request with
/// your own HTTP client, so proxy, Tor and TLS settings stay in one place.
///
/// Endpoints are configured as URL strings and deduplicated. Each call draws
/// its own random order and remembers no failures, so the handler is safe to
/// share across tasks and concurrent calls do not affect each other.
///
/// A directory chosen for a session must not change: select one when creating
/// a new session and keep it for the session's lifetime. Resuming a session
/// does not consult this handler.
#[derive(Debug, uniffi::Object)]
pub struct RequestHandler {
    inner: request_handler::RequestHandler,
}

fn parse_urls(urls: Vec<String>) -> Result<Vec<payjoin::Url>, UrlParseError> {
    urls.into_iter().map(|url| payjoin::Url::parse(&url).map_err(Into::into)).collect()
}

#[uniffi::export]
impl RequestHandler {
    /// Create a `RequestHandler` from relay and directory URL strings.
    ///
    /// Duplicates are removed so uniform selection isn't skewed by an
    /// endpoint listed more than once.
    #[uniffi::constructor]
    pub fn new(relays: Vec<String>, directories: Vec<String>) -> Result<Self, UrlParseError> {
        Ok(Self {
            inner: request_handler::RequestHandler::new(
                parse_urls(relays)?,
                parse_urls(directories)?,
            ),
        })
    }

    /// The fetches to attempt for a new session's OHTTP keys, in order.
    ///
    /// Try them front to back and stop at the first that returns keys. Pin
    /// that fetch's directory in the BIP21 URI: a session's directory must not
    /// change. A caller with OHTTP keys configured ahead of time skips this
    /// and uses the directory those keys belong to.
    ///
    /// Each directory is listed over every relay that is not itself before
    /// the next directory. A failure through one relay usually can't be
    /// pinned on the directory, so retry the directory over its remaining
    /// relays. When a failure is known to be the directory's, skip its
    /// remaining pairs. Empty when no relays or no directories are
    /// configured.
    pub fn key_fetch_order(&self) -> Vec<KeyFetch> {
        self.inner.key_fetch_order(&mut OsRng).into_iter().map(Into::into).collect()
    }

    /// The relays to try for one request, in a fresh random order, never
    /// `exclude`.
    ///
    /// `exclude` is the target the request ultimately reaches, for Payjoin v2
    /// the session directory: a server serving as both relay and directory
    /// rejects the self-loop request. Try the relays front to back with your
    /// own HTTP client and stop at the first that succeeds. Build a fresh
    /// request for each relay: retransmitting identical ciphertext would let a
    /// relay observe that a request is being retried.
    pub fn relay_order(&self, exclude: Arc<Url>) -> Vec<Arc<Url>> {
        let exclude: payjoin::Url = Arc::unwrap_or_clone(exclude).into();
        self.inner
            .relay_order(&exclude, &mut OsRng)
            .into_iter()
            .map(|relay| Arc::new(relay.into()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls() -> Vec<String> {
        vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
            "https://c.example".to_string(),
        ]
    }

    fn canonical_urls() -> Vec<String> {
        urls().into_iter().map(|url| Url::parse(url).unwrap().as_string()).collect()
    }

    #[test]
    fn new_rejects_invalid_url() {
        let err = RequestHandler::new(vec!["not a url".to_string()], urls()).unwrap_err();
        assert_eq!(err.to_string(), "invalid scheme");
    }

    #[test]
    fn key_fetch_order_lists_each_directory_over_every_other_relay() {
        let handler = RequestHandler::new(urls(), urls()).unwrap();
        let order = handler.key_fetch_order();
        assert_eq!(order.len(), 6);
        for fetch in &order {
            assert_ne!(fetch.relay.as_string(), fetch.directory.as_string());
        }
        let mut directories: Vec<String> =
            order.chunks(2).map(|pair| pair[0].directory.as_string()).collect();
        directories.sort();
        assert_eq!(directories, canonical_urls());
    }

    #[test]
    fn relay_order_lists_every_relay_once_except_the_directory() {
        let handler = RequestHandler::new(urls(), Vec::new()).unwrap();
        let directory = Arc::new(Url::parse(urls()[0].clone()).unwrap());
        let mut order: Vec<String> =
            handler.relay_order(directory).iter().map(|relay| relay.as_string()).collect();
        order.sort();
        assert_eq!(order, canonical_urls()[1..].to_vec());
    }
}
