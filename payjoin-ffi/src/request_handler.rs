use std::sync::Arc;

use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler;

use crate::ohttp::OhttpKeys;
pub use crate::uri::error::UrlParseError;
use crate::Url;

/// Error returned by [`RequestHandler::fetch_ohttp_keys`].
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct RequestHandlerError(#[from] request_handler::Error);

/// The result of a successful [`RequestHandler::fetch_ohttp_keys`].
#[derive(Debug, uniffi::Record)]
pub struct FetchedOhttpKeys {
    /// The directory the keys belong to. Pin this in the BIP21 URI when
    /// creating a session, since a session's directory must not change.
    pub directory: Arc<Url>,
    /// The directory's OHTTP keys.
    pub ohttp_keys: Arc<OhttpKeys>,
}

/// Why a single attempt to fetch a directory's OHTTP keys failed.
///
/// [`RequestHandler`] retries the same directory over another relay, and
/// gives a directory up only once it has failed over every relay.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum DirectoryFetchError {
    /// The attempt failed; retry the directory over another relay.
    #[error("OHTTP keys fetch failed: {detail}")]
    Transient {
        /// Human-readable detail.
        detail: String,
    },
}

/// Fetches a payjoin directory's OHTTP keys through an OHTTP relay.
///
/// Implemented by the binding, which owns the HTTP transport and any proxy or
/// TLS configuration. [`RequestHandler::fetch_ohttp_keys`] selects the relay
/// and directory, drives failover, and tracks failures; the fetcher performs a
/// single HTTP attempt per call.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait OhttpKeysFetcher: Send + Sync {
    /// Fetch OHTTP keys from `directory` tunnelled through `relay`.
    ///
    /// Return [`DirectoryFetchError::Transient`] on any failure, so the
    /// handler retries over another relay.
    async fn fetch(
        &self,
        relay: Arc<Url>,
        directory: Arc<Url>,
    ) -> Result<Arc<OhttpKeys>, DirectoryFetchError>;
}

/// Selects OHTTP relays and payjoin directories.
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

    /// Pin user-supplied OHTTP keys for `directory`, so a key fetch returns
    /// this pair without contacting a directory.
    ///
    /// OHTTP keys belong to one directory: a session that names another
    /// directory with these keys cannot be reached.
    pub fn set_ohttp_keys(&self, directory: Arc<Url>, ohttp_keys: Arc<OhttpKeys>) {
        let directory: payjoin::Url = Arc::unwrap_or_clone(directory).into();
        let keys: payjoin::OhttpKeys = Arc::unwrap_or_clone(ohttp_keys).into();
        self.inner.set_ohttp_keys(directory, keys);
    }

    /// Return the pinned OHTTP keys, or fetch them with automatic failover.
    ///
    /// A failed attempt retries the same directory over another relay. A
    /// directory is given up only once it has failed over every relay, and
    /// then the next directory is tried.
    ///
    /// Returns the directory alongside the keys: a receiver pins the directory
    /// in the BIP21 URI at session creation. With pinned keys, the directory
    /// is the one they were pinned for.
    pub async fn fetch_ohttp_keys(
        &self,
        fetcher: Arc<dyn OhttpKeysFetcher>,
    ) -> Result<FetchedOhttpKeys, RequestHandlerError> {
        let fetch = move |relay: payjoin::Url, directory: payjoin::Url| {
            let fetcher = fetcher.clone();
            async move {
                let ohttp_keys =
                    fetcher.fetch(Arc::new(relay.into()), Arc::new(directory.into())).await?;
                Ok::<_, DirectoryFetchError>(Arc::unwrap_or_clone(ohttp_keys).into())
            }
        };
        let (directory, ohttp_keys) = self.inner.fetch_ohttp_keys_with(&mut OsRng, fetch).await?;
        Ok(FetchedOhttpKeys {
            directory: Arc::new(directory.into()),
            ohttp_keys: Arc::new(ohttp_keys.into()),
        })
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

#[cfg(feature = "_manual-tls")]
#[uniffi::export]
impl RequestHandler {
    /// Use a DER-encoded certificate for local HTTPS connections when
    /// fetching OHTTP keys.
    pub fn set_cert_der(&self, cert_der: Vec<u8>) { self.inner.set_cert_der(cert_der); }
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
    fn relay_order_lists_every_relay_once_except_the_directory() {
        let handler = RequestHandler::new(urls(), Vec::new()).unwrap();
        let directory = Arc::new(Url::parse(urls()[0].clone()).unwrap());
        let mut order: Vec<String> =
            handler.relay_order(directory).iter().map(|relay| relay.as_string()).collect();
        order.sort();
        assert_eq!(order, canonical_urls()[1..].to_vec());
    }

    // Failover loops are async and need a runtime; they run under the
    // `_test-utils` feature, which enables tokio.
    #[cfg(feature = "_test-utils")]
    mod failover {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        use super::*;

        fn test_keys() -> Arc<OhttpKeys> {
            Arc::new(OhttpKeys::decode(payjoin_test_utils::ohttp_key_config_bytes()).unwrap())
        }

        struct TransientThenKeys {
            calls: AtomicUsize,
            keys: Arc<OhttpKeys>,
        }

        #[async_trait::async_trait]
        impl OhttpKeysFetcher for TransientThenKeys {
            async fn fetch(
                &self,
                _relay: Arc<Url>,
                _directory: Arc<Url>,
            ) -> Result<Arc<OhttpKeys>, DirectoryFetchError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(DirectoryFetchError::Transient { detail: "down".to_string() });
                }
                Ok(self.keys.clone())
            }
        }

        #[tokio::test]
        async fn fetch_retries_over_another_relay() {
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let fetcher =
                Arc::new(TransientThenKeys { calls: AtomicUsize::new(0), keys: test_keys() });
            let result = mailroom.fetch_ohttp_keys(fetcher.clone()).await.unwrap();
            assert!(canonical_urls().contains(&result.directory.as_string()));
            // The transient failure is retried over another relay.
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
        }

        struct AlwaysFails {
            calls: AtomicUsize,
            directories: Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl OhttpKeysFetcher for AlwaysFails {
            async fn fetch(
                &self,
                _relay: Arc<Url>,
                directory: Arc<Url>,
            ) -> Result<Arc<OhttpKeys>, DirectoryFetchError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.directories.lock().unwrap().push(directory.as_string());
                Err(DirectoryFetchError::Transient { detail: "404".to_string() })
            }
        }

        #[tokio::test]
        async fn fetch_tries_every_relay_for_each_directory_then_gives_up() {
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let fetcher = Arc::new(AlwaysFails {
                calls: AtomicUsize::new(0),
                directories: Mutex::new(Vec::new()),
            });
            let result = mailroom.fetch_ohttp_keys(fetcher.clone()).await;
            match result {
                Err(e) => assert_eq!(
                    e.to_string(),
                    "No valid directories available, last error: OHTTP keys fetch failed: 404"
                ),
                Ok(_) => panic!("expected directories to be exhausted, got keys"),
            }
            // Each directory is tried over the two relays that are not itself.
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 6);
            let mut tried = fetcher.directories.lock().unwrap().clone();
            tried.sort();
            tried.dedup();
            assert_eq!(tried.len(), 3);
        }

        struct NeverCalled {
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl OhttpKeysFetcher for NeverCalled {
            async fn fetch(
                &self,
                _relay: Arc<Url>,
                _directory: Arc<Url>,
            ) -> Result<Arc<OhttpKeys>, DirectoryFetchError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                unreachable!("pinned keys must not be fetched")
            }
        }

        #[tokio::test]
        async fn pinned_ohttp_keys_short_circuit_fetch() {
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let pinned = Arc::new(Url::parse("https://pinned.example".to_string()).unwrap());
            mailroom.set_ohttp_keys(pinned.clone(), test_keys());
            let fetcher = Arc::new(NeverCalled { calls: AtomicUsize::new(0) });
            let result = mailroom.fetch_ohttp_keys(fetcher.clone()).await.unwrap();
            assert_eq!(result.directory.as_string(), pinned.as_string());
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn fetch_without_relays_fails() {
            let mailroom = RequestHandler::new(Vec::new(), urls()).unwrap();
            let fetcher = Arc::new(NeverCalled { calls: AtomicUsize::new(0) });
            let result = mailroom.fetch_ohttp_keys(fetcher).await;
            assert_eq!(
                result.err().map(|e| e.to_string()).as_deref(),
                Some("No valid relays available")
            );
        }

        #[tokio::test]
        async fn second_fetch_retries_directories_that_failed_the_first() {
            // Every directory fails the first fetch over every relay. The
            // second fetch tries them again and succeeds.
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let fetcher = Arc::new(AlwaysFails {
                calls: AtomicUsize::new(0),
                directories: Mutex::new(Vec::new()),
            });
            assert!(mailroom.fetch_ohttp_keys(fetcher).await.is_err());
            let fetcher =
                Arc::new(TransientThenKeys { calls: AtomicUsize::new(0), keys: test_keys() });
            let result = mailroom.fetch_ohttp_keys(fetcher).await.unwrap();
            assert!(canonical_urls().contains(&result.directory.as_string()));
        }
    }
}
