use std::sync::Arc;

use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler;

use crate::ohttp::{ClientResponse, OhttpKeys};
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

/// A posted request and the OHTTP context needed to process its response.
#[derive(uniffi::Record)]
pub struct RelayedResponse {
    /// The response body returned through the relay.
    pub body: Vec<u8>,
    /// The OHTTP context to pass to the session's `process_response`.
    pub ohttp_context: Arc<ClientResponse>,
}

/// A request built for a specific relay, ready to POST.
#[derive(uniffi::Record)]
pub struct BuiltRequest {
    /// The request to POST to the relay.
    pub request: crate::Request,
    /// The OHTTP context needed to process the eventual response.
    pub ohttp_context: Arc<ClientResponse>,
}

/// Why building a request for a relay failed.
///
/// [`RequestHandler::post_via_relay`] stops failover on either variant and
/// surfaces it to the caller: `Expired` as [`RelayPostError::Expired`] and
/// `Fatal` as [`RelayPostError::Fatal`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RelayBuildError {
    /// The session expired while building the request; stop failover.
    #[error("session expired")]
    Expired,
    /// The request could not be built for another reason; stop failover.
    #[error("could not build request: {detail}")]
    Fatal {
        /// Human-readable detail.
        detail: String,
    },
}

impl request_handler::RequestExpiry for RelayBuildError {
    fn expired(&self) -> bool { matches!(self, RelayBuildError::Expired) }
}

/// Why a single attempt to POST a request over a relay failed.
///
/// A `Transient` failure makes [`RequestHandler`] retry over another relay.
/// Build-time failures (expiry, fatal) are reported by
/// [`RelayTransport::build`], not here.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RelayTransportError {
    /// The relay could not be reached; retry over another relay.
    #[error("relay transport failure: {detail}")]
    Transient {
        /// Human-readable detail.
        detail: String,
    },
}

/// Errors from [`RequestHandler::post_via_relay`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RelayPostError {
    /// Every configured relay failed or was excluded. The detail names the
    /// last transport failure, when there was one.
    #[error("{detail}")]
    NoRelaysAvailable {
        /// Human-readable detail.
        detail: String,
    },
    /// The session expired while building the request.
    #[error("session expired")]
    Expired,
    /// The request could not be built for another reason.
    #[error("could not build request: {detail}")]
    Fatal {
        /// Human-readable detail.
        detail: String,
    },
}

/// Builds and posts a request through a relay, implemented by the binding.
///
/// [`RequestHandler::post_via_relay`] chooses the relay and drives failover;
/// the transport builds a fresh request for that relay and performs the HTTP
/// request.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait RelayTransport: Send + Sync {
    /// Build a fresh OHTTP request addressed to `relay`.
    ///
    /// Build a new request (and OHTTP context) on every call: reusing or
    /// retransmitting identical ciphertext breaks OHTTP privacy, since a relay
    /// could observe that a request is being retried. Return
    /// [`RelayBuildError::Expired`] if the session expired while building.
    fn build(&self, relay: Arc<Url>) -> Result<BuiltRequest, RelayBuildError>;

    /// POST a request produced by [`RelayTransport::build`], returning the
    /// response body. Return [`RelayTransportError::Transient`] to retry over
    /// another relay.
    async fn post(&self, request: crate::Request) -> Result<Vec<u8>, RelayTransportError>;
}

/// Selects OHTTP relays and payjoin directories and drives failover over a
/// caller-supplied transport.
///
/// Endpoints are configured as URL strings and deduplicated. Each call tries
/// endpoints in its own random order and remembers failures only for that
/// call, so the handler is safe to share across tasks and concurrent calls do
/// not affect each other.
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

    /// Build and POST a request over a relay, failing over to another relay on
    /// transport error.
    ///
    /// `exclude` is the target the request ultimately reaches — for Payjoin v2
    /// the session directory. A relay equal to it is never selected: a server
    /// serving as both relay and directory rejects the resulting self-loop
    /// request.
    ///
    /// `transport` builds and POSTs the request, letting callers keep their own
    /// proxy and TLS client configuration while this method owns relay
    /// selection and failover. `build` runs once per relay attempt and a
    /// transport error retries over another relay. Each relay is tried at most
    /// once per call.
    ///
    /// Returns [`RelayPostError::NoRelaysAvailable`] once every relay that is
    /// not `exclude` has failed.
    pub async fn post_via_relay(
        &self,
        exclude: Arc<Url>,
        transport: Arc<dyn RelayTransport>,
    ) -> Result<RelayedResponse, RelayPostError> {
        let exclude: payjoin::Url = Arc::unwrap_or_clone(exclude).into();
        struct CoreRelayTransport {
            inner: Arc<dyn RelayTransport>,
        }
        impl payjoin::request_handler::RelayTransport for CoreRelayTransport {
            type Request = crate::Request;
            type Context = Arc<ClientResponse>;
            type Response = Vec<u8>;
            type BuildError = RelayBuildError;
            type Error = RelayTransportError;
            fn build(
                &mut self,
                relay: &payjoin::Url,
            ) -> Result<(crate::Request, Arc<ClientResponse>), RelayBuildError> {
                let built = self.inner.build(Arc::new(relay.clone().into()))?;
                Ok((built.request, built.ohttp_context))
            }
            async fn post(
                &mut self,
                request: crate::Request,
            ) -> Result<Vec<u8>, RelayTransportError> {
                self.inner.post(request).await
            }
        }
        let transport = CoreRelayTransport { inner: transport };
        match self.inner.post_via_relay(&mut OsRng, &exclude, transport).await {
            Ok(request_handler::RelayPost::Posted(body, ohttp_context)) =>
                Ok(RelayedResponse { body, ohttp_context }),
            Ok(request_handler::RelayPost::Expired) => Err(RelayPostError::Expired),
            Err(e) => Err(match e.build_error() {
                Some(RelayBuildError::Expired) => RelayPostError::Expired,
                Some(RelayBuildError::Fatal { detail }) =>
                    RelayPostError::Fatal { detail: detail.clone() },
                None => RelayPostError::NoRelaysAvailable { detail: e.to_string() },
            }),
        }
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

    // Failover loops are async and need a runtime; they run under the
    // `_test-utils` feature, which enables tokio.
    #[cfg(feature = "_test-utils")]
    mod failover {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        use super::*;

        fn unconfigured() -> Arc<Url> {
            Arc::new(Url::parse("https://unconfigured.example".to_string()).unwrap())
        }

        fn test_keys() -> Arc<OhttpKeys> {
            Arc::new(OhttpKeys::decode(payjoin_test_utils::ohttp_key_config_bytes()).unwrap())
        }

        fn post_request() -> crate::Request {
            crate::Request {
                url: "https://relay.example".to_string(),
                content_type: "message/ohttp-req".to_string(),
                body: vec![1, 2, 3],
            }
        }

        fn built() -> BuiltRequest {
            BuiltRequest {
                request: post_request(),
                ohttp_context: Arc::new(ClientResponse::dangling()),
            }
        }

        struct AlwaysTransient {
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl RelayTransport for AlwaysTransient {
            fn build(&self, _relay: Arc<Url>) -> Result<BuiltRequest, RelayBuildError> {
                Ok(built())
            }

            async fn post(&self, _request: crate::Request) -> Result<Vec<u8>, RelayTransportError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(RelayTransportError::Transient { detail: "down".to_string() })
            }
        }

        #[tokio::test]
        async fn post_via_relay_tries_each_relay_once_then_gives_up() {
            let mailroom = RequestHandler::new(urls(), Vec::new()).unwrap();
            let transport = Arc::new(AlwaysTransient { calls: AtomicUsize::new(0) });
            let result = mailroom.post_via_relay(unconfigured(), transport.clone()).await;
            match result {
                Err(RelayPostError::NoRelaysAvailable { detail }) => assert_eq!(
                    detail,
                    "No valid relays available, last error: relay transport failure: down"
                ),
                Err(other) => panic!("expected relays to be exhausted, got {other:?}"),
                Ok(_) => panic!("expected relays to be exhausted, got a response"),
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
        }

        struct FixedBuildError {
            calls: AtomicUsize,
            error: fn() -> RelayBuildError,
        }

        #[async_trait::async_trait]
        impl RelayTransport for FixedBuildError {
            fn build(&self, _relay: Arc<Url>) -> Result<BuiltRequest, RelayBuildError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err((self.error)())
            }

            async fn post(&self, _request: crate::Request) -> Result<Vec<u8>, RelayTransportError> {
                unreachable!("post must not run when build fails")
            }
        }

        #[tokio::test]
        async fn post_via_relay_stops_on_expiry() {
            let mailroom = RequestHandler::new(urls(), Vec::new()).unwrap();
            let transport = Arc::new(FixedBuildError {
                calls: AtomicUsize::new(0),
                error: || RelayBuildError::Expired,
            });
            let result = mailroom.post_via_relay(unconfigured(), transport.clone()).await;
            assert!(matches!(result, Err(RelayPostError::Expired)));
            assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn post_via_relay_stops_on_fatal_build_error() {
            let mailroom = RequestHandler::new(urls(), Vec::new()).unwrap();
            let transport = Arc::new(FixedBuildError {
                calls: AtomicUsize::new(0),
                error: || RelayBuildError::Fatal { detail: "bad".to_string() },
            });
            let result = mailroom.post_via_relay(unconfigured(), transport.clone()).await;
            match result {
                Err(RelayPostError::Fatal { detail }) => assert_eq!(detail, "bad"),
                Err(other) => panic!("expected a fatal build error, got {other:?}"),
                Ok(_) => panic!("expected a fatal build error, got a response"),
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn post_via_relay_never_selects_excluded_relay() {
            // The only relay is the excluded directory, so no relay is
            // selectable and the transport must never be called.
            let mailroom = RequestHandler::new(vec![urls()[0].clone()], Vec::new()).unwrap();
            let transport = Arc::new(AlwaysTransient { calls: AtomicUsize::new(0) });
            let exclude = Arc::new(Url::parse(urls()[0].clone()).unwrap());
            let result = mailroom.post_via_relay(exclude, transport.clone()).await;
            match result {
                Err(RelayPostError::NoRelaysAvailable { detail }) =>
                    assert_eq!(detail, "No valid relays available"),
                Err(other) => panic!("expected relays to be exhausted, got {other:?}"),
                Ok(_) => panic!("expected relays to be exhausted, got a response"),
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
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
