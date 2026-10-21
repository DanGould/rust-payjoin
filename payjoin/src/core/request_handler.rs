//! Failover-aware OHTTP relay and payjoin directory management.
//!
//! [`RequestHandler`] owns the selection policy for OHTTP relays and payjoin
//! directories and drives failover. [`RequestHandler::fetch_ohttp_keys_with`]
//! fetches OHTTP keys over a caller-supplied transport, trying each directory
//! over every relay before moving on to the next directory. With the `io`
//! feature, [`RequestHandler::fetch_ohttp_keys`] does the same over this
//! crate's HTTP client.
//!
//! [`RequestHandler::post_via_relay`] posts a request over a caller-supplied
//! [`RelayTransport`] (or [`FnRelayTransport`]), retrying transport failures
//! over another relay.
//!
//! A directory chosen for a session must not change: it is embedded in the
//! BIP21 URI at session creation and recovered from the session event log
//! on resume. [`RequestHandler`] selects a directory only when a new session is
//! created; resumption does not consult it.
//!
//! Every failover loop tries candidates in an order drawn fresh for that call,
//! and remembers failures only for that call. A handler therefore holds no
//! failure state, and concurrent calls on a shared handler cannot change each
//! other's candidates.
//!
//! A relay equal to the directory it is reaching is never tried: a server
//! serving as both rejects the self-loop request.
use std::sync::{Mutex, MutexGuard, PoisonError};

use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::Rng;

use crate::Url;

/// Selects OHTTP relays and payjoin directories and fails over between them.
///
/// Methods take `&self` and no lock is held across an `.await`, so a
/// `RequestHandler` can be shared across tasks (for example via `Arc`).
#[derive(Debug)]
pub struct RequestHandler {
    relays: Vec<Url>,
    directories: Vec<Url>,
    pinned_ohttp_keys: Mutex<Option<(Url, crate::OhttpKeys)>>,
    #[cfg(feature = "_manual-tls")]
    cert_der: Mutex<Option<Vec<u8>>>,
}

impl RequestHandler {
    /// Deduplicates `relays` and `directories` (preserving order) so uniform
    /// selection isn't skewed by an endpoint listed more than once.
    pub fn new(relays: Vec<Url>, directories: Vec<Url>) -> Self {
        Self {
            relays: dedup(relays),
            directories: dedup(directories),
            pinned_ohttp_keys: Mutex::new(None),
            #[cfg(feature = "_manual-tls")]
            cert_der: Mutex::new(None),
        }
    }

    /// Pin user-supplied OHTTP keys for `directory`, so
    /// [`RequestHandler::fetch_ohttp_keys_with`] and
    /// [`RequestHandler::fetch_ohttp_keys`] return this pair without
    /// contacting a directory.
    ///
    /// OHTTP keys belong to one directory: a session that names another
    /// directory with these keys cannot be reached. `directory` need not be
    /// one of the configured directories.
    pub fn set_ohttp_keys(&self, directory: Url, ohttp_keys: crate::OhttpKeys) {
        *lock(&self.pinned_ohttp_keys) = Some((directory, ohttp_keys));
    }

    /// Use a DER-encoded certificate for local HTTPS connections when
    /// fetching OHTTP keys.
    #[cfg(feature = "_manual-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "_manual-tls")))]
    pub fn set_cert_der(&self, cert_der: Vec<u8>) { *lock(&self.cert_der) = Some(cert_der); }

    /// Return the pinned OHTTP keys, or fetch them through `fetch`, with
    /// automatic failover.
    ///
    /// `fetch` performs a single attempt against a `(relay, directory)` pair.
    /// A failed attempt retries the same directory over another relay, and a
    /// directory is given up only once it has failed over every relay. Through
    /// OHTTP a failure can't be pinned on the directory rather than the relay
    /// (a relay may be throttled by the directory, or return its own error
    /// status), and a receiver is locked to the directory it puts in its BIP21
    /// URI, so one relay's failure does not rule a directory out.
    ///
    /// Returns the directory alongside the keys: a receiver pins the directory
    /// in the BIP21 URI at session creation. With pinned keys, the directory
    /// is the one they were pinned for.
    pub async fn fetch_ohttp_keys_with<R, F, Fut, E>(
        &self,
        rng: &mut R,
        fetch: F,
    ) -> Result<(Url, crate::OhttpKeys), Error>
    where
        R: Rng,
        F: Fn(Url, Url) -> Fut,
        Fut: std::future::Future<Output = Result<crate::OhttpKeys, E>>,
        E: std::fmt::Display,
    {
        if let Some(pinned) = lock(&self.pinned_ohttp_keys).clone() {
            return Ok(pinned);
        }
        if self.relays.is_empty() {
            return Err(Error(InternalError::NoRelaysAvailable));
        }
        let mut last_error = None;
        for directory in candidate_order(&self.directories, None, rng) {
            for relay in candidate_order(&self.relays, Some(&directory), rng) {
                match fetch(relay.clone(), directory.clone()).await {
                    Ok(keys) => return Ok((directory, keys)),
                    Err(e) => {
                        tracing::debug!("Directory {directory} failed via relay {relay}: {e}");
                        last_error = Some(e.to_string());
                    }
                }
            }
        }
        Err(Error(InternalError::NoDirectoriesAvailable { last_error }))
    }

    /// Return the pinned OHTTP keys, or fetch them over the network with
    /// automatic failover.
    ///
    /// [`RequestHandler::fetch_ohttp_keys_with`] over this crate's HTTP
    /// client.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    pub async fn fetch_ohttp_keys<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Url, crate::OhttpKeys), Error> {
        #[cfg(feature = "_manual-tls")]
        let cert_der = lock(&self.cert_der).clone();
        #[cfg(not(feature = "_manual-tls"))]
        let cert_der: Option<Vec<u8>> = None;
        self.fetch_ohttp_keys_with(rng, move |relay, directory| {
            let cert_der = cert_der.clone();
            async move { fetch_via_relay(cert_der.as_deref(), &relay, &directory).await }
        })
        .await
    }
}

/// Lock configuration, recovering from a poisoned lock rather than panicking:
/// a panic in another thread leaves the stored value intact.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn dedup(urls: Vec<Url>) -> Vec<Url> {
    let mut deduped: Vec<Url> = Vec::new();
    for url in urls {
        if !deduped.contains(&url) {
            deduped.push(url);
        }
    }
    deduped
}

/// The order in which one failover loop tries `urls`, leaving out `exclude`.
///
/// Trying a uniformly shuffled list front to back picks the same way as
/// repeatedly drawing uniformly from the candidates not yet tried.
// Every failover loop orders candidates here, so topology-aware ordering (for
// example AS-aware relay selection) added here applies to all of them.
fn candidate_order<R: Rng>(urls: &[Url], exclude: Option<&Url>, rng: &mut R) -> Vec<Url> {
    let mut order: Vec<Url> = urls.iter().filter(|url| Some(*url) != exclude).cloned().collect();
    order.shuffle(rng);
    order
}

#[cfg(feature = "io")]
async fn fetch_via_relay(
    cert_der: Option<&[u8]>,
    relay: &Url,
    directory: &Url,
) -> Result<crate::OhttpKeys, crate::io::Error> {
    #[cfg(feature = "_manual-tls")]
    if let Some(cert_der) = cert_der {
        return crate::io::fetch_ohttp_keys_with_cert(relay.as_str(), directory.as_str(), cert_der)
            .await;
    }
    #[cfg(not(feature = "_manual-tls"))]
    let _ = cert_der;
    crate::io::fetch_ohttp_keys(relay.as_str(), directory.as_str()).await
}

/// Error returned by [`RequestHandler`] key fetching.
#[derive(Debug)]
pub struct Error(InternalError);

#[derive(Debug)]
enum InternalError {
    /// No relay is configured.
    NoRelaysAvailable,
    /// Every configured directory failed. Carries the most recent fetch
    /// failure, when there was one.
    NoDirectoriesAvailable { last_error: Option<String> },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalError::NoRelaysAvailable => write!(f, "No valid relays available"),
            InternalError::NoDirectoriesAvailable { last_error: None } =>
                write!(f, "No valid directories available"),
            InternalError::NoDirectoriesAvailable { last_error: Some(e) } =>
                write!(f, "No valid directories available, last error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether a request-construction error was caused by session expiry.
///
/// Implemented for the send and receive v2 `CreateRequestError` types so
/// [`RequestHandler::post_via_relay`] can hand expiry back to the caller, which
/// owns the typestate needed to react.
pub trait RequestExpiry {
    /// Returns `true` when the request failed because the session expired.
    fn expired(&self) -> bool;
}

impl RequestExpiry for crate::send::v2::CreateRequestError {
    fn expired(&self) -> bool { self.is_expired() }
}

impl RequestExpiry for crate::receive::v2::CreateRequestError {
    fn expired(&self) -> bool { self.is_expired() }
}

/// Outcome of [`RequestHandler::post_via_relay`].
pub enum RelayPost<P, T> {
    /// The request was posted; carries the transport response and the caller
    /// context returned by the request builder.
    Posted(P, T),
    /// The request could not be built because the session had expired.
    Expired,
}

/// Error from [`RequestHandler::post_via_relay`].
///
/// When building the request is what failed, the build error is the
/// [`source`](std::error::Error::source) and is also available from
/// [`PostError::build_error`].
#[derive(Debug)]
pub struct PostError<E>(InternalPostError<E>);

#[derive(Debug)]
enum InternalPostError<E> {
    /// Every relay failed or was excluded. Carries the most recent transport
    /// failure, when there was one.
    NoRelaysAvailable { last_error: Option<String> },
    /// The request could not be built for a reason other than expiry.
    Build(E),
}

impl<E> PostError<E> {
    /// The error from building the request, when that is what failed.
    pub fn build_error(&self) -> Option<&E> {
        match &self.0 {
            InternalPostError::Build(e) => Some(e),
            InternalPostError::NoRelaysAvailable { .. } => None,
        }
    }
}

impl<E: std::fmt::Display> std::fmt::Display for PostError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalPostError::NoRelaysAvailable { last_error: None } =>
                write!(f, "No valid relays available"),
            InternalPostError::NoRelaysAvailable { last_error: Some(e) } =>
                write!(f, "No valid relays available, last error: {e}"),
            InternalPostError::Build(e) => write!(f, "Could not build request: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PostError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalPostError::Build(e) => Some(e),
            InternalPostError::NoRelaysAvailable { .. } => None,
        }
    }
}

/// Builds and POSTs a request through a relay, implemented by the caller.
///
/// [`RequestHandler::post_via_relay`] chooses the relay and drives failover; a
/// `RelayTransport` builds a fresh request for that relay and performs the
/// HTTP request, so callers keep their own HTTP client, proxy, and TLS
/// configuration.
pub trait RelayTransport {
    /// The request to POST to the relay. Generic so a caller whose request is
    /// not [`crate::Request`] (for example an FFI binding with its own
    /// request type) passes it through unchanged.
    type Request;
    /// Caller context produced by [`RelayTransport::build`] and returned on
    /// success, so the caller can process the response (for example an OHTTP
    /// context).
    type Context;
    /// The response produced by a successful POST.
    type Response;
    /// Why building a request failed. [`RequestExpiry`] lets the loop report
    /// session expiry as [`RelayPost::Expired`] instead of a build failure.
    type BuildError: RequestExpiry;
    /// Why a POST failed. Any POST failure moves on to another relay, so the
    /// loop only displays it.
    type Error: std::fmt::Display;

    /// Build a fresh request (and its context) addressed to `relay`.
    ///
    /// Build a new request on every call: retransmitting identical
    /// ciphertext would let a relay observe that a request is being retried.
    fn build(&mut self, relay: &Url) -> Result<(Self::Request, Self::Context), Self::BuildError>;

    /// POST a request produced by [`RelayTransport::build`].
    fn post(
        &mut self,
        request: Self::Request,
    ) -> impl std::future::Future<Output = Result<Self::Response, Self::Error>>;
}

/// [`RelayTransport`] over a pair of closures, for callers that already have
/// a build closure and a post closure.
pub struct FnRelayTransport<B, P> {
    build: B,
    post: P,
}

impl<B, P> FnRelayTransport<B, P> {
    /// Adapt a `build` closure (relay URL to request plus context) and a
    /// `post` closure (request to response) into a [`RelayTransport`].
    pub fn new(build: B, post: P) -> Self { Self { build, post } }
}

impl<B, P, Rq, T, E, Fut, Resp, TransportError> RelayTransport for FnRelayTransport<B, P>
where
    B: FnMut(&Url) -> Result<(Rq, T), E>,
    E: RequestExpiry,
    P: Fn(Rq) -> Fut,
    Fut: std::future::Future<Output = Result<Resp, TransportError>>,
    TransportError: std::fmt::Display,
{
    type Request = Rq;
    type Context = T;
    type Response = Resp;
    type BuildError = E;
    type Error = TransportError;

    fn build(&mut self, relay: &Url) -> Result<(Rq, T), E> { (self.build)(relay) }

    fn post(
        &mut self,
        request: Rq,
    ) -> impl std::future::Future<Output = Result<Resp, TransportError>> {
        (self.post)(request)
    }
}

impl RequestHandler {
    /// Build and POST a request over a relay, failing over to another relay on
    /// transport error.
    ///
    /// `exclude` names the target the request ultimately reaches. For Payjoin
    /// v2 that is the session directory, available from the session types
    /// (for example [`crate::receive::v2::Receiver::directory`]). A relay
    /// equal to it is never tried: a server serving as both relay and
    /// directory rejects the resulting self-loop request.
    ///
    /// `transport` builds a request per relay and performs the POST (see
    /// [`RelayTransport`]); the caller context from `build` is returned on
    /// success. When `build` reports [`RequestExpiry::expired`], the loop
    /// stops and returns [`RelayPost::Expired`] so the caller can react with
    /// its own typestate. Each relay is tried at most once per call.
    ///
    /// Returns a [`PostError`] once every relay that is not `exclude` has
    /// failed, naming the last transport failure.
    pub async fn post_via_relay<R, X>(
        &self,
        rng: &mut R,
        exclude: &Url,
        mut transport: X,
    ) -> Result<RelayPost<X::Response, X::Context>, PostError<X::BuildError>>
    where
        R: Rng,
        X: RelayTransport,
    {
        let mut last_error = None;
        for relay in candidate_order(&self.relays, Some(exclude), rng) {
            let (req, ctx) = match transport.build(&relay) {
                Ok(r) => r,
                Err(e) if e.expired() => return Ok(RelayPost::Expired),
                Err(e) => return Err(PostError(InternalPostError::Build(e))),
            };
            match transport.post(req).await {
                Ok(resp) => return Ok(RelayPost::Posted(resp, ctx)),
                Err(e) => {
                    tracing::debug!("Request to relay {relay} failed: {e}");
                    last_error = Some(e.to_string());
                }
            }
        }
        Err(PostError(InternalPostError::NoRelaysAvailable { last_error }))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use bitcoin::secp256k1::rand::rngs::StdRng;
    use bitcoin::secp256k1::rand::SeedableRng;

    use super::*;

    fn urls() -> Vec<Url> {
        ["https://a.example", "https://b.example", "https://c.example"]
            .iter()
            .map(|s| Url::parse(s).unwrap())
            .collect()
    }

    fn keys() -> crate::OhttpKeys {
        crate::OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap()
    }

    #[derive(Debug)]
    struct TestFetchError;

    impl std::fmt::Display for TestFetchError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fetch failed")
        }
    }

    #[test]
    fn new_dedups_urls_preserving_order() {
        let a = Url::parse("https://a.example").unwrap();
        let b = Url::parse("https://b.example").unwrap();
        let handler = RequestHandler::new(vec![a.clone(), a.clone(), b.clone()], vec![b.clone()]);
        assert_eq!(handler.relays, vec![a, b.clone()]);
        assert_eq!(handler.directories, vec![b]);
    }

    #[test]
    fn candidate_order_tries_each_url_once_and_skips_excluded() {
        let excluded = urls()[1].clone();
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..50 {
            let mut order = candidate_order(&urls(), Some(&excluded), &mut rng);
            order.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            assert_eq!(order, vec![urls()[0].clone(), urls()[2].clone()]);
        }
        assert_eq!(candidate_order(&urls(), None, &mut rng).len(), urls().len());
    }

    #[test]
    fn candidate_order_is_random() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut firsts = std::collections::BTreeSet::new();
        for _ in 0..200 {
            firsts.insert(candidate_order(&urls(), None, &mut rng)[0].to_string());
        }
        assert_eq!(firsts.len(), urls().len(), "every url must be able to come first");
    }

    #[test]
    fn error_displays_endpoint_kind_and_last_error() {
        assert_eq!(
            Error(InternalError::NoRelaysAvailable).to_string(),
            "No valid relays available"
        );
        assert_eq!(
            Error(InternalError::NoDirectoriesAvailable { last_error: None }).to_string(),
            "No valid directories available"
        );
        assert_eq!(
            Error(InternalError::NoDirectoriesAvailable { last_error: Some("404".to_string()) })
                .to_string(),
            "No valid directories available, last error: 404"
        );
    }

    #[tokio::test]
    async fn pinned_ohttp_keys_return_their_own_directory() {
        let pinned = Url::parse("https://pinned.example").unwrap();
        // The pinned directory is reported even when other directories are
        // configured, and even when it is not one of them.
        let handler = RequestHandler::new(urls(), urls());
        handler.set_ohttp_keys(pinned.clone(), keys());
        let fetched = std::cell::Cell::new(false);
        for seed in 0..20 {
            let mut rng = StdRng::seed_from_u64(seed);
            let (directory, _) = handler
                .fetch_ohttp_keys_with(&mut rng, |_relay, _directory| {
                    fetched.set(true);
                    async { Ok::<_, TestFetchError>(keys()) }
                })
                .await
                .unwrap();
            assert_eq!(directory, pinned);
        }
        assert!(!fetched.get(), "pinned keys must not be fetched");
    }

    #[tokio::test]
    async fn fetch_without_relays_fails() {
        let handler = RequestHandler::new(Vec::new(), urls());
        let mut rng = StdRng::seed_from_u64(3);
        let result = handler
            .fetch_ohttp_keys_with(&mut rng, |_relay, _directory| async {
                Ok::<_, TestFetchError>(keys())
            })
            .await;
        assert!(matches!(result.unwrap_err().0, InternalError::NoRelaysAvailable));
    }

    #[tokio::test]
    async fn fetch_returns_keys_with_the_directory_they_came_from() {
        let handler = RequestHandler::new(urls(), urls());
        let mut rng = StdRng::seed_from_u64(4);
        let tried = RefCell::new(Vec::new());
        let (directory, _) = handler
            .fetch_ohttp_keys_with(&mut rng, |_relay, directory| {
                tried.borrow_mut().push(directory);
                async { Ok::<_, TestFetchError>(keys()) }
            })
            .await
            .unwrap();
        assert_eq!(*tried.borrow(), vec![directory]);
    }

    #[tokio::test]
    async fn failure_retries_same_directory_over_every_other_relay() {
        let handler = RequestHandler::new(urls(), urls());
        let mut rng = StdRng::seed_from_u64(5);
        let attempts = RefCell::new(Vec::new());
        let result = handler
            .fetch_ohttp_keys_with(&mut rng, |relay, directory| {
                attempts.borrow_mut().push((relay, directory));
                async { Err::<crate::OhttpKeys, _>(TestFetchError) }
            })
            .await;
        assert!(matches!(
            result.unwrap_err().0,
            InternalError::NoDirectoriesAvailable { last_error: Some(e) } if e == "fetch failed"
        ));
        let attempts = attempts.borrow();
        // Each directory is tried over the two relays that are not itself,
        // once each, before moving on to the next directory.
        assert_eq!(attempts.len(), 6);
        for (relay, directory) in attempts.iter() {
            assert_ne!(relay, directory, "a relay equal to the directory must never be tried");
        }
        for pair in attempts.chunks(2) {
            assert_eq!(pair[0].1, pair[1].1);
            assert_ne!(pair[0].0, pair[1].0);
        }
    }

    // An error through one relay may come from that relay rather than the
    // directory, so the directory is retried over the next relay.
    #[tokio::test]
    async fn directory_is_kept_when_another_relay_reaches_it() {
        let directory = urls()[0].clone();
        let handler = RequestHandler::new(urls(), vec![directory.clone()]);
        let mut rng = StdRng::seed_from_u64(6);
        let attempts = std::cell::Cell::new(0u32);
        let (fetched, _) = handler
            .fetch_ohttp_keys_with(&mut rng, |_relay, _directory| {
                attempts.set(attempts.get() + 1);
                let first = attempts.get() == 1;
                async move {
                    if first {
                        Err(TestFetchError)
                    } else {
                        Ok(keys())
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(fetched, directory);
        assert_eq!(attempts.get(), 2);
    }

    #[tokio::test]
    async fn directory_that_failed_one_fetch_is_tried_by_the_next() {
        let only = vec![urls()[0].clone()];
        let handler = RequestHandler::new(urls(), only.clone());
        let mut rng = StdRng::seed_from_u64(7);
        let result = handler
            .fetch_ohttp_keys_with(&mut rng, |_relay, _directory| async {
                Err::<crate::OhttpKeys, _>(TestFetchError)
            })
            .await;
        assert!(matches!(result.unwrap_err().0, InternalError::NoDirectoriesAvailable { .. }));
        let (directory, _) = handler
            .fetch_ohttp_keys_with(&mut rng, |_relay, _directory| async {
                Ok::<_, TestFetchError>(keys())
            })
            .await
            .unwrap();
        assert_eq!(vec![directory], only);
    }

    #[cfg(feature = "_manual-tls")]
    #[test]
    fn set_cert_der_replaces_certificate() {
        let handler = RequestHandler::new(urls(), Vec::new());
        assert!(lock(&handler.cert_der).is_none());
        handler.set_cert_der(b"first".to_vec());
        assert_eq!(lock(&handler.cert_der).as_deref(), Some(b"first".as_slice()));
        handler.set_cert_der(b"second".to_vec());
        assert_eq!(lock(&handler.cert_der).as_deref(), Some(b"second".as_slice()));
    }

    #[derive(Debug)]
    struct TestExpiry(bool);

    impl RequestExpiry for TestExpiry {
        fn expired(&self) -> bool { self.0 }
    }

    impl std::fmt::Display for TestExpiry {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "test expiry: {}", self.0)
        }
    }

    fn req() -> crate::Request {
        crate::Request {
            url: "https://relay.example".to_string(),
            content_type: "message/ohttp-req",
            body: Vec::new(),
        }
    }

    /// A URL absent from `urls()`, so exclusion does not shrink the relay
    /// pool in tests that only exercise posting.
    fn unconfigured() -> Url { Url::parse("https://unconfigured.example").unwrap() }

    #[tokio::test]
    async fn post_via_relay_returns_response_and_context() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(11);
        let result = handler
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |_relay: &Url| Ok::<_, TestExpiry>((req(), 42u8)),
                    |_req| async { Ok::<_, TestExpiry>("response") },
                ),
            )
            .await;
        assert!(matches!(result, Ok(RelayPost::Posted("response", 42))));
    }

    #[tokio::test]
    async fn post_via_relay_reports_expiry() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(12);
        let result = handler
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |_relay: &Url| Err::<(crate::Request, u8), _>(TestExpiry(true)),
                    |_req| async { Ok::<_, TestExpiry>("response") },
                ),
            )
            .await;
        assert!(matches!(result, Ok(RelayPost::Expired)));
    }

    #[tokio::test]
    async fn post_via_relay_surfaces_build_error() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(13);
        let result = handler
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |_relay: &Url| Err::<(crate::Request, u8), _>(TestExpiry(false)),
                    |_req| async { Ok::<_, TestExpiry>("response") },
                ),
            )
            .await;
        match result {
            Err(e) => assert!(matches!(e.build_error(), Some(TestExpiry(false)))),
            Ok(_) => panic!("expected a build error"),
        }
    }

    #[test]
    fn post_error_display_and_source() {
        let no_relays =
            PostError::<std::fmt::Error>(InternalPostError::NoRelaysAvailable { last_error: None });
        assert_eq!(no_relays.to_string(), "No valid relays available");
        assert!(std::error::Error::source(&no_relays).is_none());
        assert!(no_relays.build_error().is_none());
        let last = PostError::<std::fmt::Error>(InternalPostError::NoRelaysAvailable {
            last_error: Some("down".to_string()),
        });
        assert_eq!(last.to_string(), "No valid relays available, last error: down");
        let build = PostError(InternalPostError::Build(std::fmt::Error));
        assert_eq!(
            build.to_string(),
            "Could not build request: an error occurred when formatting an argument"
        );
        assert!(std::error::Error::source(&build).is_some());
    }

    #[tokio::test]
    async fn post_via_relay_fails_over_then_succeeds() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(14);
        let relays = RefCell::new(Vec::new());
        let result = handler
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |relay: &Url| {
                        relays.borrow_mut().push(relay.clone());
                        Ok::<_, TestExpiry>((req(), ()))
                    },
                    |_req| {
                        let first = relays.borrow().len() == 1;
                        async move {
                            if first {
                                Err("transport down")
                            } else {
                                Ok("response")
                            }
                        }
                    },
                ),
            )
            .await;
        assert!(matches!(result, Ok(RelayPost::Posted("response", ()))));
        let relays = relays.borrow();
        assert_eq!(relays.len(), 2);
        assert_ne!(relays[0], relays[1], "a failed relay must not be retried");
    }

    #[tokio::test]
    async fn post_via_relay_tries_each_relay_once_then_gives_up() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(15);
        let attempts = std::cell::Cell::new(0u32);
        let post = |_req: crate::Request| {
            attempts.set(attempts.get() + 1);
            async { Err::<&str, &str>("transport down") }
        };
        let result = handler
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(|_relay: &Url| Ok::<_, TestExpiry>((req(), ())), post),
            )
            .await;
        assert_eq!(attempts.get(), 3);
        match result {
            Err(PostError(InternalPostError::NoRelaysAvailable { last_error })) =>
                assert_eq!(last_error.as_deref(), Some("transport down")),
            _ => panic!("expected relays to be exhausted"),
        }
    }

    #[tokio::test]
    async fn post_via_relay_never_tries_excluded_relay() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let excluded = urls()[0].clone();
        let mut rng = StdRng::seed_from_u64(18);
        let relays = RefCell::new(Vec::new());
        let result = handler
            .post_via_relay(
                &mut rng,
                &excluded,
                FnRelayTransport::new(
                    |relay: &Url| {
                        relays.borrow_mut().push(relay.clone());
                        Ok::<_, TestExpiry>((req(), ()))
                    },
                    |_req| async { Err::<&str, &str>("transport down") },
                ),
            )
            .await;
        assert!(matches!(result, Err(PostError(InternalPostError::NoRelaysAvailable { .. }))));
        let relays = relays.borrow();
        assert_eq!(relays.len(), 2);
        assert!(!relays.contains(&excluded), "the excluded relay must never be built");
    }

    #[tokio::test]
    async fn post_via_relay_with_only_excluded_relay_fails_without_posting() {
        let handler = RequestHandler::new(vec![urls()[0].clone()], Vec::new());
        let mut rng = StdRng::seed_from_u64(17);
        let result = handler
            .post_via_relay(
                &mut rng,
                &urls()[0],
                FnRelayTransport::new(
                    |_relay: &Url| -> Result<(crate::Request, ()), TestExpiry> {
                        panic!("no relay may be built")
                    },
                    |_req| async { Ok::<_, &str>("response") },
                ),
            )
            .await;
        assert!(matches!(
            result,
            Err(PostError(InternalPostError::NoRelaysAvailable { last_error: None }))
        ));
    }

    // Another session's call on the same handler, running while this call is
    // waiting on a relay, must not send this call back to a relay that
    // already failed it.
    #[tokio::test]
    async fn interleaved_call_does_not_reset_failover() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(40);
        let attempts = std::cell::Cell::new(0u32);
        let post = |_req: crate::Request| {
            attempts.set(attempts.get() + 1);
            let handler = &handler;
            async move {
                let mut rng = StdRng::seed_from_u64(41);
                let other = handler
                    .post_via_relay(
                        &mut rng,
                        &unconfigured(),
                        FnRelayTransport::new(
                            |_relay: &Url| Ok::<_, TestExpiry>((req(), ())),
                            |_req| async { Ok::<_, &str>("response") },
                        ),
                    )
                    .await;
                assert!(matches!(other, Ok(RelayPost::Posted("response", ()))));
                Err::<&str, &str>("transport down")
            }
        };
        let result = handler
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(|_relay: &Url| Ok::<_, TestExpiry>((req(), ())), post),
            )
            .await;
        assert!(matches!(result, Err(PostError(InternalPostError::NoRelaysAvailable { .. }))));
        assert_eq!(attempts.get(), 3, "each relay is tried once however other calls interleave");
    }

    // No lock is held across the transport's await, so posts sharing a handler
    // run at the same time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_via_relay_does_not_serialize_concurrent_posts() {
        use std::sync::Arc;

        use tokio::sync::Barrier;

        let handler = Arc::new(RequestHandler::new(urls(), Vec::new()));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for seed in [31u64, 32u64] {
            let handler = handler.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let mut rng = StdRng::seed_from_u64(seed);
                handler
                    .post_via_relay(
                        &mut rng,
                        &unconfigured(),
                        FnRelayTransport::new(
                            |_relay: &Url| Ok::<_, TestExpiry>((req(), ())),
                            |_req| {
                                let barrier = barrier.clone();
                                async move {
                                    // Each post waits for the other, so this
                                    // completes only if both are in flight.
                                    barrier.wait().await;
                                    Ok::<_, &str>("response")
                                }
                            },
                        ),
                    )
                    .await
            }));
        }
        for handle in handles {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("concurrent posts must not serialize")
                .unwrap();
            assert!(matches!(result, Ok(RelayPost::Posted("response", ()))));
        }
    }
}
