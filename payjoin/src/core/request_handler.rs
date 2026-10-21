//! Failover-aware OHTTP relay and payjoin directory management.
//!
//! [`RequestHandler`] owns the selection policy for OHTTP relays and payjoin
//! directories and drives failover. [`RequestHandler::fetch_ohttp_keys_with`]
//! fetches OHTTP keys over a caller-supplied transport, trying each directory
//! over every relay before moving on to the next directory.
//!
//! [`RequestHandler::relay_order`] gives the relays to try for one request, in
//! order. The caller builds and posts the request with its own HTTP client and
//! moves to the next relay on failure.
//!
//! The handler makes no requests of its own and holds no HTTP client. With the
//! `io` feature, callers can pass `payjoin::io::fetch_ohttp_keys` as the fetch.
//!
//! A directory chosen for a session must not change: it is embedded in the
//! BIP21 URI at session creation and recovered from the session event log
//! on resume. [`RequestHandler`] selects a directory only when a new session is
//! created; resumption does not consult it.
//!
//! Every call draws a fresh candidate order and remembers no failures, so
//! concurrent calls on a shared handler cannot change each other's candidates.
//!
//! A relay equal to the directory it is reaching is never tried: a server
//! serving as both rejects the self-loop request.
use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::Rng;

use crate::Url;

/// Selects OHTTP relays and payjoin directories and fails over between them.
///
/// Holds only the configured relays and directories, so it is cheap to clone
/// and safe to share across tasks.
#[derive(Debug, Clone)]
pub struct RequestHandler {
    relays: Vec<Url>,
    directories: Vec<Url>,
}

impl RequestHandler {
    /// Deduplicates `relays` and `directories` (preserving order) so uniform
    /// selection isn't skewed by an endpoint listed more than once.
    pub fn new(relays: Vec<Url>, directories: Vec<Url>) -> Self {
        Self { relays: dedup(relays), directories: dedup(directories) }
    }

    /// Fetch OHTTP keys through `fetch`, with automatic failover.
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
    /// in the BIP21 URI at session creation. A caller with OHTTP keys
    /// configured ahead of time skips this and uses the directory those keys
    /// belong to.
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

impl RequestHandler {
    /// The relays to try for one request, in a fresh random order, never
    /// `exclude`.
    ///
    /// `exclude` is the target the request ultimately reaches. For Payjoin v2
    /// that is the session directory, available from the session types (for
    /// example [`crate::receive::v2::Receiver::directory`]): a server serving
    /// as both relay and directory rejects the self-loop request.
    ///
    /// Try the relays front to back and stop at the first that succeeds.
    /// Build a fresh request for each relay: retransmitting identical
    /// ciphertext would let a relay observe that a request is being retried.
    pub fn relay_order<R: Rng>(&self, exclude: &Url, rng: &mut R) -> Vec<Url> {
        candidate_order(&self.relays, Some(exclude), rng)
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

    #[test]
    fn relay_order_lists_every_relay_once_except_the_directory() {
        let directory = urls()[0].clone();
        let handler = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(30);
        let mut order = handler.relay_order(&directory, &mut rng);
        order.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(order, urls()[1..].to_vec());
    }

    #[test]
    fn relay_order_is_drawn_fresh_per_call() {
        let handler = RequestHandler::new(urls(), Vec::new());
        let exclude = Url::parse("https://unconfigured.example").unwrap();
        let mut rng = StdRng::seed_from_u64(31);
        let mut firsts = std::collections::BTreeSet::new();
        for _ in 0..200 {
            firsts.insert(handler.relay_order(&exclude, &mut rng)[0].to_string());
        }
        assert_eq!(firsts.len(), urls().len(), "every relay must be able to come first");
    }
}
