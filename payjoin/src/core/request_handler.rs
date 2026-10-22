//! OHTTP relay and payjoin directory selection.
//!
//! [`RequestHandler`] decides which relays and directories to try, and in what
//! order, and returns that order as plain data. The caller makes every request
//! with its own HTTP client, so proxy, Tor and TLS settings stay in one place.
//!
//! [`RequestHandler::key_fetch_order`] gives the relay and directory pairs to
//! try when fetching OHTTP keys for a new session. [`RequestHandler::relay_order`]
//! gives the relays to try for one request to a session's directory.
//!
//! A directory chosen for a session must not change: it is embedded in the
//! BIP21 URI at session creation and recovered from the session event log
//! on resume. [`RequestHandler`] selects a directory only when a new session is
//! created; resumption does not consult it.
//!
//! Every call draws a fresh random order and remembers no failures, so
//! concurrent calls on a shared handler cannot change each other's candidates.
//!
//! A relay equal to the directory it is reaching is never listed: a server
//! serving as both rejects the self-loop request.
use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::Rng;

use crate::Url;

/// Selects OHTTP relays and payjoin directories.
///
/// Holds only the configured relays and directories, so it is cheap to clone
/// and safe to share across tasks.
#[derive(Debug, Clone)]
pub struct RequestHandler {
    relays: Vec<Url>,
    directories: Vec<Url>,
}

/// One OHTTP key fetch to attempt: `directory`'s keys, requested through
/// `relay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFetch {
    pub relay: Url,
    pub directory: Url,
}

impl RequestHandler {
    /// Deduplicates `relays` and `directories` (preserving order) so uniform
    /// selection isn't skewed by an endpoint listed more than once.
    pub fn new(relays: Vec<Url>, directories: Vec<Url>) -> Self {
        Self { relays: dedup(relays), directories: dedup(directories) }
    }

    /// The fetches to attempt for a new session's OHTTP keys, in order.
    ///
    /// Try them front to back and stop at the first that returns keys. Pin
    /// that fetch's directory in the BIP21 URI: a session's directory must not
    /// change. A caller with OHTTP keys configured ahead of time skips this
    /// and uses the directory those keys belong to.
    ///
    /// Directories come in a random order, each paired with every relay that
    /// is not itself, also in a random order, before the next directory. A
    /// failure through one relay usually can't be pinned on the directory (a
    /// relay may be throttled by the directory, or return its own error
    /// status), so retry the directory over its remaining relays. When a
    /// failure is known to be the directory's, skip its remaining pairs and
    /// move to the next directory: no URI exists yet, so changing directory
    /// costs nothing.
    ///
    /// Empty when no relays or no directories are configured.
    pub fn key_fetch_order<R: Rng>(&self, rng: &mut R) -> Vec<KeyFetch> {
        let mut order = Vec::new();
        for directory in candidate_order(&self.directories, None, rng) {
            for relay in candidate_order(&self.relays, Some(&directory), rng) {
                order.push(KeyFetch { relay, directory: directory.clone() });
            }
        }
        order
    }

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

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::rngs::StdRng;
    use bitcoin::secp256k1::rand::SeedableRng;

    use super::*;

    fn urls() -> Vec<Url> {
        ["https://a.example", "https://b.example", "https://c.example"]
            .iter()
            .map(|s| Url::parse(s).unwrap())
            .collect()
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
    fn key_fetch_order_is_empty_without_relays_or_directories() {
        let mut rng = StdRng::seed_from_u64(3);
        assert!(RequestHandler::new(Vec::new(), urls()).key_fetch_order(&mut rng).is_empty());
        assert!(RequestHandler::new(urls(), Vec::new()).key_fetch_order(&mut rng).is_empty());
    }

    #[test]
    fn key_fetch_order_tries_each_directory_over_every_other_relay() {
        let handler = RequestHandler::new(urls(), urls());
        let mut rng = StdRng::seed_from_u64(5);
        let order = handler.key_fetch_order(&mut rng);
        // Each directory over the two relays that are not itself, grouped by
        // directory so a caller can skip the rest of a failed directory.
        assert_eq!(order.len(), 6);
        for fetch in &order {
            assert_ne!(fetch.relay, fetch.directory, "a relay must never reach itself");
        }
        let mut directories = Vec::new();
        for pair in order.chunks(2) {
            assert_eq!(pair[0].directory, pair[1].directory);
            assert_ne!(pair[0].relay, pair[1].relay);
            directories.push(pair[0].directory.clone());
        }
        directories.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(directories, urls());
    }

    #[test]
    fn key_fetch_order_is_drawn_fresh_per_call() {
        let handler = RequestHandler::new(urls(), urls());
        let mut rng = StdRng::seed_from_u64(6);
        let mut firsts = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let first = handler.key_fetch_order(&mut rng).remove(0);
            firsts.insert((first.relay.to_string(), first.directory.to_string()));
        }
        // Three directories, each reachable over two relays.
        assert_eq!(firsts.len(), 6, "every pair must be able to come first");
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
