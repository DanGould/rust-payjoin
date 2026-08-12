//! Admission control for open-submission endpoints.
//!
//! Mailbox and queue writes are implicitly gated by their ids: only a
//! party that learns an id can write to it. An endpoint that accepts
//! submissions from anyone has no such secret, so submissions pass an
//! [`Admission`] check instead. Proof of work is the first mechanism;
//! the trait keeps routing code independent of which mechanism an
//! operator deploys, so alternatives (e.g. an external verification
//! service) can be substituted without touching the endpoints.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::hashes::{sha256d, Hash};
use futures::future::BoxFuture;
use hex::{DisplayHex, FromHex};
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::Mutex;

/// Why a submission was refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The submission is structurally invalid for the mechanism.
    Malformed,
    /// The submission does not carry sufficient work.
    InsufficientWork,
}

/// An admission mechanism for submissions that anyone may make.
pub trait Admission: Send + Sync {
    /// Verify a submission body. On success, return the public tag that
    /// identifies this admission for replay detection.
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>>;

    /// Whether `tag` was admitted before.
    fn seen<'a>(&'a self, _tag: &'a [u8]) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async { Ok(false) })
    }

    /// Record `tag` as admitted. Call this only after the admitted
    /// operation fully succeeds, so a submission whose operation failed
    /// can be retried without redoing its work.
    fn record_success<'a>(&'a self, _tag: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// The nonce prefix length of a proof-of-work submission body.
pub const POW_NONCE_BYTES: usize = 8;

/// Hashcash-style proof-of-work admission.
///
/// A submission body is `nonce || payload`, where the nonce is the
/// first [`POW_NONCE_BYTES`] bytes. It is admitted when
/// sha256d(nonce || payload) has at least `target_bits` leading zero
/// bits, counted from the most significant bit of the first digest
/// byte (raw digest order, not the reversed presentation Bitcoin uses
/// for txids). Hashing the whole body commits the work to the exact
/// payload bytes, so altering any byte invalidates the proof. The
/// digest doubles as the replay-detection tag.
pub struct PowAdmission {
    target_bits: u8,
    dedupe: Option<DedupeSet>,
}

impl PowAdmission {
    pub fn new(target_bits: u8, dedupe: Option<DedupeSet>) -> Self { Self { target_bits, dedupe } }
}

impl Admission for PowAdmission {
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>> {
        Box::pin(async move {
            if body.len() <= POW_NONCE_BYTES {
                return Err(Rejection::Malformed);
            }
            let digest = sha256d::Hash::hash(body).to_byte_array();
            if leading_zero_bits(&digest) < u32::from(self.target_bits) {
                return Err(Rejection::InsufficientWork);
            }
            Ok(digest.to_vec())
        })
    }

    fn seen<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async move {
            match &self.dedupe {
                Some(dedupe) => dedupe.contains(tag).await,
                None => Ok(false),
            }
        })
    }

    fn record_success<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            match &self.dedupe {
                Some(dedupe) => dedupe.insert(tag).await,
                None => Ok(()),
            }
        })
    }
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &byte in bytes {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// A persistent set of admitted tags, for replay detection.
///
/// Tags are public values (a submission is visible to the directory by
/// construction), so they are stored in plaintext: one hex-encoded tag
/// per line, appended on each successful admission and reloaded on
/// startup. Each admission context persists its own set under its own
/// path. The file is never compacted; deleting it forgets history.
#[derive(Clone)]
pub struct DedupeSet {
    inner: Arc<Mutex<DedupeInner>>,
}

struct DedupeInner {
    file: tokio::fs::File,
    seen: HashSet<Vec<u8>>,
}

impl DedupeSet {
    /// Open the set persisted at `path`, creating it if absent.
    pub async fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut seen = HashSet::new();
        if tokio::fs::try_exists(&path).await? {
            let contents = tokio::fs::read_to_string(&path).await?;
            for line in contents.lines() {
                // Skip unparsable lines, e.g. a torn tail from a crash
                // mid-append; losing a tag only permits one replay.
                if let Ok(tag) = Vec::<u8>::from_hex(line) {
                    seen.insert(tag);
                }
            }
        }
        let file = tokio::fs::OpenOptions::new().append(true).create(true).open(&path).await?;
        Ok(Self { inner: Arc::new(Mutex::new(DedupeInner { file, seen })) })
    }

    pub async fn contains(&self, tag: &[u8]) -> io::Result<bool> {
        Ok(self.inner.lock().await.seen.contains(tag))
    }

    pub async fn insert(&self, tag: &[u8]) -> io::Result<()> {
        let mut guard = self.inner.lock().await;
        if !guard.seen.insert(tag.to_vec()) {
            return Ok(());
        }
        let line = format!("{}\n", tag.to_lower_hex_string());
        guard.file.write_all(line.as_bytes()).await?;
        guard.file.sync_data().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find a nonce whose sha256d meets `bits` leading zero bits.
    fn mine(payload: &[u8], bits: u8) -> Vec<u8> {
        for nonce in 0u64.. {
            let mut body = nonce.to_be_bytes().to_vec();
            body.extend_from_slice(payload);
            let digest = sha256d::Hash::hash(&body).to_byte_array();
            if leading_zero_bits(&digest) >= u32::from(bits) {
                return body;
            }
        }
        unreachable!("some nonce meets the target")
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x0F]), 12);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[tokio::test]
    async fn test_pow_admits_sufficient_work() {
        let pow = PowAdmission::new(8, None);
        let body = mine(b"hello board", 8);
        let tag = pow.verify(&body).await.expect("mined body should be admitted");
        assert_eq!(tag, sha256d::Hash::hash(&body).to_byte_array().to_vec());
    }

    #[tokio::test]
    async fn test_pow_rejects_insufficient_work() {
        // A 32-bit target is out of reach for any nonce a test would
        // stumble on; mine to 8 bits and verify against 32.
        let pow = PowAdmission::new(32, None);
        let body = mine(b"hello board", 8);
        assert_eq!(pow.verify(&body).await, Err(Rejection::InsufficientWork));
    }

    #[tokio::test]
    async fn test_pow_rejects_short_body() {
        let pow = PowAdmission::new(0, None);
        assert_eq!(pow.verify(&[]).await, Err(Rejection::Malformed));
        assert_eq!(pow.verify(&[0u8; POW_NONCE_BYTES]).await, Err(Rejection::Malformed));
    }

    #[tokio::test]
    async fn test_pow_commits_to_payload_bytes() {
        let pow = PowAdmission::new(8, None);
        let body = mine(b"hello board", 8);
        pow.verify(&body).await.expect("mined body should be admitted");

        // Nearly every single-byte change invalidates the proof; find
        // one that does to show the work commits to the payload.
        let invalidated = (1u8..=255).any(|flip| {
            let mut mutated = body.clone();
            let last = mutated.len() - 1;
            mutated[last] ^= flip;
            futures::executor::block_on(pow.verify(&mutated)).is_err()
        });
        assert!(invalidated, "changing a payload byte should invalidate the proof");
    }

    #[tokio::test]
    async fn test_dedupe_set_persists_across_reopen() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("admitted.tags");

        {
            let set = DedupeSet::open(path.clone()).await?;
            assert!(!set.contains(b"tag one").await?);
            set.insert(b"tag one").await?;
            set.insert(b"tag two").await?;
            set.insert(b"tag one").await?; // duplicate insert is a no-op
            assert!(set.contains(b"tag one").await?);
        }

        let set = DedupeSet::open(path.clone()).await?;
        assert!(set.contains(b"tag one").await?, "tags should survive a restart");
        assert!(set.contains(b"tag two").await?);
        assert!(!set.contains(b"tag three").await?);

        let lines = std::fs::read_to_string(&path)?;
        assert_eq!(lines.lines().count(), 2, "duplicate inserts should not be re-appended");

        Ok(())
    }

    #[tokio::test]
    async fn test_dedupe_set_skips_torn_lines() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("admitted.tags");

        {
            let set = DedupeSet::open(path.clone()).await?;
            set.insert(b"tag one").await?;
        }
        // Simulate a crash mid-append: a torn, non-hex tail line.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(b"0dd")?;
        }

        let set = DedupeSet::open(path.clone()).await?;
        assert!(set.contains(b"tag one").await?, "intact tags should still load");
        Ok(())
    }

    #[tokio::test]
    async fn test_pow_dedupe_via_trait_hooks() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let set = DedupeSet::open(dir.path().join("admitted.tags")).await?;
        let pow = PowAdmission::new(8, Some(set));

        let body = mine(b"hello board", 8);
        let tag = pow.verify(&body).await.expect("mined body should be admitted");

        assert!(!pow.seen(&tag).await?, "tag is unseen until recorded");
        pow.record_success(&tag).await?;
        assert!(pow.seen(&tag).await?, "recorded tag is seen");

        Ok(())
    }
}
