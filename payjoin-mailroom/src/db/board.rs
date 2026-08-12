//! Bulletin board storage.
//!
//! The board is an open, append-only sequence of small fixed-size
//! blobs. Unlike mailboxes and queues it has no per-id secret: anyone
//! may read the whole board, and submissions are gated by admission
//! control at the routing layer rather than by knowledge of an id.
//! Entries carry monotonic sequence numbers and expire individually
//! after the TTL. The board is capped globally; when full, new
//! submissions are rejected instead of evicting older entries, so a
//! flood cannot wash earlier announcements off the board before they
//! expire.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::fs;
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{trace, warn};

use crate::db::files::load_or_create_xor_pattern;

/// The size of every board blob. Fixed so any two entries are
/// indistinguishable at rest and pages have a constant layout.
pub const BLOB_BYTES: usize = 512;

/// Bulletin board storage, persisted as one obfuscated file per entry,
/// named by sequence number.
#[derive(Clone, Debug)]
pub struct BoardStore {
    pub(crate) entries: Arc<Mutex<Entries>>,
}

impl BoardStore {
    pub async fn init(dir: PathBuf, ttl: Duration, cap: usize) -> io::Result<Self> {
        Ok(Self { entries: Arc::new(Mutex::new(Entries::init(dir, ttl, cap).await?)) })
    }

    /// Store one blob of exactly [`BLOB_BYTES`], returning its sequence
    /// number.
    pub async fn post(&self, blob: &[u8]) -> Result<u64, Error> {
        self.entries.lock().await.post(blob).await
    }

    /// Read up to `max` entries with sequence numbers at or above
    /// `since`, in sequence order. Expired entries leave gaps in the
    /// sequence; readers only observe the surviving entries.
    pub async fn read(&self, since: u64, max: usize) -> io::Result<Vec<(u64, Vec<u8>)>> {
        self.entries.lock().await.read(since, max).await
    }

    pub async fn prune(&self) -> io::Result<Duration> { self.entries.lock().await.prune().await }

    pub async fn spawn_background_prune(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let sleep_for =
                    { this.entries.lock().await.prune().await.expect("disk storage failed") };
                tokio::time::sleep(sleep_for).await;
            }
        });
    }
}

#[derive(Debug)]
pub(crate) struct Entries {
    dir: PathBuf,
    xor: Vec<u8>,
    /// Maximum live entries on the board.
    pub(crate) cap: usize,
    next_seq: u64,
    /// Live entries in sequence (and therefore creation) order.
    pub(crate) entries: VecDeque<Entry>,
    ttl: Duration,
}

#[derive(Debug)]
pub(crate) struct Entry {
    seq: u64,
    pub(crate) created: SystemTime,
    blob: Vec<u8>,
}

/// A board entry's file name: its sequence number, zero-padded so
/// lexicographic and numeric order agree.
fn entry_file_name(seq: u64) -> String { format!("{seq:016x}") }

fn parse_entry_file_name(name: &str) -> Option<u64> {
    if name.len() != 16 {
        return None;
    }
    u64::from_str_radix(name, 16).ok()
}

impl Entries {
    async fn init(dir: PathBuf, ttl: Duration, cap: usize) -> io::Result<Self> {
        fs::create_dir_all(&dir).await?;
        let xor = load_or_create_xor_pattern(&dir).await?;
        // As with queue frames: obfuscation cycles the pattern from
        // index zero per blob, which is only self-consistent if the
        // pattern length divides the blob length.
        if BLOB_BYTES % xor.len() != 0 {
            return Err(io::Error::other("xor pattern length must divide blob size"));
        }

        let mut recovered: Vec<Entry> = Vec::new();
        let mut dir_entries = fs::read_dir(&dir).await?;
        while let Some(entry) = dir_entries.next_entry().await? {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            // Non-entry files (the xor pattern, admission state) are
            // left alone.
            let Some(seq) = parse_entry_file_name(&name) else { continue };
            let created = entry.metadata().await?.created()?;
            let mut blob = fs::read(entry.path()).await?;
            if blob.len() != BLOB_BYTES {
                // A crash mid-write can leave a torn entry; it was
                // never acknowledged, so drop it.
                warn!("Removing torn board entry {name}");
                fs::remove_file(entry.path()).await?;
                continue;
            }
            xor_buffer(&xor, &mut blob);
            recovered.push(Entry { seq, created, blob });
        }
        recovered.sort_by_key(|entry| entry.seq);
        let next_seq = recovered.last().map(|entry| entry.seq + 1).unwrap_or(0);

        Ok(Self { dir, xor, cap, next_seq, entries: recovered.into(), ttl })
    }

    fn entry_path(&self, seq: u64) -> PathBuf { self.dir.join(entry_file_name(seq)) }

    async fn post(&mut self, blob: &[u8]) -> Result<u64, Error> {
        if blob.len() != BLOB_BYTES {
            return Err(Error::InvalidBlobSize(blob.len()));
        }
        self.prune().await?;
        if self.entries.len() >= self.cap {
            return Err(Error::OverCapacity);
        }

        let mut buffer = blob.to_vec();
        xor_buffer(&self.xor, &mut buffer);

        let seq = self.next_seq;
        let mut file = fs::File::create_new(self.entry_path(seq)).await?;
        file.write_all(&buffer).await?;
        file.sync_data().await?;
        let created = file.metadata().await?.created()?;

        self.next_seq += 1;
        self.entries.push_back(Entry { seq, created, blob: blob.to_vec() });
        Ok(seq)
    }

    async fn read(&mut self, since: u64, max: usize) -> io::Result<Vec<(u64, Vec<u8>)>> {
        self.prune().await?;
        Ok(self
            .entries
            .iter()
            .filter(|entry| entry.seq >= since)
            .take(max)
            .map(|entry| (entry.seq, entry.blob.clone()))
            .collect())
    }

    /// Remove entries whose TTL elapsed. Expiry is per entry, anchored
    /// at submission time, and eager as elsewhere in the db.
    async fn prune(&mut self) -> io::Result<Duration> {
        let now = SystemTime::now();
        while let Some(entry) = self.entries.front() {
            if entry.created + self.ttl < now {
                let seq = entry.seq;
                _ = self.entries.pop_front();
                match fs::remove_file(self.entry_path(seq)).await {
                    Ok(()) => trace!("Pruned expired board entry {seq}"),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => warn!(
                        "Board entry missing during prune; possible external deletion or disk error"
                    ),
                    Err(e) => return Err(e),
                }
            } else {
                break;
            }
        }
        Ok(self.next_prune())
    }

    fn next_prune(&self) -> Duration {
        self.entries
            .front()
            .map(|entry| {
                self.ttl
                    .checked_sub(entry.created.elapsed().expect("system clock moved back"))
                    .unwrap_or(self.ttl)
            })
            .unwrap_or(self.ttl)
    }
}

fn xor_buffer(pattern: &[u8], buffer: &mut [u8]) {
    for (byte, &p) in buffer.iter_mut().zip(pattern.iter().cycle()) {
        *byte ^= p;
    }
}

#[derive(Debug)]
pub enum Error {
    /// The blob is not exactly [`BLOB_BYTES`] long.
    InvalidBlobSize(usize),

    /// The board is full.
    OverCapacity,

    IO(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Self::IO(e) }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            InvalidBlobSize(len) => write!(f, "Blob must be {BLOB_BYTES} bytes, got {len}"),
            OverCapacity => "Board is full".fmt(f),
            IO(e) => write!(f, "Internal Error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::fs;

    use super::*;

    const TTL: Duration = Duration::from_secs(600);

    async fn test_store(dir: &std::path::Path, cap: usize) -> BoardStore {
        BoardStore::init(dir.to_owned(), TTL, cap).await.expect("init should succeed")
    }

    fn blob(fill: u8) -> Vec<u8> { vec![fill; BLOB_BYTES] }

    #[tokio::test]
    async fn test_post_and_paginated_read() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 16).await;

        for fill in 1..=3 {
            let seq = store.post(&blob(fill)).await.expect("post should succeed");
            assert_eq!(seq, u64::from(fill) - 1, "sequence numbers are assigned in order");
        }

        let entries = store.read(0, 16).await?;
        assert_eq!(entries, vec![(0, blob(1)), (1, blob(2)), (2, blob(3))]);

        assert_eq!(store.read(1, 16).await?, vec![(1, blob(2)), (2, blob(3))]);
        assert_eq!(store.read(0, 2).await?, vec![(0, blob(1)), (1, blob(2))]);
        assert!(store.read(3, 16).await?.is_empty(), "reading past the end returns nothing");

        Ok(())
    }

    #[tokio::test]
    async fn test_blob_size_is_enforced() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 16).await;

        for len in [0, BLOB_BYTES - 1, BLOB_BYTES + 1] {
            assert!(
                matches!(
                    store.post(&vec![0u8; len]).await,
                    Err(Error::InvalidBlobSize(got)) if got == len
                ),
                "post of {len} bytes should be rejected"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_board_cap_rejects_new_posts() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 2).await;

        store.post(&blob(1)).await.expect("post should succeed");
        store.post(&blob(2)).await.expect("post should succeed");
        assert!(
            matches!(store.post(&blob(3)).await, Err(Error::OverCapacity)),
            "post to a full board should be rejected"
        );

        // Existing entries are untouched: full boards reject rather
        // than evict.
        assert_eq!(store.read(0, 16).await?, vec![(0, blob(1)), (1, blob(2))]);

        Ok(())
    }

    // Simulate elapsed time deterministically by shifting stored
    // timestamps backward instead of sleeping, as the other db prune
    // tests do.
    #[tokio::test]
    async fn test_ttl_expires_entries_individually() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 16).await;

        store.post(&blob(1)).await.expect("post should succeed");
        store.post(&blob(2)).await.expect("post should succeed");

        // Expire only the first entry.
        {
            let mut guard = store.entries.lock().await;
            let first = guard.entries.front_mut().expect("entry should exist");
            first.created -= TTL + Duration::from_secs(1);
        }
        store.prune().await?;

        let entries = store.read(0, 16).await?;
        assert_eq!(entries, vec![(1, blob(2))], "sequence gaps are left where entries expired");
        assert!(!fs::try_exists(dir.path().join(entry_file_name(0))).await?);

        // New posts continue the monotonic sequence.
        let seq = store.post(&blob(3)).await.expect("post should succeed");
        assert_eq!(seq, 2, "sequence numbers are never reused");

        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_after_restart() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        {
            let store = test_store(dir.path(), 16).await;
            store.post(&blob(1)).await.expect("post should succeed");
            store.post(&blob(2)).await.expect("post should succeed");
        }

        let raw = fs::read(dir.path().join(entry_file_name(0))).await?;
        assert_eq!(raw.len(), BLOB_BYTES);
        assert_ne!(raw, blob(1), "entries should be obfuscated at rest");

        // A torn entry from a crash mid-write is dropped on recovery,
        // and unrelated files are left alone.
        fs::write(dir.path().join(entry_file_name(7)), b"torn").await?;
        fs::write(dir.path().join("admitted.tags"), b"unrelated\n").await?;

        let store = test_store(dir.path(), 16).await;
        assert_eq!(store.read(0, 16).await?, vec![(0, blob(1)), (1, blob(2))]);
        assert!(!fs::try_exists(dir.path().join(entry_file_name(7))).await?);
        assert!(fs::try_exists(dir.path().join("admitted.tags")).await?);

        let seq = store.post(&blob(3)).await.expect("post should succeed");
        assert_eq!(seq, 2, "sequence numbering resumes after the highest recovered entry");

        Ok(())
    }
}
