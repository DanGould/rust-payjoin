//! Append-only queue mailboxes.
//!
//! A queue mailbox extends the single-slot mailbox model to an ordered
//! sequence of fixed-size frames, so parties that exchange more than one
//! message through a mailbox id (or fan a message out to many readers)
//! do not need one id per message. Frames are write-once and are never
//! removed individually: the whole queue expires at once, anchored at
//! the queue's creation time, so a writer cannot keep a queue alive
//! indefinitely by dripping frames into it.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use payjoin::directory::ShortId;
use tokio::fs::{self, File};
use tokio::io::{self, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{trace, warn};

use crate::db::files::load_or_create_xor_pattern;

/// The size of every queue frame. This matches the HPKE-padded payjoin
/// message size, so one frame carries exactly one end-to-end encrypted
/// message. Uniform frames keep file offsets computable and make any two
/// frames indistinguishable at rest.
pub const FRAME_BYTES: usize = 7168;

/// The maximum number of frames stored across all queue mailboxes.
///
/// Bounds queue disk usage at 224 MiB (2^15 frames of 7168 bytes),
/// independently of the single-slot mailbox capacity.
const DEFAULT_TOTAL_FRAME_CAPACITY: usize = 1 << 15;

/// Append-only storage for queue mailboxes, persisted as one file of
/// concatenated obfuscated frames per queue.
#[derive(Clone, Debug)]
pub struct QueueStore {
    pub(crate) queues: Arc<Mutex<Queues>>,
}

impl QueueStore {
    pub async fn init(dir: PathBuf, ttl: Duration, frame_cap: usize) -> io::Result<Self> {
        Ok(Self { queues: Arc::new(Mutex::new(Queues::init(dir, ttl, frame_cap).await?)) })
    }

    /// Append one frame of exactly [`FRAME_BYTES`] to the queue,
    /// creating the queue if it does not exist.
    pub async fn append(&self, id: &ShortId, frame: &[u8]) -> Result<(), Error> {
        self.queues.lock().await.append(id, frame).await
    }

    /// Read up to `max` frames starting at frame index `from`. Returns
    /// fewer (possibly zero) frames if the queue is shorter, absent, or
    /// expired; readers cannot distinguish those cases.
    pub async fn read(&self, id: &ShortId, from: u64, max: usize) -> io::Result<Vec<Vec<u8>>> {
        self.queues.lock().await.read(id, from, max).await
    }

    pub async fn prune(&self) -> io::Result<Duration> { self.queues.lock().await.prune().await }

    pub async fn spawn_background_prune(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let sleep_for =
                    { this.queues.lock().await.prune().await.expect("disk storage failed") };
                tokio::time::sleep(sleep_for).await;
            }
        });
    }
}

#[derive(Debug)]
pub(crate) struct Queues {
    dir: PathBuf,
    xor: Vec<u8>,
    /// Maximum frames per queue mailbox.
    frame_cap: usize,
    /// Maximum frames across all queue mailboxes.
    pub(crate) capacity: usize,
    total_frames: usize,
    /// Frame count per live queue.
    meta: HashMap<ShortId, usize>,
    /// Queue creation times in insertion order, for TTL pruning.
    pub(crate) insert_order: VecDeque<(SystemTime, ShortId)>,
    ttl: Duration,
}

impl Queues {
    async fn init(dir: PathBuf, ttl: Duration, frame_cap: usize) -> io::Result<Self> {
        fs::create_dir_all(&dir).await?;
        let xor = load_or_create_xor_pattern(&dir).await?;
        // Frames are obfuscated individually, each cycling the pattern
        // from index zero. That equals cycling over the whole file only
        // if the pattern length divides the frame length, which also
        // lets frames be de-obfuscated without reading their
        // predecessors.
        if FRAME_BYTES % xor.len() != 0 {
            return Err(io::Error::other("xor pattern length must divide frame size"));
        }

        let mut recovered: Vec<(SystemTime, ShortId, usize)> = Vec::new();
        let mut dir_entries = fs::read_dir(&dir).await?;
        while let Some(entry) = dir_entries.next_entry().await? {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(id) = ShortId::from_str(&name) else { continue };
            let metadata = entry.metadata().await?;
            let created = metadata.created()?;
            let frames = (metadata.len() / FRAME_BYTES as u64) as usize;
            if metadata.len() % FRAME_BYTES as u64 != 0 {
                // A crash mid-append can leave a torn frame at the tail.
                // Drop it so subsequent appends stay frame-aligned.
                let file = fs::OpenOptions::new().write(true).open(entry.path()).await?;
                file.set_len((frames * FRAME_BYTES) as u64).await?;
                file.sync_all().await?;
            }
            recovered.push((created, id, frames));
        }
        recovered.sort_by_key(|&(created, ..)| created);

        let total_frames = recovered.iter().map(|&(.., frames)| frames).sum();
        let meta = recovered.iter().map(|&(_, id, frames)| (id, frames)).collect();
        let insert_order = recovered.into_iter().map(|(created, id, _)| (created, id)).collect();

        Ok(Self {
            dir,
            xor,
            frame_cap,
            capacity: DEFAULT_TOTAL_FRAME_CAPACITY,
            total_frames,
            meta,
            insert_order,
            ttl,
        })
    }

    fn queue_path(&self, id: &ShortId) -> PathBuf { self.dir.join(id.to_string()) }

    async fn append(&mut self, id: &ShortId, frame: &[u8]) -> Result<(), Error> {
        if frame.len() != FRAME_BYTES {
            return Err(Error::InvalidFrameSize(frame.len()));
        }
        self.prune().await?;
        if self.total_frames >= self.capacity {
            return Err(Error::OverCapacity);
        }
        if self.meta.get(id).copied().unwrap_or(0) >= self.frame_cap {
            return Err(Error::QueueFull);
        }

        let mut buffer = frame.to_vec();
        xor_buffer(&self.xor, &mut buffer);

        let is_new = !self.meta.contains_key(id);
        let mut file =
            fs::OpenOptions::new().append(true).create(true).open(self.queue_path(id)).await?;
        file.write_all(&buffer).await?;
        file.sync_data().await?;

        if is_new {
            let created = file.metadata().await?.created()?;
            self.insert_order.push_back((created, *id));
        }
        *self.meta.entry(*id).or_insert(0) += 1;
        self.total_frames += 1;
        Ok(())
    }

    async fn read(&mut self, id: &ShortId, from: u64, max: usize) -> io::Result<Vec<Vec<u8>>> {
        self.prune().await?;
        let Some(&frames) = self.meta.get(id) else { return Ok(Vec::new()) };
        let from = from.min(frames as u64) as usize;
        let count = frames.saturating_sub(from).min(max);
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut file = File::open(self.queue_path(id)).await?;
        file.seek(io::SeekFrom::Start((from * FRAME_BYTES) as u64)).await?;
        let mut buffer = vec![0u8; count * FRAME_BYTES];
        file.read_exact(&mut buffer).await?;
        xor_buffer(&self.xor, &mut buffer);
        Ok(buffer.chunks_exact(FRAME_BYTES).map(<[u8]>::to_vec).collect())
    }

    /// Remove queues whose TTL elapsed. Expiry is anchored at queue
    /// creation, and eager pruning resists enumeration of expired ids,
    /// as with single-slot mailboxes.
    async fn prune(&mut self) -> io::Result<Duration> {
        let now = SystemTime::now();
        while let Some(&(created, id)) = self.insert_order.front() {
            if created + self.ttl < now {
                _ = self.insert_order.pop_front();
                let frames = self.meta.remove(&id).unwrap_or(0);
                self.total_frames -= frames;
                match fs::remove_file(self.queue_path(&id)).await {
                    Ok(()) => trace!("Pruned expired queue mailbox {id}"),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => warn!(
                        "Queue file missing during prune; possible external deletion or disk error"
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
        self.insert_order
            .front()
            .map(|(created, _id)| {
                self.ttl
                    .checked_sub(created.elapsed().expect("system clock moved back"))
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
    /// The frame is not exactly [`FRAME_BYTES`] long.
    InvalidFrameSize(usize),

    /// The queue reached its per-mailbox frame cap.
    QueueFull,

    /// Global queue storage is at capacity.
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
            InvalidFrameSize(len) => write!(f, "Frame must be {FRAME_BYTES} bytes, got {len}"),
            QueueFull => "Queue mailbox frame cap reached".fmt(f),
            OverCapacity => "Queue storage over capacity".fmt(f),
            IO(e) => write!(f, "Internal Error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use payjoin::directory::ShortId;
    use tokio::fs;

    use super::*;

    const TTL: Duration = Duration::from_secs(600);

    async fn test_store(dir: &std::path::Path, frame_cap: usize) -> QueueStore {
        QueueStore::init(dir.to_owned(), TTL, frame_cap).await.expect("init should succeed")
    }

    fn frame(fill: u8) -> Vec<u8> { vec![fill; FRAME_BYTES] }

    #[tokio::test]
    async fn test_append_and_paginated_read() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 8).await;
        let id = ShortId([1u8; 8]);

        for fill in 1..=3 {
            store.append(&id, &frame(fill)).await.expect("append should succeed");
        }

        let frames = store.read(&id, 0, 4).await?;
        assert_eq!(frames, vec![frame(1), frame(2), frame(3)], "read should return all frames");

        let frames = store.read(&id, 1, 4).await?;
        assert_eq!(frames, vec![frame(2), frame(3)], "read should start at the given index");

        let frames = store.read(&id, 1, 1).await?;
        assert_eq!(frames, vec![frame(2)], "read should stop at max frames");

        assert!(store.read(&id, 3, 4).await?.is_empty(), "reading past the end returns nothing");
        assert!(store.read(&id, 99, 4).await?.is_empty(), "out of range index returns nothing");

        let absent = ShortId([9u8; 8]);
        assert!(store.read(&absent, 0, 4).await?.is_empty(), "absent queue reads as empty");

        Ok(())
    }

    #[tokio::test]
    async fn test_frame_size_is_enforced() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 8).await;
        let id = ShortId([1u8; 8]);

        for len in [0, FRAME_BYTES - 1, FRAME_BYTES + 1] {
            assert!(
                matches!(
                    store.append(&id, &vec![0u8; len]).await,
                    Err(Error::InvalidFrameSize(got)) if got == len
                ),
                "append of {len} bytes should be rejected"
            );
        }

        assert!(store.read(&id, 0, 4).await?.is_empty(), "no frame should have been stored");

        Ok(())
    }

    #[tokio::test]
    async fn test_per_mailbox_frame_cap() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 2).await;
        let id = ShortId([1u8; 8]);

        store.append(&id, &frame(1)).await.expect("append should succeed");
        store.append(&id, &frame(2)).await.expect("append should succeed");
        assert!(
            matches!(store.append(&id, &frame(3)).await, Err(Error::QueueFull)),
            "append over the frame cap should be rejected"
        );

        // The cap is per mailbox; other queues are unaffected.
        let other = ShortId([2u8; 8]);
        store.append(&other, &frame(4)).await.expect("append to another queue should succeed");

        Ok(())
    }

    #[tokio::test]
    async fn test_global_frame_capacity() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 8).await;
        store.queues.lock().await.capacity = 3;

        for i in 1..=3 {
            store.append(&ShortId([i; 8]), &frame(i)).await.expect("append should succeed");
        }
        assert!(
            matches!(store.append(&ShortId([9u8; 8]), &frame(9)).await, Err(Error::OverCapacity)),
            "append over global capacity should be rejected"
        );

        Ok(())
    }

    // Simulate elapsed time deterministically by shifting stored timestamps
    // backward instead of sleeping, as the files db prune test does.
    #[tokio::test]
    async fn test_ttl_prunes_whole_queue() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = test_store(dir.path(), 8).await;
        let id = ShortId([1u8; 8]);

        store.append(&id, &frame(1)).await.expect("append should succeed");
        store.append(&id, &frame(2)).await.expect("append should succeed");

        store.prune().await?;
        assert_eq!(store.read(&id, 0, 4).await?.len(), 2, "unexpired queue should survive prune");

        {
            let mut guard = store.queues.lock().await;
            for (ts, _) in guard.insert_order.iter_mut() {
                *ts -= TTL + Duration::from_secs(1);
            }
        }
        store.prune().await?;

        assert!(store.read(&id, 0, 4).await?.is_empty(), "expired queue should be gone");
        assert!(!fs::try_exists(dir.path().join(id.to_string())).await?, "file should be removed");
        assert_eq!(store.queues.lock().await.total_frames, 0, "capacity should be released");

        // An expired id starts over as a fresh, empty queue.
        store.append(&id, &frame(9)).await.expect("append should succeed");
        assert_eq!(store.read(&id, 0, 4).await?, vec![frame(9)], "queue restarts at index zero");

        Ok(())
    }

    #[tokio::test]
    async fn test_recovery_after_restart() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let id = ShortId([1u8; 8]);

        {
            let store = test_store(dir.path(), 8).await;
            store.append(&id, &frame(1)).await.expect("append should succeed");
            store.append(&id, &frame(2)).await.expect("append should succeed");
        }

        let raw = fs::read(dir.path().join(id.to_string())).await?;
        assert_eq!(raw.len(), 2 * FRAME_BYTES, "file should hold exactly the appended frames");
        assert_ne!(&raw[..FRAME_BYTES], &frame(1)[..], "frames should be obfuscated at rest");

        let store = test_store(dir.path(), 8).await;
        assert_eq!(
            store.read(&id, 0, 4).await?,
            vec![frame(1), frame(2)],
            "frames should be recovered after restart"
        );
        assert_eq!(store.queues.lock().await.total_frames, 2, "capacity accounting is rebuilt");

        // Appends keep working against the recovered file.
        store.append(&id, &frame(3)).await.expect("append should succeed");
        assert_eq!(store.read(&id, 2, 4).await?, vec![frame(3)]);

        Ok(())
    }

    #[tokio::test]
    async fn test_torn_tail_is_dropped_on_recovery() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let id = ShortId([1u8; 8]);

        {
            let store = test_store(dir.path(), 8).await;
            store.append(&id, &frame(1)).await.expect("append should succeed");
        }

        // Simulate a crash mid-append: a partial frame at the tail.
        let path = dir.path().join(id.to_string());
        let mut contents = fs::read(&path).await?;
        contents.extend_from_slice(&[0xFFu8; 100]);
        fs::write(&path, contents).await?;

        let store = test_store(dir.path(), 8).await;
        assert_eq!(
            store.read(&id, 0, 4).await?,
            vec![frame(1)],
            "only complete frames should be recovered"
        );

        // The next append lands frame-aligned after the truncated tail.
        store.append(&id, &frame(2)).await.expect("append should succeed");
        assert_eq!(store.read(&id, 0, 4).await?, vec![frame(1), frame(2)]);

        Ok(())
    }
}
