use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use futures::future::{self, FutureExt};
use payjoin::directory::ShortId;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::fs::{self, File};
use tokio::io::{self, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{oneshot, Mutex};
use tracing::{trace, warn};

use crate::db::{Db as DbTrait, Error as DbError, LogProbe, LOG_FRAME_BYTES, MAX_LOG_FRAMES};

/// The maximum number of pending or populated mailbox entries.
///
/// Defaults to around 2e6, for a generous upper bound rounded up from ~2
/// mailboxes/tx, ~4K txs/block, and ~144 blocks/24h.
const DEFAULT_CAPACITY: usize = 1 << (1 + 12 + 8);

#[derive(Debug)]
struct V2WaitMapEntry {
    receiver: future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>,
    sender: oneshot::Sender<Arc<Vec<u8>>>, // TODO [u8; 7168]
}

#[derive(Debug)]
struct V1WaitMapEntry {
    /// The V1 payload. Taken after the first read for data minimization —
    /// plaintext PSBTs should not linger in memory longer than needed.
    payload: Option<Arc<Vec<u8>>>,
    sender: oneshot::Sender<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct Mailboxes {
    capacity: usize,
    persistent_storage: DiskStorage,
    pending_v1: HashMap<ShortId, V1WaitMapEntry>,
    pending_v2: HashMap<ShortId, V2WaitMapEntry>,
    insert_order: VecDeque<(SystemTime, ShortId)>,
    ttl: Duration,
    /// Append-only logs live apart from v2 mailboxes, so the same ShortId can
    /// never switch a write-once mailbox into a log or back.
    log_storage: DiskStorage,
    log_insert_order: VecDeque<(SystemTime, ShortId)>,
    logs: HashMap<ShortId, Log>,
    /// Every stored log frame counts against `capacity`, so logs can't hold
    /// more data than the same number of v2 mailboxes.
    log_frames_total: usize,
    pending_log: HashMap<(ShortId, usize), V2WaitMapEntry>,
}

/// The in-memory view of one append-only log.
#[derive(Debug, Default)]
struct Log {
    len: usize,
    /// The position of each distinct frame, so a repeated append returns
    /// where the frame already is instead of storing it again. This index is
    /// kept per log on purpose: one shared across logs would tell the
    /// operator which logs received the same frame, linking mailboxes that
    /// are otherwise unrelated. Within a single log the operator already
    /// sees every frame.
    positions: HashMap<sha256::Hash, usize>,
}

impl Log {
    /// Record the frame stored at the end of the log.
    fn push(&mut self, hash: sha256::Hash) {
        self.positions.entry(hash).or_insert(self.len);
        self.len += 1;
    }
}

#[derive(Debug)]
struct DiskStorage {
    dir: PathBuf,
    xor: Vec<u8>,
}

impl DiskStorage {
    async fn init(dir: PathBuf) -> io::Result<Self> {
        let tmp_dir = &dir.join("tmp");
        if fs::try_exists(tmp_dir).await? {
            // clear out any tempfiles from uncompleted writes
            fs::remove_dir_all(tmp_dir).await?;
        }
        fs::create_dir_all(tmp_dir).await?;

        // XOR data with a random pattern to obfuscate v1 requests
        // and writing malicious data such as virus fingerprints
        let xor: Vec<u8>;
        let xor_file = dir.join("xor.dat");
        if fs::try_exists(&xor_file).await? {
            xor = fs::read(xor_file).await?;
        } else {
            xor = OsRng.next_u64().to_ne_bytes().to_vec();
            let mut file = fs::File::create_new(xor_file).await?;
            file.write_all(&xor).await?;
            file.sync_all().await?;
        }

        Ok(Self { dir, xor })
    }

    fn mailbox_path(&self, id: &ShortId) -> PathBuf { self.dir.join(id.to_string()) }

    fn insert_mailbox_path(&self, id: &ShortId) -> PathBuf {
        self.dir.join("tmp").join(id.to_string())
    }

    async fn contains_key(&self, id: &ShortId) -> io::Result<bool> {
        fs::try_exists(self.mailbox_path(id)).await
    }

    async fn get(&self, id: &ShortId) -> io::Result<Option<(SystemTime, Vec<u8>)>> {
        // If the file doesn't exist, it's Ok(None), not Err
        let mut file = match File::open(self.mailbox_path(id)).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };

        let created = file.metadata().await?.created()?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        self.xor_buffer(&mut buffer);

        Ok(Some((created, buffer)))
    }

    async fn try_insert(
        &self,
        id: &ShortId,
        contents: impl AsRef<[u8]>,
    ) -> io::Result<Option<SystemTime>> {
        let mailbox_path = self.mailbox_path(id);

        // Before attempting to write the file, check if it exists and fail
        // early. Otherwise the file will be written and only then linked into
        // the directory, so it will still be atomic but rejected data will be
        // written to disk and then discarded.
        if self.contains_key(id).await? {
            // Allow idempotent insertion if the contents are identical, in case
            // of OHTTP retries for the same e2e message.
            if let Ok(Some((created, existing_contents))) = self.get(id).await {
                if &existing_contents[..] == contents.as_ref() {
                    return Ok(Some(created));
                }
            }

            return Ok(None);
        }

        // Obfuscate the contents to avoid triggering antiviruses etc due to
        // malicious content.
        let mut buffer = contents.as_ref().to_vec();
        self.xor_buffer(&mut buffer);

        // Write the full contents to disk under a temp path
        let tmp_path = self.insert_mailbox_path(id);
        let mut file = fs::File::create_new(&tmp_path).await?;
        file.write_all(&buffer).await?;
        file.sync_data().await?;

        // Link the directory entry to the newly written file and unlink the
        // temporary entry (equivalent to rename() but without overwriting)
        let link_ret = fs::hard_link(&tmp_path, &mailbox_path).await;
        fs::remove_file(tmp_path).await?; // always unlink before returning

        // Return the creation time upon successful write
        match link_ret {
            Ok(()) => Ok(Some(file.metadata().await?.created()?)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn xor_buffer(&self, buffer: &mut [u8]) { self.xor_buffer_at(buffer, 0) }

    /// XOR a buffer that sits at byte `offset` of its file, so separately
    /// written log frames share one continuous pattern.
    fn xor_buffer_at(&self, buffer: &mut [u8], offset: usize) {
        let pattern = self.xor.iter().cycle().skip(offset % self.xor.len());
        for (byte, &pattern) in buffer.iter_mut().zip(pattern) {
            *byte ^= pattern;
        }
    }

    /// The hashes of the whole frames in a log, in order. A torn frame left
    /// by an interrupted append is skipped and gets overwritten by the next
    /// one.
    async fn frame_hashes(&self, id: &ShortId) -> io::Result<Vec<sha256::Hash>> {
        let mut buffer = fs::read(self.mailbox_path(id)).await?;
        self.xor_buffer(&mut buffer);
        Ok(buffer.chunks_exact(LOG_FRAME_BYTES).map(sha256::Hash::hash).collect())
    }

    async fn write_frame(&self, id: &ShortId, index: usize, frame: &[u8]) -> io::Result<()> {
        let offset = index * LOG_FRAME_BYTES;
        let mut buffer = frame.to_vec();
        self.xor_buffer_at(&mut buffer, offset);

        let mut file = fs::OpenOptions::new().write(true).open(self.mailbox_path(id)).await?;
        file.seek(io::SeekFrom::Start(offset as u64)).await?;
        file.write_all(&buffer).await?;
        file.sync_data().await
    }

    async fn read_frame(&self, id: &ShortId, index: usize) -> io::Result<Vec<u8>> {
        let offset = index * LOG_FRAME_BYTES;
        let mut file = File::open(self.mailbox_path(id)).await?;
        file.seek(io::SeekFrom::Start(offset as u64)).await?;
        let mut buffer = vec![0u8; LOG_FRAME_BYTES];
        file.read_exact(&mut buffer).await?;
        self.xor_buffer_at(&mut buffer, offset);
        Ok(buffer)
    }

    async fn remove(&self, id: &ShortId) -> io::Result<Option<()>> {
        match fs::remove_file(self.mailbox_path(id)).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Ok(()) => Ok(Some(())),
            Err(e) => Err(e),
        }
    }

    /// Returns the ShortId keys sorted by their creation time
    async fn insert_order(&self) -> io::Result<Vec<(SystemTime, ShortId)>> {
        // there's no need to stream this as it only happens once on startup
        // buffering to a vec simplifies any error handling
        let mut ids: Vec<(SystemTime, ShortId)> = Vec::default();

        let mut dir_entries = fs::read_dir(&self.dir).await?;
        while let Some(entry) = dir_entries.next_entry().await? {
            if let Some(file_name) = entry.file_name().to_str() {
                if let Ok(id) = ShortId::from_str(file_name) {
                    let ctime = entry.metadata().await?.created()?;
                    ids.push((ctime, id));
                }
            }
        }

        ids.sort_by_key(|&(ctime, _id)| ctime);

        Ok(ids)
    }
}

impl Mailboxes {
    async fn init(dir: PathBuf, ttl: Duration) -> io::Result<Self> {
        let log_storage = DiskStorage::init(dir.join("logs")).await?;
        let log_insert_order: VecDeque<_> = log_storage.insert_order().await?.into();
        let mut logs = HashMap::<ShortId, Log>::default();
        for (_created, id) in &log_insert_order {
            let log = logs.entry(*id).or_default();
            for hash in log_storage.frame_hashes(id).await? {
                log.push(hash);
            }
        }
        let log_frames_total = logs.values().map(|log| log.len).sum();

        let storage = DiskStorage::init(dir).await?;
        let insert_order = storage.insert_order().await?.into();
        Ok(Self {
            persistent_storage: storage,
            insert_order,
            capacity: DEFAULT_CAPACITY,
            pending_v1: HashMap::default(),
            pending_v2: HashMap::default(),
            ttl,
            log_storage,
            log_insert_order,
            logs,
            log_frames_total,
            pending_log: HashMap::default(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct FilesDb {
    timeout: Duration,
    pub(crate) mailboxes: Arc<Mutex<Mailboxes>>,
}

impl FilesDb {
    pub async fn init(timeout: Duration, path: PathBuf, ttl: Duration) -> io::Result<Self> {
        Ok(Self { timeout, mailboxes: Arc::new(Mutex::new(Mailboxes::init(path, ttl).await?)) })
    }

    pub async fn prune(&self) -> io::Result<Duration> { self.mailboxes.lock().await.prune().await }

    pub async fn spawn_background_prune(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                // TODO allow cancellation?
                let sleep_for =
                    { this.mailboxes.lock().await.prune().await.expect("disk storage failed") };
                tokio::time::sleep(sleep_for).await;
            }
        });
    }
}

impl DbTrait for FilesDb {
    type OperationalError = io::Error;
    async fn post_v2_payload(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Option<()>, DbError<Self::OperationalError>> {
        let mut guard = self.mailboxes.lock().await;
        Ok(guard.post_v2(id, payload).await?)
    }

    async fn wait_for_v2_payload(
        &self,
        id: &ShortId,
    ) -> Result<Arc<Vec<u8>>, DbError<Self::OperationalError>> {
        let receiver = {
            let mut guard = self.mailboxes.lock().await;

            if let Some(payload) = guard.read(id).await? {
                return Ok(payload);
            } else {
                guard.wait_v2(id).await?
            }
        };

        let ret = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(payload) => Ok((payload.expect("receiver must not fail")).clone()),
            Err(elapsed) => Err(DbError::Timeout(elapsed)),
        };

        self.mailboxes.lock().await.maybe_cleanup_v2_waitmap(id);

        ret
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Arc<Vec<u8>>, DbError<Self::OperationalError>> {
        let receiver = {
            self.mailboxes
                .lock()
                .await
                .post_v1_req_and_wait(id, payload)
                .await?
                .ok_or(DbError::OverCapacity)?
        };

        trace!("v1 sender waiting for v2 receiver's response");

        let ret = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(payload) => Ok(Arc::new(payload.expect("receiver must not fail"))),
            Err(elapsed) => Err(DbError::Timeout(elapsed)),
        };

        // unconditionally clear the pending v1 entry. on timeout, the sender
        // will no longer be available to process any replies so there is no
        // point delivering the request to the receiver
        self.mailboxes.lock().await.pending_v1.remove(id);

        ret
    }

    async fn post_v1_response(
        &self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<(), DbError<Self::OperationalError>> {
        let mut guard = self.mailboxes.lock().await;
        Ok(guard.post_v1_res(id, payload).await?)
    }

    async fn append_log_frame(
        &self,
        id: &ShortId,
        frame: Vec<u8>,
    ) -> Result<Option<usize>, DbError<Self::OperationalError>> {
        let mut guard = self.mailboxes.lock().await;
        Ok(guard.append_log(id, frame).await?)
    }

    async fn wait_for_log_frame(
        &self,
        id: &ShortId,
        index: usize,
    ) -> Result<Arc<Vec<u8>>, DbError<Self::OperationalError>> {
        let receiver = {
            let mut guard = self.mailboxes.lock().await;

            if index < guard.log_len(id) {
                return Ok(Arc::new(guard.log_storage.read_frame(id, index).await?));
            } else {
                guard.wait_log(id, index).await?
            }
        };

        let ret = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(frame) => Ok((frame.expect("receiver must not fail")).clone()),
            Err(elapsed) => Err(DbError::Timeout(elapsed)),
        };

        self.mailboxes.lock().await.maybe_cleanup_log_waitmap(id, index);

        ret
    }

    async fn probe_log_frame(
        &self,
        id: &ShortId,
        index: usize,
    ) -> Result<LogProbe, DbError<Self::OperationalError>> {
        let guard = self.mailboxes.lock().await;
        let frame_count = guard.log_len(id);
        if index < frame_count {
            Ok(LogProbe::Frame(Arc::new(guard.log_storage.read_frame(id, index).await?)))
        } else {
            Ok(LogProbe::Missing { frame_count })
        }
    }
}

// The async methods here generally use &mut self, and therefore assume mutex
// ownership of the mailbox struct. this means they are supposed to return
// quickly. however, they will wait for sync() on write, as the implies minimum
// number of requests per second is only 25, holding the mutex while waiting for
// disk and thereby serializing all writes should be fine even without an SSD.
impl Mailboxes {
    async fn read(&mut self, id: &ShortId) -> io::Result<Option<Arc<Vec<u8>>>> {
        // V1 POST requests are only stored in memory since they are
        // unencrypted. Check this hash table first. Use take() for data
        // minimization — clear the plaintext payload after first read.
        if let Some(entry) = self.pending_v1.get_mut(id) {
            if let Some(payload) = entry.payload.take() {
                return Ok(Some(payload));
            }
        }

        // V2 requests are stored on disk
        if let Some((_created, payload)) = self.persistent_storage.get(id).await? {
            return Ok(Some(Arc::new(payload)));
        }

        Ok(None)
    }

    async fn has_capacity(&mut self) -> io::Result<bool> {
        self.maybe_prune().await?;
        Ok(self.len() < self.capacity)
    }

    async fn wait_v2(
        &mut self,
        id: &ShortId,
    ) -> Result<future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>, Error> {
        if !self.has_capacity().await? {
            return Err(Error::OverCapacity);
        }

        if let Some(entry) = self.pending_v1.get(id) {
            if entry.payload.is_some() {
                return Err(Error::OverCapacity);
            }
            return Err(Error::AlreadyRead);
        }

        let receiver = self
            .pending_v2
            .entry(*id)
            .or_insert_with(|| {
                let (sender, receiver) = oneshot::channel::<Arc<Vec<u8>>>();
                let shared_receiver = receiver.shared();
                V2WaitMapEntry { sender, receiver: shared_receiver.clone() }
            })
            .receiver
            .clone();

        Ok(receiver)
    }

    fn maybe_cleanup_v2_waitmap(&mut self, id: &ShortId) {
        if let Some(entry) = self.pending_v2.get(id) {
            if entry.receiver.strong_count().unwrap_or(0) <= 1 {
                self.pending_v2.remove(id);
            }
        }
    }

    async fn post_v2(&mut self, id: &ShortId, payload: Vec<u8>) -> Result<Option<()>, Error> {
        if !self.has_capacity().await? {
            return Err(Error::OverCapacity);
        }

        let Some(created) = self.persistent_storage.try_insert(id, &payload).await? else {
            return Ok(None);
        };

        self.insert_order.push_back((created, *id));

        // If there are pending readers, satisfy them
        if let Some(pending) = self.pending_v2.remove(id) {
            trace!("notifying pending readers for {}", id);

            pending
                .sender
                .send(Arc::new(payload))
                .expect("sending on oneshot channel must succeed");
        }

        Ok(Some(()))
    }

    async fn post_v1_req_and_wait(
        &mut self,
        id: &ShortId,
        payload: Vec<u8>,
    ) -> Result<Option<oneshot::Receiver<Vec<u8>>>, Error> {
        // Edge case: pruning a v2 entry here can make room for this v1 insert,
        // so v1 writers may see effective capacity of n-1 instead of n.
        if !self.has_capacity().await? {
            return Err(Error::OverCapacity);
        }

        let mut ret = None;
        let payload = Arc::new(payload);

        // Don't overwrite in flight requests
        self.pending_v1.entry(*id).or_insert_with(|| {
            let payload = payload.clone();
            let (sender, receiver) = oneshot::channel::<Vec<u8>>();
            ret = Some(receiver);
            V1WaitMapEntry { payload: Some(payload), sender }
        });

        // If there are pending readers, satisfy them with the payload
        // and clear the in-memory copy for data minimization
        if let Some(pending) = self.pending_v2.remove(id) {
            trace!("notifying pending readers for {} (v1 fallback)", id);
            pending.sender.send(payload.clone()).expect("sending on oneshot channel must succeed");
            if let Some(entry) = self.pending_v1.get_mut(id) {
                entry.payload.take();
            }
        }

        Ok(ret)
    }

    fn log_len(&self, id: &ShortId) -> usize { self.logs.get(id).map_or(0, |log| log.len) }

    async fn append_log(&mut self, id: &ShortId, frame: Vec<u8>) -> Result<Option<usize>, Error> {
        let hash = sha256::Hash::hash(&frame);
        if let Some(&index) = self.logs.get(id).and_then(|log| log.positions.get(&hash)) {
            return Ok(Some(index));
        }

        if !self.has_capacity().await? {
            return Err(Error::OverCapacity);
        }

        let index = match self.logs.get(id).map(|log| log.len) {
            Some(len) if len >= MAX_LOG_FRAMES => return Ok(None),
            Some(len) => {
                self.log_storage.write_frame(id, len, &frame).await?;
                len
            }
            None => {
                // Creating the log through a temp file means a log on disk
                // always starts with a complete frame.
                let Some(created) = self.log_storage.try_insert(id, &frame).await? else {
                    return Err(io::Error::other(format!("untracked log file for {id}")).into());
                };
                self.log_insert_order.push_back((created, *id));
                0
            }
        };
        self.logs.entry(*id).or_default().push(hash);
        self.log_frames_total += 1;

        if let Some(pending) = self.pending_log.remove(&(*id, index)) {
            trace!("notifying pending readers for frame {index} of log {id}");

            pending.sender.send(Arc::new(frame)).expect("sending on oneshot channel must succeed");
        }

        Ok(Some(index))
    }

    async fn wait_log(
        &mut self,
        id: &ShortId,
        index: usize,
    ) -> Result<future::Shared<oneshot::Receiver<Arc<Vec<u8>>>>, Error> {
        if !self.has_capacity().await? {
            return Err(Error::OverCapacity);
        }

        let receiver = self
            .pending_log
            .entry((*id, index))
            .or_insert_with(|| {
                let (sender, receiver) = oneshot::channel::<Arc<Vec<u8>>>();
                let shared_receiver = receiver.shared();
                V2WaitMapEntry { sender, receiver: shared_receiver.clone() }
            })
            .receiver
            .clone();

        Ok(receiver)
    }

    fn maybe_cleanup_log_waitmap(&mut self, id: &ShortId, index: usize) {
        if let Some(entry) = self.pending_log.get(&(*id, index)) {
            if entry.receiver.strong_count().unwrap_or(0) <= 1 {
                self.pending_log.remove(&(*id, index));
            }
        }
    }

    async fn remove(&mut self, id: &ShortId) -> io::Result<Option<()>> {
        self.persistent_storage.remove(id).await
    }

    async fn post_v1_res(&mut self, id: &ShortId, payload: Vec<u8>) -> Result<(), Error> {
        match self.pending_v1.remove(id) {
            None => Err(Error::V1SenderUnavailable),
            Some(V1WaitMapEntry { sender, .. }) =>
                sender.send(payload).map_err(|_| Error::V1SenderUnavailable),
        }
    }

    fn len(&self) -> usize {
        self.insert_order.len()
            + self.pending_v1.len()
            + self.pending_v2.len()
            + self.log_frames_total
            + self.pending_log.len()
    }

    async fn maybe_prune(&mut self) -> io::Result<Duration> {
        // TODO make this lazier, once per time interval, or once per n checks
        // or both
        self.prune().await
    }

    /// Clean out the mailboxes.
    ///
    /// Since we use a mutex and not a concurrent hashmap, there's currently
    /// no benefit to putting this in a background task.
    ///
    /// Furthermore, to improve privacy and resist mailbox enumeration, we prune
    /// expired entries eagerly.
    async fn prune(&mut self) -> io::Result<Duration> {
        trace!("pruning");
        let now = SystemTime::now();

        debug_assert!(self.pending_v1.iter().all(|(_, v)| !v.sender.is_closed()));

        // Prune in flight requests, these can persist in the case of an incomplete session
        self.pending_v2.retain(|_, v| v.receiver.strong_count().unwrap_or(0) > 1);
        self.pending_log.retain(|_, v| v.receiver.strong_count().unwrap_or(0) > 1);

        // Prune any expired mailboxes
        while let Some((created, id)) = self.insert_order.front().cloned() {
            if created + self.ttl < now {
                _ = self.insert_order.pop_front();
                if self.remove(&id).await?.is_none() {
                    warn!("Mailbox file missing during prune; possible external deletion or disk error");
                } else {
                    trace!("Pruned old mailbox {id}");
                }
            } else {
                break;
            }
        }

        // Logs expire as a whole, counted from their first frame
        while let Some((created, id)) = self.log_insert_order.front().cloned() {
            if created + self.ttl < now {
                _ = self.log_insert_order.pop_front();
                self.log_frames_total -= self.logs.remove(&id).map_or(0, |log| log.len);
                if self.log_storage.remove(&id).await?.is_none() {
                    warn!(
                        "Log file missing during prune; possible external deletion or disk error"
                    );
                } else {
                    trace!("Pruned old log {id}");
                }
            } else {
                break;
            }
        }

        Ok(self.next_prune())
    }

    fn next_prune(&mut self) -> Duration {
        self.insert_order
            .front()
            .into_iter()
            .chain(self.log_insert_order.front())
            .map(|(created, _id)| {
                self.ttl
                    .checked_sub(created.elapsed().expect("system clock moved back"))
                    .unwrap_or(self.ttl)
            })
            .min()
            .unwrap_or(self.ttl)
    }
}

#[derive(Debug)]
pub enum Error {
    /// Operation rejected due to lack of capacity
    OverCapacity,

    /// Indicates receiver already consumed the plaintext V1 request payload
    AlreadyRead,

    /// Indicates the sender that was waiting for the reply is no longer there
    V1SenderUnavailable,

    IO(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Self::IO(e) }
}

// FIXME why isn't this sufficient for ?, necessitating ugly map_err(into)?
impl From<Error> for DbError<std::io::Error> {
    fn from(val: Error) -> DbError<io::Error> {
        match val {
            Error::V1SenderUnavailable => DbError::V1SenderUnavailable,
            Error::OverCapacity => DbError::OverCapacity,
            Error::AlreadyRead => DbError::AlreadyRead,
            Error::IO(e) => DbError::Operational(e),
        }
    }
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
            OverCapacity => "Database over capacity".fmt(f),
            AlreadyRead => "Mailbox payload already read".fmt(f),
            V1SenderUnavailable => "Sender no longer connected".fmt(f),
            IO(e) => write!(f, "Internal Error: {e}"),
        }
    }
}

impl crate::db::SendableError for Error {}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use payjoin::directory::ShortId;
    use tokio::fs;
    use tokio::io::AsyncWriteExt;

    use crate::db::files::DiskStorage;
    use crate::db::{Db as DbTrait, Error as DbError, FilesDb, LOG_FRAME_BYTES, MAX_LOG_FRAMES};

    #[tokio::test]
    async fn test_disk_storage_initialization() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        assert!(
            !dir.path().join("tmp").exists(),
            "tmp subdirectory should not have been created yet"
        );

        let xor_pattern = {
            let storage = DiskStorage::init(dir.path().to_owned())
                .await
                .expect("initializing storage directory should succeed");

            assert!(dir.path().join("tmp").exists(), "tmp subdirectory should have been created");
            assert!(
                dir.path().join("xor.dat").exists(),
                "random obfuscation pattern should have been generated"
            );

            fs::write(dir.path().join("tmp").join("blah"), "junk").await?;

            storage.xor
        };

        assert!(
            dir.path().join("tmp").join("blah").exists(),
            "temp file should not have been cleared yet"
        );
        let storage = DiskStorage::init(dir.path().to_owned())
            .await
            .expect("initializing storage directory should succeed");

        assert!(
            !dir.path().join("tmp").join("blah").exists(),
            "temp file should have been cleared"
        );

        assert_eq!(storage.xor, xor_pattern, "xor pattern loaded from file");

        Ok(())
    }

    #[tokio::test]
    async fn test_disk_storage_mailboxes() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let storage = DiskStorage::init(dir.path().to_owned())
            .await
            .expect("initializing storage directory should succeed");

        let id1 = ShortId::try_from(&(b"12345678")[..]).unwrap();
        let id2 = ShortId::try_from(&(b"87654321")[..]).unwrap();

        assert!(!storage
            .contains_key(&id1)
            .await
            .expect("checking mailbox existence should not error"));
        assert!(!storage
            .contains_key(&id2)
            .await
            .expect("checking mailbox existence should not error"));
        assert!(matches!(storage.get(&id1).await, Ok(None)));
        assert!(matches!(storage.get(&id2).await, Ok(None)));

        let contents1 = b"OH HAI";
        let contents2 = b"HI FREN";

        let created1 = storage
            .try_insert(&id1, contents1)
            .await
            .expect("writing should succeed")
            .expect("writing should return a creation time");

        match storage.get(&id1).await {
            Ok(Some((got_created, got_contents))) => {
                assert_eq!(got_created, created1.to_owned());
                assert_eq!(got_contents, contents1.to_owned());
            }
            e => {
                e.expect("retrieval should work");
            }
        };

        assert!(matches!(storage.get(&id2).await, Ok(None)));

        assert!(
            storage
                .try_insert(&id1, contents2)
                .await
                .expect("writing a second time should not fail with IO error")
                .is_none(),
            "writing a second time should be rejected",
        );

        assert_eq!(
            storage.try_insert(&id1, contents1).await.expect("idempotent write should not fail"),
            Some(created1),
            "idempotent write should have the same creation time",
        );

        tokio::time::sleep(Duration::from_millis(1)).await;

        let created2 = storage
            .try_insert(&id2, contents2)
            .await
            .expect("writing should succeed")
            .expect("writing should return a creation time");

        assert!(created1 < created2, "creation times should be ordered as expected");

        assert_eq!(
            storage.insert_order().await.expect("enumeration should succeed"),
            vec![(created1, id1), (created2, id2)],
            "enumeration should return expected keys and creation times",
        );

        let mut file_contents =
            fs::read(storage.mailbox_path(&id1)).await.expect("mailbox file should be readable");

        assert_eq!(file_contents.len(), contents1.len(), "file data should have the right length");
        assert_ne!(file_contents, contents1, "file data should be obfuscated");

        storage.xor_buffer(&mut file_contents[..]);
        assert_eq!(file_contents, contents1, "deobfuscation should recover contents");

        storage.remove(&id1).await.expect("removing an existing mailbox should succeed");
        assert!(
            !storage.contains_key(&id1).await.expect("checking existence should not error"),
            "mailbox file should no longer exist"
        );
        storage.remove(&id1).await.expect("removing a non-existing mailbox should still not error");

        assert_eq!(
            storage.insert_order().await.expect("enumeration should succeed"),
            vec![(created2, id2)],
            "enumeration should return expected keys and creation times",
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_mailbox_storage() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = FilesDb::init(
            Duration::from_millis(10),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await
        .expect("initializing mailbox database should succeed");

        let id = ShortId([0u8; 8]);
        let contents = b"foo bar";
        db.post_v2_payload(&id, contents.to_vec())
            .await
            .expect("posting payload should succeed")
            .expect("contents should be accepted");

        let res = db.wait_for_v2_payload(&id).await.expect("waiting for payload should succeed");
        assert_eq!(&res[..], contents, "posted payload should be retrievable");

        Ok(())
    }

    #[tokio::test]
    async fn test_v2_wait() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = FilesDb::init(
            Duration::from_millis(1),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await
        .expect("initializing mailbox database should succeed");

        let id = ShortId([0u8; 8]);
        let contents = b"foo bar";

        match db.wait_for_v2_payload(&id).await {
            Err(DbError::Timeout(_)) => {}
            res => panic!("expected timeout, got {res:?}"),
        }

        let read_task1 = tokio::spawn({
            let db = db.clone();
            async move { db.wait_for_v2_payload(&id).await }
        });
        let read_task2 = tokio::spawn({
            let db = db.clone();
            async move { db.wait_for_v2_payload(&id).await }
        });

        db.post_v2_payload(&id, contents.to_vec())
            .await
            .expect("posting payload should succeed")
            .expect("contents should be accepted");

        let res = read_task1
            .await
            .expect("joining task should succeed")
            .expect("waiting for payload should succeed");
        assert_eq!(&res[..], contents, "posted payload should be retrievable");

        let res = read_task2
            .await
            .expect("joining task should succeed")
            .expect("waiting for payload should succeed");
        assert_eq!(&res[..], contents, "posted payload should be retrievable");

        assert!(
            db.post_v2_payload(&id, b"something else".to_vec())
                .await
                .expect("posting payload should succeed")
                .is_none(),
            "duplicate POST should be rejected"
        );

        let res = db.wait_for_v2_payload(&id).await.expect("reading payload should succeed");
        assert_eq!(&res[..], contents, "posted payload should be retrievable");

        Ok(())
    }

    #[tokio::test]
    async fn test_v1_wait() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = Arc::new(
            FilesDb::init(
                Duration::from_millis(1),
                dir.path().to_owned(),
                Duration::from_secs(60 * 60 * 24 * 7),
            )
            .await
            .expect("initializing mailbox database should succeed"),
        );

        let id = ShortId([0u8; 8]);

        let v1_sender_task = tokio::spawn({
            let db = db.clone();
            async move { db.post_v1_request_and_wait_for_response(&id, b"request".to_vec()).await }
        });

        let res = db.wait_for_v2_payload(&id).await.expect("reading payload should succeed");
        assert_eq!(&res[..], b"request", "in flight v1 request should be retrievable");

        assert!(
            matches!(
                db.post_v1_request_and_wait_for_response(&id, b"different request".to_vec()).await,
                Err(DbError::OverCapacity),
            ),
            "second v1 sender with the same shortid should be rejected while request is in flight",
        );

        db.post_v1_response(&id, b"response".to_vec())
            .await
            .expect("posting payload should succeed");

        let res = v1_sender_task
            .await
            .expect("joining task should succeed")
            .expect("waiting for payload should succeed");
        assert_eq!(&res[..], b"response", "should be response from v2 receiver");

        assert!(
            matches!(
                db.post_v1_response(&id, b"response".to_vec()).await,
                Err(DbError::V1SenderUnavailable)
            ),
            "posting without a v1 sender waiting should fail"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_v1_data_minimization() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = Arc::new(
            FilesDb::init(
                Duration::from_millis(500),
                dir.path().to_owned(),
                Duration::from_secs(60 * 60 * 24 * 7),
            )
            .await
            .expect("initializing mailbox database should succeed"),
        );

        let id = ShortId([0u8; 8]);

        // Spawn v1 sender in background
        let v1_sender_task = tokio::spawn({
            let db = db.clone();
            async move { db.post_v1_request_and_wait_for_response(&id, b"request".to_vec()).await }
        });

        // Small delay to let v1 request post
        tokio::time::sleep(Duration::from_millis(10)).await;

        // First read should return the payload
        let res = db.wait_for_v2_payload(&id).await.expect("first read should succeed");
        assert_eq!(&res[..], b"request", "first read should return the payload");

        // Subsequent reads should not return the plaintext payload again.
        assert!(
            matches!(db.wait_for_v2_payload(&id).await, Err(DbError::AlreadyRead)),
            "subsequent reads should indicate the payload was already consumed"
        );

        // Verify the payload was cleared from memory by checking directly
        {
            let guard = db.mailboxes.lock().await;
            let entry = guard.pending_v1.get(&id);
            assert!(
                entry.is_none_or(|e| e.payload.is_none()),
                "v1 payload should have been cleared after first read"
            );
        }

        // V1 response flow should still work even after payload was cleared
        db.post_v1_response(&id, b"response".to_vec())
            .await
            .expect("posting response should succeed");

        let res = v1_sender_task
            .await
            .expect("joining task should succeed")
            .expect("v1 sender should get response");
        assert_eq!(&res[..], b"response", "v1 sender should receive the response");

        Ok(())
    }

    // Simulate elapsed time deterministically by shifting stored timestamps
    // backward instead of sleeping. tokio::time::pause() can't be used because
    // prune compares against SystemTime (timestamps originate from disk).
    #[tokio::test]
    async fn test_prune() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = FilesDb::init(
            Duration::from_millis(2),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await
        .expect("initializing mailbox database should succeed");

        let ttl = Duration::from_secs(600);

        {
            let mut guard = db.mailboxes.lock().await;
            guard.capacity = 2;
            guard.ttl = ttl;
        }

        assert_eq!(db.mailboxes.lock().await.len(), 0);
        db.prune().await.expect("pruning should not fail");
        assert_eq!(db.mailboxes.lock().await.len(), 0);

        let id = ShortId([0u8; 8]);
        let contents = b"fooo";

        // Pending v2 waiter that times out should be cleaned up by prune
        let read_task1 = tokio::spawn({
            let db = db.clone();
            async move { db.wait_for_v2_payload(&id).await }
        });

        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(db.mailboxes.lock().await.len(), 1);

        match read_task1.await.expect("joining should succeed") {
            Err(DbError::Timeout(_)) => {}
            res => panic!("expected timeout, got {res:?}"),
        }

        db.prune().await.expect("pruning should not fail");
        assert_eq!(db.mailboxes.lock().await.len(), 0);

        // Post a v2 payload — should survive immediate prune (TTL not elapsed)
        db.post_v2_payload(&id, contents.to_vec())
            .await
            .expect("posting payload should succeed")
            .expect("contents should be accepted");

        assert_eq!(db.mailboxes.lock().await.len(), 1);
        db.prune().await.expect("pruning should not fail");
        assert_eq!(db.mailboxes.lock().await.len(), 1);

        // Shift insert timestamps past ttl
        {
            let mut guard = db.mailboxes.lock().await;
            for (ts, _) in guard.insert_order.iter_mut() {
                *ts -= ttl + Duration::from_secs(1);
            }
        }

        assert_eq!(db.mailboxes.lock().await.len(), 1);
        db.prune().await.expect("pruning should not fail");
        assert_eq!(db.mailboxes.lock().await.len(), 0);

        // Empty db should remain empty after prune
        db.prune().await.expect("pruning should not fail");
        assert_eq!(db.mailboxes.lock().await.len(), 0);

        Ok(())
    }

    async fn assert_all_paths_over_capacity(db: &FilesDb) {
        let id = ShortId([0; 8]);

        assert!(matches!(
            db.post_v2_payload(&id, b"data".to_vec()).await,
            Err(DbError::OverCapacity)
        ));

        assert!(matches!(
            db.post_v1_request_and_wait_for_response(&id, b"data".to_vec()).await,
            Err(DbError::OverCapacity)
        ));

        assert!(matches!(db.wait_for_v2_payload(&id).await, Err(DbError::OverCapacity)));
    }

    #[tokio::test]
    async fn test_capacity_post_v2() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = FilesDb::init(
            Duration::from_millis(2),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await?;

        db.mailboxes.lock().await.capacity = 3;

        for i in 1..=3 {
            db.post_v2_payload(&ShortId([i; 8]), b"data".to_vec()).await.unwrap();
        }

        assert_all_paths_over_capacity(&db).await;

        Ok(())
    }

    #[tokio::test]
    async fn test_capacity_post_v1_req_and_wait() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = FilesDb::init(
            Duration::from_secs(60),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await?;

        db.mailboxes.lock().await.capacity = 3;

        for i in 1..=3 {
            let db = db.clone();
            tokio::spawn(async move {
                let _ = db
                    .post_v1_request_and_wait_for_response(&ShortId([i; 8]), b"data".to_vec())
                    .await;
            });
        }

        // wait until all tasks start working
        while db.mailboxes.lock().await.len() < 3 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        assert_all_paths_over_capacity(&db).await;

        Ok(())
    }

    const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 7);

    fn frame(byte: u8) -> Vec<u8> { vec![byte; LOG_FRAME_BYTES] }

    #[test]
    fn test_xor_buffer_at_offset() {
        let storage = DiskStorage { dir: PathBuf::new(), xor: vec![1, 2, 3, 4, 5, 6, 7, 8] };
        let mut whole = vec![0u8; 20];
        storage.xor_buffer(&mut whole);

        let mut tail = vec![0u8; 17];
        storage.xor_buffer_at(&mut tail, 3);
        assert_eq!(tail, whole[3..], "a buffer at an offset continues the pattern");
    }

    #[tokio::test]
    async fn test_log_append_and_read() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
        let id = ShortId([1u8; 8]);

        for byte in 0..3 {
            db.append_log_frame(&id, frame(byte))
                .await
                .expect("appending should succeed")
                .expect("log should accept the frame");
        }
        for byte in 0..3 {
            let got = db.wait_for_log_frame(&id, byte as usize).await.expect("frame should exist");
            assert_eq!(*got, frame(byte), "frames should read back in append order");
        }
        assert!(
            matches!(db.wait_for_log_frame(&id, 3).await, Err(DbError::Timeout(_))),
            "reading past the end should wait and time out"
        );

        let on_disk = fs::read(dir.path().join("logs").join(id.to_string())).await?;
        assert_eq!(on_disk.len(), 3 * LOG_FRAME_BYTES, "frames should be stored back to back");
        assert_ne!(on_disk, [frame(0), frame(1), frame(2)].concat(), "frames should be obfuscated");

        // A v2 mailbox with the same ShortId is a separate, write-once entry
        assert!(matches!(db.wait_for_v2_payload(&id).await, Err(DbError::Timeout(_))));
        db.post_v2_payload(&id, b"v2".to_vec()).await.unwrap().expect("v2 post should succeed");
        assert!(db.post_v2_payload(&id, b"other".to_vec()).await.unwrap().is_none());
        assert_eq!(&db.wait_for_v2_payload(&id).await.unwrap()[..], b"v2");
        assert_eq!(*db.wait_for_log_frame(&id, 0).await.unwrap(), frame(0));

        Ok(())
    }

    #[tokio::test]
    async fn test_log_wait() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = FilesDb::init(Duration::from_secs(10), dir.path().to_owned(), TTL).await?;
        let id = ShortId([1u8; 8]);

        let read_frame = |index| {
            let db = db.clone();
            tokio::spawn(async move { db.wait_for_log_frame(&id, index).await })
        };
        let (reader0a, reader0b, reader1) = (read_frame(0), read_frame(0), read_frame(1));
        while db.mailboxes.lock().await.pending_log.len() < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        db.append_log_frame(&id, frame(0xA)).await.unwrap().expect("first append");
        assert_eq!(*reader0a.await.unwrap().unwrap(), frame(0xA));
        assert_eq!(*reader0b.await.unwrap().unwrap(), frame(0xA));
        assert!(!reader1.is_finished(), "a reader waits for its own frame index");

        db.append_log_frame(&id, frame(0xB)).await.unwrap().expect("second append");
        assert_eq!(*reader1.await.unwrap().unwrap(), frame(0xB));

        Ok(())
    }

    #[tokio::test]
    async fn test_log_frame_limit() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
        let id = ShortId([1u8; 8]);

        db.append_log_frame(&id, frame(0)).await.unwrap().expect("first append");
        db.mailboxes.lock().await.logs.get_mut(&id).expect("log exists").len = MAX_LOG_FRAMES;
        assert!(
            db.append_log_frame(&id, frame(1)).await.unwrap().is_none(),
            "a full log should reject appends"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_log_reload() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let id = ShortId([1u8; 8]);
        {
            let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
            db.append_log_frame(&id, frame(0)).await.unwrap().expect("first append");
            db.append_log_frame(&id, frame(1)).await.unwrap().expect("second append");
        }

        // Simulate an append interrupted partway through a frame
        let path = dir.path().join("logs").join(id.to_string());
        let mut file = fs::OpenOptions::new().append(true).open(&path).await?;
        file.write_all(&[0xFF; 100]).await?;
        drop(file);

        let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
        assert_eq!(db.mailboxes.lock().await.len(), 2, "only whole frames should be counted");
        assert_eq!(*db.wait_for_log_frame(&id, 1).await.unwrap(), frame(1));
        assert!(matches!(db.wait_for_log_frame(&id, 2).await, Err(DbError::Timeout(_))));

        db.append_log_frame(&id, frame(2)).await.unwrap().expect("append after reload");
        assert_eq!(*db.wait_for_log_frame(&id, 2).await.unwrap(), frame(2));
        assert_eq!(fs::metadata(&path).await?.len(), 3 * LOG_FRAME_BYTES as u64);

        Ok(())
    }

    fn log_path(dir: &tempfile::TempDir, id: &ShortId) -> PathBuf {
        dir.path().join("logs").join(id.to_string())
    }

    #[tokio::test]
    async fn test_log_dedup() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
        let id = ShortId([1u8; 8]);

        assert_eq!(db.append_log_frame(&id, frame(0)).await.unwrap(), Some(0));
        assert_eq!(db.append_log_frame(&id, frame(1)).await.unwrap(), Some(1));
        assert_eq!(
            db.append_log_frame(&id, frame(0)).await.unwrap(),
            Some(0),
            "a repeated frame should keep its original index"
        );
        assert_eq!(db.mailboxes.lock().await.len(), 2, "a repeated frame takes no capacity slot");
        assert_eq!(fs::metadata(log_path(&dir, &id)).await?.len(), 2 * LOG_FRAME_BYTES as u64);
        assert!(matches!(db.wait_for_log_frame(&id, 2).await, Err(DbError::Timeout(_))));

        assert_eq!(
            db.append_log_frame(&id, frame(2)).await.unwrap(),
            Some(2),
            "the next new frame should follow the last stored one"
        );
        assert_eq!(*db.wait_for_log_frame(&id, 2).await.unwrap(), frame(2));

        db.mailboxes.lock().await.capacity = 3;
        assert!(matches!(db.append_log_frame(&id, frame(3)).await, Err(DbError::OverCapacity)));
        assert_eq!(
            db.append_log_frame(&id, frame(1)).await.unwrap(),
            Some(1),
            "a repeated frame should still be accepted at capacity"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_log_dedup_after_reload() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let id = ShortId([1u8; 8]);
        {
            let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
            db.append_log_frame(&id, frame(0)).await.unwrap().expect("first append");
            db.append_log_frame(&id, frame(1)).await.unwrap().expect("second append");
        }

        let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
        assert_eq!(db.append_log_frame(&id, frame(1)).await.unwrap(), Some(1));
        assert_eq!(db.append_log_frame(&id, frame(0)).await.unwrap(), Some(0));
        assert_eq!(db.mailboxes.lock().await.len(), 2);
        assert_eq!(fs::metadata(log_path(&dir, &id)).await?.len(), 2 * LOG_FRAME_BYTES as u64);
        assert_eq!(db.append_log_frame(&id, frame(2)).await.unwrap(), Some(2));

        Ok(())
    }

    #[tokio::test]
    async fn test_log_dedup_is_per_log() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = FilesDb::init(Duration::from_millis(1), dir.path().to_owned(), TTL).await?;
        let (id_a, id_b) = (ShortId([1u8; 8]), ShortId([2u8; 8]));

        assert_eq!(db.append_log_frame(&id_a, frame(0)).await.unwrap(), Some(0));
        assert_eq!(
            db.append_log_frame(&id_b, frame(0)).await.unwrap(),
            Some(0),
            "the same frame in another log should be stored there too"
        );
        assert_eq!(db.mailboxes.lock().await.len(), 2, "each log should hold its own copy");
        for id in [id_a, id_b] {
            assert_eq!(fs::metadata(log_path(&dir, &id)).await?.len(), LOG_FRAME_BYTES as u64);
            assert_eq!(*db.wait_for_log_frame(&id, 0).await.unwrap(), frame(0));
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_log_capacity_and_prune() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = FilesDb::init(
            Duration::from_millis(2),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await?;
        let ttl = Duration::from_secs(600);
        {
            let mut guard = db.mailboxes.lock().await;
            guard.capacity = 3;
            guard.ttl = ttl;
        }

        let id = ShortId([1u8; 8]);
        for byte in 0..3 {
            db.append_log_frame(&id, frame(byte)).await.unwrap().expect("append under capacity");
        }
        assert!(
            matches!(db.append_log_frame(&id, frame(3)).await, Err(DbError::OverCapacity)),
            "every log frame should count against capacity"
        );
        assert_all_paths_over_capacity(&db).await;

        {
            let mut guard = db.mailboxes.lock().await;
            for (ts, _) in guard.log_insert_order.iter_mut() {
                *ts -= ttl + Duration::from_secs(1);
            }
        }
        db.prune().await.expect("pruning should not fail");
        assert_eq!(db.mailboxes.lock().await.len(), 0, "an expired log should free its frames");
        assert!(!dir.path().join("logs").join(id.to_string()).exists());
        assert!(matches!(db.wait_for_log_frame(&id, 0).await, Err(DbError::Timeout(_))));

        Ok(())
    }

    #[tokio::test]
    async fn test_capacity_wait_v2() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;

        let db = FilesDb::init(
            Duration::from_secs(60),
            dir.path().to_owned(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await?;

        db.mailboxes.lock().await.capacity = 3;

        for i in 1..=3 {
            let db = db.clone();
            tokio::spawn(async move {
                let _ = db.wait_for_v2_payload(&ShortId([i; 8])).await;
            });
        }

        // wait until all tasks start working
        while db.mailboxes.lock().await.len() < 3 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        assert_all_paths_over_capacity(&db).await;

        Ok(())
    }
}
