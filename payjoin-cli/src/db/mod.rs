use std::collections::BTreeSet;
use std::path::Path;

use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::OutPoint;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};

pub(crate) mod error;
use error::*;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

pub(crate) const DB_PATH: &str = "payjoin.sqlite";

#[derive(Debug)]
pub(crate) struct Database(Pool<SqliteConnectionManager>);

impl Database {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        // locking_mode is a per-connection PRAGMA, so it must be set via
        // with_init to apply to every connection the pool creates, not only
        // the first one used during init_schema.
        let manager = SqliteConnectionManager::file(path.as_ref())
            .with_init(|conn| conn.execute_batch("PRAGMA locking_mode = EXCLUSIVE;"));
        let pool = Pool::new(manager)?;

        // Initialize database schema
        let conn = pool.get()?;
        Self::init_schema(&conn)?;

        Ok(Self(pool))
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_sessions (
                session_id TEXT PRIMARY KEY,
                pj_uri TEXT NOT NULL,
                receiver_pubkey BLOB NOT NULL,
                completed_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_sessions (
                session_id TEXT PRIMARY KEY,
                completed_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES send_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES receive_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS inputs_seen (
                outpoint BLOB PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    pub(crate) fn get_connection(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        Ok(self.0.get()?)
    }

    /// Whether a proposal spending `input` has already been answered.
    pub(crate) fn is_input_seen(&self, input: OutPoint) -> Result<bool> {
        let conn = self.get_connection()?;
        let seen: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM inputs_seen WHERE outpoint = ?1)",
            params![serialize(&input)],
            |row| row.get(0),
        )?;
        Ok(seen)
    }

    /// Record `inputs` as seen, or return the ones already recorded and
    /// record nothing.
    ///
    /// Call this only once the session has committed to its answer: after the
    /// transition that depends on the check is persisted (v2), or once the
    /// proposal is built (v1). A record written earlier outlives a transition
    /// that fails to persist, so the resumed session re-runs the check, finds
    /// its own sender's inputs, and rejects them as a replay.
    ///
    /// The insert is also the claim on the inputs. Concurrent sessions can
    /// all pass [`Self::is_input_seen`] before any of them records, and only
    /// the first to record gets an empty result here. A session that loses
    /// the claim answers with nothing, so none of its inputs are recorded.
    pub(crate) fn record_inputs_seen(
        &self,
        inputs: impl IntoIterator<Item = OutPoint>,
    ) -> Result<Vec<OutPoint>> {
        let mut conn = self.get_connection()?;
        let tx = conn.transaction()?;
        let mut already_recorded = Vec::new();
        for input in inputs.into_iter().collect::<BTreeSet<_>>() {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO inputs_seen (outpoint, created_at) VALUES (?1, ?2)",
                params![serialize(&input), now()],
            )?;
            if inserted == 0 {
                already_recorded.push(input);
            }
        }
        if already_recorded.is_empty() {
            tx.commit()?;
        } else {
            tx.rollback()?;
        }
        Ok(already_recorded)
    }
}

#[cfg(test)]
impl Database {
    pub(crate) fn in_memory() -> std::sync::Arc<Self> {
        // Every `:memory:` connection is its own database, so the pool must
        // never open a second one.
        let manager = SqliteConnectionManager::memory()
            .with_init(|conn| conn.execute_batch("PRAGMA locking_mode = EXCLUSIVE;"));
        let pool =
            Pool::builder().max_size(1).build(manager).expect("pool creation should succeed");
        Self::init_schema(&pool.get().expect("connection should succeed"))
            .expect("schema init should succeed");
        std::sync::Arc::new(Self(pool))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn outpoint(n: u32) -> OutPoint {
        OutPoint::from_str(&format!(
            "833b085de288cda6ff614c6e8655f61e7ae4f84604a2751998dc25a0d1ba278f:{n}"
        ))
        .expect("valid outpoint")
    }

    #[test]
    fn is_input_seen_reads_without_recording() {
        let db = Database::in_memory();
        assert!(!db.is_input_seen(outpoint(0)).unwrap());
        assert!(!db.is_input_seen(outpoint(0)).unwrap(), "a check must not record the input");
    }

    #[test]
    fn record_inputs_seen_reports_inputs_already_recorded() {
        let db = Database::in_memory();
        assert!(db.record_inputs_seen([outpoint(0), outpoint(1)]).unwrap().is_empty());
        assert!(db.is_input_seen(outpoint(0)).unwrap());
        assert!(db.is_input_seen(outpoint(1)).unwrap());

        let already = db.record_inputs_seen([outpoint(1), outpoint(2)]).unwrap();
        assert_eq!(already, vec![outpoint(1)]);
        assert!(!db.is_input_seen(outpoint(2)).unwrap(), "a lost claim must record nothing");
    }

    #[test]
    fn record_inputs_seen_treats_a_repeated_input_as_one() {
        let db = Database::in_memory();
        assert!(db.record_inputs_seen([outpoint(0), outpoint(0)]).unwrap().is_empty());
        assert!(db.is_input_seen(outpoint(0)).unwrap());
    }
}

#[cfg(feature = "v2")]
pub(crate) mod v2;
