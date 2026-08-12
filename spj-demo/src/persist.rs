//! File-backed session persistence.
//!
//! Sessions in this demo survive process stops (the receiver in the
//! async first-contact scene is down when its payment starts) by
//! replaying JSON-lines event logs from disk, the same way a wallet
//! integration restores state after a restart.

use std::fmt;
use std::io::Write;
use std::marker::PhantomData;
use std::path::PathBuf;

use payjoin::persist::SessionPersister;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct JsonlPersister<E> {
    path: PathBuf,
    _event: PhantomData<E>,
}

impl<E> JsonlPersister<E> {
    pub fn new(path: PathBuf) -> Self { Self { path, _event: PhantomData } }
}

#[derive(Debug)]
pub enum PersistError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "session log io: {e}"),
            Self::Json(e) => write!(f, "session log encoding: {e}"),
        }
    }
}

impl std::error::Error for PersistError {}

impl<E> SessionPersister for JsonlPersister<E>
where
    E: Serialize + DeserializeOwned + 'static,
{
    type InternalStorageError = PersistError;
    type SessionEvent = E;

    fn save_event(&self, event: E) -> Result<(), PersistError> {
        let line = serde_json::to_string(&event).map_err(PersistError::Json)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(PersistError::Io)?;
        writeln!(file, "{line}").map_err(PersistError::Io)
    }

    fn load(&self) -> Result<Box<dyn Iterator<Item = E>>, PersistError> {
        if !self.path.exists() {
            return Ok(Box::new(std::iter::empty()));
        }
        let contents = std::fs::read_to_string(&self.path).map_err(PersistError::Io)?;
        let events = contents
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<Vec<E>, _>>()
            .map_err(PersistError::Json)?;
        Ok(Box::new(events.into_iter()))
    }

    // The log already ends in the terminal event that closed the
    // session; replay reconstructs closure from it.
    fn close(&self) -> Result<(), PersistError> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum ToyEvent {
        Opened(String),
        Closed,
    }

    #[test]
    fn events_replay_in_saved_order_across_instances() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.jsonl");
        let persister = JsonlPersister::<ToyEvent>::new(path.clone());
        persister.save_event(ToyEvent::Opened("hello".into())).expect("save");
        persister.save_event(ToyEvent::Closed).expect("save");

        let restarted = JsonlPersister::<ToyEvent>::new(path);
        let events: Vec<ToyEvent> = restarted.load().expect("load").collect();
        assert_eq!(events, vec![ToyEvent::Opened("hello".into()), ToyEvent::Closed]);
    }

    #[test]
    fn missing_log_loads_as_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persister = JsonlPersister::<ToyEvent>::new(dir.path().join("absent.jsonl"));
        assert_eq!(persister.load().expect("load").count(), 0);
    }
}
