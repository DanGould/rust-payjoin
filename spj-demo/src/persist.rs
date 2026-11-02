//! A receiver session log that can carry BIP 375 shares to the sender.
//!
//! PDK's receiver rebuilds the proposal PSBT from an allow-list of BIP 78
//! fields when it finalizes, which drops the proprietary share and proof
//! pairs a silent payjoin receiver must attach to its inputs. The finalized
//! proposal is also the `FinalizedProposal` event in the session log, and a
//! session replayed from its log carries that event's PSBT as is. So the demo
//! rewrites that event to add the pairs and replays the session to send them,
//! without changing the payjoin library.

use std::convert::Infallible;
use std::sync::Mutex;

use bitcoin::Psbt;
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::{
    replay_event_log, PayjoinProposal, ReceiveSession, Receiver, SessionEvent,
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// An in-memory receiver session log.
#[derive(Default)]
pub struct EventLog {
    events: Mutex<Vec<SessionEvent>>,
}

impl EventLog {
    /// A copy of another persister's events, to continue its session here.
    pub fn copy_of(
        persister: &impl SessionPersister<SessionEvent = SessionEvent>,
    ) -> Result<Self, Error> {
        let events = persister.load().map_err(|e| e.to_string())?.collect();
        Ok(Self { events: Mutex::new(events) })
    }

    pub fn events(&self) -> Vec<SessionEvent> { self.events.lock().expect("not poisoned").clone() }

    /// Whether the Original arrived from a BIP 77 sender, which encrypts it
    /// end to end and gives a reply key. `None` before the Original arrived.
    pub fn from_v2_sender(&self) -> Option<bool> {
        self.events.lock().expect("not poisoned").iter().find_map(|event| match event {
            SessionEvent::RetrievedOriginalPayload { reply_key, .. } => Some(reply_key.is_some()),
            _ => None,
        })
    }

    /// Edit the finalized proposal PSBT and return the session as replayed
    /// from the edited log.
    pub fn edit_proposal(
        &self,
        edit: impl FnOnce(&mut Psbt),
    ) -> Result<Receiver<PayjoinProposal>, Error> {
        {
            let mut events = self.events.lock().expect("not poisoned");
            let psbt = events
                .iter_mut()
                .rev()
                .find_map(|event| match event {
                    SessionEvent::FinalizedProposal(psbt) => Some(psbt),
                    _ => None,
                })
                .ok_or("the session has no finalized proposal")?;
            edit(psbt);
        }
        match replay_event_log(self).map_err(|e| e.to_string())?.0 {
            ReceiveSession::PayjoinProposal(receiver) => Ok(receiver),
            _ => Err("the replayed session isn't holding a proposal".into()),
        }
    }
}

impl SessionPersister for EventLog {
    type InternalStorageError = Infallible;
    type SessionEvent = SessionEvent;

    fn save_event(&self, event: SessionEvent) -> Result<(), Infallible> {
        self.events.lock().expect("not poisoned").push(event);
        Ok(())
    }

    fn load(&self) -> Result<Box<dyn Iterator<Item = SessionEvent>>, Infallible> {
        Ok(Box::new(self.events().into_iter()))
    }

    // The log ends with the event that closed it, which replay reads.
    fn close(&self) -> Result<(), Infallible> { Ok(()) }
}
