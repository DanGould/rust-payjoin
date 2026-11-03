//! What the page renders: every step each wallet takes, as it happens.
//!
//! Both phones and the transaction between them are drawn from this one
//! stream. A page that loads late, or reloads after the recorder visited the
//! explorer, gets the history first and then the live events, so its state
//! never depends on having watched from the start.
//!
//! A recording sets the pace. In held mode a wallet that has taken a step
//! waits until the recorder lets it go on, so a step never goes by before
//! the voiceover has said what it is. The recorder lets the wallets run until
//! a given event, which may take several steps by several wallets.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{broadcast, watch};

pub struct Hub {
    tx: broadcast::Sender<Value>,
    history: Mutex<Vec<Value>>,
    seq: AtomicU64,
    pace_ms: AtomicU64,
    held: AtomicBool,
    /// The last event the recorder released.
    released: watch::Sender<u64>,
    /// How many of each kind of event have been emitted.
    counts: Mutex<HashMap<String, u64>>,
    /// Run without holding until this many events of this kind are out.
    until: Mutex<Option<(String, u64)>>,
}

impl Hub {
    /// A hub whose wallets pause `pace` between steps.
    pub fn new(pace: Duration) -> Self {
        let (tx, _) = broadcast::channel(512);
        Self {
            tx,
            history: Mutex::new(Vec::new()),
            seq: AtomicU64::new(1),
            pace_ms: AtomicU64::new(pace.as_millis() as u64),
            held: AtomicBool::new(false),
            released: watch::Sender::new(0),
            counts: Mutex::new(HashMap::new()),
            until: Mutex::new(None),
        }
    }

    /// Change the pause between steps, and whether steps wait for a release.
    pub fn set_pace(&self, pace: Option<Duration>, held: Option<bool>) {
        if let Some(pace) = pace {
            self.pace_ms.store(pace.as_millis() as u64, Ordering::SeqCst);
        }
        if let Some(held) = held {
            self.held.store(held, Ordering::SeqCst);
            if !held {
                self.release();
            }
        }
    }

    /// Let every step taken so far go on.
    pub fn release(&self) { self.released.send_replace(self.seq.load(Ordering::SeqCst) - 1); }

    /// Let the wallets run until the `n`th event of `kind` since the start
    /// is out, then hold again.
    pub fn release_until(&self, kind: String, n: u64) {
        *self.until.lock().expect("not poisoned") = Some((kind, n));
        self.release();
    }

    fn running(&self) -> bool {
        let until = self.until.lock().expect("not poisoned");
        let counts = self.counts.lock().expect("not poisoned");
        until.as_ref().is_some_and(|(kind, n)| counts.get(kind).copied().unwrap_or(0) < *n)
    }

    /// The pause after a step. Held, it lasts until the recorder releases
    /// the latest event.
    pub async fn pace(&self) {
        tokio::time::sleep(Duration::from_millis(self.pace_ms.load(Ordering::SeqCst))).await;
        if self.held.load(Ordering::SeqCst) && !self.running() {
            let last = self.seq.load(Ordering::SeqCst) - 1;
            let mut released = self.released.subscribe();
            let _ = released
                .wait_for(|r| *r >= last || !self.held.load(Ordering::SeqCst) || self.running())
                .await;
        }
    }

    /// Announce `kind` (such as `alice.original_sent`) with its data. The page
    /// keys its rendering on the kind.
    pub fn emit(&self, kind: &str, data: Value) {
        let event = json!({
            "seq": self.seq.fetch_add(1, Ordering::SeqCst),
            "kind": kind,
            "data": data,
        });
        println!("event {kind}");
        *self.counts.lock().expect("not poisoned").entry(kind.to_string()).or_default() += 1;
        self.history.lock().expect("not poisoned").push(event.clone());
        // Nobody listening is fine: the history keeps it.
        let _ = self.tx.send(event);
    }

    /// The data of every `kind` event so far.
    pub fn data_of(&self, kind: &str) -> Vec<Value> {
        let history = self.history.lock().expect("not poisoned");
        history
            .iter()
            .filter(|event| event["kind"] == kind)
            .map(|event| event["data"].clone())
            .collect()
    }

    /// The history so far and a receiver for what follows. The receiver is
    /// created first so no event falls between the two; the page drops
    /// duplicates by sequence number.
    pub fn subscribe(&self) -> (Vec<Value>, broadcast::Receiver<Value>) {
        let rx = self.tx.subscribe();
        let history = self.history.lock().expect("not poisoned").clone();
        (history, rx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn held_steps_wait_for_a_release_and_run_until_the_named_event() {
        let hub = Arc::new(Hub::new(Duration::ZERO));
        hub.set_pace(None, Some(true));
        let walker = {
            let hub = hub.clone();
            tokio::spawn(async move {
                for step in ["a", "b", "c", "d"] {
                    hub.emit(step, json!({}));
                    hub.pace().await;
                }
            })
        };
        let count =
            |hub: &Hub, kind: &str| hub.counts.lock().unwrap().get(kind).copied().unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!((count(&hub, "a"), count(&hub, "b")), (1, 0), "held after the first step");
        hub.release_until("c".into(), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!((count(&hub, "c"), count(&hub, "d")), (1, 0), "ran to c and held there");
        hub.release();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(count(&hub, "d"), 1, "released past c");
        hub.set_pace(None, Some(false));
        walker.await.unwrap();
    }
}
