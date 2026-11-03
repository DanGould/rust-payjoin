//! Bob's phone: a silent payment wallet that hands out one-time URIs, each
//! with a fresh ordinary address and his unlabelled silent payment address,
//! and a contact URI on the contact's own label. It answers each Original
//! that arrives with a coin: an Original to a one-time URI's address becomes
//! an ordinary payjoin, and one to his silent payment address a Silent
//! Payjoin, with the output re-derived and a proof for the coin. It finds
//! what it received by scanning new blocks.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use payjoin::receive::v2::{Receiver, UncheckedOriginalPayload};
use payjoin::{HpkeKeyPair, Url};
use serde_json::{json, Value};
use spj_demo::chain;
use spj_demo::contact::ContactLog;
use spj_demo::derive::{self, SpKeys};
use spj_demo::flow::{self, OneTime};
use spj_demo::labels::Purpose;
use spj_demo::net::Error;
use spj_demo::persist::EventLog;
use spj_demo::receiver::{Decline, SpReceiver};
use spj_demo::wallet::{KeyKind, Keychain};
use tokio::sync::{mpsc, oneshot};

use crate::shape::{qr_svg, Owners};
use crate::Shared;

pub type Reply = oneshot::Sender<Result<Value, String>>;

/// The seed of Bob's wallet, which his backup words stand for.
const SEED: &str = "bob";
/// The BIP 86 account whose addresses go in one-time URIs.
const ONE_TIME_ACCOUNT: u32 = 0;
/// How many unused receive addresses in a row a restored wallet derives
/// before it stops looking, as BIP 44 sets it.
const GAP_LIMIT: u32 = 20;

pub enum Command {
    /// Show a one-time URI for this amount.
    OneTime { amount: Amount, reply: Reply },
    /// Show Bob's contact URI for the contact named `name`, creating its log
    /// the first time.
    Contact { name: String, reply: Reply },
    /// Wake the phone, or put it to sleep. A sleeping phone reads no mailbox
    /// and scans no blocks.
    Awake { awake: bool, reply: Reply },
}

pub struct Bob {
    shared: Arc<Shared>,
    secp: Secp256k1<All>,
    receiver: SpReceiver,
    /// The account whose fresh addresses go in one-time URIs, and whose
    /// coins Bob adds to their payjoins.
    one_time_coins: Keychain,
    /// A separate BIP 86 account whose coins are added to payments of the
    /// contact URI, so a regular payer learns nothing of the others.
    contact_coins: Keychain,
    one_time: Option<OneTime>,
    contact: Option<ContactLog>,
    awake: bool,
    /// The last block scanned.
    scanned: u64,
    /// Every block's tweak entries since Bob started, which a wallet
    /// restored from his backup words would scan.
    index: Vec<chain::TweakEntry>,
    /// What Bob holds besides his keychains' coins: outputs found by scanning
    /// and payments to a one-time URI's ordinary address.
    received: BTreeMap<OutPoint, Amount>,
    /// Every output script in the blocks scanned, which a restored wallet
    /// checks its ordinary addresses against.
    on_chain: BTreeSet<ScriptBuf>,
}

impl Bob {
    pub fn new(shared: Arc<Shared>, one_time_coins: Keychain, contact_coins: Keychain) -> Self {
        let scanned = chain::height(shared.regtest.client()).unwrap_or_default();
        Self {
            shared,
            secp: Secp256k1::new(),
            receiver: SpReceiver::new(SpKeys::from_seed("bob")),
            one_time_coins,
            contact_coins,
            one_time: None,
            contact: None,
            awake: true,
            scanned,
            index: Vec::new(),
            received: BTreeMap::new(),
            on_chain: BTreeSet::new(),
        }
    }

    /// The keychains a demo Bob funds from before the wallets start.
    pub fn keychains() -> (Keychain, Keychain) {
        (
            Keychain::new("bob-hot", SEED, KeyKind::P2tr, ONE_TIME_ACCOUNT),
            Keychain::new("bob-keychain", SEED, KeyKind::P2tr, 1),
        )
    }

    fn emit(&self, kind: &str, data: Value) { self.shared.hub.emit(kind, data) }

    async fn pace(&self) { self.shared.hub.pace().await }

    fn balance(&self) -> u64 {
        let held: Amount = self.received.values().copied().sum();
        (self.one_time_coins.balance() + self.contact_coins.balance() + held).to_sat()
    }

    pub async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        self.emit(
            "bob.ready",
            json!({ "balance": self.balance(), "sp": self.receiver.address().to_string() }),
        );
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.command(command).await,
                    None => return,
                },
                _ = tokio::time::sleep(Duration::from_millis(300)) => {
                    if let Err(e) = self.tick().await {
                        self.emit("bob.error", json!({ "error": e.to_string() }));
                    }
                }
            }
        }
    }

    async fn command(&mut self, command: Command) {
        match command {
            Command::OneTime { amount, reply } => {
                let _ = reply.send(self.one_time(amount).map_err(|e| e.to_string()));
            }
            Command::Contact { name, reply } => {
                let _ = reply.send(self.contact(&name).await.map_err(|e| e.to_string()));
            }
            Command::Awake { awake, reply } => {
                self.awake = awake;
                self.emit("bob.awake", json!({ "awake": awake }));
                let _ = reply.send(Ok(json!({ "awake": awake })));
            }
        }
    }

    fn one_time(&mut self, amount: Amount) -> Result<Value, Error> {
        let body = self.one_time_coins.address();
        let sp = self.receiver.address();
        let one_time = flow::one_time(&self.shared.regtest.mailroom, sp, body, amount)?;
        let uri = one_time.uri.to_string();
        let data = json!({ "uri": uri, "amount": amount.to_sat(), "qr": qr_svg(&uri) });
        self.one_time = Some(one_time);
        self.emit("bob.one_time", data.clone());
        Ok(data)
    }

    async fn contact(&mut self, name: &str) -> Result<Value, Error> {
        let mailroom = &self.shared.regtest.mailroom;
        if self.contact.is_none() {
            let log = ContactLog::new(
                HpkeKeyPair::gen_keypair(),
                self.contact_coins.address(),
                Url::parse(mailroom.directory_url())?,
            );
            log.create(mailroom).await?;
            self.contact = Some(log);
        }
        let (label, sp) = self.receiver.contact_address(name);
        let log = self.contact.as_ref().expect("created above");
        let uri = log.uri(sp, mailroom).to_string();
        let data = json!({ "uri": uri, "qr": qr_svg(&uri), "label": label, "contact": name });
        self.emit("bob.contact", data.clone());
        Ok(data)
    }

    async fn tick(&mut self) -> Result<(), Error> {
        if !self.awake {
            return Ok(());
        }
        let mailroom = &self.shared.regtest.mailroom;
        if let Some(one_time) = &self.one_time {
            let session = one_time.session.clone();
            if let Some(original) = flow::poll_original(mailroom, session, &one_time.log).await? {
                let one_time = self.one_time.take().expect("checked above");
                let body = one_time.uri.address.script_pubkey();
                self.answer(original, &one_time.log, Some(body), false).await?;
            }
        }
        let next = match self.contact.as_mut() {
            Some(log) => log.next(&self.shared.regtest.mailroom).await?,
            None => None,
        };
        if let Some(inbound) = next {
            let log = EventLog::copy_of(&inbound.persister)?;
            self.answer(inbound.receiver, &log, None, true).await?;
        }
        self.scan().await
    }

    /// Answer an Original: find what pays Bob in it, add a coin, and post
    /// the proposal to the payer's reply mailbox. An output to his silent
    /// payment address is re-derived over the final inputs, with a proof of
    /// the coin's share.
    async fn answer(
        &mut self,
        original: Receiver<UncheckedOriginalPayload>,
        log: &EventLog,
        body: Option<ScriptBuf>,
        contact: bool,
    ) -> Result<(), Error> {
        let client = self.shared.regtest.client();
        let original_tx = original.extract_tx_to_check_broadcast_suitability();
        let prevouts = chain::prevouts(client, &original_tx).ok();
        self.emit("bob.original", json!({ "contact": contact }));
        self.pace().await;

        let mut mine: Vec<ScriptBuf> = body.iter().cloned().collect();
        let mut silent = Vec::new();
        let mut label = None;
        if let Some(prevouts) = &prevouts {
            for found in derive::scan(
                &self.secp,
                &self.receiver.keys,
                self.receiver.labels.table(),
                &original_tx,
                prevouts,
            ) {
                let script = original_tx.output[found.vout].script_pubkey.clone();
                label = label.or(found.label);
                mine.push(script.clone());
                silent.push(script);
            }
            let none = BTreeSet::new();
            let owners =
                Owners { payer: "payer", bob_inputs: &none, bob_outputs: &mine, silent: &silent };
            let paid: u64 = original_tx
                .output
                .iter()
                .filter(|out| mine.contains(&out.script_pubkey))
                .map(|out| out.value.to_sat())
                .sum();
            self.emit(
                "bob.found",
                json!({
                    "tx": owners.tx(&original_tx, prevouts),
                    "paid": paid,
                    "silent": !silent.is_empty(),
                    "label": label,
                }),
            );
            self.pace().await;
        }

        let coins = if contact { &mut self.contact_coins } else { &mut self.one_time_coins };
        let proposal = match self.receiver.propose(client, original, log, coins, body.as_deref()) {
            Ok(proposal) => proposal,
            Err(decline) => {
                let already_paid = matches!(decline, Decline::InputsUnavailable);
                self.emit(
                    "bob.declined",
                    json!({ "reason": decline.to_string(), "already_paid": already_paid }),
                );
                return Ok(());
            }
        };
        let bob_inputs = BTreeSet::from([proposal.coin.outpoint]);
        let mut bob_outputs: Vec<ScriptBuf> = body.iter().cloned().collect();
        bob_outputs.extend(proposal.derived.iter().cloned());
        let owners = Owners {
            payer: "payer",
            bob_inputs: &bob_inputs,
            bob_outputs: &bob_outputs,
            silent: &proposal.derived,
        };
        let psbt = proposal.receiver.psbt().clone();
        self.emit(
            "bob.coin",
            json!({
                "tx": owners.psbt(self.shared.regtest.client(), &psbt),
                "coin": proposal.coin.txout.value.to_sat(),
                "rederived": !proposal.derived.is_empty(),
                "proofs": usize::from(proposal.share.is_some()),
                "from": if contact { "contact" } else { "one_time" },
            }),
        );
        self.pace().await;
        self.pace().await;
        flow::post_proposal(&self.shared.regtest.mailroom, &proposal.receiver, log).await?;
        self.emit(
            "bob.proposal_sent",
            json!({ "tx": owners.psbt(self.shared.regtest.client(), &psbt) }),
        );
        Ok(())
    }

    /// Scan blocks since the last scan: each taproot output against Bob's
    /// scan key and the labels he handed out, plus payments to a one-time
    /// URI's ordinary address. Each transfer found is also looked for the
    /// way a wallet restored from his backup words would, over every block
    /// so far: silent payments by scanning without knowing any labels,
    /// ordinary addresses by deriving them up to the gap limit.
    async fn scan(&mut self) -> Result<(), Error> {
        let client = self.shared.regtest.client();
        let height = chain::height(client)?;
        if height <= self.scanned {
            return Ok(());
        }
        let keys = self.receiver.keys;
        let spend = keys.spend.public_key(&self.secp);
        let index = chain::tweak_index(&self.secp, client, self.scanned + 1, height)?;
        let labels = self.receiver.labels.table();
        let found = chain::scan_index(&self.secp, &keys.scan, &spend, labels, &index);
        self.index.extend(index);
        let restored: BTreeSet<OutPoint> =
            chain::restore(&self.secp, &keys.scan, &spend, &self.index)
                .into_iter()
                .map(|r| r.outpoint)
                .collect();
        let mut by_tx: BTreeMap<Txid, Received> = BTreeMap::new();
        for f in &found {
            let entry = by_tx.entry(f.outpoint.txid).or_default();
            entry.gross += f.value.to_sat();
            entry.by_scan = true;
            entry.label = entry.label.or(f.label);
            entry.restored = Some(entry.restored.unwrap_or(true) && restored.contains(&f.outpoint));
            self.received.insert(f.outpoint, f.value);
            self.receiver.record_silent_coin(f.outpoint);
        }
        for h in self.scanned + 1..=height {
            for tx in chain::block(client, h)? {
                if tx.is_coinbase() {
                    continue;
                }
                let txid = tx.compute_txid();
                let own_coin = |k: &Keychain, op: &OutPoint| {
                    k.coins().iter().find(|c| c.outpoint == *op).map(|c| c.txout.value.to_sat())
                };
                let spent: u64 = tx
                    .input
                    .iter()
                    .filter_map(|i| {
                        own_coin(&self.one_time_coins, &i.previous_output)
                            .or_else(|| own_coin(&self.contact_coins, &i.previous_output))
                    })
                    .sum();
                for (vout, out) in tx.output.iter().enumerate() {
                    self.on_chain.insert(out.script_pubkey.clone());
                    if self.one_time_coins.owns(&out.script_pubkey) {
                        let outpoint = OutPoint { txid, vout: vout as u32 };
                        self.received.insert(outpoint, out.value);
                        let entry = by_tx.entry(txid).or_default();
                        entry.gross += out.value.to_sat();
                        entry.ordinary.push(out.script_pubkey.clone());
                    }
                }
                if spent > 0 {
                    by_tx.entry(txid).or_default().spent += spent;
                }
                // A payment received is never offered as a payjoin coin:
                // the next payer would learn of it.
                self.one_time_coins.forget_spent(&tx);
                self.contact_coins.forget_spent(&tx);
            }
        }
        self.scanned = height;
        let restored_ordinary = restore_ordinary(&self.on_chain);
        for (txid, mut received) in by_tx {
            if received.gross == 0 {
                continue;
            }
            if !received.ordinary.is_empty() {
                let found = received.ordinary.iter().all(|s| restored_ordinary.contains(s));
                received.restored = Some(received.restored.unwrap_or(true) && found);
            }
            let label_for = received.label.and_then(|m| match self.receiver.labels.purpose(m)? {
                Purpose::Contact(name) => Some(name.clone()),
                _ => None,
            });
            self.emit(
                "bob.received",
                json!({
                    "txid": txid.to_string(),
                    "amount": received.gross.saturating_sub(received.spent),
                    "payjoin": received.spent > 0,
                    "by_scan": received.by_scan,
                    "label": received.label,
                    "label_for": label_for,
                    "restored": received.restored,
                    "height": height,
                    "balance": self.balance(),
                }),
            );
        }
        Ok(())
    }
}

/// The addresses of Bob's one-time account that a wallet restored from his
/// backup words finds paid in `on_chain`: it derives them in order, and
/// stops after [`GAP_LIMIT`] in a row that nothing pays.
fn restore_ordinary(on_chain: &BTreeSet<ScriptBuf>) -> BTreeSet<ScriptBuf> {
    let mut restored = Keychain::new("restored", SEED, KeyKind::P2tr, ONE_TIME_ACCOUNT);
    let mut found = BTreeSet::new();
    let mut unused = 0;
    while unused < GAP_LIMIT {
        let script = restored.address().script_pubkey();
        if on_chain.contains(&script) {
            found.insert(script);
            unused = 0;
        } else {
            unused += 1;
        }
    }
    found
}

/// What one transaction brought Bob.
#[derive(Default)]
struct Received {
    gross: u64,
    /// Bob's own coins it spent.
    spent: u64,
    by_scan: bool,
    /// The label its silent payment output pays.
    label: Option<u32>,
    /// Its outputs to addresses of Bob's one-time account.
    ordinary: Vec<ScriptBuf>,
    /// Whether a restore from Bob's backup words finds every output in it
    /// that pays Bob. `None` when it has none.
    restored: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restore_finds_ordinary_addresses_up_to_the_gap_limit() {
        let (mut one_time, _) = Bob::keychains();
        let scripts: Vec<ScriptBuf> =
            (0..=GAP_LIMIT + 10).map(|_| one_time.address().script_pubkey()).collect();
        let near = scripts[4].clone();
        let far = scripts[4 + GAP_LIMIT as usize + 1].clone();
        let restored = restore_ordinary(&BTreeSet::from([near.clone(), far.clone()]));
        assert!(restored.contains(&near));
        assert!(!restored.contains(&far), "past the gap limit");
    }
}
