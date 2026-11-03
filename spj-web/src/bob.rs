//! Bob's phone: a silent payment wallet that hands out one-time requests
//! and a contact URI, answers each Original that arrives with a coin and
//! a proof, and finds what it received by scanning new blocks.

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
use spj_demo::net::Error;
use spj_demo::persist::EventLog;
use spj_demo::receiver::{Decline, SpReceiver};
use spj_demo::wallet::{KeyKind, Keychain};
use tokio::sync::{mpsc, oneshot};

use crate::shape::{qr_svg, Owners};
use crate::Shared;

pub type Reply = oneshot::Sender<Result<Value, String>>;

pub enum Command {
    /// Show a one-time URI for this amount.
    OneTime { amount: Amount, reply: Reply },
    /// Show Bob's contact URI, creating its log the first time.
    Contact { reply: Reply },
    /// Wake the phone, or put it to sleep. A sleeping phone reads no mailbox
    /// and scans no blocks.
    Awake { awake: bool, reply: Reply },
}

pub struct Bob {
    shared: Arc<Shared>,
    secp: Secp256k1<All>,
    receiver: SpReceiver,
    /// Coins added to payments of one-time requests, whose payers Bob chose.
    one_time_coins: Keychain,
    /// A separate BIP 86 account whose coins are added to payments of the
    /// contact URI, so a regular payer learns nothing of the others.
    contact_coins: Keychain,
    one_time: Option<OneTime>,
    contact: Option<ContactLog>,
    awake: bool,
    /// The last block scanned.
    scanned: u64,
    /// What Bob holds besides his keychains' coins: outputs found by scanning
    /// and payments to a one-time URI's ordinary address.
    received: BTreeMap<OutPoint, Amount>,
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
            received: BTreeMap::new(),
        }
    }

    /// The keychains a demo Bob funds from before the wallets start.
    pub fn keychains() -> (Keychain, Keychain) {
        (
            Keychain::new("bob-hot", "bob", KeyKind::P2tr, 0),
            Keychain::new("bob-keychain", "bob", KeyKind::P2tr, 1),
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
            Command::Contact { reply } => {
                let _ = reply.send(self.contact().await.map_err(|e| e.to_string()));
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
        let one_time =
            flow::one_time(&self.shared.regtest.mailroom, self.receiver.address(), body, amount)?;
        let uri = one_time.uri.to_string();
        let data = json!({ "uri": uri, "amount": amount.to_sat(), "qr": qr_svg(&uri) });
        self.one_time = Some(one_time);
        self.emit("bob.one_time", data.clone());
        Ok(data)
    }

    async fn contact(&mut self) -> Result<Value, Error> {
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
        let log = self.contact.as_ref().expect("created above");
        let uri = log.uri(self.receiver.address(), mailroom).to_string();
        let data = json!({ "uri": uri, "qr": qr_svg(&uri) });
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

    /// Answer an Original: find the payment in it by scanning, add a coin,
    /// re-derive the output over the final inputs, prove the coin's share,
    /// and post the proposal to the payer's reply mailbox.
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
        if let Some(prevouts) = &prevouts {
            for found in derive::scan(&self.secp, &self.receiver.keys, &original_tx, prevouts) {
                let script = original_tx.output[found.vout].script_pubkey.clone();
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
                json!({ "tx": owners.tx(&original_tx, prevouts), "paid": paid, "silent": !silent.is_empty() }),
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

    /// Scan blocks since the last scan, the way a restore would: each
    /// taproot output against Bob's scan key, plus payments to a one-time
    /// URI's ordinary address.
    async fn scan(&mut self) -> Result<(), Error> {
        let client = self.shared.regtest.client();
        let height = chain::height(client)?;
        if height <= self.scanned {
            return Ok(());
        }
        let keys = self.receiver.keys;
        let spend = keys.spend.public_key(&self.secp);
        let index = chain::tweak_index(&self.secp, client, self.scanned + 1, height)?;
        let found = chain::restore(&self.secp, &keys.scan, &spend, &index);
        let mut by_tx: BTreeMap<Txid, (u64, u64, bool)> = BTreeMap::new();
        for f in &found {
            by_tx.entry(f.outpoint.txid).or_default().0 += f.value.to_sat();
            by_tx.entry(f.outpoint.txid).or_default().2 = true;
            self.received.insert(f.outpoint, f.value);
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
                    if self.one_time_coins.owns(&out.script_pubkey) {
                        let outpoint = OutPoint { txid, vout: vout as u32 };
                        self.received.insert(outpoint, out.value);
                        by_tx.entry(txid).or_default().0 += out.value.to_sat();
                    }
                }
                if spent > 0 {
                    by_tx.entry(txid).or_default().1 += spent;
                }
                // A payment received is never offered as a payjoin coin:
                // the next payer would learn of it.
                self.one_time_coins.forget_spent(&tx);
                self.contact_coins.forget_spent(&tx);
            }
        }
        self.scanned = height;
        for (txid, (gross, spent, by_scan)) in by_tx {
            if gross == 0 {
                continue;
            }
            self.emit(
                "bob.received",
                json!({
                    "txid": txid.to_string(),
                    "amount": gross.saturating_sub(spent),
                    "payjoin": spent > 0,
                    "by_scan": by_scan,
                    "height": height,
                    "balance": self.balance(),
                }),
            );
        }
        Ok(())
    }
}
