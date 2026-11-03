//! The payers: Alice, whose wallet does payjoin and silent payments, and an
//! exchange paying its user Bob through his contact URI.
//!
//! Each gets the string it pays the way a phone does, from a scan of what
//! Bob's phone shows, and reaches Bob only through the payjoin directory.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut};
use payjoin::{PjParam, PjUri};
use serde_json::{json, Value};
use spj_demo::chain;
use spj_demo::contact::ContactUri;
use spj_demo::contacts::Contacts;
use spj_demo::flow::{self, Sending, SpOriginal};
use spj_demo::net::Error;
use spj_demo::sender::{self, Broadcast};
use spj_demo::sp_address::SpAddress;
use spj_demo::uri::OneTimeUri;
use spj_demo::wallet::{self, Keychain};
use tokio::sync::mpsc;

use crate::bob::Reply;
use crate::shape::Owners;
use crate::Shared;

pub enum Command {
    /// Pay the one-time URI a scan of Bob's phone read: its ordinary
    /// address, as a BIP 77 payjoin. With `silent_only` the payer acts as a
    /// wallet without payjoin, which pays the URI's `sp=` as a plain silent
    /// payment.
    Pay { uri: String, silent_only: bool, reply: Reply },
    /// Save the last one-time URI paid as a contact with this name. A
    /// URI carries no name, so the user types one.
    SaveContact { name: String, reply: Reply },
    /// Note that Bob has this silent payment address on file and ask him
    /// for his contact URI (the exchange only).
    AskContact { sp: String, reply: Reply },
    /// Save Bob's contact URI (the exchange only).
    AddContact { uri: String, reply: Reply },
    /// Pay the saved contact: as a Silent Payjoin through its contact URI,
    /// or as a plain silent payment to a contact saved from a one-time URI.
    /// With `reply_by` the payer waits that long for Bob's proposal before
    /// sending its Original as it is.
    PayContact { amount: Amount, reply_by: Duration, reply: Reply },
}

/// How long a payer waits for a proposal when nothing says otherwise.
const PATIENCE: Duration = Duration::from_secs(60);

pub struct Payer {
    shared: Arc<Shared>,
    /// `alice` or `exchange`, the prefix of every event it emits.
    name: &'static str,
    secp: Secp256k1<All>,
    keys: Keychain,
    contacts: Contacts,
    /// The silent payment address of the contact saved for Bob.
    bob: Option<SpAddress>,
    /// The one-time URI paid last, until it is saved as a contact.
    last_paid: Option<OneTimeUri>,
}

impl Payer {
    pub fn new(shared: Arc<Shared>, name: &'static str, keys: Keychain) -> Self {
        Self {
            shared,
            name,
            secp: Secp256k1::new(),
            keys,
            contacts: Contacts::default(),
            bob: None,
            last_paid: None,
        }
    }

    fn emit(&self, step: &str, data: Value) {
        self.shared.hub.emit(&format!("{}.{step}", self.name), data)
    }

    async fn pace(&self) { self.shared.hub.pace().await }

    fn client(&self) -> &payjoin_test_utils::bitcoind::Client { self.shared.regtest.client() }

    fn balance(&self) -> u64 { self.keys.balance().to_sat() }

    pub async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        self.emit("ready", json!({ "balance": self.balance() }));
        while let Some(command) = commands.recv().await {
            let (result, reply) = match command {
                Command::Pay { uri, silent_only, reply } => {
                    // Answer at once: the transfer plays out in events.
                    let _ = reply.send(Ok(json!({})));
                    (self.pay(&uri, silent_only).await, None)
                }
                Command::SaveContact { name, reply } => (self.save_contact(&name), Some(reply)),
                Command::AskContact { sp, reply } => (self.ask_contact(&sp), Some(reply)),
                Command::AddContact { uri, reply } => (self.add_contact(&uri), Some(reply)),
                Command::PayContact { amount, reply_by, reply } => {
                    let _ = reply.send(Ok(json!({})));
                    (self.pay_contact(amount, reply_by).await, None)
                }
            };
            match (result, reply) {
                (Ok(value), Some(reply)) => {
                    let _ = reply.send(Ok(value));
                }
                (Err(e), Some(reply)) => {
                    let _ = reply.send(Err(e.to_string()));
                }
                (Err(e), None) => self.emit("error", json!({ "error": e.to_string() })),
                (Ok(_), None) => {}
            }
        }
    }

    async fn pay(&mut self, uri: &str, silent_only: bool) -> Result<Value, Error> {
        let uri = OneTimeUri::parse(uri, Network::Regtest)?;
        let amount = uri.amount.ok_or("an amount")?;
        let result = match &uri.payjoin {
            Some(pj_uri) if !silent_only => self.pay_address(pj_uri, amount).await?,
            _ => self.pay_silent(&uri.sp, amount).await?,
        };
        self.last_paid = Some(uri);
        Ok(result)
    }

    /// Pay a one-time URI's ordinary address as a BIP 77 payjoin, with
    /// ordinary change. The address is fresh, which already keeps the
    /// transfer apart from Bob's others, so the URI's `sp=` adds nothing.
    async fn pay_address(&mut self, uri: &PjUri, amount: Amount) -> Result<Value, Error> {
        let PjParam::V2(pj_param) = uri.extras().pj_param() else {
            return Err("a BIP 77 endpoint".into());
        };
        let address = uri.address().clone();
        self.emit(
            "scanned",
            json!({ "amount": amount.to_sat(), "address": address.to_string(), "silent": false }),
        );
        self.pace().await;
        let payee = vec![address.script_pubkey()];
        let coins = self
            .keys
            .select(amount + Amount::from_sat(2_000))
            .ok_or_else(|| format!("{} can't fund {amount}", self.keys.name))?;
        let payment = TxOut { value: amount, script_pubkey: address.script_pubkey() };
        let original = self.keys.original(&coins, vec![payment], flow::ORIGINAL_FEE_RATE)?;
        let original_tx = wallet::extract(&original);
        let sending = flow::post_original(
            &self.shared.regtest.mailroom,
            &original,
            pj_param,
            &address,
            amount,
            false,
        )
        .await?;
        let none = BTreeSet::new();
        let owners =
            Owners { payer: self.name, bob_inputs: &none, bob_outputs: &payee, silent: &[] };
        self.emit(
            "original_sent",
            json!({ "tx": owners.psbt(self.client(), &original), "silent": false }),
        );

        let Some(mut proposal) = self.wait_for_proposal(&sending, PATIENCE).await? else {
            self.emit("fallback", json!({ "reason": "Bob didn't answer in time" }));
            self.pace().await;
            return self.settle(&original_tx, &owners, false, amount).await;
        };
        let theirs = receiver_inputs(&original, &proposal);
        let joined =
            Owners { payer: self.name, bob_inputs: &theirs, bob_outputs: &payee, silent: &[] };
        self.emit(
            "proposal",
            json!({ "tx": joined.psbt(self.client(), &proposal), "checks": "bip78" }),
        );
        self.pace().await;
        self.keys.sign(&mut proposal)?;
        let payjoin = wallet::extract(&proposal);
        match sender::broadcast(self.client(), &payjoin, &original_tx)? {
            Broadcast::Payjoin(_) => self.settle(&payjoin, &joined, true, amount).await,
            Broadcast::Original { refused, .. } => {
                let why = format!("the node refused it: {refused}");
                self.emit("fallback", json!({ "reason": why }));
                self.settle(&original_tx, &owners, false, amount).await
            }
        }
    }

    /// Pay `sp` as a plain silent payment, the way a wallet without payjoin
    /// pays a one-time URI's `sp=`, and any wallet pays a contact saved from
    /// one.
    async fn pay_silent(&mut self, sp: &SpAddress, amount: Amount) -> Result<Value, Error> {
        self.emit(
            "scanned",
            json!({ "amount": amount.to_sat(), "sp": sp.to_string(), "silent": true }),
        );
        self.pace().await;
        let original = self.sp_original(sp, amount)?;
        let payee = vec![original.payee.clone()];
        let none = BTreeSet::new();
        let owners =
            Owners { payer: self.name, bob_inputs: &none, bob_outputs: &payee, silent: &payee };
        self.emit("signed", json!({ "tx": owners.psbt(self.client(), &original.psbt) }));
        self.pace().await;
        self.settle(&original.tx(), &owners, false, amount).await
    }

    fn save_contact(&mut self, name: &str) -> Result<Value, Error> {
        let uri = self.last_paid.take().ok_or("no URI paid to save")?;
        let contact = self.contacts.save_one_time(name, &uri);
        let saved = json!({
            "name": contact.name,
            "sp": contact.sp.to_string(),
            "payjoin": contact.payjoin.is_some(),
        });
        self.bob = Some(contact.sp);
        self.emit("contact_saved", saved.clone());
        Ok(saved)
    }

    fn ask_contact(&mut self, sp: &str) -> Result<Value, Error> {
        let sp: SpAddress = sp.parse()?;
        let asked = json!({ "sp": sp.to_string() });
        self.emit("asked", asked.clone());
        Ok(asked)
    }

    fn add_contact(&mut self, uri: &str) -> Result<Value, Error> {
        let contact = ContactUri::parse(uri, Network::Regtest)?;
        let saved = self.contacts.save_contact_uri("Bob", &contact);
        let data = json!({
            "name": saved.name,
            "sp": saved.sp.to_string(),
            "payjoin": saved.payjoin.is_some(),
        });
        self.bob = Some(contact.sp);
        self.emit("contact_saved", data.clone());
        Ok(data)
    }

    async fn pay_contact(&mut self, amount: Amount, reply_by: Duration) -> Result<Value, Error> {
        let sp = self.bob.ok_or("no contact saved")?;
        let contact = self.contacts.get(&sp).cloned().ok_or("no contact saved")?;
        self.emit("paying", json!({ "amount": amount.to_sat(), "reply_by": reply_by.as_secs() }));
        let Some(contact_uri) = contact.payjoin else {
            return self.pay_silent(&sp, amount).await;
        };
        let original = self.sp_original(&contact_uri.sp, amount)?;
        let sending = flow::post_to_contact(
            &self.shared.regtest.mailroom,
            &contact_uri,
            &original.psbt,
            &original.payee_address(),
            amount,
            reply_by,
        )
        .await?;
        self.settle_silent(&contact_uri.sp, &original, Some(sending), reply_by).await
    }

    fn sp_original(&mut self, sp: &SpAddress, amount: Amount) -> Result<SpOriginal, Error> {
        flow::sp_original(&self.secp, &mut self.keys, sp, amount)
    }

    /// After the Original is posted: wait for Bob's proposal, check it, sign
    /// and broadcast it. Without a proposal that passes, the Original goes
    /// out as a plain silent payment.
    async fn settle_silent(
        &mut self,
        sp: &SpAddress,
        original: &SpOriginal,
        sending: Option<Sending>,
        patience: Duration,
    ) -> Result<Value, Error> {
        let payee = vec![original.payee.clone()];
        let amount = original
            .psbt
            .unsigned_tx
            .output
            .iter()
            .find(|out| out.script_pubkey == original.payee)
            .map(|out| out.value)
            .unwrap_or_default();
        let none = BTreeSet::new();
        let owners =
            Owners { payer: self.name, bob_inputs: &none, bob_outputs: &payee, silent: &payee };
        self.emit(
            "original_sent",
            json!({ "tx": owners.psbt(self.client(), &original.psbt), "silent": true }),
        );
        let proposal = match &sending {
            Some(sending) => self.wait_for_proposal(sending, patience).await?,
            None => None,
        };
        let fallback = |why: &str| json!({ "reason": why });
        let Some(mut proposal) = proposal else {
            self.emit("fallback", fallback("Bob didn't answer in time"));
            self.pace().await;
            return self.settle(&original.tx(), &owners, false, amount).await;
        };
        let theirs = receiver_inputs(&original.psbt, &proposal);
        match sender::check_proposal(&self.secp, sp, &original.psbt, &original.own, &proposal) {
            Ok(accepted) => {
                let outputs: Vec<ScriptBuf> = accepted
                    .payee_vouts
                    .iter()
                    .map(|vout| proposal.unsigned_tx.output[*vout].script_pubkey.clone())
                    .collect();
                let owners = Owners {
                    payer: self.name,
                    bob_inputs: &theirs,
                    bob_outputs: &outputs,
                    silent: &outputs,
                };
                self.emit("proposal", json!({ "tx": owners.psbt(self.client(), &proposal) }));
                self.pace().await;
                self.emit(
                    "checked",
                    json!({
                        "tx": owners.psbt(self.client(), &proposal),
                        "proofs": accepted.shares_verified,
                        "paid": accepted.paid.to_sat(),
                    }),
                );
                self.pace().await;
                self.pace().await;
                self.keys.sign(&mut proposal)?;
                let payjoin = wallet::extract(&proposal);
                let original_tx = original.tx();
                match sender::broadcast(self.client(), &payjoin, &original_tx)? {
                    Broadcast::Payjoin(_) => self.settle(&payjoin, &owners, true, amount).await,
                    Broadcast::Original { refused, .. } => {
                        self.emit("fallback", fallback(&format!("the node refused it: {refused}")));
                        let owners = Owners {
                            payer: self.name,
                            bob_inputs: &none,
                            bob_outputs: &payee,
                            silent: &payee,
                        };
                        self.settle(&original_tx, &owners, false, amount).await
                    }
                }
            }
            Err(rejection) => {
                self.emit("rejected", fallback(&rejection.to_string()));
                self.pace().await;
                self.settle(&original.tx(), &owners, false, amount).await
            }
        }
    }

    async fn wait_for_proposal(
        &self,
        sending: &Sending,
        patience: Duration,
    ) -> Result<Option<Psbt>, Error> {
        let start = Instant::now();
        loop {
            if let Some(psbt) = flow::poll_proposal(&self.shared.regtest.mailroom, sending).await? {
                return Ok(Some(psbt));
            }
            if start.elapsed() >= patience {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Broadcast `tx` (unless it already is), mine it into a block, and
    /// learn from it. `payjoin` says whether Bob added a coin to it.
    /// `amount` is what the payer set out to pay, which Bob's output exceeds
    /// by his own coin in a payjoin.
    async fn settle(
        &mut self,
        tx: &Transaction,
        owners: &Owners<'_>,
        payjoin: bool,
        amount: Amount,
    ) -> Result<Value, Error> {
        let txid = tx.compute_txid();
        if chain::confirmations(self.client(), txid)?.is_none() {
            chain::broadcast(self.client(), tx)?;
        }
        let prevouts = chain::prevouts(self.client(), tx)?;
        let link = self.shared.explorer.as_ref().map(|e| owners.explorer_link(e, txid, tx));
        let silent = !owners.silent.is_empty();
        self.emit(
            "broadcast",
            json!({ "txid": txid.to_string(), "tx": owners.tx(tx, &prevouts), "payjoin": payjoin }),
        );
        self.pace().await;
        self.pace().await;
        let height = self.shared.regtest.confirm(&[txid])?;
        self.keys.credit(tx);
        let paid: u64 = tx
            .output
            .iter()
            .filter(|out| owners.bob_outputs.contains(&out.script_pubkey))
            .map(|out| out.value.to_sat())
            .sum();
        let spent: u64 = prevouts
            .iter()
            .zip(&tx.input)
            .filter(|(_, input)| !owners.bob_inputs.contains(&input.previous_output))
            .map(|(prevout, _)| prevout.value.to_sat())
            .sum();
        let change: u64 = tx
            .output
            .iter()
            .filter(|out| !owners.bob_outputs.contains(&out.script_pubkey))
            .map(|out| out.value.to_sat())
            .sum();
        let data = json!({
            "txid": txid.to_string(),
            "height": height,
            "explorer": link,
            "payjoin": payjoin,
            "silent": silent,
            "sent": spent - change,
            "amount": amount.to_sat(),
            "bob_got": paid,
            "balance": self.balance(),
        });
        self.shared
            .hub
            .emit("chain.block", json!({ "height": height, "txids": [txid.to_string()] }));
        self.emit("confirmed", data.clone());
        Ok(data)
    }
}

/// The inputs a proposal added to the Original.
fn receiver_inputs(original: &Psbt, proposal: &Psbt) -> BTreeSet<OutPoint> {
    let ours: BTreeSet<OutPoint> =
        original.unsigned_tx.input.iter().map(|input| input.previous_output).collect();
    proposal
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .filter(|outpoint| !ours.contains(outpoint))
        .collect()
}
