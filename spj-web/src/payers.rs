//! The payers' phones: Carol, whose wallet knows payjoin but not silent
//! payments; Alice, a silent payment wallet; and an exchange paying its
//! user Bob through his contact string.
//!
//! Each gets the string it pays the way a phone does, from a scan of what
//! Bob's phone shows, and reaches Bob only through the payjoin directory.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction};
use payjoin::send::v2::SenderBuilder;
use payjoin::PjParam;
use payjoin_test_utils::bitcoind;
use serde_json::{json, Value};
use spj_demo::contact::ContactUri;
use spj_demo::contacts::Contacts;
use spj_demo::flow::{self, Sending, SpOriginal};
use spj_demo::net::Error;
use spj_demo::sender::{self, attempt_gate, Broadcast, Change, Gate, Payment};
use spj_demo::sp_address::SpAddress;
use spj_demo::uri::OneTimeUri;
use spj_demo::wallet::{self, Keychain};
use spj_demo::{chain, regtest};
use tokio::sync::mpsc;

use crate::bob::Reply;
use crate::shape::Owners;
use crate::Shared;

pub enum Command {
    /// Pay the string a scan of Bob's phone read.
    Pay { uri: String, reply: Reply },
    /// Save the last one-time request paid as a contact with this name. A
    /// URI carries no name, so the user types one.
    SaveContact { name: String, reply: Reply },
    /// Save Bob's contact string (the exchange only).
    AddContact { uri: String, reply: Reply },
    /// Pay the saved contact (the exchange only). With `reply_by` the payer
    /// waits that long for Bob's proposal before sending its Original as it
    /// is.
    PayContact { amount: Amount, reply_by: Duration, reply: Reply },
}

/// How long a payer waits for a proposal when nothing says otherwise.
const PATIENCE: Duration = Duration::from_secs(60);

/// A payer's coins: a Bitcoin Core wallet for Carol, an in-process keychain
/// for the silent payment wallets.
pub enum Coins {
    Core(bitcoind::Client),
    Keys(Keychain),
}

pub struct Payer {
    shared: Arc<Shared>,
    /// `carol`, `alice` or `exchange`, the prefix of every event it emits.
    name: &'static str,
    secp: Secp256k1<All>,
    coins: Coins,
    contacts: Contacts,
    contact: Option<ContactUri>,
    /// The one-time request paid last, until it is saved as a contact.
    last_paid: Option<OneTimeUri>,
}

impl Payer {
    pub fn new(shared: Arc<Shared>, name: &'static str, coins: Coins) -> Self {
        Self {
            shared,
            name,
            secp: Secp256k1::new(),
            coins,
            contacts: Contacts::default(),
            contact: None,
            last_paid: None,
        }
    }

    fn emit(&self, step: &str, data: Value) {
        self.shared.hub.emit(&format!("{}.{step}", self.name), data)
    }

    async fn pace(&self) { self.shared.hub.pace().await }

    fn client(&self) -> &bitcoind::Client { self.shared.regtest.client() }

    fn balance(&self) -> u64 {
        match &self.coins {
            Coins::Keys(keys) => keys.balance().to_sat(),
            Coins::Core(core) => core
                .call::<f64>("getbalance", &[])
                .ok()
                .and_then(|btc| Amount::from_btc(btc).ok())
                .map(Amount::to_sat)
                .unwrap_or_default(),
        }
    }

    pub async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        self.emit("ready", json!({ "balance": self.balance() }));
        while let Some(command) = commands.recv().await {
            let (result, reply) = match command {
                Command::Pay { uri, reply } => {
                    // Answer at once: the payment plays out in events.
                    let _ = reply.send(Ok(json!({})));
                    (self.pay(&uri).await, None)
                }
                Command::SaveContact { name, reply } => (self.save_contact(&name), Some(reply)),
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

    async fn pay(&mut self, uri: &str) -> Result<Value, Error> {
        match self.name {
            "carol" => self.pay_without_silent_payments(uri).await,
            _ => self.pay_one_time(uri).await,
        }
    }

    /// Carol's wallet: a stock BIP 21 parser and PDK's BIP 77 sender. It
    /// skips `sp=`, which it doesn't know, and pays the address.
    async fn pay_without_silent_payments(&mut self, uri: &str) -> Result<Value, Error> {
        let Coins::Core(core) = &self.coins else { return Err("Carol pays from Core".into()) };
        let pj_uri = payjoin::Uri::try_from(uri)?
            .require_network(Network::Regtest)?
            .check_pj_supported()
            .map_err(|_| "a BIP 77 URI")?;
        let PjParam::V2(pj_param) = pj_uri.extras().pj_param() else {
            return Err("a BIP 77 endpoint".into());
        };
        let amount = pj_uri.amount().ok_or("an amount")?;
        let address = pj_uri.address().clone();
        self.emit(
            "scanned",
            json!({ "amount": amount.to_sat(), "address": address.to_string(), "silent": false }),
        );
        self.pace().await;
        let original = regtest::original_psbt(core, &address, amount)?;
        let persister = Default::default();
        let session = SenderBuilder::from_parts(original.clone(), pj_param, &address, Some(amount))
            .build_recommended(FeeRate::BROADCAST_MIN)?
            .save(&persister)?;
        let mailroom = &self.shared.regtest.mailroom;
        let (request, context) = session.create_v2_post_request(mailroom.relay_url())?;
        let response = mailroom.send(&request).await?;
        let session = session.process_response(&response, context).save(&persister)?;
        let sending = Sending { session, persister };
        let payee = vec![address.script_pubkey()];
        let none = BTreeSet::new();
        let owners =
            Owners { payer: self.name, bob_inputs: &none, bob_outputs: &payee, silent: &[] };
        self.emit("original_sent", json!({ "tx": owners.psbt(self.client(), &original) }));

        let Some(proposal) = self.wait_for_proposal(&sending, PATIENCE).await? else {
            return Err("no proposal arrived".into());
        };
        let theirs = receiver_inputs(&original, &proposal);
        let owners =
            Owners { payer: self.name, bob_inputs: &theirs, bob_outputs: &payee, silent: &[] };
        self.emit(
            "proposal",
            json!({ "tx": owners.psbt(self.client(), &proposal), "checks": "bip78" }),
        );
        self.pace().await;
        let Coins::Core(core) = &self.coins else { unreachable!() };
        let payjoin = regtest::sign_proposal(core, proposal)?;
        self.settle(&payjoin, &owners, None, amount).await
    }

    /// Alice's wallet: reads `sp=` and pays the URI as a silent payjoin.
    async fn pay_one_time(&mut self, uri: &str) -> Result<Value, Error> {
        let uri = OneTimeUri::parse(uri, Network::Regtest)?;
        let amount = uri.amount.ok_or("an amount")?;
        self.emit(
            "scanned",
            json!({ "amount": amount.to_sat(), "sp": uri.sp.to_string(), "silent": true }),
        );
        self.pace().await;
        let gate = attempt_gate(&uri.sp, &[Payment::SilentPayment(uri.sp)], Change::Ordinary);
        let original = self.sp_original(&uri.sp, amount)?;
        let sending = match gate {
            Gate::AttemptPayjoin => Some(
                flow::post_original(
                    &self.shared.regtest.mailroom,
                    &original.psbt,
                    &flow::one_time_param(&uri)?,
                    &original.payee_address(),
                    amount,
                    false,
                )
                .await?,
            ),
            Gate::BroadcastOriginal(_) => None,
        };
        let result = self.settle_silent(&uri.sp, &original, sending, PATIENCE).await?;
        self.last_paid = Some(uri);
        Ok(result)
    }

    fn save_contact(&mut self, name: &str) -> Result<Value, Error> {
        let uri = self.last_paid.take().ok_or("no request paid to save")?;
        let contact = self.contacts.save_one_time(name, &uri);
        let saved =
            json!({ "name": contact.name, "sp": contact.sp.to_string(), "note": contact.note() });
        self.emit("contact_saved", saved.clone());
        Ok(saved)
    }

    fn add_contact(&mut self, uri: &str) -> Result<Value, Error> {
        let contact = ContactUri::parse(uri, Network::Regtest)?;
        let saved = self.contacts.save_contact_uri("Bob", &contact);
        let data = json!({ "name": saved.name, "sp": saved.sp.to_string(), "note": saved.note() });
        self.contact = Some(contact);
        self.emit("contact_saved", data.clone());
        Ok(data)
    }

    async fn pay_contact(&mut self, amount: Amount, reply_by: Duration) -> Result<Value, Error> {
        let contact = self.contact.clone().ok_or("no contact saved")?;
        self.emit("paying", json!({ "amount": amount.to_sat(), "reply_by": reply_by.as_secs() }));
        let original = self.sp_original(&contact.sp, amount)?;
        let sending = flow::post_to_contact(
            &self.shared.regtest.mailroom,
            &contact,
            &original.psbt,
            &original.payee_address(),
            amount,
            reply_by,
        )
        .await?;
        self.settle_silent(&contact.sp, &original, Some(sending), reply_by).await
    }

    fn sp_original(&mut self, sp: &SpAddress, amount: Amount) -> Result<SpOriginal, Error> {
        let Coins::Keys(keys) = &mut self.coins else { return Err("a keychain".into()) };
        flow::sp_original(&self.secp, keys, sp, amount)
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
        self.emit("original_sent", json!({ "tx": owners.psbt(self.client(), &original.psbt) }));
        let proposal = match &sending {
            Some(sending) => self.wait_for_proposal(sending, patience).await?,
            None => None,
        };
        let fallback = |why: &str| json!({ "reason": why });
        let Some(mut proposal) = proposal else {
            self.emit("fallback", fallback("Bob didn't answer in time"));
            self.pace().await;
            return self.settle(&original.tx(), &owners, Some(original), amount).await;
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
                let Coins::Keys(keys) = &self.coins else { unreachable!() };
                keys.sign(&mut proposal)?;
                let payjoin = wallet::extract(&proposal);
                let original_tx = original.tx();
                match sender::broadcast(self.client(), &payjoin, &original_tx)? {
                    Broadcast::Payjoin(_) => self.settle(&payjoin, &owners, None, amount).await,
                    Broadcast::Original { refused, .. } => {
                        self.emit("fallback", fallback(&format!("the node refused it: {refused}")));
                        let owners = Owners {
                            payer: self.name,
                            bob_inputs: &none,
                            bob_outputs: &payee,
                            silent: &payee,
                        };
                        self.settle(&original_tx, &owners, Some(original), amount).await
                    }
                }
            }
            Err(rejection) => {
                self.emit("rejected", fallback(&rejection.to_string()));
                self.pace().await;
                self.settle(&original.tx(), &owners, Some(original), amount).await
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
    /// learn from it.
    /// `amount` is what the payer set out to pay, which Bob's output exceeds
    /// by his own coin in a payjoin.
    async fn settle(
        &mut self,
        tx: &Transaction,
        owners: &Owners<'_>,
        original: Option<&SpOriginal>,
        amount: Amount,
    ) -> Result<Value, Error> {
        let txid = tx.compute_txid();
        if chain::confirmations(self.client(), txid)?.is_none() {
            chain::broadcast(self.client(), tx)?;
        }
        let prevouts = chain::prevouts(self.client(), tx)?;
        let link = self.shared.explorer.as_ref().map(|e| owners.explorer_link(e, txid, tx));
        let payjoin = original.is_none();
        self.emit(
            "broadcast",
            json!({ "txid": txid.to_string(), "tx": owners.tx(tx, &prevouts), "payjoin": payjoin }),
        );
        self.pace().await;
        self.pace().await;
        let height = self.shared.regtest.confirm(&[txid])?;
        if let Coins::Keys(keys) = &mut self.coins {
            keys.credit(tx);
        }
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
