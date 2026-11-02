//! Six narrated scenes on one regtest chain. Each ends in a verdict read
//! back from the node: which transaction confirmed, what it pays, and what a
//! wallet restored from Bob's seed finds in the chain.

mod s1_todays_clash;
mod s2_stock_sender;
mod s3_silent_payjoin;
mod s4_stolen_mailbox_key;
mod s5_contact_uri;
mod s6_receiver_offline;

use bitcoin::psbt::Input as PsbtInput;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Amount, Script, Transaction, Txid};
use payjoin::receive::v2::{Receiver, UncheckedOriginalPayload};
use payjoin_test_utils::bitcoind;

use crate::chain::{self, Restored};
use crate::contact::{ContactLog, ContactUri};
use crate::contacts::Contacts;
use crate::derive::SpKeys;
use crate::flow::{self, Regtest, Sending, SpOriginal};
use crate::narrate::{sats, short, Narrator};
use crate::net::Error;
use crate::persist::EventLog;
use crate::receiver::{Proposal, SpReceiver};
use crate::sender::{self, Broadcast};
use crate::sp_address::SpAddress;
use crate::wallet::{self, KeyKind, Keychain};

/// Everyone in the scenes, on one chain and one mailroom.
pub struct Demo {
    pub n: Narrator,
    pub regtest: Regtest,
    pub secp: Secp256k1<All>,
    pub bob: SpReceiver,
    /// Bob's coins for one-time URIs, and the addresses in their bodies.
    pub bob_hot: Keychain,
    /// A separate BIP 86 keychain Bob adds from when a contact URI pays him.
    pub bob_contact: Keychain,
    pub alice: Keychain,
    pub alice_contacts: Contacts,
    /// A Bitcoin Core wallet paying through PDK's stock BIP 77 sender.
    pub carol: bitcoind::Client,
    pub funder: Keychain,
    pub mallory: Keychain,
    /// Bob's contact log, created in scene 5 and read again in scene 6.
    pub contact: Option<(ContactLog, ContactUri)>,
    /// Payjoins worth filming, by label.
    pub to_film: Vec<(String, Txid)>,
}

pub async fn setup(n: Narrator) -> Result<Demo, Error> {
    let regtest = Regtest::start().await?;
    let version: serde_json::Value = regtest.client().call("getnetworkinfo", &[])?;
    n.header(
        "SILENT PAYJOIN: six scenes on regtest",
        &format!(
            "bitcoind {}, payjoin-mailroom on localhost, BIP 352/374/375 from spj-crypto",
            version["subversion"].as_str().unwrap_or("?").trim_matches('/')
        ),
    );
    let k = |name: &str, seed: &str, kind, account| Keychain::new(name, seed, kind, account);
    let mut demo = Demo {
        n,
        secp: Secp256k1::new(),
        bob: SpReceiver::new(SpKeys::from_seed("bob")),
        bob_hot: k("bob-hot", "bob", KeyKind::P2tr, 0),
        bob_contact: k("bob-keychain", "bob", KeyKind::P2tr, 1),
        alice: k("alice", "alice", KeyKind::P2tr, 0),
        alice_contacts: Contacts::default(),
        carol: regtest.node.create_wallet("carol")?,
        funder: k("funder", "funder", KeyKind::P2tr, 0),
        mallory: k("mallory", "mallory", KeyKind::P2tr, 0),
        contact: None,
        to_film: Vec::new(),
        regtest,
    };
    let coins = |n, sat| vec![Amount::from_sat(sat); n];
    demo.regtest.fund(&mut demo.bob_hot, &coins(4, 30_000))?;
    demo.regtest.fund(&mut demo.bob_contact, &coins(4, 30_000))?;
    demo.regtest.fund(&mut demo.alice, &coins(6, 200_000))?;
    demo.regtest.fund(&mut demo.funder, &coins(5, 300_000))?;
    demo.regtest.fund(&mut demo.mallory, &coins(4, 40_000))?;
    let carol = demo.carol.new_address()?;
    demo.regtest.client().send_to_address(&carol, Amount::from_sat(500_000))?;
    demo.regtest.mine(1)?;
    demo.n.say(
        "Setup",
        &format!(
            "Bob's sp1 is {}. Bob's coins: 4 for one-time URIs, 4 in a separate BIP 86 keychain",
            demo.bob.address()
        ),
    );
    Ok(demo)
}

pub async fn run_all(demo: &mut Demo) -> Result<(), Error> {
    s1_todays_clash::run(demo).await?;
    s2_stock_sender::run(demo).await?;
    s3_silent_payjoin::run(demo).await?;
    s4_stolen_mailbox_key::run(demo).await?;
    s5_contact_uri::run(demo).await?;
    s6_receiver_offline::run(demo).await?;
    Ok(())
}

impl Demo {
    pub fn client(&self) -> &bitcoind::Client { self.regtest.client() }

    pub fn height(&self) -> Result<u64, Error> { chain::height(self.client()) }

    /// What a wallet restored from Bob's seed finds in blocks after `from`.
    pub fn restore_since(&self, from: u64) -> Result<Vec<Restored>, Error> {
        let index = chain::tweak_index(&self.secp, self.client(), from + 1, self.height()?)?;
        let keys = self.bob.keys;
        Ok(chain::restore(&self.secp, &keys.scan, &keys.spend.public_key(&self.secp), &index))
    }

    pub fn confirmed(&self, txid: Txid) -> Result<bool, Error> {
        Ok(chain::confirmations(self.client(), txid)?.is_some_and(|n| n > 0))
    }

    pub fn tx(&self, txid: Txid) -> Result<Transaction, Error> {
        chain::raw_tx(self.client(), txid)
    }
}

/// The bytes a receiver input's share and proof add to the PSBT.
pub fn carriage_bytes(input: &PsbtInput) -> usize {
    let compact = |n: usize| if n < 0xfd { 1 } else { 3 };
    input
        .proprietary
        .iter()
        .map(|(key, value)| {
            let key_len = 1 + compact(key.prefix.len()) + key.prefix.len() + 1 + key.key.len();
            compact(key_len) + key_len + compact(value.len()) + value.len()
        })
        .sum()
}

/// How a payer's payment settled.
pub enum Settled {
    Payjoin(Transaction),
    /// The Original went out, for this reason.
    Original(Transaction, String),
}

impl Settled {
    pub fn tx(&self) -> &Transaction {
        match self {
            Settled::Payjoin(tx) | Settled::Original(tx, _) => tx,
        }
    }
}

/// A silent payment payer after posting its Original: read the proposal,
/// run the proposal check, sign and broadcast, or broadcast the Original on
/// any failure. Mines the block and returns what confirmed.
#[allow(clippy::too_many_arguments)]
pub async fn payer_settles(
    n: &Narrator,
    regtest: &Regtest,
    secp: &Secp256k1<All>,
    who: &str,
    payee: &str,
    payer: &mut Keychain,
    sp: &SpAddress,
    original: &SpOriginal,
    sending: &Sending,
) -> Result<Settled, Error> {
    let original_tx = original.tx();
    let paid = original_tx
        .output
        .iter()
        .find(|out| out.script_pubkey == original.payee)
        .map(|out| out.value)
        .unwrap_or_default();
    let outcome: Result<Transaction, String> =
        match flow::poll_proposal(&regtest.mailroom, sending).await {
            Ok(Some(mut psbt)) =>
                match sender::check_proposal(secp, sp, &original.psbt, &original.own, &psbt) {
                    Ok(accepted) => {
                        n.check(
                            who,
                            &format!(
                                "S2 check: verifies {} proof(s), derives {payee}'s output itself \
                                 and finds it once, paying {} against the Original's {}: accepted",
                                accepted.shares_verified,
                                sats(accepted.paid),
                                sats(paid)
                            ),
                            true,
                        );
                        payer.sign(&mut psbt)?;
                        let payjoin = wallet::extract(&psbt);
                        match sender::broadcast(regtest.client(), &payjoin, &original_tx)? {
                            Broadcast::Payjoin(txid) => {
                                n.say(
                                    who,
                                    &format!(
                                        "signs and broadcasts the payjoin {}",
                                        short(&txid.to_string())
                                    ),
                                );
                                Ok(payjoin)
                            }
                            Broadcast::Original { refused, .. } => {
                                let why = format!("the node refused the payjoin ({refused})");
                                n.say(who, &format!("{why}. The Original went out instead"));
                                regtest.confirm(&[original_tx.compute_txid()])?;
                                payer.credit(&original_tx);
                                return Ok(Settled::Original(original_tx, why));
                            }
                        }
                    }
                    Err(rejection) => Err(format!("S2: rejected: {rejection}")),
                },
            Ok(None) => Err("no proposal arrived".to_string()),
            Err(e) => Err(format!("PDK's BIP 78 checks refused the proposal: {e}")),
        };
    let settled = match outcome {
        Ok(payjoin) => Settled::Payjoin(payjoin),
        Err(why) => {
            n.say(who, &format!("{why}. Broadcasts the Original instead"));
            chain::broadcast(regtest.client(), &original_tx)?;
            Settled::Original(original_tx, why)
        }
    };
    let txid = settled.tx().compute_txid();
    regtest.confirm(&[txid])?;
    let watched = sender::watch(regtest.client(), txid, &original.tx())?;
    if let Settled::Payjoin(_) = settled {
        n.check(
            who,
            "watches the payjoin through its own node until it confirms",
            watched == sender::Watch::Confirmed,
        );
    }
    payer.credit(settled.tx());
    Ok(settled)
}

/// Bob answers an Original with a coin from `coins`, narrating each rule.
/// Returns the proposal Bob posted, if any.
#[allow(clippy::too_many_arguments)]
pub async fn bob_answers(
    n: &Narrator,
    regtest: &Regtest,
    bob: &mut SpReceiver,
    coins: &mut Keychain,
    source: &str,
    payer: &str,
    received: Receiver<UncheckedOriginalPayload>,
    log: &EventLog,
    body: Option<&Script>,
) -> Result<Option<Proposal>, Error> {
    let proposal = match bob.propose(regtest.client(), received, log, coins, body) {
        Ok(proposal) => proposal,
        Err(decline) => {
            n.say("Bob", &format!("posts nothing: {decline}"));
            return Ok(None);
        }
    };
    let coin = &proposal.coin;
    for found in &proposal.found {
        n.say(
            "Bob",
            &format!(
                "scans the Original and finds an output k={} paying the sp1 ({})",
                found.k,
                sats(found.value)
            ),
        );
    }
    let what = if proposal.derived.is_empty() {
        "keeps the output, which pays the URI's ordinary address".to_string()
    } else {
        format!(
            "re-derives the output over all inputs: {}",
            short(&proposal.derived[0].to_hex_string()[4..])
        )
    };
    n.say(
        "Bob",
        &format!(
            "adds coin {} ({}) from {source} and {what}",
            sender::short_outpoint(&coin.outpoint),
            sats(coin.txout.value)
        ),
    );
    if let Some(share) = proposal.share {
        let psbt = proposal.receiver.psbt();
        let index = psbt
            .unsigned_tx
            .input
            .iter()
            .position(|input| input.previous_output == coin.outpoint)
            .expect("the coin is in the proposal");
        n.say(
            "Bob",
            &format!(
                "attaches the share C = a·B_scan ({}) and a 64-byte BIP 374 proof that it was made \
                 with the coin's own key. Wire size for this input: {} bytes",
                short(&share.to_string()),
                carriage_bytes(&psbt.inputs[index])
            ),
        );
        n.check(
            "Bob",
            "R4 self-check: scans the finished proposal as a restore would, and runs the sender's \
             share check on it",
            true,
        );
    }
    flow::post_proposal(&regtest.mailroom, &proposal.receiver, log).await?;
    n.say("Bob", &format!("posts the proposal to {payer}'s reply mailbox"));
    Ok(Some(proposal))
}

/// The restore finds an output in `txid` paying at least `at_least`.
pub fn restored_in(found: &[Restored], txid: Txid, at_least: Amount) -> bool {
    found.iter().any(|f| f.outpoint.txid == txid && f.value >= at_least)
}
