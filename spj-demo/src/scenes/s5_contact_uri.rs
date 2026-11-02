//! Scene 5: a funder pays Bob's contact URI three times. Each payment is
//! appended to Bob's contact log; Bob reads it, adds a coin from a separate
//! BIP 86 keychain with its proof, and the funder checks it like any
//! silent payjoin. A restore finds all three.

use std::time::Duration;

use bitcoin::{Amount, Network};
use payjoin::{HpkeKeyPair, Url};

use super::{bob_answers, payer_settles, restored_in, Demo, Settled};
use crate::contact::{ContactLog, ContactUri};
use crate::flow;
use crate::narrate::{sats, short};
use crate::net::Error;
use crate::persist::EventLog;
use crate::sender::{attempt_gate, Change, Gate, Payment};

const AMOUNT: Amount = Amount::from_sat(100_000);
/// How long the funder waits for Bob's proposal before broadcasting.
const REPLY_BY: Duration = Duration::from_secs(600);

pub async fn run(demo: &mut Demo) -> Result<(), Error> {
    demo.n.scene(5, "A funder pays Bob's contact URI every month");
    let start = demo.height()?;
    let mailroom = &demo.regtest.mailroom;
    let log = ContactLog::new(
        HpkeKeyPair::gen_keypair(),
        demo.bob_contact.address(),
        Url::parse(mailroom.directory_url())?,
    );
    log.create(mailroom).await?;
    let uri = log.uri(demo.bob.address(), mailroom).to_string();
    demo.n.say(
        "Bob",
        &format!(
            "creates a contact log and gives the funder a contact URI once: {}",
            short_uri(&uri)
        ),
    );
    demo.n.why(
        "an organisation paying a person: Bob's wallet adds a coin from a separate BIP 86 \
         keychain, never from the silent payment coins",
    );
    let contact = ContactUri::parse(&uri, Network::Regtest)?;
    let mut book = crate::contacts::Contacts::default();
    let saved = book.save_contact_uri("Bob", &contact);
    demo.n.say(
        "Funder",
        &format!(
            "saves the contact; note: {}",
            saved.note().unwrap_or("none, it has reusable payjoin")
        ),
    );
    let mut log = log;

    let mut payjoins = Vec::new();
    let mut all_checked = true;
    for month in 1..=3 {
        let gate =
            attempt_gate(&contact.sp, &[Payment::SilentPayment(contact.sp)], Change::Ordinary);
        all_checked &= gate == Gate::AttemptPayjoin;
        let original = flow::sp_original(&demo.secp, &mut demo.funder, &contact.sp, AMOUNT)?;
        let sending = flow::post_to_contact(
            &demo.regtest.mailroom,
            &contact,
            &original.psbt,
            &original.payee_address(),
            AMOUNT,
            REPLY_BY,
        )
        .await?;
        demo.n.say(
            "Funder",
            &format!(
                "month {month}: appends a signed Original for {} to Bob's contact log",
                sats(AMOUNT)
            ),
        );
        let inbound = log.next(&demo.regtest.mailroom).await?.ok_or("Bob's log has a frame")?;
        demo.n.say(
            "Bob",
            &format!("the phone is awake and reads frame {} of the contact log", inbound.index),
        );
        let session_log = EventLog::copy_of(&inbound.persister)?;
        let proposal = bob_answers(
            &demo.n,
            &demo.regtest,
            &mut demo.bob,
            &mut demo.bob_contact,
            "the separate BIP 86 keychain",
            "the funder",
            inbound.receiver,
            &session_log,
            None,
        )
        .await?;
        all_checked &= proposal.is_some();
        let settled = payer_settles(
            &demo.n,
            &demo.regtest,
            &demo.secp,
            "Funder",
            "Bob",
            &mut demo.funder,
            &contact.sp,
            &original,
            &sending,
        )
        .await?;
        match settled {
            Settled::Payjoin(payjoin) => {
                demo.bob_contact.credit(&payjoin);
                let has_keychain_coin = proposal.as_ref().is_some_and(|p| {
                    payjoin.input.iter().any(|input| input.previous_output == p.coin.outpoint)
                });
                all_checked &= has_keychain_coin;
                payjoins.push(payjoin.compute_txid());
            }
            Settled::Original(..) => all_checked = false,
        }
    }

    let restored = demo.restore_since(start)?;
    let found = payjoins.iter().filter(|txid| restored_in(&restored, **txid, AMOUNT)).count();
    demo.n.check(
        "Bob",
        &format!("a restore from seed finds {found} of the {} payjoins", payjoins.len()),
        found == 3,
    );
    demo.n.why(
        "the funder learns one coin from Bob's BIP 86 keychain each month. Its history stays in \
         that keychain, so the funder can't trace who else pays Bob",
    );
    let mut confirmed = payjoins.len() == 3;
    for txid in &payjoins {
        confirmed &= demo.confirmed(*txid)?;
    }
    for (month, txid) in payjoins.iter().enumerate() {
        demo.to_film.push((format!("scene5-month{}", month + 1), *txid));
    }
    demo.contact = Some((log, contact));
    demo.n.verdict(
        all_checked && confirmed && found == 3,
        &format!(
            "three silent payjoins {} confirmed, each with a coin from Bob's BIP 86 keychain, and \
             Bob's restore finds all three",
            payjoins.iter().map(|t| short(&t.to_string())).collect::<Vec<_>>().join(", ")
        ),
    );
    Ok(())
}

/// A contact URI shortened for the transcript, keeping its shape.
fn short_uri(uri: &str) -> String {
    match uri.split_once("&pjv2=") {
        Some((sp, rest)) => format!("{}…&pjv2={}…", &sp[..30], &rest[..rest.len().min(40)]),
        None => uri.to_string(),
    }
}
