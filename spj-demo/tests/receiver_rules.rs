//! The receiver's rules, each test named after the silent payjoin harness
//! scenario it reproduces. The self-check tests run on the harness's fixed
//! inputs; the rest run whole sessions on regtest through a localhost
//! mailroom.

mod harness;

use bitcoin::key::{Keypair, TapTweak};
use bitcoin::{Amount, Transaction};
use harness::*;
use spj_demo::flow::{self, Regtest};
use spj_demo::net::Error;
use spj_demo::receiver::{self, Decline, SelfCheckError, SpKeys, SpReceiver};
use spj_demo::wallet::{KeyKind, Keychain};
use spj_demo::{chain, sender, wallet};

/// The receiver's check of a harness proposal: `contrib` added to the
/// harness Original, outputs re-derived over `derive_over` (the final inputs
/// unless a test models deriving over the wrong set).
fn self_check(contrib: &[In], derive_over: &[In], attach: &[Attach]) -> Result<(), SelfCheckError> {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let basis: Vec<&In> = s.iter().chain(derive_over).collect();
    let derived = rederive(&basis);
    let added: u64 = contrib.iter().map(|i| i.prevout.value.to_sat()).sum();
    let outputs = vec![out(&derived, 50_000 + added - 300), orig[1].clone()];
    let proposal = proposal_psbt(&s, contrib, &outputs, attach);
    let original_tx = signed_tx(&s, &orig);
    let prevouts: Vec<_> = s.iter().map(|i| i.prevout.clone()).collect();
    receiver::self_check(
        &secp(),
        &bob().keys,
        &original_tx,
        &prevouts,
        &proposal,
        &[derived],
        &[None],
    )
}

fn honest(inputs: &[In], tag: &str) -> Vec<Attach> {
    inputs.iter().filter(|i| i.bip352_secret().is_some()).map(|i| Attach::honest(i, tag)).collect()
}

/// S9c: the receiver scans its finished proposal as a restore would and
/// sends it only if every re-derived output is found.
#[test]
fn s9c_receiver_self_scan() {
    let planned = [recv_input("bob-tr-a", 0xA0, false, Kind::P2tr)];
    let actual = [recv_input("bob-tr-b", 0xB0, true, Kind::P2tr)];
    assert_eq!(
        self_check(&planned, &planned, &honest(&planned, "s9c")),
        Ok(()),
        "derive after choosing"
    );
    assert!(
        matches!(
            self_check(&actual, &planned, &honest(&actual, "s9c")),
            Err(SelfCheckError::RestoreMisses(_))
        ),
        "derived over the planned input, another contributed"
    );
    let low = In::new("bob-wsh-low", Kind::P2wsh, 0x01, 0, None, 10_000);
    let with_low = [planned[0].clone(), low];
    assert!(
        matches!(
            self_check(&with_low, &planned, &honest(&planned, "s9c")),
            Err(SelfCheckError::RestoreMisses(_))
        ),
        "an ineligible input sorting lowest, added after deriving"
    );
    assert_eq!(
        self_check(&with_low, &with_low, &honest(&planned, "s9c")),
        Ok(()),
        "derived over the exact final set"
    );
    let v2 = In::new("bob-v2", Kind::SegwitV2, 0xF0, 0, None, 10_000);
    let with_v2 = [planned[0].clone(), v2];
    assert_eq!(
        self_check(&with_v2, &with_v2, &honest(&planned, "s9c")),
        Err(SelfCheckError::Unscannable),
        "a segwit v2 input makes the transaction unscannable"
    );
}

/// S26d: a share made without BIP 352's negation of an odd-y taproot key
/// fails its proof. A restore never reads the shares, so only the
/// receiver's own run of the sender's check catches it before sending.
#[test]
fn s26d_share_without_parity_fails_self_check() {
    let coin = [recv_input("bob-a", 0xA0, false, Kind::P2tr)];
    let (share, proof) = share(&coin[0], &bob().address().scan, "s26d-np", false);
    let attach = [Attach { label: coin[0].label.clone(), share, proof }];
    assert_eq!(
        self_check(&coin, &coin, &attach),
        Err(SelfCheckError::ProofInvalid(coin[0].outpoint))
    );
    assert_eq!(self_check(&coin, &coin, &[]), Err(SelfCheckError::MissingShare(coin[0].outpoint)));
}

/// R3: a BIP 86 coin's key path signs with the tweaked key, and its share
/// must be made with that key. A share made with the descriptor's internal
/// key verifies against the wrong point, so the receiver doesn't send it.
#[test]
fn r3_bip86_share_from_internal_key_fails_self_check() {
    let internal = sk("bob/bip86");
    let keypair = Keypair::from_secret_key(&secp(), &internal);
    let tweaked = keypair.tap_tweak(&secp(), None).to_keypair().secret_key();
    let coin = [In::new("bob-bip86", Kind::P2tr, 0xA0, 0, Some(tweaked), 25_000)];
    let scan = bob().address().scan;
    let (share, proof) =
        spj_crypto::carriage::share_and_proof(&secp(), &internal, &scan, &rnd32("r3")).unwrap();
    let attach = [Attach { label: coin[0].label.clone(), share, proof }];
    assert_eq!(
        self_check(&coin, &coin, &attach),
        Err(SelfCheckError::ProofInvalid(coin[0].outpoint))
    );
    assert_eq!(
        self_check(&coin, &coin, &honest(&coin, "r3")),
        Ok(()),
        "the tweaked key's share passes"
    );
}

/// The parties of a regtest session.
struct Cast {
    regtest: Regtest,
    bob: SpReceiver,
    bob_coins: Keychain,
    alice: Keychain,
}

async fn cast(bob_coins: usize, alice_coins: usize) -> Result<Cast, Error> {
    let regtest = Regtest::start().await?;
    let mut coins = Keychain::new("bob-hot", "bob", KeyKind::P2tr, 0);
    regtest.fund(&mut coins, &vec![Amount::from_sat(30_000); bob_coins])?;
    let mut alice = Keychain::new("alice", "alice", KeyKind::P2tr, 0);
    regtest.fund(&mut alice, &vec![Amount::from_sat(200_000); alice_coins])?;
    Ok(Cast { regtest, bob: SpReceiver::new(SpKeys::from_seed("bob")), bob_coins: coins, alice })
}

/// S9e on regtest: Alice pays Bob's one-time URI, Bob adds a coin with its
/// proof, Alice's check accepts, and a restore from the tweak index finds
/// the confirmed payjoin's output.
#[tokio::test(flavor = "multi_thread")]
async fn s9e_silent_payjoin_on_regtest_is_found_from_the_tweak_index() -> Result<(), Error> {
    let Cast { regtest, mut bob, mut bob_coins, mut alice } = cast(1, 1).await?;
    let secp = secp();
    let amount = Amount::from_sat(50_000);
    let start = chain::height(regtest.client())?;
    let body = bob_coins.address();
    let one_time = flow::one_time(&regtest.mailroom, bob.address(), body.clone(), amount)?;
    let original = flow::sp_original(&secp, &mut alice, &one_time.uri.sp, amount)?;
    let sending = flow::post_original(
        &regtest.mailroom,
        &original.psbt,
        &flow::one_time_param(&one_time.uri)?,
        &original.payee_address(),
        amount,
        false,
    )
    .await?;

    let received = flow::poll_original(&regtest.mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("the Original should be waiting")?;
    let proposal = bob.propose(
        regtest.client(),
        received,
        &one_time.log,
        &mut bob_coins,
        Some(&body.script_pubkey()),
    )?;
    assert!(proposal.share.is_some());
    flow::post_proposal(&regtest.mailroom, &proposal.receiver, &one_time.log).await?;

    let mut psbt = flow::poll_proposal(&regtest.mailroom, &sending).await?.ok_or("a proposal")?;
    let accepted =
        sender::check_proposal(&secp, &bob.address(), &original.psbt, &original.own, &psbt)?;
    assert_eq!(accepted.shares_verified, 1);
    alice.sign(&mut psbt)?;
    let payjoin: Transaction = wallet::extract(&psbt);
    let txid = chain::broadcast(regtest.client(), &payjoin)?;
    let height = regtest.confirm(&[txid])?;

    let index = chain::tweak_index(&secp, regtest.client(), start + 1, height)?;
    let found = chain::restore(&secp, &bob.keys.scan, &bob.keys.spend.public_key(&secp), &index);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].outpoint.txid, txid);
    assert_eq!(payjoin.output[found[0].outpoint.vout as usize].script_pubkey, proposal.derived[0]);
    assert!(found[0].value > amount, "the payee output carries the receiver's coin too");
    Ok(())
}

/// R1 with a label: Bob's address on the label he gave a contact. His scan
/// of the Original finds the output on that label, he re-derives it on the
/// same label, Alice's check derives it from the labelled `sp=` she was
/// given, and a restore from Bob's seed finds the confirmed payjoin there.
/// A one-time session carries it here, since the derivation doesn't depend
/// on how the Original reaches Bob.
#[tokio::test(flavor = "multi_thread")]
async fn r1_labelled_contact_address() -> Result<(), Error> {
    let Cast { regtest, mut bob, mut bob_coins, mut alice } = cast(1, 1).await?;
    let secp = secp();
    let amount = Amount::from_sat(50_000);
    let start = chain::height(regtest.client())?;
    let (m, sp) = bob.contact_address("Exchange");
    assert_eq!(m, 1, "label 0 is change");
    assert_ne!(sp, bob.address());
    let body = bob_coins.address();
    let one_time = flow::one_time(&regtest.mailroom, sp, body.clone(), amount)?;
    let original = flow::sp_original(&secp, &mut alice, &one_time.uri.sp, amount)?;
    let sending = flow::post_original(
        &regtest.mailroom,
        &original.psbt,
        &flow::one_time_param(&one_time.uri)?,
        &original.payee_address(),
        amount,
        false,
    )
    .await?;

    let received = flow::poll_original(&regtest.mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("the Original should be waiting")?;
    let proposal = bob.propose(
        regtest.client(),
        received,
        &one_time.log,
        &mut bob_coins,
        Some(&body.script_pubkey()),
    )?;
    let labels: Vec<_> = proposal.found.iter().map(|f| f.label).collect();
    assert_eq!(labels, [Some(m)], "the Original pays the contact's label");
    flow::post_proposal(&regtest.mailroom, &proposal.receiver, &one_time.log).await?;

    let mut psbt = flow::poll_proposal(&regtest.mailroom, &sending).await?.ok_or("a proposal")?;
    let accepted =
        sender::check_proposal(&secp, &one_time.uri.sp, &original.psbt, &original.own, &psbt)?;
    assert_eq!(accepted.shares_verified, 1);
    alice.sign(&mut psbt)?;
    let payjoin: Transaction = wallet::extract(&psbt);
    let txid = chain::broadcast(regtest.client(), &payjoin)?;
    let height = regtest.confirm(&[txid])?;

    let index = chain::tweak_index(&secp, regtest.client(), start + 1, height)?;
    let found = chain::restore(&secp, &bob.keys.scan, &bob.keys.spend.public_key(&secp), &index);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].outpoint.txid, found[0].label), (txid, Some(m)));
    assert_eq!(payjoin.output[found[0].outpoint.vout as usize].script_pubkey, proposal.derived[0]);
    Ok(())
}

/// Post `original` to a new one-time URI of Bob's and let him answer.
async fn answer(
    regtest: &Regtest,
    original: &flow::SpOriginal,
    bob: &mut SpReceiver,
    bob_coins: &mut Keychain,
    amount: Amount,
) -> Result<Result<receiver::Proposal, Decline>, Error> {
    let mailroom = &regtest.mailroom;
    let one_time = flow::one_time(mailroom, bob.address(), bob_coins.address(), amount)?;
    let param = flow::one_time_param(&one_time.uri)?;
    flow::post_original(mailroom, &original.psbt, &param, &original.payee_address(), amount, false)
        .await?;
    let received = flow::poll_original(mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("an Original")?;
    Ok(bob.propose(regtest.client(), received, &one_time.log, bob_coins, None))
}

/// S35d: an Original reusing an input of an earlier Original gets no coin,
/// across all of the receiver's URIs, so one prober input buys one coin.
/// Distinct inputs still buy one coin each.
#[tokio::test(flavor = "multi_thread")]
async fn s35d_seen_inputs_across_uris() -> Result<(), Error> {
    let Cast { regtest, mut bob, mut bob_coins, alice: mut prober } = cast(4, 4).await?;
    let secp = secp();
    let amount = Amount::from_sat(10_000);
    let sp = bob.address();

    let probe = flow::sp_original(&secp, &mut prober, &sp, amount)?;
    let mut shown = 0;
    for uri in 0..4 {
        match answer(&regtest, &probe, &mut bob, &mut bob_coins, amount).await? {
            Ok(_) => shown += 1,
            Err(Decline::SeenInput) => {}
            Err(e) => return Err(format!("URI {uri}: {e}").into()),
        }
    }
    assert_eq!(shown, 1, "one prober input posted to four URIs shows one coin");

    let mut used: Vec<_> = probe.own.keys().copied().collect();
    let mut distinct = 0;
    for _ in 0..3 {
        for outpoint in &used {
            prober.reserve(*outpoint);
        }
        let original = flow::sp_original(&secp, &mut prober, &sp, amount)?;
        used.extend(original.own.keys().copied());
        if answer(&regtest, &original, &mut bob, &mut bob_coins, amount).await?.is_ok() {
            distinct += 1;
        }
    }
    assert_eq!(distinct, 3, "three distinct inputs buy three more coins");
    Ok(())
}

/// S12d: a sender that disallows output substitution gets no coin, since
/// adding one without re-deriving the payee output loses it to a restore.
#[tokio::test(flavor = "multi_thread")]
async fn s12d_no_substitution_no_contribution() -> Result<(), Error> {
    let Cast { regtest, mut bob, mut bob_coins, mut alice } = cast(1, 1).await?;
    let amount = Amount::from_sat(50_000);
    let one_time = flow::one_time(&regtest.mailroom, bob.address(), bob_coins.address(), amount)?;
    let original = flow::sp_original(&secp(), &mut alice, &one_time.uri.sp, amount)?;
    flow::post_original(
        &regtest.mailroom,
        &original.psbt,
        &flow::one_time_param(&one_time.uri)?,
        &original.payee_address(),
        amount,
        true,
    )
    .await?;
    let received = flow::poll_original(&regtest.mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("an Original")?;
    let declined = bob.propose(regtest.client(), received, &one_time.log, &mut bob_coins, None);
    assert!(matches!(declined, Err(Decline::SubstitutionDisabled)), "{:?}", declined.err());
    assert!(bob_coins.spendable().len() == 1, "the coin stays unoffered");
    Ok(())
}
