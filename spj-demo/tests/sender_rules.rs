//! The sender's attempt gate and proposal check, each test named after the
//! silent payjoin harness scenario it reproduces, with that scenario's
//! verdicts.

mod harness;

use bitcoin::ScriptBuf;
use harness::*;
use spj_crypto::bip352;
use spj_demo::sender::{attempt_gate, check_proposal, Accepted, Change, Gate, Payment, Rejection};

fn check(
    sender: &[In],
    original: &[bitcoin::TxOut],
    proposal: &bitcoin::Psbt,
) -> Result<Accepted, Rejection> {
    check_proposal(
        &secp(),
        &bob().address(),
        &original_psbt(sender, original),
        &own_secrets(sender),
        proposal,
    )
}

/// S10a: attempt only if every silent payment output pays this sp1; the
/// Original itself may pay anyone.
#[test]
fn s10a_attempt_gate() {
    let (bob, alice, carol) = (bob(), Wallet::new("alice"), Wallet::new("carol"));
    let sp = bob.address();
    let gate = |payments: &[Payment], change| attempt_gate(&sp, payments, change);
    let pay = Payment::SilentPayment;
    assert_eq!(gate(&[pay(sp)], Change::Ordinary), Gate::AttemptPayjoin, "payee + BIP 86 change");
    assert_eq!(
        gate(&[pay(sp), pay(sp)], Change::Ordinary),
        Gate::AttemptPayjoin,
        "two outputs to this sp1"
    );
    assert!(
        matches!(
            gate(&[pay(sp), pay(bob.labelled(3))], Change::Ordinary),
            Gate::BroadcastOriginal(_)
        ),
        "a labelled sp1 of the same receiver is a different address"
    );
    assert!(
        matches!(gate(&[pay(sp)], Change::SilentPayment), Gate::BroadcastOriginal(_)),
        "SP change"
    );
    assert!(
        matches!(
            gate(&[pay(sp), pay(alice.labelled(0))], Change::None),
            Gate::BroadcastOriginal(_)
        ),
        "SP change as a label-0 output"
    );
    assert!(
        matches!(
            gate(&[pay(sp), pay(carol.address())], Change::Ordinary),
            Gate::BroadcastOriginal(_)
        ),
        "third-party SP output"
    );
    assert_eq!(
        gate(&[pay(sp), Payment::Script(alice_change())], Change::Ordinary),
        Gate::AttemptPayjoin,
        "an ordinary output to anyone is fine"
    );
}

/// S23a: the gate is the sender's alone. Bob's view of an Original paying
/// him and Carol can't tell Carol's output from change, so the sender must
/// not attempt.
#[test]
fn s23a_batch_with_third_party_sp_broadcasts_original() {
    let carol = Wallet::new("carol");
    let sp = bob().address();
    assert!(matches!(
        attempt_gate(
            &sp,
            &[Payment::SilentPayment(sp), Payment::SilentPayment(carol.address())],
            Change::Ordinary
        ),
        Gate::BroadcastOriginal(_)
    ));
}

/// S2 / S9e: an honest receiver adds an odd-y P2TR coin with its share. The
/// sender derives the same output the harness derives, and a restore finds
/// it from the tweak a BlindBit-style index publishes.
#[test]
fn s9e_honest_proposal_is_found_from_the_tweak() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let r = bob_tr();
    let (outputs, payee) = honest_outputs(&s, &orig, std::slice::from_ref(&r), 300);
    assert_eq!(key_hex(&payee), "f72d39cfa1bd5d97301731e8a4472f8b6dd1e2a2c7624b1f41f04b613f7e4ec4");
    let proposal =
        proposal_psbt(&s, std::slice::from_ref(&r), &outputs, &[Attach::honest(&r, "s9e")]);
    let accepted = check(&s, &orig, &proposal).expect("accepted");
    assert_eq!(accepted.payee_vouts, vec![0]);
    assert_eq!(accepted.shares_verified, 1);

    let all: Vec<In> = s.iter().cloned().chain([r]).collect();
    let tx = signed_tx(&all, &outputs);
    let prevouts: Vec<_> = all.iter().map(|i| i.prevout.clone()).collect();
    let tweak = bip352::transaction_tweak(&secp(), &tx, &prevouts).expect("eligible");
    assert_eq!(
        tweak.to_string(),
        "02841776b5f464162de42f31fdddd084e6d931e1b415523996929eea5b46ed9b8b"
    );
    let found = spj_demo::derive::scan(&secp(), &bob().keys, &Default::default(), &tx, &prevouts);
    assert_eq!(found.len(), 1);
    assert_eq!(tx.output[found[0].vout].script_pubkey, payee);
}

/// S32a: every proposal is checked, including one that adds no input.
#[test]
fn s32a_check_every_proposal() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let mallory = tr_key(&sk("s32a/mallory"));
    let redirect =
        proposal_psbt(&s, &[], &[out(&mallory, 50_000), out(&alice_change(), 49_000)], &[]);
    assert_eq!(
        check(&s, &orig, &redirect),
        Err(Rejection::MissingDerivedOutput),
        "no-input redirect"
    );
    let shrink = proposal_psbt(
        &s,
        &[],
        &[out(&orig[0].script_pubkey, 30_000), out(&alice_change(), 49_000)],
        &[],
    );
    assert_eq!(
        check(&s, &orig, &shrink),
        Err(Rejection::AmountRule {
            paid: bitcoin::Amount::from_sat(30_000),
            required: bitcoin::Amount::from_sat(50_000)
        })
    );
    let unchanged = proposal_psbt(&s, &[], &orig, &[]);
    assert!(check(&s, &orig, &unchanged).is_ok(), "the Original's outputs pass");
}

/// S32b: each derived script counts once. An ineligible coin above the
/// sender's smallest outpoint leaves the derived output equal to the
/// Original's; paying it twice at half value is rejected.
#[test]
fn s32b_each_derived_script_once() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let nums = In::new("s32b-thief", Kind::NumsScript, 0xB3, 0, None, 30_000);
    let refs: Vec<&In> = s.iter().chain([&nums]).collect();
    let p0 = orig[0].script_pubkey.clone();
    assert_eq!(rederive(&refs), p0, "an ineligible coin doesn't change the derivation");
    let back = ScriptBuf::from_hex(&format!("5120{}", "77".repeat(32))).unwrap();
    let dup =
        [out(&p0, 25_000), out(&p0, 25_000), out(&alice_change(), 49_000), out(&back, 29_700)];
    let proposal = proposal_psbt(&s, std::slice::from_ref(&nums), &dup, &[]);
    assert_eq!(check(&s, &orig, &proposal), Err(Rejection::DuplicateDerivedOutput));
    let once = [out(&p0, 50_000), out(&alice_change(), 49_000), out(&back, 29_700)];
    let proposal = proposal_psbt(&s, std::slice::from_ref(&nums), &once, &[]);
    assert!(check(&s, &orig, &proposal).is_ok(), "the payee output once at full value");
}

/// S32c: a receiver input's witness must match its described prevout. A
/// control block claiming the unspendable internal key on an ordinary P2TR
/// coin, and a P2WPKH witness key that doesn't hash to the program, would
/// each change what BIP 352 reads.
#[test]
fn s32c_witness_against_prevout() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let back = ScriptBuf::from_hex(&format!("5120{}", "88".repeat(32))).unwrap();
    let prop =
        [out(&orig[0].script_pubkey, 50_000), out(&alice_change(), 49_000), out(&back, 29_700)];

    let mut fake =
        In::new("s32c-thief", Kind::P2tr, 0xA8, 0, Some(sk_parity("s32c/thief", true)), 30_000);
    let (leaf, _, _) = nums_leaf("s32c", &NUMS_H);
    let mut control = vec![0xc0];
    control.extend_from_slice(&NUMS_H);
    fake.kind = Kind::NumsScript;
    fake.script_path = Some((leaf, control));
    let proposal = proposal_psbt(&s, std::slice::from_ref(&fake), &prop, &[]);
    assert_eq!(check(&s, &orig, &proposal), Err(Rejection::InvalidSpend(fake.outpoint)));

    let wpkh = In::new("s32c-w", Kind::P2wpkh, 0xA9, 0, Some(sk("s32c/w")), 30_000);
    let mut proposal = proposal_psbt(&s, std::slice::from_ref(&wpkh), &prop, &[]);
    let other = sk("s32c/other").public_key(&secp());
    let witness = proposal.inputs[2].final_script_witness.as_ref().unwrap();
    let signature = witness.nth(0).unwrap().to_vec();
    proposal.inputs[2].final_script_witness =
        Some(bitcoin::Witness::from_slice(&[signature, other.serialize().to_vec()]));
    assert_eq!(
        check(&s, &orig, &proposal),
        Err(Rejection::InputTypeNotAllowed(vec![wpkh.outpoint]))
    );

    // A key-path signature commits to every prevout, so a coin described
    // with a value other than the one it was signed over fails to verify.
    let coin = In::new("s32c-sig", Kind::P2tr, 0xAA, 0, Some(sk_parity("s32c/sig", true)), 30_000);
    let mut proposal = proposal_psbt(&s, std::slice::from_ref(&coin), &prop, &[]);
    proposal.inputs[2].witness_utxo.as_mut().unwrap().value = bitcoin::Amount::from_sat(31_000);
    assert_eq!(check(&s, &orig, &proposal), Err(Rejection::InvalidSpend(coin.outpoint)));
    let honest =
        proposal_psbt(&s, std::slice::from_ref(&coin), &prop, &[Attach::honest(&coin, "s32c")]);
    assert_eq!(
        check(&s, &orig, &honest),
        Err(Rejection::MissingDerivedOutput),
        "valid spend, stale payee"
    );
}

/// S32e: a thief holding only the mailbox key gets a proposal accepted only
/// with coins that add nothing to A. One eligible coin moves the derived
/// output somewhere only `a_s·B_scan = b_scan·A_s` can compute.
#[test]
fn s32e_thief_needs_the_shared_secret_for_an_eligible_coin() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let p0 = orig[0].script_pubkey.clone();
    let back = ScriptBuf::from_hex(&format!("5120{}", "66".repeat(32))).unwrap();

    let nums = In::new("s32e-nums", Kind::NumsScript, 0xB5, 0, None, 30_000);
    let prop = [out(&p0, 50_000), out(&alice_change(), 49_000), out(&back, 29_700)];
    assert!(check(&s, &orig, &proposal_psbt(&s, std::slice::from_ref(&nums), &prop, &[])).is_ok());

    let c1 = In::new("s32e-tr", Kind::P2tr, 0xB6, 0, Some(sk_parity("s32e/x", true)), 30_000);
    let attach = [Attach::honest(&c1, "s32e1")];
    let stale = proposal_psbt(&s, std::slice::from_ref(&c1), &prop, &attach);
    assert_eq!(check(&s, &orig, &stale), Err(Rejection::MissingDerivedOutput));
    let refs: Vec<&In> = s.iter().chain([&c1]).collect();
    let p1 = rederive(&refs);
    assert_ne!(p1, p0);
    let fresh = [out(&p1, 50_000), out(&alice_change(), 49_000), out(&back, 29_700)];
    assert!(
        check(&s, &orig, &proposal_psbt(&s, std::slice::from_ref(&c1), &fresh, &attach)).is_ok()
    );
}

/// S32f: a P2PKH coin whose scriptSig withholds its key reads as ineligible,
/// and no signature covers that scriptSig, so the input-type list rejects it
/// whether it sorts above or below the sender's smallest outpoint.
#[test]
fn s32f_p2pkh_with_withheld_key_is_rejected() {
    let sender = vec![In::new(
        "s32f-alice",
        Kind::P2tr,
        0x80,
        0,
        Some(sk_parity("s32f/alice", false)),
        60_000,
    )];
    let payee = sender_outputs(&sender, &[bob().address()]).remove(0);
    let orig = vec![out(&payee, 50_000), out(&alice_change(), 9_000)];
    let back = ScriptBuf::from_hex(&format!("5120{}", "aa".repeat(32))).unwrap();
    for (position, order) in [("above", 0x90), ("below", 0x10)] {
        let thief = In::new(
            &format!("s32f-{position}"),
            Kind::P2pkh,
            order,
            0,
            Some(sk(&format!("s32f/{position}"))),
            30_000,
        );
        let prop = [out(&payee, 50_000), out(&alice_change(), 9_000), out(&back, 29_700)];
        let mut proposal = proposal_psbt(&sender, std::slice::from_ref(&thief), &prop, &[]);
        let script_sig = proposal.inputs[1].final_script_sig.clone().unwrap();
        let signature = script_sig.instructions().next().unwrap().unwrap();
        let withheld = bitcoin::blockdata::script::Builder::new()
            .push_slice(
                <&bitcoin::script::PushBytes>::try_from(signature.push_bytes().unwrap().as_bytes())
                    .unwrap(),
            )
            .into_script();
        proposal.inputs[1].final_script_sig = Some(withheld);
        assert_eq!(
            check(&sender, &orig, &proposal),
            Err(Rejection::InputTypeNotAllowed(vec![thief.outpoint])),
            "{position}"
        );
    }
}

/// S32g: the input-type list. Honest P2TR, P2WPKH and P2SH-P2WPKH coins with
/// proofs are accepted; a non-canonical P2SH scriptSig, P2PKH, P2WSH and a
/// native segwit input with a scriptSig are rejected.
#[test]
fn s32g_input_type_list() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    for kind in [Kind::P2tr, Kind::P2wpkh, Kind::P2shP2wpkh] {
        let label = format!("s32g-{kind:?}");
        let r = recv_input(&label, 0xA0, false, kind);
        let (outputs, payee) = honest_outputs(&s, &orig, std::slice::from_ref(&r), 300);
        let proposal =
            proposal_psbt(&s, std::slice::from_ref(&r), &outputs, &[Attach::honest(&r, &label)]);
        let accepted = check(&s, &orig, &proposal).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(proposal.unsigned_tx.output[accepted.payee_vouts[0]].script_pubkey, payee);
    }

    // The harness's recorded P2SH-P2WPKH coin, rebuilt from its label.
    let sh = recv_input("s32g-sh", 0xA0, false, Kind::P2shP2wpkh);
    assert_eq!(
        sh.outpoint.txid.to_string(),
        "4c01400cae091b31e24c127b21a8f5b000ccb80f32b1ce8e34848721e93430a0"
    );
    assert_eq!(
        sh.prevout.script_pubkey.to_hex_string(),
        "a91499a5e69c5f0d7fa648b576cd3adfc1ccdf6ecd9187"
    );
    let (outputs, _) = honest_outputs(&s, &orig, std::slice::from_ref(&sh), 300);
    let honest =
        proposal_psbt(&s, std::slice::from_ref(&sh), &outputs, &[Attach::honest(&sh, "s32g-sh")]);
    assert!(check(&s, &orig, &honest).is_ok(), "one push of the redeem script");
    let redeem = redeem_script(&sh.secret.unwrap().public_key(&secp()));
    let push = |bytes: &[u8]| bitcoin::script::PushBytesBuf::try_from(bytes.to_vec()).unwrap();
    for (name, script_sig) in [
        (
            "not a P2WPKH redeem script",
            bitcoin::blockdata::script::Builder::new().push_slice(push(&[0x51])).into_script(),
        ),
        (
            "the redeem script plus an extra push",
            bitcoin::blockdata::script::Builder::new()
                .push_slice(push(redeem.as_bytes()))
                .push_slice(push(&[1]))
                .into_script(),
        ),
        ("empty", ScriptBuf::new()),
    ] {
        let mut proposal = honest.clone();
        proposal.inputs[2].final_script_sig = Some(script_sig);
        assert_eq!(
            check(&s, &orig, &proposal),
            Err(Rejection::InputTypeNotAllowed(vec![sh.outpoint])),
            "{name}"
        );
    }

    let pkh = recv_input("s32g-pkh", 0xA0, false, Kind::P2pkh);
    assert_eq!(
        pkh.outpoint.txid.to_string(),
        "77c49f8efe89cfeb9ad5f96f6997ac31596bc4b52a9d00afadeecd5a1ba4c7a0"
    );
    let (outputs, _) = honest_outputs(&s, &orig, std::slice::from_ref(&pkh), 300);
    let proposal = proposal_psbt(
        &s,
        std::slice::from_ref(&pkh),
        &outputs,
        &[Attach::honest(&pkh, "s32g-pkh")],
    );
    assert_eq!(
        check(&s, &orig, &proposal),
        Err(Rejection::InputTypeNotAllowed(vec![pkh.outpoint])),
        "P2PKH"
    );

    let wsh = In::new("s32g-wsh", Kind::P2wsh, 0xB1, 0, None, 25_000);
    let (outputs, _) = honest_outputs(&s, &orig, std::slice::from_ref(&wsh), 300);
    let proposal = proposal_psbt(&s, std::slice::from_ref(&wsh), &outputs, &[]);
    assert_eq!(
        check(&s, &orig, &proposal),
        Err(Rejection::InputTypeNotAllowed(vec![wsh.outpoint])),
        "P2WSH"
    );

    let tr = recv_input("s32g-trsig", 0xA0, false, Kind::P2tr);
    let (outputs, _) = honest_outputs(&s, &orig, std::slice::from_ref(&tr), 300);
    let mut proposal = proposal_psbt(
        &s,
        std::slice::from_ref(&tr),
        &outputs,
        &[Attach::honest(&tr, "s32g-trsig")],
    );
    proposal.inputs[2].final_script_sig =
        Some(bitcoin::blockdata::script::Builder::new().push_slice(push(&[1])).into_script());
    assert_eq!(
        check(&s, &orig, &proposal),
        Err(Rejection::InputTypeNotAllowed(vec![tr.outpoint])),
        "scriptSig on P2TR"
    );
}

/// S26d: per-input proofs are safe only with mandatory coverage. A missing
/// share, a share that isn't `a·B_scan`, and a share made without BIP 352's
/// P2TR negation are each rejected; an ineligible receiver input needs no
/// share.
#[test]
fn s26d_mandatory_coverage() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let bob_a = recv_input("bob-a", 0xA0, false, Kind::P2tr);
    let bob_b = recv_input("bob-b", 0xA5, true, Kind::P2tr);
    let r_in = [bob_a.clone(), bob_b.clone()];
    let (outputs, _) = honest_outputs(&s, &orig, &r_in, 300);

    let partial = proposal_psbt(&s, &r_in, &outputs, &[Attach::honest(&bob_a, "s26d")]);
    assert_eq!(check(&s, &orig, &partial), Err(Rejection::MissingShares(vec![bob_b.outpoint])));

    let honest_a = Attach::honest(&bob_a, "s26d");
    let junk = honest_a.share.combine(&spj_crypto::dleq::generator()).unwrap();
    let malformed = proposal_psbt(
        &s,
        &r_in,
        &outputs,
        &[Attach { share: junk, ..honest_a }, Attach::honest(&bob_b, "s26d")],
    );
    assert_eq!(check(&s, &orig, &malformed), Err(Rejection::ProofFails(bob_a.outpoint)));

    let no_parity: Vec<Attach> = r_in
        .iter()
        .map(|i| {
            let (share, proof) = share(i, &bob().address().scan, "s26d-np", false);
            Attach { label: i.label.clone(), share, proof }
        })
        .collect();
    let proposal = proposal_psbt(&s, &r_in, &outputs, &no_parity);
    assert_eq!(
        check(&s, &orig, &proposal),
        Err(Rejection::ProofFails(bob_a.outpoint)),
        "odd-y key not negated"
    );

    let wsh = In::new("bob-wsh-low", Kind::NumsScript, 0x01, 0, None, 25_000);
    let r3 = [bob_a.clone(), wsh];
    let (outputs, _) = honest_outputs(&s, &orig, &r3, 300);
    let proposal = proposal_psbt(&s, &r3, &outputs, &[Attach::honest(&bob_a, "s26d-wsh")]);
    assert!(
        check(&s, &orig, &proposal).is_ok(),
        "an ineligible input sorting lowest needs no share"
    );
}

/// S27b: no marker carries security. An eligible receiver input without a
/// share is rejected; a receiver without proof support adds nothing, and the
/// Original's outputs are signed as they are.
#[test]
fn s27b_proof_always_required() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let thief =
        In::new("s27b-thief", Kind::P2tr, 0xAB, 0, Some(sk_parity("s27b/thief", true)), 30_000);
    let mallory = tr_key(&sk("s27b/mallory"));
    let redirect = proposal_psbt(
        &s,
        std::slice::from_ref(&thief),
        &[out(&mallory, 79_700), out(&alice_change(), 49_000)],
        &[Attach::honest(&thief, "s27b")],
    );
    assert_eq!(check(&s, &orig, &redirect), Err(Rejection::MissingDerivedOutput));

    let r = bob_tr();
    let (outputs, _) = honest_outputs(&s, &orig, std::slice::from_ref(&r), 300);
    let unproven = proposal_psbt(&s, std::slice::from_ref(&r), &outputs, &[]);
    assert_eq!(check(&s, &orig, &unproven), Err(Rejection::MissingShares(vec![r.outpoint])));
    assert!(check(&s, &orig, &proposal_psbt(&s, &[], &orig, &[])).is_ok());
}

/// S4f: a segwit v2 receiver input makes the whole transaction unscannable.
#[test]
fn s4f_segwit_v2_receiver_input_is_rejected() {
    let s = sender_inputs();
    let orig = orig_paying_bob(&s);
    let r = bob_tr();
    let v2 = In::new("bob-v2", Kind::SegwitV2, 0xF0, 0, None, 10_000);
    let (outputs, _) = honest_outputs(&s, &orig, &[r.clone(), v2.clone()], 300);
    let proposal =
        proposal_psbt(&s, &[r.clone(), v2.clone()], &outputs, &[Attach::honest(&r, "s4f")]);
    assert_eq!(check(&s, &orig, &proposal), Err(Rejection::Unscannable(v2.outpoint)));
}

/// The rejection the sender prints names the input, which the scenes narrate.
#[test]
fn rejections_read_as_the_harness_reasons() {
    let op = bob_tr().outpoint;
    assert!(Rejection::MissingShares(vec![op])
        .to_string()
        .starts_with("no share for eligible input(s) "));
    assert_eq!(
        Rejection::MissingDerivedOutput.to_string(),
        "an output derived for the sp1 is missing"
    );
    let amounts = Rejection::AmountRule {
        paid: bitcoin::Amount::from_sat(49_000),
        required: bitcoin::Amount::from_sat(50_000),
    };
    assert_eq!(amounts.to_string(), "amount rule (49000 < 50000)");
}
