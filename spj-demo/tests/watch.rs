//! The sender watches a broadcast payjoin until it confirms, named after the
//! silent payjoin harness scenario it reproduces.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, FeeRate};
use spj_demo::chain;
use spj_demo::derive::SpKeys;
use spj_demo::flow::{self, Regtest};
use spj_demo::net::Error;
use spj_demo::receiver::SpReceiver;
use spj_demo::sender::{self, Broadcast, Watch};
use spj_demo::wallet::{self, KeyKind, Keychain};

/// One payer's payjoin to Bob, signed and ready to broadcast.
struct Signed {
    original: flow::SpOriginal,
    payjoin: bitcoin::Transaction,
}

async fn payjoin(
    regtest: &Regtest,
    bob: &mut SpReceiver,
    bob_coins: &mut Keychain,
    payer: &mut Keychain,
    fee_rate: FeeRate,
) -> Result<Signed, Error> {
    let secp = Secp256k1::new();
    let amount = Amount::from_sat(50_000);
    let mailroom = &regtest.mailroom;
    let one_time = flow::one_time(mailroom, bob.address(), bob_coins.address(), amount)?;
    let original = flow::sp_original_at(&secp, payer, &one_time.uri.sp, amount, fee_rate)?;
    let sending = flow::post_original(
        mailroom,
        &original.psbt,
        &flow::one_time_param(&one_time.uri)?,
        &original.payee_address(),
        amount,
        false,
    )
    .await?;
    let received = flow::poll_original(mailroom, one_time.session, &one_time.log)
        .await?
        .ok_or("an Original")?;
    let proposal = bob.propose(regtest.client(), received, &one_time.log, bob_coins, None)?;
    flow::post_proposal(mailroom, &proposal.receiver, &one_time.log).await?;
    let mut psbt = flow::poll_proposal(mailroom, &sending).await?.ok_or("a proposal")?;
    sender::check_proposal(&secp, &bob.address(), &original.psbt, &original.own, &psbt)?;
    payer.sign(&mut psbt)?;
    Ok(Signed { original, payjoin: wallet::extract(&psbt) })
}

/// S30a: under full RBF a payjoin the node accepted can still be replaced.
/// Here the receiver breaks its one-coin-per-live-session rule and offers
/// the same coin to Alice and Carol; Carol's higher-fee payjoin evicts
/// Alice's. A sender that only reacts to a refused broadcast would never pay
/// Bob. Alice watches, finds her payjoin gone, and broadcasts her Original,
/// so both payments confirm.
#[tokio::test(flavor = "multi_thread")]
async fn s30a_evicted_payjoin_falls_back_to_the_original() -> Result<(), Error> {
    let secp = Secp256k1::new();
    let regtest = Regtest::start().await?;
    let start = chain::height(regtest.client())?;
    let mut bob = SpReceiver::new(SpKeys::from_seed("bob"));
    let mut bob_coins = Keychain::new("bob-hot", "bob", KeyKind::P2tr, 0);
    regtest.fund(&mut bob_coins, &[Amount::from_sat(30_000)])?;
    let mut alice = Keychain::new("alice", "alice", KeyKind::P2tr, 0);
    let mut carol = Keychain::new("carol", "carol", KeyKind::P2wpkh, 0);
    regtest.fund(&mut alice, &[Amount::from_sat(200_000)])?;
    regtest.fund(&mut carol, &[Amount::from_sat(200_000)])?;

    let a =
        payjoin(&regtest, &mut bob, &mut bob_coins, &mut alice, FeeRate::from_sat_per_vb_u32(2))
            .await?;
    let coin = bob_coins.coins()[0].outpoint;
    bob_coins.release(&coin);
    let c =
        payjoin(&regtest, &mut bob, &mut bob_coins, &mut carol, FeeRate::from_sat_per_vb_u32(20))
            .await?;
    assert!(a.payjoin.input.iter().any(|i| i.previous_output == coin));
    assert!(c.payjoin.input.iter().any(|i| i.previous_output == coin));

    let Broadcast::Payjoin(a_txid) =
        sender::broadcast(regtest.client(), &a.payjoin, &a.original.tx())?
    else {
        return Err("Alice's payjoin should be accepted".into());
    };
    assert_eq!(sender::watch(regtest.client(), a_txid, &a.original.tx())?, Watch::InMempool);
    let Broadcast::Payjoin(c_txid) =
        sender::broadcast(regtest.client(), &c.payjoin, &c.original.tx())?
    else {
        return Err("Carol's payjoin should replace Alice's".into());
    };

    let Watch::OriginalBroadcast(fallback) =
        sender::watch(regtest.client(), a_txid, &a.original.tx())?
    else {
        return Err("Alice's payjoin should be gone".into());
    };
    assert_eq!(fallback, a.original.tx().compute_txid());
    let height = regtest.confirm(&[c_txid, fallback])?;
    assert_eq!(sender::watch(regtest.client(), c_txid, &c.original.tx())?, Watch::Confirmed);

    let index = chain::tweak_index(&secp, regtest.client(), start + 1, height)?;
    let found = chain::restore(&secp, &bob.keys.scan, &bob.keys.spend.public_key(&secp), &index);
    let txids: Vec<_> = found.iter().map(|f| f.outpoint.txid).collect();
    assert_eq!(txids.len(), 2, "{found:?}");
    assert!(txids.contains(&c_txid) && txids.contains(&fallback), "Bob is paid by both");
    Ok(())
}
