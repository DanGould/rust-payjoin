//! Scene 1: one printed string, many payments, no shared addresses,
//! and everything recoverable from the seed alone.

use std::time::Duration;

use bitcoin::{Address, Amount, Network};

use super::{
    complete_payment, fall_back, respond_with_payjoin, scan_chain_for_sp, send_message_a, BoxError,
    Demo,
};
use crate::sp;
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        1,
        "Static reuse without address reuse",
        "One published payment string is paid three times by two senders. \
         Every payment lands on a distinct taproot output, and a receiver \
         restored from nothing but seed material recovers every coin.",
    );

    let mut alice = DemoWallet::new(&demo.secp, "Alice");
    let mut bob = DemoWallet::new(&demo.secp, "Bob");
    alice.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    bob.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;

    demo.narrator.step("the receiver publishes one static payment string and goes about its day");
    demo.narrator.result("static string", &demo.static_uri);
    demo.narrator.note(
        "the address slot is a placeholder derived from the receiver's spend \
         key; each sender replaces it with an output only they can derive, \
         so the string itself never appears on chain",
    );

    // Payment 1: Alice, receiver online, payjoin completes.
    demo.narrator.step("payment 1: Alice derives her one-time output and posts to the queue");
    let p1 = send_message_a(demo, &alice, Amount::from_btc(0.4)?, None).await?;
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    let fresh1 = respond_with_payjoin(demo, proposal, &p1.sp_script, "payment-1").await?;
    let tx1 = complete_payment(demo, &mut alice, p1).await?;
    demo.narrator.result("payjoin txid", &tx1.compute_txid().to_string());
    demo.narrator
        .result("receiver output", &script_summary(&fresh1, "fresh wallet address (payjoin)"));

    // Payment 2: Bob, receiver online, payjoin completes.
    demo.narrator.step("payment 2: Bob pays the same string; his derivation differs");
    let p2 = send_message_a(demo, &bob, Amount::from_btc(0.3)?, None).await?;
    let proposals = demo.receiver_poll().await?;
    let [proposal]: [_; 1] = proposals.try_into().map_err(|_| "expected exactly one proposal")?;
    let fresh2 = respond_with_payjoin(demo, proposal, &p2.sp_script, "payment-2").await?;
    let tx2 = complete_payment(demo, &mut bob, p2).await?;
    demo.narrator.result("payjoin txid", &tx2.compute_txid().to_string());
    demo.narrator
        .result("receiver output", &script_summary(&fresh2, "fresh wallet address (payjoin)"));

    // Payment 3: Bob again, receiver away, patience lapses, fallback.
    demo.narrator.step(
        "payment 3: Bob pays the string again, but the receiver is away; \
         Bob's patience lapses and his wallet broadcasts the original \
         transaction unchanged",
    );
    let p3 =
        send_message_a(demo, &bob, Amount::from_btc(0.2)?, Some(Duration::from_secs(1))).await?;
    std::thread::sleep(Duration::from_millis(1200));
    let sp_script3 = p3.sp_script.clone();
    let tx3 = fall_back(demo, &mut bob, p3).await?;
    demo.narrator.result("fallback txid", &tx3.compute_txid().to_string());
    demo.narrator
        .result("receiver output", &script_summary(&sp_script3, "derived one-time output"));

    // No two payments share a script.
    let scripts = [fresh1.clone(), fresh2.clone(), sp_script3.clone()];
    let all_taproot = scripts.iter().all(|s| s.is_p2tr());
    let all_distinct =
        scripts.iter().collect::<std::collections::HashSet<_>>().len() == scripts.len();
    demo.narrator.step("compare the three on-chain receiver outputs");
    for (i, script) in scripts.iter().enumerate() {
        let address = Address::from_script(script, Network::Regtest)?;
        demo.narrator.result(&format!("payment {}", i + 1), &address.to_string());
    }

    // Restore from seed.
    demo.narrator.step(
        "disaster drill: throw the receiver's wallet away and restore on a \
         fresh one from seed material alone",
    );
    let live_balance = wallet_balance(demo, &demo.receiver_wallet)?;
    let restored = restore_receiver_wallet(demo)?;
    let restored_balance = wallet_balance(demo, &restored)?;
    demo.narrator.result("restored wallet rescan balance", &restored_balance.to_string());
    let hd_recovered = restored_balance == live_balance;

    demo.narrator.step("scan the chain with the scan key for anything the rescan missed");
    let found = scan_chain_for_sp(demo)?;
    demo.narrator
        .result("silent payment scan", &format!("{} unclaimed payment(s) found", found.len()));
    let mut swept = Amount::ZERO;
    let mut sweep_ok = true;
    for (outpoint, prevout, keypair) in &found {
        let destination = demo.fresh_receiver_address()?;
        let fee = Amount::from_sat(200);
        let sweep = sp::sweep_keyspend(
            &demo.secp,
            *outpoint,
            prevout,
            keypair,
            destination.script_pubkey(),
            fee,
        )
        .ok_or("sweep construction failed")?;
        match demo.broadcast(&sweep) {
            Ok(txid) => {
                demo.mine(1)?;
                swept += prevout.value - fee;
                demo.narrator.result("sweep txid", &txid.to_string());
            }
            Err(e) => {
                sweep_ok = false;
                demo.narrator.result("sweep failed", &e.to_string());
            }
        }
    }

    let pass = all_taproot && all_distinct && hd_recovered && found.len() == 1 && sweep_ok;
    demo.narrator.verdict(
        pass,
        &format!(
            "three payments, three distinct taproot outputs; wallet rescan \
             recovered {live_balance} and the scan key recovered the {swept} \
             fallback. Nothing depended on receiver state surviving.",
        ),
    );
    if !pass {
        return Err("scene 1 assertions failed".into());
    }
    Ok(())
}

fn script_summary(script: &bitcoin::ScriptBuf, kind: &str) -> String {
    let address = Address::from_script(script, Network::Regtest)
        .map(|a| a.to_string())
        .unwrap_or_else(|_| script.to_hex_string());
    format!("{address} — {kind}")
}

fn wallet_balance(
    _demo: &Demo,
    wallet: &payjoin_test_utils::corepc_node::Client,
) -> Result<Amount, BoxError> {
    Ok(wallet.get_balances()?.into_model()?.mine.trusted)
}

/// Create a blank wallet and load it with the original wallet's
/// descriptors, standing in for a seed restore: the descriptors are
/// exactly what a BIP 39/BIP 86 seed backup reproduces.
fn restore_receiver_wallet(
    demo: &Demo,
) -> Result<payjoin_test_utils::corepc_node::Client, BoxError> {
    let descriptors: serde_json::Value =
        demo.receiver_wallet.call("listdescriptors", &[serde_json::json!(true)])?;
    let mut to_import = Vec::new();
    for descriptor in descriptors["descriptors"].as_array().ok_or("descriptor listing")? {
        to_import.push(serde_json::json!({
            "desc": descriptor["desc"],
            "timestamp": 0,
            "active": descriptor["active"],
            "internal": descriptor["internal"],
        }));
    }

    let restored = demo.bitcoind.create_wallet("receiver-restored")?;
    let import_result: serde_json::Value =
        restored.call("importdescriptors", &[serde_json::Value::Array(to_import)])?;
    for entry in import_result.as_array().ok_or("import result")? {
        if entry["success"] != serde_json::json!(true) {
            return Err(format!("descriptor import failed: {entry}").into());
        }
    }
    Ok(restored)
}
