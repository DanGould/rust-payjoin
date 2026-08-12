//! Scene 3: the worst case. The receiver never comes back. The
//! sender's patience runs out, it broadcasts the original, and the
//! receiver's later scan still finds a plain silent payment.

use std::time::Duration;

use bitcoin::{Address, Amount, Network};

use super::{fall_back, scan_chain_for_sp, send_message_a, BoxError, Demo};
use crate::wallet::DemoWallet;

pub async fn run(demo: &mut Demo) -> Result<(), BoxError> {
    demo.narrator.scene(
        3,
        "The floor",
        "The receiver never responds. No payment is lost: the sender's \
         patience elapses, it broadcasts the original transaction, and the \
         receiver's later scan finds an ordinary silent payment.",
    );

    demo.publish_endpoint()?;

    let mut dave = DemoWallet::new(&demo.secp, "Dave");
    dave.fund(&demo.miner, Amount::from_btc(1.0)?)?;
    demo.mine(1)?;

    demo.narrator.step("Dave pays the string; the receiver is gone for good");
    let payment =
        send_message_a(demo, &dave, Amount::from_btc(0.5)?, Some(Duration::from_secs(1))).await?;
    let sp_script = payment.sp_script.clone();
    demo.narrator.result("intended output", &address_of(&sp_script)?);

    demo.narrator.step("the receiver never polls; Dave's patience window closes");
    std::thread::sleep(Duration::from_millis(1200));
    let tx = fall_back(demo, &mut dave, payment).await?;
    demo.narrator.result("broadcast", "original transaction (no receiver contribution)");
    demo.narrator.result("fallback txid", &tx.compute_txid().to_string());

    demo.narrator.step("later, the receiver scans the chain with its scan key");
    let found = scan_chain_for_sp(demo)?;
    let recovered: Amount = found.iter().map(|(_, txout, _)| txout.value).sum();
    demo.narrator.result("silent payments found", &found.len().to_string());
    demo.narrator.result("recovered", &recovered.to_string());

    let paid_derived = tx.output.iter().any(|out| out.script_pubkey == sp_script);
    let pass = paid_derived && found.iter().any(|(op, _, _)| op.txid == tx.compute_txid());
    demo.narrator.verdict(
        pass,
        "no failure path loses a payment. The receiver went dark and the \
         worst case was a vanilla silent payment the receiver still owns.",
    );
    if !pass {
        return Err("scene 3 assertions failed".into());
    }
    Ok(())
}

fn address_of(script: &bitcoin::ScriptBuf) -> Result<String, BoxError> {
    Ok(Address::from_script(script, Network::Regtest)?.to_string())
}
