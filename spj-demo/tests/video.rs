//! Film a confirmed regtest P2TR payment in a local mempool explorer.
//!
//! Ignored by default: it needs the built mempool checkout named in
//! `video/record-tx.sh` and takes about a minute. Run it with
//! `cargo test -p spj-demo --test video -- --ignored`, setting `SPJ_VIDEO_OUT`
//! to keep the video.

use bitcoin::{Address, Amount};
use payjoin_test_utils::bitcoind::{self, AddressType};
use spj_demo::video::{record_tx, Node};

type Error = Box<dyn std::error::Error>;

#[test]
#[ignore = "needs a built mempool checkout, MariaDB, Chromium and ffmpeg"]
fn records_a_regtest_p2tr_payment() -> Result<(), Error> {
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex");
    let node = bitcoind::BitcoinD::with_conf(bitcoind::exe_path()?, &conf)?;
    let wallet = node.create_wallet("video")?;
    let mine_to = wallet.new_address()?;
    node.client.generate_to_address(101, &mine_to)?;
    let pay_to: Address =
        wallet.get_new_address(None, Some(AddressType::Bech32m))?.into_model()?.0.assume_checked();
    let txid = wallet.send_to_address(&pay_to, Amount::from_sat(1_000_000))?.txid()?;
    node.client.generate_to_address(1, &mine_to)?;

    let dir = tempfile::tempdir()?;
    let out = std::env::var_os("SPJ_VIDEO_OUT")
        .map(Into::into)
        .unwrap_or_else(|| dir.path().join("tx.mp4"));
    record_tx(&Node::from(&node), txid, &out)?;
    assert!(std::fs::metadata(&out)?.len() > 0);
    assert!(std::fs::metadata(out.with_extension("png"))?.len() > 0);
    Ok(())
}
