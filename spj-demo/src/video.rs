//! Film a transaction's page in a local mempool explorer.
//!
//! [`record_tx`] runs `video/record-tx.sh` from this crate, which starts
//! MariaDB, a mempool backend pointed at the caller's regtest bitcoind, the
//! mempool frontend and headless Chromium, all on localhost, captures the
//! transaction page and encodes it with ffmpeg. The script stops everything it
//! started before it returns. See the script for the tools it needs.

use std::path::{Path, PathBuf};
use std::process::Command;

use bitcoin::Txid;

/// The regtest bitcoind a recording reads from: its RPC port on 127.0.0.1 and
/// its cookie file. For a confirmed transaction the node needs `-txindex`.
#[derive(Debug, Clone)]
pub struct Node {
    pub rpc_port: u16,
    pub cookie: PathBuf,
}

/// Record the mempool page for `txid` to `out`, an `.mp4` path. A full-page
/// screenshot is written beside it with a `.png` extension. Takes about a
/// minute, most of it the backend's first sync.
pub fn record_tx(node: &Node, txid: Txid, out: &Path) -> std::io::Result<()> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("video/record-tx.sh");
    let status = Command::new(script)
        .arg("--rpc-port")
        .arg(node.rpc_port.to_string())
        .arg("--cookie")
        .arg(&node.cookie)
        .arg("--txid")
        .arg(txid.to_string())
        .arg("--out")
        .arg(out)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("record-tx.sh failed: {status}")))
    }
}

impl From<&payjoin_test_utils::bitcoind::BitcoinD> for Node {
    fn from(bitcoind: &payjoin_test_utils::bitcoind::BitcoinD) -> Self {
        Self {
            rpc_port: bitcoind.params.rpc_socket.port(),
            cookie: bitcoind.params.cookie_file.clone(),
        }
    }
}
