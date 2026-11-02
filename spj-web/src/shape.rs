//! How a transaction looks on the page and in the explorer link: whose each
//! input and output is, what it is worth, and which outputs pay a silent
//! payment address.

use std::collections::BTreeSet;
use std::process::Command;

use bitcoin::psbt::Psbt;
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use payjoin_test_utils::bitcoind;
use serde_json::{json, Value};
use spj_demo::chain;

/// Who owns what in one transaction between a payer and Bob.
pub struct Owners<'a> {
    /// The payer's name as the page shows it.
    pub payer: &'a str,
    /// The inputs Bob added. Every other input is the payer's.
    pub bob_inputs: &'a BTreeSet<OutPoint>,
    /// Outputs paying Bob. Every other output is the payer's change.
    pub bob_outputs: &'a [ScriptBuf],
    /// Which of Bob's outputs pay his silent payment address.
    pub silent: &'a [ScriptBuf],
}

impl Owners<'_> {
    /// The page's view of a PSBT. Each input's value comes from the node,
    /// or its `witness_utxo` if the node doesn't know it; an input carrying
    /// proprietary fields carries Bob's share and proof.
    pub fn psbt(&self, node: &bitcoind::Client, psbt: &Psbt) -> Value {
        let known = chain::prevouts(node, &psbt.unsigned_tx).ok();
        let prevouts: Vec<Option<TxOut>> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                known.as_ref().map(|k| k[i].clone()).or_else(|| input.witness_utxo.clone())
            })
            .collect();
        let proofs: Vec<bool> =
            psbt.inputs.iter().map(|input| !input.proprietary.is_empty()).collect();
        self.view(&psbt.unsigned_tx, &prevouts, &proofs)
    }

    /// The page's view of a transaction whose prevouts are known.
    pub fn tx(&self, tx: &Transaction, prevouts: &[TxOut]) -> Value {
        let prevouts: Vec<Option<TxOut>> = prevouts.iter().cloned().map(Some).collect();
        let proofs = vec![false; tx.input.len()];
        self.view(tx, &prevouts, &proofs)
    }

    fn view(&self, tx: &Transaction, prevouts: &[Option<TxOut>], proofs: &[bool]) -> Value {
        let inputs: Vec<Value> = tx
            .input
            .iter()
            .zip(prevouts)
            .zip(proofs)
            .map(|((input, prevout), proof)| {
                let bob = self.bob_inputs.contains(&input.previous_output);
                json!({
                    "owner": if bob { "bob" } else { self.payer },
                    "value": prevout.as_ref().map(|p| p.value.to_sat()),
                    "proof": proof,
                })
            })
            .collect();
        let outputs: Vec<Value> = tx
            .output
            .iter()
            .map(|output| {
                let bob = self.bob_outputs.contains(&output.script_pubkey);
                json!({
                    "owner": if bob { "bob" } else { self.payer },
                    "value": output.value.to_sat(),
                    "silent": self.silent.contains(&output.script_pubkey),
                    "key": output_key(&output.script_pubkey),
                })
            })
            .collect();
        json!({ "inputs": inputs, "outputs": outputs })
    }

    /// The explorer's page for `txid`, with each input and output labelled by
    /// owner and the silent payment outputs marked. The fragment is read by
    /// the explorer page only; it never reaches its server.
    pub fn explorer_link(&self, explorer: &str, txid: Txid, tx: &Transaction) -> String {
        let code = |bob: bool| if bob { 'r' } else { 's' };
        let inputs: String = tx
            .input
            .iter()
            .map(|input| code(self.bob_inputs.contains(&input.previous_output)))
            .collect();
        let outputs: String = tx
            .output
            .iter()
            .map(|output| code(self.bob_outputs.contains(&output.script_pubkey)))
            .collect();
        let silent: Vec<String> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, output)| self.silent.contains(&output.script_pubkey))
            .map(|(vout, _)| vout.to_string())
            .collect();
        let mut link =
            format!("{explorer}/tx/{txid}#pj=1:{inputs}:{outputs}:{}:Bob", self.payer_label());
        if !silent.is_empty() {
            link.push_str(&format!("&sp={}", silent.join(",")));
        }
        link
    }

    fn payer_label(&self) -> String {
        let mut chars = self.payer.chars();
        chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
    }
}

/// The ends of a taproot output's key, enough to tell two outputs apart on
/// screen. `None` for any other script.
fn output_key(script: &ScriptBuf) -> Option<String> {
    if !script.is_p2tr() {
        return None;
    }
    let hex = script.as_bytes()[2..].iter().map(|b| format!("{b:02x}")).collect::<String>();
    Some(format!("{}…{}", &hex[..4], &hex[hex.len() - 4..]))
}

/// A QR code for `text` as SVG, from the `qrencode` tool. `None` if the tool
/// isn't on the PATH; the page then shows the string alone.
pub fn qr_svg(text: &str) -> Option<String> {
    let out =
        Command::new("qrencode").args(["-t", "SVG", "-m", "1", "-o", "-", text]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{absolute, transaction, Amount, TxIn};

    use super::*;

    fn outpoint(byte: u8) -> OutPoint {
        OutPoint { txid: Txid::from_byte_array([byte; 32]), vout: 0 }
    }

    fn script(byte: u8) -> ScriptBuf { ScriptBuf::from_bytes(vec![0x51, byte]) }

    #[test]
    fn the_explorer_link_labels_each_side_and_marks_silent_outputs() {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: [1, 2]
                .map(|b| TxIn { previous_output: outpoint(b), ..Default::default() })
                .to_vec(),
            output: [3, 4]
                .map(|b| TxOut { value: Amount::from_sat(1_000), script_pubkey: script(b) })
                .to_vec(),
        };
        let bob_inputs = BTreeSet::from([outpoint(2)]);
        let bob_outputs = [script(4)];
        let owners = Owners {
            payer: "alice",
            bob_inputs: &bob_inputs,
            bob_outputs: &bob_outputs,
            silent: &bob_outputs,
        };
        let txid = tx.compute_txid();
        assert_eq!(
            owners.explorer_link("http://x", txid, &tx),
            format!("http://x/tx/{txid}#pj=1:sr:sr:Alice:Bob&sp=1")
        );
        let plain = Owners { silent: &[], ..owners };
        assert!(!plain.explorer_link("http://x", txid, &tx).contains("&sp="));
    }
}
