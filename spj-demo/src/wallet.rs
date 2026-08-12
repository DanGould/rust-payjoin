//! In-process demo wallets.
//!
//! Senders and the attacker are single-key P2WPKH wallets managed here
//! rather than in bitcoind, because silent payment derivation needs the
//! sender's input private keys at payment time. The receiver's on-chain
//! wallet stays a bitcoind descriptor wallet; only its silent payment
//! keys live in process (see [`crate::sp`]).

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Address, Amount, EcdsaSighashType, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use payjoin_test_utils::corepc_node::Client;

/// Approximate virtual size of a one-input P2WPKH transaction with a
/// taproot payment output and a P2WPKH change output, used to set an
/// honest fee before signing.
const ORIGINAL_TX_VBYTES: u64 = 154;

pub struct DemoWallet {
    pub name: &'static str,
    sk: SecretKey,
    pk: PublicKey,
    utxos: Vec<(OutPoint, TxOut)>,
}

impl DemoWallet {
    /// A deterministic wallet: same name, same keys, so reruns of the
    /// demo tell the same story.
    pub fn new(secp: &Secp256k1<All>, name: &'static str) -> Self {
        let digest = sha256::Hash::hash(name.as_bytes()).to_byte_array();
        let sk = SecretKey::from_slice(&digest)
            .expect("hash output is a valid scalar with overwhelming probability");
        Self { name, sk, pk: sk.public_key(secp), utxos: Vec::new() }
    }

    pub fn address(&self) -> Address {
        Address::p2wpkh(&CompressedPublicKey(self.pk), Network::Regtest)
    }

    pub fn script_pubkey(&self) -> ScriptBuf { self.address().script_pubkey() }

    pub fn input_keys(&self) -> Vec<SecretKey> { vec![self.sk] }

    pub fn utxos(&self) -> &[(OutPoint, TxOut)] { &self.utxos }

    pub fn balance(&self) -> Amount { self.utxos.iter().map(|(_, txout)| txout.value).sum() }

    /// Receive `amount` from a funded bitcoind wallet and record the
    /// unspent output once it confirms. The caller mines the block.
    pub fn fund(
        &mut self,
        faucet: &Client,
        amount: Amount,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let txid = faucet.send_to_address(&self.address(), amount)?.txid()?;
        let tx: Transaction = {
            let raw = faucet.get_raw_transaction(txid)?;
            raw.transaction()?
        };
        self.credit_outputs(&tx);
        Ok(())
    }

    /// Record any outputs of `tx` paying this wallet, and forget any of
    /// this wallet's outputs it spends.
    pub fn credit_outputs(&mut self, tx: &Transaction) {
        let spent: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
        self.utxos.retain(|(outpoint, _)| !spent.contains(outpoint));
        let script = self.script_pubkey();
        let txid = tx.compute_txid();
        for (vout, output) in tx.output.iter().enumerate() {
            if output.script_pubkey == script {
                let outpoint = OutPoint { txid, vout: vout as u32 };
                self.utxos.push((outpoint, output.clone()));
            }
        }
    }

    /// The largest output covering `target`, if any. Callers pick the
    /// coin before building because silent payment derivation commits
    /// to the spent outpoint.
    pub fn select_utxo(&self, target: Amount) -> Option<(OutPoint, TxOut)> {
        self.utxos
            .iter()
            .filter(|(_, txout)| txout.value >= target)
            .max_by_key(|(_, txout)| txout.value)
            .cloned()
    }

    /// Build and sign an original transaction spending `outpoint` and
    /// paying `payment_script`, returned as the finalized PSBT a
    /// payjoin sender starts from.
    pub fn build_original_from(
        &self,
        outpoint: OutPoint,
        prevout: &TxOut,
        payment_script: ScriptBuf,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Psbt, Box<dyn std::error::Error>> {
        let fee = fee_rate
            .checked_mul_by_weight(bitcoin::Weight::from_vb(ORIGINAL_TX_VBYTES).expect("small"))
            .ok_or("fee overflow")?;
        let change = prevout
            .value
            .checked_sub(amount + fee)
            .ok_or_else(|| format!("{}'s coin cannot cover {} plus fees", self.name, amount))?;
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: amount, script_pubkey: payment_script },
                TxOut { value: change, script_pubkey: self.script_pubkey() },
            ],
        };

        let witness = self.p2wpkh_witness(&tx, 0, prevout)?;
        let mut psbt = Psbt::from_unsigned_tx(tx.clone())?;
        psbt.inputs[0].witness_utxo = Some(prevout.clone());
        psbt.inputs[0].final_script_witness = Some(witness.clone());
        tx.input[0].witness = witness;
        Ok(psbt)
    }

    /// Sign this wallet's inputs in a payjoin proposal and extract the
    /// broadcastable transaction. The receiver's inputs arrive already
    /// finalized; the sender's arrive cleared for re-signing.
    pub fn sign_proposal(&self, mut psbt: Psbt) -> Result<Transaction, Box<dyn std::error::Error>> {
        let tx = psbt.unsigned_tx.clone();
        for (index, input) in tx.input.iter().enumerate() {
            let Some((_, prevout)) =
                self.utxos.iter().find(|(outpoint, _)| *outpoint == input.previous_output)
            else {
                continue;
            };
            let witness = self.p2wpkh_witness(&tx, index, prevout)?;
            psbt.inputs[index].final_script_witness = Some(witness);
        }
        Ok(psbt.extract_tx()?)
    }

    fn p2wpkh_witness(
        &self,
        tx: &Transaction,
        index: usize,
        prevout: &TxOut,
    ) -> Result<Witness, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(tx).p2wpkh_signature_hash(
            index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let signature = bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &self.sk),
            sighash_type: EcdsaSighashType::All,
        };
        Ok(Witness::p2wpkh(&signature, &self.pk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet_with_coin(value: Amount) -> DemoWallet {
        let secp = Secp256k1::new();
        let mut wallet = DemoWallet::new(&secp, "test-wallet");
        let funding = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut { value, script_pubkey: wallet.script_pubkey() }],
        };
        wallet.credit_outputs(&funding);
        wallet
    }

    #[test]
    fn original_psbt_pays_exactly_and_signs_its_input() {
        let secp = Secp256k1::new();
        let wallet = wallet_with_coin(Amount::from_btc(1.0).unwrap());
        let destination = ScriptBuf::new_p2tr(&secp, wallet.pk.x_only_public_key().0, None);
        let amount = Amount::from_sat(40_000_000);
        let (outpoint, prevout) = wallet.select_utxo(amount).expect("coin available");
        let psbt = wallet
            .build_original_from(
                outpoint,
                &prevout,
                destination.clone(),
                amount,
                FeeRate::from_sat_per_vb_u32(2),
            )
            .expect("build");

        let tx = &psbt.unsigned_tx;
        assert_eq!(tx.output[0].script_pubkey, destination);
        assert_eq!(tx.output[0].value, amount);
        let fee = Amount::from_btc(1.0).unwrap() - amount - tx.output[1].value;
        assert!(fee > Amount::ZERO, "a positive fee is paid");
        let witness = psbt.inputs[0].final_script_witness.as_ref().expect("finalized");
        assert_eq!(witness.len(), 2, "P2WPKH witness is signature plus key");
    }

    #[test]
    fn spending_forgets_the_consumed_output() {
        let mut wallet = wallet_with_coin(Amount::from_btc(1.0).unwrap());
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: wallet.utxos()[0].0,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        wallet.credit_outputs(&spend);
        assert_eq!(wallet.balance(), Amount::ZERO);
    }
}
