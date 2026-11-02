//! In-process keychains for the demo's parties.
//!
//! Silent payments need the secret key of every input a sender spends, and a
//! receiver proving a BIP 375 share needs its coin's key, so the parties keep
//! their keys here instead of in a Bitcoin Core wallet. A [`Keychain`] is one
//! BIP 32 account: BIP 86 for P2TR or BIP 84 for P2WPKH, with a receive and a
//! change chain, on regtest. It tracks its coins from the transactions it is
//! shown and signs its own inputs in any PSBT whose prevouts are all filled in.

use std::collections::{BTreeSet, HashMap};

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    absolute, transaction, Address, Amount, CompressedPublicKey, EcdsaSighashType, FeeRate,
    Network, NetworkKind, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Weight, Witness,
};
use payjoin::receive::InputPair;
use spj_crypto::bip352::{self, InputKind};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Spending a P2TR output by key path: a 64-byte signature and its witness
/// framing, plus the input's non-witness bytes.
pub const P2TR_INPUT_WEIGHT: Weight = Weight::from_wu(230);
/// Spending a P2WPKH output with a 72-byte signature, the most a low-S DER
/// signature takes.
pub const P2WPKH_INPUT_WEIGHT: Weight = Weight::from_wu(272);

/// The script type of every output a keychain makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// BIP 86 single-key taproot.
    P2tr,
    /// BIP 84 native segwit v0.
    P2wpkh,
}

impl KeyKind {
    fn purpose(self) -> u32 {
        match self {
            KeyKind::P2tr => 86,
            KeyKind::P2wpkh => 84,
        }
    }

    pub fn input_weight(self) -> Weight {
        match self {
            KeyKind::P2tr => P2TR_INPUT_WEIGHT,
            KeyKind::P2wpkh => P2WPKH_INPUT_WEIGHT,
        }
    }

    /// The witness part of [`KeyKind::input_weight`]: the stack item count
    /// and each item with its length prefix.
    fn witness_weight(self) -> Weight {
        match self {
            KeyKind::P2tr => Weight::from_wu(1 + 1 + 64),
            KeyKind::P2wpkh => Weight::from_wu(1 + 1 + 72 + 1 + 33),
        }
    }

    fn bip352_kind(self) -> InputKind {
        match self {
            KeyKind::P2tr => InputKind::P2tr,
            KeyKind::P2wpkh => InputKind::P2wpkh,
        }
    }
}

/// An unspent output a keychain holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

/// One BIP 32 account on regtest.
pub struct Keychain {
    pub name: String,
    kind: KeyKind,
    secp: Secp256k1<All>,
    account: Xpriv,
    next_index: [u32; 2],
    /// Every script handed out, with the key that signs for it.
    keys: HashMap<ScriptBuf, SecretKey>,
    coins: Vec<Coin>,
    /// Coins offered to a payjoin that hasn't settled yet. They are not
    /// offered again or spent until released.
    reserved: BTreeSet<OutPoint>,
}

impl Keychain {
    /// Account `account` of the wallet whose seed is the SHA-256 of `seed`,
    /// so the same name always gives the same keys.
    pub fn new(name: &str, seed: &str, kind: KeyKind, account: u32) -> Self {
        let secp = Secp256k1::new();
        let seed = sha256::Hash::hash(seed.as_bytes()).to_byte_array();
        let master =
            Xpriv::new_master(NetworkKind::Test, &seed).expect("a 32-byte seed is a valid master");
        let path: DerivationPath = [
            ChildNumber::from_hardened_idx(kind.purpose()),
            ChildNumber::from_hardened_idx(1),
            ChildNumber::from_hardened_idx(account),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("small indices are valid")
        .into();
        let account = master.derive_priv(&secp, &path).expect("hardened derivation succeeds");
        Self {
            name: name.to_string(),
            kind,
            secp,
            account,
            next_index: [0, 0],
            keys: HashMap::new(),
            coins: Vec::new(),
            reserved: BTreeSet::new(),
        }
    }

    pub fn kind(&self) -> KeyKind { self.kind }

    fn derive(&mut self, chain: u32) -> ScriptBuf {
        let index = self.next_index[chain as usize];
        self.next_index[chain as usize] += 1;
        let path = [
            ChildNumber::from_normal_idx(chain).expect("0 and 1 are normal indices"),
            ChildNumber::from_normal_idx(index).expect("index below 2^31"),
        ];
        let secret = self
            .account
            .derive_priv(&self.secp, &path)
            .expect("normal derivation succeeds")
            .private_key;
        let (script, signing) = match self.kind {
            KeyKind::P2tr => {
                // BIP 86: the output key is the internal key tweaked with an
                // empty script tree, and the key path signs with the tweaked
                // secret.
                let keypair = Keypair::from_secret_key(&self.secp, &secret);
                let (internal, _) = keypair.x_only_public_key();
                let address = Address::p2tr(&self.secp, internal, None, Network::Regtest);
                let tweaked = keypair.tap_tweak(&self.secp, None).to_keypair();
                (address.script_pubkey(), tweaked.secret_key())
            }
            KeyKind::P2wpkh => {
                let public = CompressedPublicKey(secret.public_key(&self.secp));
                (Address::p2wpkh(&public, Network::Regtest).script_pubkey(), secret)
            }
        };
        self.keys.insert(script.clone(), signing);
        script
    }

    /// A fresh receive address.
    pub fn address(&mut self) -> Address {
        let script = self.derive(0);
        Address::from_script(&script, Network::Regtest).expect("standard script")
    }

    /// A fresh change script.
    pub fn change_script(&mut self) -> ScriptBuf { self.derive(1) }

    pub fn owns(&self, script: &bitcoin::Script) -> bool { self.keys.contains_key(script) }

    /// The secret that signs a key-path spend of `script`. For BIP 86 that is
    /// the tweaked key, not the account's internal key.
    pub fn signing_key(&self, script: &bitcoin::Script) -> Option<SecretKey> {
        self.keys.get(script).copied()
    }

    /// The secret BIP 352 uses for an input spending `script`: the signing key,
    /// negated when a taproot output key has odd y.
    pub fn bip352_secret(&self, script: &bitcoin::Script) -> Option<SecretKey> {
        let signing = self.signing_key(script)?;
        Some(bip352::input_secret_key(&self.secp, &signing, self.kind.bip352_kind()))
    }

    pub fn coins(&self) -> &[Coin] { &self.coins }

    pub fn balance(&self) -> Amount { self.coins.iter().map(|coin| coin.txout.value).sum() }

    /// Learn from a transaction: forget coins it spends, keep outputs paying
    /// this keychain.
    pub fn credit(&mut self, tx: &Transaction) {
        let spent: BTreeSet<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        self.coins.retain(|coin| !spent.contains(&coin.outpoint));
        let txid = tx.compute_txid();
        for (vout, txout) in tx.output.iter().enumerate() {
            let outpoint = OutPoint { txid, vout: vout as u32 };
            if self.owns(&txout.script_pubkey) && !self.coins.iter().any(|c| c.outpoint == outpoint)
            {
                self.coins.push(Coin { outpoint, txout: txout.clone() });
            }
        }
    }

    /// Forget the coins `tx` spends, without taking its outputs as coins.
    pub fn forget_spent(&mut self, tx: &Transaction) {
        let spent: BTreeSet<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        self.coins.retain(|coin| !spent.contains(&coin.outpoint));
    }

    /// Hold a coin for a payjoin in progress.
    pub fn reserve(&mut self, outpoint: OutPoint) { self.reserved.insert(outpoint); }

    /// Free a coin after its payjoin settled one way or the other.
    pub fn release(&mut self, outpoint: &OutPoint) { self.reserved.remove(outpoint); }

    /// Coins neither reserved nor spent, largest first.
    pub fn spendable(&self) -> Vec<Coin> {
        let mut coins: Vec<Coin> =
            self.coins.iter().filter(|c| !self.reserved.contains(&c.outpoint)).cloned().collect();
        coins.sort_by_key(|coin| std::cmp::Reverse(coin.txout.value));
        coins
    }

    /// Largest-first coins covering `target`.
    pub fn select(&self, target: Amount) -> Option<Vec<Coin>> {
        let mut selected = Vec::new();
        let mut total = Amount::ZERO;
        for coin in self.spendable() {
            if total >= target {
                break;
            }
            total += coin.txout.value;
            selected.push(coin);
        }
        (total >= target).then_some(selected)
    }

    /// A coin as a payjoin receiver contributes it.
    pub fn input_pair(&self, coin: &Coin) -> Result<InputPair, Error> {
        let txin = TxIn { previous_output: coin.outpoint, ..Default::default() };
        let psbtin = PsbtInput { witness_utxo: Some(coin.txout.clone()), ..Default::default() };
        let weight = (self.kind == KeyKind::P2tr).then_some(P2TR_INPUT_WEIGHT);
        Ok(InputPair::new(txin, psbtin, weight)?)
    }

    /// Sign and finalize every input of `psbt` this keychain owns. Every
    /// input needs its `witness_utxo`, because a taproot signature commits to
    /// all of the transaction's prevouts.
    pub fn sign(&self, psbt: &mut Psbt) -> Result<(), Error> {
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|input| input.witness_utxo.clone().ok_or("an input lacks its witness_utxo"))
            .collect::<Result<_, _>>()?;
        let tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        for (index, prevout) in prevouts.iter().enumerate() {
            let Some(secret) = self.signing_key(&prevout.script_pubkey) else { continue };
            let witness = match self.kind {
                KeyKind::P2tr => {
                    let sighash = cache.taproot_key_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )?;
                    let keypair = Keypair::from_secret_key(&self.secp, &secret);
                    let signature = self.secp.sign_schnorr_no_aux_rand(
                        &Message::from_digest(sighash.to_byte_array()),
                        &keypair,
                    );
                    Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
                        signature,
                        sighash_type: TapSighashType::Default,
                    })
                }
                KeyKind::P2wpkh => {
                    let sighash = cache.p2wpkh_signature_hash(
                        index,
                        &prevout.script_pubkey,
                        prevout.value,
                        EcdsaSighashType::All,
                    )?;
                    let signature = self
                        .secp
                        .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &secret);
                    Witness::p2wpkh(
                        &bitcoin::ecdsa::Signature {
                            signature,
                            sighash_type: EcdsaSighashType::All,
                        },
                        &secret.public_key(&self.secp),
                    )
                }
            };
            psbt.inputs[index].final_script_witness = Some(witness);
        }
        Ok(())
    }

    /// A signed Original spending `coins` to `payments`, with change back to
    /// this keychain at `fee_rate`. Returned as the finalized PSBT a payjoin
    /// sender starts from.
    pub fn original(
        &mut self,
        coins: &[Coin],
        payments: Vec<TxOut>,
        fee_rate: FeeRate,
    ) -> Result<Psbt, Error> {
        let change_script = self.change_script();
        let input: Vec<TxIn> = coins
            .iter()
            .map(|coin| TxIn {
                previous_output: coin.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();
        let mut output = payments;
        output.push(TxOut { value: Amount::ZERO, script_pubkey: change_script });
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        // The unsigned transaction already counts each input's outpoint,
        // sequence and empty scriptSig. Signing adds the segwit marker and
        // flag and one witness per input.
        let weight =
            tx.weight() + Weight::from_wu(2) + self.kind.witness_weight() * coins.len() as u64;
        let fee = fee_rate.fee_vb(weight.to_vbytes_ceil()).ok_or("fee overflow")?;
        let spent: Amount = coins.iter().map(|coin| coin.txout.value).sum();
        let paid: Amount = tx.output.iter().map(|out| out.value).sum();
        let change = spent
            .checked_sub(paid + fee)
            .filter(|change| *change >= Amount::from_sat(1_000))
            .ok_or_else(|| format!("{} can't cover {paid} plus {fee} fee", self.name))?;
        tx.output.last_mut().expect("change was pushed").value = change;

        let mut psbt = Psbt::from_unsigned_tx(tx)?;
        for (input, coin) in psbt.inputs.iter_mut().zip(coins) {
            input.witness_utxo = Some(coin.txout.clone());
        }
        self.sign(&mut psbt)?;
        Ok(psbt)
    }
}

/// The transaction a finalized PSBT encodes, without the fee-rate sanity
/// check `extract_tx` applies.
pub fn extract(psbt: &Psbt) -> Transaction { psbt.clone().extract_tx_unchecked_fee_rate() }

#[cfg(test)]
mod tests {
    use super::*;

    fn funded(kind: KeyKind) -> Keychain {
        let mut keychain = Keychain::new("test", "test seed", kind, 0);
        let address = keychain.address();
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        keychain.credit(&funding);
        keychain
    }

    #[test]
    fn bip86_signing_key_matches_the_output_key() {
        let mut keychain = Keychain::new("test", "test seed", KeyKind::P2tr, 0);
        let script = keychain.address().script_pubkey();
        let secp = Secp256k1::new();
        let signing = keychain.signing_key(&script).unwrap();
        let (x_only, _) = signing.x_only_public_key(&secp);
        assert_eq!(&script.as_bytes()[2..], &x_only.serialize());
        // BIP 352 reads the even-y point, so its secret must match that point.
        let bip352 = keychain.bip352_secret(&script).unwrap();
        let (_, key) = bip352::input_public_key(
            &ScriptBuf::new(),
            &Witness::from_slice(&[[0u8; 64]]),
            &script,
        )
        .unwrap();
        assert_eq!(bip352.public_key(&secp), key);
    }

    #[test]
    fn original_signs_every_input_and_pays_change() {
        for kind in [KeyKind::P2tr, KeyKind::P2wpkh] {
            let mut keychain = funded(kind);
            let coins = keychain.select(Amount::from_sat(60_000)).unwrap();
            let payee = TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            let psbt =
                keychain.original(&coins, vec![payee], FeeRate::from_sat_per_vb_u32(2)).unwrap();
            assert!(psbt.inputs.iter().all(|input| input.final_script_witness.is_some()));
            let tx = extract(&psbt);
            let fee = Amount::from_sat(100_000) - tx.output.iter().map(|o| o.value).sum();
            let vsize = tx.vsize() as u64;
            assert!(fee >= Amount::from_sat(2 * vsize) && fee <= Amount::from_sat(2 * vsize + 2));
            assert!(keychain.owns(&tx.output[1].script_pubkey), "change returns to the keychain");
        }
    }
}
