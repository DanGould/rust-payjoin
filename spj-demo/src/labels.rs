//! Which BIP 352 label a receiver puts in each URI it hands out.
//!
//! When the receiver adds a coin it received as a silent payment to a
//! payjoin, the coin's BIP 375 share is `(b_m + t)·B_scan`, where `b_m` is
//! the spend secret of the label `m` the coin was paid on and `t` the
//! coin's output tweak. A payer that knows `t`, because it made the coin,
//! learns `b_scan·B_m` from the share. For the unlabelled address that is
//! `b_scan·B_spend`, which lets the payer pick out the receiver's outputs
//! in any later spend made only of coins it paid. For a label it covers
//! that label alone. So each one-time URI gets a fresh label, and each
//! contact gets one label, fixed for as long as the contact lasts, so what
//! a contact can learn covers only the coins it paid. Label 0 stays
//! reserved for change, as BIP 352 says.

use std::collections::BTreeMap;

use bitcoin::secp256k1::{All, Secp256k1};
use spj_crypto::bip352::Labels;

use crate::derive::SpKeys;
use crate::sp_address::SpAddress;

/// BIP 352's label for the receiver's own change.
pub const CHANGE: u32 = 0;

/// What a label was handed out for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purpose {
    Change,
    /// A one-time URI, as handed out.
    OneTime(String),
    /// A contact, by the name the receiver gave it.
    Contact(String),
}

/// The labels a receiver has handed out and the table it scans with.
#[derive(Clone, Debug)]
pub struct LabelBook {
    purposes: BTreeMap<u32, Purpose>,
    table: Labels,
}

impl LabelBook {
    pub fn new(secp: &Secp256k1<All>, keys: &SpKeys) -> Self {
        Self {
            purposes: BTreeMap::from([(CHANGE, Purpose::Change)]),
            table: keys.labels(secp, [CHANGE]),
        }
    }

    /// The label the next one-time URI takes: one above the highest
    /// handed out, so no two URIs share one.
    pub fn next(&self) -> u32 { self.purposes.last_key_value().map_or(CHANGE, |(m, _)| m + 1) }

    /// Record that label `m` went to `purpose`, and scan for it from now on.
    pub fn record(&mut self, secp: &Secp256k1<All>, keys: &SpKeys, m: u32, purpose: Purpose) {
        self.table.insert(secp, &keys.scan, m);
        self.purposes.insert(m, purpose);
    }

    /// The label of the contact named `name`, if it has one.
    pub fn contact(&self, name: &str) -> Option<u32> {
        self.purposes
            .iter()
            .find(|(_, purpose)| **purpose == Purpose::Contact(name.to_owned()))
            .map(|(m, _)| *m)
    }

    /// The contact named `name`'s label and address, handing it the next
    /// label the first time.
    pub fn contact_address(
        &mut self,
        secp: &Secp256k1<All>,
        keys: &SpKeys,
        name: &str,
    ) -> Option<(u32, SpAddress)> {
        let m = match self.contact(name) {
            Some(m) => m,
            None => {
                let m = self.next();
                self.record(secp, keys, m, Purpose::Contact(name.to_owned()));
                m
            }
        };
        Some((m, keys.labelled_address(secp, m)?))
    }

    pub fn purpose(&self, m: u32) -> Option<&Purpose> { self.purposes.get(&m) }

    /// Every label handed out, for scanning.
    pub fn table(&self) -> &Labels { &self.table }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_uris_take_fresh_labels_and_a_contact_keeps_its_own() {
        let secp = Secp256k1::new();
        let keys = SpKeys::from_seed("labels test");
        let mut book = LabelBook::new(&secp, &keys);
        assert_eq!(book.next(), 1, "label 0 is change");

        let first = book.next();
        book.record(&secp, &keys, first, Purpose::OneTime("uri 1".into()));
        let (exchange, address) = book.contact_address(&secp, &keys, "Exchange").unwrap();
        let second = book.next();
        book.record(&secp, &keys, second, Purpose::OneTime("uri 2".into()));
        assert_eq!((first, exchange, second), (1, 2, 3));

        let (again, same) = book.contact_address(&secp, &keys, "Exchange").unwrap();
        assert_eq!((again, same), (exchange, address), "a contact keeps its label");
        assert_eq!(same, keys.labelled_address(&secp, exchange).unwrap());
        assert_eq!(book.purpose(first), Some(&Purpose::OneTime("uri 1".into())));
        assert_eq!(book.table().len(), 4);
        assert_eq!(book.table().highest(), Some(3));
    }
}
