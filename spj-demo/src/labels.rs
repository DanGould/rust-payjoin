//! Which BIP 352 label a receiver gives each contact.
//!
//! A one-time URI carries the receiver's unlabelled silent payment address.
//! Its fresh mailbox already tells the receiver which URI a payer used, and
//! every label costs a light client one more filter lookup per transaction.
//! A contact gets one label, fixed for as long as the contact lasts, so the
//! receiver can tell which contact a transfer came from. Label 0 stays
//! reserved for change, as BIP 352 says, so contacts are numbered from 1.

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

    /// The label the next contact takes: one above the highest handed
    /// out, so no two contacts share one.
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
    fn contacts_take_labels_from_1_and_keep_them() {
        let secp = Secp256k1::new();
        let keys = SpKeys::from_seed("labels test");
        let mut book = LabelBook::new(&secp, &keys);
        assert_eq!(book.next(), 1, "label 0 is change");

        let (exchange, address) = book.contact_address(&secp, &keys, "Exchange").unwrap();
        let (friend, _) = book.contact_address(&secp, &keys, "Friend").unwrap();
        assert_eq!((exchange, friend), (1, 2));

        let (again, same) = book.contact_address(&secp, &keys, "Exchange").unwrap();
        assert_eq!((again, same), (exchange, address), "a contact keeps its label");
        assert_eq!(same, keys.labelled_address(&secp, exchange).unwrap());
        assert_eq!(book.purpose(exchange), Some(&Purpose::Contact("Exchange".into())));
        assert_eq!(book.table().len(), 3);
        assert_eq!(book.table().highest(), Some(2));
    }
}
