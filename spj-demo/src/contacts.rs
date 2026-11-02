//! A payer's address book.
//!
//! A one-time URI is for one payment, but its `sp=` address can be paid
//! again. A payer that keeps it gets a contact it can pay with silent
//! payments, without payjoin until the receiver hands out a contact URI.

use crate::contact::ContactUri;
use crate::sp_address::SpAddress;
use crate::uri::OneTimeUri;

/// The note a wallet shows on a contact it can pay only with plain silent
/// payments. It doesn't block paying.
pub const NO_REUSABLE_PAYJOIN: &str =
    "this contact has silent payments but no reusable payjoin yet";

#[derive(Clone, Debug)]
pub struct Contact {
    pub name: String,
    pub sp: SpAddress,
    /// The receiver's contact URI, if it gave one.
    pub payjoin: Option<ContactUri>,
}

impl Contact {
    pub fn note(&self) -> Option<&'static str> {
        self.payjoin.is_none().then_some(NO_REUSABLE_PAYJOIN)
    }
}

#[derive(Default)]
pub struct Contacts {
    entries: Vec<Contact>,
}

impl Contacts {
    /// Keep the silent payment address of a one-time URI that was paid.
    pub fn save_one_time(&mut self, name: &str, uri: &OneTimeUri) -> &Contact {
        self.save(Contact { name: name.to_string(), sp: uri.sp, payjoin: None })
    }

    /// Keep a contact URI.
    pub fn save_contact_uri(&mut self, name: &str, uri: &ContactUri) -> &Contact {
        self.save(Contact { name: name.to_string(), sp: uri.sp, payjoin: Some(uri.clone()) })
    }

    /// Add or update the contact with this silent payment address. A contact
    /// URI, once known, is kept.
    fn save(&mut self, contact: Contact) -> &Contact {
        match self.entries.iter().position(|c| c.sp == contact.sp) {
            Some(i) => {
                let existing = &mut self.entries[i];
                existing.name = contact.name;
                if contact.payjoin.is_some() {
                    existing.payjoin = contact.payjoin;
                }
                &self.entries[i]
            }
            None => {
                self.entries.push(contact);
                self.entries.last().expect("just pushed")
            }
        }
    }

    pub fn get(&self, sp: &SpAddress) -> Option<&Contact> {
        self.entries.iter().find(|c| c.sp == *sp)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Amount, Network};
    use payjoin::{HpkeKeyPair, OhttpKeys, Url};

    use super::*;

    fn sp() -> SpAddress {
        let secp = Secp256k1::new();
        let key = |byte| SecretKey::from_slice(&[byte; 32]).unwrap().public_key(&secp);
        SpAddress::new(key(1), key(2), Network::Regtest)
    }

    #[test]
    fn a_saved_one_time_uri_has_no_reusable_payjoin_until_a_contact_uri_arrives() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[3; 32]).unwrap().x_only_public_key(&secp).0;
        let address = Address::p2tr(&secp, key, None, Network::Regtest);
        let one_time = OneTimeUri::without_payjoin(address, Some(Amount::from_sat(1_000)), sp());
        let mut contacts = Contacts::default();
        assert_eq!(contacts.save_one_time("Bob", &one_time).note(), Some(NO_REUSABLE_PAYJOIN));

        let ohttp = OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap();
        let uri = ContactUri::new(
            sp(),
            Url::parse("https://payjo.in").unwrap(),
            ohttp,
            &HpkeKeyPair::gen_keypair(),
        );
        assert_eq!(contacts.save_contact_uri("Bob", &uri).note(), None);
        assert_eq!(contacts.save_one_time("Bob", &one_time).note(), None, "a contact URI is kept");
        assert!(contacts.get(&sp()).is_some_and(|c| c.payjoin.is_some()));
    }
}
