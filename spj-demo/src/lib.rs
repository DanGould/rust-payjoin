//! A regtest demonstration of silent payjoin: the payment strings a receiver
//! hands out, a localhost mailroom to carry the payjoin messages, and contact
//! logs that let one string serve many payments.

pub mod contact;
pub mod net;
pub mod regtest;
pub mod sp_address;
pub mod uri;
