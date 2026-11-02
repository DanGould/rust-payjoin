//! A regtest demonstration of silent payjoin: the payment strings a receiver
//! hands out, a localhost mailroom to carry the payjoin messages, contact logs
//! that let one string serve many payments, and a recorder that films a
//! transaction's page in a local mempool explorer.

pub mod chain;
pub mod contact;
pub mod derive;
pub mod flow;
pub mod net;
pub mod persist;
pub mod receiver;
pub mod regtest;
pub mod sender;
pub mod sp_address;
pub mod uri;
pub mod video;
pub mod wallet;
