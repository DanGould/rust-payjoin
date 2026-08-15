//! Recorded regtest demonstration of static payjoin.
//!
//! A static payjoin endpoint is one payment string a receiver can
//! publish once and be paid over many times, by many senders, without
//! any two payments sharing an on-chain address and without the
//! receiver needing to be online when a payment starts. Each scene in
//! this demo exercises one claimed property of that construction end to
//! end — real bitcoind regtest node, real directory server code, real
//! wire bytes — and prints a narrated, self-contained account of what
//! happened.
//!
//! This crate is a demonstration harness, not a library for reuse. It
//! is split into a lib and a thin bin so scenes and helpers stay
//! individually testable.

pub mod index;
pub mod narrate;
pub mod net;
pub mod persist;
pub mod scenes;
pub mod sp;
pub mod wallet;
