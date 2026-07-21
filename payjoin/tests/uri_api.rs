//! Assertions on payjoin's public BIP 21 URI surface.
//!
//! The point of these tests is that every type named here is payjoin's own. No type from
//! the underlying BIP 21 parser may appear in a signature a downstream crate can observe,
//! so that the parser can be swapped or upgraded without a payjoin major release.
//! See issue #644.

use std::error::Error;

use payjoin::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use payjoin::bitcoin::{Amount, Network};
use payjoin::{PjParseError, Uri, UriParseError};

const NO_PJ: &str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1";

#[test]
fn parse_error_is_a_payjoin_type() {
    // The annotation is the assertion: a malformed BIP 21 URI must fail with payjoin's
    // own error, not with the parser's.
    let err: UriParseError = Uri::try_from("bitcoin:this is not a valid uri &&&").unwrap_err();
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_some(), "the underlying cause should stay reachable");
}

#[test]
fn payjoin_param_error_is_reachable_as_a_payjoin_type() {
    // A well formed BIP 21 URI with a bad `pjos` value fails in payjoin's own extras
    // parser. Downstream must be able to recover the concrete payjoin error from the
    // source chain rather than string-matching.
    let err: UriParseError =
        Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=2").unwrap_err();
    let source = err.source().expect("payjoin parameter errors have a source");
    assert!(
        source.downcast_ref::<PjParseError>().is_some(),
        "expected a payjoin::PjParseError, got: {source}"
    );
}

#[test]
fn accessors_replace_public_fields() {
    let uri: Uri<NetworkUnchecked> = NO_PJ.parse().expect("valid BIP 21 uri");
    let uri: Uri<NetworkChecked> = uri.assume_checked();

    assert_eq!(uri.address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
    assert_eq!(uri.amount(), Some(Amount::ONE_BTC));
    assert_eq!(uri.label(), None);
    assert_eq!(uri.message(), None);
    assert!(!uri.extras().pj_is_supported());
}

#[test]
fn label_and_message_decode_to_strings() {
    let uri = Uri::try_from(
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?label=Luke-Jr&message=Donation%20for%20xyz",
    )
    .expect("valid BIP 21 uri")
    .assume_checked();

    assert_eq!(uri.label().as_deref(), Some("Luke-Jr"));
    assert_eq!(uri.message().as_deref(), Some("Donation for xyz"));
}

#[test]
fn require_network_reports_a_payjoin_error() {
    let err: UriParseError = Uri::try_from(NO_PJ)
        .expect("valid BIP 21 uri")
        .require_network(Network::Testnet)
        .expect_err("mainnet address must not satisfy testnet");
    assert!(!err.to_string().is_empty());
}

#[test]
fn check_pj_supported_hands_back_a_payjoin_uri() {
    // The unsupported branch used to return the parser's own URI type. It now returns
    // payjoin's, so the caller keeps a usable value without naming a foreign type.
    let returned: Box<Uri<NetworkChecked>> = Uri::try_from(NO_PJ)
        .expect("valid BIP 21 uri")
        .assume_checked()
        .check_pj_supported()
        .expect_err("this uri has no pj parameter");
    assert_eq!(returned.to_string(), NO_PJ);
}
