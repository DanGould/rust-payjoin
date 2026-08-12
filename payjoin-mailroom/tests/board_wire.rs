//! Wire-level tests for bulletin board endpoints.
//!
//! Board routes are reachable only through the OHTTP gateway. Reads
//! form their own fixed response size class; submissions keep the
//! standard mailbox size. With the board disabled (the default), the
//! `/board` path is handled by the mailbox routes exactly as it was
//! before the board existed: it is not a valid mailbox id, so it is
//! rejected as one.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use bitcoin::hashes::{sha256d, Hash};
use common::{ohttp_roundtrip_expecting, test_directory, PADDED_MESSAGE_BYTES};
use http_body_util::BodyExt;
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use payjoin_mailroom::admission::{DedupeSet, PowAdmission};
use payjoin_mailroom::db::board::BoardStore;
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::{Board, Service};

/// The wire size of every encapsulated board read response, pinned as a
/// literal independently of the server's derivation.
const ENCAPSULATED_BOARD_RESPONSE_BYTES: usize = 16384;

/// Board submission layout, pinned as literals: an 8-byte proof-of-work
/// nonce followed by a 512-byte blob.
const NONCE_BYTES: usize = 8;
const BLOB_BYTES: usize = 512;

/// The inner body of a board read: sixteen blob slots.
const BOARD_PAGE_BYTES: usize = 16 * BLOB_BYTES;

/// A low target keeps test mining to a few hundred hashes.
const TEST_POW_BITS: u8 = 8;

const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 7);

async fn board_directory(pow_bits: u8, cap: usize) -> (Service<FilesDb>, Vec<u8>) {
    let td = test_directory().await;
    let board_dir = td.storage_dir.join("board");
    let store = BoardStore::init(board_dir.clone(), TTL, cap).await.expect("board store init");
    let dedupe = DedupeSet::open(board_dir.join("admitted.tags")).await.expect("dedupe set");
    let admission = Arc::new(PowAdmission::new(pow_bits, Some(dedupe)));
    (td.svc.with_board(Board::new(store, admission)), td.ohttp_keys)
}

fn blob(fill: u8) -> Vec<u8> { vec![fill; BLOB_BYTES] }

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &byte in bytes {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Mine a submission body (`nonce || blob`) meeting `bits` leading zero
/// bits of sha256d over the whole body.
fn mine(blob: &[u8], bits: u8) -> Vec<u8> {
    assert_eq!(blob.len(), BLOB_BYTES);
    for nonce in 0u64.. {
        let mut body = nonce.to_be_bytes().to_vec();
        body.extend_from_slice(blob);
        let digest = sha256d::Hash::hash(&body).to_byte_array();
        if leading_zero_bits(&digest) >= u32::from(bits) {
            return body;
        }
    }
    unreachable!("some nonce meets the target")
}

/// Submit an encapsulated request and return only the outer response
/// status, for pinning routes whose errors escape encapsulation.
async fn outer_status(
    svc: &mut Service<FilesDb>,
    ohttp_keys: &[u8],
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> StatusCode {
    let mut bhttp_req = bhttp::Message::request(
        method.as_bytes().to_vec(),
        b"https".to_vec(),
        b"localhost".to_vec(),
        path.as_bytes().to_vec(),
    );
    if let Some(body) = body {
        bhttp_req.write_content(body);
    }
    let mut padded = vec![0u8; ENCAPSULATED_MESSAGE_BYTES - (65 + 16 + 7)];
    bhttp_req
        .write_bhttp(bhttp::Mode::KnownLength, &mut padded.as_mut_slice())
        .expect("request must fit in padded buffer");
    let (enc_req, _res_ctx) = ohttp::ClientRequest::from_encoded_config(ohttp_keys)
        .expect("client config")
        .encapsulate(&padded)
        .expect("encapsulation");

    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost/.well-known/ohttp-gateway")
        .body(Body::from(enc_req))
        .expect("request");
    let res = tower::Service::call(svc, req).await.expect("gateway call");
    let (parts, body) = res.into_parts();
    let _ = body.collect().await.expect("body");
    parts.status
}

#[tokio::test]
async fn board_routes_absent_without_config() {
    let td = test_directory().await;
    let mut svc = td.svc;
    let submission = mine(&blob(1), TEST_POW_BITS);

    // Without a board, "board" is handled as a (necessarily invalid)
    // mailbox id, whose rejection escapes encapsulation as an outer
    // 400, exactly as before the board existed.
    let status = outer_status(&mut svc, &td.ohttp_keys, "POST", "/board", Some(&submission)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let status = outer_status(&mut svc, &td.ohttp_keys, "GET", "/board?since=0", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn board_post_and_read_roundtrip() {
    let (mut svc, keys) = board_directory(TEST_POW_BITS, 64).await;

    // Submissions stay in the standard response size class.
    for fill in [0xA1, 0xA2] {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            "/board",
            Some(&mine(&blob(fill), TEST_POW_BITS)),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200);
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=0",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body.len(), BOARD_PAGE_BYTES, "page body length is constant");
    assert_eq!(&res.body[..BLOB_BYTES], &blob(0xA1)[..]);
    assert_eq!(&res.body[BLOB_BYTES..2 * BLOB_BYTES], &blob(0xA2)[..]);
    assert!(
        res.body[2 * BLOB_BYTES..].iter().all(|&b| b == 0),
        "unused blob slots are zero-filled"
    );
    assert_eq!(res.header("x-pj-next"), Some("2"));

    // Resuming from the middle skips earlier entries.
    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=1",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(&res.body[..BLOB_BYTES], &blob(0xA2)[..]);
    assert_eq!(res.header("x-pj-next"), Some("2"));

    // Reading past the end returns an all-zero page of the same size.
    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=2",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert!(res.body.iter().all(|&b| b == 0));
    assert_eq!(res.header("x-pj-next"), Some("2"), "index does not advance past the end");
}

#[tokio::test]
async fn board_reads_paginate_in_fixed_pages() {
    let (mut svc, keys) = board_directory(TEST_POW_BITS, 64).await;

    for fill in 1..=18u8 {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            "/board",
            Some(&mine(&blob(fill), TEST_POW_BITS)),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200);
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=0",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    for (i, fill) in (1..=16u8).enumerate() {
        assert_eq!(
            &res.body[i * BLOB_BYTES..(i + 1) * BLOB_BYTES],
            &blob(fill)[..],
            "first page carries the first sixteen entries"
        );
    }
    assert_eq!(res.header("x-pj-next"), Some("16"));

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=16",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(&res.body[..BLOB_BYTES], &blob(17)[..]);
    assert_eq!(&res.body[BLOB_BYTES..2 * BLOB_BYTES], &blob(18)[..]);
    assert!(res.body[2 * BLOB_BYTES..].iter().all(|&b| b == 0));
    assert_eq!(res.header("x-pj-next"), Some("18"));
}

#[tokio::test]
async fn board_rejects_insufficient_work() {
    // The server demands 32 bits; a body mined to 8 falls short.
    let (mut svc, keys) = board_directory(32, 64).await;

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "POST",
        "/board",
        Some(&mine(&blob(1), TEST_POW_BITS)),
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 429);

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=0",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert!(res.body.iter().all(|&b| b == 0), "a rejected submission is not stored");
}

#[tokio::test]
async fn board_rejects_malformed_submission() {
    let (mut svc, keys) = board_directory(TEST_POW_BITS, 64).await;

    for len in [0, NONCE_BYTES + BLOB_BYTES - 1, NONCE_BYTES + BLOB_BYTES + 1] {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            "/board",
            Some(&vec![0u8; len]),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 400, "submission of {len} bytes must be rejected");
    }
}

#[tokio::test]
async fn board_replay_is_acknowledged_but_stored_once() {
    let (mut svc, keys) = board_directory(TEST_POW_BITS, 64).await;
    let submission = mine(&blob(0xB0), TEST_POW_BITS);

    for _ in 0..2 {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            "/board",
            Some(&submission),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200, "a replayed submission is acknowledged");
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=0",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(&res.body[..BLOB_BYTES], &blob(0xB0)[..]);
    assert!(res.body[BLOB_BYTES..].iter().all(|&b| b == 0), "the entry is stored only once");
    assert_eq!(res.header("x-pj-next"), Some("1"));
}

#[tokio::test]
async fn board_full_returns_service_unavailable() {
    let (mut svc, keys) = board_directory(TEST_POW_BITS, 2).await;

    for fill in [1, 2] {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            "/board",
            Some(&mine(&blob(fill), TEST_POW_BITS)),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200);
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "POST",
        "/board",
        Some(&mine(&blob(3), TEST_POW_BITS)),
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 503, "a full board rejects new submissions");

    // Existing entries are untouched.
    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        "/board?since=0",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(&res.body[..BLOB_BYTES], &blob(1)[..]);
    assert_eq!(&res.body[BLOB_BYTES..2 * BLOB_BYTES], &blob(2)[..]);
}

#[tokio::test]
async fn standard_mailbox_unchanged_with_board_enabled() {
    let (mut svc, keys) = board_directory(TEST_POW_BITS, 64).await;
    let id = payjoin::directory::ShortId([7u8; 8]).to_string();
    let payload = vec![0x77u8; PADDED_MESSAGE_BYTES];

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "POST",
        &format!("/{id}"),
        Some(&payload),
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 200);

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/{id}"),
        None,
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, payload);
}
