//! Wire-level tests for queue mailbox endpoints.
//!
//! Queue routes are reachable only through the OHTTP gateway, like the
//! single-slot mailbox routes. Queue reads form their own fixed
//! response size class; every other response, including queue appends,
//! keeps the standard mailbox size, and with queues disabled (the
//! default) the wire behavior is identical to a directory without any
//! queue code.

mod common;

use std::time::Duration;

use common::{ohttp_roundtrip_expecting, test_directory, PADDED_MESSAGE_BYTES};
use payjoin::directory::{ShortId, ENCAPSULATED_MESSAGE_BYTES};
use payjoin_mailroom::db::queues::QueueStore;
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::Service;

/// The wire size of every encapsulated queue read response, pinned as a
/// literal independently of the server's derivation.
const ENCAPSULATED_QUEUE_RESPONSE_BYTES: usize = 32768;

/// The inner body of a queue read: four frame slots.
const QUEUE_PAGE_BYTES: usize = 4 * PADDED_MESSAGE_BYTES;

const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 7);

async fn queue_directory(frame_cap: usize) -> (Service<FilesDb>, Vec<u8>) {
    let td = test_directory().await;
    let queues = QueueStore::init(td.storage_dir.join("queues"), TTL, frame_cap)
        .await
        .expect("queue store init");
    (td.svc.with_queues(queues), td.ohttp_keys)
}

fn frame(fill: u8) -> Vec<u8> { vec![fill; PADDED_MESSAGE_BYTES] }

#[tokio::test]
async fn queue_routes_absent_without_config() {
    let td = test_directory().await;
    let mut svc = td.svc;
    let id = ShortId([1u8; 8]).to_string();

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &td.ohttp_keys,
        "POST",
        &format!("/q/{id}"),
        Some(&frame(1)),
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 404, "queue POST must not exist unless enabled");

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &td.ohttp_keys,
        "GET",
        &format!("/q/{id}?after=0"),
        None,
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 404, "queue GET must not exist unless enabled");
}

#[tokio::test]
async fn queue_append_and_read_roundtrip() {
    let (mut svc, keys) = queue_directory(8).await;
    let id = ShortId([1u8; 8]).to_string();

    // Append acks stay in the standard response size class, so they are
    // indistinguishable from other mailbox operations on the wire.
    for fill in [0x41, 0x42] {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            &format!("/q/{id}"),
            Some(&frame(fill)),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200);
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/q/{id}?after=0"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body.len(), QUEUE_PAGE_BYTES, "page body length is constant");
    assert_eq!(&res.body[..PADDED_MESSAGE_BYTES], &frame(0x41)[..]);
    assert_eq!(&res.body[PADDED_MESSAGE_BYTES..2 * PADDED_MESSAGE_BYTES], &frame(0x42)[..]);
    assert!(
        res.body[2 * PADDED_MESSAGE_BYTES..].iter().all(|&b| b == 0),
        "unused frame slots are zero-filled"
    );
    assert_eq!(res.header("x-pj-next"), Some("2"));

    // Omitting the parameter reads from the start.
    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/q/{id}"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(&res.body[..PADDED_MESSAGE_BYTES], &frame(0x41)[..]);

    // Reading past the end returns an all-zero page of the same size.
    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/q/{id}?after=2"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(res.status, 200);
    assert!(res.body.iter().all(|&b| b == 0), "empty page is all zeros");
    assert_eq!(res.header("x-pj-next"), Some("2"), "index does not advance past the end");
}

#[tokio::test]
async fn queue_reads_paginate_in_fixed_pages() {
    let (mut svc, keys) = queue_directory(8).await;
    let id = ShortId([2u8; 8]).to_string();

    for fill in 1..=6 {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            &format!("/q/{id}"),
            Some(&frame(fill)),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200);
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/q/{id}?after=0"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await;
    for (i, fill) in (1..=4).enumerate() {
        assert_eq!(
            &res.body[i * PADDED_MESSAGE_BYTES..(i + 1) * PADDED_MESSAGE_BYTES],
            &frame(fill)[..],
            "first page carries frames one through four"
        );
    }
    assert_eq!(res.header("x-pj-next"), Some("4"));

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/q/{id}?after=4"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(&res.body[..PADDED_MESSAGE_BYTES], &frame(5)[..]);
    assert_eq!(&res.body[PADDED_MESSAGE_BYTES..2 * PADDED_MESSAGE_BYTES], &frame(6)[..]);
    assert!(res.body[2 * PADDED_MESSAGE_BYTES..].iter().all(|&b| b == 0));
    assert_eq!(res.header("x-pj-next"), Some("6"));
}

#[tokio::test]
async fn queue_append_rejects_wrong_frame_size() {
    let (mut svc, keys) = queue_directory(8).await;
    let id = ShortId([3u8; 8]).to_string();

    for len in [100, PADDED_MESSAGE_BYTES + 1] {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            &format!("/q/{id}"),
            Some(&vec![0u8; len]),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 400, "append of {len} bytes must be rejected");
    }
}

#[tokio::test]
async fn queue_read_rejects_malformed_index() {
    let (mut svc, keys) = queue_directory(8).await;
    let id = ShortId([4u8; 8]).to_string();

    // Errors stay within the read size class so they are
    // indistinguishable from successful reads on the wire.
    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "GET",
        &format!("/q/{id}?after=abc"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await;
    assert_eq!(res.status, 400);
}

#[tokio::test]
async fn queue_frame_cap_returns_too_many_requests() {
    let (mut svc, keys) = queue_directory(2).await;
    let id = ShortId([5u8; 8]).to_string();

    for fill in [1, 2] {
        let res = ohttp_roundtrip_expecting(
            &mut svc,
            &keys,
            "POST",
            &format!("/q/{id}"),
            Some(&frame(fill)),
            ENCAPSULATED_MESSAGE_BYTES,
        )
        .await;
        assert_eq!(res.status, 200);
    }

    let res = ohttp_roundtrip_expecting(
        &mut svc,
        &keys,
        "POST",
        &format!("/q/{id}"),
        Some(&frame(3)),
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await;
    assert_eq!(res.status, 429, "append over the frame cap is rejected");
}

#[tokio::test]
async fn standard_mailbox_unchanged_with_queues_enabled() {
    let (mut svc, keys) = queue_directory(8).await;
    let id = ShortId([6u8; 8]).to_string();
    let payload = frame(0x77);

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
