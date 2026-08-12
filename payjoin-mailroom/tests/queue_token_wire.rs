//! Wire-level tests for token-gated queue appends.
//!
//! With queue admission configured, an append body is `token || frame`
//! and only a one-show token minted by the mailbox owner's key admits
//! it. Queue reads are never gated, and without admission (the
//! default) appends behave exactly as they did before tokens existed.
//! Rejections are inner statuses, so every append response keeps the
//! standard fixed wire size whether it was admitted or refused.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use common::{ohttp_roundtrip_expecting, test_directory, PADDED_MESSAGE_BYTES};
use payjoin::directory::{ShortId, ENCAPSULATED_MESSAGE_BYTES};
use payjoin_mailroom::admission::{mint_queue_token, DedupeSet, TokenAdmission, TOKEN_NONCE_BYTES};
use payjoin_mailroom::db::queues::QueueStore;
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::Service;

/// The wire size of every encapsulated queue read response, pinned as a
/// literal independently of the server's derivation.
const ENCAPSULATED_QUEUE_RESPONSE_BYTES: usize = 32768;

const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 7);

async fn tokened_queue_directory() -> (Service<FilesDb>, Vec<u8>) {
    let td = test_directory().await;
    let queues_dir = td.storage_dir.join("queues");
    let queues = QueueStore::init(queues_dir.clone(), TTL, 8).await.expect("queue store init");
    let dedupe = DedupeSet::open(queues_dir.join("admitted.tags")).await.expect("dedupe set");
    (
        td.svc
            .with_queues(queues)
            .with_queue_admission(Arc::new(TokenAdmission::new(Some(dedupe)))),
        td.ohttp_keys,
    )
}

fn frame(fill: u8) -> Vec<u8> { vec![fill; PADDED_MESSAGE_BYTES] }

/// A receiver keypair and its mailbox id, derived the way BIP 77
/// derives a ShortId: the truncated SHA256 of the compressed public
/// key.
fn receiver(fill: u8) -> (SecretKey, ShortId) {
    let key = SecretKey::from_slice(&[fill; 32]).expect("nonzero constant is a valid key");
    let pubkey = key.public_key(&Secp256k1::signing_only()).serialize();
    (key, ShortId::from(sha256::Hash::hash(&pubkey)))
}

fn tokened_body(key: &SecretKey, nonce: [u8; TOKEN_NONCE_BYTES], frame: &[u8]) -> Vec<u8> {
    let mut body = mint_queue_token(key, nonce).to_vec();
    body.extend_from_slice(frame);
    body
}

async fn post_queue(
    svc: &mut Service<FilesDb>,
    keys: &[u8],
    id: &ShortId,
    body: &[u8],
) -> common::InnerResponse {
    ohttp_roundtrip_expecting(
        svc,
        keys,
        "POST",
        &format!("/q/{id}"),
        Some(body),
        ENCAPSULATED_MESSAGE_BYTES,
    )
    .await
}

async fn read_queue(
    svc: &mut Service<FilesDb>,
    keys: &[u8],
    id: &ShortId,
) -> common::InnerResponse {
    ohttp_roundtrip_expecting(
        svc,
        keys,
        "GET",
        &format!("/q/{id}?after=0"),
        None,
        ENCAPSULATED_QUEUE_RESPONSE_BYTES,
    )
    .await
}

#[tokio::test]
async fn untokened_append_is_rejected() {
    let (mut svc, keys) = tokened_queue_directory().await;
    let (_, id) = receiver(0x11);

    let res = post_queue(&mut svc, &keys, &id, &frame(0x41)).await;
    assert_eq!(res.status, 400, "a bare frame carries no parsable token");

    let res = read_queue(&mut svc, &keys, &id).await;
    assert!(res.body.iter().all(|&b| b == 0), "a rejected append stores nothing");
    assert_eq!(res.header("x-pj-next"), Some("0"));
}

#[tokio::test]
async fn owner_tokened_append_is_accepted_and_read_back() {
    let (mut svc, keys) = tokened_queue_directory().await;
    let (key, id) = receiver(0x11);

    let res =
        post_queue(&mut svc, &keys, &id, &tokened_body(&key, [1; TOKEN_NONCE_BYTES], &frame(0x41)))
            .await;
    assert_eq!(res.status, 200);

    let res = read_queue(&mut svc, &keys, &id).await;
    assert_eq!(res.status, 200);
    assert_eq!(&res.body[..PADDED_MESSAGE_BYTES], &frame(0x41)[..]);
    assert_eq!(res.header("x-pj-next"), Some("1"));
}

#[tokio::test]
async fn replayed_token_is_rejected() {
    let (mut svc, keys) = tokened_queue_directory().await;
    let (key, id) = receiver(0x11);
    let token_nonce = [2; TOKEN_NONCE_BYTES];

    let res =
        post_queue(&mut svc, &keys, &id, &tokened_body(&key, token_nonce, &frame(0x41))).await;
    assert_eq!(res.status, 200);

    // The replay carries a different frame: the token does not commit
    // to the frame, so a spent token must be refused, not acknowledged.
    let res =
        post_queue(&mut svc, &keys, &id, &tokened_body(&key, token_nonce, &frame(0x42))).await;
    assert_eq!(res.status, 409, "a spent token is refused");

    let res = read_queue(&mut svc, &keys, &id).await;
    assert_eq!(&res.body[..PADDED_MESSAGE_BYTES], &frame(0x41)[..]);
    assert!(
        res.body[PADDED_MESSAGE_BYTES..].iter().all(|&b| b == 0),
        "the replayed frame is not stored"
    );
    assert_eq!(res.header("x-pj-next"), Some("1"));

    // A fresh token from the same owner still works.
    let res =
        post_queue(&mut svc, &keys, &id, &tokened_body(&key, [3; TOKEN_NONCE_BYTES], &frame(0x43)))
            .await;
    assert_eq!(res.status, 200);
}

#[tokio::test]
async fn token_for_another_mailbox_is_rejected() {
    let (mut svc, keys) = tokened_queue_directory().await;
    let (stranger, _) = receiver(0x22);
    let (_, victim_id) = receiver(0x11);

    // The stranger's token is valid for the stranger's own mailbox;
    // presenting it for someone else's must fail the id binding.
    let res = post_queue(
        &mut svc,
        &keys,
        &victim_id,
        &tokened_body(&stranger, [4; TOKEN_NONCE_BYTES], &frame(0x41)),
    )
    .await;
    assert_eq!(res.status, 401, "a token binds to its own mailbox only");

    let res = read_queue(&mut svc, &keys, &victim_id).await;
    assert!(res.body.iter().all(|&b| b == 0), "the frame is not stored");
}

#[tokio::test]
async fn rejected_append_does_not_spend_the_token() {
    let (mut svc, keys) = tokened_queue_directory().await;
    let (key, id) = receiver(0x11);
    let token_nonce = [5; TOKEN_NONCE_BYTES];

    let res = post_queue(&mut svc, &keys, &id, &tokened_body(&key, token_nonce, &[0x41])).await;
    assert_eq!(res.status, 400, "a wrong-size frame is rejected after admission");

    // The token was admitted but its append failed, so the same token
    // can retry with a correct frame.
    let res =
        post_queue(&mut svc, &keys, &id, &tokened_body(&key, token_nonce, &frame(0x41))).await;
    assert_eq!(res.status, 200);
}

#[tokio::test]
async fn untokened_append_is_accepted_without_admission() {
    let td = test_directory().await;
    let queues =
        QueueStore::init(td.storage_dir.join("queues"), TTL, 8).await.expect("queue store init");
    let mut svc = td.svc.with_queues(queues);
    let (_, id) = receiver(0x11);

    let res = post_queue(&mut svc, &td.ohttp_keys, &id, &frame(0x41)).await;
    assert_eq!(res.status, 200, "without admission, appends stay open exactly as before");

    let res = read_queue(&mut svc, &td.ohttp_keys, &id).await;
    assert_eq!(&res.body[..PADDED_MESSAGE_BYTES], &frame(0x41)[..]);
}
