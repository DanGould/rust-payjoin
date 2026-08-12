//! Wire-level pins for the directory's OHTTP mailbox endpoints.
//!
//! The OHTTP gateway pads every encapsulated response to exactly
//! [`ENCAPSULATED_MESSAGE_BYTES`] so a transporting relay cannot
//! distinguish mailbox states (stored, empty, rejected) by response
//! length, and mailbox slots are write-once so a later, different POST
//! cannot replace a payload in flight. These tests perform the same
//! OHTTP round trip a payjoin client does and fail if either property
//! drifts.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use payjoin::directory::{ShortId, ENCAPSULATED_MESSAGE_BYTES};
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::Service;
use payjoin_mailroom::key_config::gen_ohttp_server_config;
use payjoin_mailroom::ohttp_relay::SentinelTag;

/// Client-side request padding, mirroring the derivation in the payjoin
/// crate: uncompressed public key (65) + poly1305 tag (16) + OHTTP
/// request header (7) bytes of encapsulation overhead.
const PADDED_BHTTP_REQ_BYTES: usize = ENCAPSULATED_MESSAGE_BYTES - (65 + 16 + 7);

/// The size of an HPKE-padded payjoin message, the payload a v2 client
/// posts to a mailbox.
const PADDED_MESSAGE_BYTES: usize = 7168;

async fn test_service() -> Service<FilesDb> {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = FilesDb::init(
        Duration::from_millis(100),
        dir.keep(),
        Duration::from_secs(60 * 60 * 24 * 7),
    )
    .await
    .expect("db init");
    let ohttp: ohttp::Server = gen_ohttp_server_config().expect("ohttp config").into();
    Service::new(db, ohttp, SentinelTag::new([0u8; 32]), None)
}

async fn fetch_ohttp_keys(svc: &mut Service<FilesDb>) -> Vec<u8> {
    let req = Request::builder()
        .method(Method::GET)
        .uri("http://localhost/ohttp-keys")
        .body(Body::empty())
        .expect("request");
    let res = tower::Service::call(svc, req).await.expect("ohttp-keys call");
    assert_eq!(res.status(), StatusCode::OK);
    res.into_body().collect().await.expect("body").to_bytes().to_vec()
}

struct InnerResponse {
    status: u16,
    body: Vec<u8>,
}

/// Encapsulate an inner request, submit it to the gateway, and assert the
/// fixed-size response invariant before decapsulating.
async fn ohttp_roundtrip(
    svc: &mut Service<FilesDb>,
    ohttp_keys: &[u8],
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> InnerResponse {
    let mut bhttp_req = bhttp::Message::request(
        method.as_bytes().to_vec(),
        b"https".to_vec(),
        b"localhost".to_vec(),
        path.as_bytes().to_vec(),
    );
    if let Some(body) = body {
        bhttp_req.write_content(body);
    }
    let mut padded = vec![0u8; PADDED_BHTTP_REQ_BYTES];
    bhttp_req
        .write_bhttp(bhttp::Mode::KnownLength, &mut padded.as_mut_slice())
        .expect("request must fit in padded buffer");

    let (enc_req, res_ctx) = ohttp::ClientRequest::from_encoded_config(ohttp_keys)
        .expect("client config")
        .encapsulate(&padded)
        .expect("encapsulation");
    assert_eq!(enc_req.len(), ENCAPSULATED_MESSAGE_BYTES, "request should be fully padded");

    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost/.well-known/ohttp-gateway")
        .body(Body::from(enc_req))
        .expect("request");
    let res = tower::Service::call(svc, req).await.expect("gateway call");
    assert_eq!(res.status(), StatusCode::OK);
    let enc_res = res.into_body().collect().await.expect("body").to_bytes();

    assert_eq!(
        enc_res.len(),
        ENCAPSULATED_MESSAGE_BYTES,
        "every encapsulated response must be exactly ENCAPSULATED_MESSAGE_BYTES"
    );

    let bhttp_res = res_ctx.decapsulate(&enc_res[..]).expect("decapsulation");
    let mut cursor = std::io::Cursor::new(bhttp_res);
    let msg = bhttp::Message::read_bhttp(&mut cursor).expect("parse inner response");
    InnerResponse {
        status: msg.control().status().expect("inner status").code(),
        body: msg.content().to_vec(),
    }
}

#[tokio::test]
async fn v2_mailbox_roundtrip_has_fixed_size_responses() {
    let mut svc = test_service().await;
    let keys = fetch_ohttp_keys(&mut svc).await;
    let id = ShortId([1u8; 8]).to_string();
    let payload = vec![0x42u8; PADDED_MESSAGE_BYTES];

    let res = ohttp_roundtrip(&mut svc, &keys, "POST", &format!("/{id}"), Some(&payload)).await;
    assert_eq!(res.status, 200);
    assert!(res.body.is_empty());

    let res = ohttp_roundtrip(&mut svc, &keys, "GET", &format!("/{id}"), None).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, payload);

    // A read of an empty mailbox times out with 202 Accepted, in a
    // response the same size as one carrying a full payload.
    let empty = ShortId([2u8; 8]).to_string();
    let res = ohttp_roundtrip(&mut svc, &keys, "GET", &format!("/{empty}"), None).await;
    assert_eq!(res.status, 202);
    assert!(res.body.is_empty());
}

#[tokio::test]
async fn mailbox_posts_are_write_once() {
    let mut svc = test_service().await;
    let keys = fetch_ohttp_keys(&mut svc).await;
    let id = ShortId([3u8; 8]).to_string();
    let first = vec![0xAAu8; PADDED_MESSAGE_BYTES];
    let second = vec![0xBBu8; PADDED_MESSAGE_BYTES];

    let res = ohttp_roundtrip(&mut svc, &keys, "POST", &format!("/{id}"), Some(&first)).await;
    assert_eq!(res.status, 200);

    // A different payload for the same mailbox is not stored, and the
    // response is indistinguishable from a successful store so the
    // directory does not reveal whether a mailbox is occupied.
    let res = ohttp_roundtrip(&mut svc, &keys, "POST", &format!("/{id}"), Some(&second)).await;
    assert_eq!(res.status, 200);

    // An identical retry (e.g. an OHTTP retransmit) is accepted.
    let res = ohttp_roundtrip(&mut svc, &keys, "POST", &format!("/{id}"), Some(&first)).await;
    assert_eq!(res.status, 200);

    let res = ohttp_roundtrip(&mut svc, &keys, "GET", &format!("/{id}"), None).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, first, "the first write must win");
}
