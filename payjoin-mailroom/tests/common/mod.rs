//! Shared OHTTP round-trip helpers for wire-level integration tests.
//!
//! These drive `directory::Service` the way a payjoin client does:
//! build an inner bhttp request, pad and encapsulate it, submit it to
//! the gateway route, and assert the encapsulated response has exactly
//! the expected fixed size before decapsulating.

use std::path::PathBuf;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::Service;
use payjoin_mailroom::key_config::gen_ohttp_server_config;
use payjoin_mailroom::ohttp_relay::SentinelTag;

/// Client-side request padding, mirroring the derivation in the payjoin
/// crate: uncompressed public key (65) + poly1305 tag (16) + OHTTP
/// request header (7) bytes of encapsulation overhead.
const PADDED_BHTTP_REQ_BYTES: usize = ENCAPSULATED_MESSAGE_BYTES - (65 + 16 + 7);

/// The size of an HPKE-padded payjoin message: one mailbox payload, and
/// one queue frame.
pub const PADDED_MESSAGE_BYTES: usize = 7168;

pub struct TestDirectory {
    pub svc: Service<FilesDb>,
    pub storage_dir: PathBuf,
    pub ohttp_keys: Vec<u8>,
}

/// A directory service on temporary storage with no optional features
/// enabled, plus its encoded OHTTP key configuration.
pub async fn test_directory() -> TestDirectory {
    let storage_dir = tempfile::tempdir().expect("tempdir").keep();
    let db = FilesDb::init(
        Duration::from_millis(100),
        storage_dir.clone(),
        Duration::from_secs(60 * 60 * 24 * 7),
    )
    .await
    .expect("db init");
    let ohttp: ohttp::Server = gen_ohttp_server_config().expect("ohttp config").into();
    let mut svc = Service::new(db, ohttp, SentinelTag::new([0u8; 32]), None);
    let ohttp_keys = fetch_ohttp_keys(&mut svc).await;
    TestDirectory { svc, storage_dir, ohttp_keys }
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

pub struct InnerResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl InnerResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Encapsulate an inner request, submit it to the gateway, and assert
/// the response is exactly `expected_response_bytes` long before
/// decapsulating it.
pub async fn ohttp_roundtrip_expecting(
    svc: &mut Service<FilesDb>,
    ohttp_keys: &[u8],
    method: &str,
    path_and_query: &str,
    body: Option<&[u8]>,
    expected_response_bytes: usize,
) -> InnerResponse {
    let mut bhttp_req = bhttp::Message::request(
        method.as_bytes().to_vec(),
        b"https".to_vec(),
        b"localhost".to_vec(),
        path_and_query.as_bytes().to_vec(),
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
        expected_response_bytes,
        "encapsulated response must have the fixed size of its class"
    );

    let bhttp_res = res_ctx.decapsulate(&enc_res[..]).expect("decapsulation");
    let mut cursor = std::io::Cursor::new(bhttp_res);
    let msg = bhttp::Message::read_bhttp(&mut cursor).expect("parse inner response");
    InnerResponse {
        status: msg.control().status().expect("inner status").code(),
        headers: msg
            .header()
            .fields()
            .iter()
            .map(|field| {
                (
                    String::from_utf8_lossy(field.name()).into_owned(),
                    String::from_utf8_lossy(field.value()).into_owned(),
                )
            })
            .collect(),
        body: msg.content().to_vec(),
    }
}
