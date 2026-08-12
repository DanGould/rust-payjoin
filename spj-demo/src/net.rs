//! In-process directory transport.
//!
//! The demo drives the real mailroom directory service as a plain
//! value, the same code a deployed mailroom serves behind TLS. Requests
//! built by the payjoin client library are already OHTTP-encapsulated,
//! so delivering one means handing its bytes to the gateway route and
//! returning the response bytes. Nothing is mocked below the HTTP
//! layer: padding, encapsulation, admission control, and storage all
//! run the production code paths.
//!
//! The board has no client support in the payjoin crate yet, so this
//! module also implements a minimal board client: proof-of-work mining
//! over a submission and encapsulated reads of fixed-size board pages.

use std::path::PathBuf;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request as HttpRequest};
use bitcoin::hashes::{sha256d, Hash};
use http_body_util::BodyExt;
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use payjoin_mailroom::admission::{DedupeSet, PowAdmission, POW_NONCE_BYTES};
use payjoin_mailroom::db::board::BoardStore;
use payjoin_mailroom::db::queues::QueueStore;
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::{Board, Service};
use payjoin_mailroom::key_config::gen_ohttp_server_config;
use payjoin_mailroom::ohttp_relay::SentinelTag;

/// One bulletin board blob: fixed a-priori so every submission is
/// indistinguishable on the wire.
pub const BLOB_BYTES: usize = 512;

/// Blob slots in one board read response.
pub const BOARD_PAGE_SLOTS: usize = 16;

/// The fixed size of an encapsulated board read response.
const ENCAPSULATED_BOARD_RESPONSE_BYTES: usize = 16384;

/// Client-side request padding: encapsulation adds an uncompressed
/// public key (65), a poly1305 tag (16), and an OHTTP header (7).
const PADDED_BHTTP_REQ_BYTES: usize = ENCAPSULATED_MESSAGE_BYTES - (65 + 16 + 7);

pub struct MailroomOpts {
    pub board_pow_bits: u8,
    pub board_cap: usize,
    pub queue_frame_cap: usize,
}

/// A decapsulated response from the directory.
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

pub struct Mailroom {
    svc: Service<FilesDb>,
    ohttp_keys: Vec<u8>,
    storage_dir: PathBuf,
    board_pow_bits: u8,
}

impl Mailroom {
    pub async fn start(opts: MailroomOpts) -> Result<Self, Box<dyn std::error::Error>> {
        let storage_dir = tempfile::tempdir()?.keep();
        let ttl = Duration::from_secs(60 * 60 * 24 * 7);
        let db = FilesDb::init(Duration::from_millis(100), storage_dir.clone(), ttl).await?;
        let queues =
            QueueStore::init(storage_dir.join("queues"), ttl, opts.queue_frame_cap).await?;
        let board_store = BoardStore::init(storage_dir.join("board"), ttl, opts.board_cap).await?;
        let dedupe = DedupeSet::open(storage_dir.join("board-admitted.hex")).await?;
        let admission = PowAdmission::new(opts.board_pow_bits, Some(dedupe));
        let ohttp: ohttp::Server = gen_ohttp_server_config()?.into();
        let mut svc = Service::new(db, ohttp, SentinelTag::new([0u8; 32]), None)
            .with_queues(queues)
            .with_board(Board::new(board_store, std::sync::Arc::new(admission)));
        let ohttp_keys = fetch_ohttp_keys(&mut svc).await?;
        Ok(Self { svc, ohttp_keys, storage_dir, board_pow_bits: opts.board_pow_bits })
    }

    /// The encoded OHTTP key configuration clients encapsulate to.
    pub fn ohttp_keys(&self) -> &[u8] { &self.ohttp_keys }

    /// Deliver a payjoin client request: POST its encapsulated bytes to
    /// the gateway and return the encapsulated response bytes.
    pub async fn deliver(
        &mut self,
        req: &payjoin::Request,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let http_req = HttpRequest::builder()
            .method(Method::POST)
            .uri("http://localhost/.well-known/ohttp-gateway")
            .body(Body::from(req.body.clone()))?;
        let res = tower::Service::call(&mut self.svc, http_req).await?;
        if !res.status().is_success() {
            return Err(format!("gateway returned {}", res.status()).into());
        }
        Ok(res.into_body().collect().await?.to_bytes().to_vec())
    }

    /// Find a nonce making sha256d(nonce || blob) clear the board's
    /// proof-of-work target. Returns the nonce and the hashes tried.
    pub fn mine_pow(&self, blob: &[u8]) -> ([u8; POW_NONCE_BYTES], u64) {
        let bits = u32::from(self.board_pow_bits);
        let mut submission = vec![0u8; POW_NONCE_BYTES + blob.len()];
        submission[POW_NONCE_BYTES..].copy_from_slice(blob);
        for attempt in 0u64.. {
            submission[..POW_NONCE_BYTES].copy_from_slice(&attempt.to_le_bytes());
            let digest = sha256d::Hash::hash(&submission).to_byte_array();
            if leading_zero_bits(&digest) >= bits {
                return (attempt.to_le_bytes(), attempt + 1);
            }
        }
        unreachable!("a 64-bit nonce space always contains a solution for demo targets")
    }

    /// Submit `nonce || blob` to the board and return the inner status.
    pub async fn board_post(
        &mut self,
        nonce: &[u8; POW_NONCE_BYTES],
        blob: &[u8],
    ) -> Result<u16, Box<dyn std::error::Error>> {
        let mut submission = Vec::with_capacity(POW_NONCE_BYTES + blob.len());
        submission.extend_from_slice(nonce);
        submission.extend_from_slice(blob);
        let res = self
            .gateway_roundtrip("POST", "/board", Some(&submission), ENCAPSULATED_MESSAGE_BYTES)
            .await?;
        Ok(res.status)
    }

    /// Append a raw frame to a queue mailbox, returning the inner
    /// status. Senders reach the queue through the payjoin client; this
    /// is the path an attacker uses to inject frames the client would
    /// never build, so scenes can show the receiver skipping them.
    pub async fn queue_post_raw(
        &mut self,
        queue_id: &str,
        frame: &[u8],
    ) -> Result<u16, Box<dyn std::error::Error>> {
        let res = self
            .gateway_roundtrip(
                "POST",
                &format!("/q/{queue_id}"),
                Some(frame),
                ENCAPSULATED_MESSAGE_BYTES,
            )
            .await?;
        Ok(res.status)
    }

    /// Read one fixed-size board page of entries with sequence numbers
    /// at or above `since`. Returns the non-empty slots and the
    /// sequence number to resume from.
    pub async fn board_read(
        &mut self,
        since: u64,
    ) -> Result<(Vec<Vec<u8>>, u64), Box<dyn std::error::Error>> {
        let res = self
            .gateway_roundtrip(
                "GET",
                &format!("/board?since={since}"),
                None,
                ENCAPSULATED_BOARD_RESPONSE_BYTES,
            )
            .await?;
        if res.status != 200 {
            return Err(format!("board read returned inner status {}", res.status).into());
        }
        let next = res
            .header("x-pj-next")
            .ok_or("board read response missing next header")?
            .parse::<u64>()?;
        let blobs = res
            .body
            .chunks(BLOB_BYTES)
            .take(BOARD_PAGE_SLOTS)
            .filter(|slot| slot.iter().any(|b| *b != 0))
            .map(<[u8]>::to_vec)
            .collect();
        Ok((blobs, next))
    }

    /// Everything the directory operator can see: relative paths and
    /// sizes of stored objects.
    pub fn storage_listing(&self) -> Vec<(String, u64)> {
        let mut listing = Vec::new();
        let mut stack = vec![self.storage_dir.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(meta) = path.metadata() {
                    let rel =
                        path.strip_prefix(&self.storage_dir).unwrap_or(&path).display().to_string();
                    listing.push((rel, meta.len()));
                }
            }
        }
        listing.sort();
        listing
    }

    /// A full encapsulated round trip through the gateway for demo-side
    /// clients (the board has no client in the payjoin crate yet).
    async fn gateway_roundtrip(
        &mut self,
        method: &str,
        path_and_query: &str,
        body: Option<&[u8]>,
        expected_response_bytes: usize,
    ) -> Result<InnerResponse, Box<dyn std::error::Error>> {
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
        bhttp_req.write_bhttp(bhttp::Mode::KnownLength, &mut padded.as_mut_slice())?;

        let (enc_req, res_ctx) =
            ohttp::ClientRequest::from_encoded_config(&self.ohttp_keys)?.encapsulate(&padded)?;
        let http_req = HttpRequest::builder()
            .method(Method::POST)
            .uri("http://localhost/.well-known/ohttp-gateway")
            .body(Body::from(enc_req))?;
        let res = tower::Service::call(&mut self.svc, http_req).await?;
        if !res.status().is_success() {
            return Err(format!("gateway returned {}", res.status()).into());
        }
        let enc_res = res.into_body().collect().await?.to_bytes();
        if enc_res.len() != expected_response_bytes {
            return Err(format!(
                "response is {} bytes where its size class is {}",
                enc_res.len(),
                expected_response_bytes
            )
            .into());
        }

        let bhttp_res = res_ctx.decapsulate(&enc_res[..])?;
        let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(bhttp_res))?;
        Ok(InnerResponse {
            status: msg.control().status().ok_or("inner response has no status")?.code(),
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
        })
    }
}

async fn fetch_ohttp_keys(
    svc: &mut Service<FilesDb>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let req = HttpRequest::builder()
        .method(Method::GET)
        .uri("http://localhost/ohttp-keys")
        .body(Body::empty())?;
    let res = tower::Service::call(svc, req).await?;
    if !res.status().is_success() {
        return Err(format!("key fetch returned {}", res.status()).into());
    }
    Ok(res.into_body().collect().await?.to_bytes().to_vec())
}

fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> MailroomOpts {
        MailroomOpts { board_pow_bits: 8, board_cap: 32, queue_frame_cap: 8 }
    }

    #[tokio::test]
    async fn mined_submission_is_admitted_and_read_back() {
        let mut mailroom = Mailroom::start(opts()).await.expect("mailroom");
        let blob = vec![7u8; BLOB_BYTES];
        let (nonce, _) = mailroom.mine_pow(&blob);
        let status = mailroom.board_post(&nonce, &blob).await.expect("post");
        assert_eq!(status, 200);

        let (blobs, next) = mailroom.board_read(0).await.expect("read");
        assert_eq!(blobs, vec![blob]);
        assert!(next >= 1);
    }

    #[tokio::test]
    async fn unworked_submission_is_rejected() {
        let mut mailroom = Mailroom::start(opts()).await.expect("mailroom");
        let blob = vec![9u8; BLOB_BYTES];
        // An all-zero nonce statistically fails an 8-bit target; mine
        // first and verify, then corrupt the nonce to be sure.
        let (nonce, _) = mailroom.mine_pow(&blob);
        let mut bad_nonce = nonce;
        bad_nonce[0] = bad_nonce[0].wrapping_add(1);
        let submission_check = {
            let mut s = Vec::new();
            s.extend_from_slice(&bad_nonce);
            s.extend_from_slice(&blob);
            leading_zero_bits(&sha256d::Hash::hash(&s).to_byte_array())
        };
        if submission_check >= 8 {
            // The corrupted nonce happened to also clear the target;
            // nothing to assert against.
            return;
        }
        let status = mailroom.board_post(&bad_nonce, &blob).await.expect("post");
        assert_eq!(status, 429);
    }

    #[test]
    fn leading_zero_bits_counts_from_the_first_byte() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xff]), 16);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
    }
}
