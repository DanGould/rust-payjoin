//! Wire-level tests for a board gated on a zero-knowledge credential.
//!
//! The verifier here is a stub, so these pin the route around it: the
//! submission layout, which bytes reach the board, the order the two
//! gates run in, and how each verdict reaches the client. The proof
//! system itself is exercised in `zk_sidecar.rs`.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hashes::{sha256d, Hash};
use common::{ohttp_roundtrip_expecting, test_directory, InnerResponse, PADDED_MESSAGE_BYTES};
use futures::future::BoxFuture;
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use payjoin_mailroom::admission::{
    DedupeSet, PowAdmission, PowThenZk, ProofVerifier, SpentJournal, Unavailable, Verdict,
    ZkAdmission,
};
use payjoin_mailroom::db::board::BoardStore;
use payjoin_mailroom::db::FilesDb;
use payjoin_mailroom::directory::{Board, Service};

/// The wire size of every encapsulated board read response, pinned as a
/// literal independently of the server's derivation.
const ENCAPSULATED_BOARD_RESPONSE_BYTES: usize = 16384;

/// Credentialed board submission layout, pinned as literals: an 8-byte
/// proof-of-work nonce, a proof, then a 512-byte blob.
const NONCE_BYTES: usize = 8;
const PROOF_BYTES: usize = 2793;
const BLOB_BYTES: usize = 512;
const SUBMISSION_BYTES: usize = NONCE_BYTES + PROOF_BYTES + BLOB_BYTES;

/// Where the one-show tag sits within a proof.
const KEY_IMAGE: std::ops::Range<usize> = 33..66;

/// A low target keeps test mining to a few hundred hashes.
const TEST_POW_BITS: u8 = 8;

const WEEK: Duration = Duration::from_secs(60 * 60 * 24 * 7);

/// A verifier under the test's control, answering from a script and
/// counting what it was asked.
struct StubVerifier {
    answers: Mutex<VecDeque<Result<Verdict, Unavailable>>>,
    calls: Mutex<usize>,
}

impl StubVerifier {
    fn new(answers: impl IntoIterator<Item = Result<Verdict, Unavailable>>) -> Arc<Self> {
        Arc::new(Self { answers: Mutex::new(answers.into_iter().collect()), calls: Mutex::new(0) })
    }

    fn calls(&self) -> usize { *self.calls.lock().expect("uncontended") }
}

impl ProofVerifier for StubVerifier {
    fn verify<'a>(
        &'a self,
        _proof: &'a [u8],
        _user_string: &'a str,
    ) -> BoxFuture<'a, Result<Verdict, Unavailable>> {
        Box::pin(async move {
            *self.calls.lock().expect("uncontended") += 1;
            self.answers.lock().expect("uncontended").pop_front().expect("an answer per call")
        })
    }
}

async fn credentialed_directory(
    answers: impl IntoIterator<Item = Result<Verdict, Unavailable>>,
    cap: usize,
    ttl: Duration,
) -> (Service<FilesDb>, Vec<u8>, Arc<StubVerifier>) {
    let td = test_directory().await;
    let board_dir = td.storage_dir.join("board");
    let store = BoardStore::init(board_dir.clone(), ttl, cap).await.expect("board store init");
    let dedupe = DedupeSet::open(board_dir.join("admitted.tags")).await.expect("dedupe set");
    let journal = SpentJournal::open(board_dir.join("spent.journal")).await.expect("journal");
    let verifier = StubVerifier::new(answers);
    let admission = Arc::new(PowThenZk::new(
        PowAdmission::new(TEST_POW_BITS, None),
        ZkAdmission::new(verifier.clone(), journal, Some(dedupe)),
    ));
    (td.svc.with_board(Board::with_credential(store, admission)), td.ohttp_keys, verifier)
}

fn blob(fill: u8) -> Vec<u8> { vec![fill; BLOB_BYTES] }

fn proof(tag: u8) -> Vec<u8> {
    let mut proof = vec![0u8; PROOF_BYTES];
    proof[KEY_IMAGE].fill(tag);
    proof
}

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

/// Mine a submission body (`nonce || proof || blob`) meeting `bits`
/// leading zero bits of sha256d over the whole body.
fn mine(tag: u8, fill: u8, bits: u8) -> Vec<u8> {
    let mut payload = proof(tag);
    payload.extend_from_slice(&blob(fill));
    for nonce in 0u64.. {
        let mut body = nonce.to_be_bytes().to_vec();
        body.extend_from_slice(&payload);
        let digest = sha256d::Hash::hash(&body).to_byte_array();
        if leading_zero_bits(&digest) >= u32::from(bits) {
            return body;
        }
    }
    unreachable!("some nonce meets the target")
}

async fn submit(svc: &mut Service<FilesDb>, keys: &[u8], body: &[u8]) -> u16 {
    ohttp_roundtrip_expecting(svc, keys, "POST", "/board", Some(body), ENCAPSULATED_MESSAGE_BYTES)
        .await
        .status
}

async fn read_board(svc: &mut Service<FilesDb>, keys: &[u8]) -> InnerResponse {
    ohttp_roundtrip_expecting(
        svc,
        keys,
        "GET",
        "/board?since=0",
        None,
        ENCAPSULATED_BOARD_RESPONSE_BYTES,
    )
    .await
}

#[tokio::test]
async fn credentialed_submission_stores_only_the_blob() {
    let (mut svc, keys, _) = credentialed_directory([Ok(Verdict::Accepted)], 64, WEEK).await;

    let body = mine(0x77, 0xA1, TEST_POW_BITS);
    assert_eq!(body.len(), SUBMISSION_BYTES);
    assert_eq!(submit(&mut svc, &keys, &body).await, 200);

    let page = read_board(&mut svc, &keys).await;
    assert_eq!(
        &page.body[..BLOB_BYTES],
        &blob(0xA1)[..],
        "the entry is the blob, not the credential"
    );
    assert!(page.body[BLOB_BYTES..].iter().all(|&b| b == 0), "one entry, the rest zero-filled");
    assert_eq!(page.header("x-pj-next"), Some("1"));
}

#[tokio::test]
async fn submission_of_another_length_is_rejected() {
    let (mut svc, keys, verifier) = credentialed_directory([], 64, WEEK).await;

    // The length a board without credentials takes, and either side of
    // the length this one takes.
    let uncredentialed = mine(0x77, 0xA1, TEST_POW_BITS)[..NONCE_BYTES + BLOB_BYTES].to_vec();
    let mut short = mine(0x77, 0xA1, TEST_POW_BITS);
    short.pop();
    let mut long = mine(0x77, 0xA1, TEST_POW_BITS);
    long.push(0);

    for body in [uncredentialed, short, long] {
        assert_eq!(submit(&mut svc, &keys, &body).await, 400, "{} bytes", body.len());
    }
    assert_eq!(verifier.calls(), 0, "the length gate precedes verification");
}

#[tokio::test]
async fn work_is_checked_before_the_credential() {
    // Verification is expensive and any keypair can produce a proof
    // that only the membership check rejects, so an unpriced
    // credential path would be a flood path.
    let (mut svc, keys, verifier) = credentialed_directory([], 64, WEEK).await;

    let underworked = mine(0x77, 0xA1, 0);
    let status = submit(&mut svc, &keys, &underworked).await;

    assert_eq!(status, 429);
    assert_eq!(verifier.calls(), 0, "unpaid work reaches no verifier");
}

#[tokio::test]
async fn every_verdict_reaches_the_client() {
    let (mut svc, keys, _) = credentialed_directory(
        [
            Ok(Verdict::NotAMember),
            Ok(Verdict::Invalid),
            Ok(Verdict::Reused),
            Err(Unavailable::new("no verdict")),
        ],
        64,
        WEEK,
    )
    .await;

    // A key outside the set, a proof that does not verify, a
    // credential this board never admitted, and an outage.
    let expected = [401, 400, 409, 503];
    for (tag, status) in (0x01u8..).zip(expected) {
        assert_eq!(submit(&mut svc, &keys, &mine(tag, tag, TEST_POW_BITS)).await, status);
    }

    let page = read_board(&mut svc, &keys).await;
    assert!(page.body.iter().all(|&b| b == 0), "no rejected submission is stored");
}

#[tokio::test]
async fn identical_retransmit_is_acknowledged_once() {
    // A client that never saw its response retransmits, and the
    // verifier reports the credential as spent. Answering with a
    // conflict would fail a submission that already succeeded.
    let (mut svc, keys, _) =
        credentialed_directory([Ok(Verdict::Accepted), Ok(Verdict::Reused)], 64, WEEK).await;

    let body = mine(0x77, 0xA1, TEST_POW_BITS);
    assert_eq!(submit(&mut svc, &keys, &body).await, 200);
    assert_eq!(submit(&mut svc, &keys, &body).await, 200);

    let page = read_board(&mut svc, &keys).await;
    assert_eq!(&page.body[..BLOB_BYTES], &blob(0xA1)[..]);
    assert!(
        page.body[BLOB_BYTES..].iter().all(|&b| b == 0),
        "the retransmit is not a second entry"
    );
}

#[tokio::test]
async fn a_failed_store_does_not_spend_the_credential() {
    // The credential is spent at the verifier the moment it accepts,
    // so a board that then refuses the entry must still let the
    // sender retry the same submission.
    let ttl = Duration::from_millis(200);
    let (mut svc, keys, _) = credentialed_directory(
        [Ok(Verdict::Accepted), Ok(Verdict::Accepted), Ok(Verdict::Reused)],
        1,
        ttl,
    )
    .await;

    assert_eq!(submit(&mut svc, &keys, &mine(0x11, 0xA1, TEST_POW_BITS)).await, 200);

    let body = mine(0x77, 0xA2, TEST_POW_BITS);
    assert_eq!(submit(&mut svc, &keys, &body).await, 503, "the board is full");

    tokio::time::sleep(ttl + Duration::from_millis(100)).await;
    assert_eq!(submit(&mut svc, &keys, &body).await, 200, "the same submission still admits");

    let page = read_board(&mut svc, &keys).await;
    assert_eq!(&page.body[..BLOB_BYTES], &blob(0xA2)[..], "the retry is stored");
}

#[tokio::test]
async fn standard_mailbox_unchanged_with_credentials_enabled() {
    let (mut svc, keys, _) = credentialed_directory([], 64, WEEK).await;
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
