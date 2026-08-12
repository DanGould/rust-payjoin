//! Admission control for open-submission endpoints.
//!
//! Mailbox and queue writes are implicitly gated by their ids: only a
//! party that learns an id can write to it. An endpoint that accepts
//! submissions from anyone has no such secret, so submissions pass an
//! [`Admission`] check instead. Proof of work admits strangers at a
//! computational cost; owner-minted tokens admit senders the mailbox
//! owner chose, for free. The trait keeps routing code independent of
//! which mechanism an operator deploys, so alternatives (e.g. an
//! external verification service) can be substituted without touching
//! the endpoints.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey, VerifyOnly};
use futures::future::BoxFuture;
use hex::{DisplayHex, FromHex};
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::Mutex;

/// Why a submission was refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The submission is structurally invalid for the mechanism.
    Malformed,
    /// The submission does not carry sufficient work.
    InsufficientWork,
    /// The submission does not prove authorization by the owner of the
    /// resource it targets.
    Unauthorized,
}

/// An admission mechanism for submissions that anyone may make.
pub trait Admission: Send + Sync {
    /// Verify a submission body. On success, return the public tag that
    /// identifies this admission for replay detection.
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>>;

    /// Whether `tag` was admitted before.
    fn seen<'a>(&'a self, _tag: &'a [u8]) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async { Ok(false) })
    }

    /// Record `tag` as admitted. Call this only after the admitted
    /// operation fully succeeds, so a submission whose operation failed
    /// can be retried without redoing its work.
    fn record_success<'a>(&'a self, _tag: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// The nonce prefix length of a proof-of-work submission body.
pub const POW_NONCE_BYTES: usize = 8;

/// Hashcash-style proof-of-work admission.
///
/// A submission body is `nonce || payload`, where the nonce is the
/// first [`POW_NONCE_BYTES`] bytes. It is admitted when
/// sha256d(nonce || payload) has at least `target_bits` leading zero
/// bits, counted from the most significant bit of the first digest
/// byte (raw digest order, not the reversed presentation Bitcoin uses
/// for txids). Hashing the whole body commits the work to the exact
/// payload bytes, so altering any byte invalidates the proof. The
/// digest doubles as the replay-detection tag.
pub struct PowAdmission {
    target_bits: u8,
    dedupe: Option<DedupeSet>,
}

impl PowAdmission {
    pub fn new(target_bits: u8, dedupe: Option<DedupeSet>) -> Self { Self { target_bits, dedupe } }
}

impl Admission for PowAdmission {
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>> {
        Box::pin(async move {
            if body.len() <= POW_NONCE_BYTES {
                return Err(Rejection::Malformed);
            }
            let digest = sha256d::Hash::hash(body).to_byte_array();
            if leading_zero_bits(&digest) < u32::from(self.target_bits) {
                return Err(Rejection::InsufficientWork);
            }
            Ok(digest.to_vec())
        })
    }

    fn seen<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async move {
            match &self.dedupe {
                Some(dedupe) => dedupe.contains(tag).await,
                None => Ok(false),
            }
        })
    }

    fn record_success<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            match &self.dedupe {
                Some(dedupe) => dedupe.insert(tag).await,
                None => Ok(()),
            }
        })
    }
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

/// The nonce length of a queue token. The nonce is the token's one-show
/// identity for replay detection.
pub const TOKEN_NONCE_BYTES: usize = 16;

/// The serialized length of a queue token: nonce, compressed secp256k1
/// public key, then compact ECDSA signature.
pub const TOKEN_BYTES: usize = TOKEN_NONCE_BYTES + TOKEN_PUBKEY_BYTES + TOKEN_SIG_BYTES;

const TOKEN_PUBKEY_BYTES: usize = 33;
const TOKEN_SIG_BYTES: usize = 64;

/// The length of a queue mailbox id, a truncated SHA256 of the owner's
/// compressed public key (see [`payjoin::directory::ShortId`]).
const MAILBOX_ID_BYTES: usize = 8;

/// Domain separation prefix of the token signature hash, so a token
/// signature cannot be confused with any other signature by the same
/// key.
const TOKEN_SIGNING_DOMAIN: &[u8] = b"payjoin queue token v0";

/// Owner-minted token admission for queue appends.
///
/// A queue mailbox id is the truncated SHA256 of a compressed secp256k1
/// public key, so the holder of the matching private key can prove it
/// owns the mailbox while anyone else knows only the public id. A token
/// is `nonce || pubkey || signature`: the owner signs the domain-tagged
/// hash of the mailbox id and a fresh nonce ([`mint_queue_token`]) and
/// hands the token to a sender of its choosing. An append is admitted
/// iff the token's public key hashes to the target mailbox id and the
/// signature verifies, with no receiver online and no per-request
/// callback. A token does not commit to the frame it admits, because it
/// is minted before the frame exists.
///
/// The verification input is the target mailbox id followed by the
/// token, as assembled by the queue route; a token presented for any
/// other mailbox fails the id binding. The replay tag is the mailbox id
/// and nonce together, so each token admits exactly one append and
/// replay history is scoped to its mailbox.
///
/// Key-reuse caveat: a BIP 77 receiver's mailbox id is derived from its
/// HPKE encryption key, so this scheme signs with that same key. Using
/// one secp256k1 key for both ECDSA and HPKE is accepted only for this
/// default-off, pre-standardization feature; production deployments
/// should advertise a dedicated token-signing key.
pub struct TokenAdmission {
    secp: Secp256k1<VerifyOnly>,
    dedupe: Option<DedupeSet>,
}

impl TokenAdmission {
    pub fn new(dedupe: Option<DedupeSet>) -> Self {
        Self { secp: Secp256k1::verification_only(), dedupe }
    }
}

/// The token signature hash: a domain-tagged SHA256 of the mailbox id
/// and nonce.
fn token_sighash(mailbox_id: &[u8], nonce: &[u8]) -> Message {
    let mut preimage =
        Vec::with_capacity(TOKEN_SIGNING_DOMAIN.len() + MAILBOX_ID_BYTES + TOKEN_NONCE_BYTES);
    preimage.extend_from_slice(TOKEN_SIGNING_DOMAIN);
    preimage.extend_from_slice(mailbox_id);
    preimage.extend_from_slice(nonce);
    Message::from_digest(sha256::Hash::hash(&preimage).to_byte_array())
}

/// Mint a token authorizing one append to the queue mailbox of `key`.
///
/// The mailbox id is derived from the key's public key, so a token
/// cannot be minted for a mailbox the signer does not own. The nonce is
/// the token's one-show identity: mint every token with a fresh random
/// nonce, or the directory will admit only one of them.
pub fn mint_queue_token(key: &SecretKey, nonce: [u8; TOKEN_NONCE_BYTES]) -> [u8; TOKEN_BYTES] {
    let secp = Secp256k1::signing_only();
    let pubkey = key.public_key(&secp).serialize();
    let mailbox_id = &sha256::Hash::hash(&pubkey).to_byte_array()[..MAILBOX_ID_BYTES];
    let sig = secp.sign_ecdsa(&token_sighash(mailbox_id, &nonce), key).serialize_compact();
    let mut token = [0u8; TOKEN_BYTES];
    token[..TOKEN_NONCE_BYTES].copy_from_slice(&nonce);
    token[TOKEN_NONCE_BYTES..TOKEN_NONCE_BYTES + TOKEN_PUBKEY_BYTES].copy_from_slice(&pubkey);
    token[TOKEN_NONCE_BYTES + TOKEN_PUBKEY_BYTES..].copy_from_slice(&sig);
    token
}

impl Admission for TokenAdmission {
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>> {
        Box::pin(async move {
            if body.len() != MAILBOX_ID_BYTES + TOKEN_BYTES {
                return Err(Rejection::Malformed);
            }
            let (mailbox_id, token) = body.split_at(MAILBOX_ID_BYTES);
            let (nonce, rest) = token.split_at(TOKEN_NONCE_BYTES);
            let (pubkey_bytes, sig_bytes) = rest.split_at(TOKEN_PUBKEY_BYTES);
            let pubkey = PublicKey::from_slice(pubkey_bytes).map_err(|_| Rejection::Malformed)?;
            let sig =
                ecdsa::Signature::from_compact(sig_bytes).map_err(|_| Rejection::Malformed)?;
            if &sha256::Hash::hash(pubkey_bytes).to_byte_array()[..MAILBOX_ID_BYTES] != mailbox_id {
                return Err(Rejection::Unauthorized);
            }
            self.secp
                .verify_ecdsa(&token_sighash(mailbox_id, nonce), &sig, &pubkey)
                .map_err(|_| Rejection::Unauthorized)?;
            Ok(body[..MAILBOX_ID_BYTES + TOKEN_NONCE_BYTES].to_vec())
        })
    }

    fn seen<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async move {
            match &self.dedupe {
                Some(dedupe) => dedupe.contains(tag).await,
                None => Ok(false),
            }
        })
    }

    fn record_success<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            match &self.dedupe {
                Some(dedupe) => dedupe.insert(tag).await,
                None => Ok(()),
            }
        })
    }
}

/// A persistent set of admitted tags, for replay detection.
///
/// Tags are public values (a submission is visible to the directory by
/// construction), so they are stored in plaintext: one hex-encoded tag
/// per line, appended on each successful admission and reloaded on
/// startup. Each admission context persists its own set under its own
/// path. The file is never compacted; deleting it forgets history.
#[derive(Clone)]
pub struct DedupeSet {
    inner: Arc<Mutex<DedupeInner>>,
}

struct DedupeInner {
    file: tokio::fs::File,
    seen: HashSet<Vec<u8>>,
}

impl DedupeSet {
    /// Open the set persisted at `path`, creating it if absent.
    pub async fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut seen = HashSet::new();
        if tokio::fs::try_exists(&path).await? {
            let contents = tokio::fs::read_to_string(&path).await?;
            for line in contents.lines() {
                // Skip unparsable lines, e.g. a torn tail from a crash
                // mid-append; losing a tag only permits one replay.
                if let Ok(tag) = Vec::<u8>::from_hex(line) {
                    seen.insert(tag);
                }
            }
        }
        let file = tokio::fs::OpenOptions::new().append(true).create(true).open(&path).await?;
        Ok(Self { inner: Arc::new(Mutex::new(DedupeInner { file, seen })) })
    }

    pub async fn contains(&self, tag: &[u8]) -> io::Result<bool> {
        Ok(self.inner.lock().await.seen.contains(tag))
    }

    pub async fn insert(&self, tag: &[u8]) -> io::Result<()> {
        let mut guard = self.inner.lock().await;
        if !guard.seen.insert(tag.to_vec()) {
            return Ok(());
        }
        let line = format!("{}\n", tag.to_lower_hex_string());
        guard.file.write_all(line.as_bytes()).await?;
        guard.file.sync_data().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find a nonce whose sha256d meets `bits` leading zero bits.
    fn mine(payload: &[u8], bits: u8) -> Vec<u8> {
        for nonce in 0u64.. {
            let mut body = nonce.to_be_bytes().to_vec();
            body.extend_from_slice(payload);
            let digest = sha256d::Hash::hash(&body).to_byte_array();
            if leading_zero_bits(&digest) >= u32::from(bits) {
                return body;
            }
        }
        unreachable!("some nonce meets the target")
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x0F]), 12);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[tokio::test]
    async fn test_pow_admits_sufficient_work() {
        let pow = PowAdmission::new(8, None);
        let body = mine(b"hello board", 8);
        let tag = pow.verify(&body).await.expect("mined body should be admitted");
        assert_eq!(tag, sha256d::Hash::hash(&body).to_byte_array().to_vec());
    }

    #[tokio::test]
    async fn test_pow_rejects_insufficient_work() {
        // A 32-bit target is out of reach for any nonce a test would
        // stumble on; mine to 8 bits and verify against 32.
        let pow = PowAdmission::new(32, None);
        let body = mine(b"hello board", 8);
        assert_eq!(pow.verify(&body).await, Err(Rejection::InsufficientWork));
    }

    #[tokio::test]
    async fn test_pow_rejects_short_body() {
        let pow = PowAdmission::new(0, None);
        assert_eq!(pow.verify(&[]).await, Err(Rejection::Malformed));
        assert_eq!(pow.verify(&[0u8; POW_NONCE_BYTES]).await, Err(Rejection::Malformed));
    }

    #[tokio::test]
    async fn test_pow_commits_to_payload_bytes() {
        let pow = PowAdmission::new(8, None);
        let body = mine(b"hello board", 8);
        pow.verify(&body).await.expect("mined body should be admitted");

        // Nearly every single-byte change invalidates the proof; find
        // one that does to show the work commits to the payload.
        let invalidated = (1u8..=255).any(|flip| {
            let mut mutated = body.clone();
            let last = mutated.len() - 1;
            mutated[last] ^= flip;
            futures::executor::block_on(pow.verify(&mutated)).is_err()
        });
        assert!(invalidated, "changing a payload byte should invalidate the proof");
    }

    #[tokio::test]
    async fn test_dedupe_set_persists_across_reopen() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("admitted.tags");

        {
            let set = DedupeSet::open(path.clone()).await?;
            assert!(!set.contains(b"tag one").await?);
            set.insert(b"tag one").await?;
            set.insert(b"tag two").await?;
            set.insert(b"tag one").await?; // duplicate insert is a no-op
            assert!(set.contains(b"tag one").await?);
        }

        let set = DedupeSet::open(path.clone()).await?;
        assert!(set.contains(b"tag one").await?, "tags should survive a restart");
        assert!(set.contains(b"tag two").await?);
        assert!(!set.contains(b"tag three").await?);

        let lines = std::fs::read_to_string(&path)?;
        assert_eq!(lines.lines().count(), 2, "duplicate inserts should not be re-appended");

        Ok(())
    }

    #[tokio::test]
    async fn test_dedupe_set_skips_torn_lines() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("admitted.tags");

        {
            let set = DedupeSet::open(path.clone()).await?;
            set.insert(b"tag one").await?;
        }
        // Simulate a crash mid-append: a torn, non-hex tail line.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(b"0dd")?;
        }

        let set = DedupeSet::open(path.clone()).await?;
        assert!(set.contains(b"tag one").await?, "intact tags should still load");
        Ok(())
    }

    #[tokio::test]
    async fn test_pow_dedupe_via_trait_hooks() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let set = DedupeSet::open(dir.path().join("admitted.tags")).await?;
        let pow = PowAdmission::new(8, Some(set));

        let body = mine(b"hello board", 8);
        let tag = pow.verify(&body).await.expect("mined body should be admitted");

        assert!(!pow.seen(&tag).await?, "tag is unseen until recorded");
        pow.record_success(&tag).await?;
        assert!(pow.seen(&tag).await?, "recorded tag is seen");

        Ok(())
    }

    fn test_key(fill: u8) -> SecretKey {
        SecretKey::from_slice(&[fill; 32]).expect("nonzero constant is a valid key")
    }

    fn mailbox_id(key: &SecretKey) -> [u8; MAILBOX_ID_BYTES] {
        let pubkey = key.public_key(&Secp256k1::signing_only()).serialize();
        sha256::Hash::hash(&pubkey).to_byte_array()[..MAILBOX_ID_BYTES]
            .try_into()
            .expect("id length matches")
    }

    /// The verification input the queue route assembles: mailbox id
    /// followed by the token.
    fn token_input(mailbox_id: &[u8], token: &[u8]) -> Vec<u8> {
        let mut input = mailbox_id.to_vec();
        input.extend_from_slice(token);
        input
    }

    const TEST_NONCE: [u8; TOKEN_NONCE_BYTES] = [0xA5; TOKEN_NONCE_BYTES];

    #[tokio::test]
    async fn test_token_from_owner_is_admitted() {
        let admission = TokenAdmission::new(None);
        let owner = test_key(0x11);
        let token = mint_queue_token(&owner, TEST_NONCE);

        let id = mailbox_id(&owner);
        let tag = admission
            .verify(&token_input(&id, &token))
            .await
            .expect("owner-minted token should be admitted");
        assert_eq!(tag, token_input(&id, &TEST_NONCE), "tag is the mailbox id and nonce");
    }

    #[tokio::test]
    async fn test_token_for_other_mailbox_is_rejected() {
        // A stranger holds a perfectly valid token for their own
        // mailbox; presenting it for someone else's must fail the id
        // binding.
        let admission = TokenAdmission::new(None);
        let stranger = test_key(0x22);
        let token = mint_queue_token(&stranger, TEST_NONCE);

        let victim_id = mailbox_id(&test_key(0x11));
        assert_eq!(
            admission.verify(&token_input(&victim_id, &token)).await,
            Err(Rejection::Unauthorized)
        );
    }

    #[tokio::test]
    async fn test_token_signed_by_wrong_key_is_rejected() {
        // The token names the owner's public key, so the id binding
        // holds, but the signature was made by a different key.
        let admission = TokenAdmission::new(None);
        let owner = test_key(0x11);
        let forger = test_key(0x22);
        let id = mailbox_id(&owner);

        let secp = Secp256k1::signing_only();
        let sig = secp.sign_ecdsa(&token_sighash(&id, &TEST_NONCE), &forger).serialize_compact();
        let mut token = TEST_NONCE.to_vec();
        token.extend_from_slice(&owner.public_key(&secp).serialize());
        token.extend_from_slice(&sig);

        assert_eq!(admission.verify(&token_input(&id, &token)).await, Err(Rejection::Unauthorized));
    }

    #[tokio::test]
    async fn test_token_with_altered_nonce_is_rejected() {
        // The signature commits to the nonce, so a spent token cannot
        // be revived by re-randomizing its replay identity.
        let admission = TokenAdmission::new(None);
        let owner = test_key(0x11);
        let mut token = mint_queue_token(&owner, TEST_NONCE);
        token[0] ^= 0x01;

        assert_eq!(
            admission.verify(&token_input(&mailbox_id(&owner), &token)).await,
            Err(Rejection::Unauthorized)
        );
    }

    #[tokio::test]
    async fn test_token_malformed_is_rejected() {
        let admission = TokenAdmission::new(None);
        let owner = test_key(0x11);
        let id = mailbox_id(&owner);
        let token = mint_queue_token(&owner, TEST_NONCE);

        for len in [0, MAILBOX_ID_BYTES + TOKEN_BYTES - 1, MAILBOX_ID_BYTES + TOKEN_BYTES + 1] {
            assert_eq!(
                admission.verify(&vec![0u8; len]).await,
                Err(Rejection::Malformed),
                "input of {len} bytes must be malformed"
            );
        }

        // A zeroed public key field is not a curve point.
        let mut zeroed_key = token_input(&id, &token);
        zeroed_key[MAILBOX_ID_BYTES + TOKEN_NONCE_BYTES..][..TOKEN_PUBKEY_BYTES].fill(0);
        assert_eq!(admission.verify(&zeroed_key).await, Err(Rejection::Malformed));
    }

    #[tokio::test]
    async fn test_token_dedupe_via_trait_hooks() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let set = DedupeSet::open(dir.path().join("admitted.tags")).await?;
        let admission = TokenAdmission::new(Some(set));
        let owner = test_key(0x11);
        let token = mint_queue_token(&owner, TEST_NONCE);

        let tag = admission
            .verify(&token_input(&mailbox_id(&owner), &token))
            .await
            .expect("owner-minted token should be admitted");
        assert!(!admission.seen(&tag).await?, "tag is unseen until recorded");
        admission.record_success(&tag).await?;
        assert!(admission.seen(&tag).await?, "recorded tag is seen");

        Ok(())
    }
}
