//! Admission control for open-submission endpoints.
//!
//! Mailbox and queue writes are implicitly gated by their ids: only a
//! party that learns an id can write to it. An endpoint that accepts
//! submissions from anyone has no such secret, so submissions pass an
//! [`Admission`] check instead. Proof of work admits strangers at a
//! computational cost; owner-minted tokens admit senders the mailbox
//! owner chose, for free; a zero-knowledge credential admits any
//! holder of a key in a published set, once per epoch, without
//! learning which key. The trait keeps routing code independent of
//! which mechanism an operator deploys, so mechanisms can be swapped,
//! or ordered one behind another, without touching the endpoints.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey, VerifyOnly};
use futures::future::BoxFuture;
use hex::{DisplayHex, FromHex};
use tokio::io::{self, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::warn;

/// Why a submission was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The submission is structurally invalid for the mechanism.
    Malformed,
    /// The submission does not carry sufficient work.
    InsufficientWork,
    /// The submission does not prove authorization by the owner of the
    /// resource it targets.
    Unauthorized,
    /// The submission spends a one-show credential that was already
    /// spent on different content.
    Conflict,
    /// The mechanism could not decide, because something it depends on
    /// is unavailable. The submission is not at fault and may be
    /// retried unchanged.
    Unavailable,
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

/// The serialized length of a credential proof.
///
/// Serialized aut-ct proof size for the fixed parameterization: curve
/// tree depth 2, branching factor 1024, batch size 1, default
/// generator length. Measured identical for a 6-key and a 330,000-key
/// set. Any other length is rejected before verification so a
/// parameter change upstream fails loudly at the length gate rather
/// than deep in the verifier.
pub const PROOF_BYTES: usize = 2793;

/// Where the one-show tag sits within a serialized proof.
///
/// The verifier reports only a verdict; the key image is not in its
/// output. The serialized proof begins with D, a 33-byte compressed
/// point, then E, so the tag is bytes 33..66. These bytes are trusted
/// only after the verifier accepts the proof, which requires
/// deserializing that same range as a valid point.
const KEY_IMAGE_RANGE: std::ops::Range<usize> = 33..66;

/// What a [`ProofVerifier`] concluded about a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The proof is valid and its key image was not seen before.
    Accepted,
    /// The proof is valid and its key image was seen before.
    Reused,
    /// The proof does not correspond to any member of the keyset.
    NotAMember,
    /// The proof does not verify under the verifier's current context.
    Invalid,
}

/// A verifier could not reach a verdict.
///
/// Distinct from every [`Verdict`], because the submission may be
/// perfectly good: answering with a client error would blame a sender
/// for an operator's outage and invite it to rebuild a submission that
/// was never wrong.
#[derive(Debug)]
pub struct Unavailable(String);

impl Unavailable {
    pub fn new(reason: impl Into<String>) -> Self { Self(reason.into()) }
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl std::error::Error for Unavailable {}

/// Verifier of zero-knowledge membership proofs.
///
/// Separate from [`ZkAdmission`] so that admission logic, which owns
/// the one-show accounting, can be exercised without a proof system
/// behind it.
pub trait ProofVerifier: Send + Sync {
    /// Verify `proof`, which must have been minted over `user_string`.
    fn verify<'a>(
        &'a self,
        proof: &'a [u8],
        user_string: &'a str,
    ) -> BoxFuture<'a, Result<Verdict, Unavailable>>;
}

/// Zero-knowledge credential admission.
///
/// A submission is `proof || blob`, where the proof shows its sender
/// controls the private key of one member of a published key set,
/// without revealing which member. It carries a one-show tag, the key
/// image, that is the same for every proof a given key makes within an
/// epoch and unlinkable to that key. So a key set of, say, the taproot
/// outputs at some block height becomes a per-epoch allowance of one
/// submission per coin, with no account and no issuer.
///
/// Key-image scoping and its linkage limit. The one-show tag is
/// I = x*J, where J is a per-epoch generator derived by hash-to-curve
/// from the epoch context label and shared by every set member within
/// the epoch. Because J is constant within an epoch, a party who knows
/// the scalar difference d between two member private keys can test
/// I2 - I1 = d*J and link those two admissions within the epoch
/// without learning either key. Holders of a non-hardened BIP32 xpub,
/// and BIP 352 senders who know the tweaks of outputs they created,
/// are such parties. The board is public and entries persist until
/// expiry, so the test can be run offline over a whole epoch's board.
/// This is a rate-limiting credential, not an unlinkable identity: the
/// tag enforces one admission per key per epoch and reveals nothing to
/// a party that did not already know the key relationship. Per-output
/// tag generators (I = x*H2C(P), the form Monero and FCMP++ use)
/// remove the linkage and are the production fix. See AdamISZ/aut-ct
/// docs/security-analysis.md and delvingbitcoin.org topic 862.
///
/// One-show state lives here, not in the verifier: a verifier that
/// spends the credential when it checks the proof would spend it for
/// submissions this directory then refuses to store. The journal
/// records the pair (tag, content) the moment a proof is accepted, and
/// a later report of reuse is answered against it: the same content is
/// the same submission arriving twice, anything else is a second
/// submission under a spent credential.
pub struct ZkAdmission {
    verifier: Arc<dyn ProofVerifier>,
    journal: SpentJournal,
    dedupe: Option<DedupeSet>,
}

impl ZkAdmission {
    pub fn new(
        verifier: Arc<dyn ProofVerifier>,
        journal: SpentJournal,
        dedupe: Option<DedupeSet>,
    ) -> Self {
        Self { verifier, journal, dedupe }
    }
}

impl Admission for ZkAdmission {
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>> {
        Box::pin(async move {
            if body.len() <= PROOF_BYTES {
                return Err(Rejection::Malformed);
            }
            let (proof, blob) = body.split_at(PROOF_BYTES);
            let content = sha256::Hash::hash(blob).to_byte_array();
            // The verifier folds user_string into the Fiat-Shamir
            // transcript, so the proof only verifies under the exact
            // string it was minted with. We pass the hex sha256 of the
            // stored blob bytes, which binds the credential to this
            // submission's content: a proof detached from an observed
            // post cannot admit different bytes, and a mismatch is
            // rejected before the key image is recorded, so it cannot
            // consume the prover's per-epoch allowance. Upstream's
            // RPC-API.md describes the field as unused; the transcript
            // code (peddleq.rs) is authoritative.
            let user_string = content.to_lower_hex_string();
            let verdict = match self.verifier.verify(proof, &user_string).await {
                Ok(verdict) => verdict,
                Err(e) => {
                    warn!("Credential verifier reached no verdict: {e}");
                    return Err(Rejection::Unavailable);
                }
            };
            let tag = proof[KEY_IMAGE_RANGE].to_vec();
            match verdict {
                Verdict::Accepted => match self.journal.insert(&tag, &content).await {
                    Ok(()) => Ok(tag),
                    Err(e) => {
                        // The credential is spent at the verifier but
                        // unrecorded here, so admitting would leave a
                        // retransmit indistinguishable from a reuse.
                        warn!("Could not record an accepted credential: {e}");
                        Err(Rejection::Unavailable)
                    }
                },
                Verdict::Reused => match self.journal.get(&tag).await {
                    Ok(Some(spent)) if spent == content => Ok(tag),
                    Ok(_) => Err(Rejection::Conflict),
                    Err(e) => {
                        warn!("Could not read the credential journal: {e}");
                        Err(Rejection::Unavailable)
                    }
                },
                Verdict::NotAMember => Err(Rejection::Unauthorized),
                Verdict::Invalid => Err(Rejection::Malformed),
            }
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

/// Proof-of-work admission ahead of a zero-knowledge credential.
///
/// Checking a credential is orders of magnitude more expensive than
/// checking work, and any keypair at all can produce a proof that only
/// the membership check rejects. Ordering the two is what keeps that
/// from being a denial-of-service path: the work over the whole
/// submission is a microsecond check, and a submission that fails it
/// never reaches the verifier.
///
/// The submission is `nonce || proof || blob`, so the work commits to
/// the proof as well as to the content. The admission tag is the
/// credential's key image alone: work is a toll, not an identity, and
/// re-mining a submission must not buy a second admission.
pub struct PowThenZk {
    pow: PowAdmission,
    zk: ZkAdmission,
}

impl PowThenZk {
    pub fn new(pow: PowAdmission, zk: ZkAdmission) -> Self { Self { pow, zk } }
}

impl Admission for PowThenZk {
    fn verify<'a>(&'a self, body: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, Rejection>> {
        Box::pin(async move {
            self.pow.verify(body).await?;
            self.zk.verify(&body[POW_NONCE_BYTES..]).await
        })
    }

    fn seen<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<bool>> { self.zk.seen(tag) }

    fn record_success<'a>(&'a self, tag: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        self.zk.record_success(tag)
    }
}

/// How long one verifier invocation may run before it is abandoned.
///
/// A verdict takes on the order of a tenth of a second. The bound is
/// not for slow proofs but for the paths where no answer is coming: a
/// proof that passes the signature check and then fails to
/// deserialize crashes the worker handling it, and the client waits.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// The name the proof is staged under for the client to read.
const STAGED_PROOF_FILE: &str = "pending-proof.bin";

/// The sentences the `autct` client prints for a verification, one
/// per outcome its server reports.
const ACCEPTED: &str =
    "Request was accepted by the Autct verifier! The proof is valid and the (unknown) pubkey is unused.";
const NOT_IN_TREE: &str = "Request rejected, PedDLEQ proof does not match the tree.";
const PROOF_INVALID: &str = "Request rejected, PedDLEQ proof is invalid.";
const KEY_IMAGE_REUSED: &str = "Request rejected, proofs are valid but key image is reused.";
const CONTEXT_NOT_SERVED: &str = "Request rejected, keyset chosen does not match the server's.";
const NOT_BASE64: &str = "Invalid encoding of proof, should be base64.";
const POINT_UNREADABLE: &str = "Curve point deserialization failure in proof.";
const PROOF_UNREADABLE: &str = "PedDLEQ proof deserialization failed.";

/// Read the verdict out of the client's output.
///
/// The client exits successfully whether it accepted or rejected, so
/// the printed sentence is the whole verdict. Matching whole lines
/// against the exact set means a reworded or unrecognized message
/// reads as no verdict at all, and is retried, rather than being
/// guessed at.
fn parse_verdict(stdout: &str) -> Result<Verdict, Unavailable> {
    for line in stdout.lines() {
        match line.trim() {
            ACCEPTED => return Ok(Verdict::Accepted),
            KEY_IMAGE_REUSED => return Ok(Verdict::Reused),
            NOT_IN_TREE => return Ok(Verdict::NotAMember),
            PROOF_INVALID | NOT_BASE64 | POINT_UNREADABLE | PROOF_UNREADABLE =>
                return Ok(Verdict::Invalid),
            // The sidecar serves a fixed set of context labels chosen
            // when it started, so a label it does not know is a
            // misconfiguration rather than a bad submission.
            CONTEXT_NOT_SERVED =>
                return Err(Unavailable::new("the verifier does not serve this context label")),
            _ => {}
        }
    }
    Err(Unavailable::new(format!("no verdict in verifier output: {}", stdout.trim())))
}

/// Verifier backed by the `autct` client and the sidecar it talks to.
///
/// Reading a key set of on-chain scale and building its curve tree
/// takes tens of seconds, so the verifier is a long-lived process an
/// operator starts alongside the directory, and each verification is
/// a short client invocation against it. Driving that client as a
/// subprocess keeps a proof system out of this binary: what the
/// directory depends on is an executable named in configuration,
/// which an operator can pin, sandbox or replace.
pub struct AutctVerifier {
    exe: PathBuf,
    keysets: String,
    host: String,
    port: u16,
    scratch: PathBuf,
    invocation: Mutex<()>,
}

impl AutctVerifier {
    /// `keysets` is the `context_label:keyset_file` pair the sidecar
    /// serves. `scratch` is a directory this verifier owns: the client
    /// rewrites a configuration file of its own on every run, which
    /// belongs there rather than in the operator's home, and the proof
    /// is staged there for it to read.
    pub async fn new(
        exe: PathBuf,
        keysets: String,
        host: String,
        port: u16,
        scratch: PathBuf,
    ) -> io::Result<Self> {
        tokio::fs::create_dir_all(&scratch).await?;
        Ok(Self { exe, keysets, host, port, scratch, invocation: Mutex::new(()) })
    }
}

impl ProofVerifier for AutctVerifier {
    fn verify<'a>(
        &'a self,
        proof: &'a [u8],
        user_string: &'a str,
    ) -> BoxFuture<'a, Result<Verdict, Unavailable>> {
        Box::pin(async move {
            // One invocation at a time: the client rewrites a shared
            // configuration file on every run, and the proof is handed
            // over at a fixed path. Verdicts cost about a tenth of a
            // second, and the work that gates them costs more.
            let _serialized = self.invocation.lock().await;
            let proof_file = self.scratch.join(STAGED_PROOF_FILE);
            tokio::fs::write(&proof_file, proof)
                .await
                .map_err(|e| Unavailable::new(format!("could not stage the proof: {e}")))?;

            let mut command = Command::new(&self.exe);
            command
                .args(["-M", "verify"])
                .args(["-k", &self.keysets])
                .arg("-P")
                .arg(&proof_file)
                .args(["-u", user_string])
                .args(["-H", &self.host])
                .args(["-p", &self.port.to_string()])
                // Without this the client prints its whole
                // configuration ahead of the verdict.
                .args(["--verbose", "false"])
                .env("XDG_CONFIG_HOME", &self.scratch)
                .current_dir(&self.scratch)
                .kill_on_drop(true);
            let output = match timeout(VERIFY_TIMEOUT, command.output()).await {
                Ok(Ok(output)) => output,
                Ok(Err(e)) =>
                    return Err(Unavailable::new(format!(
                        "could not run {}: {e}",
                        self.exe.display()
                    ))),
                Err(_) => return Err(Unavailable::new("the verifier did not answer in time")),
            };
            // The client exits successfully for every verdict it
            // reports, so a failed exit means it never got one.
            if !output.status.success() {
                return Err(Unavailable::new(format!(
                    "the verifier client failed ({}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            parse_verdict(&String::from_utf8_lossy(&output.stdout))
        })
    }
}

/// A persistent record of what each verified one-show credential was
/// spent on.
///
/// A one-show mechanism reports only that a credential was used
/// before, not what it was used for. Pairing each tag with a hash of
/// the content it was verified against tells an honest retransmit of
/// the same submission apart from a second submission under the same
/// credential. Records are appended and flushed before the admitted
/// operation runs, so a submission whose operation then fails is still
/// recognized on retry.
///
/// Tags and content hashes are public values, so they are stored in
/// plaintext: one `tag hash` hex pair per line. The file is never
/// compacted; deleting it forgets history.
#[derive(Clone)]
pub struct SpentJournal {
    inner: Arc<Mutex<JournalInner>>,
}

struct JournalInner {
    file: tokio::fs::File,
    spent: HashMap<Vec<u8>, [u8; 32]>,
}

/// The length of a content hash recorded in a [`SpentJournal`].
const CONTENT_HASH_BYTES: usize = 32;

fn parse_journal_line(line: &str) -> Option<(Vec<u8>, [u8; CONTENT_HASH_BYTES])> {
    let (tag, content) = line.split_once(' ')?;
    let tag = Vec::<u8>::from_hex(tag).ok()?;
    let content = Vec::<u8>::from_hex(content).ok()?.try_into().ok()?;
    (!tag.is_empty()).then_some((tag, content))
}

impl SpentJournal {
    /// Open the journal persisted at `path`, creating it if absent.
    pub async fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut spent = HashMap::new();
        if tokio::fs::try_exists(&path).await? {
            let contents = tokio::fs::read_to_string(&path).await?;
            for line in contents.lines() {
                // Skip unparsable lines, e.g. a torn tail from a crash
                // mid-append; losing a record costs one honest sender
                // the retransmit of one submission.
                if let Some((tag, content)) = parse_journal_line(line) {
                    spent.insert(tag, content);
                }
            }
        }
        let file = tokio::fs::OpenOptions::new().append(true).create(true).open(&path).await?;
        Ok(Self { inner: Arc::new(Mutex::new(JournalInner { file, spent })) })
    }

    /// The content hash `tag` was verified against, if it is recorded.
    pub async fn get(&self, tag: &[u8]) -> io::Result<Option<[u8; CONTENT_HASH_BYTES]>> {
        Ok(self.inner.lock().await.spent.get(tag).copied())
    }

    /// Record that `tag` was verified against `content`.
    ///
    /// The first record for a tag stands: a later call naming different
    /// content leaves it in place, so a spent credential cannot be
    /// repointed. The record is durable before this returns, because
    /// the caller acts on it before the admitted operation runs.
    pub async fn insert(&self, tag: &[u8], content: &[u8; CONTENT_HASH_BYTES]) -> io::Result<()> {
        let mut guard = self.inner.lock().await;
        if guard.spent.contains_key(tag) {
            return Ok(());
        }
        let line = format!("{} {}\n", tag.to_lower_hex_string(), content.to_lower_hex_string());
        guard.file.write_all(line.as_bytes()).await?;
        guard.file.sync_data().await?;
        guard.spent.insert(tag.to_vec(), *content);
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

    const CONTENT_A: [u8; CONTENT_HASH_BYTES] = [0x11; CONTENT_HASH_BYTES];
    const CONTENT_B: [u8; CONTENT_HASH_BYTES] = [0x22; CONTENT_HASH_BYTES];

    #[tokio::test]
    async fn test_spent_journal_persists_across_reopen() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("spent.journal");

        {
            let journal = SpentJournal::open(path.clone()).await?;
            assert_eq!(journal.get(b"tag one").await?, None);
            journal.insert(b"tag one", &CONTENT_A).await?;
        }

        let journal = SpentJournal::open(path).await?;
        assert_eq!(
            journal.get(b"tag one").await?,
            Some(CONTENT_A),
            "records should survive a restart"
        );
        assert_eq!(journal.get(b"tag two").await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_spent_journal_keeps_the_first_record() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("spent.journal");
        let journal = SpentJournal::open(path.clone()).await?;

        journal.insert(b"tag one", &CONTENT_A).await?;
        journal.insert(b"tag one", &CONTENT_B).await?;

        assert_eq!(
            journal.get(b"tag one").await?,
            Some(CONTENT_A),
            "a spent tag should not be repointed at other content"
        );
        assert_eq!(std::fs::read_to_string(&path)?.lines().count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_spent_journal_skips_torn_lines() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("spent.journal");

        {
            let journal = SpentJournal::open(path.clone()).await?;
            journal.insert(b"tag one", &CONTENT_A).await?;
        }
        // Simulate a crash mid-append: a torn, unparsable tail line.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(b"0dd 11")?;
        }

        let journal = SpentJournal::open(path).await?;
        assert_eq!(
            journal.get(b"tag one").await?,
            Some(CONTENT_A),
            "intact records should still load"
        );
        Ok(())
    }

    /// A verifier that answers from a script and records what it was
    /// asked, so admission can be tested without a proof system.
    struct MockVerifier {
        answers: std::sync::Mutex<std::collections::VecDeque<Result<Verdict, Unavailable>>>,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl MockVerifier {
        fn new(answers: impl IntoIterator<Item = Result<Verdict, Unavailable>>) -> Arc<Self> {
            Arc::new(Self {
                answers: std::sync::Mutex::new(answers.into_iter().collect()),
                asked: std::sync::Mutex::new(Vec::new()),
            })
        }

        /// The user strings the verifier was asked to verify under,
        /// one per call.
        fn asked(&self) -> Vec<String> { self.asked.lock().expect("uncontended").clone() }
    }

    impl ProofVerifier for MockVerifier {
        fn verify<'a>(
            &'a self,
            _proof: &'a [u8],
            user_string: &'a str,
        ) -> BoxFuture<'a, Result<Verdict, Unavailable>> {
            Box::pin(async move {
                self.asked.lock().expect("uncontended").push(user_string.to_string());
                self.answers.lock().expect("uncontended").pop_front().expect("an answer per call")
            })
        }
    }

    fn proof_with_tag(tag: u8) -> Vec<u8> {
        let mut proof = vec![0u8; PROOF_BYTES];
        proof[KEY_IMAGE_RANGE].fill(tag);
        proof
    }

    /// The submission a credential admits: proof then content.
    fn credential_submission(tag: u8, blob: &[u8]) -> Vec<u8> {
        let mut body = proof_with_tag(tag);
        body.extend_from_slice(blob);
        body
    }

    fn key_image(tag: u8) -> Vec<u8> { vec![tag; KEY_IMAGE_RANGE.len()] }

    async fn zk_admission(
        verifier: Arc<MockVerifier>,
        dir: &tempfile::TempDir,
    ) -> io::Result<ZkAdmission> {
        let journal = SpentJournal::open(dir.path().join("spent.journal")).await?;
        Ok(ZkAdmission::new(verifier, journal, None))
    }

    #[tokio::test]
    async fn test_zk_admits_an_accepted_proof() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let admission = zk_admission(MockVerifier::new([Ok(Verdict::Accepted)]), &dir).await?;

        let tag = admission
            .verify(&credential_submission(0x77, b"board blob"))
            .await
            .expect("an accepted proof should be admitted");

        assert_eq!(tag, key_image(0x77), "the tag is the proof's key image");
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_binds_the_proof_to_the_content() -> io::Result<()> {
        // A proof verifies only under the string it was minted with,
        // so asking under the content hash is what keeps an observed
        // proof from admitting different bytes.
        let dir = tempfile::tempdir()?;
        let verifier = MockVerifier::new([Ok(Verdict::Accepted)]);
        let admission = zk_admission(verifier.clone(), &dir).await?;

        let blob = b"board blob";
        admission.verify(&credential_submission(0x77, blob)).await.expect("admitted");

        assert_eq!(
            verifier.asked(),
            vec![sha256::Hash::hash(blob).to_byte_array().to_lower_hex_string()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_rejects_a_submission_without_content() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let verifier = MockVerifier::new([]);
        let admission = zk_admission(verifier.clone(), &dir).await?;

        for len in [0, PROOF_BYTES - 1, PROOF_BYTES] {
            assert_eq!(
                admission.verify(&vec![0u8; len]).await,
                Err(Rejection::Malformed),
                "a submission of {len} bytes carries no content to bind"
            );
        }
        assert!(verifier.asked().is_empty(), "the length gate precedes verification");
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_maps_verifier_rejections() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let admission =
            zk_admission(MockVerifier::new([Ok(Verdict::NotAMember), Ok(Verdict::Invalid)]), &dir)
                .await?;
        let body = credential_submission(0x77, b"board blob");

        assert_eq!(admission.verify(&body).await, Err(Rejection::Unauthorized));
        assert_eq!(admission.verify(&body).await, Err(Rejection::Malformed));
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_readmits_an_identical_retransmit() -> io::Result<()> {
        // The board write can fail after a proof is accepted, and a
        // client that never saw its response retransmits. Neither may
        // cost the sender its epoch credential.
        let dir = tempfile::tempdir()?;
        let admission =
            zk_admission(MockVerifier::new([Ok(Verdict::Accepted), Ok(Verdict::Reused)]), &dir)
                .await?;
        let body = credential_submission(0x77, b"board blob");

        assert_eq!(admission.verify(&body).await, Ok(key_image(0x77)));
        assert_eq!(
            admission.verify(&body).await,
            Ok(key_image(0x77)),
            "the same submission under a spent credential is that submission again"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_rejects_reuse_on_other_content() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let admission =
            zk_admission(MockVerifier::new([Ok(Verdict::Accepted), Ok(Verdict::Reused)]), &dir)
                .await?;

        admission.verify(&credential_submission(0x77, b"first blob")).await.expect("admitted");
        assert_eq!(
            admission.verify(&credential_submission(0x77, b"second blob")).await,
            Err(Rejection::Conflict),
            "one credential admits one submission per epoch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_rejects_unrecorded_reuse() -> io::Result<()> {
        // A verifier spends a key image on proofs it goes on to
        // reject, so its report of reuse is not evidence that this
        // directory ever admitted the credential.
        let dir = tempfile::tempdir()?;
        let admission = zk_admission(MockVerifier::new([Ok(Verdict::Reused)]), &dir).await?;

        assert_eq!(
            admission.verify(&credential_submission(0x77, b"board blob")).await,
            Err(Rejection::Conflict)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_zk_reports_an_undecided_verifier_as_retryable() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let admission =
            zk_admission(MockVerifier::new([Err(Unavailable::new("no verdict"))]), &dir).await?;

        assert_eq!(
            admission.verify(&credential_submission(0x77, b"board blob")).await,
            Err(Rejection::Unavailable),
            "an outage is not the sender's fault"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_pow_then_zk_checks_work_first() -> io::Result<()> {
        // Verification is expensive and any keypair can produce a
        // proof that only the membership check rejects, so an
        // unpriced credential path is a flood path.
        let dir = tempfile::tempdir()?;
        let verifier = MockVerifier::new([]);
        let layered = PowThenZk::new(
            PowAdmission::new(32, None),
            zk_admission(verifier.clone(), &dir).await?,
        );

        let body = mine(&credential_submission(0x77, b"board blob"), 8);
        assert_eq!(layered.verify(&body).await, Err(Rejection::InsufficientWork));
        assert!(verifier.asked().is_empty(), "unpaid work reaches no verifier");
        Ok(())
    }

    #[tokio::test]
    async fn test_pow_then_zk_tags_by_key_image() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let dedupe = DedupeSet::open(dir.path().join("admitted.tags")).await?;
        let journal = SpentJournal::open(dir.path().join("spent.journal")).await?;
        let layered = PowThenZk::new(
            PowAdmission::new(8, None),
            ZkAdmission::new(MockVerifier::new([Ok(Verdict::Accepted)]), journal, Some(dedupe)),
        );

        let body = mine(&credential_submission(0x77, b"board blob"), 8);
        let tag = layered.verify(&body).await.expect("a worked, credentialed body is admitted");

        assert_eq!(tag, key_image(0x77), "re-mining must not buy a second admission");
        assert!(!layered.seen(&tag).await?, "tag is unseen until recorded");
        layered.record_success(&tag).await?;
        assert!(layered.seen(&tag).await?, "recorded tag is seen");
        Ok(())
    }

    #[test]
    fn test_parse_verdict_reads_every_client_message() {
        assert_eq!(parse_verdict(ACCEPTED).expect("a verdict"), Verdict::Accepted);
        assert_eq!(parse_verdict(KEY_IMAGE_REUSED).expect("a verdict"), Verdict::Reused);
        assert_eq!(parse_verdict(NOT_IN_TREE).expect("a verdict"), Verdict::NotAMember);
        for invalid in [PROOF_INVALID, NOT_BASE64, POINT_UNREADABLE, PROOF_UNREADABLE] {
            assert_eq!(parse_verdict(invalid).expect("a verdict"), Verdict::Invalid);
        }
        assert!(
            parse_verdict(CONTEXT_NOT_SERVED).is_err(),
            "a label the verifier does not serve is the operator's fault, not the sender's"
        );
    }

    #[test]
    fn test_parse_verdict_finds_the_message_among_other_output() {
        let stdout = format!("some preamble\n{ACCEPTED}\n");
        assert_eq!(parse_verdict(&stdout).expect("a verdict"), Verdict::Accepted);
    }

    #[test]
    fn test_parse_verdict_refuses_to_guess() {
        // The last case is a prefix of the acceptance message: a
        // verdict is a whole line or it is no verdict at all.
        for stdout in ["", "Unrecognized error code from server?", "Request was accepted"] {
            assert!(parse_verdict(stdout).is_err(), "{stdout:?} is not a verdict");
        }
    }

    #[tokio::test]
    async fn test_autct_verifier_reports_a_missing_executable() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let verifier = AutctVerifier::new(
            dir.path().join("no-such-autct"),
            "epoch:keys.aks".to_string(),
            "127.0.0.1".to_string(),
            1,
            dir.path().join("scratch"),
        )
        .await?;

        let unavailable = verifier.verify(&[0u8; PROOF_BYTES], "00").await;
        assert!(unavailable.is_err(), "a verifier that cannot run reaches no verdict");
        Ok(())
    }
}
