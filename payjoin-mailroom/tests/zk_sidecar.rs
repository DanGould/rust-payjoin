//! Credential admission against a real aut-ct verifier.
//!
//! Set `AUTCT_EXE` to an `autct` executable to run these; without it
//! they report a skip and pass, as the nginx tests do. They drive
//! [`ZkAdmission`] directly rather than through the board route, which
//! `board_zk_wire.rs` covers with a stub: what is under test here is
//! what the proof system actually does, in the cases where guessing it
//! would be expensive to get wrong.
//!
//! Every case runs in one test function against one verifier, in
//! order. One-show state is per key and per epoch and lives in the
//! verifier for as long as it runs, so cases that share a key cannot
//! be allowed to race.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash};
use hex::DisplayHex;
use payjoin_mailroom::admission::{
    Admission, AutctVerifier, Rejection, SpentJournal, ZkAdmission, PROOF_BYTES,
};

/// Where the one-show tag sits within a proof.
const KEY_IMAGE: std::ops::Range<usize> = 33..66;

/// The board blob a credential admits.
const BLOB_BYTES: usize = 512;

/// The password the fixture keys are encrypted under.
const KEY_PASSWORD: &str = "PASS";

/// Two epochs of one deployment. The verifier serves both at once, as
/// it must to let a key renew its credential when the epoch rolls.
const EPOCH_ONE: &str = "mailroom.test.epoch-one";
const EPOCH_TWO: &str = "mailroom.test.epoch-two";
/// A label the verifier was not started with.
const EPOCH_UNSERVED: &str = "mailroom.test.epoch-three";

#[derive(Debug)]
enum SidecarInitError {
    SidecarNotAvailable,
    UnknownError(Box<dyn std::error::Error>),
}

impl std::fmt::Display for SidecarInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SidecarInitError::SidecarNotAvailable =>
                write!(f, "AUTCT_EXE environment variable not set - skipping sidecar tests"),
            SidecarInitError::UnknownError(e) => write!(f, "Unknown error: {e}"),
        }
    }
}

impl std::error::Error for SidecarInitError {}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/autct").join(name)
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind to a free port")
        .local_addr()
        .expect("local address")
        .port()
}

/// A running verifier, its state, and the port it answers on.
struct Sidecar {
    child: Child,
    dir: tempfile::TempDir,
    port: u16,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Sidecar {
    /// Start a verifier serving `labels`, all over the fixture key set.
    async fn start(labels: &[&str]) -> Result<Self, SidecarInitError> {
        let exe = std::env::var("AUTCT_EXE")
            .map(PathBuf::from)
            .map_err(|_| SidecarInitError::SidecarNotAvailable)?;
        let dir = tempfile::tempdir().map_err(|e| SidecarInitError::UnknownError(Box::new(e)))?;
        let keyset = fixture("fakekeys-6.aks");
        let keysets = labels
            .iter()
            .map(|label| format!("{label}:{}", keyset.display()))
            .collect::<Vec<_>>()
            .join(",");
        let port = find_free_port();

        let log_path = dir.path().join("sidecar.log");
        let log = std::fs::File::create(&log_path)
            .map_err(|e| SidecarInitError::UnknownError(Box::new(e)))?;
        let errors = log.try_clone().map_err(|e| SidecarInitError::UnknownError(Box::new(e)))?;
        let child = Command::new(&exe)
            .args(["-M", "serve"])
            .args(["-k", &keysets])
            .args(["-H", "127.0.0.1"])
            .args(["-p", &port.to_string()])
            .args(["--verbose", "false"])
            // Its one-show store is written to the working directory,
            // so every run starts from a temporary one and no run
            // inherits another's spent credentials.
            .current_dir(dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors))
            .spawn()
            .map_err(|e| SidecarInitError::UnknownError(Box::new(e)))?;
        let sidecar = Sidecar { child, dir, port };

        // Readiness is read from its output, never by connecting: a
        // connection that does not carry a WebSocket handshake makes
        // it panic and exit. It binds the port only after loading
        // every key set, so the line is a sound signal.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("Starting server at") {
                return Ok(sidecar);
            }
            assert!(Instant::now() < deadline, "verifier never came up: {log}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Mint a proof for `key` under `label`, committed to `blob`.
    fn prove(&self, key: &str, label: &str, blob: &[u8]) -> Vec<u8> {
        let exe = std::env::var("AUTCT_EXE").expect("the sidecar is running");
        let proof_file = self.dir.path().join("minted-proof.bin");
        let keyset = fixture("fakekeys-6.aks");
        let command = format!(
            "{exe} -M prove -k {label}:{} -n signet -i {} -P {} -u {} -H 127.0.0.1 -p {} \
             --verbose false",
            keyset.display(),
            fixture(key).display(),
            proof_file.display(),
            user_string(blob),
            self.port,
        );
        // The prover reads its password from the terminal rather than
        // from standard input, so it needs one.
        let mut child = Command::new("script")
            .arg("-qec")
            .arg(&command)
            .arg("/dev/null")
            .current_dir(self.dir.path())
            .env("XDG_CONFIG_HOME", self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("script(1) is needed to run the prover");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(format!("{KEY_PASSWORD}\n").as_bytes())
            .expect("write the key password");
        let output = child.wait_with_output().expect("prover output");
        let proof = std::fs::read(&proof_file).unwrap_or_else(|e| {
            panic!("no proof was minted ({e}): {}", String::from_utf8_lossy(&output.stdout))
        });
        std::fs::remove_file(&proof_file).expect("clear the minted proof");
        assert_eq!(proof.len(), PROOF_BYTES, "proof length is what the board budgets for");
        proof
    }

    /// An admission verifying under `label` against this verifier,
    /// journalling what it admits into `storage`.
    async fn admission(&self, label: &str, storage: &Path) -> ZkAdmission {
        self.admission_on_port(label, storage, self.port).await
    }

    async fn admission_on_port(&self, label: &str, storage: &Path, port: u16) -> ZkAdmission {
        let exe = PathBuf::from(std::env::var("AUTCT_EXE").expect("the sidecar is running"));
        let keysets = format!("{label}:{}", fixture("fakekeys-6.aks").display());
        let verifier =
            AutctVerifier::new(exe, keysets, "127.0.0.1".to_string(), port, storage.join("autct"))
                .await
                .expect("verifier scratch directory");
        let journal =
            SpentJournal::open(storage.join("spent.journal")).await.expect("credential journal");
        ZkAdmission::new(std::sync::Arc::new(verifier), journal, None)
    }
}

fn blob(fill: u8) -> Vec<u8> { vec![fill; BLOB_BYTES] }

/// The string a proof commits to: the hex hash of the blob it admits.
fn user_string(blob: &[u8]) -> String {
    sha256::Hash::hash(blob).to_byte_array().to_lower_hex_string()
}

fn submission(proof: &[u8], blob: &[u8]) -> Vec<u8> {
    let mut body = proof.to_vec();
    body.extend_from_slice(blob);
    body
}

fn tag(proof: &[u8]) -> Vec<u8> { proof[KEY_IMAGE].to_vec() }

#[tokio::test]
async fn credentials_admit_against_a_real_verifier() {
    let sidecar = match Sidecar::start(&[EPOCH_ONE, EPOCH_TWO]).await {
        Ok(sidecar) => sidecar,
        Err(SidecarInitError::SidecarNotAvailable) => {
            eprintln!("Skipping test: AUTCT_EXE environment variable not set");
            return;
        }
        Err(e) => panic!("Failed to start the verifier: {e}"),
    };
    let storage = tempfile::tempdir().expect("tempdir");
    let epoch_one = sidecar.admission(EPOCH_ONE, &storage.path().join("epoch-one")).await;
    let epoch_two = sidecar.admission(EPOCH_TWO, &storage.path().join("epoch-two")).await;

    // A proof commits to the blob it was minted for, so one lifted
    // off a public board cannot admit different bytes.
    let announcement = blob(0xA1);
    let proof = sidecar.prove("member-key-2.enc", EPOCH_ONE, &announcement);
    assert_eq!(
        epoch_one.verify(&submission(&proof, &blob(0xB2))).await,
        Err(Rejection::Malformed),
        "a proof must not admit content it was not minted for"
    );

    // Refusing it did not spend the credential: the honest submission
    // it was minted for is still admitted.
    let admitted = epoch_one
        .verify(&submission(&proof, &announcement))
        .await
        .expect("the submission the proof was minted for");
    assert_eq!(admitted, tag(&proof));

    // The client that never saw the response sends it again.
    assert_eq!(
        epoch_one.verify(&submission(&proof, &announcement)).await,
        Ok(tag(&proof)),
        "an identical retransmit is the same submission arriving twice"
    );

    // A second announcement from the same coin in the same epoch is
    // not, even though it carries a freshly minted proof.
    let second = blob(0xC3);
    let second_proof = sidecar.prove("member-key-2.enc", EPOCH_ONE, &second);
    assert_eq!(
        tag(&second_proof),
        tag(&proof),
        "one coin has one tag per epoch, whatever it signs"
    );
    assert_eq!(
        epoch_one.verify(&submission(&second_proof, &second)).await,
        Err(Rejection::Conflict)
    );

    // Bytes that are no proof at all are refused without taking the
    // verifier down with them, which the cases below rely on.
    let garbage: Vec<u8> = sha256::Hash::hash(b"not a proof")
        .to_byte_array()
        .iter()
        .cycle()
        .take(PROOF_BYTES)
        .copied()
        .collect();
    assert_eq!(
        epoch_one.verify(&submission(&garbage, &blob(0xF6))).await,
        Err(Rejection::Malformed)
    );

    // A credential minted for an epoch the directory has left behind
    // is refused, and again the refusal costs its holder nothing.
    let renewal = blob(0xD4);
    let stale_proof = sidecar.prove("member-key-3.enc", EPOCH_ONE, &renewal);
    assert_eq!(
        epoch_two.verify(&submission(&stale_proof, &renewal)).await,
        Err(Rejection::Malformed),
        "the directory verifies under its own epoch, never a claimed one"
    );
    let spent_in_epoch_one = epoch_one
        .verify(&submission(&stale_proof, &renewal))
        .await
        .expect("still good in the epoch it was minted for");

    // The same coin is admitted again once the epoch rolls, under a
    // tag that cannot be matched to the one it spent before.
    let next = blob(0xE5);
    let next_proof = sidecar.prove("member-key-3.enc", EPOCH_TWO, &next);
    let spent_in_epoch_two = epoch_two
        .verify(&submission(&next_proof, &next))
        .await
        .expect("a new epoch is a new credential");
    assert_ne!(spent_in_epoch_one, spent_in_epoch_two, "tags are scoped to their epoch");

    // An epoch the verifier was never started with, and a verifier
    // that is not there at all, are the operator's problem: the
    // submission is untouched and may be retried.
    let unserved = sidecar.admission(EPOCH_UNSERVED, &storage.path().join("unserved")).await;
    assert_eq!(unserved.verify(&submission(&next_proof, &next)).await, Err(Rejection::Unavailable));
    let unreachable = sidecar.admission_on_port(EPOCH_ONE, storage.path(), find_free_port()).await;
    assert_eq!(
        unreachable.verify(&submission(&next_proof, &next)).await,
        Err(Rejection::Unavailable)
    );
}
