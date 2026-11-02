//! Admission for contact logs: append-only logs with mailbox semantics.
//!
//! A contact log is one receiver's inbox for many senders. Only its owner may
//! create it or read it, and appends are refused until the owner has created
//! it, so a sender holding a stale or invented id gets an immediate refusal
//! instead of writing into a log nobody reads.
//!
//! Ownership is shown with a 32-byte owner token sent as the inner
//! `authorization: Owner <hex>` header. A log's id is the first 8 bytes of
//! the token's SHA-256, so the directory can check a token against an id
//! without storing anything, and nobody can claim a log id before its owner
//! does without finding a 64-bit preimage. The header travels inside the OHTTP
//! envelope, so the relay never sees it.

use std::collections::HashSet;
use std::sync::Mutex;

use bitcoin::hashes::{sha256, Hash};
use hex::FromHex;
use payjoin::directory::ShortId;

use crate::directory::{AdmissionHook, LogOperation};

/// The authorization scheme that carries an owner token.
pub const OWNER_SCHEME: &str = "Owner";

/// The log id an owner token controls.
pub fn log_id(owner_token: &[u8; 32]) -> ShortId {
    let hash = sha256::Hash::hash(owner_token).to_byte_array();
    ShortId(hash[..8].try_into().expect("a sha256 hash is longer than 8 bytes"))
}

/// An [`AdmissionHook`] that gives append-only logs mailbox semantics.
///
/// - Any request carrying the owner token for its log id is admitted and
///   marks the log as created.
/// - Appends without the owner token are admitted only to created logs.
/// - Reads always need the owner token.
///
/// The set of created logs is held in memory, so after a restart appends are
/// refused until each owner's next request recreates its log. Stored frames
/// are unaffected.
#[derive(Default)]
pub(crate) struct ContactLogs {
    created: Mutex<HashSet<ShortId>>,
}

impl AdmissionHook for ContactLogs {
    fn admit(&self, operation: LogOperation, id: &ShortId, authorization: Option<&[u8]>) -> bool {
        let owner = authorization.and_then(owner_token).is_some_and(|token| log_id(&token) == *id);
        let mut created = self.created.lock().expect("contact log set lock poisoned");
        if owner {
            created.insert(*id);
            return true;
        }
        match operation {
            LogOperation::Append => created.contains(id),
            LogOperation::Read => false,
        }
    }
}

/// Parse an `Owner <64 hex digits>` authorization value.
fn owner_token(authorization: &[u8]) -> Option<[u8; 32]> {
    let value = std::str::from_utf8(authorization).ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if scheme != OWNER_SCHEME {
        return None;
    }
    <[u8; 32]>::from_hex(token).ok()
}

#[cfg(test)]
mod tests {
    use hex::DisplayHex;

    use super::*;

    fn header(token: &[u8; 32]) -> Vec<u8> {
        format!("{OWNER_SCHEME} {}", token.as_hex()).into_bytes()
    }

    #[test]
    fn owner_creates_then_anyone_appends_and_only_owner_reads() {
        let hook = ContactLogs::default();
        let token = [7u8; 32];
        let id = log_id(&token);
        let owner = header(&token);

        assert!(!hook.admit(LogOperation::Append, &id, None), "uncreated log refuses appends");
        assert!(!hook.admit(LogOperation::Read, &id, None));

        assert!(hook.admit(LogOperation::Read, &id, Some(&owner)), "owner read creates");
        assert!(hook.admit(LogOperation::Append, &id, None));
        assert!(hook.admit(LogOperation::Append, &id, Some(b"Bearer something")));
        assert!(!hook.admit(LogOperation::Read, &id, None), "reads need the owner token");
        assert!(hook.admit(LogOperation::Read, &id, Some(&owner)));
    }

    #[test]
    fn owner_append_creates() {
        let hook = ContactLogs::default();
        let token = [9u8; 32];
        let id = log_id(&token);
        assert!(hook.admit(LogOperation::Append, &id, Some(&header(&token))));
        assert!(hook.admit(LogOperation::Append, &id, None));
    }

    #[test]
    fn token_for_another_log_is_not_ownership() {
        let hook = ContactLogs::default();
        let (mine, theirs) = ([1u8; 32], [2u8; 32]);
        let their_id = log_id(&theirs);

        assert!(!hook.admit(LogOperation::Read, &their_id, Some(&header(&mine))));
        assert!(!hook.admit(LogOperation::Append, &their_id, Some(&header(&mine))));
        assert!(
            !hook.admit(LogOperation::Append, &their_id, None),
            "a wrong token creates nothing"
        );
    }

    #[test]
    fn malformed_owner_headers_are_not_ownership() {
        let hook = ContactLogs::default();
        let token = [3u8; 32];
        let id = log_id(&token);
        let hex = token.as_hex().to_string();
        for value in [
            hex.clone(),
            format!("Bearer {hex}"),
            format!("owner {hex}"),
            format!("{OWNER_SCHEME} {}", &hex[..62]),
            format!("{OWNER_SCHEME}  {hex}"),
            format!("{OWNER_SCHEME} {hex}00"),
        ] {
            assert!(!hook.admit(LogOperation::Read, &id, Some(value.as_bytes())), "{value:?}");
        }
    }
}
