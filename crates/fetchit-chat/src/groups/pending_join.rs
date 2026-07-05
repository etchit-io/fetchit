//! Durable pending-join: the record + its disk store.
//!
//! A join to a private MLS group is a durable *intent*, not a one-shot RPC.
//! The instant `join_post` succeeds once, we persist the signed
//! `member_joined` bytes here; every later attempt re-bridges those saved
//! bytes instead of re-`join_post`ing, so a single-use invite is spent at
//! most once — exactly when the join truly converges. See
//! `docs/superpowers/specs/2026-07-04-durable-join-design.md`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::ChatError;
use crate::local_store::write_json_atomic;

/// Lifecycle of a pending join. The three non-terminal states all present
/// to callers as a single public `Pending`; `Converged`/`Failed` are
/// terminal and the record is removed once reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum PendingJoinState {
    /// `join_post` succeeded; the captured event is saved, not yet applied.
    Submitted,
    /// The captured event has been bridged to the owner at least once.
    Bridged,
    /// The roster lists us but we hold no group key (Welcome lost); the
    /// driver re-requests the staged join-result — never a new invite.
    KeyedButUnverified,
    /// Terminally failed (malformed invite, or invite already consumed by
    /// another agent).
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
}

/// A persisted join intent, one per group being joined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingJoin {
    /// 64-hex group id.
    pub group_id: String,
    /// The ONE signed `member_joined` from `join_post`, base64. Load-bearing:
    /// re-bridging these bytes is what avoids a second `join_post` (G1).
    pub captured_event_b64: String,
    /// The captured event's gossip topic — `emit_self_join_bridge` sends it
    /// verbatim, so a re-bridge must carry the same topic as the first.
    pub captured_topic: String,
    /// `sha256_hex(invite.0)` — the resume key. `join_group_durable`
    /// pre-checks this BEFORE `join_post` so a deep-link re-tap or a
    /// replayed intent drives the existing record instead of spending the
    /// single-use invite twice (G1 at the entry, not just in the driver).
    pub invite_hash: String,
    /// 64-hex inviter/owner agent id, parsed from the captured event.
    pub owner_agent_id: String,
    /// Owner ML-KEM pubkey, base64 — resolved once, cached for re-bridges.
    pub owner_kem_pubkey_b64: String,
    /// Our own ML-KEM pubkey hint, base64, for the owner's reply seal.
    pub joiner_kem_pubkey_b64: String,
    /// Epoch ms when the intent was first submitted.
    pub created_at_ms: u64,
    /// Epoch ms of the most recent drive attempt (0 = never driven yet).
    pub last_attempt_ms: u64,
    /// Number of drive attempts so far; feeds the backoff gate.
    pub attempts: u32,
    /// Current lifecycle state.
    pub state: PendingJoinState,
}

impl PendingJoin {
    /// A freshly submitted intent (state `Submitted`, zero attempts).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: String,
        captured_event_b64: String,
        captured_topic: String,
        invite_hash: String,
        owner_agent_id: String,
        owner_kem_pubkey_b64: String,
        joiner_kem_pubkey_b64: String,
        now_ms: u64,
    ) -> Self {
        Self {
            group_id,
            captured_event_b64,
            captured_topic,
            invite_hash,
            owner_agent_id,
            owner_kem_pubkey_b64,
            joiner_kem_pubkey_b64,
            created_at_ms: now_ms,
            last_attempt_ms: 0,
            attempts: 0,
            state: PendingJoinState::Submitted,
        }
    }

    /// Non-terminal states present to callers as `Pending`.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, PendingJoinState::Failed { .. })
    }
}

/// Disk-backed store: one `<dir>/<group_id>.json` file per pending join,
/// written atomically at mode 0600 via [`write_json_atomic`].
pub struct PendingJoinStore {
    dir: PathBuf,
}

impl PendingJoinStore {
    /// Open (creating the directory if needed) a store rooted at `dir`,
    /// conventionally `<data_dir>/pending_joins/`.
    ///
    /// # Errors
    /// Returns [`ChatError::Io`] if the directory cannot be created.
    pub fn open(dir: PathBuf) -> Result<Self, ChatError> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&dir)?.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(&dir, perms);
        }
        Ok(Self { dir })
    }

    fn path_for(&self, group_id: &str) -> PathBuf {
        self.dir.join(format!("{group_id}.json"))
    }

    /// Insert or replace the record for its group.
    ///
    /// # Errors
    /// Returns an error if serialization or the atomic write fails.
    pub fn upsert(&self, record: &PendingJoin) -> Result<(), ChatError> {
        write_json_atomic(&self.path_for(&record.group_id), record)
    }

    /// Fetch the record for `group_id`, if any.
    ///
    /// # Errors
    /// Returns [`ChatError::Decode`] if an existing file is corrupt.
    pub fn get(&self, group_id: &str) -> Result<Option<PendingJoin>, ChatError> {
        let path = self.path_for(group_id);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ChatError::Io(e)),
        }
    }

    /// All persisted records (corrupt/foreign files are skipped, not fatal).
    ///
    /// # Errors
    /// Returns [`ChatError::Io`] only if the directory cannot be read.
    pub fn list(&self) -> Result<Vec<PendingJoin>, ChatError> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(ChatError::Io(e)),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(rec) = serde_json::from_slice::<PendingJoin>(&bytes) {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    /// Remove the record for `group_id` (no-op if absent).
    ///
    /// # Errors
    /// Returns [`ChatError::Io`] on an unexpected filesystem error.
    pub fn remove(&self, group_id: &str) -> Result<(), ChatError> {
        match std::fs::remove_file(self.path_for(group_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ChatError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn rec(group: &str, now: u64) -> PendingJoin {
        PendingJoin::new(
            group.into(),
            "Y2FwdHVyZWQ=".into(),
            "x0x.group.test.metadata".into(),
            "invitehash".into(),
            "aa".repeat(32),
            "b3duZXJrZW0=".into(),
            "am9pbmVya2Vt".into(),
            now,
        )
    }

    fn store() -> (PendingJoinStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = PendingJoinStore::open(dir.path().join("pending_joins")).unwrap();
        (s, dir)
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let (s, _d) = store();
        let r = rec("11".repeat(32).as_str(), 1000);
        s.upsert(&r).unwrap();
        assert_eq!(s.get(&r.group_id).unwrap().as_ref(), Some(&r));
    }

    #[test]
    fn get_absent_is_none() {
        let (s, _d) = store();
        assert!(s.get(&"22".repeat(32)).unwrap().is_none());
    }

    #[test]
    fn upsert_replaces_in_place() {
        let (s, _d) = store();
        let mut r = rec("33".repeat(32).as_str(), 1);
        s.upsert(&r).unwrap();
        r.attempts = 5;
        r.state = PendingJoinState::Bridged;
        s.upsert(&r).unwrap();
        let got = s.get(&r.group_id).unwrap().unwrap();
        assert_eq!(got.attempts, 5);
        assert_eq!(got.state, PendingJoinState::Bridged);
        // still exactly one file for this group
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[test]
    fn list_returns_all_records() {
        let (s, _d) = store();
        s.upsert(&rec(&"44".repeat(32), 1)).unwrap();
        s.upsert(&rec(&"55".repeat(32), 2)).unwrap();
        let ids: std::collections::HashSet<_> =
            s.list().unwrap().into_iter().map(|r| r.group_id).collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn remove_is_idempotent() {
        let (s, _d) = store();
        let r = rec(&"66".repeat(32), 1);
        s.upsert(&r).unwrap();
        s.remove(&r.group_id).unwrap();
        s.remove(&r.group_id).unwrap(); // no-op, no error
        assert!(s.get(&r.group_id).unwrap().is_none());
    }

    #[test]
    fn list_skips_corrupt_and_foreign_files() {
        let (s, dir) = store();
        s.upsert(&rec(&"77".repeat(32), 1)).unwrap();
        let d = dir.path().join("pending_joins");
        std::fs::write(d.join("garbage.json"), b"not json").unwrap();
        std::fs::write(d.join("note.txt"), b"ignored").unwrap();
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn record_file_is_mode_600() {
        use std::os::unix::fs::PermissionsExt as _;
        let (s, dir) = store();
        let r = rec(&"88".repeat(32), 1);
        s.upsert(&r).unwrap();
        let p = dir
            .path()
            .join("pending_joins")
            .join(format!("{}.json", r.group_id));
        let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "record must be 0600");
    }

    #[test]
    fn terminal_only_for_failed() {
        let (_s, _d) = store();
        let mut r = rec(&"99".repeat(32), 1);
        assert!(!r.is_terminal());
        r.state = PendingJoinState::KeyedButUnverified;
        assert!(!r.is_terminal());
        r.state = PendingJoinState::Failed { reason: "x".into() };
        assert!(r.is_terminal());
    }
}
