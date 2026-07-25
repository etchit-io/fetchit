//! Durable local record of group-key convergence — the stock-daemon
//! replacement for the fork's read-only `GET /groups/:id/secure/self` probe.
//!
//! The fork daemon can answer "does THIS daemon hold the group's live
//! crypto state" as a pure read. Stock x0xd (v0.34.3) has no such
//! endpoint, and the only stock way to *ask* is a real `secure/encrypt`,
//! which burns a sender ratchet generation per call — unacceptable on a
//! hot path. So the client records what it already knows: whenever a join
//! converges or a group frame round-trips the daemon's crypto, this store
//! notes "keyed at epoch E". [`crate::client::Client::probe_group_state`]
//! then answers `keyed` from the record for free, and falls back to a
//! single one-shot encrypt probe only when the record is absent (fresh
//! install / wiped app data) — which also re-seeds the record.
//!
//! Honesty bounds: the record can go stale in exactly one direction that
//! matters — the DAEMON's state was wiped while the app's data survived,
//! so the record claims keyed over a keyless daemon. The consumers
//! tolerate that: a false `keyed` routes recovery through the warm/cold
//! lanes, whose first real daemon call fails and converges via the
//! durable pending-join resume, after which the record is rewritten.
//! The reverse mismatch (record lost, daemon keyed) costs one encrypt
//! probe and self-heals. Records are advisory recovery state, never an
//! authorization input.
//!
//! Storage mirrors [`super::pending_join::PendingJoinStore`]: one plain
//! JSON file per group under a `0o700` directory, atomic writes. Contents
//! are group ids + epochs the daemon already persists in its own files,
//! so there is nothing here to seal that the daemon does not already
//! hold in plaintext.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::ChatError;
use crate::local_store::write_json_atomic;

/// One "this daemon has held live keys for this group" observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceRecord {
    /// 64-hex group id the observation is for.
    pub group_id: String,
    /// The secret epoch observed at the moment of convergence — advisory
    /// (drives behind/at-epoch heuristics), never authorization.
    pub epoch: u64,
    /// When the observation was made (epoch ms).
    pub at_ms: u64,
}

/// Per-group convergence records under one directory.
pub struct ConvergenceStore {
    dir: PathBuf,
}

impl ConvergenceStore {
    /// Open (creating the directory if needed) a store rooted at `dir`,
    /// conventionally `<data_dir>/converged/`.
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

    /// Record (or refresh) convergence for `group_id` at `epoch`.
    ///
    /// # Errors
    /// Returns an error if serialization or the atomic write fails.
    pub fn record(&self, group_id: &str, epoch: u64, at_ms: u64) -> Result<(), ChatError> {
        write_json_atomic(
            &self.path_for(group_id),
            &ConvergenceRecord {
                group_id: group_id.to_owned(),
                epoch,
                at_ms,
            },
        )
    }

    /// Fetch the record for `group_id`, if any.
    ///
    /// # Errors
    /// Returns [`ChatError::Decode`] if an existing file is corrupt.
    pub fn get(&self, group_id: &str) -> Result<Option<ConvergenceRecord>, ChatError> {
        let path = self.path_for(group_id);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ChatError::Io(e)),
        }
    }

    /// Remove the record for `group_id` (no-op if absent) — used when a
    /// group is deleted or its membership is knowingly reset.
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

    fn temp_store() -> (tempfile::TempDir, ConvergenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConvergenceStore::open(dir.path().join("converged")).unwrap();
        (dir, store)
    }

    #[test]
    fn record_round_trips_and_refreshes() {
        let (_t, store) = temp_store();
        let gid = "a".repeat(64);
        assert_eq!(store.get(&gid).unwrap(), None);
        store.record(&gid, 3, 1_000).unwrap();
        assert_eq!(
            store.get(&gid).unwrap(),
            Some(ConvergenceRecord {
                group_id: gid.clone(),
                epoch: 3,
                at_ms: 1_000,
            })
        );
        // A later observation replaces, never appends.
        store.record(&gid, 7, 2_000).unwrap();
        assert_eq!(store.get(&gid).unwrap().unwrap().epoch, 7);
    }

    #[test]
    fn remove_is_idempotent() {
        let (_t, store) = temp_store();
        let gid = "b".repeat(64);
        store.remove(&gid).unwrap();
        store.record(&gid, 1, 1).unwrap();
        store.remove(&gid).unwrap();
        assert_eq!(store.get(&gid).unwrap(), None);
    }
}
