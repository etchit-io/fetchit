//! In-memory state + JSON file persistence.

use crate::error::TrustError;
use crate::types::{DenylistEntry, EntryKind, Report, TargetIdentity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    reports: Vec<Report>,
    denylist_xornames: BTreeMap<String, DenylistEntry>,
    denylist_agents: BTreeMap<String, DenylistEntry>,
    #[serde(default)]
    denylist_relay_urls: BTreeMap<String, DenylistEntry>,
    #[serde(default)]
    denylist_actor_urls: BTreeMap<String, DenylistEntry>,
    etag_seq: u64,
}

/// File-backed in-memory state for reports and denylists.
pub struct Storage {
    path: PathBuf,
    inner: RwLock<Snapshot>,
}

impl Storage {
    /// Open the snapshot at `path`, creating an empty one if missing.
    ///
    /// # Errors
    /// Returns IO / JSON errors when reading or initialising the file.
    pub fn open(path: PathBuf) -> Result<Self, TrustError> {
        let inner = if path.exists() {
            let bytes = std::fs::read(&path)?;
            if bytes.is_empty() {
                Snapshot::default()
            } else {
                serde_json::from_slice(&bytes)?
            }
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Snapshot::default()
        };
        let store = Self {
            path,
            inner: RwLock::new(inner),
        };
        store.persist()?;
        Ok(store)
    }

    /// Append a report to the queue and flush to disk.
    ///
    /// # Errors
    /// Returns persistence errors.
    pub fn enqueue_report(&self, report: Report) -> Result<(), TrustError> {
        {
            let mut g = self.inner.write().map_err(|_| poisoned())?;
            g.reports.push(report);
        }
        self.persist()
    }

    /// Get every queued report (clone). Useful for moderator tooling.
    ///
    /// # Errors
    /// Returns when the lock is poisoned.
    pub fn list_reports(&self) -> Result<Vec<Report>, TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        Ok(g.reports.clone())
    }

    /// Number of queued reports.
    ///
    /// # Errors
    /// Returns when the lock is poisoned.
    pub fn reports_len(&self) -> Result<usize, TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        Ok(g.reports.len())
    }

    /// Promote a target to the denylist (idempotent).
    ///
    /// # Errors
    /// Returns persistence errors.
    pub fn deny(&self, entry: DenylistEntry) -> Result<(), TrustError> {
        let key = entry.target.value.clone();
        {
            let mut g = self.inner.write().map_err(|_| poisoned())?;
            match entry.target.kind {
                EntryKind::XorName => {
                    g.denylist_xornames.insert(key, entry);
                }
                EntryKind::AgentId => {
                    g.denylist_agents.insert(key, entry);
                }
                EntryKind::RelayUrl => {
                    g.denylist_relay_urls.insert(key, entry);
                }
                EntryKind::ActorUrl => {
                    g.denylist_actor_urls.insert(key, entry);
                }
            }
            g.etag_seq = g.etag_seq.saturating_add(1);
        }
        self.persist()
    }

    /// Remove a target from the denylist (idempotent).
    ///
    /// # Errors
    /// Returns persistence errors.
    pub fn allow(&self, target: &TargetIdentity) -> Result<(), TrustError> {
        {
            let mut g = self.inner.write().map_err(|_| poisoned())?;
            match target.kind {
                EntryKind::XorName => {
                    g.denylist_xornames.remove(&target.value);
                }
                EntryKind::AgentId => {
                    g.denylist_agents.remove(&target.value);
                }
                EntryKind::RelayUrl => {
                    g.denylist_relay_urls.remove(&target.value);
                }
                EntryKind::ActorUrl => {
                    g.denylist_actor_urls.remove(&target.value);
                }
            }
            g.etag_seq = g.etag_seq.saturating_add(1);
        }
        self.persist()
    }

    /// Current denylist for `kind`, sorted by value.
    ///
    /// # Errors
    /// Returns when the lock is poisoned.
    pub fn denylist_for(&self, kind: EntryKind) -> Result<Vec<DenylistEntry>, TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        let entries = match kind {
            EntryKind::XorName => g.denylist_xornames.values().cloned().collect(),
            EntryKind::AgentId => g.denylist_agents.values().cloned().collect(),
            EntryKind::RelayUrl => g.denylist_relay_urls.values().cloned().collect(),
            EntryKind::ActorUrl => g.denylist_actor_urls.values().cloned().collect(),
        };
        Ok(entries)
    }

    /// Current `ETag` value (monotonically increasing).
    ///
    /// # Errors
    /// Returns when the lock is poisoned.
    pub fn etag(&self) -> Result<String, TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        Ok(format!("\"{}\"", g.etag_seq))
    }

    /// Number of denylisted `XorName` entries.
    ///
    /// # Errors
    /// Returns when the lock is poisoned.
    pub fn xornames_len(&self) -> Result<usize, TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        Ok(g.denylist_xornames.len())
    }

    /// Number of denylisted `AgentId` entries.
    ///
    /// # Errors
    /// Returns when the lock is poisoned.
    pub fn agents_len(&self) -> Result<usize, TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        Ok(g.denylist_agents.len())
    }

    fn persist(&self) -> Result<(), TrustError> {
        let g = self.inner.read().map_err(|_| poisoned())?;
        let bytes = serde_json::to_vec_pretty(&*g)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn poisoned() -> TrustError {
    TrustError::Config("storage lock poisoned".into())
}

#[allow(dead_code)]
fn _ref<P: AsRef<Path>>(_: P) {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::ReportKind;
    use tempfile::tempdir;

    fn target(hex: &str, kind: EntryKind) -> TargetIdentity {
        TargetIdentity::new(kind, hex)
    }

    fn entry(hex: &str, kind: EntryKind) -> DenylistEntry {
        DenylistEntry {
            target: target(hex, kind),
            added_at_ms: 0,
            reason: ReportKind::AbusiveContent,
        }
    }

    fn sample_report() -> Report {
        Report {
            reporter_agent_id_hex: Some("a".repeat(64)),
            target: target(&"b".repeat(64), EntryKind::AgentId),
            kind: ReportKind::Spam,
            reason: "see attached".into(),
            attached_excerpt: None,
            timestamp_ms: 1,
        }
    }

    #[test]
    fn open_creates_empty_snapshot() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("snap.json");
        let s = Storage::open(p.clone()).unwrap();
        assert_eq!(s.reports_len().unwrap(), 0);
        assert!(p.exists());
    }

    #[test]
    fn enqueue_and_persist_round_trip() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("snap.json");
        let s = Storage::open(p.clone()).unwrap();
        s.enqueue_report(sample_report()).unwrap();

        let reopened = Storage::open(p).unwrap();
        assert_eq!(reopened.reports_len().unwrap(), 1);
    }

    #[test]
    fn deny_then_allow_round_trip() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("snap.json");
        let s = Storage::open(p).unwrap();
        let hex = "c".repeat(64);
        s.deny(entry(&hex, EntryKind::XorName)).unwrap();
        assert_eq!(s.xornames_len().unwrap(), 1);
        s.allow(&target(&hex, EntryKind::XorName)).unwrap();
        assert_eq!(s.xornames_len().unwrap(), 0);
    }

    #[test]
    fn etag_bumps_on_every_denylist_change() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("snap.json");
        let s = Storage::open(p).unwrap();
        let before = s.etag().unwrap();
        s.deny(entry(&"d".repeat(64), EntryKind::AgentId)).unwrap();
        let after = s.etag().unwrap();
        assert_ne!(before, after);
    }
}
