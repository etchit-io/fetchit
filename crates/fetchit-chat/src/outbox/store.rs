//! Vault-persisted store of outbound DM bubbles.
//!
//! Mirrors `crate::groups_reachability::BridgeConsentStore`: the bubble
//! map is sealed at rest under the chat master key via
//! [`crate::at_rest::seal_to_path`], `load` is fail-safe to empty on any
//! read failure, and `flush` is best-effort (a write failure is logged and
//! swallowed; the in-memory state is authoritative). An in-memory
//! `inflight` guard prevents the retry driver from re-firing a bubble whose
//! send is already in progress.

use super::{OutboxBubble, OutboxStatus};
use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::local_store::StoreLayout;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Everything [`OutboxStore`] needs to seal its map to disk, mirroring the
/// consent store's persistence handle. Cloned into the store by
/// [`OutboxStore::load`]; absent for in-memory stores.
#[derive(Clone)]
struct OutboxPersist {
    layout: StoreLayout,
    master: MasterKey,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
}

impl std::fmt::Debug for OutboxPersist {
    // The master key never appears in Debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxPersist")
            .field("path", &self.layout.outbox_path())
            .field("master", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// In-memory map of outbound DM bubbles keyed by bubble id, optionally
/// backed by a sealed on-disk vault.
#[derive(Debug, Default)]
pub struct OutboxStore {
    inner: HashMap<String, OutboxBubble>,
    persist: Option<OutboxPersist>,
    inflight: HashSet<String>,
}

impl OutboxStore {
    /// Empty, in-memory-only store (no disk persistence). Equivalent to
    /// `Default`. Used by tests and any caller without a master key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the persisted bubbles from `outbox/outbox.json.enc`, returning
    /// a store that re-seals on every mutation.
    ///
    /// Fail-safe: a missing file, a wrong or rotated master key (AEAD tag
    /// mismatch), or a truncated/corrupt/unparseable file all fall back to
    /// an empty map rather than erroring -- a damaged outbox never blocks
    /// client startup.
    #[must_use]
    pub fn load(
        layout: &StoreLayout,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        let inner = Self::read_map(&layout.outbox_path(), master).unwrap_or_default();
        Self {
            inner,
            persist: Some(OutboxPersist {
                layout: layout.clone(),
                master: master.clone(),
                kdf_id,
                argon_salt: argon_salt.copied(),
            }),
            inflight: HashSet::new(),
        }
    }

    /// Best-effort read of the sealed map. `None` on any failure so
    /// [`Self::load`] can fall back to empty.
    fn read_map(path: &Path, master: &MasterKey) -> Option<HashMap<String, OutboxBubble>> {
        if !path.exists() {
            return None;
        }
        let plain = open_from_path(path, master).ok()?;
        serde_json::from_slice(&plain).ok()
    }

    /// Insert or replace `bubble` (keyed by its `id`) and persist.
    pub fn upsert(&mut self, bubble: OutboxBubble) {
        self.inner.insert(bubble.id.clone(), bubble);
        self.flush();
    }

    /// Borrow the bubble with `id`, if present.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&OutboxBubble> {
        self.inner.get(id)
    }

    /// All bubbles, cloned (for the initial-render snapshot the shell
    /// reads before subscribing to live events).
    #[must_use]
    pub fn snapshot(&self) -> Vec<OutboxBubble> {
        self.inner.values().cloned().collect()
    }

    /// Remove the bubble with `id` and persist the removal.
    pub fn remove(&mut self, id: &str) {
        self.inner.remove(id);
        self.flush();
    }

    /// Claim `id` as in-flight. Returns `true` if newly claimed, `false`
    /// if a send for it is already in progress (double-send guard). Not
    /// persisted -- in-flight tasks die with the process; the boot sweep
    /// reclaims orphans.
    pub fn try_mark_inflight(&mut self, id: &str) -> bool {
        self.inflight.insert(id.to_string())
    }

    /// Release the in-flight claim on `id`.
    pub fn clear_inflight(&mut self, id: &str) {
        self.inflight.remove(id);
    }

    /// Flip every `Sending` bubble older than `timeout_ms` (relative to
    /// `now_ms`) to `Failed`. Returns the changed bubbles (for event
    /// emission); persists once if anything changed.
    pub fn sweep_timeouts(&mut self, now_ms: u64, timeout_ms: u64) -> Vec<OutboxBubble> {
        let mut changed = Vec::new();
        for bubble in self.inner.values_mut() {
            if matches!(bubble.status, OutboxStatus::Sending)
                && now_ms.saturating_sub(bubble.enqueued_at_ms) >= timeout_ms
            {
                bubble.status = OutboxStatus::Failed;
                bubble.last_error = Some("delivery timed out".to_string());
                changed.push(bubble.clone());
            }
        }
        if !changed.is_empty() {
            self.flush();
        }
        changed
    }

    /// Flip orphaned in-flight bubbles to `Failed` at startup: a `Sending`
    /// bubble with no `message_id` enqueued before `process_start_ms` lost
    /// its in-flight task when the previous process exited, so it is safe
    /// to re-drive via the normal retry path. Returns the changed bubbles;
    /// persists once if anything changed.
    pub fn boot_sweep(&mut self, process_start_ms: u64) -> Vec<OutboxBubble> {
        let mut changed = Vec::new();
        for bubble in self.inner.values_mut() {
            if matches!(bubble.status, OutboxStatus::Sending)
                && bubble.message_id.is_none()
                && bubble.enqueued_at_ms < process_start_ms
            {
                bubble.status = OutboxStatus::Failed;
                bubble.last_error = Some("send interrupted by restart".to_string());
                changed.push(bubble.clone());
            }
        }
        if !changed.is_empty() {
            self.flush();
        }
        changed
    }

    /// Mark the bubble carrying `message_id` as `Delivered` (called from
    /// the `DeliveryReceipt` inbound path). Returns the updated bubble, or
    /// `None` when no bubble carries that id. Persists on a hit.
    pub fn mark_delivered(&mut self, message_id: &str) -> Option<OutboxBubble> {
        let updated = {
            let bubble = self
                .inner
                .values_mut()
                .find(|b| b.message_id.as_deref() == Some(message_id))?;
            bubble.status = OutboxStatus::Delivered;
            bubble.clone()
        };
        self.flush();
        Some(updated)
    }

    /// Apply the result of a send attempt to bubble `bubble_id`, returning
    /// the updated bubble for the caller to broadcast (or `None` if the
    /// bubble is gone or already `Delivered`). Shared by the initial send
    /// (`Client::enqueue_dm`) and the retry driver so the status mapping +
    /// the Delivered-guard live in ONE place.
    ///
    /// `error.is_some()` -> the send failed (`Failed` + `last_error`);
    /// otherwise it succeeded (`Sending`, recording `message_id` when the
    /// relay assigned one). A bubble already `Delivered` (a receipt landed
    /// during the send await) is never clobbered -- on either arm.
    pub fn record_send_outcome(
        &mut self,
        bubble_id: &str,
        message_id: Option<String>,
        error: Option<String>,
    ) -> Option<OutboxBubble> {
        let updated = {
            let bubble = self.inner.get_mut(bubble_id)?;
            if matches!(bubble.status, OutboxStatus::Delivered) {
                return None;
            }
            if let Some(reason) = error {
                bubble.status = OutboxStatus::Failed;
                bubble.last_error = Some(reason);
            } else {
                if message_id.is_some() {
                    bubble.message_id = message_id;
                }
                bubble.status = OutboxStatus::Sending;
                bubble.last_error = None;
            }
            bubble.clone()
        };
        self.flush();
        Some(updated)
    }

    /// Seal the whole map to disk when a persistence handle is set.
    /// Best-effort: a serialize or write failure is logged and swallowed.
    /// `seal_to_path` writes atomically (temp + rename). No-op for
    /// in-memory stores.
    fn flush(&self) {
        let Some(persist) = self.persist.as_ref() else {
            return;
        };
        let bytes = match serde_json::to_vec(&self.inner) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("outbox encode failed, not persisted: {e}");
                return;
            }
        };
        if let Err(e) = seal_to_path(
            &persist.layout.outbox_path(),
            &bytes,
            &persist.master,
            persist.kdf_id,
            persist.argon_salt.as_ref(),
        ) {
            log::warn!("outbox persist failed: {e}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use crate::identity::AgentId;
    use crate::outbox::OutboxStatus;
    use tempfile::tempdir;

    fn test_master() -> MasterKey {
        MasterKey::from_bytes_for_test([7u8; AEAD_KEY_LEN])
    }

    fn bubble(id: &str, peer: &str) -> OutboxBubble {
        OutboxBubble {
            id: id.into(),
            peer: AgentId(peer.repeat(64)),
            body: "hi".into(),
            status: OutboxStatus::Sending,
            message_id: None,
            enqueued_at_ms: 1,
            last_error: None,
        }
    }

    #[test]
    fn outbox_persists_across_reload() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let m = test_master();
        let mut s = OutboxStore::load(&layout, &m, 0, None);
        s.upsert(bubble("b1", "a"));
        drop(s);
        let s2 = OutboxStore::load(&layout, &m, 0, None);
        assert_eq!(s2.snapshot().len(), 1);
        assert_eq!(s2.get("b1").unwrap().peer.0, "a".repeat(64));
    }

    #[test]
    fn outbox_wrong_key_falls_back_to_empty() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let mut s = OutboxStore::load(&layout, &test_master(), 0, None);
        s.upsert(bubble("b1", "a"));
        drop(s);
        let wrong = MasterKey::from_bytes_for_test([9u8; AEAD_KEY_LEN]);
        assert!(OutboxStore::load(&layout, &wrong, 0, None)
            .snapshot()
            .is_empty());
    }

    #[test]
    fn outbox_corrupt_falls_back_to_empty() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        std::fs::write(layout.outbox_path(), b"garbage").unwrap();
        assert!(OutboxStore::load(&layout, &test_master(), 0, None)
            .snapshot()
            .is_empty());
    }

    #[test]
    fn new_store_never_touches_disk() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let mut s = OutboxStore::new();
        s.upsert(bubble("b1", "a"));
        assert!(!layout.outbox_path().exists());
        assert_eq!(s.snapshot().len(), 1);
    }

    #[test]
    fn inflight_guard_blocks_double_claim() {
        let mut s = OutboxStore::new();
        s.upsert(bubble("b1", "a"));
        assert!(s.try_mark_inflight("b1"));
        assert!(!s.try_mark_inflight("b1"));
        s.clear_inflight("b1");
        assert!(s.try_mark_inflight("b1"));
    }

    fn sending(id: &str, enqueued_at_ms: u64, message_id: Option<&str>) -> OutboxBubble {
        OutboxBubble {
            id: id.into(),
            peer: AgentId("aa".repeat(32)),
            body: "hi".into(),
            status: OutboxStatus::Sending,
            message_id: message_id.map(Into::into),
            enqueued_at_ms,
            last_error: None,
        }
    }

    #[test]
    fn sweep_timeouts_fails_stale_sending() {
        let mut s = OutboxStore::new();
        s.upsert(sending("b1", 0, None));
        let changed = s.sweep_timeouts(86_400_001, 86_400_000);
        assert_eq!(changed.len(), 1);
        assert_eq!(s.get("b1").unwrap().status, OutboxStatus::Failed);
    }

    #[test]
    fn sweep_timeouts_leaves_fresh_sending() {
        let mut s = OutboxStore::new();
        s.upsert(sending("b1", 1_000, None));
        let changed = s.sweep_timeouts(1_001, 86_400_000);
        assert!(changed.is_empty());
        assert_eq!(s.get("b1").unwrap().status, OutboxStatus::Sending);
    }

    #[test]
    fn boot_sweep_fails_orphaned_sending() {
        let mut s = OutboxStore::new();
        s.upsert(sending("b1", 10, None));
        let changed = s.boot_sweep(100);
        assert_eq!(changed.len(), 1);
        assert_eq!(s.get("b1").unwrap().status, OutboxStatus::Failed);
    }

    #[test]
    fn boot_sweep_keeps_acked_and_in_session() {
        let mut s = OutboxStore::new();
        // ACKed (message_id Some) -> not orphaned even if old.
        s.upsert(sending("b1", 10, Some("m")));
        // Enqueued after process start -> still this session, not orphaned.
        s.upsert(sending("b2", 200, None));
        let changed = s.boot_sweep(100);
        assert!(changed.is_empty());
    }

    #[test]
    fn mark_delivered_by_message_id() {
        let mut s = OutboxStore::new();
        s.upsert(sending("b1", 1, Some("m1")));
        assert!(s.mark_delivered("m1").is_some());
        assert_eq!(s.get("b1").unwrap().status, OutboxStatus::Delivered);
        assert!(s.mark_delivered("nope").is_none());
    }

    #[test]
    fn record_send_outcome_ok_sets_sending_and_records_message_id() {
        let mut s = OutboxStore::new();
        s.upsert(sending("b1", 0, None));
        let updated = s
            .record_send_outcome("b1", Some("m1".into()), None)
            .expect("bubble present");
        assert_eq!(updated.status, OutboxStatus::Sending);
        assert_eq!(updated.message_id.as_deref(), Some("m1"));
        assert_eq!(updated.last_error, None);
    }

    #[test]
    fn record_send_outcome_err_sets_failed_with_reason() {
        let mut s = OutboxStore::new();
        s.upsert(sending("b1", 0, None));
        let updated = s
            .record_send_outcome("b1", None, Some("boom".into()))
            .expect("bubble present");
        assert_eq!(updated.status, OutboxStatus::Failed);
        assert_eq!(updated.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn record_send_outcome_never_clobbers_delivered() {
        let mut s = OutboxStore::new();
        let mut delivered = sending("b1", 0, Some("m1"));
        delivered.status = OutboxStatus::Delivered;
        s.upsert(delivered);
        // A receipt won the race during the send await; neither the Ok nor
        // the Err arm may overwrite Delivered.
        assert!(s
            .record_send_outcome("b1", Some("m1".into()), None)
            .is_none());
        assert!(s
            .record_send_outcome("b1", None, Some("boom".into()))
            .is_none());
        assert_eq!(s.get("b1").unwrap().status, OutboxStatus::Delivered);
    }

    #[test]
    fn record_send_outcome_absent_bubble_is_none() {
        let mut s = OutboxStore::new();
        assert!(s.record_send_outcome("nope", None, None).is_none());
    }
}
