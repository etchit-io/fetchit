//! Vault-persisted store of outbound DM bubbles.
//!
//! Mirrors `crate::groups_reachability::BridgeConsentStore`: the bubble
//! map is sealed at rest under the chat master key via
//! [`crate::at_rest::seal_to_path`], `load` is fail-safe to empty on any
//! read failure, and `flush` is best-effort (a write failure is logged and
//! swallowed; the in-memory state is authoritative). An in-memory
//! `inflight` guard prevents the retry driver from re-firing a bubble whose
//! send is already in progress.

use super::OutboxBubble;
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
        assert!(OutboxStore::load(&layout, &wrong, 0, None).snapshot().is_empty());
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
}
