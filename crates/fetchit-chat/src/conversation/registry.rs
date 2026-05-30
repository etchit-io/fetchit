//! Persistent registry of open conversations, backed by `at_rest`.

use super::types::Conversation;
use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::error::ChatError;
use crate::local_store::StoreLayout;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// In-memory registry of open conversations, persisted via `at_rest`.
pub struct ConversationRegistry {
    layout: StoreLayout,
    master: Arc<MasterKey>,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    by_group_id: Mutex<HashMap<String, Conversation>>,
}

impl ConversationRegistry {
    /// Build an empty registry. Conversations are loaded on demand.
    #[must_use]
    pub fn new(
        layout: StoreLayout,
        master: Arc<MasterKey>,
        kdf_id: u8,
        argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        Self {
            layout,
            master,
            kdf_id,
            argon_salt,
            by_group_id: Mutex::new(HashMap::new()),
        }
    }

    /// Borrow / load a conversation by `group_id_hex`.
    /// Returns None if it's not on disk and not in memory.
    ///
    /// # Errors
    /// IO, AEAD, or JSON parse errors.
    pub async fn get(&self, group_id_hex: &str) -> Result<Option<Conversation>, ChatError> {
        {
            let g = self.by_group_id.lock().await;
            if let Some(c) = g.get(group_id_hex) {
                return Ok(Some(c.clone()));
            }
        }
        let path = self.layout.conversation_path(group_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = open_from_path(&path, &self.master)?;
        let conv: Conversation = serde_json::from_slice(&bytes)
            .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
        self.by_group_id
            .lock()
            .await
            .insert(group_id_hex.to_owned(), conv.clone());
        Ok(Some(conv))
    }

    /// Find the current DM with `peer_agent_id_hex` — any conversation
    /// with exactly two members one of whom is the peer.
    ///
    /// If more than one matching conversation exists (welcome races,
    /// re-bootstraps after a wipe), the winner is chosen by a fixed
    /// tiebreak chain:
    ///
    /// 1. higher `current_epoch` — a conversation that has seen real
    ///    traffic (rekeys, membership changes) beats an empty shell
    ///    regardless of which side's clock stamped it.
    /// 2. higher `last_rekey_at_ms` — within the same epoch, the
    ///    fresher rekey wins.
    /// 3. higher `created_at_ms` — a tiebreak for sibling bootstraps.
    /// 4. lexicographically-greater `group_id_hex` — a fully
    ///    deterministic final tiebreak so the choice doesn't depend
    ///    on `HashMap` iteration or `read_dir` ordering.
    ///
    /// **Known UX gap.** Send is re-resolved by peer agent id; if the
    /// UI lets the user type into a non-winning duplicate DM the
    /// message will still route to the winner. The principled fix is
    /// a `chat_send_in_group(group_id)` API that bypasses this lookup
    /// for the explicit thread case — not a registry-level
    /// "supersede" flag, which would encode a sticky decision that
    /// breaks under future identity-rotation flows.
    ///
    /// # Errors
    /// IO or vault open failures while scanning disk.
    pub async fn find_dm_with(
        &self,
        peer_agent_id_hex: &str,
    ) -> Result<Option<Conversation>, ChatError> {
        let mut candidates: Vec<Conversation> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        {
            let g = self.by_group_id.lock().await;
            for c in g.values() {
                if dm_with(c, peer_agent_id_hex) {
                    seen.insert(c.group_id_hex.clone());
                    candidates.push(c.clone());
                }
            }
        }
        for entry in std::fs::read_dir(&self.layout.conversations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                continue;
            }
            let bytes = open_from_path(&path, &self.master)?;
            let conv: Conversation = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
            if !dm_with(&conv, peer_agent_id_hex) {
                continue;
            }
            // Hydrate every scanned-from-disk DM into the cache so
            // subsequent calls stay cheap, not just the winner.
            self.by_group_id
                .lock()
                .await
                .entry(conv.group_id_hex.clone())
                .or_insert_with(|| conv.clone());
            if seen.insert(conv.group_id_hex.clone()) {
                candidates.push(conv);
            }
        }
        Ok(pick_current_dm(candidates))
    }

    /// Snapshot the in-memory conversation cache. Returns clones so the
    /// lock is released before the caller iterates — used by the
    /// `Client` auto-rekey sweeper.
    #[must_use]
    pub(crate) async fn snapshot_cached(&self) -> Vec<Conversation> {
        let g = self.by_group_id.lock().await;
        g.values().cloned().collect()
    }

    /// Resolve the path to the stored contact card for `sender_agent_hex`.
    /// Internal helper for inbound-dispatch signature verification.
    #[must_use]
    pub(crate) fn contact_path(&self, sender_agent_hex: &str) -> std::path::PathBuf {
        self.layout.contact_path(sender_agent_hex)
    }

    /// Persist a conversation to disk and update the in-memory cache.
    ///
    /// # Errors
    /// IO, AEAD seal, or JSON serialize errors.
    pub async fn save(&self, conv: &Conversation) -> Result<(), ChatError> {
        let path = self.layout.conversation_path(&conv.group_id_hex);
        let bytes = serde_json::to_vec(conv)
            .map_err(|e| ChatError::Invalid(format!("conv serialize: {e}")))?;
        seal_to_path(
            &path,
            &bytes,
            &self.master,
            self.kdf_id,
            self.argon_salt.as_ref(),
        )?;
        self.by_group_id
            .lock()
            .await
            .insert(conv.group_id_hex.clone(), conv.clone());
        Ok(())
    }
}

fn dm_with(conv: &Conversation, peer_agent_id_hex: &str) -> bool {
    if conv.members.len() != 2 {
        return false;
    }
    conv.members
        .iter()
        .flat_map(|m| m.devices.iter())
        .any(|d| d.agent_id_hex == peer_agent_id_hex)
}

/// Apply the tiebreak chain documented on [`ConversationRegistry::find_dm_with`].
fn pick_current_dm(mut candidates: Vec<Conversation>) -> Option<Conversation> {
    candidates.sort_by(|a, b| {
        b.current_epoch
            .cmp(&a.current_epoch)
            .then_with(|| b.last_rekey_at_ms.cmp(&a.last_rekey_at_ms))
            .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
            .then_with(|| b.group_id_hex.cmp(&a.group_id_hex))
    });
    candidates.into_iter().next()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKeySource};
    use crate::conversation::types::{
        Conversation, Member, MemberDevice, MemberDeviceStatus, Role, TrustState,
        DEFAULT_AUTO_REKEY_INTERVAL_MS,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use tempfile::tempdir;

    fn dm(
        group_id_hex: &str,
        local_id: &str,
        peer_id: &str,
        current_epoch: u32,
        last_rekey_at_ms: u64,
        created_at_ms: u64,
    ) -> Conversation {
        let device = |aid: &str| MemberDevice {
            agent_id_hex: aid.to_owned(),
            kem_public_key_b64: B64.encode([0u8; 32]),
            agent_public_key_b64: None,
            added_at_epoch: 0,
            status: MemberDeviceStatus::Active,
        };
        let member = |aid: &str| Member {
            user_id_hex: None,
            devices: vec![device(aid)],
            joined_at_epoch: 0,
        };
        Conversation {
            group_id_hex: group_id_hex.to_owned(),
            name: None,
            members: vec![member(local_id), member(peer_id)],
            current_epoch,
            current_key_b64: B64.encode([0u8; 32]),
            prior_keys: Vec::new(),
            own_role: Role::Admin,
            created_at_ms,
            last_rekey_at_ms,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Confirmed,
        }
    }

    fn fresh_registry() -> (tempfile::TempDir, ConversationRegistry) {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap(),
        );
        let reg = ConversationRegistry::new(layout, master, kdf_id_argon2(), Some(salt));
        (dir, reg)
    }

    const LOCAL: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
    const PEER: &str = "00000000000000000000000000000000000000000000000000000000000000bb";

    #[tokio::test]
    async fn no_dm_returns_none() {
        let (_d, reg) = fresh_registry();
        assert!(reg.find_dm_with(PEER).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn single_dm_returns_it() {
        let (_d, reg) = fresh_registry();
        let c = dm("aa", LOCAL, PEER, 0, 0, 100);
        reg.save(&c).await.unwrap();
        assert_eq!(
            reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex,
            "aa"
        );
    }

    #[tokio::test]
    async fn higher_current_epoch_wins() {
        let (_d, reg) = fresh_registry();
        // Older creation, lower last_rekey — but a real-traffic epoch wins all of that.
        reg.save(&dm("aa", LOCAL, PEER, 0, 9_999, 9_999))
            .await
            .unwrap();
        reg.save(&dm("bb", LOCAL, PEER, 5, 100, 100)).await.unwrap();
        assert_eq!(
            reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex,
            "bb"
        );
    }

    #[tokio::test]
    async fn equal_epoch_higher_last_rekey_wins() {
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 3, 200, 999)).await.unwrap();
        reg.save(&dm("bb", LOCAL, PEER, 3, 800, 100)).await.unwrap();
        assert_eq!(
            reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex,
            "bb"
        );
    }

    #[tokio::test]
    async fn equal_epoch_and_rekey_higher_created_at_wins() {
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 0, 500, 100)).await.unwrap();
        reg.save(&dm("bb", LOCAL, PEER, 0, 500, 900)).await.unwrap();
        assert_eq!(
            reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex,
            "bb"
        );
    }

    #[tokio::test]
    async fn everything_equal_falls_back_to_group_id_lex() {
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        reg.save(&dm("bb", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        assert_eq!(
            reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex,
            "bb"
        );
    }

    #[tokio::test]
    async fn cold_disk_state_picks_the_same_winner() {
        // Same data as `higher_current_epoch_wins`, but the lookup runs
        // against a brand-new registry whose in-memory cache is empty —
        // forcing the read_dir code path. Should return the same answer.
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap(),
        );
        let r1 =
            ConversationRegistry::new(layout.clone(), master.clone(), kdf_id_argon2(), Some(salt));
        r1.save(&dm("aa", LOCAL, PEER, 0, 9_999, 9_999))
            .await
            .unwrap();
        r1.save(&dm("bb", LOCAL, PEER, 5, 100, 100)).await.unwrap();
        let r2 = ConversationRegistry::new(layout, master, kdf_id_argon2(), Some(salt));
        assert_eq!(
            r2.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex,
            "bb"
        );
    }

    #[tokio::test]
    async fn duplicate_dm_lookup_is_deterministic_across_runs() {
        // Save the duplicates once, then run find_dm_with many times
        // and assert the chosen group_id is identical every iteration.
        // Catches HashMap-iteration-order leakage into the result.
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        reg.save(&dm("bb", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        reg.save(&dm("cc", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        let first = reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex;
        for _ in 0..50 {
            let next = reg.find_dm_with(PEER).await.unwrap().unwrap().group_id_hex;
            assert_eq!(next, first);
        }
    }
}
