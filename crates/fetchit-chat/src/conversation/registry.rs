//! Persistent registry of open conversations, backed by `at_rest`.

use super::types::Conversation;
use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::error::ChatError;
use crate::identity::AgentId;
use crate::local_store::StoreLayout;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::Mutex;

/// Decision returned by the closure handed to
/// [`ConversationRegistry::mutate_in_place`]: whether to persist the
/// (possibly-empty) mutation to disk, along with the value to return.
///
/// `Skip` causes the registry to **restore the cached entry from a
/// pre-mutation snapshot** before returning — that way callers that
/// branch midway through and decide not to commit can leave the
/// cached state byte-for-byte consistent with disk regardless of
/// any partial mutation they performed.
pub enum MutateAction<T> {
    /// Persist the mutated conversation to disk under the same
    /// `by_group_id` lock that `record_nonce` uses. Returns `T` to
    /// the caller.
    Persist(T),
    /// Do not persist. The registry restores the cached conversation
    /// from its pre-mutation snapshot. Returns `T` to the caller.
    Skip(T),
}

/// Outcome of [`ConversationRegistry::record_nonce`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceCheckOutcome {
    /// `(sender, nonce)` was fresh; the registry recorded it in the
    /// sliding window and persisted the mutation under its mutex.
    Recorded,
    /// `(sender, nonce)` was already present in the sender's sliding
    /// window. The caller MUST drop the envelope without further
    /// processing — both the persisted window and the on-disk record
    /// stay exactly as they were.
    Replay,
}

/// In-memory registry of open conversations, persisted via `at_rest`.
pub struct ConversationRegistry {
    layout: StoreLayout,
    master: Arc<MasterKey>,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    by_group_id: Mutex<HashMap<String, Conversation>>,
    /// Sync-accessible mirror of every peer member device's ML-DSA-65
    /// public key, indexed by `agent_id`. Populated by [`Self::save`]
    /// and on every hydrate-from-disk path. Read by
    /// [`crate::lan_direct_transport::LanDirectTransport`] from a sync
    /// `reachability()` callback that can't await on the tokio mutex
    /// holding the conversation cache.
    peer_pubkeys: StdRwLock<HashMap<AgentId, Vec<u8>>>,
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
            peer_pubkeys: StdRwLock::new(HashMap::new()),
        }
    }

    /// Synchronous lookup of a peer's ML-DSA-65 public key (raw bytes,
    /// decoded from the on-card base64). Returns `None` for unknown
    /// peers or for peers whose member device records have no
    /// `agent_public_key_b64` (legacy v1 cards).
    ///
    /// Wired through [`crate::lan_direct_transport::ContactPubkeyLookup`]
    /// at client-build time so the LAN-direct transport's reachability
    /// gate can run without awaiting on the tokio mutex.
    #[must_use]
    pub fn peer_ml_dsa_pubkey(&self, agent_id: &AgentId) -> Option<Vec<u8>> {
        self.peer_pubkeys
            .read()
            .ok()
            .and_then(|g| g.get(agent_id).cloned())
    }

    /// Walk every member device on `conv` and update the sync pubkey
    /// cache. Called whenever a conversation is saved or hydrated.
    fn refresh_pubkey_cache(&self, conv: &Conversation) {
        let Ok(mut g) = self.peer_pubkeys.write() else {
            return;
        };
        for member in &conv.members {
            for device in &member.devices {
                let Some(pk_b64) = device.agent_public_key_b64.as_deref() else {
                    continue;
                };
                let Ok(pk) = B64.decode(pk_b64) else { continue };
                let Ok(aid) = AgentId::parse(device.agent_id_hex.clone()) else {
                    continue;
                };
                g.insert(aid, pk);
            }
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
        self.refresh_pubkey_cache(&conv);
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
            // Refresh the sync pubkey cache for every DM we scan,
            // not just the winner — peers we know how to talk to
            // should all be LAN-eligible.
            self.refresh_pubkey_cache(&conv);
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
        self.refresh_pubkey_cache(conv);
        self.by_group_id
            .lock()
            .await
            .insert(conv.group_id_hex.clone(), conv.clone());
        Ok(())
    }

    /// Run a closure against the cached `Conversation` for
    /// `group_id_hex` while holding the [`Self::by_group_id`] mutex,
    /// then optionally persist the result to disk.
    ///
    /// This is the right entry point for any caller that does
    /// `registry.get → mutate the clone → registry.save` against an
    /// existing group, because the old shape leaks every concurrently
    /// recorded change to `seen_nonces` (and any other field) — the
    /// save replaces the cache entry wholesale with the caller's stale
    /// clone, undoing whatever a parallel [`Self::record_nonce`] just
    /// committed. The atomic `mutate_in_place` keeps the cache, the
    /// disk image, and the persisted `seen_nonces` consistent because
    /// the lock is held across the whole RMW.
    ///
    /// The closure returns a [`MutateAction`] that tells the registry
    /// whether to persist or skip. On `Skip` the cached entry is
    /// restored from a pre-mutation snapshot so callers that decided
    /// midway not to commit still leave the cache byte-equal to disk.
    ///
    /// Callers that may legitimately operate on a not-yet-installed
    /// `group_id` (e.g. receive paths racing the first envelope into
    /// a freshly-joined private group) MUST use
    /// [`Self::mutate_in_place_or_init`] instead, which bootstraps an
    /// empty shell UNDER the per-group mutex so two concurrent
    /// receives can't both race past `get → None → save(empty)` and
    /// clobber each other's recorded state.
    ///
    /// # Errors
    /// `ChatError::Invalid` when the group is not on disk or the
    /// cache invariant has been violated; IO / AEAD / JSON errors
    /// from hydrate-or-persist.
    pub async fn mutate_in_place<F, T>(&self, group_id_hex: &str, mutate: F) -> Result<T, ChatError>
    where
        F: FnOnce(&mut Conversation) -> MutateAction<T>,
    {
        self.mutate_in_place_impl::<F, fn() -> Conversation, T>(group_id_hex, None, mutate)
            .await
    }

    /// Variant of [`Self::mutate_in_place`] that bootstraps a fresh
    /// `Conversation` via `init_if_missing` when the group is absent
    /// from BOTH the in-memory cache and disk, all under the
    /// per-group mutex.
    ///
    /// This closes the lazy-create TOCTOU on receive paths: two
    /// concurrent inbound envelopes for a brand-new group both
    /// arrive, the FIRST observes "no cache, no disk" and runs the
    /// bootstrap + the mutation; the SECOND blocks on the mutex,
    /// then observes the cache entry the first installed and skips
    /// the bootstrap. Without this, the old shape —
    /// `if get().is_none() { save(empty_shell) }` followed by a
    /// separate `mutate_in_place` — let both races call
    /// `save(empty_shell)`, with the second wiping the first's
    /// recorded nonce + history.
    ///
    /// On the bootstrap path the pre-mutation snapshot is the
    /// freshly-built shell, so a `Skip` after bootstrap leaves the
    /// shell in cache (matching the existing semantics of a
    /// hydrate-then-skip on an on-disk conversation). On a `Persist`
    /// seal failure the cache restores to the bootstrapped shell —
    /// the in-flight mutation rolls back the same way the on-disk
    /// path does.
    ///
    /// # Errors
    /// Same shape as [`Self::mutate_in_place`]; `init_if_missing` is
    /// purely a bootstrap shim and surfaces no errors of its own.
    pub async fn mutate_in_place_or_init<F, Init, T>(
        &self,
        group_id_hex: &str,
        init_if_missing: Init,
        mutate: F,
    ) -> Result<T, ChatError>
    where
        F: FnOnce(&mut Conversation) -> MutateAction<T>,
        Init: FnOnce() -> Conversation,
    {
        self.mutate_in_place_impl::<F, Init, T>(group_id_hex, Some(init_if_missing), mutate)
            .await
    }

    async fn mutate_in_place_impl<F, Init, T>(
        &self,
        group_id_hex: &str,
        init_if_missing: Option<Init>,
        mutate: F,
    ) -> Result<T, ChatError>
    where
        F: FnOnce(&mut Conversation) -> MutateAction<T>,
        Init: FnOnce() -> Conversation,
    {
        let mut guard = self.by_group_id.lock().await;

        if !guard.contains_key(group_id_hex) {
            let path = self.layout.conversation_path(group_id_hex);
            if path.exists() {
                let bytes = open_from_path(&path, &self.master)?;
                let conv: Conversation = serde_json::from_slice(&bytes)
                    .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
                self.refresh_pubkey_cache(&conv);
                guard.insert(group_id_hex.to_owned(), conv);
            } else if let Some(init) = init_if_missing {
                // Lazy bootstrap under the lock — two concurrent
                // receive paths racing on the same brand-new group_id
                // both see this branch fire exactly once (the second
                // observes the freshly-inserted entry on its retry of
                // the contains_key check above).
                let conv = init();
                self.refresh_pubkey_cache(&conv);
                guard.insert(group_id_hex.to_owned(), conv);
            } else {
                return Err(ChatError::Invalid(format!(
                    "mutate_in_place: no conversation for group_id {group_id_hex}"
                )));
            }
        }

        // Snapshot for the restore paths — Skip always restores; the
        // Persist arm restores on a serialize / seal failure so the
        // in-cache conv doesn't drift ahead of disk. Cheap relative
        // to the disk seal that's the alternative.
        let snapshot = guard.get(group_id_hex).cloned();
        let Some(conv) = guard.get_mut(group_id_hex) else {
            return Err(ChatError::Invalid(format!(
                "mutate_in_place: cache miss after hydrate for {group_id_hex}"
            )));
        };

        match mutate(conv) {
            MutateAction::Persist(value) => {
                // Persist the closure's mutation. Run serialize + seal
                // inside a fallible block so a failure on either step
                // restores the pre-mutation snapshot before propagating
                // the error — otherwise the in-cache conv would carry
                // the mutation while disk still has the pre-mutation
                // state, and the next observation by record_nonce /
                // mutate_in_place / save would write that drift forward
                // (the same forward-decrypt-loss class
                // sweep_auto_rekey's build-before-commit defends
                // against, just gated on a write failure instead of a
                // build failure).
                let path = self.layout.conversation_path(group_id_hex);
                let persist = (|| -> Result<(), ChatError> {
                    let bytes = serde_json::to_vec(conv)
                        .map_err(|e| ChatError::Invalid(format!("conv serialize: {e}")))?;
                    seal_to_path(
                        &path,
                        &bytes,
                        &self.master,
                        self.kdf_id,
                        self.argon_salt.as_ref(),
                    )?;
                    Ok(())
                })();
                match persist {
                    Ok(()) => {
                        self.refresh_pubkey_cache(conv);
                        Ok(value)
                    }
                    Err(e) => {
                        if let Some(s) = snapshot {
                            *conv = s;
                        }
                        Err(e)
                    }
                }
            }
            MutateAction::Skip(value) => {
                // Restore the cached entry so cache == disk regardless
                // of any partial mutation the closure performed before
                // deciding to skip.
                if let Some(s) = snapshot {
                    *conv = s;
                }
                Ok(value)
            }
        }
    }

    /// Atomically check `(sender, nonce)` against the conversation's
    /// replay window and record it if fresh. The whole read-modify-write
    /// runs under [`Self::by_group_id`], so concurrent inbound pumps on
    /// the same group serialise rather than both observing an empty
    /// window before either persists — closing the relay/LAN dual-pump
    /// TOCTOU that the conversation-level
    /// [`crate::conversation::types::Conversation::check_and_record_nonce`]
    /// can't defend against on its own (each caller mutates a clone).
    ///
    /// This is the only entry point inbound dispatch should use to
    /// touch `seen_nonces`; the per-conversation primitive remains
    /// available for unit tests of the sliding-window mechanics.
    ///
    /// # Errors
    /// Returns [`ChatError::Invalid`] when no conversation exists for
    /// `group_id_hex` (programmer-bug case — the inbound dispatch
    /// looks the conversation up before calling this, so a missing
    /// group means stale orchestration rather than a real envelope).
    ///
    /// Surfaces vault open / AEAD seal / JSON parse errors from the
    /// hydrate-or-persist path.
    pub async fn record_nonce(
        &self,
        group_id_hex: &str,
        sender_agent_hex: &str,
        nonce: [u8; 12],
    ) -> Result<NonceCheckOutcome, ChatError> {
        let mut guard = self.by_group_id.lock().await;

        // Hydrate into the cache under the lock so a concurrent caller
        // never observes a stale clone of `seen_nonces`.
        if !guard.contains_key(group_id_hex) {
            let path = self.layout.conversation_path(group_id_hex);
            if !path.exists() {
                return Err(ChatError::Invalid(format!(
                    "record_nonce: no conversation for group_id {group_id_hex}"
                )));
            }
            let bytes = open_from_path(&path, &self.master)?;
            let conv: Conversation = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
            self.refresh_pubkey_cache(&conv);
            guard.insert(group_id_hex.to_owned(), conv);
        }

        // Snapshot for the persist-failure restore — symmetric with
        // mutate_in_place's Persist arm. If seal_to_path fails after
        // we recorded the nonce in the cache, restore from snapshot
        // so the next observation doesn't see a drifted window that
        // disk doesn't have. Same forward-decrypt-loss class round-5
        // closed for mutate_in_place.
        let snapshot = guard.get(group_id_hex).cloned();
        let Some(conv) = guard.get_mut(group_id_hex) else {
            // Defensive: hydrate above should have inserted this key.
            // If we got here without it, the cache invariant has been
            // violated.
            return Err(ChatError::Invalid(format!(
                "record_nonce: cache miss after hydrate for {group_id_hex}"
            )));
        };

        if conv.check_and_record_nonce(sender_agent_hex, nonce) {
            return Ok(NonceCheckOutcome::Replay);
        }

        // Persist while still holding the lock — a concurrent
        // record_nonce on this group blocks on `guard` and observes
        // our updated window on its retry.
        let path = self.layout.conversation_path(group_id_hex);
        let persist = (|| -> Result<(), ChatError> {
            let bytes = serde_json::to_vec(conv)
                .map_err(|e| ChatError::Invalid(format!("conv serialize: {e}")))?;
            seal_to_path(
                &path,
                &bytes,
                &self.master,
                self.kdf_id,
                self.argon_salt.as_ref(),
            )?;
            Ok(())
        })();
        match persist {
            Ok(()) => Ok(NonceCheckOutcome::Recorded),
            Err(e) => {
                if let Some(s) = snapshot {
                    *conv = s;
                }
                Err(e)
            }
        }
    }

    /// Mark a sent message as delivered in this conversation's history
    /// (a delivery receipt echoed its `message_id`). Returns `Ok(true)`
    /// when an entry was newly marked and persisted, `Ok(false)` when
    /// nothing matched — the entry aged past `HISTORY_CAP`, the id is
    /// unknown, or the receipt is a duplicate — which skips the disk
    /// write entirely.
    ///
    /// # Errors
    /// Returns [`ChatError::Invalid`] when no conversation exists for
    /// `group_id_hex` (inbound dispatch resolves the conversation
    /// before a receipt can decrypt, so a miss is stale orchestration).
    /// Surfaces vault open / AEAD seal / JSON parse errors from the
    /// hydrate-or-persist path; on persist failure the cached
    /// conversation is restored from a snapshot, symmetric with
    /// [`Self::record_nonce`].
    pub async fn record_delivery(
        &self,
        group_id_hex: &str,
        message_id: &str,
        received_at_ms: u64,
    ) -> Result<bool, ChatError> {
        let mut guard = self.by_group_id.lock().await;

        if !guard.contains_key(group_id_hex) {
            let path = self.layout.conversation_path(group_id_hex);
            if !path.exists() {
                return Err(ChatError::Invalid(format!(
                    "record_delivery: no conversation for group_id {group_id_hex}"
                )));
            }
            let bytes = open_from_path(&path, &self.master)?;
            let conv: Conversation = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("conv parse: {e}")))?;
            self.refresh_pubkey_cache(&conv);
            guard.insert(group_id_hex.to_owned(), conv);
        }

        let snapshot = guard.get(group_id_hex).cloned();
        let Some(conv) = guard.get_mut(group_id_hex) else {
            return Err(ChatError::Invalid(format!(
                "record_delivery: cache miss after hydrate for {group_id_hex}"
            )));
        };

        if !conv.apply_delivery_receipt(message_id, received_at_ms) {
            return Ok(false);
        }

        let path = self.layout.conversation_path(group_id_hex);
        let persist = (|| -> Result<(), ChatError> {
            let bytes = serde_json::to_vec(conv)
                .map_err(|e| ChatError::Invalid(format!("conv serialize: {e}")))?;
            seal_to_path(
                &path,
                &bytes,
                &self.master,
                self.kdf_id,
                self.argon_salt.as_ref(),
            )?;
            Ok(())
        })();
        match persist {
            Ok(()) => Ok(true),
            Err(e) => {
                if let Some(s) = snapshot {
                    *conv = s;
                }
                Err(e)
            }
        }
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
    use tempfile::tempdir;
    use zeroize::Zeroizing;

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
            seen_nonces: std::collections::BTreeMap::new(),
            history: std::collections::VecDeque::new(),
        }
    }

    fn fresh_registry() -> (tempfile::TempDir, ConversationRegistry) {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
                Some(&salt),
            )
            .unwrap(),
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
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
                Some(&salt),
            )
            .unwrap(),
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

    fn dm_with_pubkey(
        group_id_hex: &str,
        local_id: &str,
        peer_id: &str,
        peer_pubkey: &[u8],
    ) -> Conversation {
        let device = |aid: &str, pk: Option<&[u8]>| MemberDevice {
            agent_id_hex: aid.to_owned(),
            kem_public_key_b64: B64.encode([0u8; 32]),
            agent_public_key_b64: pk.map(|p| B64.encode(p)),
            added_at_epoch: 0,
            status: MemberDeviceStatus::Active,
        };
        let local_member = Member {
            user_id_hex: None,
            devices: vec![device(local_id, None)],
            joined_at_epoch: 0,
        };
        let peer_member = Member {
            user_id_hex: None,
            devices: vec![device(peer_id, Some(peer_pubkey))],
            joined_at_epoch: 0,
        };
        Conversation {
            group_id_hex: group_id_hex.to_owned(),
            name: None,
            members: vec![local_member, peer_member],
            current_epoch: 0,
            current_key_b64: B64.encode([0u8; 32]),
            prior_keys: Vec::new(),
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
            trust_state: TrustState::Confirmed,
            seen_nonces: std::collections::BTreeMap::new(),
            history: std::collections::VecDeque::new(),
        }
    }

    #[tokio::test]
    async fn peer_pubkey_lookup_populates_on_save() {
        let (_d, reg) = fresh_registry();
        let pk = vec![0xcd; 64];
        reg.save(&dm_with_pubkey("aa", LOCAL, PEER, &pk))
            .await
            .unwrap();
        let aid = AgentId::parse(PEER.to_owned()).unwrap();
        assert_eq!(reg.peer_ml_dsa_pubkey(&aid), Some(pk));
    }

    #[tokio::test]
    async fn peer_pubkey_lookup_populates_on_cold_disk_hydrate() {
        // Save under r1, then construct r2 against the same layout and
        // confirm find_dm_with hydration fills the sync cache.
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
                Some(&salt),
            )
            .unwrap(),
        );
        let r1 =
            ConversationRegistry::new(layout.clone(), master.clone(), kdf_id_argon2(), Some(salt));
        let pk = vec![0xef; 64];
        r1.save(&dm_with_pubkey("aa", LOCAL, PEER, &pk))
            .await
            .unwrap();

        let r2 = ConversationRegistry::new(layout, master, kdf_id_argon2(), Some(salt));
        let aid = AgentId::parse(PEER.to_owned()).unwrap();
        assert!(
            r2.peer_ml_dsa_pubkey(&aid).is_none(),
            "cold cache before lookup"
        );
        let _ = r2.find_dm_with(PEER).await.unwrap();
        assert_eq!(r2.peer_ml_dsa_pubkey(&aid), Some(pk));
    }

    #[tokio::test]
    async fn peer_pubkey_lookup_returns_none_for_unknown_agent() {
        let (_d, reg) = fresh_registry();
        let aid = AgentId::parse(PEER.to_owned()).unwrap();
        assert!(reg.peer_ml_dsa_pubkey(&aid).is_none());
    }

    #[tokio::test]
    async fn peer_pubkey_lookup_skips_devices_without_pubkey() {
        // Legacy device records lacking agent_public_key_b64 must not
        // pollute the cache with empty entries — keeps reachability
        // honest about which peers we can verify.
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        let aid = AgentId::parse(PEER.to_owned()).unwrap();
        assert!(reg.peer_ml_dsa_pubkey(&aid).is_none());
    }

    #[tokio::test]
    async fn record_nonce_first_call_is_recorded_second_is_replay() {
        let (_d, reg) = fresh_registry();
        let conv = dm("aa", LOCAL, PEER, 0, 0, 0);
        reg.save(&conv).await.unwrap();
        let nonce = [0xAB; 12];
        assert_eq!(
            reg.record_nonce("aa", PEER, nonce).await.unwrap(),
            NonceCheckOutcome::Recorded,
        );
        assert_eq!(
            reg.record_nonce("aa", PEER, nonce).await.unwrap(),
            NonceCheckOutcome::Replay,
        );
        // Same nonce, different sender — independent window.
        assert_eq!(
            reg.record_nonce("aa", LOCAL, nonce).await.unwrap(),
            NonceCheckOutcome::Recorded,
        );
    }

    #[tokio::test]
    async fn record_nonce_errors_on_unknown_group() {
        let (_d, reg) = fresh_registry();
        let err = reg.record_nonce("aa", PEER, [0; 12]).await;
        assert!(
            err.is_err(),
            "expected Invalid error for unknown group, got {err:?}",
        );
    }

    #[tokio::test]
    async fn record_nonce_persists_across_cold_restart() {
        // A recorded nonce on registry r1 must still be flagged as
        // replay when r2 reopens the same on-disk store. Catches a
        // regression where the in-memory cache update fires but the
        // disk seal doesn't.
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
                Some(&salt),
            )
            .unwrap(),
        );
        let r1 =
            ConversationRegistry::new(layout.clone(), master.clone(), kdf_id_argon2(), Some(salt));
        r1.save(&dm("aa", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        let nonce = [0xCD; 12];
        assert_eq!(
            r1.record_nonce("aa", PEER, nonce).await.unwrap(),
            NonceCheckOutcome::Recorded,
        );
        let r2 = ConversationRegistry::new(layout, master, kdf_id_argon2(), Some(salt));
        assert_eq!(
            r2.record_nonce("aa", PEER, nonce).await.unwrap(),
            NonceCheckOutcome::Replay,
            "nonce window must survive a cold restart",
        );
    }

    fn dm_with_history_entry(message_id: &str) -> Conversation {
        let mut c = dm("aa", LOCAL, PEER, 0, 0, 0);
        c.push_history(crate::conversation::HistoryEntry {
            sender_agent_id_hex: LOCAL.to_owned(),
            sender_name: None,
            body: "out".into(),
            ts_ms: 1,
            message_id: message_id.to_owned(),
            attachment: None,
            delivered_at_ms: None,
        });
        c
    }

    #[tokio::test]
    async fn record_delivery_marks_and_persists_across_cold_restart() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
                Some(&salt),
            )
            .unwrap(),
        );
        let r1 =
            ConversationRegistry::new(layout.clone(), master.clone(), kdf_id_argon2(), Some(salt));
        r1.save(&dm_with_history_entry("m1")).await.unwrap();
        assert!(r1.record_delivery("aa", "m1", 123).await.unwrap());

        // Cold restart: the delivered mark must come back from disk.
        let r2 = ConversationRegistry::new(layout, master, kdf_id_argon2(), Some(salt));
        let conv = r2.get("aa").await.unwrap().unwrap();
        let entry = conv
            .history
            .iter()
            .find(|e| e.message_id == "m1")
            .expect("entry survives reload");
        assert_eq!(entry.delivered_at_ms, Some(123));
    }

    #[tokio::test]
    async fn record_delivery_duplicate_and_unknown_id_are_false_noops() {
        let (_d, reg) = fresh_registry();
        reg.save(&dm_with_history_entry("m1")).await.unwrap();
        assert!(reg.record_delivery("aa", "m1", 100).await.unwrap());
        // Duplicate receipt: no-op, first timestamp kept.
        assert!(!reg.record_delivery("aa", "m1", 999).await.unwrap());
        // Receipt for an id this side never recorded: no-op, no error.
        assert!(!reg.record_delivery("aa", "zz", 100).await.unwrap());
        let conv = reg.get("aa").await.unwrap().unwrap();
        assert_eq!(conv.history[0].delivered_at_ms, Some(100));
    }

    #[tokio::test]
    async fn record_delivery_errors_on_unknown_group() {
        let (_d, reg) = fresh_registry();
        let err = reg.record_delivery("ff", "m1", 1).await.unwrap_err();
        assert!(err.to_string().contains("no conversation"), "got {err}");
    }

    #[tokio::test]
    async fn rekey_via_mutate_in_place_preserves_recorded_nonces() {
        // The save()-clone-roundtrip clobber the old install_or_rekey
        // path was vulnerable to: record_nonce records nonce N, then
        // a "rekey via get → mutate clone → save" round-trip would
        // overwrite the cache with the pre-record_nonce clone, leaving
        // N missing and a replay-able. mutate_in_place running the
        // entire RMW under the lock closes that — a re-record of the
        // same nonce must still surface as Replay.
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        let nonce = [0xDE; 12];
        assert_eq!(
            reg.record_nonce("aa", PEER, nonce).await.unwrap(),
            NonceCheckOutcome::Recorded,
        );
        // Simulate a rekey-style RMW that previously would have used
        // `let mut c = registry.get(...); c.current_epoch += 1; save(&c)`.
        reg.mutate_in_place("aa", |conv| {
            conv.current_epoch = conv.current_epoch.saturating_add(1);
            MutateAction::Persist(())
        })
        .await
        .unwrap();
        // The same nonce MUST still register as a replay; if save() had
        // overwritten the cache with a pre-record_nonce clone the
        // recorded N would be gone and we'd see Recorded here.
        assert_eq!(
            reg.record_nonce("aa", PEER, nonce).await.unwrap(),
            NonceCheckOutcome::Replay,
            "concurrent rekey-style RMW must not clobber recorded seen_nonces",
        );
    }

    #[tokio::test]
    async fn mutate_in_place_skip_restores_pre_mutation_state() {
        // A closure that mutates fields then decides Skip must not
        // leak the partial mutation into the cache — the registry
        // snapshots before calling the closure and restores on Skip.
        let (_d, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 7, 100, 100)).await.unwrap();
        reg.mutate_in_place("aa", |conv| {
            // Partial mutation, then change our mind:
            conv.current_epoch = 999;
            conv.last_rekey_at_ms = 8_888_888;
            MutateAction::Skip(())
        })
        .await
        .unwrap();
        // Cache must read back the pre-mutation values.
        let after = reg.get("aa").await.unwrap().unwrap();
        assert_eq!(after.current_epoch, 7);
        assert_eq!(after.last_rekey_at_ms, 100);
    }

    #[tokio::test]
    async fn mutate_in_place_restores_cache_on_persist_failure() {
        // Round-5 P2 regression: if seal_to_path fails after the
        // closure mutated the cached conv, the cache must be restored
        // from the pre-mutation snapshot. Without the restore the
        // cache drifts ahead of disk and any subsequent observation
        // (record_nonce / next save) writes the drift through — the
        // same forward-decrypt-loss class round-4 was supposed to
        // eliminate.
        let (dir, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 7, 100, 100)).await.unwrap();

        // Replace the conversations dir with a regular file so
        // seal_to_path's `create_dir_all(parent)` cannot proceed —
        // forcing the write path to surface an IO error.
        let conv_dir = dir.path().join("conversations");
        std::fs::remove_dir_all(&conv_dir).unwrap();
        std::fs::write(&conv_dir, b"blocker").unwrap();

        let result = reg
            .mutate_in_place("aa", |conv| {
                conv.current_epoch = 999;
                conv.last_rekey_at_ms = 8_888_888;
                MutateAction::Persist(())
            })
            .await;
        assert!(
            result.is_err(),
            "expected Err on missing conversations dir, got Ok",
        );

        // Remove the file blocker + restore the dir for clean TempDir
        // teardown.
        std::fs::remove_file(&conv_dir).unwrap();
        std::fs::create_dir_all(&conv_dir).unwrap();

        // The in-cache entry MUST read back the pre-mutation state.
        // (We call `get` which returns the cached clone — the disk
        // file is gone but the cache should be the un-mutated copy
        // that the Persist arm restored on the seal failure.)
        let after = reg.get("aa").await.unwrap().unwrap();
        assert_eq!(
            after.current_epoch, 7,
            "cache must NOT carry mutated current_epoch on persist failure",
        );
        assert_eq!(
            after.last_rekey_at_ms, 100,
            "cache must NOT carry mutated last_rekey_at_ms on persist failure",
        );
    }

    #[tokio::test]
    async fn record_nonce_restores_cache_on_persist_failure() {
        // Round-6 P2: symmetric with the mutate_in_place fix. If
        // seal_to_path fails after we recorded the nonce in cache,
        // the snapshot restore reverts seen_nonces so a subsequent
        // re-delivery of the same envelope can be re-attempted (and
        // disk is consistent with cache).
        let (dir, reg) = fresh_registry();
        reg.save(&dm("aa", LOCAL, PEER, 0, 0, 0)).await.unwrap();
        let nonce = [0xEF; 12];

        // Block writes by replacing the conversations dir with a file.
        let conv_dir = dir.path().join("conversations");
        std::fs::remove_dir_all(&conv_dir).unwrap();
        std::fs::write(&conv_dir, b"blocker").unwrap();

        let result = reg.record_nonce("aa", PEER, nonce).await;
        assert!(
            result.is_err(),
            "expected Err on missing dir, got {result:?}"
        );

        // Restore dir for TempDir cleanup.
        std::fs::remove_file(&conv_dir).unwrap();
        std::fs::create_dir_all(&conv_dir).unwrap();

        // Cache MUST read back the pre-record state — the nonce must
        // NOT be in seen_nonces, so a retry of the same envelope can
        // succeed once disk is back.
        let after = reg.get("aa").await.unwrap().unwrap();
        assert!(
            after
                .seen_nonces
                .get(PEER)
                .is_none_or(|w| !w.contains(&nonce)),
            "cache must NOT carry the recorded nonce after persist failure",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn record_nonce_serialises_concurrent_calls_on_same_group() {
        // Two concurrent record_nonce calls on the same (group, sender,
        // nonce) — the OLD code, where dispatch_message did its own
        // registry.get → check_and_record → save round-trip on a clone,
        // could let both observe an empty window and both surface the
        // message. The atomic record_nonce closes that race: exactly
        // one survives as Recorded, the other sees Replay.
        //
        // multi_thread runtime so the two spawn'd tasks can actually
        // race on separate worker threads; on the default single-thread
        // tokio runtime they would be cooperatively scheduled and the
        // 32-round retry loop below would never exercise the contended
        // path it claims to defend.
        let (_d, reg) = fresh_registry();
        let conv = dm("aa", LOCAL, PEER, 0, 0, 0);
        reg.save(&conv).await.unwrap();
        let reg = Arc::new(reg);

        // Run the race many times so a thread-scheduling lucky path
        // can't accidentally pass.
        for round in 0..32u8 {
            let nonce = [round; 12];
            let r1 = reg.clone();
            let r2 = reg.clone();
            let h1 = tokio::spawn(async move { r1.record_nonce("aa", PEER, nonce).await });
            let h2 = tokio::spawn(async move { r2.record_nonce("aa", PEER, nonce).await });
            let o1 = h1.await.unwrap().unwrap();
            let o2 = h2.await.unwrap().unwrap();
            let mut sorted = [o1, o2];
            sorted.sort_by_key(|o| matches!(o, NonceCheckOutcome::Replay));
            assert_eq!(
                sorted[0],
                NonceCheckOutcome::Recorded,
                "round {round}: exactly one call must record",
            );
            assert_eq!(
                sorted[1],
                NonceCheckOutcome::Replay,
                "round {round}: the loser must surface Replay",
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mutate_in_place_or_init_atomic_under_concurrent_first_touch() {
        // P0 round-7: receive_private_group_envelope's lazy-create
        // step used to be `if get().is_none() { save(empty) }` outside
        // the mutate_in_place lock. Two concurrent receives on the
        // same brand-new group_id could both observe `None`, both
        // save(empty) — the second wiping the first's recorded state.
        //
        // `mutate_in_place_or_init` closes that by running the
        // bootstrap UNDER the per-group mutex. Test: spawn N=8
        // tokio tasks, each appending one distinct entry to a
        // shared brand-new group via `mutate_in_place_or_init`. The
        // first task whose init fires installs the shell; every
        // other task observes the cache entry and skips init.
        // Post-condition: exactly N history entries land in the
        // registry.
        const N: usize = 8;
        let (_d, reg) = fresh_registry();
        let reg = Arc::new(reg);
        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let group = "aa";
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let reg = reg.clone();
            let barrier = barrier.clone();
            let entry = crate::conversation::HistoryEntry {
                sender_agent_id_hex: format!("{i:064x}"),
                sender_name: None,
                body: format!("body-{i}"),
                ts_ms: u64::try_from(i + 1).unwrap(),
                message_id: format!("{i:032x}"),
                attachment: None,
                delivered_at_ms: None,
            };
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                reg.mutate_in_place_or_init(
                    group,
                    || dm(group, LOCAL, PEER, 0, 0, 0),
                    |conv| {
                        conv.push_history(entry.clone());
                        MutateAction::Persist(())
                    },
                )
                .await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        let conv = reg.get(group).await.unwrap().unwrap();
        assert_eq!(
            conv.history.len(),
            N,
            "every concurrent push must land — a TOCTOU clobber would \
             drop entries when the second init's save() ran",
        );
    }

    #[tokio::test]
    async fn mutate_in_place_without_init_errors_when_absent() {
        // The no-init API surface must still surface Invalid when the
        // group doesn't exist on disk + cache — callers like the rekey
        // path explicitly require an existing conv, and we don't want
        // a silent shell-bootstrap on the wrong code path.
        let (_d, reg) = fresh_registry();
        let err = reg
            .mutate_in_place("aa", |conv| {
                conv.current_epoch = 1;
                MutateAction::Persist(())
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("no conversation for group_id")),
            "expected Invalid, got {err:?}",
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
