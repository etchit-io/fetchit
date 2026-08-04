//! Vault-persisted store of outbound DM bubbles.
//!
//! Mirrors `crate::groups_reachability::BridgeConsentStore`: the bubble
//! map is sealed at rest under the chat master key via
//! [`crate::at_rest::seal_to_path`], `load` is fail-safe to empty on any
//! read failure, and `flush` is best-effort (a write failure is logged and
//! swallowed; the in-memory state is authoritative). An in-memory
//! `inflight` guard prevents the retry driver from re-firing a bubble whose
//! send is already in progress.

use super::{OutboxBubble, SendState, PRIOR_MESSAGE_ID_CAP};
use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::local_store::StoreLayout;
use crate::send_state::SendFailure;
use std::collections::HashMap;
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
    /// Bubble ids with a send in progress, mapped to the Unix-ms the
    /// claim was taken. Never persisted -- in-flight tasks die with the
    /// process, and a driver (re)start clears the whole set.
    inflight: HashMap<String, u64>,
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
    ///
    /// Bubbles sealed before send-state truth are migrated as they load:
    /// a legacy `Failed` (which meant "retry me") comes back
    /// [`SendState::Queued`], and a legacy `Sending` splits on whether a
    /// relay ever acked it.
    #[must_use]
    pub fn load(
        layout: &StoreLayout,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        let mut inner = Self::read_map(&layout.outbox_path(), master).unwrap_or_default();
        Self::migrate_legacy(&mut inner);
        Self {
            inner,
            persist: Some(OutboxPersist {
                layout: layout.clone(),
                master: master.clone(),
                kdf_id,
                argon_salt: argon_salt.copied(),
            }),
            inflight: HashMap::new(),
        }
    }

    /// Re-read the pre-send-state-truth statuses honestly.
    ///
    /// A bubble with no `state_changed_at_ms` was written by the old
    /// three-state machine, where `Failed` meant "the attempt errored,
    /// retry me" and `Sending` covered both "not yet acked" and "acked,
    /// awaiting receipt". Carrying those verbatim would strand every
    /// legacy failed bubble in the NEW terminal `Failed`, so:
    ///
    /// - legacy `Failed` -> [`SendState::Queued`] (keep retrying; the
    ///   reason survives in `last_error` as diagnostics),
    /// - legacy `Sending` (deserialized as `Queued`) with a `message_id`
    ///   -> [`SendState::Sent`], since only a relay ack ever set one,
    /// - `Delivered` is unchanged.
    ///
    /// Every migrated bubble is stamped with `enqueued_at_ms` so the UI
    /// has a transition age to render instead of a zero.
    fn migrate_legacy(map: &mut HashMap<String, OutboxBubble>) {
        for bubble in map.values_mut() {
            if bubble.state_changed_at_ms != 0 {
                continue;
            }
            bubble.status = match bubble.status {
                SendState::Failed => SendState::Queued,
                SendState::Queued if bubble.message_id.is_some() => SendState::Sent,
                other => other,
            };
            bubble.state_changed_at_ms = bubble.enqueued_at_ms;
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

    /// Remove every bubble targeting a peer in `peers` and persist, returning
    /// the dropped bubble ids. `peers` is the set of device agents a contact's
    /// newer `PairRecordV4` revision removed; a device agent id is unique to
    /// one device, so this drops only the removed devices' pending sends, never
    /// a live sibling's.
    pub fn drop_bubbles_for_peers(&mut self, peers: &[crate::identity::AgentId]) -> Vec<String> {
        if peers.is_empty() {
            return Vec::new();
        }
        let dropped: Vec<String> = self
            .inner
            .values()
            .filter(|b| peers.contains(&b.peer))
            .map(|b| b.id.clone())
            .collect();
        for id in &dropped {
            self.inner.remove(id);
        }
        if !dropped.is_empty() {
            self.flush();
        }
        dropped
    }

    /// Claim `id` as in-flight at `now_ms`. Returns `true` if newly
    /// claimed, `false` if a send for it is already in progress.
    ///
    /// This claim -- not the bubble's state -- is the double-send guard:
    /// a [`SendState::Queued`] bubble is always retry-eligible, so every
    /// send path (the initial send included) must hold a claim for the
    /// duration of its attempt. Not persisted; in-flight tasks die with
    /// the process and [`Self::clear_all_inflight`] reclaims the rest.
    pub fn try_mark_inflight(&mut self, id: &str, now_ms: u64) -> bool {
        self.inflight.insert(id.to_string(), now_ms).is_none()
    }

    /// Release the in-flight claim on `id`.
    pub fn clear_inflight(&mut self, id: &str) {
        self.inflight.remove(id);
    }

    /// Drop every in-flight claim. Called at driver (re)start: a freshly
    /// started driver implies any prior driver is dead, so a lingering claim
    /// is an orphan from a `flush_peer` aborted before `clear_inflight` ran.
    /// The new driver has no legitimate in-flight send yet, so clearing all
    /// claims is safe and lets the orphaned bubble re-send on the next
    /// presence edge. Not persisted (the set never is).
    pub fn clear_all_inflight(&mut self) {
        self.inflight.clear();
    }

    /// Release in-flight claims older than `stall_ms` (relative to
    /// `now_ms`) on bubbles that are not terminal, returning them.
    ///
    /// The claim is the only thing that can wedge a message: a
    /// [`SendState::Queued`] bubble is otherwise always retry-eligible,
    /// but a send task killed between claim and release (an aborted
    /// runtime, a transport that never returns) would hold its claim for
    /// the life of the process and the message would sit there forever,
    /// silently. Nothing about the bubble's STATE changes -- a stalled
    /// attempt is still a queued message, never a failed one.
    pub fn clear_stalled_inflight(&mut self, now_ms: u64, stall_ms: u64) -> Vec<OutboxBubble> {
        let stalled: Vec<String> = self
            .inflight
            .iter()
            .filter(|(id, claimed_at)| {
                now_ms.saturating_sub(**claimed_at) >= stall_ms
                    && self.inner.get(*id).is_some_and(|b| !b.status.is_terminal())
            })
            .map(|(id, _)| id.clone())
            .collect();
        stalled
            .into_iter()
            .filter_map(|id| {
                self.inflight.remove(&id);
                self.inner.get(&id).cloned()
            })
            .collect()
    }

    /// Mark the bubble a delivery receipt for `message_id` belongs to as
    /// [`SendState::Delivered`] at `received_at_ms`. Matches superseded
    /// ids too ([`OutboxBubble::matches_receipt`]), so a receipt for the
    /// copy an earlier attempt sent still closes the bubble. Returns the
    /// updated bubble, or `None` when nothing matches. Persists on a hit.
    pub fn mark_delivered(
        &mut self,
        message_id: &str,
        received_at_ms: u64,
    ) -> Option<OutboxBubble> {
        let updated = {
            let bubble = self
                .inner
                .values_mut()
                .find(|b| b.matches_receipt(message_id))?;
            bubble.status = SendState::Delivered;
            bubble.state_changed_at_ms = received_at_ms;
            bubble.clone()
        };
        self.flush();
        Some(updated)
    }

    /// Apply the result of a send attempt to bubble `bubble_id`, returning
    /// the updated bubble for the caller to broadcast (or `None` if the
    /// bubble is gone or already terminal). Shared by the initial send
    /// (`Client::enqueue_dm`) and the retry driver so the transitions live
    /// in ONE place.
    ///
    /// The state machine, in full:
    /// - success -> [`SendState::Sent`], recording the accepted
    ///   `message_id` (the previous one, if any, is kept for receipt
    ///   matching). A relay ack is the ONLY way into `Sent`.
    /// - retryable failure -> stays [`SendState::Queued`] with the reason
    ///   in `last_error`. A dropped socket or a lost ack must never read
    ///   as failure.
    /// - terminal failure ([`SendFailure::terminal`]) -> [`SendState::Failed`].
    /// - a bubble already [`SendState::Sent`] never goes backwards: a
    ///   later attempt that fails cannot un-accept what a relay durably
    ///   took, so the state holds and only `last_error` updates.
    /// - a bubble already terminal ([`SendState::Delivered`] from a
    ///   receipt that won the race with this send, or [`SendState::Failed`])
    ///   is never clobbered -- on either arm.
    pub fn record_send_outcome(
        &mut self,
        bubble_id: &str,
        message_id: Option<String>,
        failure: Option<SendFailure>,
        now_ms: u64,
    ) -> Option<OutboxBubble> {
        let updated = {
            let bubble = self.inner.get_mut(bubble_id)?;
            if bubble.status.is_terminal() {
                return None;
            }
            if let Some(f) = failure {
                bubble.last_error = Some(f.reason);
                // Terminal only from Queued: once a relay has custody the
                // message is out, whatever a later retry reports.
                if f.terminal && !bubble.status.reached_relay() {
                    bubble.status = SendState::Failed;
                    bubble.state_changed_at_ms = now_ms;
                }
            } else {
                if let Some(new_id) = message_id {
                    if let Some(old) = bubble.message_id.replace(new_id) {
                        // A DM resend re-encrypts and mints a fresh id;
                        // remember the superseded one so its receipt still
                        // matches. Bounded: oldest drops first.
                        if !bubble.prior_message_ids.contains(&old) {
                            if bubble.prior_message_ids.len() >= PRIOR_MESSAGE_ID_CAP {
                                bubble.prior_message_ids.remove(0);
                            }
                            bubble.prior_message_ids.push(old);
                        }
                    }
                }
                if bubble.status != SendState::Sent {
                    bubble.state_changed_at_ms = now_ms;
                }
                bubble.status = SendState::Sent;
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
    use crate::error::ChatError;
    use crate::identity::AgentId;
    use tempfile::tempdir;

    fn test_master() -> MasterKey {
        MasterKey::from_bytes_for_test([7u8; AEAD_KEY_LEN])
    }

    fn bubble(id: &str, peer: &str) -> OutboxBubble {
        OutboxBubble::queued(id.into(), AgentId(peer.repeat(64)), "hi".into(), 1)
    }

    /// A retryable transport failure -- the "socket dropped" shape that
    /// must never surface as a failed message.
    fn transport_failure() -> SendFailure {
        SendFailure::classify(&ChatError::MessageTransport("relay send: eof".into()))
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
    fn drop_bubbles_for_peers_removes_only_matching_peers() {
        let mut s = OutboxStore::new();
        s.upsert(bubble("b1", "a"));
        s.upsert(bubble("b2", "b"));
        s.upsert(bubble("b3", "a"));
        // Drop peer "a" (two bubbles); peer "b" survives.
        let mut dropped = s.drop_bubbles_for_peers(&[AgentId("a".repeat(64))]);
        dropped.sort();
        assert_eq!(dropped, vec!["b1".to_string(), "b3".to_string()]);
        assert!(s.get("b1").is_none());
        assert!(s.get("b3").is_none());
        assert!(s.get("b2").is_some());
        // Empty peer set is a no-op.
        assert!(s.drop_bubbles_for_peers(&[]).is_empty());
    }

    /// A minimal sealed envelope for the group-bubble durability tests. The
    /// bytes are arbitrary -- the point is that the whole envelope round-trips
    /// through the vault seal so a queued group send survives a restart and
    /// re-sends verbatim (MLS seals must never be re-sealed on retry).
    fn test_envelope() -> fetchit_relay_proto::TransitEnvelope {
        use fetchit_relay_proto::{AgentId, EnvelopeKind, MachineId, TransitEnvelope};
        TransitEnvelope {
            version: 3,
            kind: EnvelopeKind::PrivateGroupChat,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1u8; 32]),
            sender_machine_id: MachineId::from_bytes([2u8; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![9, 9, 9],
            nonce: vec![0u8; 12],
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        }
    }

    #[test]
    fn outbox_persists_group_context_across_reload() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let m = test_master();
        let mut s = OutboxStore::load(&layout, &m, 0, None);
        let mut b = bubble("g1", "b");
        b.group = Some(crate::outbox::GroupOutbound {
            group_id: "aa".repeat(32),
            envelope: postcard::to_allocvec(&test_envelope()).unwrap(),
            client_message_id: "cmid-1".to_owned(),
        });
        s.upsert(b);
        drop(s);
        // Reload from the sealed vault: the group id AND the sealed envelope
        // bytes must both survive so the retry driver re-sends the exact
        // frame -- and the bytes must still decode to a valid envelope.
        let s2 = OutboxStore::load(&layout, &m, 0, None);
        let g = s2
            .get("g1")
            .unwrap()
            .group
            .as_ref()
            .expect("group context survives reload");
        assert_eq!(g.group_id, "aa".repeat(32));
        let decoded: fetchit_relay_proto::TransitEnvelope =
            postcard::from_bytes(&g.envelope).expect("sealed envelope bytes decode after reload");
        assert_eq!(decoded.ciphertext, vec![9, 9, 9]);
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
        assert!(s.try_mark_inflight("b1", 10));
        assert!(!s.try_mark_inflight("b1", 11));
        s.clear_inflight("b1");
        assert!(s.try_mark_inflight("b1", 12));
    }

    #[test]
    fn clear_all_inflight_releases_orphan_claims() {
        let mut s = OutboxStore::new();
        assert!(s.try_mark_inflight("b1", 0));
        assert!(s.try_mark_inflight("b2", 0));
        // Both claims are held; a re-claim is refused.
        assert!(!s.try_mark_inflight("b1", 1));
        s.clear_all_inflight();
        // After a driver (re)start clears orphans, both are claimable again.
        assert!(s.try_mark_inflight("b1", 2));
        assert!(s.try_mark_inflight("b2", 2));
    }

    #[test]
    fn clear_stalled_inflight_unwedges_without_touching_state() {
        let mut s = OutboxStore::new();
        s.upsert(bubble("b1", "a"));
        assert!(s.try_mark_inflight("b1", 1_000));
        // Fresh claim: left alone, still blocking a second send.
        assert!(s.clear_stalled_inflight(1_500, 1_000).is_empty());
        assert!(!s.try_mark_inflight("b1", 1_500));
        // Stalled claim: released, and the message is STILL queued -- a
        // send task that never returned is not a failed message.
        let freed = s.clear_stalled_inflight(3_000, 1_000);
        assert_eq!(freed.len(), 1);
        assert_eq!(freed[0].status, SendState::Queued);
        assert!(s.try_mark_inflight("b1", 3_000), "re-claimable after");
    }

    #[test]
    fn clear_stalled_inflight_leaves_terminal_bubbles_claimed() {
        let mut s = OutboxStore::new();
        let mut delivered = bubble("b1", "a");
        delivered.status = SendState::Delivered;
        s.upsert(delivered);
        assert!(s.try_mark_inflight("b1", 0));
        assert!(s.clear_stalled_inflight(999_999, 1_000).is_empty());
    }

    fn queued(id: &str, enqueued_at_ms: u64, message_id: Option<&str>) -> OutboxBubble {
        OutboxBubble {
            message_id: message_id.map(Into::into),
            ..OutboxBubble::queued(
                id.into(),
                AgentId("aa".repeat(32)),
                "hi".into(),
                enqueued_at_ms,
            )
        }
    }

    #[test]
    fn mark_delivered_by_message_id_stamps_the_receipt_time() {
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 1, Some("m1")));
        assert!(s.mark_delivered("m1", 555).is_some());
        let b = s.get("b1").unwrap();
        assert_eq!(b.status, SendState::Delivered);
        assert_eq!(b.state_changed_at_ms, 555);
        assert!(s.mark_delivered("nope", 556).is_none());
    }

    #[test]
    fn mark_delivered_matches_a_superseded_message_id() {
        // A resend minted a new logical id; the receipt for the FIRST copy
        // still proves the message arrived, so it must close the bubble.
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 1, None));
        s.record_send_outcome("b1", Some("m1".into()), None, 10);
        s.record_send_outcome("b1", Some("m2".into()), None, 20);
        assert!(s.mark_delivered("m1", 30).is_some());
        assert_eq!(s.get("b1").unwrap().status, SendState::Delivered);
    }

    #[test]
    fn record_send_outcome_ok_sets_sent_and_records_message_id() {
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 0, None));
        let updated = s
            .record_send_outcome("b1", Some("m1".into()), None, 77)
            .expect("bubble present");
        assert_eq!(
            updated.status,
            SendState::Sent,
            "relay ack is the only Sent"
        );
        assert_eq!(updated.message_id.as_deref(), Some("m1"));
        assert_eq!(updated.state_changed_at_ms, 77);
        assert_eq!(updated.last_error, None);
    }

    #[test]
    fn record_send_outcome_keeps_a_retryable_failure_queued() {
        // The headline lie this replaces: a dropped socket used to read as
        // "Failed" in the UI. It must stay Queued and keep retrying, with
        // the reason kept only as diagnostics.
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 0, None));
        let updated = s
            .record_send_outcome("b1", None, Some(transport_failure()), 5)
            .expect("bubble present");
        assert_eq!(updated.status, SendState::Queued);
        assert_eq!(updated.state_changed_at_ms, 0, "no transition happened");
        assert!(updated.last_error.is_some());
        assert!(crate::outbox::is_retryable(&updated));
    }

    #[test]
    fn record_send_outcome_fails_only_on_a_terminal_verdict() {
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 0, None));
        let denied = SendFailure::classify(&ChatError::Denied {
            agent_id_hex: "aa".repeat(32),
        });
        let updated = s
            .record_send_outcome("b1", None, Some(denied), 9)
            .expect("bubble present");
        assert_eq!(updated.status, SendState::Failed);
        assert_eq!(updated.state_changed_at_ms, 9);
        assert!(!crate::outbox::is_retryable(&updated));
    }

    #[test]
    fn a_sent_bubble_never_goes_backwards() {
        // Relay custody is a fact; a later failing retry -- even a terminal
        // one -- cannot un-accept it, so the state holds at Sent.
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 0, None));
        s.record_send_outcome("b1", Some("m1".into()), None, 10);
        let after = s
            .record_send_outcome("b1", None, Some(transport_failure()), 20)
            .expect("bubble present");
        assert_eq!(after.status, SendState::Sent);
        assert_eq!(after.state_changed_at_ms, 10, "no new transition");
        let denied = SendFailure::classify(&ChatError::Denied {
            agent_id_hex: "aa".repeat(32),
        });
        let after_denied = s
            .record_send_outcome("b1", None, Some(denied), 30)
            .expect("bubble present");
        assert_eq!(after_denied.status, SendState::Sent);
    }

    #[test]
    fn a_wedged_peer_never_advances_a_message_past_sent() {
        // The live failure this lane exists for: the peer cannot decrypt,
        // so no receipt ever comes back. However many times the relay
        // accepts a resend, the message stays Sent -- the engine never
        // manufactures a delivery the recipient never made.
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 0, None));
        for i in 0..5 {
            let updated = s
                .record_send_outcome("b1", Some(format!("m{i}")), None, 100 + i)
                .expect("bubble present");
            assert_eq!(updated.status, SendState::Sent);
        }
        let b = s.get("b1").unwrap();
        assert_eq!(b.status, SendState::Sent);
        // And the transition stamp still points at the FIRST acceptance,
        // so a shell can see how long it has sat unconfirmed.
        assert_eq!(b.state_changed_at_ms, 100);
    }

    #[test]
    fn record_send_outcome_never_clobbers_a_terminal_state() {
        let mut s = OutboxStore::new();
        let mut delivered = queued("b1", 0, Some("m1"));
        delivered.status = SendState::Delivered;
        s.upsert(delivered);
        // A receipt won the race during the send await; neither arm may
        // overwrite Delivered.
        assert!(s
            .record_send_outcome("b1", Some("m1".into()), None, 1)
            .is_none());
        assert!(s
            .record_send_outcome("b1", None, Some(transport_failure()), 2)
            .is_none());
        assert_eq!(s.get("b1").unwrap().status, SendState::Delivered);
    }

    #[test]
    fn record_send_outcome_absent_bubble_is_none() {
        let mut s = OutboxStore::new();
        assert!(s.record_send_outcome("nope", None, None, 0).is_none());
    }

    #[test]
    fn superseded_message_ids_are_bounded() {
        let mut s = OutboxStore::new();
        s.upsert(queued("b1", 0, None));
        for i in 0..(PRIOR_MESSAGE_ID_CAP + 3) {
            s.record_send_outcome("b1", Some(format!("m{i}")), None, 10);
        }
        let b = s.get("b1").unwrap();
        assert_eq!(b.prior_message_ids.len(), PRIOR_MESSAGE_ID_CAP);
        // Oldest dropped, newest-but-one kept, current id is the latest.
        assert_eq!(b.message_id.as_deref(), Some("m10"));
        assert_eq!(b.prior_message_ids.first().map(String::as_str), Some("m2"));
    }

    #[test]
    fn a_relay_accepted_group_copy_is_sent_and_never_re_fires() {
        // A group fan-out copy gets no per-member receipt, so relay
        // acceptance is as far as it can honestly go: Sent, not Delivered
        // (nobody confirmed receipt) and not retryable (re-sending one
        // sealed TreeKEM frame duplicates at the receiver).
        let mut s = OutboxStore::new();
        let g = bubble("g1", "b").with_group(crate::outbox::GroupOutbound {
            group_id: "aa".repeat(32),
            envelope: postcard::to_allocvec(&test_envelope()).unwrap(),
            client_message_id: "cmid-1".to_owned(),
        });
        s.upsert(g);
        let updated = s
            .record_send_outcome("g1", Some("relay-9".into()), None, 3)
            .expect("bubble present");
        assert_eq!(updated.status, SendState::Sent);
        assert!(!crate::outbox::is_retryable(&updated), "never re-fires");

        // A DM with the same outcome IS retryable until its receipt lands.
        s.upsert(queued("d1", 0, None));
        let dm = s
            .record_send_outcome("d1", Some("relay-10".into()), None, 4)
            .expect("bubble present");
        assert_eq!(dm.status, SendState::Sent);
        assert!(crate::outbox::is_retryable(&dm));
    }

    #[test]
    fn legacy_vault_statuses_are_migrated_on_load() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let m = test_master();
        // Hand-seal a pre-send-state-truth map: the old three states, no
        // transition stamps.
        let legacy = serde_json::json!({
            "failed": {
                "id": "failed", "peer": "aa".repeat(32), "body": "hi",
                "status": "Failed", "message_id": null,
                "enqueued_at_ms": 40, "last_error": "relay send: eof",
            },
            "unacked": {
                "id": "unacked", "peer": "aa".repeat(32), "body": "hi",
                "status": "Sending", "message_id": null,
                "enqueued_at_ms": 50, "last_error": null,
            },
            "acked": {
                "id": "acked", "peer": "aa".repeat(32), "body": "hi",
                "status": "Sending", "message_id": "m1",
                "enqueued_at_ms": 60, "last_error": null,
            },
            "done": {
                "id": "done", "peer": "aa".repeat(32), "body": "hi",
                "status": "Delivered", "message_id": "m2",
                "enqueued_at_ms": 70, "last_error": null,
            },
        });
        crate::at_rest::seal_to_path(
            &layout.outbox_path(),
            &serde_json::to_vec(&legacy).unwrap(),
            &m,
            0,
            None,
        )
        .unwrap();

        let s = OutboxStore::load(&layout, &m, 0, None);
        // Legacy "Failed" meant "retry me" -- it must NOT land in the new
        // terminal Failed, or every pending send from an old vault dies.
        let failed = s.get("failed").unwrap();
        assert_eq!(failed.status, SendState::Queued);
        assert_eq!(failed.last_error.as_deref(), Some("relay send: eof"));
        assert!(crate::outbox::is_retryable(failed));
        // Legacy "Sending" splits on whether a relay ever acked.
        assert_eq!(s.get("unacked").unwrap().status, SendState::Queued);
        assert_eq!(s.get("acked").unwrap().status, SendState::Sent);
        assert_eq!(s.get("done").unwrap().status, SendState::Delivered);
        // Every migrated bubble gets a transition age to render.
        assert_eq!(s.get("acked").unwrap().state_changed_at_ms, 60);
    }

    #[test]
    fn a_queued_message_survives_a_restart_still_queued() {
        // Restart recovery: the state a user was shown before the process
        // died is the state they see after it comes back, and the message
        // is still eligible for the next flush.
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let m = test_master();
        let mut s = OutboxStore::load(&layout, &m, 0, None);
        s.upsert(queued("b1", 10, None));
        s.record_send_outcome("b1", None, Some(transport_failure()), 20);
        // Mid-send when the process died: the claim is in RAM only.
        assert!(s.try_mark_inflight("b1", 20));
        drop(s);

        let s2 = OutboxStore::load(&layout, &m, 0, None);
        let b = s2.get("b1").unwrap();
        assert_eq!(b.status, SendState::Queued);
        assert!(b.last_error.is_some(), "the reason survives as diagnostics");
        assert!(crate::outbox::is_retryable(b));
    }

    #[test]
    fn a_sent_message_survives_a_restart_still_sent() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let m = test_master();
        let mut s = OutboxStore::load(&layout, &m, 0, None);
        s.upsert(queued("b1", 10, None));
        s.record_send_outcome("b1", Some("m1".into()), None, 33);
        drop(s);

        let s2 = OutboxStore::load(&layout, &m, 0, None);
        let b = s2.get("b1").unwrap();
        assert_eq!(b.status, SendState::Sent);
        assert_eq!(b.state_changed_at_ms, 33, "the transition stamp persists");
        assert_eq!(b.message_id.as_deref(), Some("m1"));
    }

    #[test]
    fn migration_leaves_current_vault_entries_alone() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let m = test_master();
        let mut s = OutboxStore::load(&layout, &m, 0, None);
        s.upsert(queued("b1", 10, None));
        // A genuinely terminal failure written by THIS engine carries a
        // transition stamp, so the legacy re-queue must not touch it.
        s.record_send_outcome(
            "b1",
            None,
            Some(SendFailure::classify(&ChatError::Denied {
                agent_id_hex: "aa".repeat(32),
            })),
            99,
        );
        drop(s);
        let s2 = OutboxStore::load(&layout, &m, 0, None);
        assert_eq!(s2.get("b1").unwrap().status, SendState::Failed);
        assert_eq!(s2.get("b1").unwrap().state_changed_at_ms, 99);
    }
}
