//! Per-`(group, member)` direct-gossip reachability tracking and per-group
//! bridge-consent state for the M2.5 metadata bridge.
//!
//! When the chat-peer needs to send a group-metadata event (`MemberJoined`,
//! `MemberAdded`, `Welcome`, `Commit`) to a peer `P` in group `G`, it consults:
//!
//! 1. [`ReachabilityCache`] — has a recent direct-gossip event for
//!    `(G, P)` been observed? If `Reachable`, x0xd's gossip path carries
//!    the event; no bridge wrapping needed.
//! 2. [`BridgeConsentStore`] — has the user opted into bridging for `G`?
//!    Default-OFF per Q4 lock; first `Unreachable` lookup with `NotAsked`
//!    consent triggers the consent modal.
//!
//! [`decide_route`] is the pure routing rule per §5 of
//! `private/m2.5-bridge-collapsed-spec.md`; the chat-peer is responsible
//! for taking the resulting action.
//!
//! # State
//!
//! This module owns the typed surface, the in-memory operations, and the
//! pure routing decision ([`decide_route`]). It is wired into
//! [`crate::Client`]: the dispatcher records direct-gossip activity into
//! [`ReachabilityCache`], and the send path consults [`decide_route`]
//! before wrapping a metadata event for the bridge. The reachability and
//! consent state is held in memory for the session and is not persisted
//! across restart.

use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::groups::GroupId;
use crate::identity::AgentId;
use crate::local_store::StoreLayout;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Reachability of a `(group, member)` pair on the direct-gossip path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reachability {
    /// A direct-gossip event for this `(group, member)` was observed
    /// within [`STALE_AFTER_MS`].
    Reachable,
    /// No direct-gossip event for this `(group, member)` within
    /// [`STALE_AFTER_MS`] — bridge required.
    Unreachable,
}

/// Per-group consent state for the metadata bridge.
///
/// Default per Q4 is [`Self::NotAsked`] (bridge OFF until the user
/// explicitly opts in for a given group). The first `Unreachable` lookup
/// against a `NotAsked` group is what surfaces the consent modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupBridgeConsent {
    /// The user has never been asked. Triggers the consent modal on first
    /// `Unreachable` lookup.
    NotAsked,
    /// The user opted in for this group. Bridge wraps and sends.
    ConsentedOptIn,
    /// The user declined for this group. Bridge drops the event and the
    /// UI surfaces "group unreachable".
    DeclinedOptOut,
}

/// Millisecond Unix epoch timestamp for direct-gossip last-seen tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSeenMs(pub u64);

/// Window after which a `(group, member)` is considered `Unreachable` on
/// the direct-gossip path.
///
/// 60 s, tunable per the spec. Sized for the typical x0xd
/// publish->subscribe round-trip on a healthy mesh.
pub const STALE_AFTER_MS: u64 = 60_000;

/// In-memory cache of last-seen direct-gossip activity per
/// `(group, member)`. Held in memory for the session and rebuilt from
/// live gossip after restart; not persisted to disk.
#[derive(Debug, Default)]
pub struct ReachabilityCache {
    inner: HashMap<(GroupId, AgentId), LastSeenMs>,
}

impl ReachabilityCache {
    /// Empty cache. Equivalent to `Default`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a direct-gossip event for `(group, member)` at `now_ms`.
    ///
    /// Called by the chat-peer dispatcher whenever an x0xd group event
    /// arrives **via the gossip path** (NOT via the bridge). Bridge
    /// deliveries explicitly do not update this cache — they are the
    /// signal that direct gossip *failed*.
    pub fn record(&mut self, group: GroupId, member: AgentId, now_ms: u64) {
        self.inner.insert((group, member), LastSeenMs(now_ms));
    }

    /// Reachability for `(group, member)` evaluated against `now_ms`.
    ///
    /// Missing entries → `Unreachable`. Entries older than
    /// [`STALE_AFTER_MS`] → `Unreachable`. `now_ms` going backward
    /// relative to the recorded `last_seen` (clock skew) is treated as
    /// `Reachable` via `saturating_sub`.
    #[must_use]
    pub fn lookup(&self, group: &GroupId, member: &AgentId, now_ms: u64) -> Reachability {
        match self.inner.get(&(group.clone(), member.clone())) {
            Some(LastSeenMs(last)) if now_ms.saturating_sub(*last) < STALE_AFTER_MS => {
                Reachability::Reachable
            }
            _ => Reachability::Unreachable,
        }
    }

    /// Drop the entry for `(group, member)`. Used when a member is
    /// removed from a group or the conversation is closed.
    pub fn forget(&mut self, group: &GroupId, member: &AgentId) {
        self.inner.remove(&(group.clone(), member.clone()));
    }

    /// Number of `(group, member)` entries currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no entries are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Per-group consent state for the metadata bridge.
///
/// Held in memory for the session. When constructed via [`Self::load`]
/// it also carries a `ConsentPersist` handle and re-seals the whole
/// map to `bridge/consent.json.enc` on every mutation, so the user's
/// per-group opt-in / opt-out decisions survive restart. Constructed via
/// [`Self::new`] it stays purely in memory (tests and any caller without
/// a master key).
#[derive(Debug, Default)]
pub struct BridgeConsentStore {
    inner: HashMap<GroupId, GroupBridgeConsent>,
    persist: Option<ConsentPersist>,
}

/// Everything [`BridgeConsentStore`] needs to seal its map to disk,
/// mirroring the conversation registry's persistence fields (`layout` +
/// `master` + `kdf_id` + `argon_salt`). Cloned into the store by
/// [`BridgeConsentStore::load`]; absent for in-memory stores.
#[derive(Clone)]
struct ConsentPersist {
    layout: StoreLayout,
    master: MasterKey,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
}

impl std::fmt::Debug for ConsentPersist {
    // The master key never appears in Debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentPersist")
            .field("path", &self.layout.bridge_consent_path())
            .field("master", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BridgeConsentStore {
    /// Empty, in-memory-only store with no disk persistence. Equivalent
    /// to `Default`. Used by tests and any caller without a master key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the persisted consent map from `bridge/consent.json.enc`,
    /// returning a store that re-seals on every mutation.
    ///
    /// Fail-safe: a missing file, a wrong or rotated master key (AEAD
    /// tag mismatch), a truncated or corrupt file, or an unparseable
    /// [`GroupId`] all fall back to an empty map rather than erroring.
    /// Empty == every group `NotAsked` == the pre-persistence reset
    /// behavior, so a damaged file can never hard-fail client startup --
    /// the worst case is one extra consent prompt.
    #[must_use]
    pub fn load(
        layout: &StoreLayout,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        let inner = Self::read_map(&layout.bridge_consent_path(), master).unwrap_or_default();
        Self {
            inner,
            persist: Some(ConsentPersist {
                layout: layout.clone(),
                master: master.clone(),
                kdf_id,
                argon_salt: argon_salt.copied(),
            }),
        }
    }

    /// Best-effort read of the sealed map. `None` on any failure so
    /// [`Self::load`] can fall back to empty (see its fail-safe note).
    fn read_map(path: &Path, master: &MasterKey) -> Option<HashMap<GroupId, GroupBridgeConsent>> {
        if !path.exists() {
            return None;
        }
        let plain = open_from_path(path, master).ok()?;
        serde_json::from_slice(&plain).ok()
    }

    /// Current consent state for `group`. Missing entries →
    /// [`GroupBridgeConsent::NotAsked`] (default-OFF per Q4).
    #[must_use]
    pub fn lookup(&self, group: &GroupId) -> GroupBridgeConsent {
        self.inner
            .get(group)
            .copied()
            .unwrap_or(GroupBridgeConsent::NotAsked)
    }

    /// Set consent state for `group`, then persist the map when a
    /// persistence handle is installed (i.e. the store came from
    /// [`Self::load`]). Called by the desktop UI after the consent modal
    /// resolves, or by tests / migration paths.
    pub fn set(&mut self, group: GroupId, state: GroupBridgeConsent) {
        self.inner.insert(group, state);
        self.flush();
    }

    /// Forget consent for `group` -- used when the group is left or
    /// permanently deleted -- and persist the removal so a left/deleted
    /// group's consent does not linger on disk.
    pub fn forget(&mut self, group: &GroupId) {
        self.inner.remove(group);
        self.flush();
    }

    /// Seal the whole map to disk when a persistence handle is set.
    ///
    /// Best-effort: a serialize or write failure is logged and
    /// swallowed, never propagated -- the in-memory state is already
    /// updated, and a failed persist degrades to the pre-persistence
    /// behavior (re-prompt on next restart) rather than hard-failing a
    /// consent toggle. `seal_to_path` writes atomically (temp + rename),
    /// so a crash mid-write cannot leave a torn file. No-op for in-memory
    /// stores (`persist` is `None`).
    fn flush(&self) {
        let Some(persist) = self.persist.as_ref() else {
            return;
        };
        let bytes = match serde_json::to_vec(&self.inner) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("bridge-consent encode failed, not persisted: {e}");
                return;
            }
        };
        if let Err(e) = seal_to_path(
            &persist.layout.bridge_consent_path(),
            &bytes,
            &persist.master,
            persist.kdf_id,
            persist.argon_salt.as_ref(),
        ) {
            log::warn!("bridge-consent persist failed: {e}");
        }
    }
}

/// Outcome of the §5 routing rule for a single outbound group-metadata
/// event. The chat-peer is responsible for taking the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeDecision {
    /// Direct gossip will carry the event; no bridge wrapping needed.
    LetGossipCarry,
    /// Wrap the event as a DM and send via relay (spec §3).
    WrapAndSend,
    /// The user has declined bridging for this group. Drop the event and
    /// surface "group unreachable" UI.
    DropDeclined,
    /// Consent is `NotAsked`. Trigger the consent modal and park the
    /// event until the user decides; on opt-in re-evaluate and send, on
    /// opt-out drop and surface UI.
    PromptConsent,
}

/// Window after which a bridge-inbound shadow entry stops suppressing
/// SSE-side reachability recording.
///
/// Bridge inbound flow: chat-peer receives a sealed
/// `EnvelopeKind::X0xdGroupMetadataEvent` via relay, unseals, POSTs the
/// inner JSON to local x0xd `/publish`. Saorsa pubsub's local-loopback
/// then re-emits the same event on the local `/events` SSE stream.
/// Without a shadow entry, the SSE consumer would interpret that
/// loopback as evidence of direct-gossip reachability for the signer
/// and falsely flip `(group, member)` to `Reachable` — exactly the
/// case the bridge exists to solve. The shadow window must comfortably
/// cover the round trip between `POST /publish` and SSE emission.
///
/// 30 s is wide enough to absorb SSE consumer back-pressure under a
/// bursty inbound flurry (paired with the chat-peer's
/// `spawn_sse_reachability_recorder` respawn loop, which itself
/// applies a backoff after stream errors), and narrow enough that a
/// genuine later direct-gossip event from the same signer past 30 s
/// promotes to `Reachable` on the very next tick.
pub const SHADOW_WINDOW_MS: u64 = 30_000;

/// In-memory ring of recently-bridge-delivered payload hashes. Consumed
/// by the SSE consumer to suppress false-positive reachability records
/// on bridge-loopback events.
///
/// Keyed by the FNV-style hash of the inner JSON event payload bytes
/// (i.e. the same bytes that arrive on the SSE consumer's
/// `Event::GossipMessage { payload, .. }`). The hash is intentionally
/// content-only so any path mutation in x0xd's publish/loopback layer
/// — re-base64, key-order shuffle — would cause a benign cache miss
/// (record runs, double-recording is harmless idempotent) rather than
/// a silent false reachability record.
///
/// Contract: callers `mark` before `POST /publish` and
/// `is_recent_and_evict` from the SSE consumer hot path. Periodic
/// `evict_older_than` is optional -- entries beyond
/// `2 * SHADOW_WINDOW_MS` are dropped on lookup anyway.
#[derive(Debug, Default)]
pub struct BridgeInboundShadow {
    inner: HashMap<u64, LastSeenMs>,
}

impl BridgeInboundShadow {
    /// Empty shadow set. Equivalent to `Default`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `payload_hash` as recently bridge-delivered at `now_ms`.
    /// Called from the chat-peer's bridge dispatcher BEFORE
    /// `POST /publish` so the upcoming SSE loopback finds the entry.
    pub fn mark(&mut self, payload_hash: u64, now_ms: u64) {
        self.inner.insert(payload_hash, LastSeenMs(now_ms));
    }

    /// Check whether `payload_hash` was bridge-delivered within
    /// [`SHADOW_WINDOW_MS`] of `now_ms`. Side-effect-free; pair with
    /// [`Self::evict_older_than`] to bound memory.
    #[must_use]
    pub fn is_recent(&self, payload_hash: u64, now_ms: u64) -> bool {
        match self.inner.get(&payload_hash) {
            Some(LastSeenMs(last)) => now_ms.saturating_sub(*last) < SHADOW_WINDOW_MS,
            None => false,
        }
    }

    /// Drop every entry whose age exceeds `cutoff_ms` relative to
    /// `now_ms`. Call periodically from the chat-peer (or inline at
    /// `mark` time on a counter) to keep the table bounded under
    /// sustained bridge traffic.
    pub fn evict_older_than(&mut self, now_ms: u64, cutoff_ms: u64) {
        self.inner
            .retain(|_, LastSeenMs(last)| now_ms.saturating_sub(*last) < cutoff_ms);
    }

    /// Number of shadow entries currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no shadow entries are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Compute a stable in-process hash of `payload` for use as a
/// [`BridgeInboundShadow`] key. Not cryptographically strong — the
/// adversary model is "x0xd's own loopback, not a relay attacker."
#[must_use]
pub fn hash_payload(payload: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    payload.hash(&mut h);
    h.finish()
}

/// Parse `x0x.named_group/<gid>/metadata` into the group id segment.
///
/// Returns `None` when the topic doesn't match the metadata-topic
/// shape (e.g. presence topics, chat content topics) or when the
/// embedded segment is not a valid [`GroupId`] (path traversal guard,
/// see [`GroupId::parse`]). Used by the SSE consumer to extract the
/// reachability key from `Event::GossipMessage { topic, .. }`.
#[must_use]
pub fn group_id_from_metadata_topic(topic: &str) -> Option<GroupId> {
    let inside = topic.strip_prefix("x0x.named_group/")?;
    let gid = inside.strip_suffix("/metadata")?;
    GroupId::parse(gid).ok()
}

/// Decide whether an inbound `Event::GossipMessage` deserves a
/// reachability record. Pure function — no I/O, no awaits — so the SSE
/// consumer can pass borrows of its locked
/// [`BridgeInboundShadow`] and the test path can drive every branch
/// hermetically without spinning up a real x0xd.
///
/// Returns `Some((group, sender))` when the event represents fresh
/// evidence of direct-gossip reachability and the caller should
/// [`ReachabilityCache::record`] the pair. Returns `None` when:
///
/// 1. The event has no `from` (anonymous gossip — nothing to record).
/// 2. `from` matches `local_agent_hex` (case-insensitive ASCII) — our
///    own /publish loopback. The case-insensitive compare mirrors the
///    M2 send path's `eq_ignore_ascii_case` on agent-id hexes
///    (`messages.rs`) so x0xd's `/agent` and `/events` SSE surfaces
///    can disagree on hex casing without breaking the self-publish
///    skip.
/// 3. `shadow.is_recent(hash_payload(payload), now_ms)` — bridge
///    loopback; recording would falsely promote
///    `(group, signer) → Reachable` exactly when the bridge fired
///    *because* direct gossip failed.
/// 4. `topic` does not match the
///    `x0x.named_group/<gid>/metadata` shape, or the embedded segment
///    fails [`GroupId::parse`].
///
/// Used by [`crate::client::Client::spawn_sse_reachability_recorder`]
/// to keep the §5 routing rule honest under the symmetric-NAT case
/// the bridge exists to solve.
#[must_use]
pub fn classify_sse_event(
    topic: &str,
    payload: &[u8],
    from: Option<&AgentId>,
    local_agent_hex: &str,
    shadow: &BridgeInboundShadow,
    now_ms: u64,
) -> Option<(GroupId, AgentId)> {
    let from = from?;
    if from.0.eq_ignore_ascii_case(local_agent_hex) {
        return None;
    }
    if shadow.is_recent(hash_payload(payload), now_ms) {
        return None;
    }
    let group = group_id_from_metadata_topic(topic)?;
    Some((group, from.clone()))
}

/// Routing rule per §5 of `private/m2.5-bridge-collapsed-spec.md`.
///
/// Pure decision: no side effects, no I/O. Composable into both the
/// per-event send path and the prefix-walk path that decides whether to
/// even open the consent modal on group-add. The caller takes the
/// action that the returned [`BridgeDecision`] describes.
#[must_use]
pub fn decide_route(
    cache: &ReachabilityCache,
    consent: &BridgeConsentStore,
    group: &GroupId,
    member: &AgentId,
    now_ms: u64,
) -> BridgeDecision {
    match cache.lookup(group, member, now_ms) {
        Reachability::Reachable => BridgeDecision::LetGossipCarry,
        Reachability::Unreachable => match consent.lookup(group) {
            GroupBridgeConsent::ConsentedOptIn => BridgeDecision::WrapAndSend,
            GroupBridgeConsent::DeclinedOptOut => BridgeDecision::DropDeclined,
            GroupBridgeConsent::NotAsked => BridgeDecision::PromptConsent,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use tempfile::tempdir;

    fn g(s: &str) -> GroupId {
        GroupId::parse(s).unwrap()
    }

    fn a(s: &str) -> AgentId {
        AgentId(s.to_string())
    }

    #[test]
    fn empty_cache_is_unreachable() {
        let cache = ReachabilityCache::new();
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_000),
            Reachability::Unreachable,
        );
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn recently_recorded_is_reachable() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_500),
            Reachability::Reachable,
        );
    }

    #[test]
    fn record_just_under_stale_window_is_reachable() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        // 1 ms inside the window.
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_000 + STALE_AFTER_MS - 1),
            Reachability::Reachable,
        );
    }

    #[test]
    fn record_at_stale_boundary_is_unreachable() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        // Exactly at STALE_AFTER_MS — boundary is exclusive.
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_000 + STALE_AFTER_MS),
            Reachability::Unreachable,
        );
    }

    #[test]
    fn stale_record_is_unreachable() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_000 + STALE_AFTER_MS + 1),
            Reachability::Unreachable,
        );
    }

    #[test]
    fn clock_skew_backward_treated_as_reachable() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 2_000_000);
        // now_ms goes backward relative to last_seen — saturating_sub
        // yields 0, which is inside STALE_AFTER_MS, so Reachable.
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_000),
            Reachability::Reachable,
        );
    }

    #[test]
    fn record_for_different_member_does_not_leak() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        assert_eq!(
            cache.lookup(&g("group1"), &a("bob"), 1_000_500),
            Reachability::Unreachable,
        );
    }

    #[test]
    fn record_for_different_group_does_not_leak() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        assert_eq!(
            cache.lookup(&g("group2"), &a("alice"), 1_000_500),
            Reachability::Unreachable,
        );
    }

    #[test]
    fn forget_removes_entry() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        assert_eq!(cache.len(), 1);
        cache.forget(&g("group1"), &a("alice"));
        assert!(cache.is_empty());
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_500),
            Reachability::Unreachable,
        );
    }

    #[test]
    fn record_overwrites_existing_entry() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        // Re-record at a later timestamp; lookup at a moment past the
        // original staleness boundary should still resolve Reachable.
        cache.record(g("group1"), a("alice"), 1_000_000 + STALE_AFTER_MS + 10);
        assert_eq!(
            cache.lookup(&g("group1"), &a("alice"), 1_000_000 + STALE_AFTER_MS + 100),
            Reachability::Reachable,
        );
        assert_eq!(cache.len(), 1, "no duplicate row");
    }

    #[test]
    fn consent_default_is_not_asked() {
        let store = BridgeConsentStore::new();
        assert_eq!(store.lookup(&g("group1")), GroupBridgeConsent::NotAsked);
    }

    #[test]
    fn consent_set_and_lookup_round_trip() {
        let mut store = BridgeConsentStore::new();
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        store.set(g("group2"), GroupBridgeConsent::DeclinedOptOut);
        assert_eq!(
            store.lookup(&g("group1")),
            GroupBridgeConsent::ConsentedOptIn,
        );
        assert_eq!(
            store.lookup(&g("group2")),
            GroupBridgeConsent::DeclinedOptOut,
        );
        assert_eq!(store.lookup(&g("group3")), GroupBridgeConsent::NotAsked);
    }

    #[test]
    fn consent_forget_resets_to_not_asked() {
        let mut store = BridgeConsentStore::new();
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        store.forget(&g("group1"));
        assert_eq!(store.lookup(&g("group1")), GroupBridgeConsent::NotAsked);
    }

    // -- BridgeConsentStore persistence --------------------------------

    fn test_master() -> MasterKey {
        MasterKey::from_bytes_for_test([7u8; AEAD_KEY_LEN])
    }

    #[test]
    fn consent_persists_across_reload() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = test_master();

        let mut store = BridgeConsentStore::load(&layout, &master, 0, None);
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        store.set(g("group2"), GroupBridgeConsent::DeclinedOptOut);
        drop(store);

        let reloaded = BridgeConsentStore::load(&layout, &master, 0, None);
        assert_eq!(
            reloaded.lookup(&g("group1")),
            GroupBridgeConsent::ConsentedOptIn,
        );
        assert_eq!(
            reloaded.lookup(&g("group2")),
            GroupBridgeConsent::DeclinedOptOut,
        );
        assert_eq!(reloaded.lookup(&g("group3")), GroupBridgeConsent::NotAsked);
    }

    #[test]
    fn load_with_wrong_key_falls_back_to_empty() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let mut store = BridgeConsentStore::load(&layout, &test_master(), 0, None);
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        drop(store);

        // A different master cannot open the sealed file; load must fall
        // back to an empty (all-NotAsked) map, never error.
        let wrong = MasterKey::from_bytes_for_test([9u8; AEAD_KEY_LEN]);
        let reloaded = BridgeConsentStore::load(&layout, &wrong, 0, None);
        assert_eq!(reloaded.lookup(&g("group1")), GroupBridgeConsent::NotAsked);
    }

    #[test]
    fn load_corrupt_file_falls_back_to_empty() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        // Garbage where a sealed vault is expected.
        std::fs::write(layout.bridge_consent_path(), b"not a vault file").unwrap();

        let store = BridgeConsentStore::load(&layout, &test_master(), 0, None);
        assert_eq!(store.lookup(&g("group1")), GroupBridgeConsent::NotAsked);
    }

    #[test]
    fn forget_persists_removal() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = test_master();

        let mut store = BridgeConsentStore::load(&layout, &master, 0, None);
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        store.forget(&g("group1"));
        drop(store);

        let reloaded = BridgeConsentStore::load(&layout, &master, 0, None);
        assert_eq!(reloaded.lookup(&g("group1")), GroupBridgeConsent::NotAsked);
    }

    #[test]
    fn new_store_never_touches_disk() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        // new() carries no persistence handle: mutations stay in memory
        // and must not create the consent file.
        let mut store = BridgeConsentStore::new();
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        assert_eq!(
            store.lookup(&g("group1")),
            GroupBridgeConsent::ConsentedOptIn,
        );
        assert!(!layout.bridge_consent_path().exists());
    }

    #[test]
    fn set_leaves_no_tmp_siblings() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let mut store = BridgeConsentStore::load(&layout, &test_master(), 0, None);
        store.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);

        // seal_to_path renames its tmp into place; no debris remains.
        let leftovers: Vec<_> = std::fs::read_dir(&layout.bridge_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "unexpected tmp files: {leftovers:?}");
    }

    #[test]
    fn route_reachable_always_lets_gossip_carry() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        // Even if consent is `DeclinedOptOut`, a Reachable peer doesn't
        // need the bridge — the routing rule short-circuits before
        // consulting consent.
        let mut consent = BridgeConsentStore::new();
        consent.set(g("group1"), GroupBridgeConsent::DeclinedOptOut);
        assert_eq!(
            decide_route(&cache, &consent, &g("group1"), &a("alice"), 1_000_500),
            BridgeDecision::LetGossipCarry,
        );
    }

    #[test]
    fn route_unreachable_consented_wraps_and_sends() {
        let cache = ReachabilityCache::new();
        let mut consent = BridgeConsentStore::new();
        consent.set(g("group1"), GroupBridgeConsent::ConsentedOptIn);
        assert_eq!(
            decide_route(&cache, &consent, &g("group1"), &a("alice"), 1_000_500),
            BridgeDecision::WrapAndSend,
        );
    }

    #[test]
    fn route_unreachable_declined_drops() {
        let cache = ReachabilityCache::new();
        let mut consent = BridgeConsentStore::new();
        consent.set(g("group1"), GroupBridgeConsent::DeclinedOptOut);
        assert_eq!(
            decide_route(&cache, &consent, &g("group1"), &a("alice"), 1_000_500),
            BridgeDecision::DropDeclined,
        );
    }

    #[test]
    fn route_unreachable_not_asked_prompts_consent() {
        let cache = ReachabilityCache::new();
        let consent = BridgeConsentStore::new();
        assert_eq!(
            decide_route(&cache, &consent, &g("group1"), &a("alice"), 1_000_500),
            BridgeDecision::PromptConsent,
        );
    }

    #[test]
    fn route_stale_record_falls_through_to_consent() {
        let mut cache = ReachabilityCache::new();
        cache.record(g("group1"), a("alice"), 1_000_000);
        // Stale window has elapsed → Unreachable → falls through to
        // consent lookup; with no consent set, prompts.
        let consent = BridgeConsentStore::new();
        assert_eq!(
            decide_route(
                &cache,
                &consent,
                &g("group1"),
                &a("alice"),
                1_000_000 + STALE_AFTER_MS + 1,
            ),
            BridgeDecision::PromptConsent,
        );
    }

    // ── BridgeInboundShadow ───────────────────────────────────────────

    #[test]
    fn shadow_default_is_empty_and_misses_lookup() {
        let shadow = BridgeInboundShadow::new();
        assert!(shadow.is_empty());
        assert_eq!(shadow.len(), 0);
        assert!(!shadow.is_recent(42, 1_000_000));
    }

    #[test]
    fn shadow_mark_hits_within_window() {
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(42, 1_000_000);
        assert!(shadow.is_recent(42, 1_000_500));
        // Boundary: SHADOW_WINDOW_MS - 1 is still recent.
        assert!(shadow.is_recent(42, 1_000_000 + SHADOW_WINDOW_MS - 1));
    }

    #[test]
    fn shadow_mark_misses_at_window_boundary() {
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(42, 1_000_000);
        // Boundary exclusive — at SHADOW_WINDOW_MS exactly, treated as expired.
        assert!(!shadow.is_recent(42, 1_000_000 + SHADOW_WINDOW_MS));
    }

    #[test]
    fn shadow_mark_misses_past_window() {
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(42, 1_000_000);
        assert!(!shadow.is_recent(42, 1_000_000 + SHADOW_WINDOW_MS + 1));
    }

    #[test]
    fn shadow_mark_only_matches_exact_hash() {
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(42, 1_000_000);
        assert!(!shadow.is_recent(43, 1_000_500));
    }

    #[test]
    fn shadow_clock_skew_backward_still_recent() {
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(42, 2_000_000);
        // saturating_sub treats backward skew as 0 elapsed → recent.
        assert!(shadow.is_recent(42, 1_000_000));
    }

    #[test]
    fn shadow_evict_older_than_drops_expired() {
        // Timestamps expressed relative to a `t0` anchor so the test
        // stays valid as `SHADOW_WINDOW_MS` evolves. `evict_older_than`
        // bounds memory; it is independent of `is_recent`'s lookup
        // window. Drop entries older than `2 * SHADOW_WINDOW_MS` to
        // verify both: an entry inside the lookup window survives both
        // checks, and an entry past the eviction cutoff is gone.
        let t0 = 1_000_000_u64;
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(1, t0); // ancient — should be evicted
        shadow.mark(2, t0 + 3 * SHADOW_WINDOW_MS); // recent — should survive both
        shadow.mark(3, t0 + 3 * SHADOW_WINDOW_MS + 100);
        assert_eq!(shadow.len(), 3);
        let now = t0 + 3 * SHADOW_WINDOW_MS + 200;
        shadow.evict_older_than(now, 2 * SHADOW_WINDOW_MS);
        assert_eq!(shadow.len(), 2, "ancient entry dropped");
        assert!(!shadow.is_recent(1, now), "ancient entry not recent");
        assert!(
            shadow.is_recent(2, now),
            "recent entry still inside lookup window"
        );
        assert!(shadow.is_recent(3, now));
    }

    #[test]
    fn shadow_re_mark_refreshes_timestamp() {
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(42, 1_000_000);
        // Re-mark at a later timestamp; lookup at a moment past the
        // original window should still resolve recent.
        shadow.mark(42, 1_000_000 + SHADOW_WINDOW_MS + 10);
        assert!(shadow.is_recent(42, 1_000_000 + SHADOW_WINDOW_MS + 100));
        assert_eq!(shadow.len(), 1, "no duplicate row");
    }

    // ── hash_payload ──────────────────────────────────────────────────

    #[test]
    fn hash_payload_stable_for_same_input() {
        let a = hash_payload(b"hello");
        let b = hash_payload(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_payload_differs_for_different_input() {
        let a = hash_payload(b"hello");
        let b = hash_payload(b"world");
        assert_ne!(a, b);
    }

    // ── group_id_from_metadata_topic ──────────────────────────────────

    #[test]
    fn topic_parser_extracts_valid_group_id() {
        let topic = "x0x.named_group/group-abc_123/metadata";
        let gid = group_id_from_metadata_topic(topic).unwrap();
        assert_eq!(gid.as_str(), "group-abc_123");
    }

    #[test]
    fn topic_parser_rejects_non_metadata_suffix() {
        assert!(group_id_from_metadata_topic("x0x.named_group/g/chat").is_none());
        assert!(group_id_from_metadata_topic("x0x.named_group/g").is_none());
    }

    #[test]
    fn topic_parser_rejects_wrong_prefix() {
        assert!(group_id_from_metadata_topic("presence/g/metadata").is_none());
        assert!(group_id_from_metadata_topic("named_group/g/metadata").is_none());
    }

    #[test]
    fn topic_parser_rejects_path_traversal_in_segment() {
        // `..` is rejected by GroupId::parse (only [a-zA-Z0-9_-] allowed),
        // so even though the prefix/suffix shape matches, the inner
        // segment fails validation.
        assert!(group_id_from_metadata_topic("x0x.named_group/../metadata").is_none());
        assert!(group_id_from_metadata_topic("x0x.named_group/a/b/metadata").is_none());
    }

    #[test]
    fn topic_parser_rejects_empty_group_id() {
        assert!(group_id_from_metadata_topic("x0x.named_group//metadata").is_none());
    }

    // ── classify_sse_event ────────────────────────────────────────────

    /// Helper: local agent's hex string used as the "self" identity in
    /// the classify tests.
    fn local_hex() -> String {
        "0".repeat(64)
    }

    #[test]
    fn classify_records_real_gossip_event() {
        let shadow = BridgeInboundShadow::new();
        let topic = "x0x.named_group/group1/metadata";
        let payload = b"signed-event-bytes-from-remote-peer";
        let from = AgentId("ff".repeat(32));
        let result = classify_sse_event(
            topic,
            payload,
            Some(&from),
            &local_hex(),
            &shadow,
            1_000_000,
        );
        let (group, member) = result.expect("real gossip event must record");
        assert_eq!(group.as_str(), "group1");
        assert_eq!(member.0, from.0);
    }

    #[test]
    fn classify_skips_self_publish_loopback() {
        let shadow = BridgeInboundShadow::new();
        let local = local_hex();
        let from = AgentId(local.clone());
        // Our own /publish loopback: from == local_agent_hex.
        let result = classify_sse_event(
            "x0x.named_group/group1/metadata",
            b"any-payload",
            Some(&from),
            &local,
            &shadow,
            1_000_000,
        );
        assert!(
            result.is_none(),
            "self-publish loopback must not record reachability",
        );
    }

    /// x0xd's `/agent` and `/events` surfaces can disagree on hex
    /// casing for the same agent id (see M2 `messages.rs` which uses
    /// `eq_ignore_ascii_case` against the same class of comparison).
    /// A case-sensitive equality at the loopback skip would miss the
    /// self-publish frame and falsely promote `(group, self)` to
    /// `Reachable` — exactly the silent-fail the bridge exists to
    /// avoid. Pin the case-insensitive contract here.
    #[test]
    fn classify_skips_self_publish_loopback_under_mixed_case() {
        let shadow = BridgeInboundShadow::new();
        let lower = "deadbeefcafe".to_string() + &"0".repeat(52);
        let upper = lower.to_ascii_uppercase();
        // Local stored as lowercase, SSE `from` arrives uppercase.
        let from = AgentId(upper.clone());
        let result = classify_sse_event(
            "x0x.named_group/group1/metadata",
            b"any-payload",
            Some(&from),
            &lower,
            &shadow,
            1_000_000,
        );
        assert!(
            result.is_none(),
            "mixed-case self-publish loopback must still skip",
        );
        // And vice versa (local stored uppercase, SSE from lowercase).
        let from = AgentId(lower.clone());
        let result = classify_sse_event(
            "x0x.named_group/group1/metadata",
            b"any-payload",
            Some(&from),
            &upper,
            &shadow,
            1_000_000,
        );
        assert!(
            result.is_none(),
            "mixed-case self-publish loopback must still skip (reverse direction)",
        );
    }

    #[test]
    fn classify_skips_bridge_loopback_within_window() {
        let mut shadow = BridgeInboundShadow::new();
        let payload = b"sealed-bridge-payload-bytes";
        let h = hash_payload(payload);
        shadow.mark(h, 1_000_000);

        let from = AgentId("ff".repeat(32));
        let result = classify_sse_event(
            "x0x.named_group/group1/metadata",
            payload,
            Some(&from),
            &local_hex(),
            &shadow,
            1_000_500,
        );
        assert!(
            result.is_none(),
            "bridge-loopback event within shadow window must not record",
        );
    }

    #[test]
    fn classify_records_after_shadow_window_elapses() {
        let mut shadow = BridgeInboundShadow::new();
        let payload = b"sealed-bridge-payload-bytes";
        shadow.mark(hash_payload(payload), 1_000_000);
        let from = AgentId("ff".repeat(32));
        // A FOLLOW-UP event from the same peer past the shadow window
        // is genuine gossip — record it.
        let result = classify_sse_event(
            "x0x.named_group/group1/metadata",
            payload,
            Some(&from),
            &local_hex(),
            &shadow,
            1_000_000 + SHADOW_WINDOW_MS + 1,
        );
        assert!(
            result.is_some(),
            "post-window event must record once shadow expires",
        );
    }

    #[test]
    fn classify_skips_when_from_is_none() {
        let shadow = BridgeInboundShadow::new();
        // x0xd sometimes emits frames with `from = None` (anonymous /
        // unauthenticated gossip). The reachability key needs a
        // member, so skip cleanly.
        let result = classify_sse_event(
            "x0x.named_group/group1/metadata",
            b"any-payload",
            None,
            &local_hex(),
            &shadow,
            1_000_000,
        );
        assert!(result.is_none());
    }

    #[test]
    fn classify_skips_wrong_topic_shape() {
        let shadow = BridgeInboundShadow::new();
        let from = AgentId("ff".repeat(32));
        // Not a metadata topic (chat content, presence, etc.) — the
        // reachability cache only tracks group-metadata flows.
        let result = classify_sse_event(
            "presence/group1/online",
            b"any-payload",
            Some(&from),
            &local_hex(),
            &shadow,
            1_000_000,
        );
        assert!(result.is_none());
    }

    #[test]
    fn classify_skips_traversal_in_topic_segment() {
        let shadow = BridgeInboundShadow::new();
        let from = AgentId("ff".repeat(32));
        // Path-traversal characters inside the group-id segment fail
        // GroupId::parse and so cleanly skip — we do NOT want path
        // poisoning to reach the reachability key.
        let result = classify_sse_event(
            "x0x.named_group/../metadata",
            b"any-payload",
            Some(&from),
            &local_hex(),
            &shadow,
            1_000_000,
        );
        assert!(result.is_none());
    }

    /// End-to-end semantics check: simulate the symmetric-NAT bridge
    /// loopback that the spec §5 design relies on suppressing. Without
    /// the shadow filter the cache would falsely flip to `Reachable`
    /// and the next send would silently fail by routing
    /// `LetGossipCarry` into a dead gossip path.
    #[test]
    fn classify_under_symmetric_nat_bridge_loopback_does_not_promote_reachable() {
        let mut shadow = BridgeInboundShadow::new();
        let mut cache = ReachabilityCache::new();

        let topic = "x0x.named_group/groupA/metadata";
        let payload = b"sealed-signed-member-joined-event-bytes";
        let alice = AgentId("aa".repeat(32));
        let now = 1_000_000;

        // Bridge dispatcher: mark shadow before POST /publish.
        shadow.mark(hash_payload(payload), now);

        // SSE consumer fires next, picks up the loopback frame.
        let decision = classify_sse_event(
            topic,
            payload,
            Some(&alice),
            &local_hex(),
            &shadow,
            now + 50, // 50 ms after the mark, well within SHADOW_WINDOW_MS
        );
        assert!(decision.is_none(), "loopback must not record");

        // Cache stays Unreachable for (groupA, alice). The next send
        // path will hit BridgeConsentStore::lookup → WrapAndSend (after
        // consent), which is the only delivery shape that actually
        // works on a symmetric-NAT pair.
        let group = GroupId::parse("groupA").unwrap();
        assert_eq!(
            cache.lookup(&group, &alice, now + 100),
            Reachability::Unreachable,
        );

        // Belt-and-suspenders: if a *later* genuine direct-gossip frame
        // arrives outside the window, it MUST be allowed to record.
        let later_payload = b"a-different-signed-event-bytes";
        let later = now + SHADOW_WINDOW_MS + 1_000;
        let decision = classify_sse_event(
            topic,
            later_payload,
            Some(&alice),
            &local_hex(),
            &shadow,
            later,
        );
        let (group_back, member_back) = decision.expect("post-window must record");
        cache.record(group_back, member_back, later);
        assert_eq!(
            cache.lookup(&group, &alice, later + 10),
            Reachability::Reachable,
            "post-window real gossip must promote to Reachable",
        );
    }
}
