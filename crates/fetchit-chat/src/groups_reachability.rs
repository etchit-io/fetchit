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
//! # Scaffolding status (C4)
//!
//! This file ships the typed surface + in-memory operations + the routing
//! decision. Persistence under the conversation-registry at-rest key, and
//! the wire-in points on the sender (C2) / receiver (C3) paths, land in
//! follow-up commits once C2/C3 agree on the call shape. The contract
//! exposed here is stable from C4 onward.

use crate::groups::GroupId;
use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
/// 60 s is the C4 placeholder. The spec leaves the exact value tunable;
/// C5 integration tests against a running x0xd will calibrate it against
/// the typical x0xd publish→subscribe round-trip on a healthy mesh.
pub const STALE_AFTER_MS: u64 = 60_000;

/// In-memory cache of last-seen direct-gossip activity per
/// `(group, member)`. Designed to persist alongside
/// `crate::conversation::ConversationRegistry` under the same at-rest key
/// (C4 persistence wiring is a follow-up commit).
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

/// In-memory store of per-group bridge-consent state. Designed to persist
/// alongside `crate::conversation::ConversationRegistry` under the same
/// at-rest key (C4 persistence wiring is a follow-up commit).
#[derive(Debug, Default)]
pub struct BridgeConsentStore {
    inner: HashMap<GroupId, GroupBridgeConsent>,
}

impl BridgeConsentStore {
    /// Empty store. Equivalent to `Default`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    /// Persist consent state for `group`. Called by the desktop UI after
    /// the consent modal resolves, or by tests / migration paths.
    pub fn set(&mut self, group: GroupId, state: GroupBridgeConsent) {
        self.inner.insert(group, state);
    }

    /// Forget consent for `group` — used when the group is left or
    /// permanently deleted.
    pub fn forget(&mut self, group: &GroupId) {
        self.inner.remove(group);
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
pub const SHADOW_WINDOW_MS: u64 = 5_000;

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
/// C4 scaffolding contract: callers `mark` before `POST /publish` and
/// `is_recent_and_evict` from the SSE consumer hot path. Periodic
/// `evict_older_than` is OK but optional — entries beyond
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
/// 2. `from == local_agent_hex` — our own /publish loopback.
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
    if from.0 == local_agent_hex {
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
        let mut shadow = BridgeInboundShadow::new();
        shadow.mark(1, 1_000);
        shadow.mark(2, 5_000);
        shadow.mark(3, 9_000);
        assert_eq!(shadow.len(), 3);
        shadow.evict_older_than(10_000, 6_000);
        // Keep only entries newer than 10_000 - 6_000 = 4_000
        assert_eq!(shadow.len(), 2);
        assert!(!shadow.is_recent(1, 10_000));
        // hash=2 still inside SHADOW_WINDOW_MS window relative to its
        // own mark time? mark=5000, now=10000, elapsed=5000 > 5000 = false
        // so is_recent returns false even though evict kept the entry.
        // (Eviction cutoff != lookup window; they bound different things.)
        assert!(!shadow.is_recent(2, 10_000));
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
