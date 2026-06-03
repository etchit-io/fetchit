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
}
