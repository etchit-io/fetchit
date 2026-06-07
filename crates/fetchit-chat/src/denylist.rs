//! Pluggable denylist check trait.
//!
//! Inverts the dependency between `fetchit-chat` and `fetchit-trust`:
//! the chat crate names a small async trait, and any consumer (the
//! signed denylist polling client in `fetchit-trust::consumer`, or a
//! test stub) supplies an implementation. Keeps `fetchit-chat`
//! denylist-source-agnostic and avoids pulling `axum` into the chat
//! tree just to consume a published list.
//!
//! # Where it's used
//!
//! Two chokepoints in [`crate::Client`]:
//!
//! - DM outbound: [`crate::messages::Endpoint::send`] returns
//!   [`crate::ChatError::Denied`] when the recipient is blocked.
//! - Inbound dispatcher: [`crate::Client::default_dispatch_one`]
//!   silently drops envelopes whose sender is blocked, BEFORE any
//!   decrypt path runs (preserves "no plaintext leak" semantics).
//!
//! Group sends are not gated at the sender side; the receiver-side
//! inbound gate is what makes blocking effective for group traffic.

use async_trait::async_trait;
use std::sync::Arc;

/// Decide whether a given peer is on the community denylist.
///
/// `is_blocked` MUST be cheap (read-lock or in-memory map): it runs
/// on every outbound DM send and every inbound delivery.
///
/// Convention: `agent_id_hex` is the lowercase 64-character hex of
/// the peer's ML-DSA-65 public-key fingerprint, matching the format
/// used everywhere else in the chat layer.
#[async_trait]
pub trait DenylistCheck: Send + Sync {
    /// True when the peer is currently blocked. Fail-open on cache
    /// misses or transient errors is the consumer's responsibility
    /// (the published manifest is the source of truth; an empty
    /// cache returns `false`).
    async fn is_blocked(&self, agent_id_hex: &str) -> bool;

    /// M4 Stage 4.2 extension: true when the fediverse actor URL
    /// is currently blocked. The fediverse-inbox path
    /// ([`crate::denylist::DenylistQueryAdapter`] + the M4 Stage 3
    /// inbox gate) calls this for every inbound activity's signing
    /// actor URL; chat-only consumers ignore.
    ///
    /// `actor_url` is the **canonical-form** URL produced by
    /// `fetchit_trust::TargetIdentity::try_new(EntryKind::ActorUrl, ...)`
    /// — lowercased, no fragment, no query string, no userinfo, no
    /// trailing slash on non-root paths. Callers that have not
    /// already canonicalized MUST do so before calling, otherwise
    /// the match against the canonical denylist entry will silently
    /// miss.
    ///
    /// Default impl returns `false` so existing agent-only
    /// consumers (test stubs, future single-purpose implementations)
    /// keep working unchanged.
    async fn is_blocked_actor(&self, _actor_url: &str) -> bool {
        false
    }
}

/// Bridges any [`fetchit_trust::DenylistQuery`] impl into the
/// [`DenylistCheck`] async trait the chat client expects.
///
/// The chat surface only ever asks about agent identifiers, so the
/// adapter pins the underlying query to
/// [`fetchit_trust::EntryKind::AgentId`]. Hits against other kinds
/// (`RelayUrl`, `XorName`, `ActorUrl`) are NOT surfaced as agent
/// blocks: that's a security property of the adapter, not an
/// accident, and is covered by a dedicated test below.
///
/// `DenylistQuery::is_blocked` is synchronous (in-memory snapshot);
/// the async on [`DenylistCheck::is_blocked`] satisfies the trait
/// signature but never actually awaits.
pub struct DenylistQueryAdapter {
    inner: Arc<dyn fetchit_trust::DenylistQuery>,
}

impl DenylistQueryAdapter {
    /// Wrap an `Arc<dyn DenylistQuery>` for use as a [`DenylistCheck`].
    /// The canonical inner is
    /// [`fetchit_trust_client::DenylistConsumer`].
    #[must_use]
    pub fn new(inner: Arc<dyn fetchit_trust::DenylistQuery>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl DenylistCheck for DenylistQueryAdapter {
    async fn is_blocked(&self, agent_id_hex: &str) -> bool {
        self.inner
            .is_blocked(fetchit_trust::EntryKind::AgentId, agent_id_hex)
    }

    async fn is_blocked_actor(&self, actor_url: &str) -> bool {
        self.inner
            .is_blocked(fetchit_trust::EntryKind::ActorUrl, actor_url)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// In-memory denylist for tests. Lets each test seed the set it
    /// wants without standing up the HTTPS consumer.
    pub(crate) struct StaticDenylist {
        blocked: Mutex<HashSet<String>>,
    }

    impl StaticDenylist {
        pub(crate) fn new<I, S>(entries: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                blocked: Mutex::new(entries.into_iter().map(Into::into).collect()),
            }
        }
    }

    #[async_trait]
    impl DenylistCheck for StaticDenylist {
        async fn is_blocked(&self, agent_id_hex: &str) -> bool {
            self.blocked.lock().unwrap().contains(agent_id_hex)
        }
    }

    #[tokio::test]
    async fn static_denylist_round_trip() {
        let d = StaticDenylist::new(["a".repeat(64), "b".repeat(64)]);
        assert!(d.is_blocked(&"a".repeat(64)).await);
        assert!(d.is_blocked(&"b".repeat(64)).await);
        assert!(!d.is_blocked(&"c".repeat(64)).await);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod adapter_tests {
    use super::*;
    use fetchit_trust::{DenylistQuery, EntryKind};
    use std::sync::Arc;

    struct BlocksAgent(&'static str);
    impl DenylistQuery for BlocksAgent {
        fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
            matches!(kind, EntryKind::AgentId) && value == self.0
        }
    }

    /// `AgentId` hits in the underlying `DenylistQuery` surface as
    /// chat-layer agent blocks.
    #[tokio::test]
    async fn adapter_delegates_agent_id_block_through() {
        let inner: Arc<dyn DenylistQuery> = Arc::new(BlocksAgent("evil"));
        let adapter = DenylistQueryAdapter::new(inner);
        assert!(adapter.is_blocked("evil").await);
        assert!(!adapter.is_blocked("good").await);
    }

    /// Security property: the adapter pins the kind to
    /// `EntryKind::AgentId`. A `DenylistQuery` that only returns true
    /// for some OTHER kind (here, `XorName`) MUST NOT bleed through
    /// as an agent block: otherwise a reader-side `XorName` block
    /// would silently propagate to chat agent gating.
    #[tokio::test]
    async fn adapter_only_checks_agent_id_kind() {
        struct BlocksXorName;
        impl DenylistQuery for BlocksXorName {
            fn is_blocked(&self, kind: EntryKind, _value: &str) -> bool {
                matches!(kind, EntryKind::XorName)
            }
        }
        let adapter: DenylistQueryAdapter = DenylistQueryAdapter::new(Arc::new(BlocksXorName));
        assert!(!adapter.is_blocked("anything").await);
    }

    // ---- M4 Stage 4.2: is_blocked_actor extension ----

    /// `ActorUrl` hits in the underlying `DenylistQuery` surface as
    /// chat-layer actor blocks.
    #[tokio::test]
    async fn adapter_delegates_actor_url_block_through() {
        struct BlocksActor(&'static str);
        impl DenylistQuery for BlocksActor {
            fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
                matches!(kind, EntryKind::ActorUrl) && value == self.0
            }
        }
        let inner: Arc<dyn DenylistQuery> =
            Arc::new(BlocksActor("https://attacker.example/users/eve"));
        let adapter = DenylistQueryAdapter::new(inner);
        assert!(
            adapter
                .is_blocked_actor("https://attacker.example/users/eve")
                .await
        );
        assert!(
            !adapter
                .is_blocked_actor("https://mastodon.example/users/alice")
                .await
        );
    }

    /// Security mirror of `adapter_only_checks_agent_id_kind`: the
    /// `is_blocked_actor` arm pins to `EntryKind::ActorUrl`. A
    /// `DenylistQuery` that blocks `RelayUrl` / `XorName` / `AgentId`
    /// MUST NOT bleed through as an actor-URL block — otherwise an
    /// unrelated denylist entry of another kind would silently gate
    /// the fediverse-inbox path.
    #[tokio::test]
    async fn adapter_only_checks_actor_url_kind() {
        struct BlocksRelayAndAgent;
        impl DenylistQuery for BlocksRelayAndAgent {
            fn is_blocked(&self, kind: EntryKind, _value: &str) -> bool {
                matches!(kind, EntryKind::RelayUrl | EntryKind::AgentId)
            }
        }
        let adapter: DenylistQueryAdapter =
            DenylistQueryAdapter::new(Arc::new(BlocksRelayAndAgent));
        assert!(
            !adapter
                .is_blocked_actor("https://mastodon.example/users/eve")
                .await
        );
        // The cross-arm: same inner blocks AgentId so the
        // `is_blocked` path WOULD return true, but
        // `is_blocked_actor` MUST not.
        assert!(adapter.is_blocked("anything").await);
    }

    /// The default trait impl returns `false`. Chat-only
    /// implementations (`StaticDenylist` in tests, future
    /// purpose-built consumers) don't need to override unless they
    /// actually carry actor data — confirms the back-compat
    /// guarantee.
    #[tokio::test]
    async fn default_is_blocked_actor_impl_returns_false() {
        let d = super::tests::StaticDenylist::new(["a".repeat(64)]);
        assert!(d.is_blocked(&"a".repeat(64)).await);
        // No override → default → false even for the agent hex
        // string passed as an actor URL.
        assert!(!d.is_blocked_actor(&"a".repeat(64)).await);
        assert!(
            !d.is_blocked_actor("https://anywhere.example/users/anyone")
                .await
        );
    }
}
