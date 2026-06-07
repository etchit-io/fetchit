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
}
