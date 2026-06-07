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
//!   decrypt path runs — preserves "no plaintext leak" semantics.
//!
//! Group sends are not gated at the sender side; the receiver-side
//! inbound gate is what makes blocking effective for group traffic.

use async_trait::async_trait;

/// Decide whether a given peer is on the community denylist.
///
/// `is_blocked` MUST be cheap (read-lock or in-memory map) — it runs
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
