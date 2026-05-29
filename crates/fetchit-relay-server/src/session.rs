//! Registry of currently-connected sessions.

use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, Bye, ByeReason, ServerFrame};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::UnboundedSender;

/// Monotonic per-registration token.
///
/// Each successful `register` mints a fresh `SessionId`. The caller must
/// pass the same id back to `unregister`; a stale id is a no-op. This
/// closes the race where a displaced connection's exit handler would
/// otherwise tear down the newer entry that overwrote it.
pub type SessionId = u64;

/// Maps an agent id to the channel its live WebSocket reads from.
#[derive(Default)]
pub struct SessionRegistry {
    by_agent: DashMap<AgentId, (SessionId, UnboundedSender<ServerFrame>)>,
    next_id: AtomicU64,
}

impl SessionRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `agent` to the supplied outbound channel.
    ///
    /// Returns the [`SessionId`] the caller must hand back to
    /// [`Self::unregister`] for the removal to take effect. Any prior
    /// registration is displaced: the displaced channel receives a
    /// `Bye(DisplacedByNewSession)` (best-effort; a closed channel is
    /// silently ignored) before being dropped from the map.
    pub fn register(&self, agent: AgentId, tx: UnboundedSender<ServerFrame>) -> SessionId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let prior = self.by_agent.insert(agent, (id, tx));
        if let Some((_, prior_tx)) = prior {
            let _ = prior_tx.send(ServerFrame::Bye(Bye {
                reason: ByeReason::DisplacedByNewSession,
            }));
        }
        id
    }

    /// Drop `agent`'s registration only if `id` matches the current entry.
    ///
    /// No-op when the entry has already been overwritten by a newer
    /// `register` — the displaced connection's exit must not tear down
    /// the connection that displaced it.
    pub fn unregister(&self, agent: &AgentId, id: SessionId) {
        self.by_agent
            .remove_if(agent, |_, (current_id, _)| *current_id == id);
    }

    /// Push a frame to `agent` if connected. Returns true if delivered.
    #[must_use]
    pub fn send(&self, agent: &AgentId, frame: ServerFrame) -> bool {
        let Some(entry) = self.by_agent.get(agent) else {
            return false;
        };
        let (_, tx) = entry.value();
        tx.send(frame).is_ok()
    }

    /// Count of currently-connected agents.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.by_agent.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_proto::{Bye, ByeReason, ServerFrame};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn send_routes_to_registered_agent() {
        let r = SessionRegistry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let a = AgentId::from_bytes([1u8; 32]);
        let _id = r.register(a, tx);

        let frame = ServerFrame::Bye(Bye {
            reason: ByeReason::ServerShutdown,
        });
        assert!(r.send(&a, frame.clone()));
        assert_eq!(rx.recv().await, Some(frame));
    }

    #[test]
    fn send_returns_false_for_unknown_agent() {
        let r = SessionRegistry::new();
        let a = AgentId::from_bytes([2u8; 32]);
        let frame = ServerFrame::Bye(Bye {
            reason: ByeReason::ServerShutdown,
        });
        assert!(!r.send(&a, frame));
    }

    #[tokio::test]
    async fn unregister_with_matching_id_removes() {
        let r = SessionRegistry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let a = AgentId::from_bytes([3u8; 32]);
        let id = r.register(a, tx);
        assert_eq!(r.connection_count(), 1);
        r.unregister(&a, id);
        assert_eq!(r.connection_count(), 0);
    }

    #[tokio::test]
    async fn register_twice_displaces_first_with_bye() {
        let r = SessionRegistry::new();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let a = AgentId::from_bytes([4u8; 32]);

        let _id1 = r.register(a, tx1);
        let _id2 = r.register(a, tx2);

        let received = rx1.recv().await.expect("displaced tx receives Bye");
        match received {
            ServerFrame::Bye(Bye { reason }) => {
                assert_eq!(reason, ByeReason::DisplacedByNewSession);
            }
            other => panic!("expected Bye(DisplacedByNewSession), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unregister_with_stale_id_is_noop() {
        let r = SessionRegistry::new();
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let a = AgentId::from_bytes([5u8; 32]);

        let id1 = r.register(a, tx1);
        let _id2 = r.register(a, tx2);

        // Displaced connection's exit handler runs with the stale id.
        r.unregister(&a, id1);

        // The newer entry must still be present.
        assert_eq!(r.connection_count(), 1);
    }

    #[tokio::test]
    async fn send_still_routes_after_displaced_unregister() {
        let r = SessionRegistry::new();
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let a = AgentId::from_bytes([6u8; 32]);

        let id1 = r.register(a, tx1);
        let _id2 = r.register(a, tx2);
        // Drop the displaced tx's stale registration; the newer one stays.
        r.unregister(&a, id1);

        let frame = ServerFrame::Bye(Bye {
            reason: ByeReason::ServerShutdown,
        });
        assert!(r.send(&a, frame.clone()));
        assert_eq!(rx2.recv().await, Some(frame));
    }
}
