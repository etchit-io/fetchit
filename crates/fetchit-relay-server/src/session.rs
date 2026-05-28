//! Registry of currently-connected sessions.

use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, ServerFrame};
use tokio::sync::mpsc::UnboundedSender;

/// Maps an agent id to the channel its live WebSocket reads from.
#[derive(Default)]
pub struct SessionRegistry {
    by_agent: DashMap<AgentId, UnboundedSender<ServerFrame>>,
}

impl SessionRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `agent` to the supplied outbound channel, displacing any
    /// previous connection for the same agent.
    pub fn register(&self, agent: AgentId, tx: UnboundedSender<ServerFrame>) {
        self.by_agent.insert(agent, tx);
    }

    /// Drop `agent`'s registration if any.
    pub fn unregister(&self, agent: &AgentId) {
        self.by_agent.remove(agent);
    }

    /// Push a frame to `agent` if connected. Returns true if delivered.
    #[must_use]
    pub fn send(&self, agent: &AgentId, frame: ServerFrame) -> bool {
        let Some(tx) = self.by_agent.get(agent) else {
            return false;
        };
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
        r.register(a, tx);

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

    #[test]
    fn unregister_removes_the_binding() {
        let r = SessionRegistry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let a = AgentId::from_bytes([3u8; 32]);
        r.register(a, tx);
        assert_eq!(r.connection_count(), 1);
        r.unregister(&a);
        assert_eq!(r.connection_count(), 0);
    }
}
