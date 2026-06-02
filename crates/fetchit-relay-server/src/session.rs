//! Registry of currently-connected sessions and per-connection presence watchers.

use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, Bye, ByeReason, PresenceUpdate, ServerFrame};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::Sender;

/// Monotonic per-registration token.
///
/// Each successful `register` mints a fresh `SessionId`. The caller must
/// pass the same id back to `unregister`; a stale id is a no-op. This
/// closes the race where a displaced connection's exit handler would
/// otherwise tear down the newer entry that overwrote it.
pub type SessionId = u64;

/// Maps an agent id to its live WebSocket channel, plus the per-connection
/// presence watch index.
#[derive(Default)]
pub struct SessionRegistry {
    by_agent: DashMap<AgentId, (SessionId, Sender<ServerFrame>)>,
    next_id: AtomicU64,
    /// For each watched agent, the live watchers subscribed to its
    /// presence transitions. Stored alongside each watcher's outbound
    /// channel so broadcasts don't need a second lookup.
    watchers: DashMap<AgentId, Vec<(SessionId, Sender<ServerFrame>)>>,
    /// Reverse index: agents each session is currently watching. Used to
    /// drop a session's subscriptions in O(watch-set-size) when the
    /// connection disconnects.
    watches_by_session: DashMap<SessionId, HashSet<AgentId>>,
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
    ///
    /// Emits `PresenceUpdate { online: true }` to all subscribed watchers
    /// only when this is a transition from "no entry" to "live entry"
    /// — a displacement leaves the agent's online state unchanged.
    pub fn register(&self, agent: AgentId, tx: Sender<ServerFrame>) -> SessionId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let prior = self.by_agent.insert(agent, (id, tx));
        if let Some((_, prior_tx)) = prior {
            let _ = prior_tx.try_send(ServerFrame::Bye(Bye {
                reason: ByeReason::DisplacedByNewSession,
            }));
        } else {
            self.broadcast_presence(agent, true);
        }
        id
    }

    /// Drop `agent`'s registration only if `id` matches the current entry.
    ///
    /// No-op when the entry has already been overwritten by a newer
    /// `register` — the displaced connection's exit must not tear down
    /// the connection that displaced it.
    ///
    /// When the entry is actually removed, emits
    /// `PresenceUpdate { online: false }` to all subscribed watchers.
    pub fn unregister(&self, agent: &AgentId, id: SessionId) {
        let removed = self
            .by_agent
            .remove_if(agent, |_, (current_id, _)| *current_id == id);
        if removed.is_some() {
            self.broadcast_presence(*agent, false);
        }
    }

    /// Push a frame to `agent` if connected. Returns true if delivered.
    ///
    /// Returns `false` when the agent has no live session OR when the
    /// per-connection outbound queue is full — both signal "could not
    /// deliver inline; caller should fall back to transit buffering".
    #[must_use]
    pub fn send(&self, agent: &AgentId, frame: ServerFrame) -> bool {
        let Some(entry) = self.by_agent.get(agent) else {
            return false;
        };
        let (_, tx) = entry.value();
        tx.try_send(frame).is_ok()
    }

    /// Count of currently-connected agents.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.by_agent.len()
    }

    /// `true` when `agent` currently has a live session.
    #[must_use]
    pub fn is_online(&self, agent: &AgentId) -> bool {
        self.by_agent.contains_key(agent)
    }

    /// Subscribe `watcher_id` to presence transitions for each agent in
    /// `agents`. Immediately echoes the current online state of each agent
    /// back through `watcher_tx` so the watcher can paint its UI without
    /// waiting for the next transition.
    ///
    /// Re-watching an already-watched agent is a no-op (no duplicate entry,
    /// no duplicate immediate-state echo).
    pub fn add_watches(
        &self,
        watcher_id: SessionId,
        watcher_tx: &Sender<ServerFrame>,
        agents: &[AgentId],
    ) {
        let mut session_watches = self.watches_by_session.entry(watcher_id).or_default();
        for agent in agents {
            if !session_watches.insert(*agent) {
                continue;
            }
            let mut entry = self.watchers.entry(*agent).or_default();
            entry.push((watcher_id, watcher_tx.clone()));
            let online = self.by_agent.contains_key(agent);
            let _ = watcher_tx.try_send(ServerFrame::PresenceUpdate(PresenceUpdate {
                agent_id: *agent,
                online,
            }));
        }
    }

    /// Unsubscribe `watcher_id` from presence transitions for each agent
    /// in `agents`. Removing an agent that wasn't being watched is a
    /// silent no-op.
    pub fn remove_watches(&self, watcher_id: SessionId, agents: &[AgentId]) {
        if let Some(mut session_watches) = self.watches_by_session.get_mut(&watcher_id) {
            for agent in agents {
                session_watches.remove(agent);
            }
        }
        for agent in agents {
            if let Some(mut entry) = self.watchers.get_mut(agent) {
                entry.retain(|(id, _)| *id != watcher_id);
            }
        }
    }

    /// Tear down all watches owned by `watcher_id`. Called from the
    /// connection's exit path so leaving a session never leaves dangling
    /// watcher entries.
    pub fn drop_all_watches(&self, watcher_id: SessionId) {
        let Some((_, agents)) = self.watches_by_session.remove(&watcher_id) else {
            return;
        };
        for agent in agents {
            if let Some(mut entry) = self.watchers.get_mut(&agent) {
                entry.retain(|(id, _)| *id != watcher_id);
            }
        }
    }

    fn broadcast_presence(&self, agent: AgentId, online: bool) {
        let Some(entry) = self.watchers.get(&agent) else {
            return;
        };
        let frame = ServerFrame::PresenceUpdate(PresenceUpdate {
            agent_id: agent,
            online,
        });
        for (_, tx) in entry.iter() {
            let _ = tx.try_send(frame.clone());
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use fetchit_relay_proto::{Bye, ByeReason, ServerFrame};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn send_routes_to_registered_agent() {
        let r = SessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(16);
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
        let (tx, _rx) = mpsc::channel(16);
        let a = AgentId::from_bytes([3u8; 32]);
        let id = r.register(a, tx);
        assert_eq!(r.connection_count(), 1);
        r.unregister(&a, id);
        assert_eq!(r.connection_count(), 0);
    }

    #[tokio::test]
    async fn register_twice_displaces_first_with_bye() {
        let r = SessionRegistry::new();
        let (tx1, mut rx1) = mpsc::channel(16);
        let (tx2, _rx2) = mpsc::channel(16);
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
        let (tx1, _rx1) = mpsc::channel(16);
        let (tx2, _rx2) = mpsc::channel(16);
        let a = AgentId::from_bytes([5u8; 32]);

        let id1 = r.register(a, tx1);
        let _id2 = r.register(a, tx2);

        r.unregister(&a, id1);

        assert_eq!(r.connection_count(), 1);
    }

    #[tokio::test]
    async fn send_still_routes_after_displaced_unregister() {
        let r = SessionRegistry::new();
        let (tx1, _rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);
        let a = AgentId::from_bytes([6u8; 32]);

        let id1 = r.register(a, tx1);
        let _id2 = r.register(a, tx2);
        r.unregister(&a, id1);

        let frame = ServerFrame::Bye(Bye {
            reason: ByeReason::ServerShutdown,
        });
        assert!(r.send(&a, frame.clone()));
        assert_eq!(rx2.recv().await, Some(frame));
    }

    #[tokio::test]
    async fn add_watch_echoes_initial_online_state() {
        let r = SessionRegistry::new();
        let watched = AgentId::from_bytes([10u8; 32]);
        let watcher = AgentId::from_bytes([11u8; 32]);

        let (watcher_tx, mut watcher_rx) = mpsc::channel(16);
        let watcher_id = r.register(watcher, watcher_tx.clone());

        let (watched_tx, _watched_rx) = mpsc::channel(16);
        let _watched_id = r.register(watched, watched_tx);

        r.add_watches(watcher_id, &watcher_tx, &[watched]);

        match watcher_rx.recv().await.expect("immediate presence echo") {
            ServerFrame::PresenceUpdate(p) => {
                assert_eq!(p.agent_id, watched);
                assert!(p.online);
            }
            other => panic!("expected PresenceUpdate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn add_watch_for_offline_agent_echoes_offline() {
        let r = SessionRegistry::new();
        let watcher = AgentId::from_bytes([20u8; 32]);
        let offline = AgentId::from_bytes([21u8; 32]);

        let (watcher_tx, mut watcher_rx) = mpsc::channel(16);
        let watcher_id = r.register(watcher, watcher_tx.clone());

        r.add_watches(watcher_id, &watcher_tx, &[offline]);

        match watcher_rx.recv().await.expect("offline echo") {
            ServerFrame::PresenceUpdate(p) => {
                assert_eq!(p.agent_id, offline);
                assert!(!p.online);
            }
            other => panic!("expected PresenceUpdate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_broadcasts_online_transition_to_watchers() {
        let r = SessionRegistry::new();
        let watched = AgentId::from_bytes([30u8; 32]);
        let watcher = AgentId::from_bytes([31u8; 32]);

        let (watcher_tx, mut watcher_rx) = mpsc::channel(16);
        let watcher_id = r.register(watcher, watcher_tx.clone());
        r.add_watches(watcher_id, &watcher_tx, &[watched]);
        let _ = watcher_rx.recv().await.unwrap();

        let (watched_tx, _watched_rx) = mpsc::channel(16);
        let _watched_id = r.register(watched, watched_tx);

        match watcher_rx.recv().await.expect("transition update") {
            ServerFrame::PresenceUpdate(p) => {
                assert_eq!(p.agent_id, watched);
                assert!(p.online);
            }
            other => panic!("expected online PresenceUpdate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unregister_broadcasts_offline_transition() {
        let r = SessionRegistry::new();
        let watched = AgentId::from_bytes([40u8; 32]);
        let watcher = AgentId::from_bytes([41u8; 32]);

        let (watcher_tx, mut watcher_rx) = mpsc::channel(16);
        let watcher_id = r.register(watcher, watcher_tx.clone());
        let (watched_tx, _watched_rx) = mpsc::channel(16);
        let watched_id = r.register(watched, watched_tx);

        r.add_watches(watcher_id, &watcher_tx, &[watched]);
        let _ = watcher_rx.recv().await.unwrap();

        r.unregister(&watched, watched_id);

        match watcher_rx.recv().await.expect("offline update") {
            ServerFrame::PresenceUpdate(p) => {
                assert_eq!(p.agent_id, watched);
                assert!(!p.online);
            }
            other => panic!("expected offline PresenceUpdate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn drop_all_watches_stops_further_updates() {
        let r = SessionRegistry::new();
        let watched = AgentId::from_bytes([50u8; 32]);
        let watcher = AgentId::from_bytes([51u8; 32]);

        let (watcher_tx, mut watcher_rx) = mpsc::channel(16);
        let watcher_id = r.register(watcher, watcher_tx.clone());
        r.add_watches(watcher_id, &watcher_tx, &[watched]);
        let _ = watcher_rx.recv().await.unwrap();

        r.drop_all_watches(watcher_id);

        let (watched_tx, _watched_rx) = mpsc::channel(16);
        let _watched_id = r.register(watched, watched_tx);

        let res =
            tokio::time::timeout(std::time::Duration::from_millis(50), watcher_rx.recv()).await;
        assert!(res.is_err(), "no further updates after drop_all_watches");
    }

    #[tokio::test]
    async fn displacement_does_not_emit_extra_presence() {
        let r = SessionRegistry::new();
        let watched = AgentId::from_bytes([60u8; 32]);
        let watcher = AgentId::from_bytes([61u8; 32]);

        let (watcher_tx, mut watcher_rx) = mpsc::channel(16);
        let watcher_id = r.register(watcher, watcher_tx.clone());
        let (first_tx, _first_rx) = mpsc::channel(16);
        let _first_id = r.register(watched, first_tx);

        r.add_watches(watcher_id, &watcher_tx, &[watched]);
        let _ = watcher_rx.recv().await.unwrap();

        let (second_tx, _second_rx) = mpsc::channel(16);
        let _second_id = r.register(watched, second_tx);

        let res =
            tokio::time::timeout(std::time::Duration::from_millis(50), watcher_rx.recv()).await;
        assert!(res.is_err(), "displacement is not a presence transition");
    }
}
