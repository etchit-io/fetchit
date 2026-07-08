//! Engine-side per-group recovery status, so a shell can render
//! "reconnecting to group…" instead of showing a silently-dead group.
//!
//! [`GroupStatusMap`] is cheaply cloneable (all state behind `Arc`) so the
//! [`crate::Client`] and the recovery driver share one map. It is set to
//! [`GroupRecoveryStatus::Reconnecting`] while the driver is working a
//! group and cleared to [`GroupRecoveryStatus::Live`] on convergence.
//! Changes broadcast a [`GroupStatusEvent`] so a shell can react without
//! polling; a group never seen is [`GroupRecoveryStatus::Live`] by default.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

/// Coarse, user-facing group health the engine tracks + surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupRecoveryStatus {
    /// Keyed at the current epoch — messages flow normally.
    Live,
    /// The recovery driver is catching this group up (fetching + applying
    /// commits, or re-driving a cold join). The shell shows a
    /// "reconnecting…" affordance rather than a dead conversation.
    Reconnecting,
}

/// Broadcast when a group's [`GroupRecoveryStatus`] changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupStatusEvent {
    /// Hex group id whose status changed.
    pub group_id: String,
    /// The new status.
    pub status: GroupRecoveryStatus,
}

/// Default broadcast backlog. Small: shells consume promptly and a lagged
/// receiver only misses intermediate transitions, never the map's truth
/// (queryable via [`GroupStatusMap::get`]).
const STATUS_EVENT_CAPACITY: usize = 64;

/// Shared, cheaply-cloneable map of per-group recovery status + a change
/// broadcast. All clones observe the same state.
#[derive(Clone)]
pub struct GroupStatusMap {
    inner: Arc<Mutex<HashMap<String, GroupRecoveryStatus>>>,
    events: broadcast::Sender<GroupStatusEvent>,
}

impl std::fmt::Debug for GroupStatusMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupStatusMap").finish_non_exhaustive()
    }
}

impl Default for GroupStatusMap {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupStatusMap {
    /// A fresh, empty status map (every group defaults to `Live`).
    #[must_use]
    pub fn new() -> Self {
        let (events, _rx) = broadcast::channel(STATUS_EVENT_CAPACITY);
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            events,
        }
    }

    /// Current status of `group_id`. A group never marked is `Live`.
    #[must_use]
    pub fn get(&self, group_id: &str) -> GroupRecoveryStatus {
        self.inner.lock().map_or(GroupRecoveryStatus::Live, |m| {
            m.get(group_id)
                .copied()
                .unwrap_or(GroupRecoveryStatus::Live)
        })
    }

    /// Mark `group_id` as [`GroupRecoveryStatus::Reconnecting`]. Broadcasts
    /// only on an actual change.
    pub fn set_reconnecting(&self, group_id: &str) {
        self.set(group_id, GroupRecoveryStatus::Reconnecting);
    }

    /// Mark `group_id` as [`GroupRecoveryStatus::Live`]. Broadcasts only on
    /// an actual change.
    pub fn set_live(&self, group_id: &str) {
        self.set(group_id, GroupRecoveryStatus::Live);
    }

    fn set(&self, group_id: &str, status: GroupRecoveryStatus) {
        let changed = {
            let Ok(mut m) = self.inner.lock() else {
                return;
            };
            // An untracked group is effectively `Live` (the default), so
            // confirming `Live` on one is a true no-op — never a spurious
            // event churn on a healthy group.
            let prev_effective = m
                .get(group_id)
                .copied()
                .unwrap_or(GroupRecoveryStatus::Live);
            if prev_effective == status {
                false
            } else {
                m.insert(group_id.to_owned(), status);
                true
            }
        };
        if changed {
            // A send error only means no live subscribers — the map is
            // still authoritative via `get`.
            let _ = self.events.send(GroupStatusEvent {
                group_id: group_id.to_owned(),
                status,
            });
        }
    }

    /// Subscribe to status-change events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<GroupStatusEvent> {
        self.events.subscribe()
    }

    /// Snapshot of every group currently tracked as non-default. Groups
    /// absent from the snapshot are `Live`.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<String, GroupRecoveryStatus> {
        self.inner.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unknown_group_defaults_to_live() {
        let m = GroupStatusMap::new();
        assert_eq!(m.get("never-seen"), GroupRecoveryStatus::Live);
    }

    #[tokio::test]
    async fn set_reconnecting_then_live_updates_and_broadcasts() {
        let m = GroupStatusMap::new();
        let mut rx = m.subscribe();

        m.set_reconnecting("g1");
        assert_eq!(m.get("g1"), GroupRecoveryStatus::Reconnecting);
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.group_id, "g1");
        assert_eq!(ev.status, GroupRecoveryStatus::Reconnecting);

        m.set_live("g1");
        assert_eq!(m.get("g1"), GroupRecoveryStatus::Live);
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.status, GroupRecoveryStatus::Live);
    }

    #[tokio::test]
    async fn no_change_does_not_broadcast() {
        let m = GroupStatusMap::new();
        m.set_reconnecting("g1");
        let mut rx = m.subscribe();
        // Setting the same status again is a no-op — no event.
        m.set_reconnecting("g1");
        // A distinct change DOES fire, proving the channel is live and the
        // repeat above was suppressed (only one event arrives).
        m.set_live("g1");
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.status, GroupRecoveryStatus::Live);
        assert!(
            rx.try_recv().is_err(),
            "only the Live change should be queued; the repeat Reconnecting was suppressed"
        );
    }

    #[test]
    fn clones_share_state() {
        let a = GroupStatusMap::new();
        let b = a.clone();
        a.set_reconnecting("g");
        assert_eq!(b.get("g"), GroupRecoveryStatus::Reconnecting);
        assert_eq!(
            b.snapshot().get("g"),
            Some(&GroupRecoveryStatus::Reconnecting)
        );
    }
}
