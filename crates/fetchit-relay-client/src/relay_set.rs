//! Multi-home wrapper that fans send across multiple relays and merges
//! their inbound streams into a single Deliver stream.
//!
//! **Status: scaffold.** Stage 1 Task 1.1 of M3 federation core
//! (`docs/superpowers/plans/2026-06-06-m3-federation-core-plan.md`).
//! Only `connect`, `connection_states`, and `shutdown` are implemented
//! here; `send` and `next_delivery` resolve through later tasks once
//! the dedupe + fan-out strategy is cross-reviewed with Alice (Box A).
//!
//! Per the plan, the open design questions blocking the rest are:
//! send-all vs send-one-with-failover, inbound dedupe scope, and
//! per-relay reconnect bookkeeping.

#![allow(dead_code)] // scaffolding — send/recv plumbing arrives in later tasks.

use crate::client::{Client, ClientConfig, ConnState};
use crate::error::ClientError;
use crate::signer::Signer;
use std::sync::Arc;
use tokio::sync::watch;

/// One per-relay session a peer maintains concurrently with N-1 others.
///
/// All sessions share the same [`Signer`] (identity is per-peer, not
/// per-relay) but each carries an independent [`ClientConfig`] so peers
/// can dial different regions, different operators, or different
/// constellations from one process.
pub struct RelaySet {
    relays: Vec<Arc<Client>>,
    /// Per-relay live state, indexed in the same order as `relays`.
    /// Updated by a small forwarder task per relay that watches the
    /// underlying `connection_state` and republishes the snapshot.
    states_rx: watch::Receiver<Vec<ConnState>>,
}

impl RelaySet {
    /// Connect to every config in `configs` concurrently.
    ///
    /// Fails only when EVERY relay fails its initial handshake — any
    /// surviving subset is enough to keep the peer reachable.
    ///
    /// # Errors
    /// Returns the last underlying [`ClientError`] when no relay
    /// completes the handshake. Also returns [`ClientError::InboxClosed`]
    /// when `configs` is empty (a `RelaySet` with no relays is a logic
    /// bug at the call site).
    pub async fn connect(
        configs: Vec<ClientConfig>,
        signer: Arc<dyn Signer + Send + Sync>,
    ) -> Result<Self, ClientError> {
        if configs.is_empty() {
            return Err(ClientError::InboxClosed);
        }

        let connects = configs
            .into_iter()
            .map(|cfg| {
                let signer = signer.clone();
                async move { Client::connect(cfg, signer).await }
            })
            .collect::<Vec<_>>();
        let results = futures_util::future::join_all(connects).await;

        let mut relays: Vec<Arc<Client>> = Vec::with_capacity(results.len());
        let mut last_err: Option<ClientError> = None;
        for r in results {
            match r {
                Ok(c) => relays.push(Arc::new(c)),
                Err(e) => last_err = Some(e),
            }
        }
        if relays.is_empty() {
            return Err(last_err.unwrap_or(ClientError::InboxClosed));
        }

        let initial_states: Vec<ConnState> = relays
            .iter()
            .map(|c| c.connection_state().borrow().clone())
            .collect();
        let (states_tx, states_rx) = watch::channel(initial_states);

        // One forwarder task per relay republishes per-relay state
        // transitions to the merged watch channel. The forwarder reads
        // a clone of the per-relay state receiver and never writes to
        // its own client.
        for (idx, relay) in relays.iter().enumerate() {
            let mut per = relay.connection_state();
            let states_tx = states_tx.clone();
            tokio::spawn(async move {
                while per.changed().await.is_ok() {
                    let snapshot = per.borrow().clone();
                    states_tx.send_modify(|v| {
                        if let Some(slot) = v.get_mut(idx) {
                            *slot = snapshot;
                        }
                    });
                }
            });
        }

        Ok(Self { relays, states_rx })
    }

    /// One [`ConnState`] per relay in the same order as `configs`.
    ///
    /// UI surfaces "2 of 3 relays connected" from this; ops surfaces
    /// the same as a per-relay table.
    #[must_use]
    pub fn connection_states(&self) -> Vec<ConnState> {
        self.states_rx.borrow().clone()
    }

    /// Number of relays in the set (alive or not). Use
    /// [`Self::connection_states`] for liveness.
    #[must_use]
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// True when the set holds no relays. Can only return true if
    /// [`Self::connect`] is bypassed — `connect` rejects empty input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Borrow a `watch::Receiver<Vec<ConnState>>` reporting the live
    /// per-relay state vector. Each per-relay state transition pushes
    /// a fresh snapshot.
    #[must_use]
    pub fn states_receiver(&self) -> watch::Receiver<Vec<ConnState>> {
        self.states_rx.clone()
    }

    /// Signal every relay's supervisor to close its session.
    ///
    /// Subsequent calls are no-ops.
    pub async fn shutdown(&self) {
        let shutdowns = self.relays.iter().map(|r| r.shutdown());
        futures_util::future::join_all(shutdowns).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_with_empty_configs_errors() {
        // Calling connect with no configs is a logic bug: a RelaySet
        // with zero relays has nothing to do. Surface that fast.
        // Empty-configs path doesn't touch the signer — any dummy is fine.
        let signer = Arc::new(crate::signer::StaticKeySigner::from_public_key(vec![0u8; 32]));
        let res = RelaySet::connect(Vec::new(), signer).await;
        assert!(res.is_err(), "empty configs must surface an error");
    }

    // Coverage for the success path (N healthy relays) and the
    // partial-success path (1 healthy, M-1 fail) lands with Task 1.2
    // when the in-process relay-server test harness is wired in.
}
