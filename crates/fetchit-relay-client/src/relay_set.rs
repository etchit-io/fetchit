//! Multi-home wrapper that fans send across multiple relays and merges
//! their inbound streams into a single Deliver stream.
//!
//! M3 federation core
//! (`docs/superpowers/plans/2026-06-06-m3-federation-core-plan.md`).
//! Stage 1 Tasks 1.1-1.2 land here: `connect`, `connection_states`,
//! `send` (fan-out), `shutdown`. Task 1.3 (`next_delivery` merged
//! inbox) lands separately.
//!
//! Design decisions resolved per Alice's #251 plan landing
//! (62d7424/3e74a36): fan-out send to every healthy relay, lean on
//! x0xd's canonical-event-hash dedup at the recipient's chat layer
//! rather than transport-layer dedupe at the sender. Each relay's
//! own `Client` supervisor owns its reconnect bookkeeping; `RelaySet`
//! only observes per-relay state via the merged watch.

use crate::client::{Client, ClientConfig, ConnState};
use crate::error::ClientError;
use crate::outbox::Receipt;
use crate::signer::Signer;
use fetchit_relay_proto::{AgentId, DedupeKey, TransitEnvelope};
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

    /// Fan-out send to every relay in the set.
    ///
    /// Each relay's transit layer holds the envelope independently;
    /// receivers see at most one copy because the recipient's x0xd
    /// dedupes by canonical event hash (see Alice's #251 plan
    /// Discovery section). The first successful per-relay `Receipt`
    /// is reported as [`SendOutcome::primary`]; the rest sit in
    /// [`SendOutcome::extras`] for ops introspection.
    ///
    /// # Errors
    /// Returns the last per-relay [`ClientError`] only when EVERY
    /// relay errors. Any partial success still resolves `Ok` so a
    /// single healthy relay keeps the peer reachable.
    pub async fn send(
        &self,
        to: AgentId,
        envelope: TransitEnvelope,
        dedupe_key: DedupeKey,
    ) -> Result<SendOutcome, ClientError> {
        let sends = self.relays.iter().map(|relay| {
            let r = Arc::clone(relay);
            let env = envelope.clone();
            async move { r.send(to, env, dedupe_key).await }
        });
        let results = futures_util::future::join_all(sends).await;

        let mut primary: Option<Receipt> = None;
        let mut extras: Vec<Result<Receipt, ClientError>> = Vec::with_capacity(results.len());
        for r in results {
            match r {
                Ok(receipt) if primary.is_none() => primary = Some(receipt),
                other => extras.push(other),
            }
        }

        if let Some(p) = primary {
            Ok(SendOutcome { primary: p, extras })
        } else {
            Err(extras
                .into_iter()
                .filter_map(Result::err)
                .last()
                .unwrap_or(ClientError::InboxClosed))
        }
    }
}

/// Result of a fan-out [`RelaySet::send`].
///
/// `primary` is the first successful per-relay `Receipt` returned in
/// fan-out order; `extras` carries every other per-relay result (both
/// successes and errors) so ops surfaces can show "delivered on 2 of
/// 3 relays" without re-issuing the send.
#[derive(Debug)]
pub struct SendOutcome {
    /// First successful per-relay receipt in fan-out order.
    pub primary: Receipt,
    /// Per-relay results from every relay other than the one that
    /// produced [`Self::primary`]. Order matches the relay order
    /// passed to [`RelaySet::connect`], with the primary's slot
    /// elided.
    pub extras: Vec<Result<Receipt, ClientError>>,
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
