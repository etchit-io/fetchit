//! Multi-home wrapper that fans send across multiple relays and merges
//! their inbound streams into a single Deliver stream.
//!
//! M3 federation core
//! (`docs/superpowers/plans/2026-06-06-m3-federation-core-plan.md`).
//! Stage 1 Tasks 1.1-1.4 land here: `connect`, `connection_states`,
//! `send` (fan-out), `next_delivery` (merged inbox), `watch_presence`
//! / `unwatch_presence` / `next_presence` (presence multiplexing),
//! `shutdown`.
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
use fetchit_relay_proto::{AgentId, DedupeKey, Deliver, PresenceUpdate, TransitEnvelope};
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};

/// A delivery from the merged inbox, tagged with the index of the
/// relay that delivered it (positions match the `configs` order given
/// to [`RelaySet::connect`]). The tag is what makes acking safe:
/// `Deliver::transit_seq` ids are relay-local, so a
/// [`RelaySet::ack_transit`] must go back to exactly this relay.
#[derive(Debug)]
pub struct SetDelivery {
    /// Index of the delivering relay within the set.
    pub relay: usize,
    /// The delivered envelope frame.
    pub deliver: Deliver,
}

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
    /// Merged inbox: every relay's `Client::next_delivery` stream is
    /// forwarded into this single channel by a per-relay task spawned
    /// in `connect`, tagged with the delivering relay's index so
    /// transit acks can be routed back to the SAME relay (transit ids
    /// are relay-local). Caller-side dedupe (when needed) lives at the
    /// chat layer keyed off the envelope's `message_id`; the recipient's
    /// x0xd is the source-of-truth dedupe via canonical event hash.
    inbox_rx: Mutex<mpsc::UnboundedReceiver<SetDelivery>>,
    /// Merged presence: every relay's `Client::next_presence` stream
    /// is forwarded into this single channel. Same per-relay forwarder
    /// pattern as `inbox_rx`. Duplicates absorb at the chat layer.
    presence_rx: Mutex<mpsc::UnboundedReceiver<PresenceUpdate>>,
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

        // One inbox forwarder task per relay drains the per-relay
        // `Client::next_delivery` stream into a single merged mpsc
        // channel. `RelaySet::next_delivery` reads from that channel.
        // The merged channel does not dedupe — receiver-side caller
        // (the chat layer) handles dedupe via `message_id`; x0xd at the
        // recipient is the canonical-event-hash source of truth.
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        for (idx, relay) in relays.iter().enumerate() {
            let r = Arc::clone(relay);
            let tx = inbox_tx.clone();
            tokio::spawn(async move {
                while let Some(d) = r.next_delivery().await {
                    if tx
                        .send(SetDelivery {
                            relay: idx,
                            deliver: d,
                        })
                        .is_err()
                    {
                        // Receiver was dropped — RelaySet is being torn
                        // down. Exit cleanly so the per-relay task
                        // doesn't leak across the rest of the process
                        // lifetime.
                        break;
                    }
                }
            });
        }
        drop(inbox_tx);

        // Per-relay presence forwarder — same shape as the inbox
        // forwarders, draining `Client::next_presence` into a single
        // merged mpsc.
        let (presence_tx, presence_rx) = mpsc::unbounded_channel();
        for relay in &relays {
            let r = Arc::clone(relay);
            let tx = presence_tx.clone();
            tokio::spawn(async move {
                while let Some(p) = r.next_presence().await {
                    if tx.send(p).is_err() {
                        break;
                    }
                }
            });
        }
        drop(presence_tx);

        Ok(Self {
            relays,
            states_rx,
            inbox_rx: Mutex::new(inbox_rx),
            presence_rx: Mutex::new(presence_rx),
        })
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

    /// Borrow the first relay's `connection_state` receiver as a
    /// single-relay convenience for callers that haven't yet adopted
    /// multi-relay aggregation (e.g. the desktop's terminal-disconnect
    /// toast still consumes one `ConnState` stream). The relay at
    /// index 0 is the first config passed to [`Self::connect`].
    ///
    /// Always returns a live receiver because [`Self::connect`] rejects
    /// empty input. Future Vec-aware UIs should consume
    /// [`Self::states_receiver`] directly.
    #[must_use]
    pub fn primary_connection_state(&self) -> watch::Receiver<ConnState> {
        self.relays[0].connection_state()
    }

    /// Signal every relay's supervisor to close its session.
    ///
    /// Subsequent calls are no-ops.
    pub async fn shutdown(&self) {
        let shutdowns = self.relays.iter().map(|r| r.shutdown());
        futures_util::future::join_all(shutdowns).await;
    }

    /// Subscribe every relay in the set to presence transitions for
    /// `agents`. Each relay maintains its own watch set across
    /// reconnects, so fan-out is durable past any single relay's
    /// supervisor restart.
    ///
    /// # Errors
    /// Returns the last underlying [`ClientError`] only when EVERY
    /// relay's `watch_presence` errored. Any partial success keeps
    /// the watch alive on the healthy relays and resolves `Ok`.
    pub fn watch_presence(&self, agents: &[AgentId]) -> Result<(), ClientError> {
        let mut any_ok = false;
        let mut last_err: Option<ClientError> = None;
        for relay in &self.relays {
            match relay.watch_presence(agents) {
                Ok(()) => any_ok = true,
                Err(e) => last_err = Some(e),
            }
        }
        if any_ok || last_err.is_none() {
            Ok(())
        } else {
            Err(last_err.unwrap_or(ClientError::InboxClosed))
        }
    }

    /// Drop every relay's interest in `agents`.
    ///
    /// # Errors
    /// Same any-ok semantics as [`Self::watch_presence`].
    pub fn unwatch_presence(&self, agents: &[AgentId]) -> Result<(), ClientError> {
        let mut any_ok = false;
        let mut last_err: Option<ClientError> = None;
        for relay in &self.relays {
            match relay.unwatch_presence(agents) {
                Ok(()) => any_ok = true,
                Err(e) => last_err = Some(e),
            }
        }
        if any_ok || last_err.is_none() {
            Ok(())
        } else {
            Err(last_err.unwrap_or(ClientError::InboxClosed))
        }
    }

    /// Receive the next presence transition from the merged stream.
    ///
    /// Returns `None` once every relay has shut down.
    pub async fn next_presence(&self) -> Option<PresenceUpdate> {
        self.presence_rx.lock().await.recv().await
    }

    /// Receive the next delivered envelope from the merged inbox.
    ///
    /// Drains the union of every relay's per-relay `next_delivery`
    /// stream. The same logical envelope MAY surface more than once
    /// when the sender fanned out to multiple relays and the receiver
    /// is connected to multiple of those same relays; caller-side
    /// dedupe at the chat layer (keyed off the envelope's `message_id`)
    /// absorbs the duplication. The recipient's x0xd is the
    /// canonical-event-hash dedupe source-of-truth past that.
    ///
    /// Returns `None` once every relay has shut down — useful for the
    /// orderly-drain shutdown path.
    pub async fn next_delivery(&self) -> Option<Deliver> {
        self.next_delivery_tagged().await.map(|t| t.deliver)
    }

    /// Like [`Self::next_delivery`] but tagged with the index of the
    /// relay that delivered, so the caller can route a
    /// [`Self::ack_transit`] back to the SAME relay after it has
    /// durably processed the envelope. Consumers that ack must use
    /// this variant — the untagged one discards the routing needed to
    /// ack safely.
    pub async fn next_delivery_tagged(&self) -> Option<SetDelivery> {
        self.inbox_rx.lock().await.recv().await
    }

    /// Confirm durable transit ids to the relay at index `relay` (as
    /// tagged on the [`SetDelivery`] the ids came from). Ids are
    /// relay-local: acking them on any other relay could reclaim
    /// unrelated entries, so out-of-range indices are rejected rather
    /// than broadcast.
    ///
    /// # Errors
    /// Returns [`ClientError::InboxClosed`] when `relay` is out of
    /// range or that relay's supervisor has shut down.
    pub fn ack_transit(&self, relay: usize, acked_ids: Vec<u64>) -> Result<(), ClientError> {
        let Some(client) = self.relays.get(relay) else {
            return Err(ClientError::InboxClosed);
        };
        client.ack_transit(acked_ids)
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
        let signer = Arc::new(crate::signer::StaticKeySigner::from_public_key(vec![
            0u8;
            32
        ]));
        let res = RelaySet::connect(Vec::new(), signer).await;
        assert!(res.is_err(), "empty configs must surface an error");
    }

    // Coverage for the success path (N healthy relays) and the
    // partial-success path (1 healthy, M-1 fail) lands with Task 1.2
    // when the in-process relay-server test harness is wired in.
}
