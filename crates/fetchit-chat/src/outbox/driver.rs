//! Background retry driver -- the resend policy that used to live in
//! desktop's `outboxDriver.ts`, now engine-owned so desktop and Android
//! share it.
//!
//! The driver owns the [`OutboxStore`] behind a mutex and re-sends
//! retryable bubbles on each peer offline->online edge, warming the link
//! first (so the initial and retry sends skip the cold-QUIC timeout). It
//! reclaims stalled in-flight claims (at boot and periodically) and
//! broadcasts an [`OutboxEvent`] for every bubble mutation so the shell
//! can project live status. The transport is abstracted
//! ([`OutboxTransport`]) so the loop is unit-testable with scripted
//! doubles; production wires it to the `Router` + `messages().connect()`.
//!
//! What the driver deliberately does NOT do: give up. No sweep here ever
//! turns a queued message into a failed one -- only a terminal verdict
//! from a send attempt does (`crate::send_state::SendFailure`).

use super::store::OutboxStore;
use super::{is_retryable, now_ms, OutboxBubble, OutboxEvent};
#[cfg(test)]
use super::{SendState, PRIOR_MESSAGE_ID_CAP};
use crate::error::ChatError;
use crate::identity::AgentId;
use crate::send_state::SendFailure;
use crate::transport::SendReceipt;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// How long an in-flight claim may sit before the periodic sweep releases
/// it so the bubble can be re-sent.
///
/// Long enough that no live send attempt is ever cut in half (transport
/// timeouts are seconds), short enough that a send task killed between
/// claim and release does not wedge the message for the life of the
/// process. This is a claim timeout, NOT a delivery deadline: the message
/// itself keeps its state and keeps retrying.
pub const STALLED_CLAIM_MS: u64 = 15 * 60 * 1000;

/// The transport the driver re-sends through. Abstracted so the driver is
/// unit-testable; production wires it to the `Router` + the existing
/// `messages().connect()` warm-connect.
pub trait OutboxTransport: Send + Sync + 'static {
    /// Warm the direct link to `peer` before a send (avoids the cold-QUIC
    /// timeout). Best-effort; the caller ignores failures.
    fn connect(&self, peer: AgentId) -> impl std::future::Future<Output = ()> + Send;

    /// Attempt to send `bubble`, returning the relay receipt.
    fn send(
        &self,
        bubble: OutboxBubble,
    ) -> impl std::future::Future<Output = Result<SendReceipt, ChatError>> + Send;
}

/// No-send-before-registered gate.
///
/// A flush must not fire a send until the relay connection the transport
/// routes through is established and registered. Without this, a presence
/// edge that lands before the relay supervisor reaches
/// [`fetchit_relay_client::ConnState::Connected`] drives a send into a relay
/// set whose every entry is still unreachable, which surfaces as
/// [`ChatError::AllRelaysUnreachable`] -- harmless retry-noise on a bare-IP
/// connection, but a fatal exit on a wss one.
///
/// Object-safe (boxed `async` via [`std::pin::Pin`]) so the driver can hold
/// `dyn ReadyGate` while production wires it to the relay client's
/// `ConnState` watch and tests supply a scripted double.
pub trait ReadyGate: Send + Sync + 'static {
    /// Resolve once the routing relay is registered and ready for a send.
    /// Implementations may return immediately when already ready, or await
    /// the transition; the driver awaits this before every flush.
    fn wait_ready(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// Background retry driver. Owns the outbox state + the retry policy; the
/// shell only starts it and renders the [`OutboxEvent`] stream.
pub struct OutboxDriver<T: OutboxTransport> {
    store: Arc<Mutex<OutboxStore>>,
    events: broadcast::Sender<OutboxEvent>,
    transport: T,
    last_online: Mutex<HashMap<AgentId, bool>>,
    /// Optional no-send-before-registered gate. When set, every flush awaits
    /// it before sending; `None` (the default) means "always ready", which
    /// keeps relay-less / scripted-transport tests unchanged.
    ready_gate: Option<Arc<dyn ReadyGate>>,
}

impl<T: OutboxTransport> OutboxDriver<T> {
    /// Build a driver over `store`, broadcasting changes on `events`.
    pub fn new(
        store: Arc<Mutex<OutboxStore>>,
        events: broadcast::Sender<OutboxEvent>,
        transport: T,
    ) -> Self {
        Self {
            store,
            events,
            transport,
            last_online: Mutex::new(HashMap::new()),
            ready_gate: None,
        }
    }

    /// Attach a [`ReadyGate`] so flushes wait for the routing relay to be
    /// registered before sending. Production wires this to the relay
    /// client's `ConnState` watch; without it the driver assumes the
    /// transport is always ready (the relay-less test default).
    #[must_use]
    pub fn with_ready_gate(mut self, gate: Arc<dyn ReadyGate>) -> Self {
        self.ready_gate = Some(gate);
        self
    }

    /// Broadcast an upsert for each changed bubble. A lagging receiver
    /// drops events and re-syncs from `outbox_snapshot` (shell side).
    fn emit(&self, bubbles: impl IntoIterator<Item = OutboxBubble>) {
        for bubble in bubbles {
            let _ = self.events.send(OutboxEvent { bubble });
        }
    }

    /// Re-send every retryable bubble for `peer` not already in flight,
    /// warming the link first.
    pub async fn flush_peer(&self, peer: &AgentId) {
        // No-send-before-registered: wait for the routing relay to be ready
        // before claiming anything. A presence edge can arrive before the
        // relay supervisor reaches Connected; sending then yields
        // AllRelaysUnreachable (a fatal exit on a wss connection). Gating
        // here -- the single chokepoint on_presence / flush_all funnel
        // through -- covers every flush path. No gate set => always ready.
        if let Some(gate) = self.ready_gate.as_ref() {
            gate.wait_ready().await;
        }
        // Claim the eligible bubbles under the lock, then release it for
        // the awaits below.
        let claims: Vec<OutboxBubble> = {
            let claimed_at = now_ms();
            let mut store = self.store.lock().await;
            let candidates: Vec<OutboxBubble> = store
                .snapshot()
                .into_iter()
                .filter(|b| &b.peer == peer && is_retryable(b))
                .collect();
            candidates
                .into_iter()
                .filter(|b| store.try_mark_inflight(&b.id, claimed_at))
                .collect()
        };
        for claimed in claims {
            self.transport.connect(peer.clone()).await;
            let result = self.transport.send(claimed.clone()).await;
            let emitted = {
                let mut store = self.store.lock().await;
                // Every transition + the terminal-state guard (a receipt may
                // have landed during the send await; it is authoritative and
                // must not be clobbered) + the bubble-still-present check
                // live in one place -- OutboxStore::record_send_outcome --
                // shared with the initial send (Client::enqueue_dm) so the
                // two paths cannot drift. clear_inflight stays unconditional.
                let (message_id, failure) = match &result {
                    Ok(receipt) => (receipt.message_id.clone(), None),
                    Err(e) => (None, Some(SendFailure::classify(e))),
                };
                let updated = store.record_send_outcome(&claimed.id, message_id, failure, now_ms());
                store.clear_inflight(&claimed.id);
                updated
            };
            if let Some(u) = emitted {
                self.emit([u]);
            }
        }
    }

    /// Record `peer`'s online state and, on a transition to online (or the
    /// first time we see them online), flush their retryable bubbles.
    pub async fn on_presence(&self, peer: &AgentId, online: bool) {
        let should_flush = {
            let mut last = self.last_online.lock().await;
            let was = last.insert(peer.clone(), online);
            online && was != Some(true)
        };
        if should_flush {
            self.flush_peer(peer).await;
        }
    }

    /// Release in-flight claims stalled past [`STALLED_CLAIM_MS`] and
    /// re-flush the peers they were blocking.
    ///
    /// The bubbles keep their state -- a stalled attempt leaves a queued
    /// message queued -- so this emits nothing; it just un-wedges the
    /// retry path for sends whose task died holding a claim.
    pub async fn sweep_stalled(&self, now_ms: u64) {
        let peers: Vec<AgentId> = {
            let freed = self
                .store
                .lock()
                .await
                .clear_stalled_inflight(now_ms, STALLED_CLAIM_MS);
            let mut seen = HashSet::new();
            freed
                .into_iter()
                .filter_map(|b| seen.insert(b.peer.clone()).then_some(b.peer))
                .collect()
        };
        for peer in peers {
            log::warn!("outbox: releasing a stalled send claim; re-flushing");
            self.flush_peer(&peer).await;
        }
    }

    /// Startup reclaim, run once per driver (re)start: drop every
    /// in-flight claim left by a prior driver that died mid-flush.
    ///
    /// A freshly started driver implies any prior one is dead, so no claim
    /// can be legitimate. No bubble STATE changes: a queued message
    /// interrupted by a restart is still a queued message, and the next
    /// presence edge re-sends it.
    pub async fn boot_sweep(&self) {
        self.store.lock().await.clear_all_inflight();
    }

    /// Mark the bubble a `DeliveryReceipt` for `message_id` belongs to
    /// Delivered at `received_at_ms`, emitting the change.
    pub async fn mark_delivered(&self, message_id: &str, received_at_ms: u64) {
        let changed = self
            .store
            .lock()
            .await
            .mark_delivered(message_id, received_at_ms);
        self.emit(changed);
    }

    /// Flush every online... actually every peer with a retryable bubble
    /// (the manual Retry button). Caller decides online-gating.
    pub async fn flush_all(&self) {
        let peers: Vec<AgentId> = {
            let store = self.store.lock().await;
            let mut seen = HashSet::new();
            store
                .snapshot()
                .into_iter()
                .filter(is_retryable)
                .filter_map(|b| seen.insert(b.peer.clone()).then_some(b.peer))
                .collect()
        };
        for peer in peers {
            self.flush_peer(&peer).await;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // Scripted transport doubles mirror the trait's explicit `impl Future
    // + Send` shape rather than `async fn` for parity with OutboxTransport.
    clippy::manual_async_fn
)]
mod tests {
    use super::*;

    fn peer_a() -> AgentId {
        AgentId("aa".repeat(32))
    }

    fn bubble(
        id: &str,
        status: SendState,
        message_id: Option<&str>,
        enqueued_at_ms: u64,
    ) -> OutboxBubble {
        OutboxBubble {
            status,
            message_id: message_id.map(Into::into),
            ..OutboxBubble::queued(id.into(), peer_a(), "hi".into(), enqueued_at_ms)
        }
    }

    /// Records connects + sends; returns Ok with a relay message id.
    struct OkTransport {
        connected: Arc<Mutex<Vec<AgentId>>>,
        sent: Arc<Mutex<Vec<String>>>,
    }
    impl OutboxTransport for OkTransport {
        fn connect(&self, peer: AgentId) -> impl std::future::Future<Output = ()> + Send {
            let c = self.connected.clone();
            async move {
                c.lock().await.push(peer);
            }
        }
        fn send(
            &self,
            b: OutboxBubble,
        ) -> impl std::future::Future<Output = Result<SendReceipt, ChatError>> + Send {
            let s = self.sent.clone();
            async move {
                s.lock().await.push(b.id.clone());
                Ok(SendReceipt {
                    accepted_at_ms: 1,
                    message_id: Some("relay-1".into()),
                    transport_name: "test",
                })
            }
        }
    }

    /// Always errors (for the failed-send path).
    struct ErrTransport;
    impl OutboxTransport for ErrTransport {
        fn connect(&self, _peer: AgentId) -> impl std::future::Future<Output = ()> + Send {
            async {}
        }
        fn send(
            &self,
            _b: OutboxBubble,
        ) -> impl std::future::Future<Output = Result<SendReceipt, ChatError>> + Send {
            async { Err(ChatError::Invalid("boom".into())) }
        }
    }

    fn driver_with<T: OutboxTransport>(
        store: OutboxStore,
        transport: T,
    ) -> (OutboxDriver<T>, broadcast::Receiver<OutboxEvent>) {
        let (tx, rx) = broadcast::channel(16);
        let driver = OutboxDriver::new(Arc::new(Mutex::new(store)), tx, transport);
        (driver, rx)
    }

    /// Scripted [`ReadyGate`]: resolves `wait_ready` only after `ready` flips
    /// true. Until then the await parks on the notifier, modelling a relay
    /// that has not yet reached Connected.
    struct ScriptedGate {
        ready: Arc<std::sync::atomic::AtomicBool>,
        notify: Arc<tokio::sync::Notify>,
    }
    impl ScriptedGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                notify: Arc::new(tokio::sync::Notify::new()),
            })
        }
        fn mark_ready(&self) {
            self.ready.store(true, std::sync::atomic::Ordering::SeqCst);
            self.notify.notify_waiters();
        }
    }
    impl ReadyGate for ScriptedGate {
        fn wait_ready(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                loop {
                    if self.ready.load(std::sync::atomic::Ordering::SeqCst) {
                        return;
                    }
                    self.notify.notified().await;
                }
            })
        }
    }

    #[tokio::test]
    async fn flush_waits_for_ready_gate_then_sends() {
        // A presence edge fires while the gate is pending: no send happens
        // until the gate flips ready. Models the wss race -- a flush before
        // the relay registers must not drive an AllRelaysUnreachable send.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let gate = ScriptedGate::new();
        let (tx, _rx) = broadcast::channel(16);
        let driver = OutboxDriver::new(
            Arc::new(Mutex::new(store)),
            tx,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: sent.clone(),
            },
        )
        .with_ready_gate(gate.clone());

        // Spawn the flush; it must park on the gate, not send.
        let flush = {
            let driver = Arc::new(driver);
            let d = driver.clone();
            let h = tokio::spawn(async move { d.on_presence(&peer_a(), true).await });
            // Yield generously: the gate is not ready, so nothing should send.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                sent.lock().await.is_empty(),
                "no send may occur while the ready gate is pending"
            );
            (driver, h)
        };

        // Flip the gate: the parked flush wakes and sends.
        gate.mark_ready();
        flush.1.await.unwrap();
        assert_eq!(
            sent.lock().await.as_slice(),
            &["b1".to_string()],
            "send proceeds once the relay is ready"
        );
    }

    #[tokio::test]
    async fn ready_gate_already_ready_sends_immediately() {
        // Gate ready before the edge: behaves exactly like the no-gate path.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let gate = ScriptedGate::new();
        gate.mark_ready();
        let (tx, _rx) = broadcast::channel(16);
        let driver = OutboxDriver::new(
            Arc::new(Mutex::new(store)),
            tx,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: sent.clone(),
            },
        )
        .with_ready_gate(gate);
        driver.on_presence(&peer_a(), true).await;
        assert_eq!(sent.lock().await.as_slice(), &["b1".to_string()]);
    }

    #[tokio::test]
    async fn online_edge_flushes_queued_bubble_and_warms() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        let connected = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport {
                connected: connected.clone(),
                sent: sent.clone(),
            },
        );
        driver.on_presence(&peer_a(), true).await; // offline(default)->online edge
        assert_eq!(sent.lock().await.as_slice(), &["b1".to_string()]);
        assert_eq!(connected.lock().await.len(), 1, "warmed before send (C1)");
        let store = driver.store.lock().await;
        let b = store.get("b1").unwrap();
        assert_eq!(b.status, SendState::Sent, "the relay ack, and only it");
        assert_eq!(b.message_id.as_deref(), Some("relay-1"));
    }

    #[tokio::test]
    async fn a_claimed_bubble_is_not_resent() {
        // The in-flight claim -- not the state -- is the double-send guard:
        // a send already in progress (here, the initial send from
        // Client::enqueue_dm) holds the claim, so a presence edge that
        // lands mid-send must not fire a second copy.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        assert!(store.try_mark_inflight("b1", 0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: sent.clone(),
            },
        );
        driver.on_presence(&peer_a(), true).await;
        assert!(
            sent.lock().await.is_empty(),
            "in-flight bubble must not double-send"
        );
    }

    #[tokio::test]
    async fn no_flush_when_already_online() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: sent.clone(),
            },
        );
        driver.on_presence(&peer_a(), true).await; // edge -> flush
        sent.lock().await.clear();
        driver.on_presence(&peer_a(), true).await; // still online, no new edge
        assert!(
            sent.lock().await.is_empty(),
            "no re-flush without an offline->online edge"
        );
    }

    #[tokio::test]
    async fn a_failing_send_leaves_the_message_queued_forever() {
        // The lane's headline: a peer that cannot be reached must never
        // turn a message into a lie. The bubble keeps its Queued state,
        // records the reason as diagnostics, and stays retryable.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        let (driver, _rx) = driver_with(store, ErrTransport);
        driver.on_presence(&peer_a(), true).await;
        let store = driver.store.lock().await;
        let b = store.get("b1").unwrap();
        assert_eq!(b.status, SendState::Queued);
        assert!(b.last_error.is_some());
        assert!(is_retryable(b));
    }

    #[tokio::test]
    async fn sweep_stalled_releases_the_claim_and_re_sends() {
        // A send task that died holding its claim is the one way a queued
        // message can wedge. The sweep releases the claim and re-flushes;
        // the message's state never changes.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 0));
        assert!(store.try_mark_inflight("b1", 0), "simulate the dead task");
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: sent.clone(),
            },
        );
        // Not yet stalled: nothing moves.
        driver.sweep_stalled(STALLED_CLAIM_MS - 1).await;
        assert!(sent.lock().await.is_empty());
        // Past the claim timeout: released and re-sent.
        driver.sweep_stalled(STALLED_CLAIM_MS + 1).await;
        assert_eq!(sent.lock().await.as_slice(), &["b1".to_string()]);
        assert_eq!(
            driver.store.lock().await.get("b1").unwrap().status,
            SendState::Sent
        );
    }

    #[tokio::test]
    async fn boot_sweep_reclaims_orphaned_inflight_for_resend() {
        // A retryable bubble whose in-flight claim leaked when a prior
        // driver was aborted mid-flush. A fresh driver must clear the
        // orphan claim at boot_sweep so the next presence edge re-sends
        // it -- without the clear, try_mark_inflight stays false forever.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Sent, Some("relay-1"), 0));
        assert!(
            store.try_mark_inflight("b1", 0),
            "simulate the leaked claim"
        );
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: sent.clone(),
            },
        );
        driver.boot_sweep().await;
        driver.on_presence(&peer_a(), true).await; // offline->online edge
        assert_eq!(
            sent.lock().await.as_slice(),
            &["b1".to_string()],
            "reclaimed bubble re-sends after its orphan claim is cleared"
        );
    }

    #[tokio::test]
    async fn boot_sweep_leaves_every_state_alone() {
        // A restart is not a delivery verdict: nothing a boot sweep does
        // may change what the user was told about a message.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Queued, None, 10));
        store.upsert(bubble("b2", SendState::Sent, Some("m1"), 10));
        let (driver, mut rx) = driver_with(store, ErrTransport);
        driver.boot_sweep().await;
        let store = driver.store.lock().await;
        assert_eq!(store.get("b1").unwrap().status, SendState::Queued);
        assert_eq!(store.get("b2").unwrap().status, SendState::Sent);
        assert!(rx.try_recv().is_err(), "no state change, no event");
    }

    #[tokio::test]
    async fn a_dm_resend_keeps_the_earlier_id_for_receipt_matching() {
        // Each DM resend mints a fresh logical message id. The receipt for
        // whichever copy the peer decrypted must still close the bubble.
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", SendState::Sent, Some("relay-0"), 0));
        let (driver, _rx) = driver_with(
            store,
            OkTransport {
                connected: Arc::new(Mutex::new(Vec::new())),
                sent: Arc::new(Mutex::new(Vec::new())),
            },
        );
        driver.on_presence(&peer_a(), true).await; // resend -> "relay-1"
        driver.mark_delivered("relay-0", 42).await;
        let store = driver.store.lock().await;
        let b = store.get("b1").unwrap();
        assert_eq!(b.status, SendState::Delivered);
        assert_eq!(b.state_changed_at_ms, 42);
        assert!(b.prior_message_ids.len() <= PRIOR_MESSAGE_ID_CAP);
    }

    /// Simulates a `DeliveryReceipt` landing during the send await: its
    /// `send` marks the bubble Delivered via the shared store before
    /// returning Ok, racing the post-send status update.
    struct DeliverDuringSend {
        store: Arc<Mutex<OutboxStore>>,
        message_id: String,
    }
    impl OutboxTransport for DeliverDuringSend {
        fn connect(&self, _peer: AgentId) -> impl std::future::Future<Output = ()> + Send {
            async {}
        }
        fn send(
            &self,
            _b: OutboxBubble,
        ) -> impl std::future::Future<Output = Result<SendReceipt, ChatError>> + Send {
            let store = self.store.clone();
            let mid = self.message_id.clone();
            async move {
                store.lock().await.mark_delivered(&mid, 7);
                Ok(SendReceipt {
                    accepted_at_ms: 1,
                    message_id: Some(mid),
                    transport_name: "test",
                })
            }
        }
    }

    #[tokio::test]
    async fn delivered_during_inflight_send_is_not_clobbered() {
        let store = Arc::new(Mutex::new(OutboxStore::new()));
        store
            .lock()
            .await
            .upsert(bubble("b1", SendState::Sent, Some("m1"), 0));
        let (tx, _rx) = broadcast::channel(16);
        let driver = OutboxDriver::new(
            store.clone(),
            tx,
            DeliverDuringSend {
                store: store.clone(),
                message_id: "m1".into(),
            },
        );
        // Edge -> flush_peer claims the retryable bubble; the send marks it
        // Delivered mid-flight; the post-send update must NOT clobber it.
        driver.on_presence(&peer_a(), true).await;
        assert_eq!(
            store.lock().await.get("b1").unwrap().status,
            SendState::Delivered
        );
    }
}
