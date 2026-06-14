//! Background retry driver -- the resend policy that used to live in
//! desktop's `outboxDriver.ts`, now engine-owned so desktop and Android
//! share it.
//!
//! The driver owns the [`OutboxStore`] behind a mutex and re-sends
//! retryable bubbles on each peer offline->online edge, warming the link
//! first (so the initial and retry sends skip the cold-QUIC timeout). It
//! runs a 24h timeout sweep and a boot sweep, and broadcasts an
//! [`OutboxEvent`] for every bubble mutation so the shell can project
//! live status. The transport is abstracted ([`OutboxTransport`]) so the
//! loop is unit-testable with scripted doubles; production wires it to the
//! `Router` + `messages().connect()`.

use super::store::OutboxStore;
use super::{is_retryable, OutboxBubble, OutboxEvent, OutboxStatus};
use crate::error::ChatError;
use crate::identity::AgentId;
use crate::transport::SendReceipt;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// How long a bubble may sit `Sending` before the timeout sweep flips it
/// to `Failed`. 24h, matching desktop's `outboxDriver`.
pub const SEND_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

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

/// Background retry driver. Owns the outbox state + the retry policy; the
/// shell only starts it and renders the [`OutboxEvent`] stream.
pub struct OutboxDriver<T: OutboxTransport> {
    store: Arc<Mutex<OutboxStore>>,
    events: broadcast::Sender<OutboxEvent>,
    transport: T,
    last_online: Mutex<HashMap<AgentId, bool>>,
    process_start_ms: u64,
}

impl<T: OutboxTransport> OutboxDriver<T> {
    /// Build a driver over `store`, broadcasting changes on `events`.
    /// `process_start_ms` anchors the boot sweep (bubbles enqueued before
    /// it with no `message_id` are treated as orphaned).
    pub fn new(
        store: Arc<Mutex<OutboxStore>>,
        events: broadcast::Sender<OutboxEvent>,
        transport: T,
        process_start_ms: u64,
    ) -> Self {
        Self {
            store,
            events,
            transport,
            last_online: Mutex::new(HashMap::new()),
            process_start_ms,
        }
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
        // Claim the eligible bubbles under the lock, then release it for
        // the awaits below.
        let claims: Vec<OutboxBubble> = {
            let mut store = self.store.lock().await;
            let candidates: Vec<OutboxBubble> = store
                .snapshot()
                .into_iter()
                .filter(|b| &b.peer == peer && is_retryable(b))
                .collect();
            candidates
                .into_iter()
                .filter(|b| store.try_mark_inflight(&b.id))
                .collect()
        };
        for claimed in claims {
            self.transport.connect(peer.clone()).await;
            let result = self.transport.send(claimed.clone()).await;
            let emitted = {
                let mut store = self.store.lock().await;
                // The bubble may have been removed while in flight; only
                // update if it is still present.
                let updated = store.get(&claimed.id).cloned().map(|mut current| {
                    match &result {
                        Ok(receipt) => {
                            if let Some(mid) = receipt.message_id.clone() {
                                current.message_id = Some(mid);
                            }
                            current.status = OutboxStatus::Sending;
                            current.last_error = None;
                        }
                        Err(e) => {
                            current.status = OutboxStatus::Failed;
                            current.last_error = Some(e.to_string());
                        }
                    }
                    current
                });
                if let Some(u) = &updated {
                    store.upsert(u.clone());
                }
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

    /// Run the 24h timeout sweep against `now_ms`, emitting any changes.
    pub async fn sweep_timeouts(&self, now_ms: u64) {
        let changed = self.store.lock().await.sweep_timeouts(now_ms, SEND_TIMEOUT_MS);
        self.emit(changed);
    }

    /// Run the boot sweep (orphaned in-flight bubbles -> Failed), emitting
    /// any changes. Call once at startup.
    pub async fn boot_sweep(&self) {
        let changed = self.store.lock().await.boot_sweep(self.process_start_ms);
        self.emit(changed);
    }

    /// Mark the bubble carrying `message_id` Delivered (DeliveryReceipt
    /// inbound path), emitting the change.
    pub async fn mark_delivered(&self, message_id: &str) {
        let changed = self.store.lock().await.mark_delivered(message_id);
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
                .filter(|b| is_retryable(b))
                .filter_map(|b| seen.insert(b.peer.clone()).then_some(b.peer))
                .collect()
        };
        for peer in peers {
            self.flush_peer(&peer).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn peer_a() -> AgentId {
        AgentId("aa".repeat(32))
    }

    fn bubble(id: &str, status: OutboxStatus, message_id: Option<&str>, enqueued_at_ms: u64) -> OutboxBubble {
        OutboxBubble {
            id: id.into(),
            peer: peer_a(),
            body: "hi".into(),
            status,
            message_id: message_id.map(Into::into),
            enqueued_at_ms,
            last_error: None,
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
        process_start_ms: u64,
    ) -> (OutboxDriver<T>, broadcast::Receiver<OutboxEvent>) {
        let (tx, rx) = broadcast::channel(16);
        let driver = OutboxDriver::new(Arc::new(Mutex::new(store)), tx, transport, process_start_ms);
        (driver, rx)
    }

    #[tokio::test]
    async fn online_edge_flushes_failed_bubble_and_warms() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", OutboxStatus::Failed, None, 0));
        let connected = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport { connected: connected.clone(), sent: sent.clone() },
            0,
        );
        driver.on_presence(&peer_a(), true).await; // offline(default)->online edge
        assert_eq!(sent.lock().await.as_slice(), &["b1".to_string()]);
        assert_eq!(connected.lock().await.len(), 1, "warmed before send (C1)");
        let store = driver.store.lock().await;
        let b = store.get("b1").unwrap();
        assert_eq!(b.status, OutboxStatus::Sending); // markSent keeps sending
        assert_eq!(b.message_id.as_deref(), Some("relay-1"));
    }

    #[tokio::test]
    async fn sending_without_message_id_is_not_resent() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", OutboxStatus::Sending, None, 0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport { connected: Arc::new(Mutex::new(Vec::new())), sent: sent.clone() },
            0,
        );
        driver.on_presence(&peer_a(), true).await;
        assert!(sent.lock().await.is_empty(), "in-flight bubble must not double-send");
    }

    #[tokio::test]
    async fn no_flush_when_already_online() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", OutboxStatus::Failed, None, 0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (driver, _rx) = driver_with(
            store,
            OkTransport { connected: Arc::new(Mutex::new(Vec::new())), sent: sent.clone() },
            0,
        );
        driver.on_presence(&peer_a(), true).await; // edge -> flush
        sent.lock().await.clear();
        driver.on_presence(&peer_a(), true).await; // still online, no new edge
        assert!(sent.lock().await.is_empty(), "no re-flush without an offline->online edge");
    }

    #[tokio::test]
    async fn send_error_marks_failed_with_reason() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", OutboxStatus::Failed, None, 0));
        let (driver, _rx) = driver_with(store, ErrTransport, 0);
        driver.on_presence(&peer_a(), true).await;
        let store = driver.store.lock().await;
        let b = store.get("b1").unwrap();
        assert_eq!(b.status, OutboxStatus::Failed);
        assert!(b.last_error.is_some());
    }

    #[tokio::test]
    async fn timeout_sweep_fails_and_emits() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", OutboxStatus::Sending, None, 0));
        let (driver, mut rx) = driver_with(store, ErrTransport, 0);
        driver.sweep_timeouts(SEND_TIMEOUT_MS + 1).await;
        assert_eq!(
            driver.store.lock().await.get("b1").unwrap().status,
            OutboxStatus::Failed
        );
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.bubble.id, "b1");
        assert_eq!(ev.bubble.status, OutboxStatus::Failed);
    }

    #[tokio::test]
    async fn boot_sweep_fails_orphan_and_emits() {
        let mut store = OutboxStore::new();
        store.upsert(bubble("b1", OutboxStatus::Sending, None, 10));
        let (driver, mut rx) = driver_with(store, ErrTransport, 100); // process started after enqueue
        driver.boot_sweep().await;
        assert_eq!(
            driver.store.lock().await.get("b1").unwrap().status,
            OutboxStatus::Failed
        );
        assert_eq!(rx.try_recv().unwrap().bubble.id, "b1");
    }
}
