//! Multi-home transport — owns up to 3 concurrent `RelayTransport`
//! sessions and fans inbound deliveries into a single deduplicating
//! dispatch stream.
//!
//! Slot policy (per M3 brainstorm Decision 1, locked 2026-06-07):
//! - Slot 0 = my primary, pinned at boot. NEVER evicted.
//! - Slots 1, 2 = LRU-managed, dynamically opened to contacts'
//!   primary relays as outbound traffic dictates. When both are
//!   occupied and a third destination needs a slot, the slot with
//!   the oldest `last_traffic_at` is evicted.
//!
//! D3 wires the outbound send path:
//! 1. Look up `hints.relays[0]` to pick the recipient's primary.
//! 2. Reject on denylist hit.
//! 3. Match against slot 0; if equal, send there.
//! 4. Match against slots 1 + 2; if equal, send there and refresh
//!    `last_traffic_at`.
//! 5. Otherwise allocate a new slot, fill an empty slot 1/2, or
//!    evict the LRU of 1/2 (slot 0 is immune).
//!
//! D4 wires the inbound fan-in: each slot owns an inbound mpsc
//! receiver; per-slot fan-in tasks drain those into a shared
//! [`NonceDedup`] gate and dispatch first-seen envelopes via
//! `on_inbound`. Duplicates arriving on a sibling slot are dropped.
//!
//! D5 hard-blocks outbound sends to a denylisted `AgentId`: the
//! symmetric half of D3's `RelayUrl` check. The inbound `AgentId`
//! block lives in `dispatch.rs` (D7).
//!
//! D6 closes the mid-session reactivity loop: when a `BlockEvent`
//! arrives on the optional [`fetchit_trust_client::BlockEvent`]
//! subscriber with `kind = RelayUrl`, any active slot 1/2 whose
//! `relay_url` is in `added` gets dropped. Slot 0 is immune — the
//! user's chosen primary is a Settings surface concern (G1 banner),
//! not a transport drop. Subsequent sends naturally re-allocate via
//! the LRU path.

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use fetchit_relay_proto::TransitEnvelope;

use crate::transport::nonce_dedup::NonceDedup;
use crate::transport::InboundEnvelope;

/// Concrete handle returned by [`RelayBuilder::build`]. Production
/// wraps an `Arc<RelayTransport>` (plumbed in D5+); tests use
/// [`RelayHandle::mock`] which records sends in an internal buffer
/// and exposes an `inbound_tx` channel for assertion-driven inbound
/// delivery without standing up a real WebSocket.
#[derive(Debug)]
pub struct RelayHandle {
    url: String,
    #[cfg(test)]
    sends: std::sync::Mutex<Vec<TransitEnvelope>>,
    #[cfg(test)]
    inbound_tx: tokio::sync::mpsc::UnboundedSender<InboundEnvelope>,
    #[cfg(test)]
    inbound_rx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>>>,
    // D5+ will add: transport: Arc<RelayTransport>,
}

impl RelayHandle {
    /// Mock handle used by tests that just need a URL-bearing slot
    /// filler without standing up a live WebSocket. Records every
    /// envelope passed to [`Self::send`] so tests can assert routing,
    /// and exposes [`Self::deliver_inbound`] to push test envelopes
    /// into the per-slot inbound channel the multi-home fan-in drains.
    /// Not exposed in production builds.
    #[cfg(test)]
    pub(crate) fn mock(url: String) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            url,
            sends: std::sync::Mutex::new(Vec::new()),
            inbound_tx: tx,
            inbound_rx: std::sync::Mutex::new(Some(rx)),
        }
    }

    /// Borrow the URL this handle was built against.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send an envelope through this relay session.
    ///
    /// In tests, this records the envelope in the mock's internal
    /// buffer and returns `Ok(())`. In production builds (D3 floor),
    /// the underlying [`crate::relay_transport::RelayTransport`] has
    /// not yet been plumbed through — every call returns
    /// [`TransportError::BuildFailed`]. D4 wires the real transport,
    /// at which point this body becomes a genuine await.
    ///
    /// # Errors
    /// Returns [`TransportError::BuildFailed`] in non-test builds
    /// until D4 wires the real transport.
    // `async` is intentional even though D3's body never awaits — D4
    // will plumb `RelayTransport::send` here and needs the future.
    #[allow(clippy::unused_async, clippy::expect_used)]
    pub async fn send(&self, envelope: TransitEnvelope) -> Result<(), TransportError> {
        #[cfg(test)]
        {
            self.sends.lock().expect("sends lock").push(envelope);
            Ok(())
        }
        #[cfg(not(test))]
        {
            let _ = envelope;
            Err(TransportError::BuildFailed(
                "D3 placeholder; D4 plumbs real transport".into(),
            ))
        }
    }

    /// Number of envelopes that were sent via this mock handle.
    #[cfg(test)]
    #[allow(clippy::expect_used)] // poisoned lock is a test bug; panic is fine.
    pub(crate) fn traffic_count_for_test(&self) -> usize {
        self.sends.lock().expect("sends lock").len()
    }

    /// Push a test envelope into this mock handle's inbound channel.
    /// The per-slot fan-in task picks it up and feeds it through the
    /// shared dedup gate.
    #[cfg(test)]
    pub(crate) fn deliver_inbound(&self, env: InboundEnvelope) {
        let _ = self.inbound_tx.send(env);
    }

    /// Take the inbound receiver. Test-only; D5+ replaces this with
    /// a real path via `RelayTransport::take_inbound`. Returns `None`
    /// if the receiver has already been taken (per-slot one-shot
    /// ownership).
    #[cfg(test)]
    #[allow(clippy::expect_used)] // poisoned lock is a test bug; panic is fine.
    pub(crate) fn take_inbound_for_test(
        &self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound_rx.lock().expect("inbound_rx lock").take()
    }
}

/// Builds a [`RelayHandle`] for a given URL. Tests inject a stub
/// builder that returns canned mocks; production will wire a real
/// implementation in D3 that lifts `RelayTransport::connect` behind
/// this trait.
#[async_trait]
pub trait RelayBuilder: Send + Sync {
    /// Open a fresh relay session to `url` and return the handle the
    /// multi-home transport will store in a slot.
    ///
    /// # Errors
    /// Returns [`TransportError::BuildFailed`] on any underlying
    /// handshake or connection failure.
    async fn build(&self, url: &str) -> Result<Arc<RelayHandle>, TransportError>;
}

/// Failure modes specific to [`MultiHomeTransport`] construction and
/// slot management. Kept distinct from
/// [`crate::error::ChatError`] so that D3+'s slot allocator can
/// pattern-match on transport-level failures without dragging the
/// full chat-layer error surface in.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The underlying [`RelayBuilder`] could not establish a session.
    #[error("transport build failed: {0}")]
    BuildFailed(String),
    /// The candidate URL is on the active denylist (enforced by D5+).
    #[error("blocked by denylist: {0}")]
    Blocked(String),
}

/// One occupied slot in [`MultiHomeTransport`]. Carries the URL, the
/// active handle, and the last-traffic timestamp the LRU allocator
/// (D3) will compare against to evict the coldest slot when a new
/// outbound destination needs a slot.
#[derive(Debug, Clone)]
pub struct Slot {
    /// Relay URL this slot is bound to.
    pub relay_url: String,
    /// Active session handle.
    pub handle: Arc<RelayHandle>,
    /// Last inbound-or-outbound traffic timestamp; used by D3's LRU.
    pub last_traffic_at: SystemTime,
}

/// Multi-home transport owning up to 3 active relay sessions.
///
/// Slot 0 is pinned at boot to the local primary URL and is immune
/// from eviction; slots 1 and 2 open dynamically as outbound traffic
/// to remote primaries demands, with LRU eviction when both are
/// occupied. Inbound deliveries fan into a single dispatch stream
/// gated by [`NonceDedup`] (D4).
pub struct MultiHomeTransport {
    #[allow(dead_code)] // Used by D7 (rebuild on net flap).
    primary_url: String,
    builder: Arc<dyn RelayBuilder>,
    slots: Arc<RwLock<[Option<Slot>; 3]>>,
    inbox_dedup: Arc<std::sync::Mutex<NonceDedup>>,
    denylist: Arc<dyn fetchit_trust::DenylistQuery>,
    on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
}

impl MultiHomeTransport {
    /// Construct a new multi-home transport. Slot 0 is opened
    /// immediately to `primary_url`; slots 1 and 2 stay empty until
    /// D3's outbound path opens them.
    ///
    /// Equivalent to
    /// [`Self::new_with_subscriber`]`(primary_url, denylist, on_inbound, builder, None)`:
    /// no mid-session denylist reactivity. Production callers use
    /// `new_with_subscriber` to wire the
    /// [`fetchit_trust_client::DenylistConsumer`] broadcast.
    ///
    /// # Errors
    /// Returns [`TransportError::BuildFailed`] when the `builder`
    /// cannot open slot 0 against `primary_url`.
    pub async fn new(
        primary_url: String,
        denylist: Arc<dyn fetchit_trust::DenylistQuery>,
        on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
        builder: Arc<dyn RelayBuilder>,
    ) -> Result<Self, TransportError> {
        Self::new_with_subscriber(primary_url, denylist, on_inbound, builder, None).await
    }

    /// Construct a multi-home transport with an optional
    /// [`fetchit_trust_client::BlockEvent`] subscriber. When `Some`,
    /// a background task drains the channel and drops any active slot
    /// 1/2 whose `relay_url` appears in a `RelayUrl` block's `added`
    /// list. Slot 0 is immune — see module docs.
    ///
    /// # Errors
    /// Returns [`TransportError::BuildFailed`] when the `builder`
    /// cannot open slot 0 against `primary_url`.
    pub async fn new_with_subscriber(
        primary_url: String,
        denylist: Arc<dyn fetchit_trust::DenylistQuery>,
        on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
        builder: Arc<dyn RelayBuilder>,
        block_events: Option<tokio::sync::broadcast::Receiver<fetchit_trust_client::BlockEvent>>,
    ) -> Result<Self, TransportError> {
        let handle = builder.build(&primary_url).await?;
        let primary_slot = Slot {
            relay_url: primary_url.clone(),
            handle: Arc::clone(&handle),
            last_traffic_at: SystemTime::now(),
        };
        let initial_slots: [Option<Slot>; 3] = [Some(primary_slot), None, None];
        let dedup = NonceDedup::new(10_000, std::time::Duration::from_secs(300));
        let inbox_dedup = Arc::new(std::sync::Mutex::new(dedup));
        Self::spawn_fan_in_for_slot(handle, Arc::clone(&inbox_dedup), Arc::clone(&on_inbound));
        let mh = Self {
            primary_url,
            builder,
            slots: Arc::new(RwLock::new(initial_slots)),
            inbox_dedup,
            denylist,
            on_inbound,
        };
        if let Some(rx) = block_events {
            mh.spawn_denylist_subscriber(rx);
        }
        Ok(mh)
    }

    /// Drain a [`fetchit_trust_client::BlockEvent`] broadcast and drop
    /// any active slot 1/2 whose `relay_url` matches a `RelayUrl`
    /// kind's `added` list. Slot 0 stays — see module docs.
    fn spawn_denylist_subscriber(
        &self,
        mut rx: tokio::sync::broadcast::Receiver<fetchit_trust_client::BlockEvent>,
    ) {
        let slots = Arc::clone(&self.slots);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if !matches!(event.kind, fetchit_trust::EntryKind::RelayUrl)
                            || event.added.is_empty()
                        {
                            continue;
                        }
                        let mut guard = match slots.write() {
                            Ok(g) => g,
                            Err(e) => {
                                log::warn!(
                                    "multi_home slots lock poisoned during denylist drop: {e}",
                                );
                                continue;
                            }
                        };
                        // Slots 1 + 2 only: slot 0 is the user's chosen
                        // primary and a denylist hit there is a Settings
                        // concern (G1 banner), not a transport drop.
                        for slot in guard.iter_mut().skip(1) {
                            let drop_it = slot
                                .as_ref()
                                .is_some_and(|s| event.added.iter().any(|u| u == &s.relay_url));
                            if drop_it {
                                if let Some(s) = slot.as_ref() {
                                    log::info!(
                                        "multi_home dropping slot: relay denylisted mid-session: url={}",
                                        s.relay_url,
                                    );
                                }
                                *slot = None;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Slow consumer; missed events. At worst we'll
                        // miss a single denylist transition for the
                        // active slot; the next outbound send re-checks
                        // `is_blocked` against the cached snapshot.
                    }
                }
            }
        });
    }

    /// Send `envelope` to recipient `to` via the first relay in
    /// `hints`.
    ///
    /// Slot policy (module doc):
    /// - Picks `hints.relays[0]` as the destination.
    /// - Rejects on relay-URL denylist hit.
    /// - Rejects on recipient-`AgentId` denylist hit (D5).
    /// - Reuses slot 0 if the destination matches the local primary.
    /// - Reuses slots 1/2 if either matches, refreshing
    ///   `last_traffic_at`.
    /// - Otherwise allocates a new slot — fills an empty slot 1/2 or
    ///   evicts the LRU of 1/2 (slot 0 is never evicted).
    ///
    /// # Errors
    /// - [`TransportError::Blocked`] when the destination relay URL or
    ///   recipient agent is on the active denylist.
    /// - [`TransportError::BuildFailed`] when `hints.relays` is empty,
    ///   when the underlying [`RelayBuilder`] fails to open a new
    ///   slot, or when the per-slot send fails.
    pub async fn send(
        &self,
        to: &crate::identity::AgentId,
        envelope: TransitEnvelope,
        hints: &crate::card::RendezvousHintsV1,
    ) -> Result<(), TransportError> {
        let target_url = hints
            .relays
            .first()
            .ok_or_else(|| TransportError::BuildFailed("hints.relays empty".into()))?
            .clone();

        if self
            .denylist
            .is_blocked(fetchit_trust::EntryKind::RelayUrl, &target_url)
        {
            return Err(TransportError::Blocked(format!(
                "relay denylisted: {target_url}"
            )));
        }

        // D5: hard-block outbound to a denylisted recipient agent.
        if self
            .denylist
            .is_blocked(fetchit_trust::EntryKind::AgentId, &to.0)
        {
            return Err(TransportError::Blocked(format!(
                "agent denylisted: {}",
                to.0
            )));
        }

        let handle = self.acquire_slot(&target_url).await?;
        handle.send(envelope).await
    }

    /// Acquire a relay handle for `target_url`, opening a new slot if
    /// none currently host it. Slot 0 is pinned and never evicted;
    /// slots 1 and 2 are LRU.
    #[allow(clippy::expect_used)] // RwLock poison is unrecoverable; panic matches `slots_for_test`.
    async fn acquire_slot(&self, target_url: &str) -> Result<Arc<RelayHandle>, TransportError> {
        // Fast path: under a write lock, refresh an existing slot's
        // last_traffic_at if any slot already hosts target_url.
        {
            let mut slots = self.slots.write().expect("slots lock");
            let now = SystemTime::now();
            for slot in slots.iter_mut().flatten() {
                if slot.relay_url == target_url {
                    slot.last_traffic_at = now;
                    return Ok(Arc::clone(&slot.handle));
                }
            }
        }

        // No existing slot hosts target_url. Decide which slot to
        // install into BEFORE building the handle so we don't hold
        // the write lock across the async build call. Slot 0 is
        // immune; pick the first empty 1/2 or the LRU of 1/2.
        let victim_idx = {
            let slots = self.slots.read().expect("slots lock");
            if let Some(empty) = (1..3).find(|&i| slots[i].is_none()) {
                empty
            } else {
                // Both 1 and 2 occupied — evict whichever has the
                // older last_traffic_at. Slot 0 is intentionally
                // ignored here so the pinned primary never moves.
                let lru_1 = slots[1]
                    .as_ref()
                    .map_or_else(SystemTime::now, |s| s.last_traffic_at);
                let lru_2 = slots[2]
                    .as_ref()
                    .map_or_else(SystemTime::now, |s| s.last_traffic_at);
                if lru_1 <= lru_2 {
                    1
                } else {
                    2
                }
            }
        };

        let handle = self.builder.build(target_url).await?;
        Self::spawn_fan_in_for_slot(
            Arc::clone(&handle),
            Arc::clone(&self.inbox_dedup),
            Arc::clone(&self.on_inbound),
        );

        let mut slots = self.slots.write().expect("slots lock");
        slots[victim_idx] = Some(Slot {
            relay_url: target_url.to_string(),
            handle: Arc::clone(&handle),
            last_traffic_at: SystemTime::now(),
        });
        Ok(handle)
    }

    /// Wire a slot's inbound stream into the dedup + dispatch path.
    /// Spawned per slot at slot-construction time (during init for
    /// slot 0; during [`Self::acquire_slot`] for slots 1 + 2).
    ///
    /// The spawned task does NOT keep an [`Arc<RelayHandle>`] alive;
    /// it consumes only the `UnboundedReceiver` taken out of the
    /// handle so that when the slot is evicted the
    /// [`Arc<RelayHandle>`] drops, its `inbound_tx` field drops, the
    /// channel closes, and the task exits naturally on the next
    /// `recv()`.
    #[allow(clippy::expect_used)] // dedup mutex poison is unrecoverable; panic is fine in the fan-in task.
    fn spawn_fan_in_for_slot(
        slot_handle: Arc<RelayHandle>,
        dedup: Arc<std::sync::Mutex<NonceDedup>>,
        on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
    ) {
        #[cfg(test)]
        {
            let Some(mut rx) = slot_handle.take_inbound_for_test() else {
                return;
            };
            let url = slot_handle.url().to_string();
            drop(slot_handle);
            tokio::spawn(async move {
                while let Some(env) = rx.recv().await {
                    let Some(transit) = env.transit.as_ref() else {
                        // No transit envelope means no canonical
                        // nonce to dedup on. Pass through so the
                        // dispatch layer can decide what to do.
                        on_inbound(env);
                        continue;
                    };
                    let Ok(nonce) = <[u8; 12]>::try_from(transit.nonce.as_slice()) else {
                        tracing::debug!(
                            url = %url,
                            "multi-home fan-in: skipping envelope with non-12-byte nonce",
                        );
                        continue;
                    };
                    let key = (env.from.0.clone(), nonce);
                    let pass = {
                        let mut d = dedup.lock().expect("dedup lock");
                        d.observe(key, std::time::Instant::now())
                    };
                    if pass {
                        on_inbound(env);
                    } else {
                        tracing::debug!(url = %url, "multi-home dedup dropped duplicate");
                    }
                }
            });
        }
        #[cfg(not(test))]
        {
            // Production fan-in plumbed in D5+ when RelayHandle wraps
            // Arc<RelayTransport> and exposes a real take_inbound().
            let _ = (slot_handle, dedup, on_inbound);
        }
    }

    /// Snapshot the current slot array for test inspection. Not
    /// exposed in production builds.
    #[cfg(test)]
    #[allow(clippy::expect_used)] // poisoned lock is a test bug; panic is fine.
    pub(crate) fn slots_for_test(&self) -> [Option<Slot>; 3] {
        self.slots.read().expect("slots lock").clone()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_proto::{AgentId as RelayAgentId, EnvelopeKind, MachineId, WIRE_VERSION};

    /// No-op denylist for tests that don't care about block enforcement.
    struct NoopDenylist;
    impl fetchit_trust::DenylistQuery for NoopDenylist {
        fn is_blocked(&self, _: fetchit_trust::EntryKind, _: &str) -> bool {
            false
        }
    }

    /// Stub builder: returns a `RelayHandle::mock(url)` for any URL,
    /// recording every URL it was asked to build.
    #[derive(Default)]
    struct StubRelayBuilder {
        built: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl RelayBuilder for StubRelayBuilder {
        async fn build(&self, url: &str) -> Result<Arc<RelayHandle>, TransportError> {
            self.built.lock().unwrap().push(url.to_string());
            Ok(Arc::new(RelayHandle::mock(url.to_string())))
        }
    }

    /// Denylist stub that blocks one specific relay URL.
    struct BlockOneRelay(&'static str);
    impl fetchit_trust::DenylistQuery for BlockOneRelay {
        fn is_blocked(&self, kind: fetchit_trust::EntryKind, value: &str) -> bool {
            kind == fetchit_trust::EntryKind::RelayUrl && value == self.0
        }
    }

    /// Denylist stub that blocks specific `AgentId` hex strings.
    struct AgentBlockingDenylist {
        blocked_agents: Vec<String>,
    }
    impl AgentBlockingDenylist {
        fn new(blocked: &[&str]) -> Self {
            Self {
                blocked_agents: blocked.iter().map(|s| (*s).to_string()).collect(),
            }
        }
    }
    impl fetchit_trust::DenylistQuery for AgentBlockingDenylist {
        fn is_blocked(&self, kind: fetchit_trust::EntryKind, value: &str) -> bool {
            matches!(kind, fetchit_trust::EntryKind::AgentId)
                && self.blocked_agents.iter().any(|v| v == value)
        }
    }

    fn sample_envelope() -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes([0x11u8; 32]),
            sender_machine_id: MachineId::from_bytes([0x22u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 0,
            ciphertext: vec![0xaa; 16],
            nonce: vec![0xbb; 12],
            kem_ciphertext: vec![0xcc; 32],
            sender_signature: vec![0xdd; 64],
        }
    }

    fn hints(url: &str) -> crate::card::RendezvousHintsV1 {
        crate::card::RendezvousHintsV1 {
            relays: vec![url.to_string()],
        }
    }

    /// Default test recipient: a stable 64-hex agent id distinct
    /// from the D5 denylist tests' `blocked_hex` / `allowed_hex`.
    fn sample_recipient() -> crate::identity::AgentId {
        crate::identity::AgentId("1".repeat(64))
    }

    /// Build an inbound envelope keyed on `(sender, nonce)` for the
    /// dedup gate. The dedup key components are
    /// `(InboundEnvelope.from.0, transit.nonce[..12])` — every other
    /// field is set to a stable default so equality-by-key is the
    /// only thing distinguishing two test envelopes.
    fn sample_inbound_envelope(sender: &str, nonce: [u8; 12]) -> InboundEnvelope {
        // The sender_agent_id field carried in the transit envelope
        // is a 32-byte fingerprint; the dedup key uses only the outer
        // `from.0` String, so the byte form here is arbitrary.
        let sender_bytes = {
            let mut b = [0u8; 32];
            for (i, ch) in sender.as_bytes().iter().take(32).enumerate() {
                b[i] = *ch;
            }
            b
        };
        let transit = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(sender_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 0,
            ciphertext: vec![0xaa; 16],
            nonce: nonce.to_vec(),
            kem_ciphertext: vec![0xcc; 32],
            sender_signature: vec![0xdd; 64],
        };
        InboundEnvelope {
            kind: crate::transport::OutboundKind::Dm,
            from: crate::identity::AgentId(sender.to_string()),
            payload: vec![0xee; 16],
            timestamp_ms: 1_700_000_000_000,
            transport_name: "multi-home-test",
            transit: Some(transit),
        }
    }

    #[tokio::test]
    async fn new_opens_slot_zero_to_primary() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_env| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .expect("new succeeds");
        let slots = mh.slots_for_test();
        assert_eq!(
            slots[0].as_ref().map(|s| s.relay_url.as_str()),
            Some("wss://primary.test/v1/ws")
        );
        assert!(slots[1].is_none());
        assert!(slots[2].is_none());
        assert_eq!(
            builder.built.lock().unwrap().clone(),
            vec!["wss://primary.test/v1/ws".to_string()]
        );
    }

    /// Sending to the primary URL reuses slot 0 — no new builder call,
    /// no allocation in slot 1/2, and the slot-0 handle records the
    /// envelope.
    #[tokio::test]
    async fn send_to_primary_uses_slot_zero() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_env| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://primary.test/v1/ws"),
        )
        .await
        .unwrap();

        let slots = mh.slots_for_test();
        assert!(slots[0].is_some());
        assert!(slots[1].is_none());
        assert!(slots[2].is_none());
        // Builder ran exactly once — for slot 0 at init.
        assert_eq!(builder.built.lock().unwrap().len(), 1);
        let handle = Arc::clone(&slots[0].as_ref().unwrap().handle);
        assert_eq!(handle.traffic_count_for_test(), 1);
    }

    /// Sending to a non-primary URL opens slot 1 and routes through it.
    /// Slot 0 stays bound to the primary; the new handle records the
    /// envelope; slot 2 stays empty.
    #[tokio::test]
    async fn send_to_non_primary_opens_slot_one() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_env| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://secondary.test/v1/ws"),
        )
        .await
        .unwrap();

        let slots = mh.slots_for_test();
        assert_eq!(
            slots[0].as_ref().map(|s| s.relay_url.as_str()),
            Some("wss://primary.test/v1/ws"),
        );
        assert_eq!(
            slots[1].as_ref().map(|s| s.relay_url.as_str()),
            Some("wss://secondary.test/v1/ws"),
        );
        assert!(slots[2].is_none());
        assert_eq!(
            slots[1].as_ref().unwrap().handle.traffic_count_for_test(),
            1
        );
    }

    /// Sending to a fourth distinct URL evicts the LRU of slots 1+2 —
    /// never slot 0. Order: primary opens at boot, then r1 (slot 1),
    /// then r2 (slot 2), then r3 — r1 is oldest so it gets evicted.
    #[tokio::test]
    async fn send_evicts_lru_of_slots_1_2_when_full() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_env| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://r1.test/v1/ws"),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://r2.test/v1/ws"),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://r3.test/v1/ws"),
        )
        .await
        .unwrap();

        let slots = mh.slots_for_test();
        let urls: Vec<String> = slots
            .iter()
            .filter_map(|s| s.as_ref().map(|x| x.relay_url.clone()))
            .collect();
        // Slot 0 is immune — primary survives unconditionally.
        assert!(urls.contains(&"wss://primary.test/v1/ws".to_string()));
        // r2 + r3 are the warmest; r1 is the LRU and was evicted.
        assert!(urls.contains(&"wss://r2.test/v1/ws".to_string()));
        assert!(urls.contains(&"wss://r3.test/v1/ws".to_string()));
        assert!(!urls.contains(&"wss://r1.test/v1/ws".to_string()));
    }

    /// A denylisted destination short-circuits with
    /// `TransportError::Blocked` without touching the slots.
    #[tokio::test]
    async fn send_to_denylisted_relay_returns_blocked() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> =
            Arc::new(BlockOneRelay("wss://evil.test/v1/ws"));
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_env| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let err = mh
            .send(
                &sample_recipient(),
                sample_envelope(),
                &hints("wss://evil.test/v1/ws"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransportError::Blocked(_)),
            "expected Blocked, got {err:?}",
        );
        // No allocation happened — only the slot-0 build at init.
        assert_eq!(builder.built.lock().unwrap().len(), 1);
        let slots = mh.slots_for_test();
        assert!(slots[1].is_none());
        assert!(slots[2].is_none());
    }

    /// D5: an outbound send to a denylisted recipient short-circuits
    /// with `TransportError::Blocked` even when the destination relay
    /// is allowed. No slot 1/2 allocation occurs and the relay handle
    /// records nothing.
    #[tokio::test]
    async fn send_to_denylisted_agent_returns_blocked_error() {
        let builder = Arc::new(StubRelayBuilder::default());
        let blocked_hex = "d".repeat(64);
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> =
            Arc::new(AgentBlockingDenylist::new(&[blocked_hex.as_str()]));
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let result = mh
            .send(
                &crate::identity::AgentId(blocked_hex.clone()),
                sample_envelope(),
                &hints("wss://primary.test/v1/ws"),
            )
            .await;
        assert!(
            matches!(result, Err(TransportError::Blocked(_))),
            "expected Blocked, got {result:?}",
        );
        // Only the slot-0 build at init: the block fires before
        // acquire_slot would dial.
        assert_eq!(builder.built.lock().unwrap().len(), 1);
        let slot0_handle = Arc::clone(&mh.slots_for_test()[0].as_ref().unwrap().handle);
        assert_eq!(slot0_handle.traffic_count_for_test(), 0);
    }

    /// D5: a send to a non-denylisted agent still succeeds even when
    /// other agents are on the denylist; the check is value-scoped,
    /// not kind-scoped.
    #[tokio::test]
    async fn send_to_non_blocked_agent_succeeds_even_when_others_blocked() {
        let builder = Arc::new(StubRelayBuilder::default());
        let blocked_hex = "d".repeat(64);
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> =
            Arc::new(AgentBlockingDenylist::new(&[blocked_hex.as_str()]));
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let allowed_hex = "a".repeat(64);
        mh.send(
            &crate::identity::AgentId(allowed_hex),
            sample_envelope(),
            &hints("wss://primary.test/v1/ws"),
        )
        .await
        .unwrap();
    }

    /// A first-seen inbound envelope on slot 0 fans through the dedup
    /// gate and reaches `on_inbound` exactly once.
    #[tokio::test]
    async fn inbound_passes_through_on_first_seen() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = Arc::clone(&count);
        let on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync> = Arc::new(move |_| {
            count_cb.fetch_add(1, Ordering::SeqCst);
        });

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            on_inbound,
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let slot0_handle = Arc::clone(&mh.slots_for_test()[0].as_ref().unwrap().handle);
        slot0_handle.deliver_inbound(sample_inbound_envelope("alice", [1u8; 12]));

        // Give the spawned task time to drain.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// The same envelope arriving over two slots (same `(sender,
    /// nonce)` key) reaches `on_inbound` exactly once. The dedup gate
    /// drops the sibling delivery.
    #[tokio::test]
    async fn duplicate_inbound_across_slots_dedup_to_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = Arc::clone(&count);
        let on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync> = Arc::new(move |_| {
            count_cb.fetch_add(1, Ordering::SeqCst);
        });

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            on_inbound,
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        // Open slot 1 via an outbound send to a second URL.
        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://secondary.test/v1/ws"),
        )
        .await
        .unwrap();

        let slot0_handle = Arc::clone(&mh.slots_for_test()[0].as_ref().unwrap().handle);
        let slot1_handle = Arc::clone(&mh.slots_for_test()[1].as_ref().unwrap().handle);

        slot0_handle.deliver_inbound(sample_inbound_envelope("alice", [9u8; 12]));
        slot1_handle.deliver_inbound(sample_inbound_envelope("alice", [9u8; 12]));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "duplicate (sender, nonce) across slots dedups to one",
        );
    }

    /// D6: a mid-session `RelayUrl` block event drops the matching
    /// slot 1/2 (slot 0 is immune). Subsequent sends would naturally
    /// re-allocate via the LRU path; the assertion here is only that
    /// the active slot got cleared.
    #[tokio::test]
    async fn mid_session_relay_block_drops_active_slot() {
        use tokio::sync::broadcast;

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let (tx, rx) = broadcast::channel::<fetchit_trust_client::BlockEvent>(16);

        let mh = MultiHomeTransport::new_with_subscriber(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
            Some(rx),
        )
        .await
        .unwrap();

        // Open slot 1 via outbound send so there's something to drop.
        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://later-blocked.test/v1/ws"),
        )
        .await
        .unwrap();
        assert!(mh.slots_for_test()[1].is_some());

        // Emit a block event for the slot 1 URL.
        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://later-blocked.test/v1/ws".to_string()],
            removed: vec![],
        });

        // Let the subscriber task process.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let slots = mh.slots_for_test();
        let urls: Vec<&str> = slots
            .iter()
            .filter_map(|s| s.as_ref().map(|x| x.relay_url.as_str()))
            .collect();
        assert!(
            !urls.contains(&"wss://later-blocked.test/v1/ws"),
            "slot to denylisted relay should have been dropped, got {urls:?}",
        );
        assert!(
            urls.contains(&"wss://primary.test/v1/ws"),
            "slot 0 stays — it's the primary",
        );
    }

    /// D6: slot 0 (primary) is immune from the mid-session drop even
    /// when its URL appears in the block event. Surfacing a denylisted
    /// primary is a Settings concern (G1 banner), not a transport drop.
    #[tokio::test]
    async fn mid_session_relay_block_does_not_drop_slot_zero() {
        use tokio::sync::broadcast;

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let (tx, rx) = broadcast::channel::<fetchit_trust_client::BlockEvent>(16);

        let mh = MultiHomeTransport::new_with_subscriber(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
            Some(rx),
        )
        .await
        .unwrap();

        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://primary.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(
            mh.slots_for_test()[0]
                .as_ref()
                .map(|s| s.relay_url.as_str()),
            Some("wss://primary.test/v1/ws"),
            "slot 0 must survive a denylist of its own URL",
        );
    }

    /// D6: a non-`RelayUrl` block event (`AgentId`, `XorName`, `ActorUrl`)
    /// does NOT touch any slot. Slot drops are scoped to
    /// `EntryKind::RelayUrl` only — the `AgentId` block path is the
    /// outbound `send` guard (D5).
    #[tokio::test]
    async fn mid_session_non_relay_block_does_not_touch_slots() {
        use tokio::sync::broadcast;

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let (tx, rx) = broadcast::channel::<fetchit_trust_client::BlockEvent>(16);

        let mh = MultiHomeTransport::new_with_subscriber(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
            Some(rx),
        )
        .await
        .unwrap();

        mh.send(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://secondary.test/v1/ws"),
        )
        .await
        .unwrap();
        let before: Vec<String> = mh
            .slots_for_test()
            .iter()
            .filter_map(|s| s.as_ref().map(|x| x.relay_url.clone()))
            .collect();

        // Same URL value, but kind=AgentId — must not match the slot
        // drop. (The hex shape is wrong for an AgentId, but the
        // subscriber filters on kind, not on value validity.)
        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::AgentId,
            added: vec!["wss://secondary.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let after: Vec<String> = mh
            .slots_for_test()
            .iter()
            .filter_map(|s| s.as_ref().map(|x| x.relay_url.clone()))
            .collect();
        assert_eq!(
            before, after,
            "non-RelayUrl block kinds must not drop any slot",
        );
    }

    /// Distinct dedup keys (different nonces, different senders) each
    /// pass through independently.
    #[tokio::test]
    async fn distinct_nonces_each_pass_through() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = Arc::clone(&count);
        let on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync> = Arc::new(move |_| {
            count_cb.fetch_add(1, Ordering::SeqCst);
        });

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            on_inbound,
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let slot0_handle = Arc::clone(&mh.slots_for_test()[0].as_ref().unwrap().handle);
        slot0_handle.deliver_inbound(sample_inbound_envelope("alice", [1u8; 12]));
        slot0_handle.deliver_inbound(sample_inbound_envelope("alice", [2u8; 12]));
        slot0_handle.deliver_inbound(sample_inbound_envelope("bob", [1u8; 12]));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
