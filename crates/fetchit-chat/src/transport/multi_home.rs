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
//! 5. Otherwise allocate a new slot — fill an empty slot 1/2, or
//!    evict the LRU of 1/2 (slot 0 is immune).
//!
//! Inbound fan-in (D4) and denylist enforcement on `AgentId` (D5+) land
//! in subsequent tasks.

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use fetchit_relay_proto::TransitEnvelope;

use crate::transport::nonce_dedup::NonceDedup;
use crate::transport::InboundEnvelope;

/// Concrete handle returned by [`RelayBuilder::build`]. Production
/// wraps an `Arc<RelayTransport>` (plumbed in D4); tests use
/// [`RelayHandle::mock`] which records sends in an internal buffer for
/// assertion without standing up a real WebSocket.
#[derive(Debug)]
pub struct RelayHandle {
    url: String,
    #[cfg(test)]
    sends: std::sync::Mutex<Vec<TransitEnvelope>>,
    // D4+ will add: transport: Arc<RelayTransport>,
}

impl RelayHandle {
    /// Mock handle used by tests that just need a URL-bearing slot
    /// filler without standing up a live WebSocket. Records every
    /// envelope passed to [`Self::send`] so tests can assert routing.
    /// Not exposed in production builds.
    #[cfg(test)]
    pub(crate) fn mock(url: String) -> Self {
        Self {
            url,
            sends: std::sync::Mutex::new(Vec::new()),
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
    #[allow(dead_code)] // Used by D4 (inbound fan-in).
    inbox_dedup: Arc<std::sync::Mutex<NonceDedup>>,
    denylist: Arc<dyn fetchit_trust::DenylistQuery>,
    #[allow(dead_code)] // Used by D4 (inbound fan-in).
    on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
}

impl MultiHomeTransport {
    /// Construct a new multi-home transport. Slot 0 is opened
    /// immediately to `primary_url`; slots 1 and 2 stay empty until
    /// D3's outbound path opens them.
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
        let handle = builder.build(&primary_url).await?;
        let primary_slot = Slot {
            relay_url: primary_url.clone(),
            handle,
            last_traffic_at: SystemTime::now(),
        };
        let initial_slots: [Option<Slot>; 3] = [Some(primary_slot), None, None];
        let dedup = NonceDedup::new(10_000, std::time::Duration::from_secs(300));
        Ok(Self {
            primary_url,
            builder,
            slots: Arc::new(RwLock::new(initial_slots)),
            inbox_dedup: Arc::new(std::sync::Mutex::new(dedup)),
            denylist,
            on_inbound,
        })
    }

    /// Send `envelope` to the recipient identified by `hints`.
    ///
    /// Slot policy (module doc):
    /// - Picks `hints.relays[0]` as the destination.
    /// - Rejects on relay-URL denylist hit.
    /// - Reuses slot 0 if the destination matches the local primary.
    /// - Reuses slots 1/2 if either matches, refreshing
    ///   `last_traffic_at`.
    /// - Otherwise allocates a new slot — fills an empty slot 1/2 or
    ///   evicts the LRU of 1/2 (slot 0 is never evicted).
    ///
    /// # Errors
    /// - [`TransportError::Blocked`] when the destination relay URL is
    ///   on the active denylist.
    /// - [`TransportError::BuildFailed`] when `hints.relays` is empty,
    ///   when the underlying [`RelayBuilder`] fails to open a new
    ///   slot, or when the per-slot send fails.
    pub async fn send(
        &self,
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
        // AgentId denylist check lands in D5; this slot picks only on
        // the relay URL.

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

        let mut slots = self.slots.write().expect("slots lock");
        slots[victim_idx] = Some(Slot {
            relay_url: target_url.to_string(),
            handle: Arc::clone(&handle),
            last_traffic_at: SystemTime::now(),
        });
        Ok(handle)
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

        mh.send(sample_envelope(), &hints("wss://primary.test/v1/ws"))
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

        mh.send(sample_envelope(), &hints("wss://secondary.test/v1/ws"))
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

        mh.send(sample_envelope(), &hints("wss://r1.test/v1/ws"))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        mh.send(sample_envelope(), &hints("wss://r2.test/v1/ws"))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        mh.send(sample_envelope(), &hints("wss://r3.test/v1/ws"))
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
            .send(sample_envelope(), &hints("wss://evil.test/v1/ws"))
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
}
