//! Multi-home transport — owns up to 3 concurrent `RelayTransport`
//! sessions and fans inbound deliveries into a single deduplicating
//! dispatch stream.
//!
//! Slot policy (per M3 brainstorm Decision 1, locked 2026-06-07):
//! - Slot 0 = my primary, pinned at boot.
//! - Slots 1, 2 = LRU-managed, dynamically opened to contacts'
//!   primary relays as outbound traffic dictates.
//!
//! This module is the structural skeleton for the multi-home work
//! (M3 Task D2). Slot allocation (D3), inbound fan-in (D4), and
//! denylist enforcement (D5+) land in subsequent tasks.

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;

use crate::transport::nonce_dedup::NonceDedup;
use crate::transport::InboundEnvelope;

/// Concrete handle returned by [`RelayBuilder::build`]. In production
/// this wraps an actual [`crate::relay_transport::RelayTransport`]; in
/// tests it is a mock that just remembers its URL. D3 will replace
/// this with the real `Arc<RelayTransport>` integration.
#[derive(Debug)]
pub struct RelayHandle {
    url: String,
    // D3+ will add: transport: Arc<RelayTransport>,
}

impl RelayHandle {
    /// Mock handle used by tests that just need a URL-bearing slot
    /// filler without standing up a live WebSocket. Not exposed in
    /// production builds.
    #[cfg(test)]
    pub(crate) fn mock(url: String) -> Self {
        Self { url }
    }

    /// Borrow the URL this handle was built against.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
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
/// Slot 0 is pinned at boot to the local primary URL; slots 1 and 2
/// open dynamically in D3 as outbound traffic to remote primaries
/// demands. Inbound deliveries fan into a single dispatch stream
/// gated by [`NonceDedup`] (D4).
pub struct MultiHomeTransport {
    #[allow(dead_code)] // Used by D3 (slot allocator) and D7 (rebuild on net flap).
    primary_url: String,
    #[allow(dead_code)] // Used by D3 to build slots 1 and 2 on demand.
    builder: Arc<dyn RelayBuilder>,
    #[allow(dead_code)] // Read in prod by D3+; today only `slots_for_test` consumes it.
    slots: Arc<RwLock<[Option<Slot>; 3]>>,
    #[allow(dead_code)] // Used by D4 (inbound fan-in).
    inbox_dedup: Arc<std::sync::Mutex<NonceDedup>>,
    #[allow(dead_code)] // Used by D5 (denylist enforcement on slot open).
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
}
