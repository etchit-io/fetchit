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
use crate::transport::{InboundEnvelope, OutboundEnvelope, OutboundKind, SendReceipt};

const TRANSPORT_NAME: &str = "multi-home";

/// Upper bound on how long [`MultiHomeTransport::replace_primary`] waits
/// for the freshly built slot-0 relay to report
/// [`fetchit_relay_client::ConnState::Connected`] before declaring the
/// swap failed. On timeout the new session is torn down and the old slot
/// 0 is left intact.
const REPLACE_PRIMARY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Concrete handle returned by [`RelayBuilder::build`]. Production
/// wraps an `Arc<RelayTransport>` ([`RelayHandle::from_transport`]);
/// tests use `RelayHandle::mock` which records sends in an internal
/// buffer and exposes an `inbound_tx` channel for assertion-driven
/// inbound delivery without standing up a real WebSocket.
pub struct RelayHandle {
    url: String,
    /// Production: real transport. `None` for mock handles built via
    /// [`RelayHandle::mock`] — those route through the test recording
    /// fields below.
    transport: Option<Arc<crate::relay_transport::RelayTransport>>,
    #[cfg(test)]
    sends: std::sync::Mutex<Vec<TransitEnvelope>>,
    #[cfg(test)]
    inbound_tx: tokio::sync::mpsc::UnboundedSender<InboundEnvelope>,
    #[cfg(test)]
    inbound_rx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>>>,
}

impl std::fmt::Debug for RelayHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayHandle")
            .field("url", &self.url)
            .field("transport", &self.transport.as_ref().map(|_| "<connected>"))
            .finish_non_exhaustive()
    }
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
            transport: None,
            sends: std::sync::Mutex::new(Vec::new()),
            inbound_tx: tx,
            inbound_rx: std::sync::Mutex::new(Some(rx)),
        }
    }

    /// Production constructor: wrap an already-connected
    /// [`crate::relay_transport::RelayTransport`] together with the URL
    /// it was opened against. [`RealRelayBuilder::build`] is the only
    /// production caller.
    #[must_use]
    pub fn from_transport(
        url: String,
        transport: Arc<crate::relay_transport::RelayTransport>,
    ) -> Self {
        Self {
            url,
            transport: Some(transport),
            #[cfg(test)]
            sends: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            inbound_tx: tokio::sync::mpsc::unbounded_channel().0,
            #[cfg(test)]
            inbound_rx: std::sync::Mutex::new(None),
        }
    }

    /// Borrow the URL this handle was built against.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Borrow the wrapped [`crate::relay_transport::RelayTransport`] for
    /// callers that need direct access to its presence-watch surface
    /// (e.g. `Client::watch_relay_presence`). Returns `None` for mock
    /// handles built via `Self::mock`.
    #[must_use]
    pub fn relay_transport_arc(&self) -> Option<Arc<crate::relay_transport::RelayTransport>> {
        self.transport.clone()
    }

    /// Send `envelope` to `to` through this relay session.
    ///
    /// Production handles ([`Self::from_transport`]) delegate to the
    /// wrapped [`crate::relay_transport::RelayTransport`]; test mocks
    /// (`Self::mock`) record the transit envelope in an internal
    /// buffer and synthesize a placeholder [`SendReceipt`] so tests
    /// can assert routing without standing up a real WebSocket.
    ///
    /// Mid-tier `RelayHandle`s built without a transport in non-test
    /// builds (a misuse) return [`TransportError::BuildFailed`].
    ///
    /// # Errors
    /// - [`TransportError::BuildFailed`] wrapping any underlying
    ///   [`crate::error::ChatError`] from the real transport, including
    ///   [`crate::error::ChatError::SealedRequired`] when `envelope.transit`
    ///   is `None`.
    #[allow(clippy::expect_used)]
    pub async fn send(
        &self,
        to: &crate::identity::AgentId,
        envelope: OutboundEnvelope,
    ) -> Result<SendReceipt, TransportError> {
        if let Some(transport) = &self.transport {
            // The underlying RelayTransport binds to a single relay URL
            // and ignores hints (R-tail-1); MultiHomeTransport's slot
            // policy is what selected this handle, so hints have already
            // done their work.
            return <crate::relay_transport::RelayTransport as crate::transport::Transport>::send(
                transport, to, envelope, None,
            )
            .await
            .map_err(|e| TransportError::BuildFailed(format!("relay send: {e}")));
        }
        #[cfg(test)]
        {
            let transit = envelope.transit.ok_or_else(|| {
                TransportError::BuildFailed("RelayHandle::send mock: missing transit".into())
            })?;
            self.sends.lock().expect("sends lock").push(transit);
            Ok(SendReceipt {
                accepted_at_ms: 0,
                message_id: None,
                transport_name: "multi-home-mock",
            })
        }
        #[cfg(not(test))]
        {
            let _ = (to, envelope);
            Err(TransportError::BuildFailed(
                "RelayHandle::send called without a transport".into(),
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
/// builder that returns canned mocks; production uses
/// [`RealRelayBuilder`] which opens a live WebSocket via
/// [`crate::relay_transport::RelayTransport::connect`].
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

/// Production [`RelayBuilder`]: each [`Self::build`] call opens a real
/// WebSocket via [`crate::relay_transport::RelayTransport::connect`]
/// using the supplied [`fetchit_relay_client::Signer`] for the
/// bearer-token handshake, then wraps the connected transport in a
/// [`RelayHandle`] for [`MultiHomeTransport`] slot ownership.
pub struct RealRelayBuilder {
    signer: Arc<dyn fetchit_relay_client::Signer>,
}

impl RealRelayBuilder {
    /// Construct a builder that authenticates every relay handshake
    /// with `signer`. In production this is an
    /// `X0xdSigner`; tests use `StaticKeySigner`.
    #[must_use]
    pub fn new(signer: Arc<dyn fetchit_relay_client::Signer>) -> Self {
        Self { signer }
    }
}

#[async_trait]
impl RelayBuilder for RealRelayBuilder {
    async fn build(&self, url: &str) -> Result<Arc<RelayHandle>, TransportError> {
        let parsed = url::Url::parse(url)
            .map_err(|e| TransportError::BuildFailed(format!("invalid relay url {url}: {e}")))?;
        let transport =
            crate::relay_transport::RelayTransport::connect(parsed, Arc::clone(&self.signer))
                .await
                .map_err(|e| TransportError::BuildFailed(format!("relay connect: {e}")))?;
        Ok(Arc::new(RelayHandle::from_transport(
            url.to_string(),
            transport,
        )))
    }
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
    /// A [`MultiHomeTransport::replace_primary`] swap built a session to
    /// the new relay but it did not reach
    /// [`fetchit_relay_client::ConnState::Connected`] within
    /// `REPLACE_PRIMARY_CONNECT_TIMEOUT`. The new session was torn down
    /// and the existing slot 0 left untouched, so the caller can retry or
    /// keep the old primary.
    #[error("relay swap did not go live: {url}")]
    SwapNotLive {
        /// The relay URL the failed swap targeted.
        url: String,
    },
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
    /// Abort handle for this slot's fan-in task (the loop draining the
    /// per-slot inbound stream into the shared dedup gate). Held so
    /// teardown (e.g. [`MultiHomeTransport::replace_primary`]) can stop
    /// the fan-in deterministically. `None` only for slots whose handle
    /// exposed no inbound receiver. Dropping an
    /// [`tokio::task::AbortHandle`] does NOT abort the task — teardown
    /// must call `.abort()` explicitly.
    pub fan_in: Option<tokio::task::AbortHandle>,
}

/// M3 G1 — closure shape the primary-denylisted callback registers.
/// Type-aliased so the struct field + the `set_*_callback` setter
/// share one canonical name (`clippy::type_complexity` gate).
pub type PrimaryDenylistedCallback = Arc<dyn Fn(String) + Send + Sync>;

/// Multi-home transport owning up to 3 active relay sessions.
///
/// Slot 0 is pinned at boot to the local primary URL and is immune
/// from eviction; slots 1 and 2 open dynamically as outbound traffic
/// to remote primaries demands, with LRU eviction when both are
/// occupied. Inbound deliveries fan into a single dispatch stream
/// gated by [`NonceDedup`] (D4).
pub struct MultiHomeTransport {
    /// URL that names slot 0 — the user's pinned primary. Retained for
    /// diagnostics, the G1 primary-denylisted match (the denylist
    /// subscriber reads it), and future fallback-policy work; the live
    /// slot 0 is owned by [`Self::slots`] and reachable via
    /// [`Self::slot_zero_handle`].
    ///
    /// Interior-mutable so [`Self::replace_primary`] can keep it accurate
    /// across a home-relay failover: the only reader is the denylist
    /// subscriber's primary match, which must follow the live slot-0 URL
    /// or it would key off a stale value after a swap. `Arc`-wrapped so
    /// the spawned subscriber task can share ownership and read the live
    /// value across its `await` points.
    primary_url: Arc<RwLock<String>>,
    builder: Arc<dyn RelayBuilder>,
    slots: Arc<RwLock<[Option<Slot>; 3]>>,
    inbox_dedup: Arc<std::sync::Mutex<NonceDedup>>,
    denylist: Arc<dyn fetchit_trust::DenylistQuery>,
    on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
    /// M3 G1: optional callback the denylist subscriber invokes when
    /// the user's primary relay (slot 0) is added to the community
    /// denylist mid-session. Slot 0 is NOT dropped (per the D6
    /// "Settings concern" contract); the callback surfaces the URL
    /// so the desktop shell can emit a Tauri event + render the
    /// conversation banner. Production callers register the closure
    /// at boot; tests record into a shared `Mutex<Vec<String>>` to
    /// assert the dispatch path.
    primary_denylisted_cb: Arc<RwLock<Option<PrimaryDenylistedCallback>>>,
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
        let dedup = NonceDedup::new(10_000, std::time::Duration::from_secs(300));
        let inbox_dedup = Arc::new(std::sync::Mutex::new(dedup));
        let fan_in = Self::spawn_fan_in_for_slot(
            Arc::clone(&handle),
            Arc::clone(&inbox_dedup),
            Arc::clone(&on_inbound),
        );
        let primary_slot = Slot {
            relay_url: primary_url.clone(),
            handle: Arc::clone(&handle),
            last_traffic_at: SystemTime::now(),
            fan_in,
        };
        let initial_slots: [Option<Slot>; 3] = [Some(primary_slot), None, None];
        let mh = Self {
            primary_url: Arc::new(RwLock::new(primary_url)),
            builder,
            slots: Arc::new(RwLock::new(initial_slots)),
            inbox_dedup,
            denylist,
            on_inbound,
            primary_denylisted_cb: Arc::new(RwLock::new(None)),
        };
        if let Some(rx) = block_events {
            mh.spawn_denylist_subscriber(rx);
        }
        Ok(mh)
    }

    /// M3 G1: register a callback the denylist subscriber invokes
    /// when slot 0's primary relay URL appears in a fresh
    /// `BlockEvent::added` list. Replaces any prior callback. The
    /// closure is dispatched from the subscriber task, so it MUST be
    /// `Send + Sync`. Production callers register an emitter for the
    /// `chat:relay-denylisted` Tauri event; tests record into a shared
    /// `Mutex<Vec<String>>`.
    pub fn set_primary_denylisted_callback(&self, cb: PrimaryDenylistedCallback) {
        if let Ok(mut guard) = self.primary_denylisted_cb.write() {
            *guard = Some(cb);
        }
    }

    /// M3 D6: attach a [`fetchit_trust_client::BlockEvent`] subscriber to
    /// an already-constructed transport.
    ///
    /// `MultiHomeTransport` is built in `Client::build_with_chat` before
    /// the denylist consumer exists, so the constructor receives `None`.
    /// `Client::install_m3_denylist` calls this once the consumer's
    /// broadcast is live, closing the D6 mid-session loop: a `RelayUrl`
    /// block then drops the matching slot 1/2 and fires the
    /// primary-denylisted callback, exactly as the construction-time
    /// path. Spawns one background drain task per call.
    pub fn attach_block_event_subscriber(
        &self,
        block_events: tokio::sync::broadcast::Receiver<fetchit_trust_client::BlockEvent>,
    ) {
        self.spawn_denylist_subscriber(block_events);
    }

    /// Drain a [`fetchit_trust_client::BlockEvent`] broadcast and:
    ///
    /// 1. Drop any active slot 1/2 whose `relay_url` matches a
    ///    `RelayUrl` kind's `added` list. Slot 0 stays — a denylist
    ///    hit there is a Settings concern (G1 banner), not a
    ///    transport drop.
    /// 2. Fire the registered [`Self::set_primary_denylisted_callback`]
    ///    callback (if any) when slot 0's URL appears in the same
    ///    `added` list. The callback emits the Tauri event that
    ///    drives the conversation banner.
    fn spawn_denylist_subscriber(
        &self,
        mut rx: tokio::sync::broadcast::Receiver<fetchit_trust_client::BlockEvent>,
    ) {
        let slots = Arc::clone(&self.slots);
        // Share the primary-URL lock with the task so it reads the live
        // slot-0 URL on every event, tracking a `replace_primary` swap.
        let primary_url = Arc::clone(&self.primary_url);
        let cb_slot = Arc::clone(&self.primary_denylisted_cb);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if !matches!(event.kind, fetchit_trust::EntryKind::RelayUrl)
                            || event.added.is_empty()
                        {
                            continue;
                        }
                        // Snapshot the live slot-0 URL for this event so the
                        // match tracks a `replace_primary` failover. On poison
                        // fall back to None: skip ONLY the G1 primary-denylist
                        // callback, never the slot 1/2 drop below -- a poisoned
                        // primary_url lock must not disable denylist
                        // enforcement for the other slots. (Poison is
                        // practically unreachable: the sole writer,
                        // replace_primary, only assigns a String.)
                        let primary = match primary_url.read() {
                            Ok(g) => Some(g.clone()),
                            Err(e) => {
                                log::warn!(
                                    "multi_home primary_url lock poisoned in denylist subscriber: {e}",
                                );
                                None
                            }
                        };
                        // G1: emit BEFORE the slot mutation so the
                        // callback fires even if `slots` is poisoned
                        // below (the user still needs to know).
                        if let Some(ref primary) = primary {
                            if event.added.iter().any(|u| u == primary) {
                                log::info!(
                                    "multi_home primary relay denylisted mid-session: url={primary}",
                                );
                                let cb_opt =
                                    cb_slot.read().ok().and_then(|g| g.as_ref().map(Arc::clone));
                                if let Some(cb) = cb_opt {
                                    cb(primary.clone());
                                }
                            }
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
    /// `envelope` is the sealed [`TransitEnvelope`] from the
    /// conversation/group layer; this method wraps it in an
    /// [`OutboundEnvelope`] for the underlying handle.
    ///
    /// The [`crate::transport::Transport`] impl on this type wraps this
    /// inherent method, adapting the [`OutboundEnvelope`] +
    /// `Option<&RendezvousHintsV1>` signature and mapping
    /// [`TransportError`] into [`crate::error::ChatError`].
    ///
    /// # Errors
    /// - [`TransportError::Blocked`] when the destination relay URL or
    ///   recipient agent is on the active denylist.
    /// - [`TransportError::BuildFailed`] when `hints.relays` is empty,
    ///   when the underlying [`RelayBuilder`] fails to open a new
    ///   slot, or when the per-slot send fails.
    pub async fn send_inner(
        &self,
        to: &crate::identity::AgentId,
        envelope: TransitEnvelope,
        hints: &crate::card::RendezvousHintsV1,
    ) -> Result<SendReceipt, TransportError> {
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
        let outbound = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload: envelope.ciphertext.clone(),
            timestamp_ms: envelope.timestamp_ms,
            transit: Some(envelope),
        };
        handle.send(to, outbound).await
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
        let fan_in = Self::spawn_fan_in_for_slot(
            Arc::clone(&handle),
            Arc::clone(&self.inbox_dedup),
            Arc::clone(&self.on_inbound),
        );

        let mut slots = self.slots.write().expect("slots lock");
        slots[victim_idx] = Some(Slot {
            relay_url: target_url.to_string(),
            handle: Arc::clone(&handle),
            last_traffic_at: SystemTime::now(),
            fan_in,
        });
        Ok(handle)
    }

    /// Wire a slot's inbound stream into the dedup + dispatch path,
    /// returning the spawned task's [`tokio::task::AbortHandle`] (or
    /// `None` when the handle exposed no inbound receiver). The caller
    /// stores it on the [`Slot`] for deterministic teardown.
    ///
    /// Spawned per slot at slot-construction time (during init for
    /// slot 0; during [`Self::acquire_slot`] for slots 1 + 2).
    ///
    /// The spawned task does NOT keep an [`Arc<RelayHandle>`] alive; it
    /// consumes only the `UnboundedReceiver` taken out of the handle.
    /// How that receiver closes depends on the path:
    ///
    /// - Test-mock path: the receiver is fed by the mock handle's
    ///   `inbound_tx`. Dropping the last [`Arc<RelayHandle>`] drops that
    ///   sender, the channel closes, and the task exits on the next
    ///   `recv()`.
    /// - Production path: the receiver is fed by
    ///   [`crate::relay_transport::RelayTransport`]'s inbound pump, which
    ///   holds its own `Arc<RelaySet>`. Dropping the `RelayHandle` does
    ///   NOT close that channel — the pump keeps the sender alive. The
    ///   fan-in exits only once the merged channel closes, which happens
    ///   when [`crate::relay_transport::RelayTransport::shutdown`] runs
    ///   [`fetchit_relay_client::RelaySet::shutdown`] (supervisors drop
    ///   their `inbox_tx` -> forwarders exit -> merged channel closes ->
    ///   pump breaks and drops its tx -> this loop's `recv()` returns
    ///   `None`). Eviction that merely drops the slot therefore does NOT
    ///   stop a production fan-in; teardown must `.abort()` the returned
    ///   handle (or call `shutdown`) explicitly.
    ///
    /// Production handles drain
    /// [`crate::relay_transport::RelayTransport::take_inbound`]; test
    /// mocks drain the local mpsc fed by [`RelayHandle::deliver_inbound`].
    #[allow(clippy::expect_used)] // dedup mutex poison is unrecoverable; panic is fine in the fan-in task.
    fn spawn_fan_in_for_slot(
        slot_handle: Arc<RelayHandle>,
        dedup: Arc<std::sync::Mutex<NonceDedup>>,
        on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
    ) -> Option<tokio::task::AbortHandle> {
        let url = slot_handle.url().to_string();
        let rx = if let Some(transport) = &slot_handle.transport {
            <crate::relay_transport::RelayTransport as crate::transport::Transport>::take_inbound(
                transport.as_ref(),
            )
        } else {
            #[cfg(test)]
            {
                slot_handle.take_inbound_for_test()
            }
            #[cfg(not(test))]
            {
                None
            }
        };
        let mut rx = rx?;
        drop(slot_handle);
        let join = tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                let Some(transit) = env.transit.as_ref() else {
                    // No transit envelope means no canonical nonce to
                    // dedup on. Pass through so the dispatch layer can
                    // decide what to do.
                    on_inbound(env);
                    continue;
                };
                let Ok(nonce) = <[u8; 12]>::try_from(transit.nonce.as_slice()) else {
                    log::debug!(
                        "multi-home fan-in: skipping envelope with non-12-byte nonce: url={url}"
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
                    log::debug!("multi-home dedup dropped duplicate: url={url}");
                }
            }
        });
        Some(join.abort_handle())
    }

    /// Snapshot the current slot array for test inspection. Not
    /// exposed in production builds.
    #[cfg(test)]
    #[allow(clippy::expect_used)] // poisoned lock is a test bug; panic is fine.
    pub(crate) fn slots_for_test(&self) -> [Option<Slot>; 3] {
        self.slots.read().expect("slots lock").clone()
    }

    /// Borrow the slot-0 handle (the pinned primary). Callers that need
    /// the inner [`crate::relay_transport::RelayTransport`] for
    /// presence-watch or other single-WS APIs go through this to grab
    /// the bare transport via [`RelayHandle::relay_transport_arc`].
    /// Returns `None` only if slot 0 has been cleared (unreachable in
    /// production — slot 0 is pinned at boot and never evicted).
    #[must_use]
    #[allow(clippy::expect_used)] // RwLock poison is unrecoverable; panic matches `slots_for_test`.
    pub fn slot_zero_handle(&self) -> Option<Arc<RelayHandle>> {
        self.slots
            .read()
            .expect("slots lock")
            .first()
            .and_then(|s| s.as_ref().map(|s| Arc::clone(&s.handle)))
    }

    /// Borrow slot 0's per-relay connection-state stream — the clean
    /// seam the home-relay failover watcher (T8b, in `client.rs`)
    /// subscribes to. Walks
    /// [`Self::slot_zero_handle`] ->
    /// [`RelayHandle::relay_transport_arc`] ->
    /// [`crate::relay_transport::RelayTransport::relay_set`] ->
    /// [`fetchit_relay_client::RelaySet::states_receiver`].
    ///
    /// Each slot wraps a single-URL `RelaySet`, so the watched vector has
    /// length 1; index 0 is slot 0's relay. After a [`Self::replace_primary`]
    /// swap, slot 0 is a fresh handle with a FRESH `RelaySet`, so the
    /// watcher MUST call this again to re-subscribe — the old receiver
    /// only ever reports the torn-down relay.
    ///
    /// Returns `None` when slot 0 has been cleared (unreachable in
    /// production — slot 0 is pinned at boot and never evicted) or when
    /// slot 0 is a transport-less mock handle (the test fixtures expose
    /// no `RelaySet`, which is why the watcher state machine is unit-tested
    /// against a hand-driven [`tokio::sync::watch`] channel instead).
    #[must_use]
    pub fn slot_zero_states(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<Vec<fetchit_relay_client::ConnState>>> {
        let handle = self.slot_zero_handle()?;
        let transport = handle.relay_transport_arc()?;
        Some(transport.relay_set().states_receiver())
    }

    /// Rebuild slot 0 against `new_url`, the lib primitive behind
    /// home-relay failover (a region change or a dead primary). The
    /// POLICY that decides *when* to call this lives in a later task;
    /// this method only performs the swap, correctly.
    ///
    /// Order is load-bearing: the NEW session is built and its inbound
    /// path verified LIVE before the OLD slot 0 is torn down, so a FAILED
    /// swap leaves the working primary intact (important when the old
    /// relay is still alive and the caller is merely migrating):
    ///
    /// 1. Build the new handle and spawn its fan-in.
    /// 2. Verify inbound liveness: wait until the new relay reports
    ///    [`fetchit_relay_client::ConnState::Connected`], bounded by
    ///    `REPLACE_PRIMARY_CONNECT_TIMEOUT`. On timeout, abort the new
    ///    fan-in, drain the new session via
    ///    [`crate::relay_transport::RelayTransport::shutdown`], and return
    ///    [`TransportError::SwapNotLive`] WITHOUT touching slot 0. (Mock
    ///    handles expose no transport and skip the wait; their tests
    ///    assert liveness behaviorally.)
    /// 3. Install the new slot under the write lock (guard dropped before
    ///    any await) and point `Self::primary_url` at `new_url` so the
    ///    G1 denylist match keys off the live primary.
    /// 4. Tear the old slot down explicitly: abort its fan-in and drain
    ///    its session. The shared [`NonceDedup`] absorbs the brief window
    ///    where both fan-ins are alive, so the overlap is safe.
    ///
    /// This is the lib-layer fix for #358: the old session is drained via
    /// the deterministic [`fetchit_relay_client::RelaySet::shutdown`]
    /// cascade, leaking neither the WebSocket nor the inbound pump.
    ///
    /// # Errors
    /// - [`TransportError::BuildFailed`] when `new_url` cannot be dialed.
    /// - [`TransportError::SwapNotLive`] when the new session is built but
    ///   does not go [`fetchit_relay_client::ConnState::Connected`] in
    ///   time. In both error cases slot 0 is unchanged.
    #[allow(clippy::expect_used)] // RwLock poison is unrecoverable; panic matches `slots_for_test`.
    pub async fn replace_primary(&self, new_url: &str) -> Result<(), TransportError> {
        // 1. Build + wire the NEW slot-0 candidate.
        let new_handle = self.builder.build(new_url).await?;
        let fan_in = Self::spawn_fan_in_for_slot(
            Arc::clone(&new_handle),
            Arc::clone(&self.inbox_dedup),
            Arc::clone(&self.on_inbound),
        );

        // 2. Verify inbound liveness on the new relay BEFORE committing.
        // Production handles expose a transport with a per-relay state
        // stream; mock handles do not and skip the wait.
        if let Some(transport) = new_handle.relay_transport_arc() {
            if !Self::await_slot_connected(&transport).await {
                // Swap failed to go live: tear the new session down and
                // leave slot 0 untouched.
                if let Some(h) = &fan_in {
                    h.abort();
                }
                transport.shutdown().await;
                drop(new_handle);
                return Err(TransportError::SwapNotLive {
                    url: new_url.to_string(),
                });
            }
        }

        // 3. Commit the swap: capture the OLD slot, install the NEW one, and
        // update primary_url ATOMICALLY under the slots write lock so the
        // (slot 0, primary_url) pair can never desync across overlapping
        // swaps -- primary_url is the value the G1 denylist subscriber
        // matches on, so a stale pairing would key the security check off the
        // wrong relay. Nesting slots -> primary_url cannot deadlock: the only
        // other primary_url holder (the denylist subscriber) releases its
        // primary_url read guard before it ever takes the slots lock. The
        // guard is dropped before any await below.
        let old_slot = {
            let mut slots = self.slots.write().expect("slots lock");
            let old = slots[0].replace(Slot {
                relay_url: new_url.to_string(),
                handle: Arc::clone(&new_handle),
                last_traffic_at: SystemTime::now(),
                fan_in,
            });
            match self.primary_url.write() {
                Ok(mut g) => *g = new_url.to_string(),
                Err(e) => log::warn!(
                    "multi_home primary_url lock poisoned during replace_primary; \
                     primary may desync from slot 0: {e}",
                ),
            }
            old
        };

        // 4. Tear the OLD slot down explicitly. NEW is live and installed.
        // Drain the OLD transport FIRST: shutdown() flushes the pump's
        // remaining deliveries through the fan-in rx (an unbounded channel
        // yields all buffered items before None), so any in-flight OLD-relay
        // envelope is dispatched, not dropped mid-map -- this matters on a
        // planned migration where the old relay is still alive and delivering
        // at the swap instant. The fan-in then exits naturally when the pump
        // drops its tx; the explicit abort afterward is a no-op backstop. (The
        // shared dedup gate absorbs the brief two-fan-in overlap before this.)
        if let Some(old) = old_slot {
            if let Some(old_transport) = old.handle.relay_transport_arc() {
                old_transport.shutdown().await;
            }
            if let Some(h) = &old.fan_in {
                h.abort();
            }
            drop(old);
        }

        Ok(())
    }

    /// Whether the slot's single-URL relay reaches
    /// [`fetchit_relay_client::ConnState::Connected`] within
    /// [`REPLACE_PRIMARY_CONNECT_TIMEOUT`]. `false` means it never went
    /// live in time (the caller maps that to
    /// [`TransportError::SwapNotLive`]) or its state stream closed first.
    async fn await_slot_connected(transport: &Arc<crate::relay_transport::RelayTransport>) -> bool {
        use fetchit_relay_client::ConnState;
        let mut states = transport.relay_set().states_receiver();
        // Each slot wraps a single-URL RelaySet, so the state vector has
        // length 1; index 0 is that relay.
        let connected = |v: &Vec<ConnState>| matches!(v.first(), Some(ConnState::Connected { .. }));
        // PermanentlyDisconnected is terminal (the supervisor gave up). Fast
        // fail on it instead of burning the full timeout, to bound user-facing
        // failover latency when the new relay is already dead.
        let terminal = |v: &Vec<ConnState>| {
            matches!(v.first(), Some(ConnState::PermanentlyDisconnected { .. }))
        };
        {
            let v = states.borrow();
            if connected(&v) {
                return true;
            }
            if terminal(&v) {
                return false;
            }
        }
        let wait = async {
            while states.changed().await.is_ok() {
                let v = states.borrow();
                if connected(&v) {
                    return true;
                }
                if terminal(&v) {
                    return false;
                }
            }
            // Sender dropped without ever reaching Connected.
            false
        };
        // `Err` from `timeout` means the deadline elapsed -> not live in time.
        matches!(
            tokio::time::timeout(REPLACE_PRIMARY_CONNECT_TIMEOUT, wait).await,
            Ok(true)
        )
    }
}

#[async_trait]
impl crate::transport::Transport for MultiHomeTransport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn reachability(&self, _: &crate::identity::AgentId) -> crate::transport::Reachability {
        // MultiHomeTransport always has slot 0 pinned to the local
        // primary, so it can always attempt a send. The Router gates
        // *which* transport to try via `Reachability::No`; here we
        // signal "always attempt" and let `send` reject (with
        // `Invalid("hints required")`) when called without hints.
        crate::transport::Reachability::Always
    }

    async fn send(
        &self,
        to: &crate::identity::AgentId,
        envelope: OutboundEnvelope,
        hints: Option<&crate::card::RendezvousHintsV1>,
    ) -> crate::error::Result<SendReceipt> {
        // R-tail-5: every send-site (DM, group fanout, bridge,
        // auto-rekey) now resolves the recipient's hints (or
        // synthesizes a fallback to the local primary) before calling
        // through the Router. `None` is a real bug at this layer —
        // someone added a new call site and forgot to resolve hints.
        // Surfacing the typed `Invalid` lets the bug fail loudly at
        // the wire boundary instead of silently dropping the send.
        let hints = hints.ok_or_else(|| {
            crate::error::ChatError::Invalid(
                "MultiHomeTransport::send requires RendezvousHints".into(),
            )
        })?;
        let transit = envelope
            .transit
            .ok_or(crate::error::ChatError::SealedRequired {
                caller: "MultiHomeTransport::send",
            })?;
        let receipt = self
            .send_inner(to, transit, hints)
            .await
            .map_err(|e| match e {
                TransportError::Blocked(msg) => {
                    crate::error::ChatError::Denied { agent_id_hex: msg }
                }
                // `send_inner` never produces `SwapNotLive` (that is a
                // `replace_primary`-only failure), but the mapper must be
                // total; a swap-not-live is a transport-reachability
                // failure, so it folds into the same variant as a build
                // failure.
                TransportError::BuildFailed(msg) => crate::error::ChatError::MessageTransport(msg),
                TransportError::SwapNotLive { url } => crate::error::ChatError::MessageTransport(
                    format!("relay swap did not go live: {url}"),
                ),
            })?;
        // Re-stamp transport_name so receipts attribute to multi-home
        // rather than the underlying single-relay transport that
        // actually handled the wire send.
        Ok(SendReceipt {
            transport_name: TRANSPORT_NAME,
            ..receipt
        })
    }

    fn take_inbound(
        &self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<crate::transport::InboundEnvelope>> {
        // MultiHomeTransport's inbound is fanned in via the
        // `on_inbound` callback supplied at construction time, not via
        // the trait's `take_inbound`. Returning `None` tells the
        // Router not to pump inbound from us — Client wires the
        // callback at boot (R-tail-4).
        None
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
            ack: None,
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

        mh.send_inner(
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

        mh.send_inner(
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

        mh.send_inner(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://r1.test/v1/ws"),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        mh.send_inner(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://r2.test/v1/ws"),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        mh.send_inner(
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
            .send_inner(
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
            .send_inner(
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
        mh.send_inner(
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
        mh.send_inner(
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
        mh.send_inner(
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

    /// D6 post-construction: a transport built WITHOUT a subscriber (the
    /// production path, since the consumer is created after the transport
    /// in `Client::install_m3_denylist`) gains full mid-session
    /// reactivity once `attach_block_event_subscriber` is called. A
    /// `RelayUrl` block then drops the matching slot 1/2 just like the
    /// construction-time `new_with_subscriber` path.
    #[tokio::test]
    async fn attach_block_event_subscriber_enables_mid_session_drop() {
        use tokio::sync::broadcast;

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);

        // Build with the no-subscriber constructor, mirroring the `None`
        // that build_with_chat passes today.
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        // Open slot 1 so there's an active slot to drop.
        mh.send_inner(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://later-blocked.test/v1/ws"),
        )
        .await
        .unwrap();
        assert!(mh.slots_for_test()[1].is_some());

        // Attach the subscriber AFTER construction, then block slot 1's URL.
        let (tx, rx) = broadcast::channel::<fetchit_trust_client::BlockEvent>(16);
        mh.attach_block_event_subscriber(rx);

        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://later-blocked.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let slots = mh.slots_for_test();
        let urls: Vec<&str> = slots
            .iter()
            .filter_map(|s| s.as_ref().map(|x| x.relay_url.as_str()))
            .collect();
        assert!(
            !urls.contains(&"wss://later-blocked.test/v1/ws"),
            "post-attach block should drop the slot, got {urls:?}",
        );
        assert!(
            urls.contains(&"wss://primary.test/v1/ws"),
            "slot 0 stays after a post-attach block",
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

    /// G1: when slot 0's primary URL appears in a `RelayUrl` block
    /// event's `added` list, the registered callback is invoked with
    /// the URL. Slot 0 is NOT dropped (D6 contract); the desktop shell
    /// uses this signal to surface the conversation banner that tells
    /// the user "your primary relay was just added to the denylist."
    #[tokio::test]
    async fn mid_session_primary_denylist_fires_callback() {
        use std::sync::Mutex;
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

        let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cb_recorded = Arc::clone(&recorded);
        mh.set_primary_denylisted_callback(Arc::new(move |url| {
            cb_recorded.lock().unwrap().push(url);
        }));

        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://primary.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let captured = recorded.lock().unwrap().clone();
        assert_eq!(
            captured,
            vec!["wss://primary.test/v1/ws".to_string()],
            "primary-denylisted callback must fire exactly once with the matched url",
        );
        // And slot 0 still survives — the callback signals the UI but
        // doesn't drop the transport (D6 invariant + see
        // `mid_session_relay_block_does_not_drop_slot_zero`).
        assert_eq!(
            mh.slots_for_test()[0]
                .as_ref()
                .map(|s| s.relay_url.as_str()),
            Some("wss://primary.test/v1/ws"),
        );
    }

    /// G1: a `BlockEvent` whose `added` list does NOT include slot 0's
    /// URL must NOT fire the callback. Pins the "primary-only" scope
    /// so a denylist hit on a slot-1/2 URL doesn't surface the banner
    /// (those are silent drops per D6).
    #[tokio::test]
    async fn mid_session_non_primary_block_skips_callback() {
        use std::sync::Mutex;
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

        let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cb_recorded = Arc::clone(&recorded);
        mh.set_primary_denylisted_callback(Arc::new(move |url| {
            cb_recorded.lock().unwrap().push(url);
        }));

        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://other.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(
            recorded.lock().unwrap().is_empty(),
            "callback must NOT fire when added list misses slot 0's URL",
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

        mh.send_inner(
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

    fn sample_outbound_envelope() -> OutboundEnvelope {
        OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload: vec![0xaa; 16],
            timestamp_ms: 1_700_000_000_000,
            transit: Some(sample_envelope()),
        }
    }

    /// R-tail-3: calling `MultiHomeTransport` through the `Transport`
    /// trait routes via the inherent slot allocator and yields a
    /// `SendReceipt` stamped with our transport name. The mock
    /// `RelayHandle` records the transit envelope so we can assert
    /// the slot-0 handoff happened.
    #[tokio::test]
    async fn transport_impl_routes_via_inherent_send() {
        use crate::transport::Transport;
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let to = sample_recipient();
        let envelope = sample_outbound_envelope();
        let hints = crate::card::RendezvousHintsV1 {
            relays: vec!["wss://primary.test/v1/ws".to_string()],
        };

        let receipt = <MultiHomeTransport as Transport>::send(&mh, &to, envelope, Some(&hints))
            .await
            .expect("trait send succeeds");
        assert_eq!(receipt.transport_name, "multi-home");

        // The slot-0 mock handle should have recorded the transit
        // envelope handed off through the trait surface.
        let slot0_handle = Arc::clone(&mh.slots_for_test()[0].as_ref().unwrap().handle);
        assert_eq!(slot0_handle.traffic_count_for_test(), 1);
    }

    /// R-tail-5: every send-site now resolves hints (with fallback to
    /// the local primary) before calling the Router, so `None` at
    /// this layer is a real bug. The `Transport` impl returns a typed
    /// `Invalid` error rather than silently routing to slot 0 — that
    /// loud failure is what catches the next contributor who adds a
    /// new send path and forgets to resolve hints.
    #[tokio::test]
    async fn transport_impl_errors_on_none_hints() {
        use crate::transport::Transport;
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://primary.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let to = sample_recipient();
        let envelope = sample_outbound_envelope();
        let err = <MultiHomeTransport as Transport>::send(&mh, &to, envelope, None)
            .await
            .expect_err("None-hints must error post-R-tail-5");
        assert!(
            matches!(err, crate::error::ChatError::Invalid(ref s) if s.contains("RendezvousHints")),
            "expected Invalid(\"...RendezvousHints...\"), got {err:?}",
        );

        // No send recorded on slot 0; no slot 1/2 allocations either.
        let slot0_handle = Arc::clone(&mh.slots_for_test()[0].as_ref().unwrap().handle);
        assert_eq!(slot0_handle.traffic_count_for_test(), 0);
        assert!(mh.slots_for_test()[1].is_none());
        assert!(mh.slots_for_test()[2].is_none());
    }

    // ── T8a replace_primary ──────────────────────────────────────────────────

    /// After `replace_primary`, slot 0 reports the new URL and the live
    /// slot-0 handle is the freshly built one. The OLD handle is not the
    /// one a follow-up `slot_zero_handle()` hands back.
    #[tokio::test]
    async fn replace_primary_installs_new_slot_zero() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://relay-a.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        let old_handle = mh.slot_zero_handle().expect("slot 0 present");

        mh.replace_primary("wss://relay-b.test/v1/ws")
            .await
            .expect("replace_primary succeeds");

        assert_eq!(
            mh.slot_zero_handle().map(|h| h.url().to_string()),
            Some("wss://relay-b.test/v1/ws".to_string()),
            "slot 0 must report the new URL after the swap",
        );
        let slots = mh.slots_for_test();
        assert_eq!(
            slots[0].as_ref().map(|s| s.relay_url.as_str()),
            Some("wss://relay-b.test/v1/ws"),
        );
        let new_handle = mh.slot_zero_handle().expect("slot 0 present");
        assert!(
            !Arc::ptr_eq(&old_handle, &new_handle),
            "the live slot-0 handle must be the rebuilt one, not the old handle",
        );
    }

    /// The r14 reconnect case: `replace_primary` to the SAME url must
    /// still build a fresh session and swap it in — a network-identity
    /// change (Wi-Fi to cellular) kills the TCP flow while the URL stays
    /// unchanged. Same-url is deliberately NOT a no-op at this layer;
    /// the no-op short-circuit lives in `Client::migrate_primary`, where
    /// "already there" is the right answer.
    #[tokio::test]
    async fn replace_primary_same_url_swaps_in_a_fresh_session() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://relay-a.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();
        let old_handle = mh.slot_zero_handle().expect("slot 0 present");

        mh.replace_primary("wss://relay-a.test/v1/ws")
            .await
            .expect("same-url replace must succeed");

        let new_handle = mh.slot_zero_handle().expect("slot 0 present");
        assert!(
            !Arc::ptr_eq(&old_handle, &new_handle),
            "same-url reconnect must install a FRESH session, not keep the dead one",
        );
        assert_eq!(
            mh.slot_zero_handle().map(|h| h.url().to_string()),
            Some("wss://relay-a.test/v1/ws".to_string()),
            "primary URL is unchanged across an in-place reconnect",
        );
    }

    /// THE CORRECTNESS BAR: inbound liveness follows the swap. An inbound
    /// delivered via the NEW slot-0 handle reaches `on_inbound`; an inbound
    /// delivered via the OLD (torn-down) handle does NOT.
    #[tokio::test]
    async fn replace_primary_inbound_lives_on_new_dies_on_old() {
        use std::sync::Mutex;

        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let received_cb = Arc::clone(&received);
        let on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync> = Arc::new(move |env| {
            received_cb.lock().unwrap().push(env.from.0.clone());
        });

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://relay-a.test/v1/ws".into(),
            denylist,
            on_inbound,
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        // Grab the OLD slot-0 handle before the swap so we can poke it after.
        let old_handle = mh.slot_zero_handle().expect("slot 0 present");

        mh.replace_primary("wss://relay-b.test/v1/ws")
            .await
            .expect("replace_primary succeeds");

        // Inbound on the NEW slot-0 handle must reach on_inbound.
        let new_handle = mh.slot_zero_handle().expect("slot 0 present");
        new_handle.deliver_inbound(sample_inbound_envelope("on-new", [1u8; 12]));

        // Inbound on the OLD handle must NOT reach on_inbound — its fan-in
        // was aborted during teardown.
        old_handle.deliver_inbound(sample_inbound_envelope("on-old", [2u8; 12]));

        // Abort is asynchronous; let both the new fan-in drain and the old
        // fan-in's abort take effect.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let got = received.lock().unwrap().clone();
        assert!(
            got.contains(&"on-new".to_string()),
            "inbound on the NEW slot-0 handle must reach on_inbound, got {got:?}",
        );
        assert!(
            !got.contains(&"on-old".to_string()),
            "inbound on the OLD (torn-down) handle must NOT reach on_inbound, got {got:?}",
        );
    }

    /// `replace_primary` only touches slot 0: an already-open slot 1
    /// survives the swap untouched.
    #[tokio::test]
    async fn replace_primary_leaves_slots_1_2_untouched() {
        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let mh = MultiHomeTransport::new(
            "wss://relay-a.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
        )
        .await
        .unwrap();

        // Open slot 1 via an outbound send to a second relay.
        mh.send_inner(
            &sample_recipient(),
            sample_envelope(),
            &hints("wss://secondary.test/v1/ws"),
        )
        .await
        .unwrap();
        assert_eq!(
            mh.slots_for_test()[1]
                .as_ref()
                .map(|s| s.relay_url.as_str()),
            Some("wss://secondary.test/v1/ws"),
        );

        mh.replace_primary("wss://relay-b.test/v1/ws")
            .await
            .expect("replace_primary succeeds");

        let slots = mh.slots_for_test();
        assert_eq!(
            slots[0].as_ref().map(|s| s.relay_url.as_str()),
            Some("wss://relay-b.test/v1/ws"),
            "slot 0 swapped to relay-b",
        );
        assert_eq!(
            slots[1].as_ref().map(|s| s.relay_url.as_str()),
            Some("wss://secondary.test/v1/ws"),
            "slot 1 must survive replace_primary untouched",
        );
        assert!(slots[2].is_none());
    }

    /// After a failover, the G1 primary-denylisted match keys off the NEW
    /// primary URL (`primary_url` is interior-mutable and kept in sync).
    /// Blocking the OLD primary URL no longer fires the callback; blocking
    /// the NEW one does.
    #[tokio::test]
    async fn replace_primary_keeps_g1_denylist_match_in_sync() {
        use std::sync::Mutex;
        use tokio::sync::broadcast;

        let builder = Arc::new(StubRelayBuilder::default());
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylist);
        let (tx, rx) = broadcast::channel::<fetchit_trust_client::BlockEvent>(16);

        let mh = MultiHomeTransport::new_with_subscriber(
            "wss://relay-a.test/v1/ws".into(),
            denylist,
            Arc::new(|_| {}),
            Arc::clone(&builder) as Arc<dyn RelayBuilder>,
            Some(rx),
        )
        .await
        .unwrap();

        let recorded: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cb_recorded = Arc::clone(&recorded);
        mh.set_primary_denylisted_callback(Arc::new(move |url| {
            cb_recorded.lock().unwrap().push(url);
        }));

        mh.replace_primary("wss://relay-b.test/v1/ws")
            .await
            .expect("replace_primary succeeds");

        // Block the OLD primary — must NOT fire the callback anymore.
        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://relay-a.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            recorded.lock().unwrap().is_empty(),
            "blocking the OLD primary after a swap must not fire the callback",
        );

        // Block the NEW primary — must fire.
        let _ = tx.send(fetchit_trust_client::BlockEvent {
            kind: fetchit_trust::EntryKind::RelayUrl,
            added: vec!["wss://relay-b.test/v1/ws".to_string()],
            removed: vec![],
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            recorded.lock().unwrap().clone(),
            vec!["wss://relay-b.test/v1/ws".to_string()],
            "blocking the NEW primary after a swap must fire the callback",
        );
    }
}
