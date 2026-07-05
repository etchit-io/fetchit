//! `Transport` impl backed by `fetchit-relay-client`.
//!
//! Drives a live WebSocket session against a fetchit relay using the
//! local x0xd as the signing oracle. Outbound chat envelopes are
//! wrapped in [`fetchit_relay_proto::TransitEnvelope`]s and sent to
//! the relay; inbound deliveries are decoded and pumped onto an mpsc
//! channel that the chat layer consumes.
//!
//! # Sealing status (M2 floor)
//!
//! Every send MUST carry a prebuilt sealed `TransitEnvelope` on
//! [`OutboundEnvelope::transit`]; the conversation/group layer is the
//! only sanctioned producer. Callers that pass `transit: None` get
//! [`ChatError::SealedRequired`] — the legacy v1 fabricated escape
//! hatch has been removed at M2 so there is no unsealed wire shape
//! left in this module.

use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use crate::transport::{
    InboundEnvelope, OutboundEnvelope, OutboundKind, Reachability, SendReceipt, Transport,
};
use async_trait::async_trait;
use fetchit_relay_client::{Client, ClientConfig, RelaySet, Signer};
use fetchit_relay_proto::{
    AgentId as RelayAgentId, DedupeKey, EnvelopeKind as RelayKind, TransitEnvelope,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use url::Url;

const TRANSPORT_NAME: &str = "relay";

/// Idle timeout for pooled outbound connections: entries unused for this
/// long are reaped lazily on the next `send`.
const POOL_IDLE_MS: u64 = 5 * 60 * 1000;

/// One entry in the per-relay outbound connection pool.
struct PooledConn {
    client: Arc<Client>,
    last_used: Instant,
}

/// Outbound-only connection pool keyed by normalized relay URL string.
/// Each entry is a single [`Client`] session to a specific relay.
type RelayPool = StdMutex<HashMap<String, PooledConn>>;

/// Cross-internet chat transport routed through one or more
/// `fetchit-relay-server` instances via [`RelaySet`].
///
/// M3 federation core: outbound sends fan out to every relay in the
/// set; inbound deliveries arrive on a single merged stream. Receiver-
/// side dedupe is handled at the chat layer via the envelope's
/// `message_id` (canonical event hash at x0xd).
pub struct RelayTransport {
    relay_set: Arc<RelaySet>,
    counter: AtomicU64,
    inbound: StdMutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>,
    /// `JoinHandle` of the inbound pump spawned by [`spawn_inbound_pump`].
    /// Held so [`Self::shutdown`] can await the pump to completion after
    /// [`RelaySet::shutdown`] closes the merged channel (the orderly-drain
    /// teardown). Taken out (`Option::take`) by the first `shutdown` call.
    pump_join: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Abort handle for the inbound pump, derived from `pump_join` at
    /// connect time. Used only as the [`Drop`] backstop and as the
    /// timeout fallback inside [`Self::shutdown`]; never the primary
    /// teardown path. Aborting releases the pump's `Arc<RelaySet>` clone
    /// so the WS closes once the last `Client` Arc drops (the #358 leak
    /// backstop).
    pump_abort: tokio::task::AbortHandle,
    /// Local agent id captured from the signer at connect time. Used
    /// to populate `TransitEnvelope::sender_agent_id` for outbound
    /// sends; the relay rejects sends whose `sender_agent_id` doesn't
    /// match the bearer-token identity, so they must agree.
    local_agent_id: RelayAgentId,
    /// Signer held for authenticating new pool connections to hinted relays.
    signer: Arc<dyn Signer + Send + Sync>,
    /// Outbound-only connection pool for hinted relay deposits.
    pool: RelayPool,
    /// Normalized wss:// URL keys of the own-relay set (the relays this
    /// transport is already listening on). A hint that matches one of these
    /// reuses the existing `relay_set` session instead of opening a pool entry.
    own_relay_keys: Vec<String>,
}

/// Relay-client config for the always-on chat message pump.
///
/// The pump reconnects FOREVER ([`ClientConfig::with_unbounded_reconnect`])
/// so a relay outage longer than the default attempt cap can never leave the
/// pump permanently dead: it self-heals when connectivity returns instead of
/// requiring the app to rebuild the client. Chat-resilience win #1.
fn chat_pump_config(url: Url) -> ClientConfig {
    ClientConfig::new(url).with_unbounded_reconnect()
}

impl RelayTransport {
    /// Connect to a single relay at `base_url`. Convenience wrapper
    /// over [`Self::connect_multi`] that wraps the URL in a one-entry
    /// vec — preserves the M2 single-relay call surface while letting
    /// the internals run through [`RelaySet`].
    ///
    /// # Errors
    /// Returns [`ChatError::MessageTransport`] on any handshake or
    /// connection failure.
    pub async fn connect(base_url: Url, signer: Arc<dyn Signer>) -> Result<Arc<Self>> {
        Self::connect_multi(vec![base_url], signer).await
    }

    /// Connect concurrently to every relay in `base_urls`, using any
    /// [`Signer`] implementation for ML-DSA-65 auth (production:
    /// `X0xdSigner`; tests can use `StaticKeySigner`).
    ///
    /// Spawns a background task that pumps merged inbound deliveries
    /// from the [`RelaySet`] into the channel exposed via
    /// [`Transport::take_inbound`].
    ///
    /// # Errors
    /// Returns [`ChatError::MessageTransport`] when every relay fails
    /// its initial handshake — any surviving subset keeps the peer
    /// reachable. Also returns the same error when `base_urls` is
    /// empty.
    pub async fn connect_multi(base_urls: Vec<Url>, signer: Arc<dyn Signer>) -> Result<Arc<Self>> {
        let local_agent_id = RelayAgentId::from_bytes(signer.agent_id());
        let own_relay_keys: Vec<String> = base_urls
            .iter()
            .filter_map(|u| https_url_to_wss_key(u).ok())
            .collect();
        let configs: Vec<ClientConfig> = base_urls.into_iter().map(chat_pump_config).collect();
        let relay_set = RelaySet::connect(configs, signer.clone())
            .await
            .map_err(|e| ChatError::MessageTransport(format!("relay connect: {e}")))?;
        let relay_set = Arc::new(relay_set);
        // TODO(perf): bound this channel once we measure realistic inbound rates.
        let (tx, rx) = mpsc::unbounded_channel();
        let pump_join = spawn_inbound_pump(relay_set.clone(), tx);
        let pump_abort = pump_join.abort_handle();
        Ok(Arc::new(Self {
            relay_set,
            counter: AtomicU64::new(0),
            inbound: StdMutex::new(Some(rx)),
            local_agent_id,
            signer,
            pool: StdMutex::new(HashMap::new()),
            own_relay_keys,
            pump_join: StdMutex::new(Some(pump_join)),
            pump_abort,
        }))
    }

    /// Borrow the local agent id this transport is bound to. The
    /// relay server enforces that outbound `sender_agent_id` equals
    /// the bearer-token identity, so callers can treat this as
    /// authoritative.
    #[must_use]
    pub fn local_agent_id(&self) -> &RelayAgentId {
        &self.local_agent_id
    }

    /// Borrow the underlying [`RelaySet`] for telemetry, presence
    /// subscription, or connection-state observation. Multi-home
    /// aware callers route through this instead of poking at any
    /// single per-relay client.
    #[must_use]
    pub fn relay_set(&self) -> &Arc<RelaySet> {
        &self.relay_set
    }

    /// Tear this transport down by orderly drain, closing its WebSocket
    /// and stopping its inbound pump with no leaked task and no in-flight
    /// envelope dropped mid-map.
    ///
    /// Mechanism (the deterministic cascade, not an abort):
    /// 1. [`RelaySet::shutdown`] awaits every `Client` supervisor's
    ///    `JoinHandle`. Each supervisor drops its `inbox_tx`, so each
    ///    per-relay forwarder sees `None`, exits, and drops its merged-tx
    ///    clone; the merged channel then closes and
    ///    [`RelaySet::next_delivery`] returns `None`.
    /// 2. The pump's loop breaks on that `None` and drops the chat `tx`.
    ///    This method then awaits the pump `JoinHandle` to completion so
    ///    any last in-flight envelope finishes mapping before we return.
    ///
    /// The `JoinHandle` await is bounded by a 5s timeout; on overrun the
    /// pump is aborted so production teardown can never hang. Idempotent:
    /// a second call finds the handle already taken and only re-signals
    /// the (already shut-down) [`RelaySet`].
    pub async fn shutdown(&self) {
        self.relay_set.shutdown().await;
        // Never hold a std Mutex guard across an await: take the handle,
        // drop the guard, then await it.
        let taken = self.pump_join.lock().ok().and_then(|mut g| g.take());
        if let Some(jh) = taken {
            if tokio::time::timeout(Duration::from_secs(5), jh)
                .await
                .is_err()
            {
                // Pump overran the orderly-drain budget; fall back to the
                // abort backstop so teardown returns promptly.
                self.pump_abort.abort();
            }
        }
    }

    /// Test-only: whether [`Self::shutdown`] has taken the pump
    /// `JoinHandle` out of `pump_join` (i.e. the orderly-drain
    /// take-then-await path ran, not just `relay_set.shutdown()`). Guards
    /// the load-bearing half of the #358 fix.
    #[cfg(test)]
    pub(crate) fn pump_handle_taken_for_test(&self) -> bool {
        self.pump_join.lock().map_or(true, |g| g.is_none())
    }

    fn next_dedupe_key(&self) -> DedupeKey {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        let ts_part = now_ms().to_le_bytes();
        bytes[8..].copy_from_slice(&ts_part);
        DedupeKey::from_bytes(bytes)
    }

    /// Send via the own-relay set (back-compat path, used when hints are absent
    /// or all hints point at own relays).
    async fn send_via_relay_set(
        &self,
        to: RelayAgentId,
        transit: TransitEnvelope,
        dedupe_key: DedupeKey,
    ) -> Result<SendReceipt> {
        let outcome = self
            .relay_set
            .send(to, transit, dedupe_key)
            .await
            .map_err(|e| ChatError::MessageTransport(format!("relay send: {e}")))?;
        Ok(SendReceipt {
            accepted_at_ms: outcome.primary.accepted_at_ms,
            message_id: Some(hex::encode(dedupe_key.as_bytes())),
            transport_name: TRANSPORT_NAME,
        })
    }

    /// Get or create a pooled [`Client`] for the given normalized `wss://`
    /// key. Creates a new authenticated connection when one is missing or
    /// the existing entry was reaped.
    ///
    /// # Security invariant
    /// Every pooled connection completes the IDENTICAL challenge/verify auth
    /// handshake as the primary session: `obtain_bearer` -> ML-DSA-65 sign ->
    /// `AuthVerifyResponse` token. The pool uses the same `signer` as the
    /// primary session; deposits are authenticated as the SENDER, not the
    /// recipient. There is no unauthenticated deposit path.
    async fn get_or_create_pool_conn(&self, wss_key: &str, https_url: Url) -> Result<Arc<Client>> {
        // Reap stale entries and return the live one if present.
        {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| ChatError::MessageTransport("pool lock poisoned".into()))?;
            let idle_threshold = Duration::from_millis(POOL_IDLE_MS);
            pool.retain(|_, v| v.last_used.elapsed() < idle_threshold);
            if let Some(entry) = pool.get_mut(wss_key) {
                entry.last_used = Instant::now();
                return Ok(Arc::clone(&entry.client));
            }
        }

        // Not in pool — open a new authenticated connection. The pool
        // lock is intentionally released before this await (holding a
        // std MutexGuard across an await would serialize every send
        // behind a slow connect and is a !Send footgun). The tradeoff:
        // two concurrent first-contact sends to the same new relay may
        // each open a connection; the loser's Arc drops on return and
        // its supervisor shuts down cleanly. First-contact races are
        // rare and self-healing, so this is accepted over per-key
        // locking that would reintroduce the across-await hold.
        let config = chat_pump_config(https_url);
        let client = Client::connect(config, self.signer.clone())
            .await
            .map_err(|e| ChatError::MessageTransport(format!("pool connect {wss_key}: {e}")))?;
        let client = Arc::new(client);
        {
            let mut pool = self
                .pool
                .lock()
                .map_err(|_| ChatError::MessageTransport("pool lock poisoned".into()))?;
            pool.insert(
                wss_key.to_owned(),
                PooledConn {
                    client: Arc::clone(&client),
                    last_used: Instant::now(),
                },
            );
        }
        Ok(client)
    }

    /// Walk hinted relays in priority order. First success returns Ok.
    /// All failures return the last error (honest failure, not silent Ok).
    async fn send_via_hints(
        &self,
        to: RelayAgentId,
        transit: &TransitEnvelope,
        dedupe_key: DedupeKey,
        hints: &crate::card::RendezvousHintsV1,
    ) -> Result<SendReceipt> {
        let mut normalized: Vec<String> = Vec::with_capacity(hints.relays.len());
        for raw in &hints.relays {
            match normalize_wss_url(raw) {
                Ok(n) if !normalized.contains(&n) => normalized.push(n),
                _ => {}
            }
        }

        let mut last_err: Option<ChatError> = None;
        for wss_key in &normalized {
            // A hint pointing at one of our own relays reuses the listen session.
            if self.own_relay_keys.contains(wss_key) {
                match self
                    .send_via_relay_set(to, transit.clone(), dedupe_key)
                    .await
                {
                    Ok(r) => return Ok(r),
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            }

            // External relay: convert to https:// and get-or-create pool entry.
            let https_url = match wss_key_to_https_url(wss_key) {
                Ok(u) => u,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            // SSRF guard (T13): a contact-supplied hint pointing at loopback /
            // link-local / RFC1918 / ULA space must not be dialed. Skip the
            // blocked hint and try the next, mirroring the unreachable-relay
            // fallback. The dev / FETCHIT_ALLOW_LOCAL_RELAY carve-out keeps
            // localhost relays working in tests and dev.
            if let Err(e) = crate::relay_http::guard_relay_url(&https_url).await {
                last_err = Some(ChatError::MessageTransport(format!(
                    "relay blocked {wss_key}: {e}"
                )));
                continue;
            }
            let client = match self.get_or_create_pool_conn(wss_key, https_url).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match client.send(to, transit.clone(), dedupe_key).await {
                Ok(receipt) => {
                    // Touch last_used on success.
                    if let Ok(mut pool) = self.pool.lock() {
                        if let Some(entry) = pool.get_mut(wss_key.as_str()) {
                            entry.last_used = Instant::now();
                        }
                    }
                    return Ok(SendReceipt {
                        accepted_at_ms: receipt.accepted_at_ms,
                        message_id: Some(hex::encode(dedupe_key.as_bytes())),
                        transport_name: TRANSPORT_NAME,
                    });
                }
                Err(e) => {
                    last_err = Some(ChatError::MessageTransport(format!(
                        "pool send {wss_key}: {e}"
                    )));
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| ChatError::MessageTransport("all hinted relays unreachable".into())))
    }

    /// Reap pool entries that have been idle for at least `age`. Used
    /// directly in tests to verify lazy reaping without waiting real time.
    #[cfg(test)]
    fn reap_older_than(&self, age: Duration) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.retain(|_, v| v.last_used.elapsed() < age);
        }
    }

    /// Return the number of live entries in the pool. Used in tests only.
    #[cfg(test)]
    fn pool_len(&self) -> usize {
        self.pool.lock().map_or(0, |g| g.len())
    }
}

impl Drop for RelayTransport {
    /// Leak backstop for the #358 detached-pump WebSocket leak: any code
    /// path that drops a [`RelayTransport`] without first awaiting
    /// [`Self::shutdown`] still aborts the inbound pump here. Aborting
    /// releases the pump's cloned `Arc<RelaySet>`, so the underlying WS
    /// closes once the last `Client` Arc drops. `Drop` cannot await, so
    /// this is abort-only and NOT the correctness path — `shutdown` (an
    /// orderly drain) is. A second abort after `shutdown` already took the
    /// handle is a harmless no-op.
    fn drop(&mut self) {
        self.pump_abort.abort();
    }
}

#[async_trait]
impl Transport for RelayTransport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn reachability(&self, _: &AgentId) -> Reachability {
        Reachability::Always
    }

    async fn send(
        &self,
        to: &AgentId,
        envelope: OutboundEnvelope,
        hints: Option<&crate::card::RendezvousHintsV1>,
    ) -> Result<SendReceipt> {
        let to_relay = agent_id_to_relay(to)?;
        // Sealed-only post-M2 — every caller must hand us a fully
        // sealed envelope produced by the conversation/group layer.
        // The v1 fabricated escape hatch has been removed.
        let transit = envelope.transit.ok_or(ChatError::SealedRequired {
            caller: "RelayTransport::send",
        })?;
        let dedupe_key = self.next_dedupe_key();

        // Route by hints when present and non-empty; fall back to own relay.
        match hints {
            Some(h) if !h.relays.is_empty() => {
                self.send_via_hints(to_relay, &transit, dedupe_key, h).await
            }
            _ => {
                // No hints or empty relay list: deposit on the own relay session,
                // preserving the pre-pool back-compat behavior.
                self.send_via_relay_set(to_relay, transit, dedupe_key).await
            }
        }
    }

    fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound.lock().ok().and_then(|mut g| g.take())
    }
}

/// Spawn the inbound pump and return its [`tokio::task::JoinHandle`].
///
/// The pump drains the merged [`RelaySet`] delivery stream, maps each
/// envelope to an [`InboundEnvelope`], and forwards it on `tx`. It exits
/// when `relay_set.next_delivery()` returns `None` (every supervisor shut
/// down) or when `tx` is closed. [`RelayTransport::connect_multi`] stores
/// the handle for the orderly-drain teardown in [`RelayTransport::shutdown`].
fn spawn_inbound_pump(
    relay_set: Arc<RelaySet>,
    tx: mpsc::UnboundedSender<InboundEnvelope>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some(delivery) = relay_set.next_delivery().await else {
                break;
            };
            let Some(inbound) = map_inbound_delivery(delivery.envelope) else {
                continue;
            };
            if tx.send(inbound).is_err() {
                break;
            }
        }
    })
}

/// Map a relay inbound [`TransitEnvelope`] to a chat-layer
/// [`InboundEnvelope`], or `None` when the kind has no chat-layer route
/// (the pump drops it).
///
/// The returned [`OutboundKind`] is only the coarse shape the chat
/// layer keys off; the fine discrimination happens downstream on
/// `transit.kind` (see `Client::default_dispatch_one`). That's why
/// `Dm`, the M2.5 bridge metadata event, and a bridged `PublicPost` all
/// ride the `Dm` shape — none has a dedicated [`OutboundKind`], and the
/// dispatcher re-reads `transit.kind` to route the bridge event and the
/// public post to their own handlers before any DM logic runs.
fn map_inbound_delivery(env: TransitEnvelope) -> Option<InboundEnvelope> {
    let kind = match env.kind {
        // Dm, the M2.5 bridge metadata event, a bridged fediverse
        // PublicPost, and an M6.7 PairRecordPush all ride the Dm shape;
        // `default_dispatch_one` re-discriminates each on `transit.kind`
        // (X0xdGroupMetadataEvent -> dispatch_inbound_bridge,
        // PublicPost -> dispatch_inbound_public_post, PairRecordPush ->
        // the M6.7 revoke-push receiver) before the conversation/DM path.
        // PublicPost was previously dropped here on a stale "until Stage
        // 5.3" comment; 5.3 is built, so it now forwards. PairRecordPush
        // forwards for the same reason: it is unsealed + self-verified
        // (the record's own ML-DSA-65 signature is the authority), so the
        // relay carries it like a public post and the dispatcher routes it.
        RelayKind::Dm
        | RelayKind::X0xdGroupMetadataEvent
        | RelayKind::PublicPost
        | RelayKind::PairRecordPush => OutboundKind::Dm,
        // PrivateGroupChat rides the same inbound shape as GroupChat —
        // peer.rs's `is_private_group_envelope` predicate is what
        // discriminates the two downstream.
        RelayKind::GroupChat | RelayKind::PrivateGroupChat | RelayKind::DeliveryReceipt => {
            OutboundKind::Group {
                group_id: env
                    .group_id
                    .map(|g| hex::encode(g.as_bytes()))
                    .unwrap_or_default(),
            }
        }
        RelayKind::AdminEvent => return None,
        // Forward-compat: a newer sender used a kind we don't recognise
        // yet. The relay passed it through verbatim; we drop it since the
        // chat layer has no semantics to map it to. Logged so an
        // unexpectedly-common Unknown stream surfaces in journals.
        RelayKind::Unknown(disc) => {
            log::warn!("relay inbound: dropping envelope with unknown kind disc={disc}");
            return None;
        }
        // Reserved7 is a historical M2.5 Welcome-bridge discriminator kept
        // reserved for wire-stability. Drop here; the bridge is no longer
        // shipped, so no chat-layer route exists. (Slot 6 graduated from
        // Reserved6 to PairRecordPush, which forwards above.)
        RelayKind::Reserved7 => {
            log::warn!("relay inbound: dropping envelope with reserved (M2.5 Welcome-bridge) kind");
            return None;
        }
    };
    let from = AgentId(hex::encode(env.sender_agent_id.as_bytes()));
    Some(InboundEnvelope {
        kind,
        from,
        payload: env.ciphertext.clone(),
        timestamp_ms: env.timestamp_ms,
        transport_name: TRANSPORT_NAME,
        transit: Some(env),
    })
}

fn agent_id_to_relay(id: &AgentId) -> Result<RelayAgentId> {
    let bytes = parse_hex_32(&id.0).map_err(|e| ChatError::Invalid(format!("agent id: {e}")))?;
    Ok(RelayAgentId::from_bytes(bytes))
}

fn parse_hex_32(s: &str) -> std::result::Result<[u8; 32], String> {
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

/// Normalize a relay hint URL to a canonical `ws(s)://` pool-key string:
/// - convert `http(s)://` advertised-relay form to `ws(s)://`
/// - lowercase host
/// - strip default port (443 for wss, 80 for ws)
/// - strip trailing `/` on an empty path
///
/// Advertised-relay hints (pair records, in-band refresh) are stored in
/// `http(s)://` base-URL form, the relay's HTTP endpoint; the deposit path
/// dials the `ws(s)://` endpoint on the same host. `apply_relay_hint`
/// documents this contract ("the send path normalizes them"), so a hint
/// arriving as `http(s)` is converted here rather than rejected.
///
/// Returns `Err` when the URL cannot be parsed or the scheme is not one of
/// ws / wss / http / https.
fn normalize_wss_url(raw: &str) -> std::result::Result<String, ChatError> {
    let mut url = raw
        .parse::<Url>()
        .map_err(|e| ChatError::Invalid(format!("hint url parse: {e}")))?;
    match url.scheme() {
        "wss" | "ws" => {}
        "https" => url
            .set_scheme("wss")
            .map_err(|()| ChatError::Invalid("hint url set_scheme https->wss failed".into()))?,
        "http" => url
            .set_scheme("ws")
            .map_err(|()| ChatError::Invalid("hint url set_scheme http->ws failed".into()))?,
        s => {
            return Err(ChatError::Invalid(format!(
                "hint url scheme must be ws(s) or http(s), got {s}"
            )));
        }
    }
    let lower = url.host_str().unwrap_or("").to_ascii_lowercase();
    url.set_host(Some(&lower))
        .map_err(|e| ChatError::Invalid(format!("set_host: {e}")))?;
    let default_port: Option<u16> = match url.scheme() {
        "wss" => Some(443),
        "ws" => Some(80),
        _ => None,
    };
    if let Some(dp) = default_port {
        if url.port() == Some(dp) {
            url.set_port(None)
                .map_err(|()| ChatError::Invalid("set_port failed".into()))?;
        }
    }
    let mut s = url.to_string();
    if s.ends_with('/') && url.path() == "/" {
        s.pop();
    }
    Ok(s)
}

/// Convert a normalized `wss://` key (or any `wss://` URL) to its
/// `https://` equivalent for use with [`ClientConfig::new`].
fn wss_key_to_https_url(wss_key: &str) -> Result<Url> {
    let mut url = wss_key
        .parse::<Url>()
        .map_err(|e| ChatError::Invalid(format!("wss_key parse: {e}")))?;
    let https_scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        s => {
            return Err(ChatError::Invalid(format!(
                "expected wss/ws scheme, got {s}"
            )));
        }
    };
    url.set_scheme(https_scheme)
        .map_err(|()| ChatError::Invalid("set_scheme failed".into()))?;
    Ok(url)
}

/// Derive the normalized `wss://` pool key from an `https://` base URL.
/// Used at construction time to populate `own_relay_keys`.
fn https_url_to_wss_key(https_url: &Url) -> std::result::Result<String, ChatError> {
    let mut url = https_url.clone();
    let wss_scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        s => {
            return Err(ChatError::Invalid(format!(
                "expected https/http scheme, got {s}"
            )));
        }
    };
    url.set_scheme(wss_scheme)
        .map_err(|()| ChatError::Invalid("set_scheme failed".into()))?;
    normalize_wss_url(url.as_str())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn chat_pump_config_reconnects_forever() {
        // Chat-resilience win #1: the always-on message pump must never
        // permanently give up reconnecting (Some(20) would leave the pump
        // dead after ~20 min of outage until the app rebuilds the client).
        let cfg = chat_pump_config("https://relay.example".parse().unwrap());
        assert!(
            cfg.max_reconnect_attempts.is_none(),
            "chat pump must reconnect forever, not surface PermanentlyDisconnected"
        );
    }

    #[test]
    fn parse_hex_32_accepts_64_chars() {
        let h = "a".repeat(64);
        let bytes = parse_hex_32(&h).unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        assert!(parse_hex_32("ab").is_err());
    }

    #[test]
    fn normalize_wss_url_lowercases_host() {
        let n = normalize_wss_url("wss://RELAY.EXAMPLE.COM/v1/ws").unwrap();
        assert_eq!(n, "wss://relay.example.com/v1/ws");
    }

    #[test]
    fn normalize_wss_url_strips_default_port_443() {
        let n = normalize_wss_url("wss://r.io:443/v1/ws").unwrap();
        assert_eq!(n, "wss://r.io/v1/ws");
    }

    #[test]
    fn normalize_wss_url_strips_trailing_slash_on_empty_path() {
        let n = normalize_wss_url("wss://r.io/").unwrap();
        assert_eq!(n, "wss://r.io");
    }

    #[test]
    fn normalize_wss_url_dedup_cosmetic_variants() {
        let a = normalize_wss_url("wss://R.IO:443/").unwrap();
        let b = normalize_wss_url("wss://r.io/").unwrap();
        let c = normalize_wss_url("wss://r.io").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn normalize_wss_url_converts_http_to_ws() {
        // Advertised-relay hints arrive in http(s) base-URL form; the
        // deposit path dials the ws(s) endpoint on the same host. A plain
        // http base normalizes to a ws key (default :80 stripped).
        assert_eq!(normalize_wss_url("http://r.io/").unwrap(), "ws://r.io");
        assert_eq!(
            normalize_wss_url("http://r.io:8088/").unwrap(),
            "ws://r.io:8088"
        );
    }

    #[test]
    fn normalize_wss_url_converts_https_to_wss() {
        assert_eq!(normalize_wss_url("https://r.io/").unwrap(), "wss://r.io");
        assert_eq!(
            normalize_wss_url("https://r.io:443/").unwrap(),
            "wss://r.io"
        );
    }

    #[test]
    fn normalize_wss_url_rejects_non_web_scheme() {
        assert!(normalize_wss_url("ftp://r.io/").is_err());
        assert!(normalize_wss_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn normalize_wss_url_http_and_ws_forms_converge() {
        // The same host reached via the http advertised form and the ws
        // form must produce the identical pool key, so an own-relay hint
        // in either form matches own_relay_keys.
        assert_eq!(
            normalize_wss_url("http://r.io:8088/").unwrap(),
            normalize_wss_url("ws://r.io:8088").unwrap()
        );
    }

    use fetchit_relay_client::StaticKeySigner;
    use fetchit_relay_proto::Region;
    use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn start_relay_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = ServerConfig::defaults(addr, Region::Nyc);
        let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
        let (router, _state) = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        addr
    }

    fn make_signer(seed: &[u8]) -> Arc<dyn Signer + Send + Sync> {
        Arc::new(StaticKeySigner::from_public_key(seed.to_vec()))
    }

    fn make_transit(from_signer: &Arc<dyn Signer + Send + Sync>) -> TransitEnvelope {
        use fetchit_relay_proto::{identity::MachineId, EnvelopeKind, WIRE_VERSION};
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(from_signer.agent_id()),
            sender_machine_id: MachineId::from_bytes([0x22u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 0,
            ciphertext: b"payload".to_vec(),
            nonce: vec![0u8; 12],
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        }
    }

    fn sealed_envelope(transit: TransitEnvelope) -> OutboundEnvelope {
        OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: Some([0x22; 32]),
            payload: transit.ciphertext.clone(),
            timestamp_ms: transit.timestamp_ms,
            transit: Some(transit),
        }
    }

    fn to_agent() -> AgentId {
        AgentId(hex::encode([0x33u8; 32]))
    }

    /// `RelayTransport::send` MUST reject any envelope that doesn't
    /// carry a prebuilt sealed `TransitEnvelope`. The v1 fabricated
    /// fallback was removed at M2 — there is no wire-level escape
    /// hatch left, and this is the contract callers see.
    #[tokio::test]
    async fn send_without_prebuilt_envelope_returns_sealed_required() {
        let addr = start_relay_server().await;
        let base = url::Url::parse(&format!("http://{addr}/")).unwrap();
        let signer = make_signer(b"alice-pubkey");
        let transport = RelayTransport::connect(base, signer).await.unwrap();

        let to = to_agent();
        let outbound = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: Some([0x22; 32]),
            payload: b"unsealed".to_vec(),
            timestamp_ms: 1_700_000_000_000,
            transit: None,
        };

        let err = transport.send(&to, outbound, None).await.unwrap_err();
        assert!(
            matches!(
                err,
                ChatError::SealedRequired { caller } if caller == "RelayTransport::send",
            ),
            "expected SealedRequired{{caller=RelayTransport::send}}, got {err:?}",
        );
    }

    /// Regression: the inbound pump used to DROP `PublicPost` envelopes
    /// on a stale "until Stage 5.3" comment. 5.3 is built —
    /// `Client::default_dispatch_one` routes `transit.kind == PublicPost`
    /// to the public-post handler — so the pump MUST forward it, riding
    /// the `Dm` shape with `transit.kind` preserved. Dropping it again
    /// silently breaks the fediverse public feed end to end.
    #[test]
    fn pump_forwards_public_post_riding_dm_shape() {
        let env = TransitEnvelope::public_post(
            "https://mastodon.example/users/alice",
            br#"{"type":"Create","object":{"type":"Note","content":"hi"}}"#.to_vec(),
            1_700_000_000_000,
        )
        .unwrap();
        let mapped = map_inbound_delivery(env).expect("PublicPost must be forwarded, not dropped");
        assert!(
            matches!(mapped.kind, OutboundKind::Dm),
            "PublicPost rides the Dm shape; the dispatcher re-discriminates on transit.kind",
        );
        let transit = mapped
            .transit
            .expect("a forwarded envelope must carry its TransitEnvelope");
        assert!(
            matches!(transit.kind, RelayKind::PublicPost),
            "transit.kind must stay PublicPost so default_dispatch_one routes it to the public-post handler",
        );
    }

    /// M6.7: a `PairRecordPush` is unsealed + self-verified (the record's
    /// own ML-DSA-65 signature is the authority), so — exactly like a
    /// bridged `PublicPost` — the relay pump MUST forward it riding the
    /// `Dm` shape with `transit.kind` preserved. `default_dispatch_one`
    /// re-discriminates it to the M6.7 revoke-push receiver; dropping it
    /// here would silently break proactive roster convergence.
    #[test]
    fn pump_forwards_pair_record_push_riding_dm_shape() {
        use fetchit_relay_proto::identity::MachineId;
        let env = TransitEnvelope::pair_record_push(
            RelayAgentId::from_bytes([7u8; 32]),
            MachineId::from_bytes([9u8; 32]),
            b"signed-pair-record-v4-wire-bytes".to_vec(),
            1_700_000_000_000,
        )
        .unwrap();
        let mapped =
            map_inbound_delivery(env).expect("PairRecordPush must be forwarded, not dropped");
        assert!(
            matches!(mapped.kind, OutboundKind::Dm),
            "PairRecordPush rides the Dm shape; the dispatcher re-discriminates on transit.kind",
        );
        let transit = mapped
            .transit
            .expect("a forwarded envelope must carry its TransitEnvelope");
        assert!(
            matches!(transit.kind, RelayKind::PairRecordPush),
            "transit.kind must stay PairRecordPush so default_dispatch_one routes it to the revoke-push receiver",
        );
    }

    /// The forward fix must not turn the pump into a pass-through: kinds
    /// with no chat-layer route still drop to `None`.
    #[test]
    fn pump_still_drops_unroutable_kinds() {
        let mut env =
            TransitEnvelope::public_post("https://x.example/u/a", b"{}".to_vec(), 1).unwrap();
        env.kind = RelayKind::AdminEvent;
        assert!(
            map_inbound_delivery(env).is_none(),
            "AdminEvent has no chat-layer route and must stay dropped",
        );
    }

    // ── pool tests ────────────────────────────────────────────────────────────

    // Test helpers for pool tests use `ws://` (not `wss://`) because the
    // in-process relay server is plain HTTP/WS. `RendezvousHintsV1` is
    // constructed directly (not via `from_value`) so the `wss://`-only
    // validator is not invoked; the pool normalize/convert path handles
    // `ws://` -> `http://` identically to the `wss://` -> `https://`
    // production path.

    fn ws_hint(addr: SocketAddr) -> crate::card::RendezvousHintsV1 {
        crate::card::RendezvousHintsV1 {
            relays: vec![format!("ws://{addr}/")],
        }
    }

    /// Two sends to the same hinted relay open exactly ONE pooled connection.
    #[tokio::test]
    async fn pool_reuse_same_relay_opens_one_connection() {
        let relay_addr = start_relay_server().await;
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"pool-reuse-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        let hints = ws_hint(relay_addr);
        let transit = make_transit(&signer);

        transport
            .send(&to_agent(), sealed_envelope(transit.clone()), Some(&hints))
            .await
            .unwrap();
        transport
            .send(&to_agent(), sealed_envelope(transit.clone()), Some(&hints))
            .await
            .unwrap();

        assert_eq!(
            transport.pool_len(),
            1,
            "two sends to the same relay must reuse one pooled connection"
        );
    }

    /// Sends to two different hinted relays open two distinct pool entries.
    #[tokio::test]
    async fn pool_distinct_relays_open_two_connections() {
        let relay_a = start_relay_server().await;
        let relay_b = start_relay_server().await;
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"pool-distinct-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        let transit = make_transit(&signer);

        transport
            .send(
                &to_agent(),
                sealed_envelope(transit.clone()),
                Some(&ws_hint(relay_a)),
            )
            .await
            .unwrap();
        transport
            .send(
                &to_agent(),
                sealed_envelope(transit.clone()),
                Some(&ws_hint(relay_b)),
            )
            .await
            .unwrap();

        assert_eq!(
            transport.pool_len(),
            2,
            "sends to two different relays must each open their own pool entry"
        );
    }

    /// Cosmetically different but equivalent URLs collapse to one pool entry.
    /// Hints `["ws://host:PORT/", "ws://host:PORT"]` must deduplicate.
    #[tokio::test]
    async fn pool_normalized_key_dedup() {
        let relay_addr = start_relay_server().await;
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"pool-dedup-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        // Both forms should normalize to the same key.
        let (host, port) = (relay_addr.ip(), relay_addr.port());
        let form_a = format!("ws://{host}:{port}/");
        let form_b = format!("ws://{host}:{port}");
        let hints = crate::card::RendezvousHintsV1 {
            relays: vec![form_a, form_b],
        };

        let transit = make_transit(&signer);
        transport
            .send(&to_agent(), sealed_envelope(transit), Some(&hints))
            .await
            .unwrap();

        assert_eq!(
            transport.pool_len(),
            1,
            "cosmetically equivalent relay URLs must collapse to one pool entry"
        );
    }

    /// First hinted relay unreachable: second relay is tried and succeeds.
    #[tokio::test]
    async fn deposit_walk_first_unreachable_second_used() {
        let relay_b = start_relay_server().await;
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"deposit-walk-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        // Relay A: unreachable (port 1 is always closed).
        let hints = crate::card::RendezvousHintsV1 {
            relays: vec!["ws://127.0.0.1:1/".to_owned(), format!("ws://{relay_b}/")],
        };

        let transit = make_transit(&signer);
        let receipt = transport
            .send(&to_agent(), sealed_envelope(transit), Some(&hints))
            .await
            .unwrap();
        assert!(
            receipt.message_id.is_some(),
            "must get a message_id from the successful second relay"
        );
    }

    /// All hinted relays fail: `send` returns Err (not silent Ok).
    #[tokio::test]
    async fn all_hints_fail_returns_err() {
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"all-hints-fail-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        let hints = crate::card::RendezvousHintsV1 {
            relays: vec![
                "ws://127.0.0.1:1/".to_owned(),
                "ws://127.0.0.1:2/".to_owned(),
            ],
        };

        let transit = make_transit(&signer);
        let err = transport
            .send(&to_agent(), sealed_envelope(transit), Some(&hints))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::MessageTransport(_)),
            "all hints fail must return MessageTransport error, got {err:?}"
        );
    }

    /// No hints: own-relay session is used (back-compat path).
    #[tokio::test]
    async fn no_hints_uses_own_relay() {
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"no-hints-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        let transit = make_transit(&signer);
        let receipt = transport
            .send(&to_agent(), sealed_envelope(transit), None)
            .await
            .unwrap();
        assert_eq!(receipt.transport_name, TRANSPORT_NAME);
        // No pool entries opened for the no-hints path.
        assert_eq!(transport.pool_len(), 0);
    }

    /// A hint that equals the own relay reuses the primary session (no pool entry).
    #[tokio::test]
    async fn hint_equal_to_own_relay_reuses_session_no_pool_entry() {
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"own-relay-hint-sender");
        let transport = RelayTransport::connect(own_base.clone(), signer.clone())
            .await
            .unwrap();

        // Construct a hint that normalizes to the same key as the own relay.
        // The own relay is http://{addr}/ -> ws://{host}:{port} key.
        let hints = ws_hint(own_addr);

        let transit = make_transit(&signer);
        let receipt = transport
            .send(&to_agent(), sealed_envelope(transit), Some(&hints))
            .await
            .unwrap();
        assert_eq!(receipt.transport_name, TRANSPORT_NAME);
        // No pool entry opened: the session was reused.
        assert_eq!(
            transport.pool_len(),
            0,
            "hint pointing at own relay must not open a pool entry"
        );
    }

    /// Idle reap: a connection past the age threshold is dropped on the
    /// next reap call.
    #[tokio::test]
    async fn idle_reap_drops_stale_entry() {
        let relay_addr = start_relay_server().await;
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"idle-reap-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        let hints = ws_hint(relay_addr);
        let transit = make_transit(&signer);
        transport
            .send(&to_agent(), sealed_envelope(transit), Some(&hints))
            .await
            .unwrap();
        assert_eq!(transport.pool_len(), 1);

        // Reap with a zero threshold: every entry is "stale".
        transport.reap_older_than(Duration::from_secs(0));
        assert_eq!(
            transport.pool_len(),
            0,
            "reap with zero threshold must drop all entries"
        );
    }

    /// After `shutdown().await` the inbound path is dead: the orderly
    /// drain runs [`RelaySet::shutdown`] then awaits the pump to
    /// completion, so the merged delivery stream is closed and
    /// `next_delivery()` returns `None`. A second `shutdown()` is an
    /// idempotent no-op.
    #[tokio::test]
    async fn shutdown_drains_inbound_path() {
        let addr = start_relay_server().await;
        let base = url::Url::parse(&format!("http://{addr}/")).unwrap();
        let signer = make_signer(b"shutdown-drain-sender");
        let transport = RelayTransport::connect(base, signer).await.unwrap();

        transport.shutdown().await;

        // The orderly drain must have TAKEN (and awaited) the pump
        // JoinHandle, not merely run relay_set.shutdown(). This guards the
        // load-bearing half of the #358 fix: a regression that dropped the
        // pump-await would leave the handle untaken and trip this assert
        // (relay_set.shutdown() alone still makes next_delivery() -> None).
        assert!(
            transport.pump_handle_taken_for_test(),
            "shutdown must take + await the pump JoinHandle (orderly drain), not skip it",
        );

        // The merged inbox closed as the cascade unwound — no further
        // deliveries can ever arrive.
        assert!(
            transport.relay_set().next_delivery().await.is_none(),
            "after shutdown the merged inbox must be closed (next_delivery -> None)",
        );

        // Idempotent: a second shutdown finds the pump handle already
        // taken and does not hang or panic.
        transport.shutdown().await;
    }

    /// Auth: a pooled connection must complete the challenge/verify handshake.
    /// The test relay uses `AcceptAllVerifier`, so the pool connect succeeds
    /// (proving the challenge path ran). Any relay that rejects an unsigned
    /// challenge would surface `MessageTransport` here — verified by the
    /// `all_hints_fail_returns_err` test via a dead port.
    #[tokio::test]
    async fn pool_connect_authenticates_via_challenge_verify() {
        let relay_addr = start_relay_server().await;
        let own_addr = start_relay_server().await;
        let own_base = url::Url::parse(&format!("http://{own_addr}/")).unwrap();
        let signer = make_signer(b"auth-test-sender");
        let transport = RelayTransport::connect(own_base, signer.clone())
            .await
            .unwrap();

        let hints = ws_hint(relay_addr);
        let transit = make_transit(&signer);
        // Success proves the handshake ran (AcceptAllVerifier accepts any
        // signed challenge; a relay with a real verifier would reject an
        // unauthenticated frame before the Ready response).
        let receipt = transport
            .send(&to_agent(), sealed_envelope(transit), Some(&hints))
            .await
            .unwrap();
        assert!(receipt.message_id.is_some());
    }
}
