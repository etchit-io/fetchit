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
        let configs: Vec<ClientConfig> = base_urls.into_iter().map(ClientConfig::new).collect();
        let relay_set = RelaySet::connect(configs, signer.clone())
            .await
            .map_err(|e| ChatError::MessageTransport(format!("relay connect: {e}")))?;
        let relay_set = Arc::new(relay_set);
        // TODO(perf): bound this channel once we measure realistic inbound rates.
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_inbound_pump(relay_set.clone(), tx);
        Ok(Arc::new(Self {
            relay_set,
            counter: AtomicU64::new(0),
            inbound: StdMutex::new(Some(rx)),
            local_agent_id,
            signer,
            pool: StdMutex::new(HashMap::new()),
            own_relay_keys,
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
        let config = ClientConfig::new(https_url);
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

fn spawn_inbound_pump(relay_set: Arc<RelaySet>, tx: mpsc::UnboundedSender<InboundEnvelope>) {
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
    });
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
        // Dm, the M2.5 bridge metadata event, and a bridged fediverse
        // PublicPost all ride the Dm shape; `default_dispatch_one`
        // re-discriminates each on `transit.kind`
        // (X0xdGroupMetadataEvent -> dispatch_inbound_bridge,
        // PublicPost -> dispatch_inbound_public_post) before the
        // conversation/DM path. PublicPost was previously dropped here
        // on a stale "until Stage 5.3" comment; 5.3 is built, so it now
        // forwards.
        RelayKind::Dm | RelayKind::X0xdGroupMetadataEvent | RelayKind::PublicPost => {
            OutboundKind::Dm
        }
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
        // Reserved6 / Reserved7 are historical M2.5 Welcome-bridge
        // discriminators kept reserved for wire-stability. Drop here; the
        // bridge is no longer shipped, so no chat-layer route exists.
        RelayKind::Reserved6 | RelayKind::Reserved7 => {
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

/// Normalize a `wss://` or `ws://` URL to a canonical pool-key string:
/// - lowercase host
/// - strip default port (443 for wss, 80 for ws)
/// - strip trailing `/` on an empty path
///
/// Returns `Err` when the URL cannot be parsed or the scheme is not ws/wss.
fn normalize_wss_url(raw: &str) -> std::result::Result<String, ChatError> {
    let mut url = raw
        .parse::<Url>()
        .map_err(|e| ChatError::Invalid(format!("hint url parse: {e}")))?;
    match url.scheme() {
        "wss" | "ws" => {}
        s => {
            return Err(ChatError::Invalid(format!(
                "hint url scheme must be wss or ws, got {s}"
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
    fn normalize_wss_url_rejects_http_scheme() {
        assert!(normalize_wss_url("http://r.io/v1/ws").is_err());
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
