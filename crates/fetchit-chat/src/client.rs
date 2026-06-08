//! Top-level chat client. Owns the HTTP wrapper to x0xd, a Router of
//! message transports, the local chat identity vault, and the
//! conversation registry.

use crate::at_rest::{
    fresh_argon_salt, kdf_id_argon2, kdf_id_keychain, read_argon_salt, read_kdf_id, MasterKey,
    MasterKeySource, ARGON_SALT_LEN,
};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::{build_welcome_outbox, Conversation, ConversationRegistry, MutateAction};
use crate::discovery::{discover_local, DaemonEndpoint};
use crate::error::{ChatError, Result};
use crate::events::{open_stream, Event, EventStream};
use crate::http::Http;
use crate::lan_direct_transport::{ContactPubkeyLookup, LanDirectTransport};
use crate::lan_discovery::LanPeerTable;
use crate::lan_static::LanStaticIdentity;
use crate::local_store::StoreLayout;
use crate::relay_transport::RelayTransport;
use crate::transport::{InboundEnvelope, OutboundEnvelope, OutboundKind, Router};
use crate::{contacts, groups, identity, messages, presence};
use base64::Engine as _;
use fetchit_relay_client::{Signer, X0xdSigner};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;
use x0xd_client::X0xdVersion;
use zeroize::Zeroizing;

/// How often the auto-rekey sweeper fires.
const AUTO_REKEY_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// File name that gates whether vault state already exists for this
/// data dir. The chat identity vault is the first file written, so its
/// presence implies the rest of the layout was initialised under a
/// matching KDF / salt pair.
const IDENTITY_VAULT_FILE: &str = "identity.json.enc";

/// Builder for [`Client`] with optional overrides.
#[derive(Default)]
pub struct ClientBuilder {
    base_url: Option<String>,
    token: Option<String>,
    relay_url: Option<Url>,
    data_dir: Option<PathBuf>,
    passphrase: Option<String>,
    enable_lan_direct: bool,
    /// Caller-supplied callback that resolves a peer `agent_id` to its
    /// ML-DSA-65 public key. The desktop wires this through the chat
    /// contact store / conversation registry; tests can stub it. When
    /// LAN-direct is enabled and no lookup is supplied, the transport
    /// is wired with a no-op lookup (always returns `None`), so
    /// reachability stays `No` and the Router falls through to relay.
    contact_pubkey_lookup: Option<ContactPubkeyLookup>,
    /// Optional path to x0xd's `api.port` discovery file. When set, the
    /// internal [`x0xd_client::X0xdSigner`] is constructed via
    /// [`x0xd_client::X0xdSigner::connect_with_port_file`] and the
    /// signer self-heals across x0xd restarts — a connect-refused
    /// error re-reads the port file, swaps the cached URL, and retries
    /// once. Long-running consumers (chat-peer, desktop app) survive
    /// a daemon restart without going through their own restart cycle.
    x0xd_port_file: Option<PathBuf>,
    /// M3 federation core: optional community denylist consumer.
    /// When set, outbound DM sends to blocked recipients return
    /// [`ChatError::Denied`] and inbound envelopes from blocked
    /// senders are silently dropped at the dispatcher. When `None`,
    /// the chat layer is ungated (LAN-only / offline deployments,
    /// integration tests, and the M0 boot path where the consumer
    /// hasn't completed its first refresh yet).
    denylist: Option<Arc<dyn crate::denylist::DenylistCheck>>,
    /// M3 Phase E1: initial advertised-relays list seeded into the
    /// card's `fetchit_rendezvous_hints` slot at construction time.
    /// When `Some`, the list is validated by
    /// [`crate::card::RendezvousHintsV1::from_value`] and used
    /// verbatim. When `None`, [`seed_initial_advertised_relays`]
    /// falls back to `[primary_relay_url]` if (and only if) the
    /// relay URL parses as `wss://`; otherwise leaves the slot
    /// empty and the v2 hints field is omitted from the card.
    advertised_relays: Option<Vec<String>>,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_deref().map(|_| "<redacted>"))
            .field("relay_url", &self.relay_url)
            .field("data_dir", &self.data_dir)
            .field(
                "passphrase",
                &self.passphrase.as_deref().map(|_| "<redacted>"),
            )
            .field("enable_lan_direct", &self.enable_lan_direct)
            .field(
                "contact_pubkey_lookup",
                &self.contact_pubkey_lookup.as_ref().map(|_| "<closure>"),
            )
            .field("x0xd_port_file", &self.x0xd_port_file)
            .field("denylist", &self.denylist.as_ref().map(|_| "<consumer>"))
            .field("advertised_relays", &self.advertised_relays)
            .finish()
    }
}

impl ClientBuilder {
    /// Override the daemon base URL (e.g. `http://127.0.0.1:12700`).
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Override the bearer token.
    #[must_use]
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the relay URL. When set, the client wires a `RelayTransport`
    /// into its `Router` using the local x0xd as the signing oracle.
    /// Without this, outbound chat sends fail with
    /// [`ChatError::NoTransportAvailable`].
    #[must_use]
    pub fn relay_url(mut self, url: Url) -> Self {
        self.relay_url = Some(url);
        self
    }

    /// Override the chat data directory. Defaults to a platform-specific
    /// location under the user config dir.
    #[must_use]
    pub fn data_dir(mut self, p: PathBuf) -> Self {
        self.data_dir = Some(p);
        self
    }

    /// Supply a passphrase that derives the at-rest vault master key.
    /// When omitted, the keystore path is used.
    #[must_use]
    pub fn passphrase(mut self, s: String) -> Self {
        self.passphrase = Some(s);
        self
    }

    /// Wire a LAN-direct transport into the Router. When `true`, the
    /// transport is registered **before** the relay so LAN delivery
    /// wins by reachability priority; sends fall through to relay on
    /// error per the existing Router contract.
    ///
    /// The default is `false` — disabled until the host has tested it.
    /// Without a paired `contact_pubkey_lookup`, the transport is wired
    /// with a closure that always returns `None`, so reachability stays
    /// `No` for every peer and the Router falls through to relay.
    #[must_use]
    pub fn enable_lan_direct(mut self, enabled: bool) -> Self {
        self.enable_lan_direct = enabled;
        self
    }

    /// Supply the callback that resolves a peer `agent_id` to its
    /// ML-DSA-65 public key, used by the LAN-direct transport's Noise
    /// channel-binding verifier. Only consulted when
    /// [`Self::enable_lan_direct`] is also `true`.
    #[must_use]
    pub fn contact_pubkey_lookup(mut self, lookup: ContactPubkeyLookup) -> Self {
        self.contact_pubkey_lookup = Some(lookup);
        self
    }

    /// Path to x0xd's `api.port` discovery file. Enables port self-
    /// healing in the embedded [`x0xd_client::X0xdSigner`] so
    /// long-running consumers survive a daemon restart without the
    /// signer's cached base URL going stale. Recommended for any
    /// process that outlives a single x0xd lifetime — desktop app,
    /// chat-peer rig, etch>it agent bridges.
    #[must_use]
    pub fn x0xd_port_file(mut self, path: PathBuf) -> Self {
        self.x0xd_port_file = Some(path);
        self
    }

    /// Plug in a community denylist consumer. With this set:
    ///
    /// - DM outbound to a blocked recipient returns
    ///   [`ChatError::Denied`] before the envelope is sealed or sent.
    /// - Inbound deliveries from blocked senders are silently
    ///   dropped at the dispatcher, before any decrypt path runs —
    ///   the conversation layer never sees them.
    ///
    /// Without this, the chat layer is ungated (LAN-only / offline
    /// builds, tests, M0 startup before the consumer's first
    /// refresh). The consumer is whatever the host wires up — the
    /// canonical implementation is `fetchit_trust::DenylistConsumer`,
    /// bridged via a thin adapter to [`crate::DenylistCheck`].
    #[must_use]
    pub fn denylist(mut self, denylist: Arc<dyn crate::denylist::DenylistCheck>) -> Self {
        self.denylist = Some(denylist);
        self
    }

    /// M3 Phase E1: seed the initial advertised-relays list that gets
    /// minted into the card's `fetchit_rendezvous_hints` slot. The
    /// list is validated by
    /// [`crate::card::RendezvousHintsV1::from_value`] at build time —
    /// non-`wss://` schemes, oversize entries (>256 chars), excess
    /// entries (>8), and empty lists all surface as
    /// [`ChatError::Invalid`].
    ///
    /// When this is not set, the constructor falls back to
    /// `[primary_relay_url]` if (and only if) the relay URL parses
    /// as `wss://`; otherwise the v2 hints field is omitted from
    /// the card until [`Client::regenerate_card_with_relays`] is
    /// called explicitly. Desktop callers usually populate this
    /// from the Settings → Network → Advanced panel (E3); CLI /
    /// chat-peer callers read it from their TOML config.
    #[must_use]
    pub fn advertised_relays(mut self, relays: Vec<String>) -> Self {
        self.advertised_relays = Some(relays);
        self
    }

    /// Build the client. Falls back to [`discover_local`] for any
    /// x0xd connection field not explicitly set.
    ///
    /// # Errors
    /// Returns discovery, HTTP, relay-handshake, or vault failures.
    pub async fn build(self) -> Result<Client> {
        let (base_url, token) = match (self.base_url, self.token) {
            (Some(u), Some(t)) => (u, t),
            (u, t) => {
                let ep = discover_local().await?;
                (u.unwrap_or(ep.base_url), t.unwrap_or(ep.token))
            }
        };
        Client::from_parts(
            base_url,
            token,
            self.relay_url,
            self.data_dir,
            self.passphrase,
            self.enable_lan_direct,
            self.contact_pubkey_lookup,
            self.x0xd_port_file,
            self.denylist,
            self.advertised_relays,
        )
        .await
    }
}

/// Optional chat-encryption state — present whenever the caller
/// supplied a `data_dir` or `relay_url`, absent for the bare REST-only
/// mode used by integration tests against `wiremock`.
#[derive(Clone)]
struct ChatState {
    identity: Arc<FetchitIdentity>,
    registry: Arc<ConversationRegistry>,
    signer: Arc<dyn Signer>,
    layout: StoreLayout,
    local_machine_id: [u8; 32],
    /// M2.5 bridge — per-`(group, member)` direct-gossip reachability
    /// cache. The chat-peer dispatcher feeds [`ReachabilityCache::record`]
    /// from inbound gossip events; sender routing consults
    /// [`crate::groups_reachability::decide_route`] before wrapping.
    /// In-memory only at C4; persistence under the conversation-registry
    /// at-rest key is a follow-up.
    reachability: Arc<tokio::sync::Mutex<crate::groups_reachability::ReachabilityCache>>,
    /// M2.5 bridge — per-group consent state (default-OFF per Q4).
    /// Desktop "Use relay if direct gossip fails" toggle writes through
    /// [`BridgeConsentStore::set`]; sender routing reads via
    /// [`BridgeConsentStore::lookup`].
    bridge_consent: Arc<tokio::sync::Mutex<crate::groups_reachability::BridgeConsentStore>>,
    /// M2.5 bridge — recent bridge-inbound payload hashes. Marked by
    /// [`Client::dispatch_inbound_bridge`] before `POST /publish` so
    /// the SSE consumer can distinguish bridge-loopback from real
    /// direct-gossip delivery and avoid the false-positive reachability
    /// record that would silently break the symmetric-NAT case.
    bridge_inbound_shadow: Arc<tokio::sync::Mutex<crate::groups_reachability::BridgeInboundShadow>>,
    /// Per-`group_id` in-flight deduplicator for the x0xd `/members`
    /// fetch on the inbound bootstrap path. Concurrent envelopes for
    /// the same brand-new group collapse to one upstream call instead
    /// of N. See [`crate::members_singleflight`].
    members_singleflight: Arc<crate::members_singleflight::MembersSingleflight>,
}

/// Strongly-typed client for the chat surface — wraps x0xd's REST API,
/// the relay-routed message transport, the local chat identity, and
/// the conversation registry.
#[derive(Clone)]
pub struct Client {
    http: Arc<Http>,
    router: Arc<Router>,
    chat: Option<ChatState>,
    /// Direct handle to the relay transport when it's wired. The
    /// `Router` already routes outbound through it; this slot lets the
    /// shell drive relay-level capabilities (presence watch set) that
    /// don't fit the `Transport` trait shape.
    relay: Option<Arc<RelayTransport>>,
    /// Direct handle to the LAN-direct transport when it's wired.
    /// Lets the desktop shell drive transport-adjacent capabilities
    /// (mDNS announce + browse against `LanPeerTable`) that don't fit
    /// behind the `Transport` trait.
    lan: Option<Arc<LanDirectTransport>>,
    /// The TCP `SocketAddr` the LAN-direct listener bound when wired.
    /// Desktop publishes this port via mDNS so peers can dial back.
    lan_bound_addr: Option<std::net::SocketAddr>,
    /// M3 federation core: community denylist consumer. When wired,
    /// the dispatcher drops inbound from blocked senders and
    /// `messages::Endpoint::send` returns [`ChatError::Denied`] for
    /// blocked recipients. Cloneable across `Client` clones; the
    /// underlying refresh loop runs on the host's runtime.
    denylist: Option<Arc<dyn crate::denylist::DenylistCheck>>,
    /// M3 federation core: monotonic counter of inbound envelopes
    /// silently dropped by the denylist gate. Surfaced to ops via
    /// [`Self::denylist_dropped_inbound_count`] so operators can see
    /// whether the consumer is actually catching anything. Shared
    /// across `Client` clones via `Arc<AtomicU64>`.
    denylist_dropped_inbound: Arc<std::sync::atomic::AtomicU64>,
    /// M3 federation core: the list of `wss://` relay URLs this client
    /// currently advertises in the v2 share card's reserved
    /// `fetchit_rendezvous_hints` slot. Empty means the card is minted
    /// without the hints field (forward-compat with v1 readers).
    /// Mutated by [`Self::regenerate_card_with_relays`]; consumed by
    /// [`Self::current_card_value`] when minting a fresh card.
    advertised_relays: Arc<tokio::sync::RwLock<Vec<String>>>,
    /// M3 R-tail-4: inbound stream pumped from
    /// [`crate::transport::MultiHomeTransport`]'s `on_inbound` callback.
    /// `MultiHomeTransport` does not expose `take_inbound` (the trait
    /// surface returns `None`) because its fan-in is shaped as a
    /// closure-driven callback; this channel is the seam that lets
    /// [`Self::take_transport_inbound`] return the unified stream the
    /// existing relay-name callers expect. Wrapped in `Mutex<Option<_>>`
    /// so the first taker wins (matches the bare `RelayTransport`'s
    /// single-consumer inbound discipline). `None` when no relay URL
    /// was supplied at boot.
    multi_home_inbound:
        Option<Arc<std::sync::Mutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>>>,
    /// M3 R-tail-5: the local primary relay URL pinned to
    /// [`crate::transport::MultiHomeTransport`]'s slot 0. Send-path
    /// helpers synthesize this into a fallback
    /// `RendezvousHintsV1 { relays: [primary_url] }` when the
    /// recipient's stored card has no `v2_rendezvous_hints` slot —
    /// keeps legacy v1 contacts routable through slot 0 while letting
    /// the transport layer be strict-on-`None`. `None` when the
    /// client was built without a relay URL (REST-only mode).
    primary_relay_url: Option<String>,
}

impl Client {
    /// Discover a running daemon on this machine and connect to it.
    /// No relay transport is wired — call [`ClientBuilder::relay_url`]
    /// for that.
    pub async fn auto() -> Result<Self> {
        Self::builder().build().await
    }

    /// Build from an already-resolved endpoint, no relay transport.
    pub async fn from_endpoint(ep: DaemonEndpoint) -> Result<Self> {
        Self::from_parts(
            ep.base_url,
            ep.token,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
        )
        .await
    }

    /// Start a builder for custom configuration.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    #[allow(clippy::too_many_arguments)]
    async fn from_parts(
        base_url: String,
        token: String,
        relay_url: Option<Url>,
        data_dir: Option<PathBuf>,
        passphrase: Option<String>,
        enable_lan_direct: bool,
        contact_pubkey_lookup: Option<ContactPubkeyLookup>,
        x0xd_port_file: Option<PathBuf>,
        denylist: Option<Arc<dyn crate::denylist::DenylistCheck>>,
        advertised_relays: Option<Vec<String>>,
    ) -> Result<Self> {
        let http = Arc::new(match x0xd_port_file.as_ref() {
            Some(path) => Http::new_with_port_file(path.clone(), token.clone())?,
            None => Http::new(base_url.clone(), token.clone())?,
        });
        let needs_chat =
            relay_url.is_some() || data_dir.is_some() || passphrase.is_some() || enable_lan_direct;

        let (router, chat, relay, lan, lan_bound_addr, multi_home_inbound, primary_relay_url) =
            if needs_chat {
                announce_identity_best_effort(&http).await;
                build_with_chat(
                    &http,
                    &base_url,
                    token,
                    relay_url,
                    data_dir,
                    passphrase,
                    enable_lan_direct,
                    contact_pubkey_lookup,
                    x0xd_port_file,
                )
                .await?
            } else {
                (Router::new(), None, None, None, None, None, None)
            };

        let router = Arc::new(router);
        if let Some(chat) = chat.as_ref() {
            spawn_auto_rekey_sweeper(&router, chat, primary_relay_url.clone());
        }

        let initial_relays =
            seed_initial_advertised_relays(advertised_relays, primary_relay_url.as_deref())?;

        Ok(Self {
            http,
            router,
            chat,
            relay,
            lan,
            lan_bound_addr,
            denylist,
            denylist_dropped_inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            advertised_relays: Arc::new(tokio::sync::RwLock::new(initial_relays)),
            multi_home_inbound,
            primary_relay_url,
        })
    }

    /// Snapshot of the cumulative inbound-drop counter — number of
    /// envelopes the denylist gate has silently rejected since this
    /// `Client` was constructed. Ops surfaces poll this to confirm
    /// the consumer is actually catching anything.
    #[must_use]
    pub fn denylist_dropped_inbound_count(&self) -> u64 {
        self.denylist_dropped_inbound
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Construct an M3 denylist consumer rooted at `denylist_url_base`
    /// (e.g. `https://etchit.io/v1`), spawn its background poll loop
    /// against `http`, and install it into this client's denylist gate.
    ///
    /// `cache_path` is the on-disk directory `DenylistConsumer` writes
    /// the per-kind signed manifests under for offline-boot hydration;
    /// `None` skips disk persistence. Cache hydration runs synchronously
    /// before this method returns, so a cold offline boot still picks
    /// up the prior good snapshot.
    ///
    /// `http` is the [`fetchit_trust_client::HttpClient`] the poll loop
    /// drives the refresh through. Production callers pass a
    /// [`fetchit_trust_client::ReqwestClient`] (constructed with
    /// `ReqwestClient::new()`); tests inject a stub so the boot path is
    /// exercisable without network access.
    ///
    /// On return:
    /// - The client's [`crate::DenylistCheck`] field is set to a
    ///   [`crate::denylist::DenylistQueryAdapter`] wrapping the new
    ///   consumer; outbound DM sends and inbound dispatch begin gating
    ///   immediately (against the cache snapshot until the first online
    ///   refresh completes).
    /// - A background tokio task polls `denylist_url_base` on the
    ///   consumer's default cadence; the [`tokio::task::JoinHandle`] is
    ///   currently dropped (M3 D8.2 will stash it for graceful
    ///   shutdown).
    /// - The consumer's [`fetchit_trust_client::BlockEvent`] subscriber
    ///   is created and dropped; D9+ will route it into
    ///   [`crate::transport::MultiHomeTransport::new_with_subscriber`]
    ///   so mid-session `RelayUrl` blocks drop active slots.
    ///
    /// The hardcoded issuer pubkey is
    /// [`fetchit_trust_client::etchitio_pubkey`]; pre-launch this is a
    /// placeholder fixture, swapped for the real etchit-io key before
    /// any production deploy.
    ///
    /// # Errors
    /// Returns no errors today: the consumer constructor is infallible
    /// and the cache load is best-effort. The signature is `Result` so
    /// future versions (e.g. surfacing first-refresh failures or
    /// rejecting a malformed URL) can fail loudly.
    pub fn install_m3_denylist(
        &mut self,
        denylist_url_base: String,
        cache_path: Option<PathBuf>,
        http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static>,
    ) -> Result<()> {
        let consumer = Arc::new(fetchit_trust_client::DenylistConsumer::new(
            fetchit_trust_client::etchitio_pubkey(),
            denylist_url_base,
            cache_path,
        ));
        consumer.load_cache_blocking();

        // Subscribe before spawning the poll loop so the very first
        // refresh's BlockEvent isn't lost. D9+ hands this receiver to
        // MultiHomeTransport::new_with_subscriber; today it's discarded
        // (drop closes the receiver but the consumer keeps the
        // broadcast Sender alive, so future subscribers still work).
        let _subscriber = consumer.subscribe();

        // TODO(M3 D8.2): stash the JoinHandle on Client so shutdown can
        // abort the loop deterministically. Today the task lives until
        // the consumer Arc drops (every subscriber + the adapter + this
        // spawned closure each hold one).
        let _handle = Arc::clone(&consumer).spawn_poll_loop(http);

        let query: Arc<dyn fetchit_trust::DenylistQuery> = consumer;
        let adapter: Arc<dyn crate::denylist::DenylistCheck> =
            Arc::new(crate::denylist::DenylistQueryAdapter::new(query));
        self.denylist = Some(adapter);
        Ok(())
    }

    /// Replace the relay list advertised in this client's v2 share card
    /// with `relays`, after validating them through
    /// [`crate::card::RendezvousHintsV1::from_value`]. Subsequent calls
    /// to [`Self::current_card_value`] (and any future
    /// `extended_share_uri` mint) embed the new list in the card's
    /// reserved `fetchit_rendezvous_hints` slot.
    ///
    /// Validation (delegated to `RendezvousHintsV1::from_value`):
    /// `relays` is non-empty, has at most 8 entries, and every entry
    /// is at most 256 chars and prefixed with `wss://`.
    ///
    /// The v3 profile manifest republish that propagates the new
    /// relay set across the federation is **deferred to Phase E**
    /// (`apps/fetchit-desktop/src-tauri` will drive the publish from
    /// the Tauri command); this method only mutates in-memory state
    /// and logs an info line so operators see when a regenerate
    /// happens.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when the relay list fails validation.
    pub async fn regenerate_card_with_relays(&self, relays: Vec<String>) -> Result<()> {
        let hints_value = serde_json::json!({ "relays": relays });
        // Validate via the v1 decoder so the same shape that ships in
        // a card is rejected here too — non-empty, <= 8 entries,
        // <= 256 chars, wss:// scheme.
        let _validated = crate::card::RendezvousHintsV1::from_value(&hints_value)?;

        {
            let mut slot = self.advertised_relays.write().await;
            slot.clone_from(&relays);
        }

        log::info!(
            "[chat] card regenerated with {} advertised relays",
            relays.len()
        );
        // TODO(M3 Phase E): republish the v3 profile manifest so the
        // new hints propagate to the federation. Tauri command in
        // apps/fetchit-desktop/src-tauri (Phase E2) will drive that
        // network call once this in-memory swap returns.
        Ok(())
    }

    /// Mint the v2 extended share card from in-memory chat state +
    /// the currently advertised relays. Used today by D9 tests and by
    /// Phase E callers that want the card without the HTTP round-trip
    /// to `GET /agent/card` (which a unit test cannot stand up).
    ///
    /// Returns the card JSON value with the `fetchit_*` fields baked
    /// in (and `fetchit_rendezvous_hints` populated when
    /// [`Self::regenerate_card_with_relays`] has been called with a
    /// non-empty list). The contained x0x card body is a minimal
    /// fixture-shaped object derived from the chat identity's
    /// `agent_id_hex`; the production code path
    /// ([`identity::Endpoint::extended_share_uri`]) replaces that with
    /// the live `GET /agent/card` body before signing.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when the client was built without chat
    /// state (REST-only mode has no KEM key or signer to attach), or
    /// when the card-signing path fails.
    pub async fn current_card_value(&self) -> Result<serde_json::Value> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not built; no card to mint".into()))?;
        let relays = self.advertised_relays.read().await.clone();
        let hints = if relays.is_empty() {
            None
        } else {
            Some(crate::card::RendezvousHintsV1 { relays })
        };
        // Minimal x0x card body — only the agent_id is load-bearing
        // for the card-signature path. Production callers replace this
        // with the daemon's `GET /agent/card` body before signing.
        let x0x_card = serde_json::json!({
            "agent_id": chat.identity.agent_id_hex(),
            "display_name": "",
            "addresses": [],
        });
        crate::card::extend_with_fetchit_fields(
            &x0x_card,
            chat.identity.kem_public_key(),
            chat.signer.as_ref(),
            hints,
        )
        .await
    }

    /// Borrow the LAN-direct transport handle when one is wired.
    /// Returns `None` for clients built without
    /// [`ClientBuilder::enable_lan_direct`]. Desktop callers use this
    /// to drive the mDNS announce + browse against the transport's
    /// [`crate::lan_discovery::LanPeerTable`].
    #[must_use]
    pub fn lan_transport_arc(&self) -> Option<&Arc<LanDirectTransport>> {
        self.lan.as_ref()
    }

    /// The TCP listener address the LAN-direct transport bound to.
    /// Returns `None` if LAN-direct isn't wired. Desktop publishes this
    /// `port` via mDNS so co-resident peers can dial back.
    #[must_use]
    pub fn lan_bound_addr(&self) -> Option<std::net::SocketAddr> {
        self.lan_bound_addr
    }

    /// Identity endpoint: read your agent, generate cards, import others.
    #[must_use]
    pub fn identity(&self) -> identity::Endpoint<'_> {
        identity::Endpoint::new(
            &self.http,
            self.chat.as_ref().map(|c| &c.identity),
            self.chat.as_ref().map(|c| &c.signer),
        )
    }

    /// Contacts endpoint: list, add, remove, set trust.
    #[must_use]
    pub fn contacts(&self) -> contacts::Endpoint<'_> {
        contacts::Endpoint::new(&self.http)
    }

    /// Direct messaging endpoint — sends route through the Router.
    #[must_use]
    pub fn messages(&self) -> messages::Endpoint<'_> {
        messages::Endpoint::new_with_denylist(
            &self.http,
            &self.router,
            self.chat.as_ref().map(|c| &c.identity),
            self.chat.as_ref().map(|c| &c.registry),
            self.chat.as_ref().map(|c| &c.signer),
            self.chat.as_ref().map(|c| &c.layout),
            self.chat.as_ref().map_or([0u8; 32], |c| c.local_machine_id),
            self.chat.as_ref().map(|c| &c.members_singleflight),
            self.denylist.as_ref(),
            self.primary_relay_url.as_deref(),
        )
    }

    /// Group messaging endpoint.
    #[must_use]
    pub fn groups(&self) -> groups::Endpoint<'_> {
        groups::Endpoint::new(&self.http)
    }

    /// Presence + FOAF endpoint.
    #[must_use]
    pub fn presence(&self) -> presence::Endpoint<'_> {
        presence::Endpoint::new(&self.http)
    }

    /// Borrow the message Router (telemetry, dev tooling).
    #[must_use]
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// Cloneable handle to the local chat identity (needed by the
    /// desktop pump to drive `conversation::dispatch_inbound`). Returns
    /// `None` for clients built without a `data_dir` / `passphrase` /
    /// `relay_url` — REST-only mode.
    #[must_use]
    pub fn identity_arc(&self) -> Option<Arc<FetchitIdentity>> {
        self.chat.as_ref().map(|c| c.identity.clone())
    }

    /// Cloneable handle to the conversation registry (needed by the
    /// desktop pump to drive `conversation::dispatch_inbound`). Returns
    /// `None` in REST-only mode.
    #[must_use]
    pub fn registry_arc(&self) -> Option<Arc<ConversationRegistry>> {
        self.chat.as_ref().map(|c| c.registry.clone())
    }

    /// Borrow the on-disk layout (needed by the chat-import code path
    /// to persist the v2 share card alongside x0xd's contact list).
    /// Returns `None` in REST-only mode.
    #[must_use]
    pub fn layout(&self) -> Option<&StoreLayout> {
        self.chat.as_ref().map(|c| &c.layout)
    }

    /// Take the inbound stream of the named transport once.
    /// Returns `None` if the transport isn't wired or its inbound has
    /// already been taken.
    ///
    /// `"relay"` and `"multi-home"` both resolve to the unified inbound
    /// fanned in by [`crate::transport::MultiHomeTransport`]: that
    /// transport doesn't expose `take_inbound` on the trait surface (its
    /// dispatch is callback-shaped), so `Client` stashes the channel
    /// behind [`Self::multi_home_inbound`] at boot. Existing callers
    /// still ask for `"relay"`; new ones can use the canonical name.
    #[must_use]
    pub fn take_transport_inbound(
        &self,
        name: &str,
    ) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        if matches!(name, "relay" | "multi-home") {
            if let Some(slot) = self.multi_home_inbound.as_ref() {
                if let Ok(mut guard) = slot.lock() {
                    if let Some(rx) = guard.take() {
                        return Some(rx);
                    }
                }
            }
        }
        self.router
            .transports()
            .iter()
            .find(|t| t.name() == name)
            .and_then(|t| t.take_inbound())
    }

    /// Spawn a background dispatcher that drains the relay transport's
    /// inbound channel and routes every envelope through the right
    /// receive path. This is the piece every consumer of relay inbound
    /// needs but that `Client::build` does NOT wire automatically —
    /// without it, `Conversation::history` never gains entries from
    /// remote sends because nothing pulls envelopes off the mpsc and
    /// nothing calls [`messages::Endpoint::receive_private_group_envelope`]
    /// or [`crate::conversation::dispatch_inbound`].
    ///
    /// Routing mirrors `crates/fetchit-chat/src/bin/peer.rs::decode_inbound`:
    /// - [`crate::messages::is_private_group_envelope`] matches the M2
    ///   `EnvelopeKind::PrivateGroupChat` shape and goes through
    ///   `receive_private_group_envelope` (which calls x0xd
    ///   `/secure/decrypt`, ML-DSA verifies, dedups, persists via
    ///   `push_history`).
    /// - Anything else goes through `dispatch_inbound` (the legacy
    ///   chat-v2 path).
    /// - Self-source filter at the top drops own-sends that round-trip
    ///   over the relay (same logic as `peer.rs` line ~230).
    ///
    /// Errors from individual envelopes are swallowed silently — a
    /// single bad envelope must not wedge the dispatch pump. Callers
    /// that need richer behaviour (logging, echo, receipt-send) should
    /// drive their own dispatch loop and reserve this helper for the
    /// "I just need history to update" path (`m2_live` tests, future
    /// tooling that wants drop-in chat dispatch).
    ///
    /// Returns `None` if the `"relay"` transport is not wired or its
    /// inbound has already been taken (the channel is single-consumer).
    /// The returned [`tokio::task::JoinHandle`] should be held by the
    /// caller; dropping it cancels the dispatcher.
    #[must_use]
    pub fn spawn_default_dispatcher(&self) -> Option<tokio::task::JoinHandle<()>> {
        let mut rx = self.take_transport_inbound("relay")?;
        let client = self.clone();
        Some(tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                client.default_dispatch_one(env).await;
            }
        }))
    }

    async fn default_dispatch_one(&self, mut env: InboundEnvelope) {
        let Some(transit) = env.transit.take() else {
            return;
        };
        if let Some(identity) = self.identity_arc() {
            if hex::encode(transit.sender_agent_id.as_bytes()) == identity.agent_id_hex() {
                return;
            }
        }
        if matches!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent
        ) {
            if let Err(e) = self.dispatch_inbound_bridge(&transit).await {
                log::warn!("bridge dispatch dropped envelope: {e}");
            }
            return;
        }
        // M3 D7: drop inbound user-content from denylisted senders
        // BEFORE the decrypt path runs. Gate sits AFTER the bridge /
        // Welcome dispatchers so group-state propagation and invite
        // mechanics keep working even when the sender is on the list
        // (those flows would otherwise leave the group membership
        // state divergent across the federation). Sender identity
        // comes from the signed `sender_agent_id`, so the relay can't
        // help an attacker bypass this by spoofing.
        //
        // Silent drop (no error surfaced) is deliberate — mirrors the
        // `ChatError::Denied` doc contract, and avoids leaking a
        // "you're blocked" signal that an attacker could correlate
        // against a candidate sender set.
        if should_drop_inbound_from_denylisted(self.denylist.as_ref(), &transit).await {
            self.denylist_dropped_inbound
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        if messages::is_private_group_envelope(&transit) {
            let group_id_hex = transit
                .group_id
                .as_ref()
                .map(|g| hex::encode(g.as_bytes()))
                .unwrap_or_default();
            if group_id_hex.is_empty() {
                return;
            }
            let _ = self
                .messages()
                .receive_private_group_envelope(&transit, &group_id_hex)
                .await;
        } else if let (Some(identity), Some(registry)) = (self.identity_arc(), self.registry_arc())
        {
            let _ = crate::conversation::dispatch_inbound(
                transit,
                identity.as_ref(),
                registry.as_ref(),
            )
            .await;
        }
    }

    /// Build a [`x0xd_client::SecureGroupsEndpoint`] against the same
    /// x0xd this client dials. Used by the M2.5 bridge dispatch to
    /// `POST /publish` the inner JSON event so pubsub-loopback advances
    /// local MLS state via the standard apply path.
    fn secure_groups(&self) -> Result<x0xd_client::SecureGroupsEndpoint> {
        let base = url::Url::parse(&self.http.base_url())
            .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
        x0xd_client::SecureGroupsEndpoint::new(base, self.http.token().to_owned())
            .map_err(ChatError::from)
    }

    /// Cloneable handle to the M2.5 reachability cache. Mutated by the
    /// chat-peer dispatcher whenever an x0xd group event arrives via
    /// the direct gossip path, queried by [`Self::send_x0xd_metadata_event`]
    /// before deciding whether to bridge.
    #[must_use]
    pub fn reachability_cache(
        &self,
    ) -> Option<Arc<tokio::sync::Mutex<crate::groups_reachability::ReachabilityCache>>> {
        self.chat.as_ref().map(|c| c.reachability.clone())
    }

    /// Cloneable handle to the M2.5 bridge-consent store. Desktop UI
    /// writes through this when the consent modal resolves.
    #[must_use]
    pub fn bridge_consent(
        &self,
    ) -> Option<Arc<tokio::sync::Mutex<crate::groups_reachability::BridgeConsentStore>>> {
        self.chat.as_ref().map(|c| c.bridge_consent.clone())
    }

    /// Cloneable handle to the M2.5 bridge-inbound shadow set. The SSE
    /// reachability recorder consults this to avoid false-recording
    /// `(group, member)` as `Reachable` when the inbound event came
    /// via bridge-loopback (the case the bridge exists to solve).
    /// External callers should typically prefer
    /// [`Client::spawn_sse_reachability_recorder`] over driving the
    /// shadow directly.
    #[must_use]
    pub fn bridge_inbound_shadow(
        &self,
    ) -> Option<Arc<tokio::sync::Mutex<crate::groups_reachability::BridgeInboundShadow>>> {
        self.chat.as_ref().map(|c| c.bridge_inbound_shadow.clone())
    }

    /// Send an M2.5 bridge envelope — a signed x0xd
    /// `NamedGroupMetadataEvent` JSON body — to a single peer over the
    /// relay path, gated by the per-group consent + reachability rule
    /// from §5 of the bridge spec.
    ///
    /// Routing flow:
    /// - If direct gossip can reach `recipient_agent_id_hex` for
    ///   `group_id` (via [`ReachabilityCache::lookup`]), returns
    ///   `Ok(BridgeDecision::LetGossipCarry)` without sending — the
    ///   caller is expected to publish the event to local x0xd
    ///   (gossip will deliver it).
    /// - Otherwise consults [`BridgeConsentStore::lookup`] for
    ///   `group_id`:
    ///   * `ConsentedOptIn` → seal + send via relay; returns
    ///     `Ok(BridgeDecision::WrapAndSend)`.
    ///   * `DeclinedOptOut` → returns [`ChatError::BridgeDeclined`].
    ///   * `NotAsked` → returns [`ChatError::BridgeNeedsConsent`] so
    ///     the desktop UI can surface the consent modal.
    ///
    /// The caller is responsible for constructing the signed event
    /// body (canonical bytes → `POST /agent/sign` → JSON event). The
    /// helpers in [`crate::groups::bridge`] expose the canonical-bytes
    /// formula + JSON shape for each event variant.
    ///
    /// # Errors
    /// - [`ChatError::ShareCardMissing`] when no contact card exists
    ///   for the recipient — UI should route to "Import contact card
    ///   first".
    /// - [`ChatError::BridgeNeedsConsent`] / [`ChatError::BridgeDeclined`]
    ///   per the routing rule above.
    /// - [`ChatError::Invalid`] when the chat state is missing, the
    ///   recipient hex is malformed, or the seal/sign path fails.
    /// - Router errors forwarded as [`ChatError::MessageTransport`].
    pub async fn send_x0xd_metadata_event(
        &self,
        recipient_agent_id_hex: &str,
        group_id: &crate::groups::GroupId,
        topic: String,
        signed_event_json_bytes: &[u8],
    ) -> Result<crate::groups_reachability::BridgeDecision> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        let recipient_aid_obj = crate::identity::AgentId(recipient_agent_id_hex.to_owned());
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let decision = {
            let cache = chat.reachability.lock().await;
            let consent = chat.bridge_consent.lock().await;
            crate::groups_reachability::decide_route(
                &cache,
                &consent,
                group_id,
                &recipient_aid_obj,
                now_ms,
            )
        };
        match decision {
            crate::groups_reachability::BridgeDecision::LetGossipCarry => return Ok(decision),
            crate::groups_reachability::BridgeDecision::DropDeclined => {
                return Err(ChatError::BridgeDeclined {
                    group_id: group_id.as_str().to_owned(),
                });
            }
            crate::groups_reachability::BridgeDecision::PromptConsent => {
                return Err(ChatError::BridgeNeedsConsent {
                    group_id: group_id.as_str().to_owned(),
                });
            }
            crate::groups_reachability::BridgeDecision::WrapAndSend => {}
        }

        let recipient_kem_pub =
            crate::groups::bridge::recipient_kem_key(&chat.layout, recipient_agent_id_hex)?;
        let mut recipient_aid = [0u8; 32];
        hex::decode_to_slice(recipient_agent_id_hex, &mut recipient_aid)
            .map_err(|e| ChatError::Invalid(format!("recipient agent_id hex: {e}")))?;
        let mut local_aid = [0u8; 32];
        hex::decode_to_slice(chat.identity.agent_id_hex(), &mut local_aid)
            .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(signed_event_json_bytes);

        let outbound = crate::groups::bridge::build_bridge_outbox(
            &recipient_aid,
            &recipient_kem_pub,
            topic,
            payload_b64,
            &local_aid,
            &chat.local_machine_id,
            chat.signer.as_ref(),
        )
        .await?;

        let recipient =
            crate::identity::AgentId(hex::encode(outbound.recipient_agent_id.as_bytes()));
        let transport_out = crate::transport::OutboundEnvelope {
            kind: crate::transport::OutboundKind::Dm,
            from_machine_id: Some(chat.local_machine_id),
            payload: Vec::new(),
            timestamp_ms: outbound.envelope.timestamp_ms,
            transit: Some(outbound.envelope),
        };
        // M3 R-tail-5: resolve the recipient's advertised relay hints
        // from their stored card so MultiHomeTransport can route this
        // sealed bridge envelope to slot 1/2 when their primary
        // differs from ours. Legacy v1 contacts fall back to the
        // local primary URL (slot 0).
        let hints = crate::messages::StoredContactCard::resolve_recipient_hints(
            &chat.layout,
            recipient_agent_id_hex,
        )
        .ok()
        .flatten()
        .or_else(|| {
            self.primary_relay_url
                .as_deref()
                .map(|url| crate::card::RendezvousHintsV1 {
                    relays: vec![url.to_owned()],
                })
        });
        self.router
            .send(&recipient, transport_out, hints.as_ref())
            .await?;
        Ok(decision)
    }

    /// Unseal an inbound M2.5 bridge envelope
    /// (`EnvelopeKind::X0xdGroupMetadataEvent`) and POST the inner
    /// JSON payload to local x0xd `/publish`. Saorsa pubsub's
    /// local-loopback then advances local MLS state via the standard
    /// `apply_named_group_metadata_event` path.
    ///
    /// The dispatch pump spawned by [`Client::spawn_default_dispatcher`]
    /// calls this automatically; external binaries (chat-peer) call it
    /// directly from their inbound loop.
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] when the envelope kind doesn't match,
    ///   the chat-state isn't built, or the seal can't be opened.
    /// - [`ChatError::MessageTransport`] forwarded from x0xd's
    ///   `/publish` rejection.
    pub async fn dispatch_inbound_bridge(
        &self,
        transit: &fetchit_relay_proto::TransitEnvelope,
    ) -> Result<()> {
        let identity = self
            .identity_arc()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let secure = self.secure_groups()?;
        if transit.kind != fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent {
            return Err(ChatError::Invalid(format!(
                "dispatch_inbound_bridge called on kind={:?}",
                transit.kind
            )));
        }
        let wrapper = crate::groups::bridge::unseal_bridge_wrapper(
            identity.kem_secret_key(),
            &transit.kem_ciphertext,
            &transit.nonce,
            &transit.ciphertext,
        )?;
        // Mark the bridge-inbound shadow BEFORE we publish so the SSE
        // consumer (which races us via x0xd's local pubsub loopback)
        // can recognise the about-to-arrive event as bridge-delivered
        // and skip the false-positive reachability record. Hashing the
        // decoded JSON bytes matches whatever the SSE consumer sees on
        // `Event::GossipMessage { payload, .. }`. A best-effort
        // decode-failure here just skips the shadow entry — the
        // publish below still runs, so the worst case is a benign
        // future false-positive Reachable record.
        if let Some(shadow) = self.bridge_inbound_shadow() {
            if let Ok(payload_bytes) =
                base64::engine::general_purpose::STANDARD.decode(wrapper.payload_b64.as_bytes())
            {
                let h = crate::groups_reachability::hash_payload(&payload_bytes);
                shadow.lock().await.mark(
                    h,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                );
            }
        }
        secure
            .publish(&wrapper.topic, &wrapper.payload_b64)
            .await
            .map_err(ChatError::from)?;
        Ok(())
    }

    /// Spawn the M2.5 SSE reachability recorder: a background task that
    /// consumes `/events`, watches for `NamedGroupMetadataEvent` gossip
    /// frames, and records direct-gossip reachability into
    /// [`ReachabilityCache`] for `(group, sender)`. Events that match
    /// a recent [`BridgeInboundShadow`] entry are skipped, and
    /// self-published loopbacks (`from == local agent id`) are skipped
    /// — together that keeps `Reachable` honest under the
    /// symmetric-NAT bridge-loopback case the spec §5 routing rule
    /// depends on.
    ///
    /// The returned handle owns the task; dropping it terminates the
    /// recorder.
    ///
    /// # Respawn contract
    ///
    /// The task wraps its `/events` subscription in an exponential
    /// backoff loop (1 s → 2 s → 4 s → … capped at 60 s) so a
    /// transient x0xd outage (service restart, port drift, network
    /// flap) does not silently kill reachability tracking — the next
    /// successful open resets the backoff. Errors are logged once per
    /// retry. The task only exits when its `JoinHandle` is dropped.
    ///
    /// # Errors
    /// Returns `ChatError::Invalid` when the client was built without
    /// chat state (the cache + shadow would have no host to write to).
    pub fn spawn_sse_reachability_recorder(&self) -> Result<tokio::task::JoinHandle<()>> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let cache = chat.reachability.clone();
        let shadow = chat.bridge_inbound_shadow.clone();
        let local_agent_hex = chat.identity.agent_id_hex().to_owned();
        let client = self.clone();
        Ok(tokio::spawn(async move {
            const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
            const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
            let mut backoff = MIN_BACKOFF;
            loop {
                let mut stream = match client.events().await {
                    Ok(s) => {
                        // Successful subscribe — reset backoff so a
                        // long-running session that later fails comes
                        // back at the floor.
                        backoff = MIN_BACKOFF;
                        s
                    }
                    Err(e) => {
                        log::warn!(
                            "sse reachability recorder: open /events failed: {e}; retrying in {backoff:?}",
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                };
                let mut stream_ok = true;
                while let Some(event) = stream.next().await {
                    let event = match event {
                        Ok(e) => e,
                        Err(e) => {
                            log::warn!("sse reachability recorder: stream error: {e}; reopening");
                            stream_ok = false;
                            break;
                        }
                    };
                    let Event::GossipMessage {
                        topic,
                        payload,
                        from,
                    } = event
                    else {
                        continue;
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    // Snapshot the shadow under its lock, run the pure
                    // classify decision, then drop the shadow lock
                    // before touching the cache. Keeps the two
                    // mutexes from composing into a held-across-await
                    // chain.
                    let classified = {
                        let shadow_guard = shadow.lock().await;
                        crate::groups_reachability::classify_sse_event(
                            &topic,
                            &payload,
                            from.as_ref(),
                            &local_agent_hex,
                            &shadow_guard,
                            now,
                        )
                    };
                    if let Some((group, member)) = classified {
                        cache.lock().await.record(group, member, now);
                    }
                }
                // Stream ended (either clean EOF or an error broke us
                // out above). Brief sleep + reopen — clean EOF likely
                // means x0xd terminated the SSE; if we hammer reopen,
                // x0xd treats us as a buggy client.
                if stream_ok {
                    log::info!("sse reachability recorder: stream ended cleanly; reopening");
                    tokio::time::sleep(MIN_BACKOFF).await;
                } else {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }))
    }

    /// Open the unified SSE event stream from x0xd — presence,
    /// contacts, group state, gossip. Direct messages do not flow here
    /// in the relay-routed deployment; subscribe to the relay's
    /// inbound via [`Client::take_transport_inbound`] for those.
    pub async fn events(
        &self,
    ) -> Result<EventStream<impl futures_util::Stream<Item = Result<Event>>>> {
        open_stream(&self.http, "/events").await
    }

    /// Open the DM-only SSE event stream from x0xd. Kept for API
    /// parity; should not see traffic when chat is relay-routed.
    pub async fn direct_events(
        &self,
    ) -> Result<EventStream<impl futures_util::Stream<Item = Result<Event>>>> {
        open_stream(&self.http, "/direct/events").await
    }

    /// Open the presence-only SSE event stream.
    pub async fn presence_events(
        &self,
    ) -> Result<EventStream<impl futures_util::Stream<Item = Result<Event>>>> {
        open_stream(&self.http, "/presence/events").await
    }

    /// Cheap reachability probe.
    pub async fn health(&self) -> Result<()> {
        let _: serde_json::Value = self.http.get_json("/health").await?;
        Ok(())
    }

    /// Subscribe to relay-level presence transitions for the listed
    /// agents.
    ///
    /// Returns `Ok(())` when no relay transport is wired — callers
    /// don't need to gate on relay availability.
    ///
    /// # Errors
    /// Returns [`ChatError::MessageTransport`] when the supervisor
    /// has shut down.
    pub fn watch_relay_presence(&self, agents: &[fetchit_relay_proto::AgentId]) -> Result<()> {
        let Some(relay) = self.relay.as_ref() else {
            return Ok(());
        };
        relay
            .relay_set()
            .watch_presence(agents)
            .map_err(|e| ChatError::MessageTransport(format!("watch_presence: {e}")))
    }

    /// Unsubscribe from relay-level presence for the listed agents.
    ///
    /// # Errors
    /// Returns [`ChatError::MessageTransport`] when the supervisor
    /// has shut down.
    pub fn unwatch_relay_presence(&self, agents: &[fetchit_relay_proto::AgentId]) -> Result<()> {
        let Some(relay) = self.relay.as_ref() else {
            return Ok(());
        };
        relay
            .relay_set()
            .unwatch_presence(agents)
            .map_err(|e| ChatError::MessageTransport(format!("unwatch_presence: {e}")))
    }

    /// Await the next relay-emitted `PresenceUpdate`. Returns `None`
    /// if no relay transport is wired or the supervisor has shut down.
    pub async fn next_relay_presence(&self) -> Option<fetchit_relay_proto::PresenceUpdate> {
        let relay = self.relay.as_ref()?;
        relay.relay_set().next_presence().await
    }

    /// Watch the relay connection state. Returns `None` when no relay
    /// transport is wired (REST-only / LAN-only deployments). The
    /// desktop bridge subscribes to this so the UI can surface a
    /// `PermanentlyDisconnected` toast + retry affordance when the
    /// supervisor gives up.
    #[must_use]
    pub fn relay_connection_state(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<fetchit_relay_client::ConnState>> {
        let relay = self.relay.as_ref()?;
        Some(relay.relay_set().primary_connection_state())
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Client");
        s.field("transports", &self.router.len());
        if let Some(chat) = self.chat.as_ref() {
            s.field("agent_id", &chat.identity.agent_id_hex());
        }
        s.finish_non_exhaustive()
    }
}

/// Probe x0xd's `/version` endpoint and refuse to proceed when the
/// daemon is older than [`X0xdVersion::M2_TREEKEM_MIN`].
///
/// Transport failures surface as
/// [`ChatError::MessageTransport`]; an outdated daemon surfaces as
/// [`ChatError::Invalid`] with a message that names both the live
/// version and the upgrade target.
/// M3 D7 inbound denylist gate. Lifted out of
/// [`Client::default_dispatch_one`] so it can be unit-tested without
/// standing up a full [`Client`] (which would require an x0xd
/// version probe, a relay handshake, and a populated chat vault).
///
/// Returns `true` when the consumer is wired AND the envelope's
/// signed `sender_agent_id` hashes to a 64-hex value currently on
/// the denylist. `false` when the consumer is absent (ungated), the
/// sender is allowed, or the consumer hasn't refreshed yet (the
/// snapshot fails open — see [`crate::denylist::DenylistCheck`]).
async fn should_drop_inbound_from_denylisted(
    denylist: Option<&Arc<dyn crate::denylist::DenylistCheck>>,
    transit: &fetchit_relay_proto::TransitEnvelope,
) -> bool {
    let Some(denylist) = denylist else {
        return false;
    };
    let sender_hex = hex::encode(transit.sender_agent_id.as_bytes());
    denylist.is_blocked(&sender_hex).await
}

/// Seed the initial `advertised_relays` slot for a freshly-built
/// [`Client`].
///
/// M3 Phase E1 contract:
/// - `explicit = Some(list)` is validated by
///   [`crate::card::RendezvousHintsV1::from_value`] and used as-is.
///   Empty / non-`wss://` / oversize lists surface as
///   [`ChatError::Invalid`].
/// - `explicit = None` falls back to `[primary_relay_url]` when the
///   single-entry candidate validates through the same
///   `RendezvousHintsV1::from_value` path. Threading the fallback
///   through the same validator keeps the explicit-vs-fallback
///   contract aligned — a future tightening of the per-entry cap or
///   scheme rule cannot silently desync the two branches.
/// - All other cases return an empty `Vec` and the v2 hints field
///   is omitted from the card until
///   [`Client::regenerate_card_with_relays`] populates the slot.
fn seed_initial_advertised_relays(
    explicit: Option<Vec<String>>,
    primary_relay_url: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(list) = explicit {
        let _ = crate::card::RendezvousHintsV1::from_value(&serde_json::json!({"relays": list}))?;
        return Ok(list);
    }
    if let Some(url) = primary_relay_url {
        let candidate = vec![url.to_owned()];
        if crate::card::RendezvousHintsV1::from_value(&serde_json::json!({"relays": candidate}))
            .is_ok()
        {
            return Ok(candidate);
        }
    }
    Ok(Vec::new())
}

/// Best-effort announce of this agent's `agent_id -> public_key`
/// binding to x0xd's gossip identity store via `POST /announce`.
/// Runs once at chat-flow startup so any subsequent
/// `groups::create_private` user-flow can pass the MLS
/// `MemberJoined` signature-verify path. A failure here is logged
/// and swallowed: DM and inbound group-receive surfaces stay
/// functional, and the next process startup gets another chance.
async fn announce_identity_best_effort(http: &Http) {
    let base = match url::Url::parse(&http.base_url()) {
        Ok(u) => u,
        Err(e) => {
            log::warn!("identity/announce: invalid x0xd base url: {e}");
            return;
        }
    };
    let endpoint = match x0xd_client::IdentityEndpoint::new(base, http.token().to_owned()) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("identity/announce: endpoint setup failed: {e}");
            return;
        }
    };
    if let Err(e) = endpoint.announce(false, false).await {
        log::warn!(
            "identity/announce: failed (private-group MemberJoined verifies may fail until next chat startup): {e}"
        );
    }
}

async fn enforce_m2_treekem_minimum(base_url: &str, token: &str) -> Result<()> {
    let parsed_base =
        Url::parse(base_url).map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
    let version = X0xdVersion::probe(&parsed_base, token)
        .await
        .map_err(|e| ChatError::MessageTransport(format!("x0xd /version probe: {e}")))?;
    if !version.satisfies_m2_treekem() {
        return Err(ChatError::Invalid(format!(
            "x0xd {}.{}.{} does not support PQ TreeKEM groups; upgrade to >= {}.{}.{}",
            version.major,
            version.minor,
            version.patch,
            X0xdVersion::M2_TREEKEM_MIN.major,
            X0xdVersion::M2_TREEKEM_MIN.minor,
            X0xdVersion::M2_TREEKEM_MIN.patch,
        )));
    }
    Ok(())
}

/// Wire chat state, signer, and transports against a reachable x0xd.
///
/// Only runs in the chat-needing build path (`needs_chat` true in
/// [`Client::from_parts`]); REST-only clients skip this entirely.
///
/// Gates on `x0xd >= 0.20.1` before doing any chat work: v0.20.0
/// over-included `TreeKEM` activation; v0.20.1 narrowed it correctly to
/// `private_secure` + `Hidden`. The probe fires here (after the HTTP
/// wrapper is built, so transport errors stay as transport errors)
/// but before `/agent` or any chat state, so an outdated daemon fails
/// fast with a typed error that names the upgrade target.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::too_many_lines
)]
async fn build_with_chat(
    http: &Http,
    base_url: &str,
    token: String,
    relay_url: Option<Url>,
    data_dir: Option<PathBuf>,
    passphrase: Option<String>,
    enable_lan_direct: bool,
    contact_pubkey_lookup: Option<ContactPubkeyLookup>,
    x0xd_port_file: Option<PathBuf>,
) -> Result<(
    Router,
    Option<ChatState>,
    Option<Arc<RelayTransport>>,
    Option<Arc<LanDirectTransport>>,
    Option<std::net::SocketAddr>,
    Option<Arc<std::sync::Mutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>>>,
    // M3 R-tail-5: slot-0 primary URL string the caller passed (already
    // pinned inside `MultiHomeTransport`). Send-path fallback synthesizes
    // this into a `RendezvousHintsV1` when the recipient's stored card
    // has no v2 hints slot.
    Option<String>,
)> {
    // Gate on x0xd >= 0.20.1 (PQ `TreeKEM` minimum) before any
    // chat-side work so an outdated daemon never gets a chance to
    // mis-handle a `private_secure` group.
    enforce_m2_treekem_minimum(base_url, &token).await?;

    // Resolve the local agent identity from x0xd. The chat identity
    // vault is bound to this agent_id — rotating the x0xd identity
    // forces a fresh KEM keypair.
    let agent_identity: identity::AgentIdentity = http.get_json("/agent").await?;
    let agent_id_hex = agent_identity.agent_id.0.clone();
    let local_machine_id = derive_machine_id(&agent_identity.machine_id);

    let data_dir = match data_dir {
        Some(p) => p,
        None => crate::local_store::default_data_dir()?,
    };
    let layout = StoreLayout::ensure(data_dir)?;

    let identity_vault_path = layout.root.join(IDENTITY_VAULT_FILE);
    let (master, kdf_id, argon_salt) =
        resolve_master_key(identity_vault_path.as_path(), passphrase.as_deref())?;
    let master = Arc::new(master);

    let identity = Arc::new(FetchitIdentity::load_or_create(
        &layout.root,
        &master,
        &agent_id_hex,
        kdf_id,
        argon_salt.as_ref(),
    )?);

    let registry = Arc::new(ConversationRegistry::new(
        layout.clone(),
        master.clone(),
        kdf_id,
        argon_salt,
    ));

    // One signer, shared between the chat-state path and the relay
    // transport: each `X0xdSigner` opens its own warmup round-trip and
    // every `sign` call hits `/agent/sign`, so cloning the Arc keeps a
    // single WebSocket-paired x0xd identity instead of doubling sessions.
    //
    // When the caller supplied a `port_file` path
    // ([`ClientBuilder::x0xd_port_file`]), the signer self-heals across
    // x0xd restarts: a connect-refused error during signing triggers a
    // re-read of `api.port` and a one-shot retry against the new URL,
    // so long-running consumers (chat-peer, desktop app) survive a
    // daemon restart without going through their own restart cycle.
    let x0xd_signer = Arc::new(if let Some(path) = x0xd_port_file {
        X0xdSigner::connect_with_port_file(path, token)
            .await
            .map_err(|e| ChatError::MessageTransport(format!("x0xd signer (port-file): {e}")))?
    } else {
        X0xdSigner::connect(
            Url::parse(base_url).map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?,
            token,
        )
        .await
        .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?
    });
    let signer: Arc<dyn Signer> = x0xd_signer.clone();

    let mut router = Router::new();
    let mut lan_handle: Option<Arc<LanDirectTransport>> = None;
    let mut lan_bound_addr: Option<std::net::SocketAddr> = None;

    // LAN-direct is registered FIRST so `IfReachable` wins over the
    // relay's `Always` whenever the peer is co-resident on the LAN.
    if enable_lan_direct {
        let lan_static = Arc::new(LanStaticIdentity::load_or_create(
            &layout.root,
            master.as_ref(),
            &agent_id_hex,
            kdf_id,
            argon_salt.as_ref(),
        )?);
        let table = Arc::new(LanPeerTable::new());
        let lookup: ContactPubkeyLookup = contact_pubkey_lookup.unwrap_or_else(|| {
            let registry_for_lookup = registry.clone();
            Arc::new(move |aid: &identity::AgentId| registry_for_lookup.peer_ml_dsa_pubkey(aid))
        });
        let local_aid = identity::AgentId(agent_id_hex.clone());
        let bind =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let (lan_transport, bound) = LanDirectTransport::start(
            local_aid,
            lan_static,
            signer.clone(),
            table.clone(),
            lookup,
            bind,
        )
        .await?;
        // The desktop layer reads `lan_bound_addr()` + `lan_transport_arc()
        // -> peer_table()` to spawn mDNS announce + browse against the
        // host's tokio runtime. The LanPeerTable's contents flow back
        // into the transport's reachability gate.
        lan_handle = Some(lan_transport.clone());
        lan_bound_addr = Some(bound);
        router.add(lan_transport);
    }

    // M3 R-tail-4: the bare `RelayTransport` is no longer registered
    // directly on the Router — it lives inside slot 0 of
    // `MultiHomeTransport`, which is what the Router sees. The
    // `relay_handle` slot is still populated (from slot 0 of MH) so the
    // presence-watch capabilities on `Client.relay` keep working.
    let mut relay_handle: Option<Arc<RelayTransport>> = None;
    let mut mh_inbound_slot: Option<
        Arc<std::sync::Mutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>>,
    > = None;
    let mut primary_relay_url_str: Option<String> = None;
    if let Some(url) = relay_url {
        // The denylist gate inside `MultiHomeTransport` is `DenylistQuery`
        // (read-side trait). Until R-tail-4.x splits `DenylistCheck`'s
        // query half into a free-standing `DenylistQuery` impl, MH ships
        // with a no-op gate; the existing `Client.denylist` field still
        // gates the chat-layer surfaces (send + dispatch) end-to-end.
        // BlockEvent reactivity (D6) is similarly wired via
        // `Client::install_m3_denylist`'s consumer subscriber — out of
        // scope here. When that lands, swap the `None` below for the
        // consumer's `BlockEvent` broadcast receiver.
        struct NoopDenylistQuery;
        impl fetchit_trust::DenylistQuery for NoopDenylistQuery {
            fn is_blocked(&self, _: fetchit_trust::EntryKind, _: &str) -> bool {
                false
            }
        }
        let mh_denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylistQuery);

        // Inbound seam: every envelope MH fans in lands on this mpsc.
        // `Client::take_transport_inbound("relay"|"multi-home")` drains
        // it; that's what the existing dispatch path (`peer.rs`,
        // `desktop/src-tauri/src/chat.rs`, `spawn_default_dispatcher`)
        // hangs off of.
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundEnvelope>();
        let on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync> = {
            let tx = inbound_tx.clone();
            Arc::new(move |env: InboundEnvelope| {
                let _ = tx.send(env);
            })
        };

        let builder: Arc<dyn crate::transport::RelayBuilder> =
            Arc::new(crate::transport::RealRelayBuilder::new(x0xd_signer.clone()));

        let url_str = url.to_string();
        primary_relay_url_str = Some(url_str.clone());
        let mh = crate::transport::MultiHomeTransport::new_with_subscriber(
            url_str,
            mh_denylist,
            on_inbound,
            builder,
            None,
        )
        .await
        .map_err(|e| ChatError::MessageTransport(format!("multi-home boot: {e}")))?;
        let mh = Arc::new(mh);

        // Slot 0 is the pinned primary. Surface its inner
        // `RelayTransport` so `Client.relay` keeps working for
        // presence-watch and connection-state subscribers.
        relay_handle = mh.slot_zero_handle().and_then(|h| h.relay_transport_arc());

        mh_inbound_slot = Some(Arc::new(std::sync::Mutex::new(Some(inbound_rx))));

        router.add(mh as Arc<dyn crate::transport::Transport>);
    }

    Ok((
        router,
        Some(ChatState {
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
            reachability: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::ReachabilityCache::new(),
            )),
            bridge_consent: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeConsentStore::new(),
            )),
            bridge_inbound_shadow: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeInboundShadow::new(),
            )),
            members_singleflight: Arc::new(crate::members_singleflight::MembersSingleflight::new()),
        }),
        relay_handle,
        lan_handle,
        lan_bound_addr,
        mh_inbound_slot,
        primary_relay_url_str,
    ))
}

/// Derive a 32-byte machine fingerprint from the x0xd-supplied machine
/// id string. Returns `[0u8; 32]` when the value is empty so legacy
/// callsites are preserved.
fn derive_machine_id(machine_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    if machine_id.is_empty() {
        return [0u8; 32];
    }
    let mut h = Sha256::new();
    h.update(b"fetchit-chat/v1/machine-id\0");
    h.update(machine_id.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Spawn the background task that walks the conversation registry
/// every [`AUTO_REKEY_SWEEP_INTERVAL`] and rotates every Admin
/// conversation whose `auto_rekey_due()` is true.
///
/// The first tick is consumed immediately so the sweep does not run
/// the instant the client starts.
fn spawn_auto_rekey_sweeper(
    router: &Arc<Router>,
    chat: &ChatState,
    primary_relay_url: Option<String>,
) {
    let registry = chat.registry.clone();
    let identity = chat.identity.clone();
    let signer = chat.signer.clone();
    let router = router.clone();
    let machine_id = chat.local_machine_id;
    let layout = chat.layout.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(AUTO_REKEY_SWEEP_INTERVAL);
        // First tick fires immediately; skip so we don't rotate on
        // launch.
        tick.tick().await;
        loop {
            tick.tick().await;
            match sweep_auto_rekey(
                &registry,
                &identity,
                &router,
                machine_id,
                &signer,
                &layout,
                primary_relay_url.as_deref(),
            )
            .await
            {
                Ok(n) if n > 0 => log::info!("[chat] auto-rekey: rotated {n} conversations"),
                Ok(_) => {}
                Err(e) => log::warn!("[chat] auto-rekey sweep error: {e}"),
            }
        }
    });
}

/// Try to rotate one conversation's epoch and build the welcomes that
/// announce the new key to peers. Pure read-then-commit shape:
///
/// 1. Generate a fresh symmetric key.
/// 2. Build the would-be post-advance conversation in memory only.
/// 3. Call `build_welcome_outbox` against that prospective state. If
///    it fails (signer/x0xd offline, KEM-encap, AEAD seal, recipient
///    hex parse), we drop the prospective state on the floor and the
///    next sweep tick retries — the registry's on-disk + cached state
///    is unchanged.
/// 4. Only after welcomes are known good, commit the advance via
///    `mutate_in_place`. Re-check `auto_rekey_due` AND
///    `current_epoch == snapshot_epoch` inside the lock so a
///    peer-driven rekey landing between snapshot and commit can
///    preempt; the welcomes we built are for the (now-stale)
///    prospective epoch and would be rejected by peers, so we drop
///    them.
///
/// Returns:
/// * `Ok(Some(welcomes))` — committed, caller should fanout-send the
///   welcomes.
/// * `Ok(None)` — skipped (build failed, or peer-driven rekey
///   preempted, or no longer `auto_rekey_due`). Local state unchanged.
/// * `Err(_)` — persistence-layer failure (vault open, AEAD seal,
///   serde error). Caller should propagate; the next sweep retries.
///
/// Pulled out of `sweep_auto_rekey` so test code can drive the
/// build-then-commit invariant directly with a stub `Signer` —
/// without that test, the d5886a8 round-4 fix had zero coverage and
/// a future refactor reordering advance-before-build would silently
/// brick the conversation again.
async fn try_rekey_and_build_welcomes(
    registry: &ConversationRegistry,
    snapshot: &Conversation,
    identity: &FetchitIdentity,
    machine_id: [u8; 32],
    signer: &dyn Signer,
) -> Result<Option<Vec<crate::conversation::OutboundEnvelope>>> {
    use crate::chat_crypto::random_symmetric_key;
    use rand::rngs::OsRng;

    let group_id_hex = snapshot.group_id_hex.clone();
    let snapshot_epoch = snapshot.current_epoch;

    let new_key = random_symmetric_key(&mut OsRng);
    let mut prospective = snapshot.clone();
    prospective.advance_epoch(new_key);
    let welcomes = match build_welcome_outbox(&prospective, identity, machine_id, signer).await {
        Ok(w) => w,
        Err(e) => {
            log::warn!(
                    "[chat] auto-rekey: build welcomes for {group_id_hex} failed: {e}; will retry next sweep",
                );
            return Ok(None);
        }
    };

    let committed = registry
        .mutate_in_place(&group_id_hex, |conv| {
            if !conv.auto_rekey_due() || conv.current_epoch != snapshot_epoch {
                return MutateAction::Skip(false);
            }
            conv.advance_epoch(new_key);
            MutateAction::Persist(true)
        })
        .await?;
    if !committed {
        return Ok(None);
    }
    Ok(Some(welcomes))
}

/// Walk the in-memory conversation cache, rotating every Admin
/// conversation whose `auto_rekey_due()` returns true. Returns the
/// count of rotated conversations.
///
/// Individual transport-send failures are logged but do not abort the
/// sweep — a single unreachable recipient must not block the rest.
/// Persistence failures (`registry.save`) propagate.
async fn sweep_auto_rekey(
    registry: &Arc<ConversationRegistry>,
    identity: &Arc<FetchitIdentity>,
    router: &Arc<Router>,
    machine_id: [u8; 32],
    signer: &Arc<dyn Signer>,
    layout: &StoreLayout,
    primary_relay_url: Option<&str>,
) -> Result<usize> {
    let cached = registry.snapshot_cached().await;
    let mut rekeyed = 0usize;
    for snapshot in cached {
        if !snapshot.auto_rekey_due() {
            continue;
        }
        let Some(welcomes) = try_rekey_and_build_welcomes(
            registry,
            &snapshot,
            identity,
            machine_id,
            signer.as_ref(),
        )
        .await?
        else {
            continue;
        };
        for ob in welcomes {
            let recipient = identity::AgentId(hex::encode(ob.recipient_agent_id.as_bytes()));
            let timestamp_ms = ob.envelope.timestamp_ms;
            let transport_out = OutboundEnvelope {
                kind: OutboundKind::Dm,
                from_machine_id: Some(machine_id),
                payload: Vec::new(),
                timestamp_ms,
                transit: Some(ob.envelope),
            };
            // M3 R-tail-5: thread per-recipient hints — auto-rekey
            // welcomes are exactly the kind of relay traffic
            // multi-home wants to route via the contact's primary
            // slot. Legacy v1 contacts fall back to our own primary.
            let hints =
                crate::messages::StoredContactCard::resolve_recipient_hints(layout, &recipient.0)
                    .ok()
                    .flatten()
                    .or_else(|| {
                        primary_relay_url.map(|url| crate::card::RendezvousHintsV1 {
                            relays: vec![url.to_owned()],
                        })
                    });
            if let Err(e) = router.send(&recipient, transport_out, hints.as_ref()).await {
                log::warn!(
                    "[chat] auto-rekey: send to {} failed: {e}",
                    recipient.short()
                );
            }
        }
        rekeyed += 1;
    }
    Ok(rekeyed)
}

impl Client {
    /// Mint a fresh fediverse-bridge actor identity for this user's
    /// chat identity. Generates an RSA-2048 keypair, signs the
    /// ML-DSA-65 attestation over the canonical
    /// [`fetchit_fedi::attestation::signing_input`] bytes, and
    /// persists everything to the encrypted fedi vault at
    /// `<layout.root>/fedi/<handle>.json.enc`.
    ///
    /// `domain` is the fediverse host that will publish the actor's
    /// `WebFinger` record (currently fetchit-operated: `etchit.io`).
    /// `actor_url` is constructed as `https://<domain>/actors/<handle>`.
    ///
    /// `passphrase` mirrors the rest of the chat surface — `None` uses
    /// the OS keychain entry, `Some` derives via Argon2id with the
    /// existing identity vault's salt.
    ///
    /// # Errors
    ///
    /// - [`ChatError::Invalid`] when chat state has not been initialised.
    /// - [`ChatError::Invalid`] when `handle` fails validation (empty,
    ///   more than 64 chars, or chars outside `[A-Za-z0-9_-]`). This
    ///   also gates path-traversal: handles are formatted into a file
    ///   path under `fedi_dir`, and the validator forbids `.` and `/`.
    /// - Propagates RSA keygen, attestation signing, master-key
    ///   resolution, and vault-write failures verbatim.
    pub async fn mint_actor_identity(
        &self,
        handle: &str,
        domain: &str,
        passphrase: Option<&str>,
    ) -> Result<fetchit_fedi::actor::ActorIdentity> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;

        validate_actor_handle(handle)?;
        let actor_url = build_actor_url(domain, handle)?;
        let agent_id_hex = chat.identity.agent_id_hex().to_string();

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) = resolve_master_key(&identity_vault_path, passphrase)?;

        if chat.layout.actor_identity_path(handle).exists() {
            log::warn!(
                "[chat] mint_actor_identity called on handle {handle:?} which already has a \
                 persisted vault; the prior vault will be overwritten. Consider \
                 load_actor_identity instead."
            );
        }

        let material = crate::fedi_identity::generate_rsa_2048().await?;
        let attestation = crate::fedi_identity::sign_actor_attestation(
            handle,
            &actor_url,
            &agent_id_hex,
            &material.spki_der,
            chat.signer.as_ref(),
        )
        .await?;

        let vault = crate::fedi_vault::ActorIdentityVault {
            handle: handle.to_string(),
            actor_url: actor_url.clone(),
            agent_id_hex: agent_id_hex.clone(),
            rsa_priv_pem: material.priv_pem.clone(),
            spki_der: material.spki_der.clone(),
            ml_dsa_attestation: attestation.clone(),
        };
        crate::fedi_vault::save_actor_identity(&vault, &master, &chat.layout)?;

        Ok(fetchit_fedi::actor::ActorIdentity::new(
            handle.to_string(),
            actor_url,
            agent_id_hex,
            material.priv_pem,
            material.spki_der,
            attestation,
        ))
    }

    /// Load a previously-minted [`fetchit_fedi::actor::ActorIdentity`]
    /// from the fedi vault. Returns `Ok(None)` when no vault file
    /// exists for the handle (the caller's "first run / not yet
    /// minted" path).
    ///
    /// `passphrase` semantics mirror [`Self::mint_actor_identity`].
    ///
    /// # Errors
    ///
    /// - [`ChatError::Invalid`] when chat state has not been initialised.
    /// - [`ChatError::Invalid`] when `handle` fails validation.
    /// - Propagates master-key resolution and vault-decrypt failures
    ///   (tampered ciphertext, wrong master, parse).
    #[allow(clippy::unused_async)]
    pub async fn load_actor_identity(
        &self,
        handle: &str,
        passphrase: Option<&str>,
    ) -> Result<Option<fetchit_fedi::actor::ActorIdentity>> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        validate_actor_handle(handle)?;

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) = resolve_master_key(&identity_vault_path, passphrase)?;

        let Some(vault) = crate::fedi_vault::load_actor_identity(handle, &master, &chat.layout)?
        else {
            return Ok(None);
        };
        Ok(Some(fetchit_fedi::actor::ActorIdentity::from_persisted(
            vault.handle,
            vault.rsa_priv_pem,
            vault.spki_der,
            vault.ml_dsa_attestation,
            vault.actor_url,
            vault.agent_id_hex,
        )))
    }
}

fn build_actor_url(domain: &str, handle: &str) -> Result<url::Url> {
    // TODO(M5): domain becomes user-configurable. Add a domain-shape
    // validator (similar to validate_actor_handle) before
    // multi-tenant launch. M4 only ships with `etchit.io`, so
    // url::Url::parse failure is sufficient.
    let raw = format!("https://{domain}/actors/{handle}");
    raw.parse()
        .map_err(|e| ChatError::Invalid(format!("actor url {raw:?}: {e}")))
}

/// Sanity-check an actor handle before it is used as a path component
/// or sent to the registry. Real ownership verification happens at
/// Stage 6.2 (the `WebFinger` registration API); this is a local
/// pre-claim guard.
///
/// Rejects empty handles, handles longer than 64 chars, or any
/// character outside `[A-Za-z0-9_-]`. The character allowlist forbids
/// `.` and `/` so a malicious handle cannot traverse out of `fedi_dir`
/// via [`crate::local_store::StoreLayout::actor_identity_path`].
fn validate_actor_handle(handle: &str) -> Result<()> {
    if handle.is_empty() {
        return Err(ChatError::Invalid("actor handle must be non-empty".into()));
    }
    if handle.len() > 64 {
        return Err(ChatError::Invalid(format!(
            "actor handle exceeds 64 chars (got {})",
            handle.len()
        )));
    }
    for b in handle.bytes() {
        if !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-') {
            return Err(ChatError::Invalid(format!(
                "actor handle contains invalid char {:?}; allowed: [A-Za-z0-9_-]",
                b as char
            )));
        }
    }
    Ok(())
}

fn resolve_master_key(
    identity_vault_path: &std::path::Path,
    passphrase: Option<&str>,
) -> Result<(MasterKey, u8, Option<[u8; ARGON_SALT_LEN]>)> {
    if identity_vault_path.exists() {
        // Existing vault wins — honour whichever KDF was used at
        // first-launch so we don't lock the user out by changing modes.
        let kdf_id = read_kdf_id(identity_vault_path)?;
        if kdf_id == kdf_id_argon2() {
            let salt = read_argon_salt(identity_vault_path)?;
            let pass = passphrase.ok_or_else(|| {
                ChatError::Invalid("vault is passphrase-mode but no passphrase was supplied".into())
            })?;
            let master = MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new(pass.to_owned())),
                Some(&salt),
            )?;
            Ok((master, kdf_id, Some(salt)))
        } else {
            let master = MasterKey::resolve(&MasterKeySource::Keychain, None)?;
            Ok((master, kdf_id, None))
        }
    } else if let Some(pass) = passphrase {
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new(pass.to_owned())),
            Some(&salt),
        )?;
        Ok((master, kdf_id_argon2(), Some(salt)))
    } else {
        let master = MasterKey::resolve(&MasterKeySource::Keychain, None)?;
        Ok((master, kdf_id_keychain(), None))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
    use crate::conversation::{Member, MemberDevice, MemberDeviceStatus};
    use crate::local_store::StoreLayout;
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD as B64;
    use fetchit_relay_client::{MlDsaSigner, Signer};
    use tempfile::TempDir;

    /// Signer stub whose `sign` always returns Err — simulates a
    /// transient x0xd `/agent/sign` outage so we can exercise the
    /// build-failure-preserves-epoch invariant inside
    /// `try_rekey_and_build_welcomes`.
    struct ErrSigner {
        pubkey: Vec<u8>,
        aid: [u8; 32],
    }

    #[async_trait]
    impl Signer for ErrSigner {
        fn agent_id(&self) -> [u8; 32] {
            self.aid
        }
        fn public_key(&self) -> Vec<u8> {
            self.pubkey.clone()
        }
        async fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Err("test: signer offline".to_owned())
        }
    }

    /// Build a minimal `(registry, identity, conv)` fixture for a DM
    /// between two fresh ML-DSA identities. The conv is set up with
    /// `auto_rekey_interval_ms = 1` so `auto_rekey_due()` returns true
    /// without any wall-clock manipulation.
    async fn fixture_rekey_due_conv() -> (
        TempDir,
        ErrSigner,
        FetchitIdentity,
        Arc<ConversationRegistry>,
        Conversation,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".to_owned())),
                Some(&salt),
            )
            .unwrap(),
        );

        let alice_signer = MlDsaSigner::generate().unwrap();
        let aid_a = hex::encode(alice_signer.agent_id());
        let identity = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            &aid_a,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();

        // ErrSigner replaces alice_signer for the actual sweep call so
        // the build always fails; pubkey/agent_id must still match the
        // identity for `build_welcome_outbox` to accept us as a member.
        let err_signer = ErrSigner {
            pubkey: alice_signer.public_key(),
            aid: alice_signer.agent_id(),
        };

        let bob_signer = MlDsaSigner::generate().unwrap();
        let aid_b = hex::encode(bob_signer.agent_id());

        let alice_member = Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: aid_a.clone(),
                kem_public_key_b64: B64.encode(identity.kem_public_key()),
                agent_public_key_b64: Some(B64.encode(alice_signer.public_key())),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let bob_member = Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: aid_b,
                kem_public_key_b64: B64.encode(vec![0u8; 1184]),
                agent_public_key_b64: Some(B64.encode(bob_signer.public_key())),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let mut conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        // Trip auto_rekey_due immediately — interval=1ms is well below
        // any clock skew the test runner can produce.
        conv.auto_rekey_interval_ms = 1;

        let registry = Arc::new(ConversationRegistry::new(
            layout,
            master,
            kdf_id_argon2(),
            Some(salt),
        ));
        registry.save(&conv).await.unwrap();

        // Refresh the snapshot from disk so the auto_rekey_due check
        // observes a `last_rekey_at_ms` that's at least 1ms in the
        // past relative to `now_ms()`.
        tokio::time::sleep(Duration::from_millis(3)).await;

        (dir, err_signer, identity, registry, conv)
    }

    /// Build a fixture with a real ML-KEM peer key so
    /// `build_welcome_outbox` can succeed end-to-end. Used by the
    /// successful-rekey and peer-preemption tests.
    async fn fixture_real_peer_conv() -> (
        TempDir,
        MlDsaSigner,
        FetchitIdentity,
        Arc<ConversationRegistry>,
        Conversation,
    ) {
        use crate::chat_crypto::kem_keygen;

        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("p".to_owned())),
                Some(&salt),
            )
            .unwrap(),
        );

        let alice_signer = MlDsaSigner::generate().unwrap();
        let aid_a = hex::encode(alice_signer.agent_id());
        let identity = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            &aid_a,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();

        let bob_signer = MlDsaSigner::generate().unwrap();
        let aid_b = hex::encode(bob_signer.agent_id());
        let (bob_kem_pub, _bob_kem_sec) = kem_keygen().unwrap();

        let alice_member = Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: aid_a.clone(),
                kem_public_key_b64: B64.encode(identity.kem_public_key()),
                agent_public_key_b64: Some(B64.encode(alice_signer.public_key())),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let bob_member = Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: aid_b,
                kem_public_key_b64: B64.encode(&bob_kem_pub),
                agent_public_key_b64: Some(B64.encode(bob_signer.public_key())),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let mut conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        conv.auto_rekey_interval_ms = 1;

        let registry = Arc::new(ConversationRegistry::new(
            layout,
            master,
            kdf_id_argon2(),
            Some(salt),
        ));
        registry.save(&conv).await.unwrap();
        tokio::time::sleep(Duration::from_millis(3)).await;
        (dir, alice_signer, identity, registry, conv)
    }

    /// Round-6 P2: successful rekey advances epoch by exactly 1,
    /// pushes the old key into `prior_keys`, and produces welcomes
    /// for each peer device.
    #[tokio::test]
    async fn try_rekey_and_build_welcomes_advances_and_pushes_prior_key() {
        let (_dir, signer, identity, registry, conv_before) = fixture_real_peer_conv().await;
        let prior_keys_before = conv_before.prior_keys.len();
        let key_before = conv_before.current_key_b64.clone();
        let epoch_before = conv_before.current_epoch;

        let result = try_rekey_and_build_welcomes(
            registry.as_ref(),
            &conv_before,
            &identity,
            [0u8; 32],
            &signer,
        )
        .await
        .expect("helper must not error on the happy path");
        let welcomes = result.expect("happy path must commit and return welcomes");
        assert!(
            !welcomes.is_empty(),
            "welcomes must include the peer's device",
        );

        let conv_after = registry
            .get(&conv_before.group_id_hex)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            conv_after.current_epoch,
            epoch_before + 1,
            "current_epoch must advance by exactly 1",
        );
        assert_ne!(
            conv_after.current_key_b64, key_before,
            "current_key_b64 must change to a fresh symmetric key",
        );
        assert_eq!(
            conv_after.prior_keys.len(),
            prior_keys_before + 1,
            "exactly one prior_keys entry must be pushed",
        );
        assert_eq!(
            conv_after.prior_keys.last().unwrap().key_b64,
            key_before,
            "the pushed prior key must be the pre-advance current key",
        );
        assert_eq!(
            conv_after.prior_keys.last().unwrap().epoch,
            epoch_before,
            "the pushed prior key must carry the pre-advance epoch tag",
        );
    }

    /// Round-6 P2: a peer-driven rekey that lands between our
    /// snapshot read and our commit must preempt. We simulate this by
    /// running the helper once successfully, then calling it again
    /// with the original (now-stale) snapshot — the second call's
    /// closure observes `current_epoch != snapshot_epoch` and returns
    /// Skip(false), so the welcomes built against the stale
    /// prospective state are dropped.
    #[tokio::test]
    async fn try_rekey_and_build_welcomes_skips_when_peer_preempts() {
        let (_dir, signer, identity, registry, snapshot) = fixture_real_peer_conv().await;
        let _first = try_rekey_and_build_welcomes(
            registry.as_ref(),
            &snapshot,
            &identity,
            [0u8; 32],
            &signer,
        )
        .await
        .expect("first call must succeed");

        let epoch_after_first = registry
            .get(&snapshot.group_id_hex)
            .await
            .unwrap()
            .unwrap()
            .current_epoch;
        assert_eq!(epoch_after_first, snapshot.current_epoch + 1);

        // Second call replays the stale snapshot, simulating a sweep
        // tick that started before a peer/local rekey landed. The
        // re-check in the helper's closure must catch the epoch drift.
        let second = try_rekey_and_build_welcomes(
            registry.as_ref(),
            &snapshot,
            &identity,
            [0u8; 32],
            &signer,
        )
        .await
        .expect("second call must not error");
        assert!(
            second.is_none(),
            "stale-snapshot replay must return Ok(None), got Some(_) (would have committed stale welcomes)",
        );
        let epoch_after_second = registry
            .get(&snapshot.group_id_hex)
            .await
            .unwrap()
            .unwrap()
            .current_epoch;
        assert_eq!(
            epoch_after_second, epoch_after_first,
            "preempted second call must NOT advance the epoch further",
        );
    }

    /// Regression: round-4 `d5886a8` re-ordered sweep to build-before-
    /// commit so a transient signer outage couldn't silently brick the
    /// conversation. Without this test, a future refactor reversing
    /// the order would slip past CI — the original round-3 bug only
    /// surfaced under live conditions.
    #[tokio::test]
    async fn try_rekey_and_build_welcomes_does_not_advance_on_signer_failure() {
        let (_dir, err_signer, identity, registry, conv_before) = fixture_rekey_due_conv().await;
        assert!(
            conv_before.auto_rekey_due(),
            "fixture must satisfy auto_rekey_due() to exercise the path",
        );

        let result = try_rekey_and_build_welcomes(
            registry.as_ref(),
            &conv_before,
            &identity,
            [0u8; 32],
            &err_signer,
        )
        .await
        .expect("sweep helper itself must not error on signer failure");
        assert!(
            result.is_none(),
            "signer-error must yield Ok(None), got Some(_) — the rekey was committed",
        );

        let conv_after = registry
            .get(&conv_before.group_id_hex)
            .await
            .unwrap()
            .expect("conv must still be on disk");
        assert_eq!(
            conv_after.current_epoch, conv_before.current_epoch,
            "current_epoch must NOT advance when build_welcome_outbox fails",
        );
        assert_eq!(
            conv_after.current_key_b64, conv_before.current_key_b64,
            "current_key_b64 must NOT change when build_welcome_outbox fails",
        );
        assert_eq!(
            conv_after.last_rekey_at_ms, conv_before.last_rekey_at_ms,
            "last_rekey_at_ms must NOT move when build_welcome_outbox fails",
        );
        assert!(
            conv_after.prior_keys.is_empty(),
            "no prior_keys entry should accumulate from a failed rekey",
        );
    }

    /// Builder gate: an x0xd that reports a pre-M2 version on
    /// `/health` is refused at chat-build time. The probe runs at the
    /// top of `build_with_chat`, so we never touch `/agent`, the
    /// signer, or any chat state — the wiremock only needs to answer
    /// `/health` with x0xd's standard shape (the `version` field is
    /// the load-bearing piece; the surrounding `status`/`peers`/
    /// `uptime_secs` fields are ignored by the probe but kept here
    /// so the fixture mirrors a real daemon response).
    #[tokio::test]
    async fn build_rejects_x0xd_below_m2_treekem_minimum() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "status": "healthy",
                "version": "0.19.53",
                "peers": 8,
                "uptime_secs": 1234,
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let err = Client::builder()
            .base_url(server.uri())
            .token("test-token")
            .data_dir(dir.path().to_path_buf())
            .passphrase("p".to_owned())
            .build()
            .await
            .expect_err("pre-M2 x0xd must fail the version gate");

        match err {
            ChatError::Invalid(msg) => {
                assert!(
                    msg.contains("does not support PQ TreeKEM"),
                    "expected TreeKEM gate message, got: {msg}"
                );
                assert!(
                    msg.contains("0.19.53"),
                    "expected daemon version in error, got: {msg}"
                );
                assert!(
                    msg.contains("0.20.1"),
                    "expected upgrade target in error, got: {msg}"
                );
            }
            other => panic!("expected ChatError::Invalid, got {other:?}"),
        }
    }

    // ── M4 actor identity helpers ─────────────────────────────────

    #[test]
    fn validate_actor_handle_accepts_valid_handles() {
        assert!(validate_actor_handle("josh").is_ok());
        assert!(validate_actor_handle("Alice_42").is_ok());
        assert!(validate_actor_handle("ab-c-d").is_ok());
        assert!(validate_actor_handle("x").is_ok());
        // Right at the 64-char cap.
        let max = "a".repeat(64);
        assert!(validate_actor_handle(&max).is_ok());
    }

    #[test]
    fn validate_actor_handle_rejects_empty() {
        let err = validate_actor_handle("").unwrap_err();
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn validate_actor_handle_rejects_too_long() {
        let too_long = "a".repeat(65);
        let err = validate_actor_handle(&too_long).unwrap_err();
        assert!(format!("{err}").contains("64"));
    }

    #[test]
    fn validate_actor_handle_rejects_path_separator() {
        // Both `.` and `/` are forbidden — path-traversal defense
        // when actor_identity_path joins the handle into fedi_dir.
        assert!(validate_actor_handle("../etc/passwd").is_err());
        assert!(validate_actor_handle("foo/bar").is_err());
        assert!(validate_actor_handle("foo.bar").is_err());
    }

    #[test]
    fn validate_actor_handle_rejects_whitespace_and_punctuation() {
        assert!(validate_actor_handle("hello world").is_err());
        assert!(validate_actor_handle("foo!").is_err());
        assert!(validate_actor_handle("a@b").is_err());
        assert!(validate_actor_handle("a$b").is_err());
    }

    #[test]
    fn build_actor_url_constructs_https_path() {
        let url = build_actor_url("etchit.io", "josh").unwrap();
        assert_eq!(url.as_str(), "https://etchit.io/actors/josh");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("etchit.io"));
        assert_eq!(url.path(), "/actors/josh");
    }

    #[test]
    fn build_actor_url_rejects_malformed_domain() {
        // A literal space breaks URL parsing.
        let err = build_actor_url("not a domain", "josh").unwrap_err();
        assert!(format!("{err}").contains("actor url"));
    }

    // ── M3 D7 inbound denylist gate ───────────────────────────────

    /// Build a minimal transit envelope whose `sender_agent_id` is
    /// the given 32-byte fingerprint. Every other field carries a
    /// stable default — the D7 gate only consults `sender_agent_id`,
    /// so the surrounding shape is fixture-only.
    fn d7_envelope(sender: [u8; 32]) -> fetchit_relay_proto::TransitEnvelope {
        use fetchit_relay_proto::{
            AgentId as RelayAgentId, EnvelopeKind, MachineId, TransitEnvelope, WIRE_VERSION,
        };
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: RelayAgentId::from_bytes(sender),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 0,
            ciphertext: vec![0u8; 16],
            nonce: vec![0u8; 12],
            kem_ciphertext: vec![0u8; 32],
            sender_signature: vec![0u8; 64],
        }
    }

    /// D7: with no denylist wired, every inbound is accepted — the
    /// gate is ungated by design (LAN-only deployments, M0 startup
    /// before the consumer's first refresh).
    #[tokio::test]
    async fn d7_should_drop_inbound_returns_false_when_denylist_absent() {
        let env = d7_envelope([0xaa; 32]);
        assert!(!super::should_drop_inbound_from_denylisted(None, &env).await);
    }

    /// D7 happy path: a denylisted sender's envelope returns `true`
    /// so the caller can silently drop + bump the counter.
    #[tokio::test]
    async fn d7_should_drop_inbound_returns_true_for_denylisted_sender() {
        let sender_bytes = [0xbb; 32];
        let blocked_hex = hex::encode(sender_bytes);
        let denylist: Arc<dyn crate::denylist::DenylistCheck> =
            Arc::new(crate::denylist::tests::StaticDenylist::new([blocked_hex]));
        let env = d7_envelope(sender_bytes);
        assert!(super::should_drop_inbound_from_denylisted(Some(&denylist), &env).await);
    }

    /// D7: an envelope from a non-blocked sender flows through even
    /// when the denylist is non-empty — the check is value-scoped,
    /// not kind-scoped (mirrors the D5 outbound symmetry test).
    #[tokio::test]
    async fn d7_should_drop_inbound_returns_false_for_allowed_sender() {
        let blocked_bytes = [0xcc; 32];
        let allowed_bytes = [0xdd; 32];
        let denylist: Arc<dyn crate::denylist::DenylistCheck> = Arc::new(
            crate::denylist::tests::StaticDenylist::new([hex::encode(blocked_bytes)]),
        );
        let env = d7_envelope(allowed_bytes);
        assert!(!super::should_drop_inbound_from_denylisted(Some(&denylist), &env).await);
    }

    /// D7: the gate keys on the lowercase 64-hex of the 32-byte
    /// fingerprint — exactly the format the published denylist
    /// emits. A consumer seeded with the canonical hex MUST match.
    #[tokio::test]
    async fn d7_should_drop_inbound_uses_lowercase_64_hex_key() {
        let sender_bytes = [0x10; 32];
        let canonical_hex = hex::encode(sender_bytes);
        assert_eq!(canonical_hex.len(), 64);
        assert!(canonical_hex
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        let denylist: Arc<dyn crate::denylist::DenylistCheck> =
            Arc::new(crate::denylist::tests::StaticDenylist::new([canonical_hex]));
        let env = d7_envelope(sender_bytes);
        assert!(super::should_drop_inbound_from_denylisted(Some(&denylist), &env).await);
    }

    // ── M3 D8 install boot wiring ────────────────────────────────

    /// Stub HTTP client whose `get` never returns: the install path
    /// constructs the consumer + spawns the poll loop but should NOT
    /// actually fire a refresh during the call itself (the poll
    /// loop's first tick fires the configured interval after spawn,
    /// not synchronously).
    ///
    /// Using a never-returning stub catches any future refactor that
    /// accidentally turns `install_m3_denylist` into a synchronous
    /// refresher — the test would hang instead of passing.
    struct PendingHttp;

    #[async_trait]
    impl fetchit_trust_client::HttpClient for PendingHttp {
        async fn get(
            &self,
            _url: &str,
        ) -> std::result::Result<Vec<u8>, fetchit_trust_client::TrustError> {
            std::future::pending().await
        }
    }

    // ── M3 D9 regenerate_card_with_relays ────────────────────────

    /// Build a chat-state-enabled `Client` without going through
    /// `from_parts` (which probes `/version` and refuses without a
    /// reachable x0xd). The HTTP, router, and transports are stubbed
    /// to whatever a hermetic test needs.
    fn test_client_no_denylist() -> (Client, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("d9-test".to_owned())),
                Some(&salt),
            )
            .unwrap(),
        );
        let dsa_signer = MlDsaSigner::generate().unwrap();
        let agent_id_hex = hex::encode(dsa_signer.agent_id());
        let identity = Arc::new(
            FetchitIdentity::load_or_create(
                dir.path(),
                &master,
                &agent_id_hex,
                kdf_id_argon2(),
                Some(&salt),
            )
            .unwrap(),
        );
        let registry = Arc::new(ConversationRegistry::new(
            layout.clone(),
            master,
            kdf_id_argon2(),
            Some(salt),
        ));
        let signer: Arc<dyn Signer> = Arc::new(dsa_signer);
        let chat = ChatState {
            identity,
            registry,
            signer,
            layout,
            local_machine_id: [0u8; 32],
            reachability: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::ReachabilityCache::new(),
            )),
            bridge_consent: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeConsentStore::new(),
            )),
            bridge_inbound_shadow: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeInboundShadow::new(),
            )),
            members_singleflight: Arc::new(crate::members_singleflight::MembersSingleflight::new()),
        };
        let http = Arc::new(Http::new("http://127.0.0.1:1".into(), "tok".into()).unwrap());
        let client = Client {
            http,
            router: Arc::new(Router::new()),
            chat: Some(chat),
            relay: None,
            lan: None,
            lan_bound_addr: None,
            denylist: None,
            denylist_dropped_inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            advertised_relays: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            multi_home_inbound: None,
            primary_relay_url: None,
        };
        (client, dir)
    }

    /// D9 happy path: validation accepts a real-world relay list and
    /// the next `current_card_value()` call carries those URLs in
    /// the v2 hints slot under `{v: 1, data: {relays: [...]}}`.
    #[tokio::test]
    async fn regenerate_card_with_relays_validates_and_updates_hints() {
        let (client, _dir) = test_client_no_denylist();
        let relays = vec![
            "wss://nyc.etchit.io/v1/ws".to_string(),
            "wss://community.example/v1/ws".to_string(),
        ];
        client
            .regenerate_card_with_relays(relays.clone())
            .await
            .expect("validated relay list must succeed");
        let card_value = client.current_card_value().await.expect("card mint");
        let parsed: crate::card::CardExtension =
            serde_json::from_value(card_value).expect("v2 extension parses");
        let hints = parsed.v2_rendezvous_hints.expect("hints present in card");
        assert_eq!(hints.v, 1);
        let v1 = crate::card::RendezvousHintsV1::from_value(&hints.data).unwrap();
        assert_eq!(v1.relays, relays);
    }

    /// D9 negative: non-`wss://` schemes are rejected at validation
    /// before any in-memory state is mutated. We confirm the rejection
    /// AND that the advertised-relays slot is untouched on error.
    #[tokio::test]
    async fn regenerate_card_with_relays_rejects_non_wss() {
        let (client, _dir) = test_client_no_denylist();
        let result = client
            .regenerate_card_with_relays(vec!["http://not-wss.example/v1/ws".into()])
            .await;
        assert!(matches!(result, Err(ChatError::Invalid(_))));
        assert!(
            client.advertised_relays.read().await.is_empty(),
            "validation failure must leave the relay slot empty",
        );
    }

    /// D9 negative: empty list is rejected by `RendezvousHintsV1::from_value`.
    #[tokio::test]
    async fn regenerate_card_with_relays_rejects_empty() {
        let (client, _dir) = test_client_no_denylist();
        let result = client.regenerate_card_with_relays(vec![]).await;
        assert!(matches!(result, Err(ChatError::Invalid(_))));
    }

    /// D9 follow-up: when no relays have been registered the card
    /// mint omits the `fetchit_rendezvous_hints` field entirely
    /// (matches the M0 schema-freeze v1-wire contract).
    #[tokio::test]
    async fn current_card_value_without_regenerate_omits_hints() {
        let (client, _dir) = test_client_no_denylist();
        let card_value = client.current_card_value().await.expect("card mint");
        let parsed: crate::card::CardExtension = serde_json::from_value(card_value).unwrap();
        assert!(parsed.v2_rendezvous_hints.is_none());
    }

    // ── M3 E1 seed_initial_advertised_relays ──────────────────────

    /// E1: an explicit list of wss:// URLs is returned verbatim after
    /// validation. The seed function is the single chokepoint that
    /// runs the wire-format validator at boot, matching the post-boot
    /// `regenerate_card_with_relays` contract.
    #[test]
    fn seed_initial_relays_uses_explicit_when_provided() {
        let relays = vec![
            "wss://nyc.etchit.io/v1/ws".to_owned(),
            "wss://community.example/v1/ws".to_owned(),
        ];
        let seeded = super::seed_initial_advertised_relays(
            Some(relays.clone()),
            Some("wss://fallback.example/v1/ws"),
        )
        .expect("valid wss list must pass");
        assert_eq!(seeded, relays);
    }

    /// E1: a non-wss scheme in the explicit list fails validation
    /// before the slot is seeded. The same `RendezvousHintsV1`
    /// validator rejects http://, ws://, file:// — anything but wss://.
    #[test]
    fn seed_initial_relays_rejects_non_wss_explicit() {
        let result = super::seed_initial_advertised_relays(
            Some(vec!["http://not-wss.example/v1/ws".to_owned()]),
            Some("wss://fallback.example/v1/ws"),
        );
        assert!(matches!(result, Err(ChatError::Invalid(_))));
    }

    /// E1: an empty explicit list is rejected. The wire-format
    /// contract requires at least one entry; callers that want
    /// the no-hints behaviour should pass `None` (not `Some(vec![])`).
    #[test]
    fn seed_initial_relays_rejects_empty_explicit() {
        let result = super::seed_initial_advertised_relays(Some(vec![]), None);
        assert!(matches!(result, Err(ChatError::Invalid(_))));
    }

    /// E1: when no explicit list is provided and the primary relay
    /// URL parses as wss://, the slot defaults to `[primary_url]`.
    /// Gives a fresh boot a sensible single-relay hint without
    /// requiring the operator to populate Settings → Network.
    #[test]
    fn seed_initial_relays_defaults_to_primary_when_wss() {
        let primary = "wss://nyc.etchit.io/v1/ws";
        let seeded = super::seed_initial_advertised_relays(None, Some(primary))
            .expect("wss primary must default to [primary]");
        assert_eq!(seeded, vec![primary.to_owned()]);
    }

    /// E1: when no explicit list is provided and the primary URL is
    /// http://, the slot stays empty. Defaulting would surface as a
    /// validation error at the next card mint because the wire-format
    /// requires wss://; staying empty matches the M0 schema-freeze
    /// contract of "no hints field" instead.
    #[test]
    fn seed_initial_relays_empty_when_primary_is_http() {
        let seeded =
            super::seed_initial_advertised_relays(None, Some("http://dev-relay.local:8088/"))
                .expect("http primary must seed empty, not error");
        assert!(seeded.is_empty());
    }

    /// E1: REST-only test mode (no relay configured at all). The
    /// slot stays empty; the v2 hints field is simply omitted from
    /// the card. This is the bare wiremock-backed Client shape used
    /// by `tests/integration.rs::client_against`.
    #[test]
    fn seed_initial_relays_empty_when_no_primary() {
        let seeded = super::seed_initial_advertised_relays(None, None)
            .expect("REST-only build must seed empty without error");
        assert!(seeded.is_empty());
    }

    /// E1 follow-up (G-1): the wss-primary fallback runs through the
    /// same `RendezvousHintsV1::from_value` validator the explicit
    /// path does, so a too-long single-entry primary (over the per-
    /// entry cap) lands in the empty branch rather than silently
    /// bypassing the cap with a hand-rolled length check.
    #[test]
    fn seed_initial_relays_empty_when_primary_wss_exceeds_per_entry_cap() {
        let oversize_wss = format!("wss://{}.example/v1/ws", "x".repeat(260));
        assert!(oversize_wss.len() > 256, "fixture must exceed the cap");
        let seeded = super::seed_initial_advertised_relays(None, Some(&oversize_wss))
            .expect("oversize wss primary must seed empty, not error");
        assert!(seeded.is_empty());
    }

    // ── M3 R-tail-4 client boot wiring ───────────────────────────

    /// R-tail-4 boot smoke: stand up a `Client` whose `build_with_chat`
    /// path is mimicked here — we substitute a stub `RelayBuilder` so
    /// no real WebSocket is opened — and assert (a) the Router holds a
    /// `MultiHomeTransport` (single transport, slot 0 = the primary)
    /// and (b) `Client.relay` is populated for the presence-watch
    /// surfaces that read it directly. The inbound-rx slot exposed via
    /// [`Client::take_transport_inbound`] under the legacy `"relay"`
    /// name resolves through the new `multi_home_inbound` field.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // hermetic boot mirrors `build_with_chat` end-to-end.
    async fn client_boot_wires_multi_home_into_router() {
        use crate::transport::{
            MultiHomeTransport, RelayBuilder, RelayHandle, Transport, TransportError,
        };
        use async_trait::async_trait;

        struct StubBuilder;
        #[async_trait]
        impl RelayBuilder for StubBuilder {
            async fn build(
                &self,
                url: &str,
            ) -> std::result::Result<Arc<RelayHandle>, TransportError> {
                Ok(Arc::new(RelayHandle::mock(url.to_string())))
            }
        }

        struct NoopDenylistQuery;
        impl fetchit_trust::DenylistQuery for NoopDenylistQuery {
            fn is_blocked(&self, _: fetchit_trust::EntryKind, _: &str) -> bool {
                false
            }
        }

        // Build MH the same shape `build_with_chat` does: stub builder,
        // no-op denylist, a callback that pushes inbound onto an mpsc
        // we own — exactly the seam `Client::take_transport_inbound`
        // drains for the legacy `"relay"` name.
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundEnvelope>();
        let on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync> = {
            let tx = inbound_tx.clone();
            Arc::new(move |env| {
                let _ = tx.send(env);
            })
        };
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(NoopDenylistQuery);
        let builder: Arc<dyn RelayBuilder> = Arc::new(StubBuilder);
        let mh = MultiHomeTransport::new_with_subscriber(
            "wss://primary.test/v1/ws".into(),
            denylist,
            on_inbound,
            builder,
            None,
        )
        .await
        .expect("MH boot succeeds with stub builder");
        let mh = Arc::new(mh);

        let mut router = Router::new();
        router.add(Arc::clone(&mh) as Arc<dyn Transport>);
        // Stub handles built via `RelayHandle::mock` carry no real
        // `RelayTransport`, so `relay_handle` stays None in the
        // hermetic boot — production wires the real transport via
        // `RealRelayBuilder`. The presence-watch contract is the
        // `relay_transport_arc` accessor on the slot-0 handle, which
        // we exercise from `MultiHomeTransport`'s own tests.

        // Drive the same shape `from_parts` builds.
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let salt = fresh_argon_salt();
        let master = Arc::new(
            MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new("rtail4-test".to_owned())),
                Some(&salt),
            )
            .unwrap(),
        );
        let dsa_signer = MlDsaSigner::generate().unwrap();
        let agent_id_hex = hex::encode(dsa_signer.agent_id());
        let identity = Arc::new(
            FetchitIdentity::load_or_create(
                dir.path(),
                &master,
                &agent_id_hex,
                kdf_id_argon2(),
                Some(&salt),
            )
            .unwrap(),
        );
        let registry = Arc::new(ConversationRegistry::new(
            layout.clone(),
            master,
            kdf_id_argon2(),
            Some(salt),
        ));
        let signer: Arc<dyn Signer> = Arc::new(dsa_signer);
        let chat = ChatState {
            identity,
            registry,
            signer,
            layout,
            local_machine_id: [0u8; 32],
            reachability: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::ReachabilityCache::new(),
            )),
            bridge_consent: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeConsentStore::new(),
            )),
            bridge_inbound_shadow: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeInboundShadow::new(),
            )),
            members_singleflight: Arc::new(crate::members_singleflight::MembersSingleflight::new()),
        };
        let http = Arc::new(Http::new("http://127.0.0.1:1".into(), "tok".into()).unwrap());
        let client = Client {
            http,
            router: Arc::new(router),
            chat: Some(chat),
            relay: None,
            lan: None,
            lan_bound_addr: None,
            denylist: None,
            denylist_dropped_inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            advertised_relays: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            multi_home_inbound: Some(Arc::new(std::sync::Mutex::new(Some(inbound_rx)))),
            primary_relay_url: None,
        };

        // Router carries exactly one transport — MultiHomeTransport —
        // and its name() is the canonical "multi-home".
        let transports = client.router.transports();
        assert_eq!(transports.len(), 1, "router holds MultiHomeTransport");
        assert_eq!(
            transports[0].name(),
            "multi-home",
            "router slot 0 is MultiHomeTransport",
        );

        // Legacy `"relay"` name still resolves — that's the seam
        // existing callers (peer.rs, desktop chat.rs) hang off of.
        let rx_via_relay = client.take_transport_inbound("relay");
        assert!(
            rx_via_relay.is_some(),
            "legacy `relay` name resolves to the multi-home inbound seam",
        );

        // And it's a single-consumer channel — second take is None.
        let rx_via_relay_again = client.take_transport_inbound("relay");
        assert!(rx_via_relay_again.is_none(), "inbound rx is taken once");

        // The canonical `"multi-home"` name resolves through the same
        // slot. Both names share the underlying Client-owned channel.
        let rx_via_canonical = client.take_transport_inbound("multi-home");
        assert!(
            rx_via_canonical.is_none(),
            "canonical name shares the legacy-named slot",
        );

        // The stub-built MH carries slot 0 — pinned primary — and
        // exposes the slot-0 handle for presence-watch surfaces.
        assert!(
            mh.slot_zero_handle().is_some(),
            "slot 0 handle accessible for presence-watch surfaces",
        );
    }

    /// D8 happy path: a REST-only client begins with no denylist
    /// wired, `install_m3_denylist` populates the field with the
    /// adapter, and inbound-drop counter starts at zero. Uses a
    /// pending HTTP stub so no real network call fires.
    #[tokio::test]
    async fn install_m3_denylist_sets_denylist_field() {
        // REST-only client (no relay_url / data_dir / passphrase /
        // lan-direct) — `from_parts` skips build_with_chat entirely
        // and never touches the network or x0xd.
        let mut client = Client::from_parts(
            "http://127.0.0.1:1".into(),
            "test-token".into(),
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("REST-only client construction");
        assert!(
            client.denylist.is_none(),
            "fresh REST-only client has no denylist wired"
        );

        let http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static> =
            Arc::new(PendingHttp);
        client
            .install_m3_denylist("https://etchit.io/v1".into(), None, http)
            .expect("install succeeds");
        assert!(client.denylist.is_some(), "denylist installed");
        assert_eq!(
            client.denylist_dropped_inbound_count(),
            0,
            "counter starts at zero"
        );
    }
}
