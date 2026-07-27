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
use fetchit_fedi::transport::FediverseTransport;
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

/// T8b: how long slot 0 may stay continuously
/// [`fetchit_relay_client::ConnState::Disconnected`] before the
/// home-relay failover watcher migrates the pinned primary to a fallback
/// relay. A return to `Connected` resets the timer;
/// [`fetchit_relay_client::ConnState::PermanentlyDisconnected`] bypasses
/// it and triggers immediately. Production passes this to
/// [`run_failover_watcher`]; tests inject a short override.
const FAILOVER_AFTER_MS: Duration = Duration::from_secs(120);

/// T8b: how long the failover watcher waits after a failed migration
/// (no fallback candidate, or [`crate::transport::MultiHomeTransport::replace_primary`]
/// errored) before re-attempting. Paces the retry loop so a dead primary
/// with no reachable fallback never busy-spins. Tests inject a short
/// override.
const FAILOVER_RETRY_BACKOFF: Duration = Duration::from_secs(15);

/// File name that gates whether vault state already exists for this
/// data dir. The chat identity vault is the first file written, so its
/// presence implies the rest of the layout was initialised under a
/// matching KDF / salt pair.
const IDENTITY_VAULT_FILE: &str = "identity.json.enc";

/// Sentinel x0xd base URL for daemonless builds. Port 9 (discard) is
/// never an x0xd, so any daemon-only endpoint that does get called in
/// a daemonless client fails fast with an honest connection error
/// instead of hanging on discovery.
const DAEMONLESS_BASE_URL: &str = "http://127.0.0.1:9";

/// Builder for [`Client`] with optional overrides.
#[derive(Default)]
pub struct ClientBuilder {
    base_url: Option<String>,
    token: Option<String>,
    relay_url: Option<Url>,
    data_dir: Option<PathBuf>,
    /// #91 Z4a: held in a `Zeroizing` so the builder never keeps a plain
    /// passphrase copy between `.passphrase()` and `.build()`; `build()`
    /// moves it on into the `Arc<Zeroizing<String>>` custody hold.
    passphrase: Option<zeroize::Zeroizing<String>>,
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
    /// Build without any x0xd daemon: skip discovery, skip the `TreeKEM`
    /// version probe, and sign with a local ML-DSA-65 keypair persisted
    /// in the chat vault ([`crate::local_signer::LocalSignerVault`])
    /// instead of `X0xdSigner`. Daemon-backed surfaces (M1/M2 groups,
    /// presence, v2 card generation) fail with transport errors against
    /// an unconnectable sentinel base URL. Meaningful only together
    /// with `data_dir` (and usually `relay_url` + `passphrase`); the
    /// Android shell is the primary consumer. Supplying an explicit
    /// `base_url` together with `daemonless` re-enables the daemon
    /// version probe against it (the P2 in-process-router shape).
    daemonless: bool,
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
            .field("daemonless", &self.daemonless)
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
        // #91 Z4a: wrap on the way in so the builder's held copy is wiped
        // on drop. Signature stays `String` so callers are unaffected.
        self.passphrase = Some(zeroize::Zeroizing::new(s));
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

    /// Enable the daemonless profile. See the field doc for semantics.
    #[must_use]
    pub fn daemonless(mut self, enabled: bool) -> Self {
        self.daemonless = enabled;
        self
    }

    /// Build the client. Falls back to [`discover_local`] for any
    /// x0xd connection field not explicitly set.
    ///
    /// # Errors
    /// Returns discovery, HTTP, relay-handshake, or vault failures.
    pub async fn build(self) -> Result<Client> {
        let (base_url, token) = if self.daemonless {
            (
                self.base_url
                    .unwrap_or_else(|| DAEMONLESS_BASE_URL.to_owned()),
                self.token.unwrap_or_default(),
            )
        } else {
            match (self.base_url, self.token) {
                (Some(u), Some(t)) => (u, t),
                (u, t) => {
                    let ep = discover_local().await?;
                    (u.unwrap_or(ep.base_url), t.unwrap_or(ep.token))
                }
            }
        };
        Client::from_parts(
            base_url,
            token,
            self.relay_url,
            self.data_dir,
            // #91 Z4c: hand `from_parts` the `Zeroizing<String>` directly so
            // no plain copy of the passphrase escapes into the build path
            // (the copy drops wiped at each seam instead of lingering).
            self.passphrase,
            self.enable_lan_direct,
            self.contact_pubkey_lookup,
            self.x0xd_port_file,
            self.denylist,
            self.advertised_relays,
            self.daemonless,
        )
        .await
    }
}

/// A bridged fediverse public post that passed every relay-side inbox
/// gate and was fanned out to this client as an
/// [`EnvelopeKind::PublicPost`](fetchit_relay_proto::EnvelopeKind::PublicPost)
/// envelope.
///
/// Attribution is [`Self::verified_actor_url`] — the relay-verified,
/// denylist-canonical signing actor — NOT anything inside
/// [`Self::activity_json`], which is opaque, untrusted fediverse content
/// the render surface MUST sanitize per the rendered-content-is-untrusted
/// model (`docs`/`SECURITY.md`). The activity body's self-asserted
/// `actor` never leaves those opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPostDelivery {
    /// Relay-verified, denylist-canonical actor URL the post is from.
    pub verified_actor_url: String,
    /// Raw `application/activity+json` bytes, handed to the content
    /// handler verbatim — untrusted; sanitize before rendering.
    pub activity_json: Vec<u8>,
}

/// Bound on the in-memory public-post broadcast channel. A UI consumer
/// that lags past this drops the oldest posts (broadcast `Lagged`);
/// public posts are live-only, history-pull is a post-launch concern.
const PUBLIC_POST_CHANNEL_CAP: usize = 256;

/// Capacity of the outbound-outbox event broadcast. A lagging shell
/// re-syncs from `Client::outbox_snapshot` (same rationale as the
/// public-post channel).
const OUTBOX_CHANNEL_CAP: usize = 256;

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
    /// Outbound-DM outbox: pending bubbles + retry state, vault-sealed.
    /// Loaded in the prod ctor; the shell starts the retry loop via
    /// [`Client::start_outbox_driver`]. See [`crate::outbox`].
    outbox: Arc<tokio::sync::Mutex<crate::outbox::store::OutboxStore>>,
    /// Broadcast of [`crate::outbox::OutboxEvent`] upserts (outbound-only)
    /// for the shell to project; cap `OUTBOX_CHANNEL_CAP`.
    outbox_tx: tokio::sync::broadcast::Sender<crate::outbox::OutboxEvent>,
    /// Manual-retry kick for the outbox driver. `None` until
    /// [`Client::start_outbox_driver`] publishes the sender; the driver
    /// run-loop holds the receiver and flushes every retryable bubble on
    /// each kick (the shell's Retry button -> [`Client::retry_outbox`]).
    outbox_retry_tx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
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
    /// M4 Stage 5.3: broadcast surface for inbound bridged fediverse
    /// public posts. The receive path
    /// ([`Client::dispatch_inbound_public_post`]) sends decoded
    /// [`PublicPostDelivery`]s here; the desktop shell drains it via
    /// [`Client::subscribe_to_public_posts`] to emit the
    /// `chat:public-post` Tauri event. Lives on `ChatState` (not a
    /// top-level builder field) so REST-only clients expose no surface.
    public_post_tx: tokio::sync::broadcast::Sender<PublicPostDelivery>,
}

/// Outcome of a home-relay failover attempt, delivered to the callback
/// registered via [`Client::set_relay_failover_callback`].
#[derive(Debug, Clone)]
pub enum RelayFailoverEvent {
    /// Slot 0 migrated from the dead relay to a live fallback.
    Migrated {
        /// The relay that was abandoned.
        from: String,
        /// The new live primary.
        to: String,
    },
    /// No migration happened: no fallback candidate, or the swap failed.
    Failed {
        /// The dead (still-current) primary.
        dead: String,
    },
}

/// Stored shape of the home-relay failover callback (T8b / T9). Mirrors the
/// G1 `PrimaryDenylistedCallback`: the watcher invokes it with a typed
/// [`RelayFailoverEvent`] describing whether the primary migrated to a live
/// fallback or the attempt failed.
type RelayFailoverCallback = Arc<dyn Fn(RelayFailoverEvent) + Send + Sync>;

/// Epoch-ms clock for advisory stamps (convergence records). Same
/// zero-on-clock-error fallback as the crate's other `now_ms` helpers —
/// these stamps order observations, they never gate security decisions.
fn chat_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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
    /// M3 G4: concrete handle to the denylist consumer (the same
    /// instance backing the `denylist` gate adapter above), retained so
    /// the desktop shell can subscribe to its
    /// [`fetchit_trust_client::BlockEvent`] broadcast and emit the
    /// `chat:denylist-updated` Tauri event. Populated by
    /// [`Self::install_m3_denylist`]; `None` until the consumer is
    /// installed (REST-only mode, or before the install runs at boot).
    denylist_consumer: Option<Arc<fetchit_trust_client::DenylistConsumer>>,
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
    /// Defork P1: latched false the first time an engine-A apply endpoint
    /// answers a route-level 404 (stock daemon — the endpoints are fork
    /// additions). Unset reads as supported, so a fork daemon never pays
    /// a capability probe; once false, the bridge arms drop relayed
    /// events (the stock daemon's own direct-plane join machinery owns
    /// delivery) and warm recovery skips straight to the cold resume.
    /// Shared across `Client` clones.
    engine_a_supported: Arc<std::sync::OnceLock<bool>>,
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
    /// M3 G1: direct handle to the [`crate::transport::MultiHomeTransport`]
    /// when one is wired, so the desktop shell can register a
    /// primary-denylisted callback that emits the
    /// `chat:relay-denylisted` Tauri event. `None` when the client was
    /// built without a relay URL — REST-only mode has no MH instance
    /// to attach the callback to.
    multi_home: Option<Arc<crate::transport::MultiHomeTransport>>,
    /// M3 R-tail-5: the local primary relay URL pinned to
    /// [`crate::transport::MultiHomeTransport`]'s slot 0. Send-path
    /// helpers synthesize this into a fallback
    /// `RendezvousHintsV1 { relays: [primary_url] }` when the
    /// recipient's stored card has no `v2_rendezvous_hints` slot —
    /// keeps legacy v1 contacts routable through slot 0 while letting
    /// the transport layer be strict-on-`None`. `None` when the
    /// client was built without a relay URL (REST-only mode).
    ///
    /// Interior-mutable (T8b): the home-relay failover watcher rewrites
    /// this after migrating slot 0 to a fallback relay, so the publish
    /// path ([`Self::publish_pair_record`]) and the send-path fallback
    /// hints (`messages::Endpoint`, the auto-rekey sweeper) advertise the
    /// NEW primary rather than the dead one. `Arc`-wrapped so `Client`
    /// clones (the spawned publish task, the watcher) share one cell;
    /// `tokio::sync::RwLock` to match `advertised_relays` and stay
    /// await-friendly at the async read sites.
    primary_relay_url: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Session-lived negative cache of sender agent ids whose on-receive
    /// group-sender pair-record resolve recently failed (relay 404 /
    /// unreachable). Cloned into every [`messages::Endpoint`] so
    /// [`messages::Endpoint::receive_private_group_envelope`] fetches a
    /// given unknown sender's pair-record at most once per TTL window
    /// instead of once per delivered envelope (H1 relay-GET amplification).
    ///
    /// Entries map sender-id -> insertion `Instant` and EXPIRE after
    /// [`messages::NEG_CACHE_TTL`]: pair-records are RAM-only and per-relay,
    /// so a relay restart drops them and peers re-POST on reconnect -- a 404
    /// is therefore transient, and a session-permanent suppression would
    /// silently wedge a now-resolvable sender ("messages won't decrypt")
    /// until app restart. A short TTL self-heals by re-validating. Bounded
    /// in `Endpoint`; never persisted. `std::sync::Mutex` (not async): the
    /// critical section is a `HashMap` get/insert, no `.await` held.
    neg_resolve_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    /// The vault custody passphrase this client was built with (`None` =
    /// OS-keychain custody). Retained so every vault re-open (fediverse
    /// actor mint/load/upgrade, public post) resolves the SAME custody
    /// the boot-time vault used -- per-call passphrase parameters let a
    /// caller pass `None` against a passphrase-mode vault, which fails
    /// only at runtime on mobile. `Zeroizing` clears the heap bytes on
    /// final drop; `Arc` so `Client` clones share one zeroized value.
    custody_passphrase: Option<Arc<Zeroizing<String>>>,
    /// Session-lived `GroupId -> kind` cache shared into every
    /// [`messages::Endpoint`] (cloned in [`Self::messages`], exactly like
    /// [`Self::neg_resolve_cache`]) so [`messages::Endpoint::send_to_group`]
    /// routes private-vs-public without a `GET /groups/<id>` per send.
    /// Warmed on the create/join paths via
    /// [`messages::Endpoint::note_group_kind`] and, on a cold miss, by the
    /// router's one-shot kind lookup. `std::sync::Mutex` (not async): the
    /// critical section is a `HashMap` get/insert, no `.await` held.
    /// Never persisted -- kind is immutable per group and cheap to
    /// re-resolve after a restart.
    group_kinds: Arc<std::sync::Mutex<std::collections::HashMap<String, groups::GroupKind>>>,
    /// T8b / T9: optional callback the home-relay failover watcher (and
    /// [`Self::migrate_primary`]) fires after attempting to migrate slot 0.
    /// The argument is a typed [`RelayFailoverEvent`] (see
    /// [`Self::set_relay_failover_callback`]). The desktop shell registers
    /// an emitter for a Tauri toast; `None` until then, and a no-op in
    /// REST-only mode (no watcher is spawned). Mirrors the G1
    /// primary-denylisted callback storage shape.
    relay_failover_cb: Arc<tokio::sync::RwLock<Option<RelayFailoverCallback>>>,
    /// T8b: abort handle for the background failover watcher task. The
    /// watcher holds its own `Client` clone, so it is NOT stopped by
    /// dropping other clones; teardown paths that rebuild the `Client`
    /// (the desktop relay switch / daemon restart) MUST call
    /// [`Self::stop_failover_watcher`] first or every rebuild stacks
    /// another immortal watcher pinning the dead transport stack.
    /// Shared across clones so any clone can stop it.
    failover_watcher_abort: Arc<std::sync::Mutex<Option<tokio::task::AbortHandle>>>,
    /// M4 Stage 5.2: shared outbound HTTPS-POST transport for the
    /// fediverse bridge. Owns one `reqwest::Client` + the per-instance
    /// HTTP-Signature capability cache; [`Self::publish_public_post`]
    /// fans an `ActivityPub` `Create{Note}` out to resolved recipient
    /// inboxes through it. Built alongside the chat stack in
    /// [`build_with_chat`]; `None` in REST-only mode (no actor identity
    /// vault, so nothing to sign with).
    fediverse: Option<Arc<FediverseTransport>>,
    /// Task #297 (chat resilience): per-group MLS-epoch recovery status.
    /// The dispatcher flips a group to `Reconnecting` when its inbound
    /// decrypt fails (a stale/keyless epoch) and back to `Live` when
    /// messages flow again; [`Self::recover_group_once`] drives the
    /// catch-up. Shared across `Client` clones so the spawned dispatcher,
    /// the shell's status getter, and any recovery driver observe one map.
    group_recovery: crate::groups::epoch_recovery::GroupStatusMap,
    /// Per-group last-applied group-log cursor for epoch recovery. Held on
    /// the client (not the driver) so it survives `recover_group_once`
    /// rebuilding the driver each call — warm catch-up resumes from the
    /// cursor instead of re-fetching the whole log every tick. Shared
    /// across `Client` clones (`Arc`) so every recovery pass sees one
    /// store. Not durable across a restart; the applier's idempotent 409
    /// handling covers a cold start.
    recovery_cursors: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    /// Group ids with an epoch-recovery pass currently in flight. Guards
    /// [`Self::trigger_group_recovery`] so a burst of stale-epoch frames for
    /// one group spawns a single recovery, not a storm. Shared across clones.
    recovering: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
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
            false,
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
        passphrase: Option<Zeroizing<String>>,
        enable_lan_direct: bool,
        contact_pubkey_lookup: Option<ContactPubkeyLookup>,
        x0xd_port_file: Option<PathBuf>,
        denylist: Option<Arc<dyn crate::denylist::DenylistCheck>>,
        advertised_relays: Option<Vec<String>>,
        daemonless: bool,
    ) -> Result<Self> {
        let http = Arc::new(match x0xd_port_file.as_ref() {
            Some(path) => Http::new_with_port_file(path.clone(), token.clone())?,
            None => Http::new(base_url.clone(), token.clone())?,
        });
        let needs_chat =
            relay_url.is_some() || data_dir.is_some() || passphrase.is_some() || enable_lan_direct;
        // Retain the custody choice for the client's lifetime BEFORE the
        // passphrase moves into the vault build: later vault re-opens
        // (fediverse identity paths) must resolve the same custody. `p` is
        // already `Zeroizing<String>`, so clone it straight into the Arc (no
        // second wrap, no plain copy).
        let custody_passphrase = passphrase.as_ref().map(|p| Arc::new(p.clone()));

        let (
            router,
            chat,
            relay,
            lan,
            lan_bound_addr,
            multi_home_inbound,
            primary_relay_url,
            multi_home,
            fediverse,
        ) = if needs_chat {
            if !daemonless {
                announce_identity_best_effort(&http).await;
            }
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
                daemonless,
            )
            .await?
        } else {
            (
                Router::new(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        };

        // Seed advertised_relays from the boot-time primary snapshot
        // BEFORE wrapping the URL into its shared cell: the seed is a
        // one-shot derivation, not a live read.
        let initial_relays =
            seed_initial_advertised_relays(advertised_relays, primary_relay_url.as_deref())?;

        // Interior-mutable primary URL: the failover watcher rewrites it
        // after a migration. The auto-rekey sweeper takes an `Arc` clone
        // (not a snapshot) so its per-tick fallback hints follow slot 0
        // across a failover instead of routing rekeys to the dead relay.
        let primary_relay_url = Arc::new(tokio::sync::RwLock::new(primary_relay_url));

        let router = Arc::new(router);
        if let Some(chat) = chat.as_ref() {
            spawn_auto_rekey_sweeper(&router, chat, Arc::clone(&primary_relay_url));
        }

        let client = Self {
            http,
            router,
            chat,
            relay,
            lan,
            lan_bound_addr,
            denylist,
            denylist_consumer: None,
            denylist_dropped_inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            failover_watcher_abort: Arc::new(std::sync::Mutex::new(None)),
            advertised_relays: Arc::new(tokio::sync::RwLock::new(initial_relays)),
            engine_a_supported: Arc::new(std::sync::OnceLock::new()),
            multi_home_inbound,
            primary_relay_url,
            neg_resolve_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            custody_passphrase,
            group_kinds: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            multi_home,
            fediverse,
            relay_failover_cb: Arc::new(tokio::sync::RwLock::new(None)),
            group_recovery: crate::groups::epoch_recovery::GroupStatusMap::new(),
            recovery_cursors: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recovering: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        };

        // Best-effort pair-record publish: runs once at connect time so
        // peers can discover this agent via `GET /v1/pair-record/<id>`.
        // A failure only logs a warning and never blocks or fails startup.
        if client.chat.is_some() && client.primary_relay_url.read().await.is_some() {
            let client_for_publish = client.clone();
            tokio::spawn(async move {
                if let Err(e) = client_for_publish.publish_pair_record().await {
                    log::warn!("[chat] pair-record publish failed at connect: {e}");
                }
            });
            // T8b: spawn the home-relay failover watcher. It observes slot
            // 0's connection state and migrates the pinned primary to the
            // next advertised relay when the current one dies. Gated on a
            // wired MultiHomeTransport (slot 0 only exists there).
            if client.multi_home.is_some() {
                client.spawn_failover_watcher();
            }
        }

        Ok(client)
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

    /// The local agent id (lowercase 64-hex), when chat state is wired.
    /// Daemonless consumers (the Android FFI) read identity from here
    /// instead of x0xd's `/agent`.
    #[must_use]
    pub fn local_agent_id_hex(&self) -> Option<String> {
        self.chat
            .as_ref()
            .map(|c| c.identity.agent_id_hex().to_owned())
    }

    /// Shared handle to the outbound fediverse transport, when one was
    /// wired at boot. `None` in REST-only mode (no actor identity vault,
    /// so the bridge has nothing to sign with). The M4 Stage 5.2 driver
    /// [`Self::publish_public_post`] delivers through this; exposed so
    /// the desktop shell can pre-flight bridge availability before
    /// offering the "publish to fediverse" affordance.
    #[must_use]
    pub fn fediverse_transport(&self) -> Option<&Arc<FediverseTransport>> {
        self.fediverse.as_ref()
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
    /// - When a [`crate::transport::MultiHomeTransport`] is wired, the
    ///   consumer's [`fetchit_trust_client::BlockEvent`] broadcast is
    ///   routed into it (via
    ///   [`crate::transport::MultiHomeTransport::attach_block_event_subscriber`])
    ///   so a mid-session `RelayUrl` block drops the matching slot 1/2
    ///   and fires the primary-denylisted callback. The consumer is also
    ///   retained on the client so the desktop shell can take its own
    ///   subscriber via [`Self::subscribe_to_block_events`].
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

        // D6: route the consumer's BlockEvent broadcast into the
        // MultiHomeTransport (when one is wired) so a mid-session
        // `RelayUrl` block drops the matching slot 1/2 and fires the
        // primary-denylisted callback. The transport was built before
        // the consumer existed (build_with_chat passes `None`), so the
        // attach happens here. Each `subscribe()` is an independent
        // receiver; the desktop G4 pump takes its own via
        // [`Self::subscribe_to_block_events`]. REST-only clients have no
        // MH to attach to.
        if let Some(mh) = self.multi_home.as_ref() {
            mh.attach_block_event_subscriber(consumer.subscribe());
        }

        // TODO(M3 D8.2): stash the JoinHandle on Client so shutdown can
        // abort the loop deterministically. Today the task lives until
        // the consumer Arc drops (every subscriber + the adapter + this
        // spawned closure each hold one).
        let _handle = Arc::clone(&consumer).spawn_poll_loop(http);

        let query: Arc<dyn fetchit_trust::DenylistQuery> = consumer.clone();
        let adapter: Arc<dyn crate::denylist::DenylistCheck> =
            Arc::new(crate::denylist::DenylistQueryAdapter::new(query));
        self.denylist = Some(adapter);
        self.denylist_consumer = Some(consumer);
        Ok(())
    }

    /// M3 G4: subscribe to the installed denylist consumer's
    /// [`fetchit_trust_client::BlockEvent`] broadcast.
    ///
    /// Returns a fresh broadcast receiver each call (the consumer keeps
    /// the sender alive across subscribers), or `None` when no consumer
    /// is installed yet, REST-only mode, or before
    /// [`Self::install_m3_denylist`] runs. The desktop shell drains this
    /// to emit the `chat:denylist-updated` Tauri event that drives the
    /// contacts denylist indicator; the `RelayUrl`-driven slot drops +
    /// primary banner are wired separately inside `install_m3_denylist`
    /// (see [`crate::transport::MultiHomeTransport::attach_block_event_subscriber`]).
    #[must_use]
    pub fn subscribe_to_block_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<fetchit_trust_client::BlockEvent>> {
        self.denylist_consumer.as_ref().map(|c| c.subscribe())
    }

    /// M4 Stage 5.3: subscribe to inbound bridged fediverse public posts.
    ///
    /// Returns a fresh broadcast receiver each call, or `None` in
    /// REST-only mode (no chat state). The desktop shell drains this to
    /// emit the `chat:public-post` Tauri event; the renderer attributes
    /// each post to `PublicPostDelivery::verified_actor_url` and treats
    /// `PublicPostDelivery::activity_json` as untrusted content to
    /// sanitize. A lagging consumer drops the oldest posts
    /// (`PUBLIC_POST_CHANNEL_CAP`); public posts are live-only.
    #[must_use]
    pub fn subscribe_to_public_posts(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<PublicPostDelivery>> {
        self.chat.as_ref().map(|c| c.public_post_tx.subscribe())
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

    /// M6.4 new-device side: mint a link offer for THIS device and publish it,
    /// returning the QR pointer + short-code to show. `ttl_secs` bounds the
    /// enrollment window.
    ///
    /// # Errors
    /// [`ChatError`] when chat state is absent (REST-only mode), or sealing /
    /// publishing fails.
    pub async fn create_link_offer(
        &self,
        ttl_secs: u64,
    ) -> Result<crate::link_device_flow::CreatedLinkOffer> {
        let chat = self.chat.as_ref().ok_or_else(|| {
            ChatError::Invalid("chat state not built; cannot link a device".into())
        })?;
        let agent_id = chat.identity.agent_id_hex().to_owned();
        let ml_dsa = chat.signer.public_key();
        let kem = chat.identity.kem_public_key().to_vec();
        let relays = self.advertised_relays.read().await.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let exp_ms = now.saturating_add(ttl_secs.saturating_mul(1000));
        crate::link_device_flow::create_link_offer(
            agent_id,
            &ml_dsa,
            &kem,
            &relays,
            exp_ms,
            &crate::relay_http::guarded_client(),
        )
        .await
    }

    /// M6.4 existing-device side: fetch a scanned link `uri` and return the
    /// confirm-screen preview (agent id + short-code + freshness).
    ///
    /// # Errors
    /// [`ChatError`] on a bad URI / fetch or a malformed offer.
    pub async fn preview_link_offer(
        &self,
        uri: &str,
    ) -> Result<crate::link_device_flow::LinkOfferPreview> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        crate::link_device_flow::preview_link_offer(uri, now, &crate::relay_http::guarded_client())
            .await
    }

    /// M3 G1: register a callback the multi-home transport invokes
    /// when the user's primary relay (slot 0) is added to the
    /// community denylist mid-session. Slot 0 is NOT dropped — that's
    /// the D6 "Settings concern" contract — but the callback fires so
    /// the desktop shell can emit a Tauri `chat:relay-denylisted`
    /// event and render the conversation banner.
    ///
    /// No-op when the client was built without a relay URL
    /// (REST-only mode); the callback registration silently drops.
    pub fn set_relay_denylisted_callback(&self, cb: Arc<dyn Fn(String) + Send + Sync>) {
        if let Some(mh) = self.multi_home.as_ref() {
            mh.set_primary_denylisted_callback(cb);
        }
    }

    /// T8b / T9: register a callback the home-relay failover watcher (and
    /// the manual [`Self::migrate_primary`] path) fires after attempting to
    /// migrate slot 0. The argument is a typed [`RelayFailoverEvent`]:
    /// [`RelayFailoverEvent::Migrated`] with the old and new URLs on a
    /// successful swap, or [`RelayFailoverEvent::Failed`] with the dead URL
    /// when no fallback was reachable. The desktop shell wires this to a
    /// Tauri event so the user sees a "switched relays" toast and the
    /// persisted relay-url setting tracks the new primary.
    ///
    /// Replaces any prior callback. No-op when the client was built
    /// without a relay URL (REST-only mode never spawns a watcher), but
    /// the registration is still stored harmlessly.
    pub fn set_relay_failover_callback(&self, cb: RelayFailoverCallback) {
        // Block briefly on the write lock from a sync surface: the only
        // contention is the watcher's read at trigger time, so this never
        // stalls. `try_write` would risk dropping the desktop's
        // registration on a spurious miss.
        let slot = Arc::clone(&self.relay_failover_cb);
        if let Ok(mut guard) = slot.try_write() {
            *guard = Some(cb);
            return;
        }
        // Extremely unlikely fallback: spawn the store so we never block
        // a sync caller on the async lock.
        tokio::spawn(async move {
            *slot.write().await = Some(cb);
        });
    }

    /// T8b: spawn the background home-relay failover watcher.
    ///
    /// Wires the three production seams into `run_failover_watcher`:
    /// 1. **resubscribe** — re-fetch slot 0's live state stream from the
    ///    [`crate::transport::MultiHomeTransport`]. Called once at start
    ///    and again after every migration, so the watcher sticks to the
    ///    NEW slot 0 (whose `RelaySet` is fresh).
    /// 2. **`current_primary`** — snapshot the live (interior-mutable)
    ///    primary URL so the action knows which relay just died.
    /// 3. **action** — `Self::failover_to_next_relay`, which picks a
    ///    candidate, swaps slot 0, updates state, republishes, prunes, and
    ///    fires the callback.
    ///
    /// No-op (returns without spawning) when no
    /// [`crate::transport::MultiHomeTransport`] is wired — slot 0 only
    /// exists there. Caller (in `from_parts`) already gates on that.
    /// Stop the background home-relay failover watcher, if one is
    /// running. Idempotent; callable from any clone.
    ///
    /// The watcher task holds its own `Client` clone and therefore
    /// outlives every other clone; rebuild paths (the desktop's relay
    /// switch, daemon restart) call this before dropping the old
    /// `Client` so the watcher does not keep observing, and keeping
    /// alive, a torn-down transport stack.
    pub fn stop_failover_watcher(&self) {
        if let Ok(guard) = self.failover_watcher_abort.lock() {
            if let Some(h) = guard.as_ref() {
                h.abort();
            }
        }
    }

    fn spawn_failover_watcher(&self) {
        let Some(mh) = self.multi_home.clone() else {
            return;
        };
        let primary_for_read = Arc::clone(&self.primary_relay_url);
        let action_client = self.clone();
        let watcher = tokio::spawn(async move {
            run_failover_watcher(
                {
                    let mh = Arc::clone(&mh);
                    move || mh.slot_zero_states()
                },
                move || {
                    // Read the live primary without blocking the watcher
                    // loop: `try_read` misses only under a concurrent
                    // failover write, and the next state change re-drives
                    // this. On a miss, return None -> the watcher backs off
                    // rather than acting on a stale URL.
                    primary_for_read.try_read().ok().and_then(|g| g.clone())
                },
                FAILOVER_AFTER_MS,
                FAILOVER_RETRY_BACKOFF,
                move |dead_url| {
                    let client = action_client.clone();
                    async move { client.failover_to_next_relay(dead_url).await }
                },
            )
            .await;
        });
        if let Ok(mut guard) = self.failover_watcher_abort.lock() {
            // One watcher per Client build; abort any prior one so a
            // double-spawn can never stack immortal watchers.
            if let Some(prev) = guard.replace(watcher.abort_handle()) {
                prev.abort();
            }
        }
    }

    /// T8b action: migrate the pinned primary off `dead_url` to the next
    /// advertised relay.
    ///
    /// Steps, in order:
    /// 1. Pick the first [`Self::advertised_relays`] entry that is not
    ///    `dead_url`. None -> fire [`RelayFailoverEvent::Failed`] and return
    ///    `Err(())` so the watcher backs off.
    /// 2. [`crate::transport::MultiHomeTransport::replace_primary`] to the
    ///    candidate. On error, fire [`RelayFailoverEvent::Failed`] and
    ///    return `Err(())`.
    /// 3. Update the live `primary_relay_url` to the candidate so the
    ///    publish + send paths advertise it.
    /// 4. Republish the pair record at the new relay (best-effort).
    /// 5. Prune `dead_url` from the advertised list + regenerate the share
    ///    card (best-effort).
    /// 6. Fire [`RelayFailoverEvent::Migrated`] with the old + new URLs.
    ///
    /// Returns `Ok(new_url)` on a successful migration so the watcher
    /// re-subscribes to the new slot 0 and keeps watching (sticky: no
    /// auto-recover to `dead_url`).
    async fn failover_to_next_relay(&self, dead_url: String) -> std::result::Result<String, ()> {
        let Some(mh) = self.multi_home.as_ref() else {
            return Err(());
        };
        let candidate = {
            let advertised = self.advertised_relays.read().await;
            // SSRF boundary: candidates come from the user's OWN
            // advertised-relay list (self-configured), never from
            // contact-supplied hints, so this dial is deliberately not
            // guard_relay_url-gated — pointing at one's own LAN relay
            // is legitimate here.
            //
            // Denylist-aware candidate filtering is deferred: the transport
            // layer's DenylistQuery is a documented no-op until the
            // trust-client relocation lands, so a filter here would be
            // decorative. Tracked follow-up.
            pick_failover_candidate(&advertised, &dead_url)
        };
        let Some(candidate) = candidate else {
            log::warn!(
                "[chat] home-relay failover: primary {dead_url} is down and no fallback relay is configured"
            );
            self.fire_failover_callback(RelayFailoverEvent::Failed { dead: dead_url })
                .await;
            return Err(());
        };

        if let Err(e) = mh.replace_primary(&candidate).await {
            log::warn!(
                "[chat] home-relay failover: replace_primary to {candidate} failed: {e}; keeping watch"
            );
            self.fire_failover_callback(RelayFailoverEvent::Failed { dead: dead_url })
                .await;
            return Err(());
        }

        // Slot 0 is now the candidate. Point the live primary at it BEFORE
        // the republish so the pair record advertises the new relay.
        *self.primary_relay_url.write().await = Some(candidate.clone());
        log::info!("[chat] home-relay failover: migrated primary {dead_url} -> {candidate}");

        // Best-effort republish at the new relay so peers rediscover us.
        if let Err(e) = self.publish_pair_record().await {
            log::warn!(
                "[chat] home-relay failover: pair-record republish at {candidate} failed: {e}"
            );
        }

        // Prune the dead relay from the advertised list + re-mint the card.
        // Best-effort: a regenerate failure (e.g. the pruned list is empty
        // and fails validation) must not unwind the completed migration.
        let pruned: Vec<String> = {
            let advertised = self.advertised_relays.read().await;
            advertised
                .iter()
                .filter(|r| *r != &dead_url)
                .cloned()
                .collect()
        };
        if !pruned.is_empty() {
            if let Err(e) = self.regenerate_card_with_relays(pruned).await {
                log::warn!("[chat] home-relay failover: card regenerate after pruning {dead_url} failed: {e}");
            }
        }

        self.fire_failover_callback(RelayFailoverEvent::Migrated {
            from: dead_url,
            to: candidate.clone(),
        })
        .await;
        Ok(candidate)
    }

    /// T9: manually migrate the pinned primary (slot 0) to `new_url`.
    ///
    /// This is the user-driven region change, distinct from the automatic
    /// `Self::failover_to_next_relay` in one crucial way: the OLD relay is
    /// still ALIVE, so the T7 forwarding record posted at it can heal stale
    /// senders that still deposit per the old pair record. (Failover cannot
    /// do this -- you can neither POST nor FETCH a forwarding record at a
    /// dead relay.)
    ///
    /// Steps, in order:
    /// 1. Snapshot the current primary (the old url). Reject when the client
    ///    has no chat state or no multi-home transport (relay-mode only API).
    /// 2. `new_url == old` -> `Ok(())` no-op.
    /// 3. [`crate::transport::MultiHomeTransport::replace_primary`] to
    ///    `new_url`. A failed swap leaves slot 0 intact, so the error is
    ///    propagated and no client state is touched.
    /// 4. Update the live `primary_relay_url` to `new_url`.
    /// 5. Republish the pair record at the new relay (best-effort).
    /// 6. Post a signed forwarding record at the OLD (still-alive) relay
    ///    pointing to the new one -- the layer-2 heal (best-effort).
    /// 7. Replace the old url with the new one in `advertised_relays` and
    ///    regenerate the share card (best-effort).
    /// 8. Fire [`RelayFailoverEvent::Migrated`] so the desktop toast +
    ///    persistence path is shared with the failover watcher.
    ///
    /// The failover watcher is NOT restarted: after `replace_primary` the
    /// old slot-0 state stream closes, the watcher's `changed()` errs, and it
    /// re-subscribes to the new slot 0 on its own.
    ///
    /// # Errors
    ///
    /// [`ChatError::Invalid`] when the client is REST-only or has no primary
    /// pinned. [`ChatError::MessageTransport`] when the slot-0 swap fails
    /// (slot 0 stays on the old relay in that case).
    pub async fn migrate_primary(&self, new_url: &str) -> Result<()> {
        let Some(mh) = self.multi_home.as_ref() else {
            return Err(ChatError::Invalid(
                "no relay transport; migrate_primary requires relay mode".into(),
            ));
        };
        let old = {
            let snapshot = self.primary_relay_url.read().await.clone();
            snapshot.ok_or_else(|| {
                ChatError::Invalid("no primary relay pinned; nothing to migrate".into())
            })?
        };

        if new_url == old {
            return Ok(());
        }

        // The old relay is alive: a failed swap MUST leave slot 0 intact, so
        // propagate the error and touch nothing.
        mh.replace_primary(new_url)
            .await
            .map_err(|e| ChatError::MessageTransport(format!("replace_primary: {e}")))?;

        // Slot 0 is now new_url. Point the live primary at it BEFORE the
        // republish so the pair record advertises the new relay.
        *self.primary_relay_url.write().await = Some(new_url.to_owned());
        log::info!("[chat] region migration: migrated primary {old} -> {new_url}");

        // Best-effort republish at the new relay so peers rediscover us.
        if let Err(e) = self.publish_pair_record().await {
            log::warn!("[chat] region migration: pair-record republish at {new_url} failed: {e}");
        }

        // Layer-2 heal: post a forwarding record AT THE OLD (alive) relay
        // pointing to the new one, so stale senders depositing per the old
        // pair record get redirected. Best-effort: the migration already
        // committed.
        self.post_forwarding_at(&old, new_url).await;

        // Replace the old url with the new one in the advertised list +
        // re-mint the card. Best-effort: a regenerate failure (e.g. the
        // swapped list fails validation) must not unwind the committed swap.
        let swapped: Vec<String> = {
            let advertised = self.advertised_relays.read().await;
            advertised
                .iter()
                .map(|r| {
                    if r == &old {
                        new_url.to_owned()
                    } else {
                        r.clone()
                    }
                })
                .collect()
        };
        if !swapped.is_empty() {
            if let Err(e) = self.regenerate_card_with_relays(swapped).await {
                log::warn!(
                    "[chat] region migration: card regenerate after swapping {old} -> {new_url} failed: {e}"
                );
            }
        }

        self.fire_failover_callback(RelayFailoverEvent::Migrated {
            from: old,
            to: new_url.to_owned(),
        })
        .await;
        Ok(())
    }

    /// Best-effort T9 layer-2 heal: build, sign, and POST a forwarding
    /// record at the OLD (still-alive) relay pointing at `new_url`. Logs and
    /// returns on any failure; the migration has already committed.
    async fn post_forwarding_at(&self, old_relay: &str, new_url: &str) {
        let Some(chat) = self.chat.as_ref() else {
            return;
        };
        let old = match url::Url::parse(old_relay) {
            Ok(u) => u,
            Err(e) => {
                log::warn!("[chat] region migration: old relay url parse for forwarding: {e}");
                return;
            }
        };
        let http = crate::relay_http::guarded_client();
        match crate::pair_record::post_forwarding_record(
            &old,
            &chat.identity,
            chat.signer.as_ref(),
            vec![new_url.to_owned()],
            &chat.layout,
            &http,
        )
        .await
        {
            Ok(crate::pair_record::ForwardingOutcome::Written) => {
                log::info!("[chat] region migration: forwarding record posted at {old_relay}");
            }
            Ok(crate::pair_record::ForwardingOutcome::SkippedNoPairRecord) => {}
            Err(e) => {
                log::warn!(
                    "[chat] region migration: forwarding record post at {old_relay} failed: {e}"
                );
            }
        }
    }

    /// Fire the registered failover callback with `event`, if one was
    /// registered. Cloned out under the read guard so the closure runs
    /// without holding the lock.
    async fn fire_failover_callback(&self, event: RelayFailoverEvent) {
        let cb = self.relay_failover_cb.read().await.clone();
        if let Some(cb) = cb {
            cb(event);
        }
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
        let endpoint = messages::Endpoint::new_with_denylist(
            &self.http,
            &self.router,
            self.chat.as_ref().map(|c| &c.identity),
            self.chat.as_ref().map(|c| &c.registry),
            self.chat.as_ref().map(|c| &c.signer),
            self.chat.as_ref().map(|c| &c.layout),
            self.chat.as_ref().map_or([0u8; 32], |c| c.local_machine_id),
            self.chat.as_ref().map(|c| &c.members_singleflight),
            self.denylist.as_ref(),
            Arc::clone(&self.primary_relay_url),
            Arc::clone(&self.neg_resolve_cache),
            Arc::clone(&self.group_kinds),
        );
        // Wire the durable-outbox sink so a private-group send that reaches
        // no member enqueues a retryable bubble per undelivered member
        // instead of hard-failing; the retry driver's RealOutboxTransport
        // re-sends each stored frame on reconnect. REST-only clients (no
        // chat state) leave it unwired -> pre-durability hard-fail behavior.
        match self.chat.as_ref() {
            Some(c) => endpoint.with_outbox(&c.outbox, &c.outbox_tx),
            None => endpoint,
        }
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
    /// behind `Self::multi_home_inbound` at boot. Existing callers
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

    #[allow(clippy::too_many_lines)] // one arm per envelope kind; splitting would scatter the ack decision table
    async fn default_dispatch_one(&self, mut env: InboundEnvelope) {
        // Ack-after-persist: `ack` confirms the transport's stored copy
        // ONLY at terminal outcomes (vault-persisted, provable
        // duplicate, deterministic reject of immutable bytes). Every
        // transient path — StaleEpoch-class frames, bridge dispatch
        // with x0xd down, vault I/O errors — returns WITHOUT
        // confirming, so the relay redelivers within its TTL and the
        // recovery paths (re-key, epoch catch-up) get the frame again.
        let ack = env.ack.take();
        let Some(transit) = env.transit.take() else {
            // No wire envelope: nothing any consumer could ever apply.
            if let Some(a) = &ack {
                a.confirm();
            }
            return;
        };
        if let Some(identity) = self.identity_arc() {
            if hex::encode(transit.sender_agent_id.as_bytes()) == identity.agent_id_hex() {
                // Our own echo: permanently uninteresting.
                if let Some(a) = &ack {
                    a.confirm();
                }
                return;
            }
        }
        if matches!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent
        ) {
            match self.dispatch_inbound_bridge(&transit).await {
                Ok(()) => {
                    if let Some(a) = &ack {
                        a.confirm();
                    }
                }
                // Bridge apply can fail because the local x0xd is
                // down/restarting: hold, redelivery retries it.
                Err(e) => log::warn!("bridge dispatch dropped envelope: {e}"),
            }
            return;
        }
        // M4 Stage 5.3: bridged fediverse public post. Recognised on
        // `kind` BEFORE any seq/gap/denylist logic — it has no
        // conversation, no per-message signature, and the all-zeros
        // sentinel sender, so the conversation path (which requires a
        // group_id + a sender card) would reject it. The decode surfaces
        // it on the public-post broadcast for the UI; a decode failure
        // just drops the envelope.
        if matches!(transit.kind, fetchit_relay_proto::EnvelopeKind::PublicPost) {
            if let Err(e) = self.dispatch_inbound_public_post(&transit) {
                log::warn!("public-post dispatch dropped envelope: {e}");
            }
            // Terminal either way: broadcast is the ephemeral surface
            // (no vault state), and a decode failure is a deterministic
            // verdict on immutable bytes.
            if let Some(a) = &ack {
                a.confirm();
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
            // Deliberate drop: reclaim the stored copy so a blocked
            // sender's backlog doesn't redeliver every reconnect.
            if let Some(a) = &ack {
                a.confirm();
            }
            return;
        }
        // M6.7: a contact proactively pushing its re-signed device roster
        // (after revoking/adding a device). Gated on `kind` after the
        // denylist so a blocked sender's push is dropped like their content;
        // the record's own signature + anti-rollback are the authority.
        if matches!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::PairRecordPush
        ) {
            match self.dispatch_inbound_pair_record_push(&transit).await {
                // Applied (or already-current: the apply is
                // anti-rollback idempotent) — durable, reclaim.
                Ok(()) => {
                    if let Some(a) = &ack {
                        a.confirm();
                    }
                }
                // Could be a vault write failure: hold for redelivery.
                // An invalid push redelivering until TTL is bounded
                // noise; a lost valid push is a real regression.
                Err(e) => log::warn!("pair-record-push dispatch dropped envelope: {e}"),
            }
            return;
        }
        if messages::is_private_group_envelope(&transit) {
            let group_id_hex = transit
                .group_id
                .as_ref()
                .map(|g| hex::encode(g.as_bytes()))
                .unwrap_or_default();
            if group_id_hex.is_empty() {
                // Malformed: no group id can ever appear on redelivery.
                if let Some(a) = &ack {
                    a.confirm();
                }
                return;
            }
            // Persisted and Replay are both terminal (history extended +
            // vault flushed, or provably already held). Errors include
            // the x0xd decrypt failures of a stale/keyless epoch — the
            // exact frames that must redeliver after re-key / epoch
            // catch-up — so they hold the token.
            if self
                .messages()
                .receive_private_group_envelope(&transit, &group_id_hex)
                .await
                .is_ok()
            {
                // Deliver + ack. Do NOT clear Reconnecting here: a successful
                // decrypt only proves we are keyed for THIS frame's epoch, not
                // that we have caught up to the group's current epoch — a
                // delayed old-epoch frame decrypts fine while we are still
                // behind (#297 cross-review F1). Only `recover_group_once`,
                // which drains the group-log to a known target and re-probes,
                // is authoritative for `Live`.
                if let Some(a) = &ack {
                    a.confirm();
                }
            } else {
                // Decrypt failed: a stale / keyless epoch (the StaleEpoch loop).
                // Surface Reconnecting so the shell shows catch-up rather than a
                // silent drop, and HOLD the frame (no ack) for relay
                // redelivery. Trigger the recovery driver toward this frame's
                // epoch (the target so an empty log does not falsely converge);
                // it drains the group-log, applies the missed commits, and
                // clears `Live` once keyed at target.
                self.group_recovery.set_reconnecting(&group_id_hex);
                self.trigger_group_recovery(group_id_hex.clone(), Some(u64::from(transit.epoch)));
            }
        } else if let (Some(identity), Some(registry)) = (self.identity_arc(), self.registry_arc())
        {
            // Pass the outbox handle so a DeliveryReceipt flips the matching
            // outbound bubble to Delivered (engine-side, so this dispatcher
            // gives Android the same Delivered path desktop gets).
            let outbox = self.chat.as_ref().map(|c| &c.outbox);
            let outbox_tx = self.chat.as_ref().map(|c| &c.outbox_tx);
            // Variant-aware: StaleEpoch / KemDecapFailed / missing-card
            // drops are Ok-shaped but NOT terminal — the classifier
            // holds exactly those for redelivery. Err (vault/registry
            // I/O) is transient and also holds.
            if let Ok(dispatch) = crate::conversation::dispatch_inbound_with_outbox(
                transit,
                identity.as_ref(),
                registry.as_ref(),
                outbox,
                outbox_tx,
            )
            .await
            {
                if crate::conversation::confirms_delivery(&dispatch) {
                    if let Some(a) = &ack {
                        a.confirm();
                    }
                }
            }
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

    /// Task #297: current recovery status of a group — `Live` (keyed and
    /// flowing) or `Reconnecting` (a stale-epoch catch-up is in progress).
    /// A group never in trouble reads `Live`. A shell renders this as
    /// "reconnecting to group…" instead of a silently-dead conversation.
    #[must_use]
    pub fn group_recovery_status(
        &self,
        group_id_hex: &str,
    ) -> crate::groups::epoch_recovery::GroupRecoveryStatus {
        self.group_recovery.get(group_id_hex)
    }

    /// Subscribe to per-group recovery status transitions (Live <->
    /// Reconnecting), so a shell reacts without polling. Mirrors
    /// [`Self::subscribe_outbox`].
    #[must_use]
    pub fn subscribe_group_recovery(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::groups::epoch_recovery::GroupStatusEvent> {
        self.group_recovery.subscribe()
    }

    /// Drive the ONE recovery path for a single group one step (#297). The
    /// `EpochBehind` + warm triggers pass `target_epoch = Some(secret_epoch)`
    /// (the inbound frame's epoch we must reach); the wedge-watchdog passes
    /// `None` (drain whatever commits exist and re-check keyed).
    ///
    /// Dispatch (see [`crate::groups::epoch_recovery::EpochRecoveryDriver`]):
    /// keyed + caught up -> `Converged` (status `Live`); keyed but behind ->
    /// fetch + apply group-log commits, re-probe; not keyed -> hand off to
    /// the existing durable pending-join resume ([`Self::drive_pending_joins_once`]).
    ///
    /// The warm path is live over the durable relay group-log (#297 Lane A):
    /// [`LogFetchCommitSource`] fetches the commits (and self-addressed
    /// join-results) with `seq` past our cursor, and `WarmApplier` applies
    /// each through x0xd's signature-verifying apply endpoints
    /// (`apply_metadata_event` / `apply_join_result`) — never a bypass, the
    /// daemon re-runs full membership authority. With no relay configured
    /// the source yields nothing and a behind member falls through to the
    /// cold pending-join resume rather than a false `Live`.
    ///
    /// # Errors
    /// Propagates a probe (`group_self_status`) or cold-resume error.
    pub async fn recover_group_once(
        &self,
        group_id_hex: &str,
        target_epoch: Option<u64>,
    ) -> Result<crate::groups::epoch_recovery::RecoverOutcome> {
        use std::future::Future;

        use crate::groups::epoch_recovery::{
            ColdRecover, EpochRecoveryDriver, GroupState, GroupStateProbe, LogFetchCommitSource,
            X0xdCommitApplier,
        };

        // Production probe: the fork's read-only keyed-status endpoint when
        // the daemon has it, else the stock derivation (roster + durable
        // convergence record + one-shot encrypt probe) — one shared
        // implementation, [`Client::probe_group_state`].
        struct WarmProbe<'a> {
            client: &'a Client,
        }
        impl GroupStateProbe for WarmProbe<'_> {
            fn probe(&self, group_id: &str) -> impl Future<Output = Result<GroupState>> + Send {
                let client = self.client;
                let gid = group_id.to_owned();
                async move { client.probe_group_state(&gid).await }
            }
        }

        // Cold path: delegate to the EXISTING durable pending-join resume
        // — never a parallel loop. Returns whether this group had a record.
        struct ColdViaPendingJoins<'a> {
            client: &'a Client,
        }
        impl ColdRecover for ColdViaPendingJoins<'_> {
            fn recover_cold(&self, group_id: &str) -> impl Future<Output = Result<bool>> + Send {
                let client = self.client;
                let gid = group_id.to_owned();
                async move {
                    let outcomes = client.drive_pending_joins_once().await?;
                    Ok(outcomes.iter().any(|(g, _)| g == &gid))
                }
            }
        }

        // Our own agent id (hex), for classifying a self-addressed
        // join-result. Absent only in daemonless/no-chat builds, where warm
        // recovery cannot run anyway; empty then, so join-results simply
        // never self-target and commits still apply via their author.
        let my_agent_hex = self
            .chat
            .as_ref()
            .map(|c| c.identity.agent_id_hex().to_owned())
            .unwrap_or_default();

        // Warm applier: routes each fetched record to x0xd's
        // signature-verifying apply endpoint (never a bypass; the daemon
        // re-runs full membership authority). Built from the same daemon
        // base URL + token the client's `secure_groups` uses. Carries the
        // shared engine-A latch so a stock daemon's route-level 404 flips
        // it instead of masquerading as a poison record.
        let applier = X0xdCommitApplier::new(
            self.http.base_url(),
            self.http.token().to_owned(),
            my_agent_hex,
            self.engine_a_supported.clone(),
        );

        // The warm lane rides the fork's apply endpoints. Once the daemon is
        // known stock (latch false), hand the driver an empty commit source —
        // the documented no-relay behavior — so a behind member goes straight
        // to the cold resume instead of fetching records it can never apply.
        let warm_relay = if self.engine_a_available() {
            self.relay.clone()
        } else {
            None
        };

        let driver = EpochRecoveryDriver::new_with_cursors(
            LogFetchCommitSource::new(warm_relay),
            applier,
            WarmProbe { client: self },
            ColdViaPendingJoins { client: self },
            self.group_recovery.clone(),
            self.recovery_cursors.clone(),
        );
        driver.recover_once(group_id_hex, target_epoch).await
    }

    /// Spawn a background epoch-recovery pass for `group_id` toward
    /// `target_epoch`, deduplicated so at most one runs per group at a time:
    /// a burst of stale-epoch frames for one group triggers a single pass,
    /// not a storm. The spawned task drops the group from the in-flight set
    /// when it finishes (success or error), so the next stale frame re-arms
    /// it. Fire-and-forget: a recovery error just leaves the group
    /// `Reconnecting` for the next trigger.
    pub fn trigger_group_recovery(&self, group_id: String, target_epoch: Option<u64>) {
        {
            let Ok(mut inflight) = self.recovering.lock() else {
                return;
            };
            if !inflight.insert(group_id.clone()) {
                // Already recovering this group — the in-flight pass will
                // pick up the latest log state; no need to stack another.
                return;
            }
        }
        let client = self.clone();
        tokio::spawn(async move {
            let _ = client.recover_group_once(&group_id, target_epoch).await;
            if let Ok(mut inflight) = client.recovering.lock() {
                inflight.remove(&group_id);
            }
        });
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

    /// Cloneable receiver for outbox change events. Each
    /// [`crate::outbox::OutboxEvent`] is an upsert keyed by `bubble.id`; a
    /// lagging consumer drops the oldest events (`OUTBOX_CHANNEL_CAP`).
    /// `None` when the client has no chat state (REST-only mode). Mirrors
    /// [`Client::subscribe_to_public_posts`].
    #[must_use]
    pub fn subscribe_outbox(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<crate::outbox::OutboxEvent>> {
        self.chat.as_ref().map(|c| c.outbox_tx.subscribe())
    }

    /// Cloneable sender for the outbox broadcast channel that
    /// [`Self::subscribe_outbox`] reads. A shell that drives its OWN
    /// inbound pump -- desktop's Tauri-emitting pump, Android's
    /// `chat_ffi` pump -- hands this (with [`Self::outbox_arc`]) to
    /// [`crate::conversation::dispatch_inbound_with_outbox`] so an
    /// inbound `DeliveryReceipt` marks the matching outbound bubble
    /// Delivered engine-side. The engine's own SSE dispatcher already
    /// wires this; a shell that takes the relay inbound itself bypasses
    /// that dispatcher and so needs the handle. `None` in REST-only mode.
    #[must_use]
    pub fn outbox_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Sender<crate::outbox::OutboxEvent>> {
        self.chat.as_ref().map(|c| c.outbox_tx.clone())
    }

    /// Cloneable handle to the vault-persisted outbox store, paired with
    /// [`Self::outbox_events`] for the same own-inbound-pump shells. Lets
    /// the shell thread the live store into
    /// [`crate::conversation::dispatch_inbound_with_outbox`] so delivery
    /// receipts are applied to the durable outbox (not just the UI),
    /// which stops the retry driver from re-sending an already-delivered
    /// DM on the next presence edge. `None` in REST-only mode.
    #[must_use]
    pub fn outbox_arc(
        &self,
    ) -> Option<std::sync::Arc<tokio::sync::Mutex<crate::outbox::store::OutboxStore>>> {
        self.chat.as_ref().map(|c| c.outbox.clone())
    }

    /// Current outbox contents (all tracked DM bubbles), for a shell to
    /// hydrate its UI on startup before subscribing to live events. Empty
    /// when the client has no chat state.
    pub async fn outbox_snapshot(&self) -> Vec<crate::outbox::OutboxBubble> {
        match self.chat.as_ref() {
            Some(chat) => chat.outbox.lock().await.snapshot(),
            None => Vec::new(),
        }
    }

    /// Enqueue an outbound DM: persist a `Sending` bubble and broadcast it
    /// immediately (optimistic echo), then warm-connect and send. The
    /// bubble's terminal state is recorded via
    /// [`crate::outbox::store::OutboxStore::record_send_outcome`] -- the
    /// same path the retry driver uses, so an initial send and a resend
    /// converge on identical status transitions (and the Delivered-guard).
    /// Returns the client-assigned bubble id.
    ///
    /// `sender_name` is shell-supplied (the engine holds no canonical
    /// display name); `reply_to_message_id` + `attachment` mirror
    /// [`messages::Endpoint::send`].
    ///
    /// # Errors
    ///
    /// [`ChatError::Invalid`] when the client has no chat state -- a
    /// misconfiguration, since `enqueue_dm` requires a `data_dir`/relay
    /// client.
    pub async fn enqueue_dm(
        &self,
        peer: &crate::identity::AgentId,
        body: &str,
        sender_name: &str,
        reply_to_message_id: Option<&str>,
        attachment: Option<&crate::attachment::Attachment>,
    ) -> Result<String> {
        let Some(chat) = self.chat.as_ref() else {
            return Err(ChatError::Invalid(
                "enqueue_dm requires chat state (no data_dir/relay configured)".into(),
            ));
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let bubble = crate::outbox::OutboxBubble {
            id: crate::outbox::new_bubble_id(),
            peer: peer.clone(),
            body: body.to_owned(),
            status: crate::outbox::OutboxStatus::Sending,
            message_id: None,
            enqueued_at_ms: now_ms,
            last_error: None,
            group: None,
        };
        // Optimistic echo: persist + broadcast BEFORE the send so the UI
        // shows the bubble the instant the user hits enter (desktop parity).
        {
            let mut outbox = chat.outbox.lock().await;
            outbox.upsert(bubble.clone());
        }
        let _ = chat.outbox_tx.send(crate::outbox::OutboxEvent {
            bubble: bubble.clone(),
        });
        // Warm-connect (best-effort), then send.
        let _ = self.messages().connect(peer).await;
        let result = self
            .messages()
            .send(peer, body, sender_name, reply_to_message_id, attachment)
            .await;
        let (message_id, error) = match &result {
            Ok(mid) => (mid.clone(), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let updated = {
            let mut outbox = chat.outbox.lock().await;
            outbox.record_send_outcome(&bubble.id, message_id, error)
        };
        if let Some(u) = updated {
            let _ = chat
                .outbox_tx
                .send(crate::outbox::OutboxEvent { bubble: u });
        }
        Ok(bubble.id)
    }

    /// Send an M2.5 bridge envelope — a signed x0xd
    /// `NamedGroupMetadataEvent` JSON body — to a single peer over the
    /// relay path, gated by the per-group consent + reachability rule
    /// from §5 of the bridge spec.
    ///
    /// Routing flow:
    /// - If direct gossip can reach `recipient_agent_id_hex` for
    ///   `group_id` (via [`crate::groups_reachability::ReachabilityCache::lookup`]), returns
    ///   `Ok(BridgeDecision::LetGossipCarry)` without sending — the
    ///   caller is expected to publish the event to local x0xd
    ///   (gossip will deliver it).
    /// - Otherwise consults [`crate::groups_reachability::BridgeConsentStore::lookup`] for
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
        // Snapshot the live primary (interior-mutable post-T8b) before the
        // closure so the fallback hint tracks slot 0 across a failover.
        let primary_snapshot = self.primary_relay_url.read().await.clone();
        let hints = crate::messages::StoredContactCard::resolve_recipient_hints(
            &chat.layout,
            recipient_agent_id_hex,
        )
        .ok()
        .flatten()
        .or_else(|| {
            primary_snapshot
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
        // Engine A: a cross-NAT JOIN bridge carries the joiner's ML-KEM
        // key as a reply hint. Re-inject so x0xd applies the native
        // member_joined (it enforces the joiner signature + single-use
        // invite_secret), then reply with the authoritative inline-welcome
        // MemberAdded so the NAT'd joiner converges.
        if wrapper.joiner_kem_pubkey.is_some() {
            // Admission gate. v1 auto-admits every valid-invite bearer
            // (x0xd is the cryptographic backstop); a denylist /
            // manual-accept policy refuses the apply here instead.
            //
            // The metadata gossip mesh is off (v1 + dual-NAT), so a plain
            // `/publish` would reach no local apply path -- the owner must
            // apply the joiner's `member_joined` DIRECTLY. x0xd re-runs full
            // membership authority on it (ML-DSA sig + single-use
            // `invite_secret` + inviter-gate), so this is a local-delivery
            // shortcut, never a validation bypass.
            // The bridge topic carries only the first 16 hex of the group
            // id; the full id the apply path needs comes from the event
            // body itself (x0xd's member_joined `group_id`).
            let event_bytes = base64::engine::general_purpose::STANDARD
                .decode(wrapper.payload_b64.as_bytes())
                .map_err(|e| ChatError::Invalid(format!("join-bridge: payload b64: {e}")))?;
            let group_id = crate::groups::join_bridge::group_id_from_member_joined(&event_bytes)
                .ok_or_else(|| {
                    ChatError::Invalid(
                        "join-bridge: captured member_joined has no group_id".to_owned(),
                    )
                })?;
            let sender_hex = hex::encode(transit.sender_agent_id.as_bytes());
            match secure
                .apply_metadata_event(&group_id, &wrapper.payload_b64, &sender_hex)
                .await
            {
                Ok(_) => {}
                Err(e) if crate::groups::engine_a::route_miss_404(&e) => {
                    // Stock daemon: no engine-A apply door. Drop the bridged
                    // event — the stock join machinery (direct-plane
                    // join-result listener + peer relay) owns delivery.
                    self.mark_engine_a_unsupported();
                    return Ok(());
                }
                Err(e) if crate::groups::engine_a::apply_conflict_409(&e) => {
                    // The applier declined without a handler error: for a
                    // bridged member_joined that means REPLAY — the joiner
                    // retried because our earlier reply never landed, and
                    // this member is already admitted. What the joiner is
                    // missing is not admission but the STAGED join-result,
                    // so fall through to the reply poll and re-serve it. If
                    // the stage has expired the poll times out and logs (the
                    // upstream already-active re-stage gap owns that tail).
                    log::info!(
                        "[chat] engine-a owner: replayed member_joined for an admitted member; re-serving staged join-result"
                    );
                }
                Err(e) => return Err(ChatError::from(e)),
            }
            // The owner reply polls the local x0xd for the staged
            // join-result (up to seconds) and the inbound dispatch pump is
            // serial, so run it off-thread to avoid head-of-line blocking.
            let me = self.clone();
            let joiner_agent = *transit.sender_agent_id.as_bytes();
            tokio::spawn(async move {
                match me.reply_to_bridged_join(wrapper, joiner_agent).await {
                    Ok(()) => {
                        log::info!("[chat] engine-a owner reply: bridged join-result to joiner");
                    }
                    Err(e) => log::warn!("[chat] engine-a owner reply failed: {e}"),
                }
            });
            return Ok(());
        }

        // Reverse engine-A: a bridged `member_added` for THIS node is its
        // own join-result (the owner's reply). APPLY it on the local x0xd --
        // gossip-off, the daemon's own join-result fetch DMs the NAT'd owner
        // and never lands, so this push IS the delivery. The daemon runs the
        // same verifying path as an inbound join-result DM (`member` == this
        // node, `sender` == the group creator, then the MLS Welcome applies),
        // so the owner agent id passed is `transit.sender_agent_id` -- the
        // AUTHENTICATED bridge sender, symmetric with the forward apply arm
        // above. The owner's `MemberAdded` carries `group_id` as the STABLE
        // id the daemon keys by. Every other bridged metadata event is a
        // normal publish.
        let event_bytes = base64::engine::general_purpose::STANDARD
            .decode(wrapper.payload_b64.as_bytes())
            .map_err(|e| ChatError::Invalid(format!("bridge: payload b64: {e}")))?;
        if let Some((stable_group_id, member)) =
            crate::groups::join_bridge::member_added_self_target(
                &event_bytes,
                identity.agent_id_hex(),
            )
        {
            let owner_hex = hex::encode(transit.sender_agent_id.as_bytes());
            match secure
                .apply_join_result(&stable_group_id, &member, &wrapper.payload_b64, &owner_hex)
                .await
            {
                Ok(_) => {}
                Err(e) if crate::groups::engine_a::route_miss_404(&e) => {
                    // Stock daemon: no engine-A apply door. Leave the durable
                    // pending-join intact — the join has NOT converged; the
                    // stock join machinery / cold resume owns it from here.
                    self.mark_engine_a_unsupported();
                    return Ok(());
                }
                Err(e) if crate::groups::engine_a::apply_conflict_409(&e) => {
                    // A duplicate owner reply (re-bridged after a retried
                    // join) the daemon already converged past — or a decline
                    // of a stale result. Neither warrants failing the
                    // dispatch pump, and neither PROVES convergence, so
                    // leave the durable pending-join for the resume driver /
                    // keyed probe to settle authoritatively.
                    log::info!(
                        "[chat] engine-a joiner: local apply declined a join-result replay; leaving pending-join to the resume driver"
                    );
                    return Ok(());
                }
                Err(e) => return Err(ChatError::from(e)),
            }
            // Applying the owner's join-result IS the keying event: this
            // durable pending-join has converged. Remove the intent so the
            // resume driver stops re-pulling it. This is the authoritative
            // `ActiveKeyed` signal -- a read-only keyed probe on `/members`
            // is the deferred x0xd ask, so until it lands convergence is
            // observed here at the apply site, not by polling. Best-effort:
            // a stale record only costs one idempotent re-bridge next tick.
            if let Ok(store) = self.pending_join_store() {
                let _ = store.remove(&stable_group_id);
            }
            // Refresh the durable convergence record the stock keyed-probe
            // reads (epoch is settled by the next probe; 0 = "unknown yet").
            self.note_group_converged(&stable_group_id, 0);
            return Ok(());
        }

        secure
            .publish(&wrapper.topic, &wrapper.payload_b64)
            .await
            .map_err(ChatError::from)?;
        Ok(())
    }

    /// Owner-side engine-A reply: after re-injecting a bridged
    /// `member_joined`, poll the local x0xd for the staged authoritative
    /// `MemberAdded` (with the `TreeKEM` Welcome inlined by the
    /// `join-result` endpoint), then bridge it back to the NAT'd joiner
    /// sealed to the `joiner_kem_pubkey` hint. The joiner's stock x0xd
    /// applies it via its inline-welcome path and converges -- no
    /// network Welcome-blob pull, which a dual-NAT path can't complete.
    ///
    /// Runs on a spawned task; errors are logged, not propagated.
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] in REST-only mode, on a non-metadata
    ///   topic, a missing `member_agent_id`, or a malformed reply.
    /// - [`ChatError::ShareCardMissing`] / transport errors from the
    ///   sealed bridge back to the joiner.
    async fn reply_to_bridged_join(
        &self,
        wrapper: crate::groups::bridge::X0xdGroupMetadataEventWrapper,
        joiner_agent: [u8; 32],
    ) -> Result<()> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let joiner_kem = wrapper
            .joiner_kem_pubkey
            .as_deref()
            .ok_or_else(|| ChatError::Invalid("join reply: wrapper missing joiner kem".into()))?;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(wrapper.payload_b64.as_bytes())
            .map_err(|e| ChatError::Invalid(format!("join reply: payload b64: {e}")))?;
        // x0xd keys pending_join_results by {stable_group_id}:{member}, not
        // the mls group_id, so poll the staged join-result by the STABLE id
        // (a separate field in the member_joined payload).
        let stable_group_id = crate::groups::join_bridge::stable_group_id_from_member_joined(
            &payload,
        )
        .ok_or_else(|| {
            ChatError::Invalid("join reply: member_joined has no stable_group_id".to_owned())
        })?;
        let joiner_hex = crate::groups::join_bridge::member_agent_id_from_member_joined(&payload)
            .ok_or_else(|| {
            ChatError::Invalid("join reply: member_joined has no member_agent_id".into())
        })?;
        // Defense in depth (mirrors the joiner-emit member==self check): in
        // Plan A the joiner bridges its OWN member_joined, so the bridge
        // sender is always the member for a legitimate join. Refusing
        // sender != member avoids routing a MemberAdded reply to a
        // non-member and denies a third-party-relay DoS amplification. The
        // native x0xd signature + the HPKE-sealed Welcome already make a
        // secret leak impossible; this just declines the wasted reply.
        if !hex::encode(joiner_agent).eq_ignore_ascii_case(&joiner_hex) {
            return Err(ChatError::Invalid(format!(
                "join reply: bridge sender {} != member {joiner_hex}; refusing reply",
                hex::encode(joiner_agent),
            )));
        }
        // Poll the LOCAL x0xd for the self-contained inline-welcome event.
        let result = self
            .fetch_inline_join_result(&stable_group_id, &joiner_hex)
            .await?;
        let event = result
            .get("event")
            .ok_or_else(|| ChatError::Invalid("join reply: GET response missing event".into()))?;
        let event_bytes = serde_json::to_vec(event)
            .map_err(|e| ChatError::Invalid(format!("join reply: event encode: {e}")))?;
        // Durable-first (#297 Lane A): deposit the Welcome-bearing event
        // (JoinResult, gated to the joiner) and its commit-only projection
        // (Commit, broadcast) onto the relay group-log BEFORE the live
        // sends, so a member that misses the live frame warm-recovers from
        // the log instead of desyncing. Best-effort: a log failure never
        // blocks the live reply, it only leaves recovery on the cold path.
        self.append_join_reply_log(&payload, joiner_agent, event);
        // Seal the inline-welcome MemberAdded to the joiner kem (R3) and
        // bridge it back on the same metadata topic; the reply needs no
        // further kem hint.
        let reply = crate::groups::bridge::X0xdGroupMetadataEventWrapper {
            topic: wrapper.topic.clone(),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&event_bytes),
            joiner_kem_pubkey: None,
        };
        let conv = crate::groups::bridge::seal_and_sign_bridge_wrapper(
            &joiner_agent,
            joiner_kem,
            &reply,
            &chat.signer.agent_id(),
            &chat.local_machine_id,
            chat.signer.as_ref(),
        )
        .await?;
        let recipient = crate::identity::AgentId(hex::encode(joiner_agent));
        let transport_out = crate::transport::OutboundEnvelope {
            kind: crate::transport::OutboundKind::Dm,
            from_machine_id: Some(chat.local_machine_id),
            payload: Vec::new(),
            timestamp_ms: conv.envelope.timestamp_ms,
            transit: Some(conv.envelope),
        };
        let primary_snapshot = self.primary_relay_url.read().await.clone();
        let hints =
            crate::messages::StoredContactCard::resolve_recipient_hints(&chat.layout, &joiner_hex)
                .ok()
                .flatten()
                .or_else(|| {
                    primary_snapshot
                        .as_deref()
                        .map(|url| crate::card::RendezvousHintsV1 {
                            relays: vec![url.to_owned()],
                        })
                });
        self.router
            .send(&recipient, transport_out, hints.as_ref())
            .await?;

        // R3 ("group only knows the first 2"): the joiner now has its
        // Welcome, but EXISTING members never see the resulting
        // `MemberAdded` commit cross-NAT, so they never advance their
        // TreeKEM epoch or learn the new leaf. Fan the SAME authoritative
        // staged event -- stripped to commit-only -- to them over the relay.
        self.fan_member_added_to_existing(
            &payload,
            event,
            &wrapper.topic,
            joiner_agent,
            chat,
            primary_snapshot.as_deref(),
        )
        .await?;
        Ok(())
    }

    /// Best-effort producer append onto the durable relay group-log
    /// (#297 Lane A): the Welcome-bearing event as a recipient-gated
    /// `JoinResult` plus its commit-only projection as a broadcast
    /// `Commit`. Never fails the caller -- a log failure only leaves a
    /// future recovery on the cold path -- and is a no-op with no relay.
    fn append_join_reply_log(
        &self,
        member_joined_payload: &[u8],
        joiner_agent: [u8; 32],
        event: &serde_json::Value,
    ) {
        let Some(relay) = self.relay.as_ref() else {
            return;
        };
        let Some(mls_gid) =
            crate::groups::join_bridge::group_id_from_member_joined(member_joined_payload)
        else {
            log::warn!("[chat] group-log skipped: member_joined has no group_id");
            return;
        };
        match crate::groups::group_log::join_reply_log_intents(&mls_gid, joiner_agent, event) {
            Ok(intents) => {
                for i in intents {
                    if let Err(e) = relay.log_append(i.group_id, i.kind, i.recipient, i.payload) {
                        log::warn!("[chat] group-log append failed: {e}");
                    }
                }
            }
            Err(e) => log::warn!("[chat] group-log intents failed: {e}"),
        }
    }

    /// R3 fan-out: bridge the commit-only `MemberAdded` to the group's
    /// EXISTING members so they advance their `TreeKEM` epoch and learn the
    /// new leaf. The joiner is excluded (it already gets the full
    /// Welcome-bearing event from [`Self::reply_to_bridged_join`]); the
    /// owner (self / actor) is excluded too.
    ///
    /// The roster is fetched by the MLS `group_id` (the
    /// `/groups/<id>/members` map key), NOT the stable id used for
    /// `/join-result`: x0xd's `get_named_group_members` resolves its path id
    /// strictly by `mls_group_id`, while `pending_join_results` keys by
    /// `stable_group_id`. Both ids ride the captured `member_joined`
    /// payload; [`crate::groups::join_bridge::group_id_from_member_joined`]
    /// extracts the MLS one.
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] when `member_joined` carries no `group_id`
    ///   or it fails [`crate::groups::GroupId::parse`].
    /// - Whatever `GET /groups/<id>/members` surfaces.
    /// - Seal / sign / transport errors from
    ///   [`crate::groups::dispatch::dispatch_member_added_bridge`].
    async fn fan_member_added_to_existing(
        &self,
        member_joined_payload: &[u8],
        event: &serde_json::Value,
        metadata_topic: &str,
        joiner_agent: [u8; 32],
        chat: &ChatState,
        primary_relay_url: Option<&str>,
    ) -> Result<()> {
        let mls_group_id =
            crate::groups::join_bridge::group_id_from_member_joined(member_joined_payload)
                .ok_or_else(|| {
                    ChatError::Invalid("join reply: member_joined has no group_id".into())
                })?;
        let group_id = crate::groups::GroupId::parse(&mls_group_id)?;
        let roster = self.groups().members(&group_id).await?;
        // Map the hex roster to raw 32-byte agent ids. A roster entry that
        // is not 32-byte hex can't be a recipient -- skip it rather than
        // failing the whole fan-out (defense in depth; x0xd emits 64-hex).
        let active_member_aids: Vec<[u8; 32]> = roster
            .iter()
            .filter_map(|aid| {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(&aid.0, &mut bytes)
                    .ok()
                    .map(|()| bytes)
            })
            .collect();
        let commit_only = crate::groups::bridge_member_added::commit_only_member_added(event);
        crate::groups::dispatch::dispatch_member_added_bridge(
            chat.signer.as_ref(),
            &self.router,
            &chat.layout,
            metadata_topic,
            chat.signer.agent_id(),
            joiner_agent,
            commit_only,
            &active_member_aids,
            chat.local_machine_id,
            primary_relay_url,
        )
        .await
    }

    /// Poll the local x0xd `GET /groups/<id>/join-result/<member>` until
    /// the staged inline-welcome `MemberAdded` is available, backing off
    /// across the apply window. A `404` means "not staged yet" (the apply
    /// after re-inject is async); any other error propagates.
    async fn fetch_inline_join_result(
        &self,
        group_id: &str,
        joiner_hex: &str,
    ) -> Result<serde_json::Value> {
        let path = format!("/groups/{group_id}/join-result/{joiner_hex}");
        let delays = [
            Duration::from_millis(150),
            Duration::from_millis(250),
            Duration::from_millis(400),
            Duration::from_millis(600),
            Duration::from_millis(900),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ];
        for delay in delays {
            match self.http.get_json::<serde_json::Value>(&path).await {
                Ok(v) => return Ok(v),
                Err(ChatError::Daemon { status: 404, .. }) => {
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(ChatError::Invalid(
            "join reply: inline join-result not staged within the poll window".into(),
        ))
    }

    /// Cross-NAT private-group join (engine A). Lets a NAT'd joiner
    /// converge into a group whose owner is also NAT'd, where the x0xd
    /// metadata-gossip join anchor never reaches the joiner directly:
    ///
    /// 1. `POST /groups/join` -- the patched x0xd mints the joiner
    ///    `TreeKEM` `KeyPackage`, signs the joiner-authored
    ///    `member_joined`, and returns it INLINE in the response. This is
    ///    mesh-independent on purpose: capturing the event off the gossip
    ///    SSE starves whenever the joiner's gossip mesh has not formed,
    ///    which is the exact cold/NAT case engine A targets.
    /// 2. bridge that native (joiner-signed) event sealed to the owner via
    ///    [`crate::groups::join_bridge::emit_self_join_bridge`] (with the
    ///    joiner's ML-KEM key as the reply hint) so the owner re-injects
    ///    it through [`Self::dispatch_inbound_bridge`] and x0xd applies
    ///    the authoritative add,
    /// 3. wait for local membership to converge -- the owner's post-apply
    ///    commit rides the same bridge back, sealed to the hint.
    ///
    /// This is the bridged counterpart to
    /// [`crate::groups::Endpoint::join`]; callers on a warm direct-gossip
    /// path can still use the plain join.
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] in REST-only mode (no chat state), when the
    ///   join response carries no inline `member_joined` (unpatched daemon
    ///   or sign failure), or when the event carries no `inviter_agent_id`.
    /// - [`ChatError::ShareCardMissing`] when the owner's contact card
    ///   (its KEM key) is not on disk -- the joiner must import it first.
    /// - Propagates join / seal / transport / membership errors.
    pub async fn join_group_bridged(
        &self,
        invite: &groups::GroupInvite,
        display_name: Option<&str>,
    ) -> Result<groups::Group> {
        // 1. POST /groups/join: the patched x0xd mints + signs the
        //    joiner's member_joined and returns it inline. This is
        //    mesh-independent on purpose -- capturing it off the gossip
        //    SSE starves whenever the joiner's gossip mesh has not formed
        //    (the exact cold/NAT case engine A targets).
        let (group, self_join) = self.groups().join_post(invite, display_name).await?;
        let captured = self_join.ok_or_else(|| {
            ChatError::Invalid(
                "join-bridge: x0xd join response carried no member_joined \
                 (event sign failed, or daemon lacks the inline-member_joined patch)"
                    .into(),
            )
        })?;

        // 2-5. Seal the captured member_joined to the owner over the relay
        //      and wait for the bridged-back commit to flip us active.
        self.bridge_captured_join(&group, &captured).await?;
        Ok(group)
    }

    /// The engine-A bridge tail: given the joiner's already-captured,
    /// signed `member_joined` (from a prior
    /// [`crate::groups::Endpoint::join_post`]), seal it to the group owner
    /// over the relay and wait for the owner's bridged-back commit to flip
    /// this joiner active.
    ///
    /// Shared by [`Self::join_group_bridged`] (which does its own
    /// `join_post` first) and [`Self::join_group_auto`] (which falls back
    /// here after a native warm-gossip convergence timeout, reusing the
    /// captured event so the single-use invite is consumed exactly once).
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] in REST-only mode (no chat state), or when
    ///   the captured `member_joined` carries no `inviter_agent_id`.
    /// - [`ChatError::ShareCardMissing`] when the owner KEM cannot be
    ///   resolved from a local card or the relay pair-record.
    /// - Propagates seal / transport / membership errors.
    async fn bridge_captured_join(
        &self,
        group: &groups::Group,
        captured: &crate::groups::join_bridge::CapturedSelfJoin,
    ) -> Result<()> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let self_id = crate::identity::AgentId(chat.identity.agent_id_hex().to_owned());
        let local_agent_id = chat.signer.agent_id();

        // Resolve the owner (the event's inviter) + bridge sealed to it.
        let owner_hex =
            crate::groups::join_bridge::inviter_agent_id_from_member_joined(&captured.payload)
                .ok_or_else(|| {
                    ChatError::Invalid(
                        "join-bridge: captured member_joined has no inviter_agent_id".into(),
                    )
                })?;
        let primary_snapshot = self.primary_relay_url.read().await.clone();
        // The owner is the invite signer; a cold invite (group address with
        // no prior contact exchange) carries no local card, so resolve the
        // owner KEM from its relay pair-record when no card is imported --
        // the joiner needs it to seal the bridged member_joined.
        let relay = primary_snapshot
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok());
        let http = crate::relay_http::guarded_client();
        let owner_kem = crate::groups::bridge::resolve_owner_kem_with_fallback(
            &chat.layout,
            relay.as_ref(),
            &http,
            &owner_hex,
        )
        .await?;
        let hints =
            crate::messages::StoredContactCard::resolve_recipient_hints(&chat.layout, &owner_hex)
                .ok()
                .flatten()
                .or_else(|| {
                    primary_snapshot
                        .as_deref()
                        .map(|url| crate::card::RendezvousHintsV1 {
                            relays: vec![url.to_owned()],
                        })
                });
        crate::groups::join_bridge::emit_self_join_bridge(
            captured,
            &owner_hex,
            &owner_kem,
            chat.identity.kem_public_key(),
            &local_agent_id,
            &chat.local_machine_id,
            chat.signer.as_ref(),
            &self.router,
            hints.as_ref(),
        )
        .await?;

        // Wait for the bridged-back owner commit to flip us active.
        self.groups()
            .wait_membership(
                &group.group_id,
                &self_id,
                crate::groups::membership::membership_wait_timeout(),
                crate::groups::membership::MEMBERSHIP_POLL_INTERVAL,
            )
            .await?;
        Ok(())
    }

    /// Join a private group with the v1 shared join policy: best-effort
    /// native warm-gossip convergence, then ALWAYS deliver the joiner's
    /// `TreeKEM` Welcome over the engine-A relay bridge.
    ///
    /// Roster convergence does NOT imply the joiner holds the group's
    /// `TreeKEM` keys: the roster arrives over gossip, but the Welcome is a
    /// separate x0x content-pull that fails cross-NAT, leaving the joiner
    /// roster-active but keyless and unable to encrypt (a tracked x0x
    /// limitation, api-reference.md ADR-0012). x0xd exposes no keys-ready
    /// signal to poll, so rather than guess, the join always re-delivers the
    /// Welcome over the relay (`Self::bridge_captured_join`) -- the
    /// sanctioned workaround -- which guarantees the joiner can encrypt.
    ///
    /// The native [`crate::groups::Endpoint::join`] membership wait still
    /// runs FIRST (best-effort, outcome non-gating): it lets gossip deliver
    /// the joiner's `member_joined` to the owner so the *existing* members
    /// converge natively. Skipping it would deliver the join to the owner
    /// only via `apply_metadata_event`, which does NOT gossip-publish,
    /// forcing existing members onto the R3 relay fan-out instead.
    ///
    /// The single `join_post` is consumed exactly once: the captured
    /// `member_joined` is reused by the bridge, never a second `join_post`
    /// that would spend the single-use invite. Idempotent on the warm path:
    /// the owner re-applies (`409`) and re-sends a Welcome the joiner may
    /// already hold.
    ///
    /// # Errors
    /// - Propagates `join_post` errors (malformed invite, self-join,
    ///   network failure) directly.
    /// - [`ChatError::Invalid`] when the daemon returned no inline
    ///   `member_joined` (unpatched daemon), so the Welcome cannot be
    ///   bridged.
    /// - Otherwise propagates the bridge's error.
    pub async fn join_group_auto(
        &self,
        invite: &groups::GroupInvite,
        display_name: Option<&str>,
    ) -> Result<groups::Group> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let self_id = crate::identity::AgentId(chat.identity.agent_id_hex().to_owned());

        // Consume the single-use invite exactly once; the captured
        // member_joined is reused by the bridge fallback below so we never
        // re-`join_post` (which would spend an already-consumed invite).
        let (group, captured) = self.groups().join_post(invite, display_name).await?;
        let group_id = group.group_id.clone();
        let native_wait = crate::groups::membership::native_first_wait();

        Self::run_native_then_bridge(
            captured,
            move || async move {
                self.groups()
                    .wait_membership(
                        &group_id,
                        &self_id,
                        native_wait,
                        crate::groups::membership::MEMBERSHIP_POLL_INTERVAL,
                    )
                    .await
            },
            |cap| {
                let group = &group;
                async move { self.bridge_captured_join(group, &cap).await }
            },
        )
        .await?;
        Ok(group)
    }

    /// Open the durable pending-join store under the chat data dir.
    fn pending_join_store(&self) -> Result<crate::groups::pending_join::PendingJoinStore> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("durable join requires chat state".into()))?;
        crate::groups::pending_join::PendingJoinStore::open(chat.layout.root.join("pending_joins"))
    }

    /// Open the durable convergence-record store under the chat data dir —
    /// the stock-daemon replacement input for the fork's `/secure/self`
    /// keyed probe (see [`crate::groups::convergence`]).
    fn convergence_store(&self) -> Result<crate::groups::convergence::ConvergenceStore> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("convergence store requires chat state".into()))?;
        crate::groups::convergence::ConvergenceStore::open(chat.layout.root.join("converged"))
    }

    /// True until the daemon proves it lacks the fork's engine-A apply
    /// endpoints (route-level 404). A fork daemon never trips this, so it
    /// costs nothing there.
    pub(crate) fn engine_a_available(&self) -> bool {
        *self.engine_a_supported.get().unwrap_or(&true)
    }

    /// Latch "this daemon has no engine-A endpoints" — logged once, on the
    /// first route-level 404. From here the bridge arms drop relayed
    /// events (the stock daemon's direct-plane join machinery owns
    /// delivery) and warm recovery goes straight to the cold resume.
    pub(crate) fn mark_engine_a_unsupported(&self) {
        if self.engine_a_supported.set(false).is_ok() {
            log::warn!(
                "[chat] engine-a: daemon has no apply endpoints (stock x0xd); \
                 relay-bridged group events disabled, native delivery owns joins"
            );
        }
    }

    /// Group keyed/roster/epoch state, tolerant of a stock daemon.
    ///
    /// Fork daemon: one read of `GET /groups/:id/secure/self`. Stock
    /// daemon (probe answers 404 => `None`): derive the same three facts
    /// from stock surfaces — `in_roster` from the members list, `keyed`
    /// from the durable convergence record, and when the record is absent
    /// for a roster-listed member (fresh install / wiped app data) settle
    /// it with a single 1-byte `secure/encrypt` probe. That probe burns
    /// one sender ratchet generation, which is why it runs only on this
    /// rare recovery path and its success immediately re-seeds the record
    /// so the next probe is free. `epoch` is the record's last
    /// observation on the stock path — advisory for behind-detection,
    /// never authorization.
    pub(crate) async fn probe_group_state(
        &self,
        group_id_hex: &str,
    ) -> Result<crate::groups::epoch_recovery::GroupState> {
        use crate::groups::epoch_recovery::GroupState;

        let secure = self.secure_groups()?;
        if let Some(st) = secure
            .group_self_status(group_id_hex)
            .await
            .map_err(ChatError::from)?
        {
            return Ok(GroupState {
                keyed: st.keyed,
                in_roster: st.in_roster,
                epoch: st.epoch,
            });
        }

        // Stock daemon. Roster first: not listed means not keyed either.
        let parsed = groups::GroupId::parse(group_id_hex)?;
        let members = self.groups().members(&parsed).await?;
        let self_hex = self
            .local_agent_id_hex()
            .ok_or_else(|| ChatError::Invalid("group probe requires chat state".into()))?;
        if !members.iter().any(|a| a.0 == self_hex) {
            return Ok(GroupState {
                keyed: false,
                in_roster: false,
                epoch: 0,
            });
        }

        let store = self.convergence_store()?;
        let stale_record = match store.get(group_id_hex)? {
            // A settled record answers for free — the hot path.
            Some(rec) if rec.epoch > 0 => {
                return Ok(GroupState {
                    keyed: true,
                    in_roster: true,
                    epoch: rec.epoch,
                });
            }
            // Epoch-0 record = "converged, epoch not yet observed" (written
            // at the apply site, which does not see the epoch). Fall through
            // to the one-shot probe to settle it; if the probe refuses, the
            // record was stale and must go.
            Some(_) => true,
            None => false,
        };

        // Roster-listed with no settled convergence record: one-shot encrypt
        // probe settles keyed-vs-keyless and (re)seeds the record on success.
        match secure.encrypt(group_id_hex, &[0u8]).await {
            Ok(frame) => {
                let epoch = u64::from(frame.secret_epoch);
                store.record(group_id_hex, epoch, chat_now_ms())?;
                Ok(GroupState {
                    keyed: true,
                    in_roster: true,
                    epoch,
                })
            }
            Err(e) => {
                log::debug!(
                    "[chat] stock keyed-probe: encrypt refused for {group_id_hex}: {e} \
                     (treating as not keyed)"
                );
                if stale_record {
                    // The unsettled record claimed keyed over a daemon that
                    // refuses to encrypt — drop it so recovery stops trusting it.
                    let _ = store.remove(group_id_hex);
                }
                Ok(GroupState {
                    keyed: false,
                    in_roster: true,
                    epoch: 0,
                })
            }
        }
    }

    /// Note that this daemon converged on `group_id_hex` (join completed /
    /// keys held), refreshing the durable convergence record the stock
    /// keyed-probe reads. Quiet best-effort: recording is advisory
    /// recovery state, and a failed write must never fail the join that
    /// just succeeded.
    fn note_group_converged(&self, group_id_hex: &str, epoch: u64) {
        match self.convergence_store() {
            Ok(store) => {
                if let Err(e) = store.record(group_id_hex, epoch, chat_now_ms()) {
                    log::debug!("[chat] convergence record write failed for {group_id_hex}: {e}");
                }
            }
            Err(e) => log::debug!("[chat] convergence store unavailable: {e}"),
        }
    }

    /// Group ids with a durable pending join still in progress — shells show
    /// these as "joining…" rather than a failure.
    ///
    /// # Errors
    /// Propagates a store listing error.
    pub fn pending_joins(&self) -> Result<Vec<String>> {
        Ok(self
            .pending_join_store()?
            .list()?
            .into_iter()
            .filter(|r| !r.is_terminal())
            .map(|r| r.group_id)
            .collect())
    }

    /// Build a persistable pending-join record from the one captured event,
    /// caching the owner + own KEM keys so a re-bridge needs no re-resolution.
    async fn build_pending_join(
        &self,
        gid_hex: &str,
        invite_hash: &str,
        captured: &crate::groups::join_bridge::CapturedSelfJoin,
    ) -> Result<crate::groups::pending_join::PendingJoin> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("durable join requires chat state".into()))?;
        let owner_hex =
            crate::groups::join_bridge::inviter_agent_id_from_member_joined(&captured.payload)
                .ok_or_else(|| {
                    ChatError::Invalid("durable join: captured event has no inviter".into())
                })?;
        let primary_snapshot = self.primary_relay_url.read().await.clone();
        let relay = primary_snapshot
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok());
        let http = crate::relay_http::guarded_client();
        let owner_kem = crate::groups::bridge::resolve_owner_kem_with_fallback(
            &chat.layout,
            relay.as_ref(),
            &http,
            &owner_hex,
        )
        .await?;
        // Resolve the owner's rendezvous relay hints now (same resolution the
        // first bridge uses), with a primary-relay fallback, and cache the
        // relay URLs on the record. A resume re-bridge then routes to the owner
        // even when they are not on our primary relay -- never a `None` hint
        // (PR #7 B1). Empty only if neither a card nor a primary relay exists.
        let owner_relay_hints =
            crate::messages::StoredContactCard::resolve_recipient_hints(&chat.layout, &owner_hex)
                .ok()
                .flatten()
                .or_else(|| {
                    primary_snapshot
                        .as_deref()
                        .map(|url| crate::card::RendezvousHintsV1 {
                            relays: vec![url.to_owned()],
                        })
                })
                .map(|h| h.relays)
                .unwrap_or_default();
        Ok(crate::groups::pending_join::PendingJoin::new(
            gid_hex.to_owned(),
            b64.encode(&captured.payload),
            captured.topic.clone(),
            invite_hash.to_owned(),
            owner_hex,
            b64.encode(&owner_kem),
            owner_relay_hints,
            b64.encode(chat.identity.kem_public_key()),
            crate::groups::pending_join_driver::now_ms(),
        ))
    }

    /// Re-bridge a saved pending-join to its owner — byte-identical to the
    /// first bridge, using the record's cached KEM keys, and NEVER
    /// `join_post`. The driver's re-drive primitive.
    async fn rebridge_pending(
        &self,
        record: &crate::groups::pending_join::PendingJoin,
    ) -> Result<()> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("durable join requires chat state".into()))?;
        let payload = b64
            .decode(&record.captured_event_b64)
            .map_err(|e| ChatError::Invalid(format!("pending-join payload b64: {e}")))?;
        let owner_kem = b64
            .decode(&record.owner_kem_pubkey_b64)
            .map_err(|e| ChatError::Invalid(format!("pending-join owner_kem b64: {e}")))?;
        let joiner_kem = b64
            .decode(&record.joiner_kem_pubkey_b64)
            .map_err(|e| ChatError::Invalid(format!("pending-join joiner_kem b64: {e}")))?;
        let captured = crate::groups::join_bridge::CapturedSelfJoin {
            topic: record.captured_topic.clone(),
            payload,
        };
        let local_agent_id = chat.signer.agent_id();
        // Reconstruct the owner's cached rendezvous hints so the re-bridge
        // routes to the owner even when they are off our primary relay (PR #7
        // B1) -- never a `None` hint, unless the record predates the field and
        // no primary is set, in which case the router's primary-relay fallback
        // still applies.
        let hints = if record.owner_relay_hints.is_empty() {
            None
        } else {
            Some(crate::card::RendezvousHintsV1 {
                relays: record.owner_relay_hints.clone(),
            })
        };
        crate::groups::join_bridge::emit_self_join_bridge(
            &captured,
            &record.owner_agent_id,
            &owner_kem,
            &joiner_kem,
            &local_agent_id,
            &chat.local_machine_id,
            chat.signer.as_ref(),
            &self.router,
            hints.as_ref(),
        )
        .await
    }

    /// Durable join: `join_post` once, persist the intent, and return
    /// [`groups::JoinOutcome`]. `Pending` is NOT an error — the persisted
    /// record is completed by [`Self::drive_pending_joins_once`] (shell-pumped)
    /// when the owner's daemon is next reachable, with no user action and no
    /// second `join_post` (the single-use invite is spent at most once, G1).
    /// This is the INITIAL-join entrypoint; resume is the driver, not a
    /// re-call of this method.
    ///
    /// # Errors
    /// Propagates `join_post` errors (malformed invite, self-join). A
    /// non-convergence is returned as `Pending`, never an error.
    pub async fn join_group_durable(
        &self,
        invite: &groups::GroupInvite,
        display_name: Option<&str>,
    ) -> Result<groups::JoinOutcome> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let self_id = crate::identity::AgentId(chat.identity.agent_id_hex().to_owned());
        let store = self.pending_join_store()?;

        // Resume pre-check (PR #7 #1): `GroupInvite` is opaque, so key the
        // guard on `sha256(invite)`. If a non-terminal intent already exists
        // for this exact invite, a second `join_post` would spend the
        // single-use secret again — the bug this method exists to prevent. So
        // return the in-progress `Pending` and let the driver finish it. This
        // makes G1 structural at the ENTRY, not just inside the driver.
        let invite_hash = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(invite.0.as_bytes());
            hex::encode(h.finalize())
        };
        if let Some(existing) = store
            .list()?
            .into_iter()
            .find(|r| !r.is_terminal() && r.invite_hash == invite_hash)
        {
            return Ok(groups::JoinOutcome::Pending {
                group_id: existing.group_id,
            });
        }

        // Exactly one join_post; the captured event is reused by the bridge
        // and persisted so a resume never re-`join_post`s (G1).
        let (group, captured) = self.groups().join_post(invite, display_name).await?;
        let gid_hex = group.group_id.as_str().to_owned();
        // A durable record lands on disk only when the daemon returned the
        // inline captured event (persisted below). This governs the
        // transient-error arm: a `Pending` with no record has nothing to
        // resume, so it must propagate instead (PR #7 B2).
        let persisted = captured.is_some();

        // Persist the intent BEFORE the wait so a timeout leaves a durable
        // record the driver completes. Needs the inline captured event; an
        // unpatched daemon that returns none just gets the plain wait below.
        // PR #7 #2: a persist failure must PROPAGATE — returning `Pending`
        // with no record on disk means the invite is spent but the driver has
        // nothing to resume (the pre-PR silent-never-completes failure).
        if let Some(cap) = &captured {
            let record = self.build_pending_join(&gid_hex, &invite_hash, cap).await?;
            store.upsert(&record)?;
        }

        let native_wait = crate::groups::membership::native_first_wait();
        let outcome = Self::run_native_then_bridge(
            captured,
            {
                let gid = group.group_id.clone();
                let self_id = self_id.clone();
                move || async move {
                    self.groups()
                        .wait_membership(
                            &gid,
                            &self_id,
                            native_wait,
                            crate::groups::membership::MEMBERSHIP_POLL_INTERVAL,
                        )
                        .await
                }
            },
            |cap| {
                let group = &group;
                async move { self.bridge_captured_join(group, &cap).await }
            },
        )
        .await;

        match outcome {
            Ok(()) => {
                // Roster convergence is NOT a keyed check: a roster-active
                // joiner can still be keyless (the Welcome pull is a
                // separate, cross-NAT-fragile step). Leave the durable
                // record — the apply-site removal fires at the authoritative
                // keyed moment (join-result applied), and the driver
                // re-drives if the Welcome never lands. Removing here would
                // strand a keyless "joined" group with no safety net.
                Ok(groups::JoinOutcome::Converged(group))
            }
            Err(ChatError::JoinerNotConverged { .. }) => {
                Ok(groups::JoinOutcome::Pending { group_id: gid_hex })
            }
            Err(e) => {
                // Post-`join_post`: the single-use invite is already spent, so
                // a bridge/wait failure here is transient (owner offline, relay
                // blip) -- a malformed or already-consumed invite fails at
                // `join_post` above, never here. Keep the durable record and
                // report Pending so the driver completes it; removing it would
                // strand a spent invite (PR #7 B2). Only when NO record was
                // persisted (an unpatched daemon returned no inline event) is
                // there nothing to resume, so propagate the error instead.
                if persisted {
                    Ok(groups::JoinOutcome::Pending { group_id: gid_hex })
                } else {
                    let _ = store.remove(&gid_hex);
                    Err(e)
                }
            }
        }
    }

    /// Pump the durable pending-join resume once: for each record DUE for a
    /// retry ([`is_due`](crate::groups::pending_join_driver::is_due), N1),
    /// probe membership and either converge (remove) or re-bridge the SAVED
    /// event (never `join_post`). Shells call this on startup and on a timer /
    /// presence-online, mirroring the outbox driver.
    ///
    /// # Errors
    /// Propagates a store listing error.
    pub async fn drive_pending_joins_once(
        &self,
    ) -> Result<Vec<(String, crate::groups::pending_join_driver::DriveOutcome)>> {
        use std::future::Future;

        use crate::groups::pending_join::PendingJoin;
        use crate::groups::pending_join_driver::{
            is_due, now_ms, DriveOutcome, JoinBridge, MembershipProbe, MembershipStatus,
            PendingJoinDriver, SystemClock,
        };

        // Production probe. Preferred path: the read-only keyed-check
        // (`GET /groups/<id>/secure/self`, the x0x `keyed_epoch` endpoint) --
        // `keyed` => `ActiveKeyed`, roster-listed-but-not-keyed =>
        // `ListedButUnkeyed`, not-in-roster => `Absent`. It is a pure read: it
        // burns no MLS generation and cannot re-spend the single-use invite --
        // the reason the earlier decrypt / `apply_join_result`-409 probes were
        // rejected (apply_* RE-RUN the `invite_secret`, and a cold-start joiner
        // has no stored frame to decrypt). Fallback, when the daemon predates
        // the endpoint (404) or is unreachable: roster-only, where any
        // in-roster member reads as `ListedButUnkeyed` -- never a false
        // `ActiveKeyed`. In BOTH modes the inbound-apply removal
        // (`dispatch_inbound_bridge`) stays the authoritative convergence that
        // retires the record; the probe only decides re-bridge vs re-request
        // between ticks (PR #7 review #3 + the `keyed_epoch` follow-up).
        struct Probe<'a> {
            client: &'a Client,
        }
        impl MembershipProbe for Probe<'_> {
            fn status(
                &self,
                group_id: &str,
            ) -> impl Future<Output = std::result::Result<MembershipStatus, ChatError>> + Send
            {
                let client = self.client;
                let gid = group_id.to_owned();
                async move {
                    let self_hex = client
                        .chat
                        .as_ref()
                        .map(|c| c.identity.agent_id_hex().to_owned())
                        .ok_or_else(|| {
                            ChatError::Invalid("durable join requires chat state".into())
                        })?;
                    let parsed = crate::groups::GroupId::parse(&gid)?;
                    // One shared derivation, fork and stock alike
                    // ([`Client::probe_group_state`]): the fork's read-only
                    // secure/self when present, else roster + the durable
                    // convergence record (+ one-shot encrypt probe). `keyed`
                    // => ActiveKeyed; roster-listed but not keyed =>
                    // ListedButUnkeyed; not in roster => Absent. On a probe
                    // ERROR (daemon unreachable), fall to roster-only —
                    // never a false ActiveKeyed.
                    if let Ok(st) = client.probe_group_state(&gid).await {
                        return Ok(if st.keyed {
                            MembershipStatus::ActiveKeyed
                        } else if st.in_roster {
                            MembershipStatus::ListedButUnkeyed
                        } else {
                            MembershipStatus::Absent
                        });
                    }
                    let list = client.groups().members(&parsed).await?;
                    Ok(if list.iter().any(|a| a.0 == self_hex) {
                        MembershipStatus::ListedButUnkeyed
                    } else {
                        MembershipStatus::Absent
                    })
                }
            }
        }

        // Production bridge: both arms re-emit the SAVED event (never
        // `join_post`, G1). The owner's `reply_to_bridged_join` re-applies the
        // member_joined and re-stages+re-bridges the Welcome on every received
        // bridge, so re-bridging IS the Welcome re-request. `request_join_result`
        // is kept a distinct entrypoint (Bob's Decision 3) so the warm
        // epoch-catch-up recovery can extend it without touching the cold path.
        // KNOWN LIMITATION (PR #7 M1): today `request_join_result` aliases
        // `rebridge`, and the owner's re-stage is a no-op outside the relay's
        // 10-minute JoinResult TTL, so a resume later than that window relies on
        // the owner still holding the staged result. It converges inside the
        // window; the durable relay Commit-log re-stage (the warm-recovery
        // build) lifts the limit. Tracked, not blocking.
        struct Bridge<'a> {
            client: &'a Client,
        }
        impl JoinBridge for Bridge<'_> {
            fn rebridge(
                &self,
                record: &PendingJoin,
            ) -> impl Future<Output = std::result::Result<(), ChatError>> + Send {
                let client = self.client;
                let record = record.clone();
                async move { client.rebridge_pending(&record).await }
            }
            fn request_join_result(
                &self,
                record: &PendingJoin,
            ) -> impl Future<Output = std::result::Result<(), ChatError>> + Send {
                let client = self.client;
                let record = record.clone();
                async move { client.rebridge_pending(&record).await }
            }
        }

        if self.chat.is_none() {
            return Ok(Vec::new());
        }
        let store = self.pending_join_store()?;
        let driver = PendingJoinDriver::new(
            self.pending_join_store()?,
            Bridge { client: self },
            Probe { client: self },
            SystemClock,
        );

        // N1: the LOOP gates by `is_due`; `drive_once` acts on every call, so
        // only hand it records past their backoff. A not-yet-due record stays
        // Pending, untouched.
        let mut out = Vec::new();
        for record in store.list()? {
            if record.is_terminal() {
                continue;
            }
            if !is_due(&record, now_ms()) {
                out.push((record.group_id.clone(), DriveOutcome::Pending));
                continue;
            }
            let gid = record.group_id.clone();
            out.push((gid, driver.drive_once(record).await?));
        }
        Ok(out)
    }

    /// Pure native-best-effort-then-always-bridge orchestration over a
    /// single `join_post`. Factored from [`Self::join_group_auto`] so the
    /// policy is unit-testable without a live daemon or relay.
    ///
    /// `native` runs the warm-gossip membership wait BEST-EFFORT: its
    /// outcome only logs and never gates the bridge, so gossip can deliver
    /// the join to the owner (existing members converge natively) before the
    /// bridge runs. `bridge` then ALWAYS runs to GUARANTEE the joiner's
    /// `TreeKEM` keys, because x0xd exposes no keys-ready signal and a
    /// roster-active joiner can still be keyless (the Welcome is a separate
    /// cross-NAT-fragile pull). `captured` is the joiner's inline
    /// `member_joined` from the one `join_post`. With a captured event the
    /// bridge ALWAYS runs (guaranteed keys). Without one -- an unpatched
    /// daemon that returns no inline `member_joined`, so no bridge is
    /// possible -- a native success is accepted on its own (native is the
    /// only path that daemon offers), and only a native failure with no
    /// captured event is the clear cannot-bridge error.
    ///
    /// # Errors
    /// Returns [`ChatError::Invalid`] when native convergence failed AND
    /// there is no captured event to bridge with; otherwise returns the
    /// `bridge` result (or `Ok` for a captured-less native success).
    async fn run_native_then_bridge<NF, NFut, BF, BFut>(
        captured: Option<crate::groups::join_bridge::CapturedSelfJoin>,
        native: NF,
        bridge: BF,
    ) -> Result<()>
    where
        NF: FnOnce() -> NFut,
        NFut: std::future::Future<Output = Result<()>>,
        BF: FnOnce(crate::groups::join_bridge::CapturedSelfJoin) -> BFut,
        BFut: std::future::Future<Output = Result<()>>,
    {
        // Best-effort native warm-gossip convergence: lets gossip carry the
        // join to the owner so EXISTING members converge natively. The
        // outcome does not gate the bridge -- a roster-active joiner can
        // still be keyless (the Welcome is a separate, cross-NAT-fragile
        // pull), so the bridge below runs to guarantee the keys.
        let native_result = native().await;
        if let Err(ref native_err) = native_result {
            log::warn!(
                "[chat] group join: native warm-gossip convergence did not land \
                 ({native_err}); bridging the Welcome over the relay anyway"
            );
        }

        match captured {
            // Patched daemon: always deliver the Welcome over the relay
            // bridge so the joiner is guaranteed encryptable, even when
            // native looked converged (roster-active != keys-applied).
            Some(captured) => bridge(captured).await,
            // Unpatched daemon: no inline member_joined exists to bridge, so
            // the engine-A path is unavailable. Native is the only path that
            // daemon offers -- accept its success, surface its failure.
            None => native_result.map_err(|native_err| {
                ChatError::Invalid(format!(
                    "group join: native convergence failed ({native_err}) and the daemon \
                     returned no inline member_joined, so the Welcome cannot be bridged"
                ))
            }),
        }
    }

    /// Drain an inbound [`fetchit_relay_proto::EnvelopeKind::PublicPost`] envelope: decode the
    /// [`fetchit_relay_proto::PublicPostPayload`] wrapper and surface it on the public-post
    /// broadcast that [`Self::subscribe_to_public_posts`] hands out.
    ///
    /// `PublicPost` is the SOLE envelope kind exempt from the chat
    /// sig/KEM verify regime — its body is `application/activity+json`,
    /// not chat ciphertext, and its attribution
    /// (`PublicPostPayload::verified_actor_url`) was verified by the
    /// relay at the inbox HTTP-Signature boundary (the client cannot
    /// verify HTTP signatures itself; see `crates/fetchit-chat/SECURITY.md`
    /// caveat 8). The exemption is structural: the envelope carries no
    /// signature/KEM/nonce and the all-zeros sentinel sender. Dispatch is
    /// driven by `kind` so a DM can never be smuggled through this path.
    ///
    /// Returns the decoded `PublicPostDelivery` (also broadcast). A
    /// send with no subscribers is intentionally not an error — public
    /// posts are live-only.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when the envelope kind isn't `PublicPost`,
    /// the client was built without chat state, or the wrapper fails to
    /// decode.
    pub fn dispatch_inbound_public_post(
        &self,
        transit: &fetchit_relay_proto::TransitEnvelope,
    ) -> Result<PublicPostDelivery> {
        if transit.kind != fetchit_relay_proto::EnvelopeKind::PublicPost {
            return Err(ChatError::Invalid(format!(
                "dispatch_inbound_public_post called on kind={:?}",
                transit.kind
            )));
        }
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let payload = fetchit_relay_proto::PublicPostPayload::from_ciphertext(&transit.ciphertext)
            .map_err(|e| ChatError::Invalid(format!("public-post wrapper decode: {e}")))?;
        let delivery = PublicPostDelivery {
            verified_actor_url: payload.verified_actor_url,
            activity_json: payload.activity_json,
        };
        // Live-only fan-out: a send with zero subscribers returns
        // Err(SendError), intentionally ignored (no UI attached yet).
        let _ = chat.public_post_tx.send(delivery.clone());
        Ok(delivery)
    }

    /// M6.7: apply a proactively-pushed [`PairRecordV4`](fetchit_relay_proto::pair_record::PairRecordV4)
    /// from a contact whose device set changed (revoke/add).
    ///
    /// The push is unsealed and public, so the record's OWN user signature
    /// plus the anti-rollback revision check are the only authority (see
    /// [`crate::pair_record_v4::accept_pushed_pair_record_v4`]). The pushing
    /// contact must be a known M6 contact — the sender's `user_id` is resolved
    /// from their stored card, and an unknown sender is ignored so a stranger
    /// cannot fill the cache with records for users we do not track. On an
    /// accepted (strictly-newer, verified) record, cancels any pending outbox
    /// sends to a device the new revision revoked, mirroring the M6.3
    /// `fanout_targets` cleanup.
    ///
    /// # Errors
    /// A malformed sender id, a wrapper/record decode failure, or a cache I/O
    /// error. A push from a non-contact or an unaccepted revision is a
    /// success (`Ok(())`) with no state change.
    async fn dispatch_inbound_pair_record_push(
        &self,
        transit: &fetchit_relay_proto::TransitEnvelope,
    ) -> Result<()> {
        let Some(chat) = self.chat.as_ref() else {
            return Ok(());
        };
        let layout = &chat.layout;
        let data_dir = &layout.root;

        // Only a known M6 contact (whose imported card carried an x0x user_id)
        // has a device fabric to converge; ignore anyone else.
        let sender_hex = hex::encode(transit.sender_agent_id.as_bytes());
        let Some(user_id_hex) = messages::contact_user_id_hex(layout, &sender_hex)? else {
            return Ok(());
        };

        let record = decode_pushed_pair_record_v4(&transit.ciphertext)?;

        // Verify + anti-rollback + cache. On accept over an existing record,
        // cancel pending sends to any device the new revision revoked.
        if let Some((Some(old), new)) =
            crate::pair_record_v4::accept_pushed_pair_record_v4(data_dir, &user_id_hex, record)?
        {
            let removed = crate::pair_record_v4::removed_device_agents(&old, &new);
            if !removed.is_empty() {
                chat.outbox.lock().await.drop_bubbles_for_peers(&removed);
            }
        }
        Ok(())
    }

    /// M6.7 SEND: proactively push our freshly re-signed
    /// [`PairRecordV4`](fetchit_relay_proto::pair_record::PairRecordV4) to
    /// every active contact after our own device set changes (a device was
    /// revoked or added), so contacts converge on the new roster without
    /// waiting to re-resolve us.
    ///
    /// Recipients are the distinct active peer devices across every cached
    /// conversation (own device and revoked devices excluded, cross-conversation
    /// duplicates collapsed). Each push rides an
    /// [`crate::transport::OutboundKind::Dm`]-shaped envelope whose transit
    /// `kind` stays [`fetchit_relay_proto::EnvelopeKind::PairRecordPush`], so a
    /// relay forwards it and the receiver re-discriminates it back into
    /// `dispatch_inbound_pair_record_push`. The record carries its own
    /// user signature and is public, so the push travels UNSEALED — there is no
    /// per-recipient seal (see [`fetchit_relay_proto::pair_record_push`]).
    ///
    /// Best-effort: a transport failure to one contact is logged and skipped.
    /// Returns the number of recipients the router accepted the push for.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when the client was built without chat state or
    /// the record cannot be JSON-encoded. A per-recipient transport failure is
    /// NOT an error — it is counted out of the returned total.
    pub async fn push_pair_record_to_active_contacts(
        &self,
        record: &fetchit_relay_proto::pair_record::PairRecordV4,
    ) -> Result<usize> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        // Serialize once: the record carries its own user signature, so every
        // recipient re-verifies these exact bytes (matches the receive-side
        // serde_json decode in `dispatch_inbound_pair_record_push`).
        let record_bytes = serde_json::to_vec(record)
            .map_err(|e| ChatError::Invalid(format!("encode pair record for push: {e}")))?;

        let local_agent_hex = chat.identity.agent_id_hex().to_owned();
        let sender_agent_id =
            fetchit_relay_proto::identity::AgentId::from_bytes(chat.signer.agent_id());
        let sender_machine_id =
            fetchit_relay_proto::identity::MachineId::from_bytes(chat.local_machine_id);

        let conversations = chat.registry.snapshot_cached().await;
        let recipients = pair_record_push_recipients(&conversations, &local_agent_hex);
        if recipients.is_empty() {
            return Ok(0);
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        // Snapshot the live primary once so the per-recipient fallback hint
        // tracks slot 0 across a mid-loop failover (same pattern as the bridge
        // send path).
        let primary_snapshot = self.primary_relay_url.read().await.clone();

        let mut sent = 0usize;
        for recipient_hex in recipients {
            let transit = match fetchit_relay_proto::TransitEnvelope::pair_record_push(
                sender_agent_id,
                sender_machine_id,
                record_bytes.clone(),
                now_ms,
            ) {
                Ok(env) => env,
                Err(e) => {
                    log::warn!("pair-record-push encode for {recipient_hex}: {e}");
                    continue;
                }
            };
            let transport_out = crate::transport::OutboundEnvelope {
                kind: crate::transport::OutboundKind::Dm,
                from_machine_id: Some(chat.local_machine_id),
                payload: Vec::new(),
                timestamp_ms: now_ms,
                transit: Some(transit),
            };
            let recipient = crate::identity::AgentId(recipient_hex.clone());
            let hints = crate::messages::StoredContactCard::resolve_recipient_hints(
                &chat.layout,
                &recipient_hex,
            )
            .ok()
            .flatten()
            .or_else(|| {
                primary_snapshot
                    .as_deref()
                    .map(|url| crate::card::RendezvousHintsV1 {
                        relays: vec![url.to_owned()],
                    })
            });
            match self
                .router
                .send(&recipient, transport_out, hints.as_ref())
                .await
            {
                Ok(_) => sent += 1,
                Err(e) => log::debug!("pair-record-push to {recipient_hex}: {e}"),
            }
        }
        Ok(sent)
    }

    /// Spawn the M2.5 SSE reachability recorder: a background task that
    /// consumes `/events`, watches for `NamedGroupMetadataEvent` gossip
    /// frames, and records direct-gossip reachability into
    /// [`crate::groups_reachability::ReachabilityCache`] for `(group, sender)`. Events that match
    /// a recent [`crate::groups_reachability::BridgeInboundShadow`] entry are skipped, and
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

    /// Start the engine-owned outbox retry loop. Boot-sweeps orphaned
    /// in-flight sends, then on each peer offline->online edge re-sends that
    /// peer's retryable bubbles (warming the link first), and runs the 24h
    /// timeout sweep hourly. Returns the task handle; `None` for a client
    /// with no chat state. Dropping the handle does not stop the loop
    /// (fire-and-forget, like the dispatcher); abort it to stop.
    ///
    /// `name_provider` supplies the sender display name at send time -- the
    /// engine holds no canonical name (it lives in the shell's settings),
    /// so desktop reads it from settings and Android wires its own. The SAME
    /// source should feed [`Client::enqueue_dm`]'s `sender_name` so an
    /// initial send and its later retries agree on the name.
    pub fn start_outbox_driver(
        &self,
        name_provider: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let chat = self.chat.as_ref()?;
        // Manual-retry channel: cap 1 + try_send => coalescing (one pending
        // kick suffices; extra Retry taps are dropped). Publish the sender so
        // Client::retry_outbox can reach this spawned run-loop.
        let (retry_tx, mut retry_rx) = tokio::sync::mpsc::channel::<()>(1);
        if let Ok(mut slot) = chat.outbox_retry_tx.lock() {
            *slot = Some(retry_tx);
        }
        let process_start_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        // No-send-before-registered: gate flushes on the primary relay
        // reaching ConnState::Connected. On a wss client a flush fired before
        // registration surfaces AllRelaysUnreachable and crash-loops; the gate
        // holds the flush until the relay is ready. REST/LAN-only clients have
        // no relay state and the gate is permanently ready.
        let ready_gate = Arc::new(RelayReadyGate {
            relay_state: self.relay_connection_state(),
        });
        let driver = crate::outbox::driver::OutboxDriver::new(
            chat.outbox.clone(),
            chat.outbox_tx.clone(),
            RealOutboxTransport {
                client: self.clone(),
                name_provider,
            },
            process_start_ms,
        )
        .with_ready_gate(ready_gate);
        let client = self.clone();
        Some(tokio::spawn(async move {
            const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
            const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
            const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);
            driver.boot_sweep().await;
            let mut backoff = MIN_BACKOFF;
            let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
            sweep.tick().await; // consume the immediate first tick (boot_sweep already ran)
            loop {
                let mut stream = match client.events().await {
                    Ok(s) => {
                        // Reset backoff on a fresh subscribe so a later
                        // failure restarts at the floor.
                        backoff = MIN_BACKOFF;
                        s
                    }
                    Err(e) => {
                        log::warn!(
                            "outbox driver: open /events failed: {e}; retrying in {backoff:?}",
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                };
                loop {
                    tokio::select! {
                        maybe_event = stream.next() => {
                            match maybe_event {
                                Some(Ok(Event::Presence(t))) => {
                                    driver
                                        .on_presence(&t.agent_id, t.event == "online")
                                        .await;
                                }
                                Some(Ok(_)) => {}
                                Some(Err(e)) => {
                                    log::warn!("outbox driver: stream error: {e}; reopening");
                                    break;
                                }
                                None => break,
                            }
                        }
                        _ = sweep.tick() => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                            driver.sweep_timeouts(now).await;
                        }
                        maybe_retry = retry_rx.recv() => {
                            match maybe_retry {
                                // Manual Retry: flush every peer's retryable
                                // bubbles (= desktop outboxDriver.flushAll).
                                Some(()) => driver.flush_all().await,
                                // Sender dropped (client gone); reopen loop.
                                None => break,
                            }
                        }
                    }
                }
            }
        }))
    }

    /// Kick the outbox retry loop to re-send every retryable bubble now
    /// (the shell's "Retry" button). Fire-and-forget + coalescing: a no-op
    /// when a kick is already pending, when the driver has not been started,
    /// or when there is no chat state. Mirrors desktop `outboxDriver.flushAll`.
    pub fn retry_outbox(&self) {
        if let Some(chat) = self.chat.as_ref() {
            if let Ok(slot) = chat.outbox_retry_tx.lock() {
                if let Some(tx) = slot.as_ref() {
                    let _ = tx.try_send(());
                }
            }
        }
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

    /// Whether this client has a wired multi-home transport (slot 0 / a
    /// pinned primary relay). `true` only for relay-mode clients;
    /// REST-only / LAN-only builds return `false`. The desktop region
    /// switch consults this to decide between a clean
    /// [`Self::migrate_primary`] hot-swap and a full rebuild.
    #[must_use]
    pub fn has_multi_home(&self) -> bool {
        self.multi_home.is_some()
    }

    /// Publish a fresh signed [`fetchit_relay_proto::pair_record::PairRecordV1`]
    /// to the configured relay's `POST /v1/pair-record` endpoint.
    ///
    /// On a 409 `WatermarkReject` response the method observes the
    /// relay's current watermark, computes a new `issued_at_ms`, rebuilds
    /// the record, and retries **once**. A second 409 is a hard error.
    ///
    /// The `advertised_relays` list sent in the record is the single
    /// configured relay URL (the full multi-relay list is a later task;
    /// 1..=4 entries are valid per the proto spec).
    ///
    /// Returns `Ok(())` when the relay accepted the record. No-op when
    /// the client was built without a relay URL or without chat state.
    ///
    /// # Errors
    ///
    /// [`ChatError::Invalid`] when the relay returns a second 409, or
    /// on other non-2xx responses. [`ChatError::Transport`] on connection
    /// failure.
    pub async fn publish_pair_record(&self) -> Result<()> {
        let Some(chat) = self.chat.as_ref() else {
            return Ok(());
        };
        // Snapshot the live primary (interior-mutable post-T8b): after a
        // home-relay failover this publishes the NEW primary so peers
        // discover the migrated rendezvous, not the dead one.
        let primary_snapshot = self.primary_relay_url.read().await.clone();
        let Some(relay_str) = primary_snapshot.as_deref() else {
            return Ok(());
        };
        let relay = url::Url::parse(relay_str)
            .map_err(|e| ChatError::Invalid(format!("relay url: {e}")))?;
        let advertised_relays = vec![relay_str.to_owned()];
        let agent_hex = chat.identity.agent_id_hex().to_owned();

        // The publisher's own x0x machine id, carried in the pointer record
        // so a pointer-URI importer can reconstruct a card x0x >= 0.29
        // accepts (its /agent/card/import requires `machine_id`). Best-effort:
        // an empty string on lookup failure keeps the field legacy-shaped —
        // the record still publishes + verifies (machine_id is unsigned), and
        // only newer importers that need the field are affected.
        let machine_id = self
            .identity()
            .me()
            .await
            .map(|id| id.machine_id)
            .unwrap_or_default();

        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            // 0 (not u64::MAX) on the unreachable overflow branch: feeding
            // u64::MAX into the watermark would persist the corrupt sentinel
            // and brick publishing. next_issued_at_ms handles wall=0 fine.
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));

        let issued = crate::pair_record::next_issued_at_ms(&chat.layout, &agent_hex, wall_ms)?;
        let record = crate::pair_record::build_signed_pair_record(
            &chat.identity,
            chat.signer.as_ref(),
            advertised_relays.clone(),
            issued,
            machine_id.clone(),
        )
        .await?;

        let http = crate::relay_http::guarded_client();
        let outcome = crate::pair_record::post_pair_record(&relay, &record, &http).await?;
        if let crate::pair_record::PostOutcome::WatermarkReject {
            current_issued_at_ms,
        } = outcome
        {
            crate::pair_record::observe_external_watermark(
                &chat.layout,
                &agent_hex,
                current_issued_at_ms,
            )?;
            let wall_ms2 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
            let issued2 =
                crate::pair_record::next_issued_at_ms(&chat.layout, &agent_hex, wall_ms2)?;
            let record2 = crate::pair_record::build_signed_pair_record(
                &chat.identity,
                chat.signer.as_ref(),
                advertised_relays,
                issued2,
                machine_id.clone(),
            )
            .await?;
            if let crate::pair_record::PostOutcome::WatermarkReject { .. } =
                crate::pair_record::post_pair_record(&relay, &record2, &http).await?
            {
                return Err(ChatError::Invalid(
                    "pair-record publish rejected twice by relay watermark guard".into(),
                ));
            }
        }

        // M6.2: also republish the account's cached user-signed device-list
        // record (v4) to the primary, verbatim. A no-op for accounts without a
        // minted device list, so the V1 path above is unaffected pre-M6.
        // Best-effort: a v4 relay failure degrades per-device DIRECTNESS, not
        // account DELIVERY (DM fanout still hits every listed device, and a
        // failed-over device catches up via the M6.6 devices-group sync), so
        // it must never fail the V1 publish that just succeeded.
        if let Err(e) =
            crate::pair_record_v4::republish_cached_pair_record_v4(&chat.layout.root, &relay, &http)
                .await
        {
            log::warn!("[chat] v4 pair-record republish failed (non-fatal): {e}");
        }
        Ok(())
    }

    /// Import a contact from a `x0x://pair/<agent_id_hex>?r=<relay>...` URI.
    ///
    /// Parses the URI, rejects importing your own agent id, walks the
    /// advertised relays in order calling
    /// [`crate::pair::fetch_pair_record_by_id`] on each, and on the first
    /// verified record persists a [`crate::messages::StoredContactCard`]
    /// and runs the x0xd legacy import via
    /// [`crate::identity::Endpoint::import_uri`].
    ///
    /// Returns a clear error when all relays are unreachable rather than
    /// silently succeeding.
    ///
    /// # Errors
    ///
    /// [`ChatError::Invalid`] for a malformed URI, self-import attempt,
    /// or when every relay fails. [`ChatError::Transport`] on underlying
    /// HTTP failure.
    pub async fn import_pair_uri(&self, uri: &str) -> Result<()> {
        use crate::pair_uri::{parse_pair_uri, PairUriError};

        // v3 share URIs (`fetchit://share/v3/…`) come from a fediverse handle
        // lookup ("message privately") or a pasted profile share link. Resolve
        // them via the same parse → fetch → verify → persist path the desktop's
        // pair-accept command uses, so a single call imports either a legacy
        // `x0x://pair/` link or a v3 share URI.
        if uri.starts_with(crate::profile::V3_SHARE_URI_PREFIX) {
            let parsed = crate::profile::from_v3_share_uri(uri)
                .map_err(|e| ChatError::Invalid(e.to_string()))?;
            // Reject self-import before any network call.
            if let Some(chat) = self.chat.as_ref() {
                if chat.identity.agent_id_hex() == parsed.agent_id {
                    return Err(ChatError::Invalid("that is your own pairing link".into()));
                }
            }
            let layout = self.layout().ok_or_else(|| {
                ChatError::Invalid("chat state not built; cannot import a pair URI".into())
            })?;
            let http = crate::relay_http::guarded_client();
            crate::pair::pair_accept(uri, &http, layout).await?;
            return Ok(());
        }

        let parsed = parse_pair_uri(uri).map_err(|e| match e {
            PairUriError::TooLong => ChatError::Invalid("pair URI too long".into()),
            other => ChatError::Invalid(other.to_string()),
        })?;

        // Reject self-import before any network call.
        if let Some(chat) = self.chat.as_ref() {
            if chat.identity.agent_id_hex() == parsed.agent_id_hex {
                return Err(ChatError::Invalid("that is your own pairing link".into()));
            }
        }

        let layout = self.layout().ok_or_else(|| {
            ChatError::Invalid("chat state not built; cannot import a pair URI".into())
        })?;

        let http = crate::relay_http::guarded_client();
        let mut last_err = String::new();
        let mut record_opt = None;
        for relay_str in &parsed.relays {
            let relay = url::Url::parse(relay_str)
                .map_err(|e| ChatError::Invalid(format!("relay URL in pair URI: {e}")))?;
            match crate::pair::fetch_pair_record_by_id(&relay, &parsed.agent_id_hex, &http).await {
                Ok(r) => {
                    record_opt = Some(r);
                    break;
                }
                Err(e) => last_err = e.to_string(),
            }
        }

        let record = record_opt.ok_or_else(|| {
            ChatError::Invalid(format!("could not reach any of their relays: {last_err}"))
        })?;

        // Build and persist the stored contact card. Carry the pair
        // record's advertised relays into the card as rendezvous hints so
        // the deposit path routes DMs to THEIR relay (cross-relay
        // delivery), not ours. Stamp the record's issued_at_ms as the hint
        // watermark so a later in-band refresh only overrides a newer one.
        // Without this the send path falls back to our own primary and a
        // peer on a different relay never receives.
        let rendezvous_hints =
            (!record.advertised_relays.is_empty()).then(|| crate::card::RendezvousHintsV1 {
                relays: record.advertised_relays.clone(),
            });
        let stored = crate::messages::StoredContactCard {
            agent_id_hex: record.agent_id_hex.clone(),
            display_name: String::new(),
            kem_public_key_b64: record.kem_pubkey_b64.clone(),
            agent_public_key_b64: Some(record.ml_dsa_pubkey_b64.clone()),
            rendezvous_hints,
            last_hint_epoch_ms: Some(record.issued_at_ms),
            user_id_hex: None,
        };
        // Persist under CARD_UPDATE_LOCK, preserving any newer in-band
        // relay-hint watermark already on disk so a re-import can't reset
        // the per-contact downgrade guard.
        stored.save_imported(layout)?;

        // Build a minimal legacy AgentCard URI and forward it to x0xd's
        // /agent/card/import endpoint so the daemon-backed contact list
        // reflects the new peer (mirrors the pair_accept flow).
        let agent_id = crate::identity::AgentId(record.agent_id_hex.clone());
        let card = crate::identity::AgentCard {
            agent_id,
            display_name: String::new(),
            // x0xd's AgentCard requires `created_at` as a real u64 (Unix
            // seconds); `None` serialises to JSON `null` and x0x >= 0.24's
            // stricter card import (ADR-0017) rejects it with "expected u64".
            // Carry the pair record's issued_at (ms -> s) so the mirror card
            // reflects the record it's derived from.
            created_at: Some(record.issued_at_ms / 1000),
            addresses: Vec::new(),
            // Carry the peer's machine id into the card's flattened `extra` so
            // it serialises as a top-level `machine_id`. x0x >= 0.29 requires
            // it on /agent/card/import; without it the daemon-side contact
            // mirror never lands and DMs to this peer can't route. A legacy
            // pointer without the field leaves `extra` Null (nothing emitted).
            extra: if record.machine_id.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!({ "machine_id": record.machine_id })
            },
        };
        // Best-effort legacy sync. The local StoredContactCard saved above
        // is the messaging source of truth (it carries the ML-KEM key the
        // send path seals to); the x0xd daemon-side contact list is a
        // convenience mirror. A daemon hiccup must not fail an import whose
        // essential work is done -- the next import or connect re-syncs.
        if let Err(e) = self.identity().import(&card).await {
            log::warn!("[chat] pair import: x0xd card sync failed (contact saved locally): {e}");
        }

        Ok(())
    }
}

/// Normalize a user-typed fediverse handle for lookup: trim, lowercase,
/// and tolerate a missing leading `@` (`user@instance.org` is how people
/// type handles; the strict leading-`@` form is a mention-scanner rule,
/// not a UX contract). Only the LOOKUP entrance is lenient — message-text
/// mention scanning keeps requiring `@user@instance` so ordinary email
/// addresses in prose never parse as mentions.
fn normalize_lookup_handle(handle: &str) -> String {
    let trimmed = handle.trim().to_lowercase();
    if trimmed.starts_with('@') {
        trimmed
    } else {
        format!("@{trimmed}")
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

/// Production [`crate::outbox::driver::OutboxTransport`]: re-sends a bubble
/// through the same `messages()` path as the initial send. Holds a cloned
/// [`Client`] (cheap -- shares the inner Arcs, exactly like the dispatcher +
/// SSE-recorder tasks) plus a shell-supplied display-name source read at
/// send time (the engine has no canonical name; it lives in the shell's
/// settings).
struct RealOutboxTransport {
    client: Client,
    name_provider: Arc<dyn Fn() -> String + Send + Sync>,
}

impl crate::outbox::driver::OutboxTransport for RealOutboxTransport {
    fn connect(
        &self,
        peer: crate::identity::AgentId,
    ) -> impl std::future::Future<Output = ()> + Send {
        let client = self.client.clone();
        async move {
            // Best-effort warm-connect; the send below reports the real error.
            let _ = client.messages().connect(&peer).await;
        }
    }

    fn send(
        &self,
        bubble: crate::outbox::OutboxBubble,
    ) -> impl std::future::Future<
        Output = std::result::Result<crate::transport::SendReceipt, ChatError>,
    > + Send {
        let client = self.client.clone();
        let sender_name = (self.name_provider)();
        async move {
            // A group bubble re-sends its STORED sealed frame verbatim (a
            // re-seal would ratchet TreeKEM and duplicate at the receiver);
            // a DM re-encrypts its body. RETRY fidelity for DMs: OutboxBubble
            // stores body only, so a DM resend drops the original attachment
            // + reply_to (faithful to desktop outboxDriver.ts; full-fidelity
            // retry is a deferred Josh-gated improvement -- see the
            // outbox-lift plan notes).
            let message_id = match &bubble.group {
                Some(group) => {
                    client
                        .messages()
                        .resend_group_bubble(&bubble.peer, &group.group_id, &group.envelope)
                        .await?
                }
                None => {
                    client
                        .messages()
                        .send(&bubble.peer, &bubble.body, &sender_name, None, None)
                        .await?
                }
            };
            let accepted_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            Ok(crate::transport::SendReceipt {
                accepted_at_ms,
                message_id,
                transport_name: "outbox-retry",
            })
        }
    }
}

/// Production [`crate::outbox::driver::ReadyGate`]: holds off an outbox
/// flush until the primary relay is registered.
///
/// Backed by the relay supervisor's `ConnState` watch (slot 0 in the
/// multi-home set). `relay_state = None` means no relay transport is wired
/// (REST-only / LAN-only deployments), where there is nothing to wait for,
/// so the gate is permanently ready. Otherwise [`Self::wait_ready`] resolves
/// once the primary reaches [`fetchit_relay_client::ConnState::Connected`].
struct RelayReadyGate {
    relay_state: Option<tokio::sync::watch::Receiver<fetchit_relay_client::ConnState>>,
}

impl crate::outbox::driver::ReadyGate for RelayReadyGate {
    fn wait_ready(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let Some(rx) = self.relay_state.as_ref() else {
                // No relay transport => nothing to register; always ready.
                return;
            };
            let mut rx = rx.clone();
            loop {
                if matches!(
                    *rx.borrow(),
                    fetchit_relay_client::ConnState::Connected { .. }
                ) {
                    return;
                }
                // Not yet connected. Wait for the next state change. If the
                // sender is gone (supervisor shut down) we will not block a
                // flush forever -- proceed and let the send report the real
                // transport error rather than hang.
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
    }
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
    passphrase: Option<Zeroizing<String>>,
    enable_lan_direct: bool,
    contact_pubkey_lookup: Option<ContactPubkeyLookup>,
    x0xd_port_file: Option<PathBuf>,
    daemonless: bool,
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
    // M3 G1: direct handle to the `MultiHomeTransport` for the
    // primary-denylisted callback registration on the desktop shell.
    Option<Arc<crate::transport::MultiHomeTransport>>,
    // M4 Stage 5.2: shared outbound fediverse transport (one
    // `reqwest::Client` + HTTP-Signature capability cache).
    // `Client::publish_public_post` delivers through it.
    Option<Arc<FediverseTransport>>,
)> {
    // Gate on x0xd >= 0.20.1 (PQ `TreeKEM` minimum) before any chat work.
    // Daemonless skips the probe ONLY against the unconnectable sentinel:
    // an explicitly supplied base_url in daemonless mode (the P2
    // in-process-router shape) claims a live daemon, so the version
    // protection must still hold.
    if !daemonless || base_url != DAEMONLESS_BASE_URL {
        enforce_m2_treekem_minimum(base_url, &token).await?;
    }

    let data_dir = match data_dir {
        Some(p) => p,
        None => crate::local_store::default_data_dir()?,
    };
    let layout = StoreLayout::ensure(data_dir)?;

    let identity_vault_path = layout.root.join(IDENTITY_VAULT_FILE);
    let (master, kdf_id, argon_salt) = resolve_master_key(
        identity_vault_path.as_path(),
        passphrase.as_ref().map(|z| z.as_str()),
    )?;
    let master = Arc::new(master);

    // Resolve the local agent identity. Daemon path: x0xd `/agent` owns
    // the agent id + machine id. Daemonless path: both come from the
    // local signer vault — agent id is derived from the local ML-DSA-65
    // public key, so pair records and relay handshakes verify the same
    // way they do for an x0xd-backed agent.
    let (agent_id_hex, local_machine_id, local_signer): (
        String,
        [u8; 32],
        Option<Arc<dyn Signer>>,
    ) = if daemonless {
        let vault = crate::local_signer::LocalSignerVault::load_or_create(
            &layout.root,
            &master,
            kdf_id,
            argon_salt.as_ref(),
        )?;
        let agent_id_hex = hex::encode(vault.signer.agent_id());
        let machine = derive_machine_id(&vault.machine_token);
        (agent_id_hex, machine, Some(Arc::new(vault.signer)))
    } else {
        let agent_identity: identity::AgentIdentity = http.get_json("/agent").await?;
        let machine = derive_machine_id(&agent_identity.machine_id);
        (agent_identity.agent_id.0.clone(), machine, None)
    };

    let identity = Arc::new(FetchitIdentity::load_or_create(
        &layout.root,
        &master,
        &agent_id_hex,
        kdf_id,
        argon_salt.as_ref(),
    )?);

    // Load persisted per-group bridge-consent (or an empty map on first
    // run / unreadable file) so the user's opt-in / opt-out decisions
    // survive restart. Built before `argon_salt` and `layout` are moved
    // into the registry / ChatState below; mirrors the registry's
    // (layout, master, kdf_id, argon_salt) sealed-vault wiring.
    let bridge_consent_store = crate::groups_reachability::BridgeConsentStore::load(
        &layout,
        &master,
        kdf_id,
        argon_salt.as_ref(),
    );
    // Load the persisted outbound-DM outbox (or empty on first run /
    // unreadable file), before `argon_salt` + `layout` are moved into the
    // registry / ChatState below -- same ordering as the consent store.
    let outbox_store =
        crate::outbox::store::OutboxStore::load(&layout, &master, kdf_id, argon_salt.as_ref());

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
    // In the daemonless profile the signer is the local ML-DSA-65 vault
    // key resolved above — no daemon round-trips at all.
    //
    // When the caller supplied a `port_file` path
    // ([`ClientBuilder::x0xd_port_file`]), the signer self-heals across
    // x0xd restarts: a connect-refused error during signing triggers a
    // re-read of `api.port` and a one-shot retry against the new URL,
    // so long-running consumers (chat-peer, desktop app) survive a
    // daemon restart without going through their own restart cycle.
    let signer: Arc<dyn Signer> = match local_signer {
        Some(s) => s,
        None => Arc::new(if let Some(path) = x0xd_port_file {
            X0xdSigner::connect_with_port_file(path, token)
                .await
                .map_err(|e| ChatError::MessageTransport(format!("x0xd signer (port-file): {e}")))?
        } else {
            X0xdSigner::connect(
                Url::parse(base_url)
                    .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?,
                token,
            )
            .await
            .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?
        }),
    };

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
    let mut multi_home_handle: Option<Arc<crate::transport::MultiHomeTransport>> = None;
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
            Arc::new(crate::transport::RealRelayBuilder::new(signer.clone()));

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
        multi_home_handle = Some(Arc::clone(&mh));

        router.add(mh as Arc<dyn crate::transport::Transport>);
    }

    // M4 Stage 5.2: stand up the outbound fediverse transport. It carries
    // no chat state — just a shared `reqwest::Client` + the per-instance
    // HTTP-Signature capability cache — but is assembled here so REST-only
    // clients (which never mint an actor identity) get `None` and the
    // delivery path is unreachable without the chat vault.
    let fediverse = Some(Arc::new(FediverseTransport::new().map_err(|e| {
        ChatError::MessageTransport(format!("fediverse transport: {e}"))
    })?));

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
            bridge_consent: Arc::new(tokio::sync::Mutex::new(bridge_consent_store)),
            outbox: Arc::new(tokio::sync::Mutex::new(outbox_store)),
            outbox_tx: tokio::sync::broadcast::channel(OUTBOX_CHANNEL_CAP).0,
            outbox_retry_tx: Arc::new(std::sync::Mutex::new(None)),
            bridge_inbound_shadow: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeInboundShadow::new(),
            )),
            members_singleflight: Arc::new(crate::members_singleflight::MembersSingleflight::new()),
            public_post_tx: tokio::sync::broadcast::channel(PUBLIC_POST_CHANNEL_CAP).0,
        }),
        relay_handle,
        lan_handle,
        lan_bound_addr,
        mh_inbound_slot,
        primary_relay_url_str,
        multi_home_handle,
        fediverse,
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
    primary_relay_url: Arc<tokio::sync::RwLock<Option<String>>>,
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
            // Read the live primary each tick (interior-mutable post-T8b):
            // after a home-relay failover, rekey welcomes must fall back
            // to the NEW primary, never the dead relay.
            let primary_snapshot = primary_relay_url.read().await.clone();
            match sweep_auto_rekey(
                &registry,
                &identity,
                &router,
                machine_id,
                &signer,
                &layout,
                primary_snapshot.as_deref(),
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

/// T8b candidate selection: the first `advertised` relay that is not the
/// dead primary. Returns `None` when the list is empty or contains only
/// `dead_url` (the no-fallback case the watcher backs off on).
fn pick_failover_candidate(advertised: &[String], dead_url: &str) -> Option<String> {
    advertised.iter().find(|r| *r != dead_url).cloned()
}

/// T8b core: the home-relay failover trigger state machine, extracted
/// from its production wiring so it is unit-testable against a
/// hand-driven [`tokio::sync::watch`] channel.
///
/// Observes slot 0's per-relay connection state (a length-1
/// `Vec<ConnState>`; index 0 is slot 0) and fires `action` when the
/// primary is gone:
/// - [`fetchit_relay_client::ConnState::PermanentlyDisconnected`]
///   triggers immediately (the supervisor gave up).
/// - [`fetchit_relay_client::ConnState::Disconnected`] sustained for
///   `failover_after` triggers. A return to
///   [`fetchit_relay_client::ConnState::Connected`] before the deadline
///   resets the timer.
/// - [`fetchit_relay_client::ConnState::Connecting`] is neutral (in-flight
///   reconnect): it neither arms nor clears the timer.
///
/// `action(dead_url)` performs the migration and returns `Ok(new_url)` on
/// success or `Err(())` on a failed/no-fallback migration. The dead URL
/// is read from `current_primary` at trigger time. On success the loop
/// calls `resubscribe` to re-fetch the NEW slot 0's state stream (sticky:
/// it keeps watching the new primary and will failover again if it also
/// dies). On failure it sleeps `backoff` then re-subscribes and re-checks,
/// so a terminal state with no reachable fallback retries at a bounded
/// pace instead of busy-spinning.
///
/// `resubscribe` returning `None` (slot 0 not ready, or a transport-less
/// mock) is treated as transient: the watcher sleeps `backoff` and tries
/// again. The loop never returns under normal operation, and the spawned
/// watcher holds its own `Client` clone, so it is NOT stopped by dropping
/// other clones; teardown paths abort it explicitly via
/// [`Client::stop_failover_watcher`].
async fn run_failover_watcher<RS, CP, AC, Fut>(
    mut resubscribe: RS,
    current_primary: CP,
    failover_after: Duration,
    backoff: Duration,
    mut action: AC,
) where
    RS: FnMut() -> Option<tokio::sync::watch::Receiver<Vec<fetchit_relay_client::ConnState>>>,
    CP: Fn() -> Option<String>,
    AC: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<String, ()>>,
{
    use fetchit_relay_client::ConnState;

    let is_connected = |v: &[ConnState]| matches!(v.first(), Some(ConnState::Connected { .. }));
    let is_permanent =
        |v: &[ConnState]| matches!(v.first(), Some(ConnState::PermanentlyDisconnected { .. }));
    let is_disconnected =
        |v: &[ConnState]| matches!(v.first(), Some(ConnState::Disconnected { .. }));

    'outer: loop {
        let Some(mut states) = resubscribe() else {
            // Slot 0 not observable yet (boot race or mock handle): wait
            // and retry rather than spin.
            tokio::time::sleep(backoff).await;
            continue;
        };

        // `deadline` is armed while slot 0 is continuously Disconnected.
        let mut deadline: Option<tokio::time::Instant> = None;
        // Seed the state machine from the current value without waiting
        // for the first change.
        {
            let v = states.borrow_and_update();
            if is_disconnected(&v) {
                deadline = Some(tokio::time::Instant::now() + failover_after);
            }
        }

        loop {
            // Decide whether to trigger NOW (permanent), wait for the
            // disconnect deadline, or just wait for the next state change.
            let snapshot = states.borrow().clone();
            let trigger = if is_permanent(&snapshot) {
                true
            } else if is_connected(&snapshot) {
                deadline = None;
                false
            } else if is_disconnected(&snapshot) {
                if deadline.is_none() {
                    deadline = Some(tokio::time::Instant::now() + failover_after);
                }
                false
            } else {
                // Connecting / unknown: leave the timer as-is.
                false
            };

            if !trigger {
                // Block until either a fresh state arrives or the armed
                // disconnect deadline elapses.
                let changed = states.changed();
                if let Some(at) = deadline {
                    tokio::select! {
                        biased;
                        r = changed => {
                            if r.is_err() {
                                // Sender dropped (slot 0 torn down):
                                // re-subscribe to the live slot 0.
                                continue 'outer;
                            }
                            continue;
                        }
                        () = tokio::time::sleep_until(at) => {
                            // Window elapsed. Only a live Connected clears
                            // the armed deadline; a Connecting blip landing
                            // exactly at the deadline must not grant another
                            // full window (the primary has been gone the
                            // whole time). Anything not Connected triggers.
                            if is_connected(&states.borrow()) {
                                deadline = None;
                                continue;
                            }
                            // fall through to trigger below.
                        }
                    }
                } else {
                    if changed.await.is_err() {
                        continue 'outer;
                    }
                    continue;
                }
            }

            // Triggered. Resolve the dead URL and run the migration.
            let Some(dead_url) = current_primary() else {
                // No primary to migrate off (transient read miss): back off
                // and re-evaluate.
                tokio::time::sleep(backoff).await;
                continue;
            };
            // Sticky: on success re-subscribe to the NEW slot 0 and keep
            // watching (fresh RelaySet state stream). On failure (no fallback
            // or replace_primary errored) back off first, then re-subscribe
            // (slot 0 is unchanged) and re-attempt at a bounded pace.
            if action(dead_url).await.is_err() {
                tokio::time::sleep(backoff).await;
            } else {
                // Starvation guard: the immediate-trigger path (resubscribe
                // hands back a still-terminal receiver and the action keeps
                // succeeding) otherwise has no await point that yields, which
                // would starve a current-thread runtime unkillably. Production
                // cannot reach that cycle (success implies the new relay just
                // liveness-gated Connected), but one yield makes the watcher
                // starvation-proof against any misbehaving seam.
                tokio::task::yield_now().await;
            }
            continue 'outer;
        }
    }
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

/// Distinct active peer-device agent ids to push a pair-record to, across
/// every cached conversation. [`Conversation::fanout_devices`] already
/// excludes our own device and any inactive (revoked) device; this dedupes a
/// contact device we share across several conversations so the push reaches
/// it exactly once.
fn pair_record_push_recipients(
    conversations: &[Conversation],
    local_agent_hex: &str,
) -> Vec<String> {
    let mut recipients: Vec<String> = Vec::new();
    for conv in conversations {
        for device in conv.fanout_devices(local_agent_hex) {
            if !recipients.iter().any(|r| r == &device.agent_id_hex) {
                recipients.push(device.agent_id_hex.clone());
            }
        }
    }
    recipients
}

/// Decode a pushed [`PairRecordV4`](fetchit_relay_proto::pair_record::PairRecordV4)
/// from the unsealed `PairRecordPush` ciphertext: postcard wrapper, then the
/// inner JSON record.
///
/// The `record_bytes` are size-capped at
/// [`crate::pair_record::MAX_RELAY_BODY_BYTES`] before the JSON parse, mirroring
/// the `read_body_capped` cap the HTTP resolve path applies to the same record
/// shape, so a known contact cannot deliver an oversized blob the relay
/// envelope cap permits but the fetch path would reject.
///
/// # Errors
/// [`ChatError::Invalid`] on a wrapper decode failure, an over-cap
/// `record_bytes`, or a record JSON decode failure.
fn decode_pushed_pair_record_v4(
    ciphertext: &[u8],
) -> Result<fetchit_relay_proto::pair_record::PairRecordV4> {
    let payload = fetchit_relay_proto::PairRecordPushPayload::from_ciphertext(ciphertext)
        .map_err(|e| ChatError::Invalid(format!("pair-record-push wrapper decode: {e}")))?;
    if payload.record_bytes.len() > crate::pair_record::MAX_RELAY_BODY_BYTES {
        return Err(ChatError::Invalid(format!(
            "pushed pair record too large: {} bytes (cap {})",
            payload.record_bytes.len(),
            crate::pair_record::MAX_RELAY_BODY_BYTES
        )));
    }
    serde_json::from_slice(&payload.record_bytes)
        .map_err(|e| ChatError::Invalid(format!("pushed pair record decode: {e}")))
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
    /// The vault custody passphrase retained at build time, as the
    /// `Option<&str>` shape [`resolve_master_key`] takes. `None` =
    /// OS-keychain custody.
    fn custody_passphrase(&self) -> Option<&str> {
        self.custody_passphrase.as_ref().map(|z| z.as_str())
    }

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
    /// Vault custody resolves from the passphrase retained at client
    /// build time (`None` = OS keychain), so every re-open matches the
    /// boot-time vault.
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
    ) -> Result<fetchit_fedi::actor::ActorIdentity> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;

        validate_actor_handle(handle)?;
        let actor_url = build_actor_url(domain, handle)?;
        let agent_id_hex = chat.identity.agent_id_hex().to_string();

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) =
            resolve_master_key(&identity_vault_path, self.custody_passphrase())?;

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
            ml_dsa_attestation_v2: None,
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

    /// Mint the actor identity AND its v2 attestation in one step. The
    /// caller supplies the published profile address and the active
    /// relay (the v3 share-URI fields); both become part of the signed
    /// binding. The v1 attestation is still minted and emitted for
    /// actor-document compatibility with pre-M5 verifiers.
    ///
    /// # Errors
    ///
    /// Same surface as [`Self::mint_actor_identity`], plus
    /// signing-input validation of `profile_addr` / `relay_hint`.
    pub async fn mint_actor_identity_v2(
        &self,
        handle: &str,
        domain: &str,
        profile_addr: &str,
        relay_hint: &str,
        hint_epoch_ms: u64,
    ) -> Result<fetchit_fedi::actor::ActorIdentity> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;

        validate_actor_handle(handle)?;
        let actor_url = build_actor_url(domain, handle)?;
        let agent_id_hex = chat.identity.agent_id_hex().to_string();

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) =
            resolve_master_key(&identity_vault_path, self.custody_passphrase())?;

        if chat.layout.actor_identity_path(handle).exists() {
            log::warn!(
                "[chat] mint_actor_identity_v2 called on handle {handle:?} which already has \
                 a persisted vault; the prior vault will be overwritten. Consider \
                 upgrade_actor_attestation_v2 instead."
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
        let attestation_v2 = crate::fedi_identity::sign_actor_attestation_v2(
            handle,
            &actor_url,
            &agent_id_hex,
            &material.spki_der,
            profile_addr,
            relay_hint,
            hint_epoch_ms,
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
            ml_dsa_attestation_v2: Some(attestation_v2.clone()),
        };
        crate::fedi_vault::save_actor_identity(&vault, &master, &chat.layout)?;

        Ok(fetchit_fedi::actor::ActorIdentity::new(
            handle.to_string(),
            actor_url,
            agent_id_hex,
            material.priv_pem,
            material.spki_der,
            attestation,
        )
        .with_attestation_v2(attestation_v2))
    }

    /// Publish a **minimal** (handle-only) profile index record for this
    /// identity to `relay`, so a fresh identity with no etch/it-published
    /// profile can still mint a fediverse handle and be looked up. fetch>it
    /// signs the record with the chat identity's ML-DSA key and POSTs it — a
    /// blind relay pointer ([`crate::pair::MINIMAL_PROFILE_ADDR`]), no wallet,
    /// no Autonomi write. The rich profile (name / bio / avatar) stays an
    /// optional etch/it upgrade. Idempotent-ish: re-publishing overwrites the
    /// prior minimal record with a fresher `issued_at_ms`.
    ///
    /// # Errors
    /// Chat state uninitialised, the signer being unreachable, or a relay
    /// write failure.
    pub async fn publish_minimal_profile(&self, relay: &url::Url, now_ms: u64) -> Result<()> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        let agent_id_hex = chat.identity.agent_id_hex().to_string();
        let kem_pub = chat.identity.kem_public_key().to_vec();
        let ml_dsa_pub = chat.signer.public_key();
        let http = crate::relay_http::guarded_client();
        let record = crate::pair::sign_minimal_index_record(
            &agent_id_hex,
            &kem_pub,
            &ml_dsa_pub,
            now_ms,
            chat.signer.as_ref(),
        )
        .await
        .map_err(|e| ChatError::Invalid(format!("sign minimal profile: {e}")))?;
        crate::pair::publish_index_record(relay, &record, &http)
            .await
            .map_err(|e| ChatError::Invalid(format!("publish minimal profile: {e}")))?;
        Ok(())
    }

    /// Mint an actor identity for `handle` AND register it with the
    /// fediverse directory in one engine call, so the desktop command and
    /// the FFI mint path share this orchestration (the DRY lift). Fetches
    /// the local profile-index record from `relay` (its `profile_addr` binds
    /// the v2 attestation), mints + persists the RSA identity via
    /// [`Self::mint_actor_identity_v2`], then POST-then-PUT registers it with
    /// [`crate::fedi_identity::register_or_update_actor`] at `registry_base`
    /// (prod `https://etchit.io/`).
    ///
    /// **One-tap:** if no profile is published yet (relay 404 / tombstoned —
    /// the common case for a fresh identity), fetch>it first publishes a
    /// minimal handle-only record ([`Self::publish_minimal_profile`]) and
    /// binds it, so minting a handle never dead-ends into an etch/it
    /// round-trip. An existing real profile is used as-is and never clobbered.
    ///
    /// Directory registration failure is REPORTED in [`MintOutcome`], never
    /// fatal: a bridge outage degrades to "registration pending", never a
    /// failed mint. The composed steps are each unit-tested on their own
    /// (`fetch_index_record_by_id`, `sign_minimal_index_record`,
    /// `mint_actor_identity_v2`, `register_or_update_actor`).
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] on a transient relay error fetching the
    ///   profile record, or if publishing the minimal fallback fails.
    /// - The mint itself failing (handle validation, key/attestation, vault).
    pub async fn mint_and_register_actor(
        &self,
        handle: &str,
        domain: &str,
        relay: &url::Url,
        registry_base: &url::Url,
        now_ms: u64,
    ) -> Result<MintOutcome> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        let agent_id_hex = chat.identity.agent_id_hex().to_string();
        let http = crate::relay_http::guarded_client();
        // One-tap mint: if no profile is published yet (the common case for a
        // fresh identity), publish a minimal handle-only record and bind it,
        // rather than dead-ending the user into an etch/it round-trip. Only a
        // genuine "no profile" (404 / tombstoned) triggers the fallback — a
        // transient relay error propagates, and an EXISTING real profile is
        // used as-is and never clobbered.
        let profile_addr = match crate::pair::fetch_index_record_by_id(relay, &agent_id_hex, &http)
            .await
        {
            Ok(record) => record.profile_addr,
            Err(crate::pair::PairError::RelayStatus(404) | crate::pair::PairError::Tombstoned) => {
                self.publish_minimal_profile(relay, now_ms).await?;
                crate::pair::MINIMAL_PROFILE_ADDR.to_owned()
            }
            Err(e) => return Err(ChatError::Invalid(format!("profile record: {e}"))),
        };
        let identity = self
            .mint_actor_identity_v2(handle, domain, &profile_addr, relay.as_str(), now_ms)
            .await?;
        let (registered, registration_error) =
            crate::fedi_identity::register_or_update_actor(registry_base, &identity, &http).await;
        Ok(MintOutcome {
            actor_url: identity.actor_url.to_string(),
            registered,
            registration_error,
        })
    }

    /// Run the heal + v2 upgrade + re-register pass for the active `handle`
    /// (called when the fedi hub opens). Transparently re-signs attestations
    /// the current verifiers reject (pre-0.29 signing format, rotated agent
    /// key), upgrades a pre-M5 (v1-only) identity to v2, and re-asserts the
    /// directory record. NEVER errors the
    /// pass for upgrade blockers -- no published profile, bridge unreachable
    /// -- those land in [`EnsureV2Outcome::pending`]. Shares one path with
    /// the desktop `fediverse_ensure_v2` command.
    ///
    /// # Errors
    /// The vault/mint machinery failing (chat state missing, vault access) or
    /// a minted identity that unexpectedly cannot be reloaded.
    pub async fn ensure_actor_v2_and_register(
        &self,
        handle: &str,
        relay: &url::Url,
        registry_base: &url::Url,
        now_ms: u64,
    ) -> Result<EnsureV2Outcome> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        let agent_id_hex = chat.identity.agent_id_hex().to_string();
        let http = crate::relay_http::guarded_client();
        // Heal stale attestations FIRST: identities minted before the x0x
        // 0.29 agent-sign framing carry signatures no current verifier
        // accepts (the bridge answers 403 forever), and an attestation
        // signed by a rotated-away agent key binds a dead identity. Both
        // re-sign transparently under the live key. Best-effort: a heal
        // failure surfaces through the registration error below.
        let mut pending: Option<String> = None;
        if let Err(e) = self.heal_actor_attestations(handle, now_ms).await {
            pending = Some(format!("attestation heal failed: {e}"));
        }
        // Best-effort profile refresh + attestation upgrade. A missing or
        // unreachable published profile must NOT block registration: the bridge
        // directory only needs handle + RSA SPKI + v2 attestation, none of which
        // require a live profile fetch. Registering unconditionally lets a fresh
        // device or an emptied directory self-heal its registration; the profile
        // note is surfaced only when registration itself has nothing to report.
        let upgraded = match crate::pair::fetch_index_record_by_id(relay, &agent_id_hex, &http)
            .await
        {
            Ok(record) => self
                .upgrade_actor_attestation_v2(handle, &record.profile_addr, relay.as_str(), now_ms)
                .await
                .unwrap_or(false),
            Err(e) => {
                if pending.is_none() {
                    pending = Some(format!("profile refresh skipped: {e}"));
                }
                false
            }
        };
        // Nothing minted is a pending state, not an error: the pass's
        // contract is "never errors on a blocker" so the hub stays usable.
        let Some(identity) = self.load_actor_identity(handle).await? else {
            return Ok(EnsureV2Outcome {
                upgraded,
                registered: false,
                pending: Some(format!("no actor identity minted for {handle}")),
            });
        };
        let (registered, reg_pending) =
            crate::fedi_identity::register_or_update_actor(registry_base, &identity, &http).await;
        // A registration failure is actionable — surface it, but never at the
        // cost of hiding an earlier heal/profile note (a masked heal error
        // makes the resulting 403 undiagnosable from the outcome alone).
        if let Some(reg) = reg_pending {
            pending = Some(match pending {
                Some(prior) => format!("{reg} (also: {prior})"),
                None => reg,
            });
        }
        Ok(EnsureV2Outcome {
            upgraded,
            registered,
            pending,
        })
    }

    /// Resolve a fediverse handle to a verified (or public-only) identity
    /// card: `WebFinger` -> actor doc -> v2 attestation verify -> the sender's
    /// relay profile-index (for the share URI + handle-takeover continuity).
    /// Shared by the desktop lookup command and the FFI. The rich display
    /// profile (name/bio/avatar) is NOT fetched here -- it lives in the
    /// Autonomi manifest at the returned `profile_addr`, which the shell's
    /// reader loads separately.
    ///
    /// A crypto/attestation failure returns a `PublicOnly` card with a
    /// visible `verify_failure` (fail closed, visibly); a transport failure
    /// after that point is an error.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] on a malformed handle, a `WebFinger`/actor-fetch
    /// transport failure, or an unreachable sender relay.
    pub async fn lookup_fedi_handle(&self, handle: &str) -> Result<FediLookup> {
        let parsed = fetchit_fedi::parse_mention(&normalize_lookup_handle(handle))
            .map_err(|e| ChatError::Invalid(format!("handle: {e}")))?;
        let canonical = format!("@{}@{}", parsed.local, parsed.instance);
        let actor_url = fetchit_fedi::resolve_handle(&parsed)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't resolve {canonical}: {e}")))?;
        let actor = fetchit_fedi::lookup::fetch_remote_actor(&actor_url)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't fetch that account: {e}")))?;
        let actor_url_str = actor.id.to_string();

        let Some(att) = actor.attestation_v2.clone() else {
            return Ok(FediLookup::public_only(canonical, actor_url_str, None));
        };
        let agent_id_hex = match actor.verify_attestation_v2() {
            Ok(id) => id,
            Err(e) => {
                return Ok(FediLookup::public_only(
                    canonical,
                    actor_url_str,
                    Some(e.to_string()),
                ))
            }
        };
        // The attested relay hint is part of the verified binding; one that
        // does not parse fails closed to public-only, like a bad signature.
        let Ok(relay) = att.relay_hint.parse::<url::Url>() else {
            return Ok(FediLookup::public_only(
                canonical,
                actor_url_str,
                Some("attested relay hint is not a valid URL".into()),
            ));
        };
        let http = crate::relay_http::guarded_client();
        let record = crate::pair::fetch_index_record_by_id(&relay, &agent_id_hex, &http)
            .await
            .map_err(|e| ChatError::Invalid(format!("couldn't reach their relay: {e}")))?;
        let share_uri =
            crate::profile::to_v3_share_uri(&agent_id_hex, &record.profile_addr, &relay).map_err(
                |e| ChatError::Invalid(format!("couldn't build the contact pointer: {e}")),
            )?;
        // Continuity ledger: surfaces "handle changed hands". Best-effort; a
        // layout-less (REST-only) client just skips it.
        let previous_agent_id_hex = self.layout().and_then(|layout| {
            match crate::fedi_resolutions::note_resolution(layout, &canonical, &agent_id_hex) {
                Ok(crate::fedi_resolutions::ResolutionChange::Changed {
                    previous_agent_id_hex,
                }) => Some(previous_agent_id_hex),
                _ => None,
            }
        });
        Ok(FediLookup {
            kind: FediLookupKind::Verified,
            handle: canonical,
            actor_url: actor_url_str,
            agent_id_hex: Some(agent_id_hex),
            profile_addr: Some(record.profile_addr),
            share_uri: Some(share_uri),
            previous_agent_id_hex,
            verify_failure: None,
        })
    }

    /// Re-sign the v2 attestation in place: same handle, same actor
    /// URL, SAME RSA keypair (HTTP-Signature key continuity is the
    /// invariant; this function never regenerates RSA material).
    /// Returns `false` without touching the vault when the stored v2
    /// attestation already covers the same `profile_addr` and
    /// `relay_hint`.
    ///
    /// # Errors
    ///
    /// - [`ChatError::Invalid`] when chat state is uninitialised, the
    ///   handle fails validation, or no identity exists for `handle`.
    /// - Propagates master-key resolution, vault-decrypt, signing, and
    ///   vault-write failures verbatim.
    pub async fn upgrade_actor_attestation_v2(
        &self,
        handle: &str,
        profile_addr: &str,
        relay_hint: &str,
        hint_epoch_ms: u64,
    ) -> Result<bool> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        validate_actor_handle(handle)?;

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) =
            resolve_master_key(&identity_vault_path, self.custody_passphrase())?;

        let Some(mut vault) =
            crate::fedi_vault::load_actor_identity(handle, &master, &chat.layout)?
        else {
            return Err(ChatError::Invalid(format!(
                "no actor identity for {handle}"
            )));
        };
        if let Some(v2) = &vault.ml_dsa_attestation_v2 {
            if v2.profile_addr == profile_addr && v2.relay_hint == relay_hint {
                return Ok(false);
            }
        }

        let agent_id_hex = chat.identity.agent_id_hex().to_string();
        let attestation_v2 = crate::fedi_identity::sign_actor_attestation_v2(
            handle,
            &vault.actor_url,
            &agent_id_hex,
            &vault.spki_der,
            profile_addr,
            relay_hint,
            hint_epoch_ms,
            chat.signer.as_ref(),
        )
        .await?;
        vault.ml_dsa_attestation_v2 = Some(attestation_v2);
        crate::fedi_vault::save_actor_identity(&vault, &master, &chat.layout)?;
        Ok(true)
    }

    /// Verify the vault's stored attestations under the live agent key and
    /// re-sign any that no longer hold (pre-0.29 signing format, rotated
    /// agent key), persisting the healed vault. Returns whether anything
    /// was re-signed; `Ok(false)` when nothing is minted for `handle`.
    /// Called by [`Self::ensure_actor_v2_and_register`] so every ensure
    /// pass leaves the vault verifiable before registration is attempted.
    ///
    /// # Errors
    ///
    /// - [`ChatError::Invalid`] when chat state has not been initialised
    ///   or `handle` fails validation.
    /// - Propagates master-key resolution, vault decrypt/save, and
    ///   re-signing failures.
    async fn heal_actor_attestations(&self, handle: &str, now_ms: u64) -> Result<bool> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        validate_actor_handle(handle)?;

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) =
            resolve_master_key(&identity_vault_path, self.custody_passphrase())?;

        let Some(mut vault) =
            crate::fedi_vault::load_actor_identity(handle, &master, &chat.layout)?
        else {
            return Ok(false);
        };
        let healed =
            crate::fedi_identity::heal_actor_attestations(&mut vault, chat.signer.as_ref(), now_ms)
                .await?;
        if healed {
            crate::fedi_vault::save_actor_identity(&vault, &master, &chat.layout)?;
        }
        Ok(healed)
    }

    /// Master key + store layout for the fedi at-rest files (identity
    /// vault, DM thread store). One master-key resolve per operation,
    /// mirroring every other fedi vault path.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when chat state has not been initialised;
    /// propagates master-key resolution failures.
    pub(crate) fn fedi_at_rest(
        &self,
    ) -> Result<(crate::at_rest::MasterKey, crate::local_store::StoreLayout)> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) =
            resolve_master_key(&identity_vault_path, self.custody_passphrase())?;
        Ok((master, chat.layout.clone()))
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
    ) -> Result<Option<fetchit_fedi::actor::ActorIdentity>> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        validate_actor_handle(handle)?;

        let identity_vault_path = chat.layout.root.join(IDENTITY_VAULT_FILE);
        let (master, _kdf, _salt) =
            resolve_master_key(&identity_vault_path, self.custody_passphrase())?;

        let Some(vault) = crate::fedi_vault::load_actor_identity(handle, &master, &chat.layout)?
        else {
            return Ok(None);
        };
        let identity = fetchit_fedi::actor::ActorIdentity::from_persisted(
            vault.handle,
            vault.rsa_priv_pem,
            vault.spki_der,
            vault.ml_dsa_attestation,
            vault.actor_url,
            vault.agent_id_hex,
        );
        Ok(Some(match vault.ml_dsa_attestation_v2 {
            Some(att2) => identity.with_attestation_v2(att2),
            None => identity,
        }))
    }

    /// Publish a public post to the fediverse: wrap it as an
    /// `ActivityPub` `Create { Note }` signed by the actor identity for
    /// `handle`, and deliver it to every resolved recipient inbox (the
    /// replied-to actor plus each mentioned actor).
    ///
    /// `handle`/`passphrase` select and unseal the signing identity,
    /// exactly as [`Self::load_actor_identity`].
    ///
    /// Denylist gating runs BEFORE any delivery: `reply_to_actor_url`
    /// and every mention (after `WebFinger` resolution) are checked
    /// against the community denylist when one is installed; a blocked
    /// actor aborts the whole publish with [`ChatError::DeniedActor`]
    /// and nothing goes out. The denylist is dormant until the
    /// launch-gate energization — absent it, resolution still runs but
    /// nothing is blocked.
    ///
    /// Delivery is best-effort per recipient: an unreachable or
    /// rejecting inbox is recorded in `PublishReport::failed` without
    /// aborting the rest. A top-level post with no mentions has no
    /// direct recipients (follower shared-inbox fan-out is a later
    /// stage) and returns an empty report.
    ///
    /// # Errors
    /// - [`ChatError::Invalid`] when no fediverse transport is wired
    ///   (REST-only client), chat state is uninitialised, or no actor
    ///   identity is minted for `handle`.
    /// - [`ChatError::DeniedActor`] when a reply-to or mention actor is
    ///   denylisted.
    /// - [`ChatError::Invalid`] when a mention fails `WebFinger`
    ///   resolution or `reply_to_actor_url` is not a valid URL.
    pub async fn publish_public_post(
        &self,
        handle: &str,
        post: &fetchit_fedi::PublicPost,
    ) -> Result<PublishReport> {
        let transport = self.fediverse.as_ref().ok_or_else(|| {
            ChatError::Invalid("fediverse transport not configured (REST-only client)".into())
        })?;

        let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no fediverse actor identity minted for handle {handle}"
            ))
        })?;

        // Pre-flight: gate the replied-to actor before any resolution
        // or delivery. Mentions are gated per-resolution just below.
        if let Some(denylist) = self.denylist.as_ref() {
            crate::public::check_publish_denylist(denylist.as_ref(), post).await?;
        }

        // Resolve every mention to its canonical actor URL (and gate it
        // when a denylist is installed). These feed the Create{Note}
        // cc/tag fields and the delivery recipient set.
        let mut resolved_mentions: Vec<(String, Url)> = Vec::with_capacity(post.mentions.len());
        for mention in &post.mentions {
            let url = self.resolve_and_gate_mention(mention).await?;
            resolved_mentions.push((mention.clone(), url));
        }

        let recipients =
            assemble_recipients(&resolved_mentions, post.reply_to_actor_url.as_deref())?;

        let activity = fetchit_fedi::activity::build_create_note(
            post,
            identity.actor_url.as_str(),
            &resolved_mentions,
        );
        let body = serde_json::to_vec(&activity)
            .map_err(|e| ChatError::Invalid(format!("serialize activity: {e}")))?;

        let key = fetchit_fedi::signature::HttpSignatureKey {
            key_id: format!("{}#main-key", identity.actor_url),
            rsa_private_pem: identity.rsa_priv_pem.clone(),
        };

        let mut report = PublishReport::default();
        for actor_url in &recipients {
            // Lenient decode: mentioned recipients are ordinary fediverse
            // actors (no PQ attestation required); we only need the inbox.
            match fetchit_fedi::lookup::fetch_remote_actor(actor_url).await {
                Ok(actor) => {
                    match transport
                        .deliver(&key, &body, &actor.inbox, &identity.actor_url)
                        .await
                    {
                        Ok(_) => report.delivered.push(actor.inbox.to_string()),
                        Err(e) => report.failed.push((actor.inbox.to_string(), e.to_string())),
                    }
                }
                Err(e) => report.failed.push((actor_url.to_string(), e.to_string())),
            }
        }
        Ok(report)
    }

    /// Resolve one `@user@instance` mention to its canonical actor URL,
    /// gating it through the community denylist when one is installed.
    /// Without a denylist the resolution still runs (we need the URL to
    /// find the inbox) but nothing is blocked.
    /// Sign `canonical` bytes with the chat agent's ML-DSA key for the
    /// `bridge-auth-v1` request auth (M7). Returns `(agent_id_hex,
    /// signature_bytes)`; the `Signer` trait wraps `agent_sign_input`
    /// exactly as the bridge re-applies before verifying.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] for a REST-only client (no chat state) or a
    /// signer failure.
    pub(crate) async fn bridge_auth_sign(&self, canonical: &[u8]) -> Result<(String, Vec<u8>)> {
        let chat = self
            .chat
            .as_ref()
            .ok_or_else(|| ChatError::Invalid("chat state not initialised".into()))?;
        let sig = chat
            .signer
            .sign(canonical)
            .await
            .map_err(|e| ChatError::Invalid(format!("bridge-auth sign: {e}")))?;
        Ok((chat.identity.agent_id_hex().to_owned(), sig))
    }

    pub(crate) async fn resolve_and_gate_mention(&self, mention: &str) -> Result<Url> {
        if let Some(denylist) = self.denylist.as_ref() {
            crate::public::check_mention_denylist(denylist.as_ref(), mention).await
        } else {
            let parsed = fetchit_fedi::parse_mention(mention)
                .map_err(|e| ChatError::Invalid(format!("webfinger: {e}")))?;
            fetchit_fedi::resolve_handle(&parsed)
                .await
                .map_err(|e| ChatError::Invalid(format!("webfinger: {e}")))
        }
    }
}

/// Outcome of [`Client::mint_and_register_actor`]: the identity is always
/// created + persisted locally on success; directory registration is
/// best-effort and reported honestly (mirrors the desktop `MintOutcomeDto`).
#[derive(Clone, Debug)]
pub struct MintOutcome {
    /// Canonical actor URL of the minted identity.
    pub actor_url: String,
    /// True when the directory accepted the registration.
    pub registered: bool,
    /// Why registration is pending, when it is (bridge unreachable, etc.).
    pub registration_error: Option<String>,
}

/// Outcome of [`Client::ensure_actor_v2_and_register`]: a hub-open upgrade
/// pass that never errors for blockers -- they land in `pending`.
#[derive(Clone, Debug)]
pub struct EnsureV2Outcome {
    /// True when a fresh v2 attestation was signed + stored this pass.
    pub upgraded: bool,
    /// True when the directory holds the current record.
    pub registered: bool,
    /// Why the pass could not complete (profile unpublished, bridge
    /// unreachable); user-facing copy.
    pub pending: Option<String>,
}

/// Verified-vs-public classification of a [`Client::lookup_fedi_handle`]
/// result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FediLookupKind {
    /// The v2 attestation verified: the actor is cryptographically bound to
    /// the returned chat `agent_id`.
    Verified,
    /// No attestation, or it failed to verify: display the account but do
    /// NOT trust the identity binding.
    PublicOnly,
}

/// One resolved fediverse account card (identity + share pointer) from
/// [`Client::lookup_fedi_handle`]. The rich display fields (name/bio/avatar)
/// are fetched separately from the Autonomi manifest at `profile_addr`.
#[derive(Clone, Debug)]
pub struct FediLookup {
    /// Verified or public-only.
    pub kind: FediLookupKind,
    /// Canonical `@local@instance` handle.
    pub handle: String,
    /// Actor URL the handle resolved to.
    pub actor_url: String,
    /// Verified chat agent id (verified kind only).
    pub agent_id_hex: Option<String>,
    /// Autonomi profile-manifest address (verified only); the shell's reader
    /// loads name/bio/avatar from it.
    pub profile_addr: Option<String>,
    /// Synthesized v3 share URI for "message privately" (verified only).
    pub share_uri: Option<String>,
    /// Set when this handle previously resolved to a DIFFERENT agent id on
    /// this device (a possible handle takeover).
    pub previous_agent_id_hex: Option<String>,
    /// Set when an attestation was present but failed verification.
    pub verify_failure: Option<String>,
}

impl FediLookup {
    fn public_only(handle: String, actor_url: String, verify_failure: Option<String>) -> Self {
        Self {
            kind: FediLookupKind::PublicOnly,
            handle,
            actor_url,
            agent_id_hex: None,
            profile_addr: None,
            share_uri: None,
            previous_agent_id_hex: None,
            verify_failure,
        }
    }
}

/// Outcome of [`Client::publish_public_post`]: which recipient inboxes
/// accepted the activity and which failed. Delivery is best-effort, so a
/// non-empty `failed` is not itself an error — the post still reached
/// every inbox in `delivered`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublishReport {
    /// Inbox URLs that returned a 2xx for the delivered activity.
    pub delivered: Vec<String>,
    /// `(target, error)` for each recipient that could not be reached or
    /// rejected the activity. `target` is the inbox URL when the actor
    /// was fetched, otherwise the actor URL (fetch itself failed).
    pub failed: Vec<(String, String)>,
}

/// Build the de-duplicated delivery recipient set from the resolved
/// mention URLs plus the optional replied-to actor URL. The replied-to
/// actor is appended only when it is not already a mention, so a post
/// that both replies to and mentions the same actor delivers once.
///
/// # Errors
/// [`ChatError::Invalid`] when `reply_to` is present but not a valid URL.
fn assemble_recipients(
    resolved_mentions: &[(String, Url)],
    reply_to: Option<&str>,
) -> Result<Vec<Url>> {
    let mut recipients: Vec<Url> = resolved_mentions.iter().map(|(_, u)| u.clone()).collect();
    if let Some(reply_to) = reply_to {
        let url = Url::parse(reply_to)
            .map_err(|e| ChatError::Invalid(format!("reply_to_actor_url: {e}")))?;
        if !recipients.contains(&url) {
            recipients.push(url);
        }
    }
    Ok(recipients)
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
/// character outside `[a-z0-9_-]`. Handles are **lowercase**: uppercase
/// is rejected (callers lowercase user input) so the signed attestation,
/// the actor URL, the vault path, and the registry record all share one
/// canonical form, matching the fediverse's case-insensitive acct
/// local-parts. The allowlist also forbids `.` and `/` so a malicious
/// handle cannot traverse out of `fedi_dir` via
/// [`crate::local_store::StoreLayout::actor_identity_path`].
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
        if !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-') {
            return Err(ChatError::Invalid(format!(
                "actor handle contains invalid char {:?}; allowed: [a-z0-9_-] \
                 (handles are lowercase; uppercase is rejected so the signed \
                 attestation, actor URL, and registry record share one canonical form)",
                b as char
            )));
        }
    }
    Ok(())
}

/// The daemonless chat-vault ML-DSA-65 signing keypair, returned so an
/// embedder can seed the in-process x0xd's agent identity to the SAME key.
/// `secret_key` is zeroized on drop -- hand it straight to the x0xd identity
/// seed; never log or persist it elsewhere.
pub struct ProvisionedSignerKey {
    /// ML-DSA-65 public-key bytes (saorsa-pqc encoding).
    pub public_key: Vec<u8>,
    /// ML-DSA-65 secret-key bytes; zeroized on drop.
    pub secret_key: Zeroizing<Vec<u8>>,
    /// The derived agent id, lowercase 64-hex.
    pub agent_id_hex: String,
}

/// Load-or-create the daemonless chat-vault ML-DSA-65 identity WITHOUT
/// building the full [`Client`], returning its keypair bytes.
///
/// Android calls this BEFORE starting the in-process x0xd so it can seed the
/// x0xd agent key with the vault key: otherwise the x0xd mints its own agent
/// id, the group it owns is keyed under that id, but the owner pair-record is
/// published under the vault id -- and engine-A joiners resolve the owner KEM
/// by the x0xd id, so they 404. Idempotent: a later
/// `Client::builder().build()` on the same `data_dir` + `passphrase` loads the
/// identical vault (this mirrors that setup exactly).
///
/// # Errors
/// Layout, master-key, or vault failures as [`ChatError`].
pub fn provision_local_signer_keypair(
    data_dir: &std::path::Path,
    passphrase: Option<&str>,
) -> Result<ProvisionedSignerKey> {
    let layout = StoreLayout::ensure(data_dir.to_path_buf())?;
    let identity_vault_path = layout.root.join(IDENTITY_VAULT_FILE);
    let (master, kdf_id, argon_salt) = resolve_master_key(&identity_vault_path, passphrase)?;
    let vault = crate::local_signer::LocalSignerVault::load_or_create(
        &layout.root,
        &master,
        kdf_id,
        argon_salt.as_ref(),
    )?;
    // Persist the KEM identity vault too (mirrors build_with_chat's daemonless
    // setup) so the master-key argon salt is stored in identity.json.enc.
    // Otherwise the later Client::build()'s resolve_master_key, finding no
    // identity vault, derives a FRESH salt -> a different master -> an
    // AEAD-open failure on the local_signer vault we just sealed.
    let agent_id_hex = hex::encode(vault.signer.agent_id());
    let _identity = FetchitIdentity::load_or_create(
        &layout.root,
        &master,
        &agent_id_hex,
        kdf_id,
        argon_salt.as_ref(),
    )?;
    Ok(ProvisionedSignerKey {
        public_key: vault.signer.public_key(),
        secret_key: Zeroizing::new(vault.signer.secret_key_bytes()),
        agent_id_hex,
    })
}

/// Restore the chat identity from its 24-word BIP39 recovery phrase, sealing a
/// fresh local-signer vault under `data_dir` keyed at rest by `passphrase`. The
/// restored identity reproduces the exact ML-DSA agent id (and thus, at the
/// next `connect`, the unified in-process x0xd id). The ML-KEM decryption key
/// regenerates fresh: recovery restores the signing identity, not prior message
/// history. Refuses if an identity already exists under `data_dir`, so the
/// caller must gate this to a fresh install. Returns the restored agent id
/// (hex), for the UI to confirm.
///
/// # Errors
/// `ChatError::Invalid` if the phrase is not valid BIP39 or an identity already
/// exists; layout / master-key / vault failures as [`ChatError`].
pub fn restore_identity_from_recovery_phrase(
    data_dir: &std::path::Path,
    passphrase: Option<&str>,
    phrase: &str,
) -> Result<String> {
    let seed = crate::recovery_phrase::recovery_phrase_to_seed(phrase)?;
    let layout = StoreLayout::ensure(data_dir.to_path_buf())?;
    let identity_vault_path = layout.root.join(IDENTITY_VAULT_FILE);
    let (master, kdf_id, argon_salt) = resolve_master_key(&identity_vault_path, passphrase)?;
    let vault = crate::local_signer::LocalSignerVault::restore_from_seed(
        &layout.root,
        &master,
        kdf_id,
        argon_salt.as_ref(),
        &seed,
    )?;
    let agent_id_hex = hex::encode(vault.signer.agent_id());
    // Persist the KEM identity vault too (mirrors provision_local_signer_keypair)
    // so the argon salt lands in identity.json.enc and the later Client::build
    // resolves the SAME master instead of deriving a fresh salt.
    let _identity = FetchitIdentity::load_or_create(
        &layout.root,
        &master,
        &agent_id_hex,
        kdf_id,
        argon_salt.as_ref(),
    )?;
    Ok(agent_id_hex)
}

#[cfg(test)]
mod provision_tests {
    #![allow(clippy::unwrap_used)]
    use super::provision_local_signer_keypair;

    #[test]
    fn idempotent_and_nonempty() {
        let dir = tempfile::TempDir::new().unwrap();
        let k1 = provision_local_signer_keypair(dir.path(), Some("test-pass")).unwrap();
        let k2 = provision_local_signer_keypair(dir.path(), Some("test-pass")).unwrap();
        assert!(!k1.public_key.is_empty());
        assert_eq!(k1.public_key, k2.public_key);
        assert_eq!(k1.secret_key.as_slice(), k2.secret_key.as_slice());
    }

    #[test]
    fn restore_from_recovery_phrase_reproduces_the_identity() {
        // Original device: mint an identity, read its backup phrase.
        let a = tempfile::TempDir::new().unwrap();
        let orig = provision_local_signer_keypair(a.path(), Some("pass-a")).unwrap();
        let phrase = crate::reveal_local_signer_recovery_phrase(a.path(), Some("pass-a"))
            .unwrap()
            .unwrap();

        // Fresh device with a DIFFERENT local passphrase: restore from the phrase.
        let b = tempfile::TempDir::new().unwrap();
        let restored_id =
            super::restore_identity_from_recovery_phrase(b.path(), Some("pass-b"), &phrase)
                .unwrap();
        assert!(!restored_id.is_empty());

        // The restored vault carries the EXACT signing keypair (the passphrase
        // only seals it at rest; the phrase carries the identity).
        let reprov = provision_local_signer_keypair(b.path(), Some("pass-b")).unwrap();
        assert_eq!(reprov.public_key, orig.public_key);
        assert_eq!(reprov.secret_key.as_slice(), orig.secret_key.as_slice());
    }

    #[test]
    fn restore_refuses_to_overwrite_an_existing_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let _ = provision_local_signer_keypair(dir.path(), Some("pass")).unwrap();
        let phrase = crate::reveal_local_signer_recovery_phrase(dir.path(), Some("pass"))
            .unwrap()
            .unwrap();
        // Restore into a dir that already holds an identity must refuse, not clobber.
        assert!(
            super::restore_identity_from_recovery_phrase(dir.path(), Some("pass"), &phrase)
                .is_err()
        );
    }
}

pub(crate) fn resolve_master_key(
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

    #[test]
    fn lookup_handle_normalizes_missing_leading_at() {
        // The email-like form users actually type must parse.
        assert_eq!(
            normalize_lookup_handle("happyborg@fosstodon.org"),
            "@happyborg@fosstodon.org"
        );
        // Canonical form passes through untouched.
        assert_eq!(
            normalize_lookup_handle("@happyborg@fosstodon.org"),
            "@happyborg@fosstodon.org"
        );
        // Whitespace + case are cleaned before the check.
        assert_eq!(
            normalize_lookup_handle("  HappyBorg@Fosstodon.org "),
            "@happyborg@fosstodon.org"
        );
        // Both normalized forms parse identically downstream.
        let a = fetchit_fedi::parse_mention("@happyborg@fosstodon.org").unwrap();
        let b = fetchit_fedi::parse_mention(&normalize_lookup_handle("happyborg@fosstodon.org"))
            .unwrap();
        assert_eq!((a.local, a.instance), (b.local, b.instance));
    }

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

    /// Always-bridge policy: even when native (warm-gossip) convergence
    /// SUCCEEDS, the bridge still runs -- roster-active does not imply the
    /// joiner has `TreeKEM` keys, so the Welcome is always re-delivered.
    #[tokio::test]
    async fn native_then_bridge_runs_bridge_even_on_native_success() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let bridged = Arc::new(AtomicBool::new(false));
        let b = bridged.clone();
        let captured = Some(crate::groups::join_bridge::CapturedSelfJoin {
            topic: "topic".to_owned(),
            payload: vec![1, 2, 3],
        });

        let out = Client::run_native_then_bridge(
            captured,
            || async { Ok::<(), ChatError>(()) },
            move |_cap| async move {
                b.store(true, Ordering::SeqCst);
                Ok::<(), ChatError>(())
            },
        )
        .await;

        assert!(out.is_ok());
        assert!(
            bridged.load(Ordering::SeqCst),
            "bridge must ALWAYS run to guarantee keys, even when native converged"
        );
    }

    /// Native best-effort: when native convergence fails, the bridge still
    /// runs with the SAME captured `member_joined` -- proving the single-use
    /// invite is reused, not re-fetched via a second `join_post`.
    #[tokio::test]
    async fn native_then_bridge_runs_bridge_reusing_captured_on_native_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let bridged = Arc::new(AtomicBool::new(false));
        let b = bridged.clone();
        let captured = Some(crate::groups::join_bridge::CapturedSelfJoin {
            topic: "topic".to_owned(),
            payload: vec![9, 9, 9],
        });

        let out = Client::run_native_then_bridge(
            captured,
            || async {
                Err::<(), ChatError>(ChatError::JoinerNotConverged {
                    group_id: "g".to_owned(),
                    waited_ms: 1,
                })
            },
            move |cap| async move {
                assert_eq!(
                    cap.payload,
                    vec![9, 9, 9],
                    "the bridge must reuse the captured member_joined verbatim"
                );
                b.store(true, Ordering::SeqCst);
                Ok::<(), ChatError>(())
            },
        )
        .await;

        assert!(out.is_ok());
        assert!(
            bridged.load(Ordering::SeqCst),
            "bridge must run when native convergence fails"
        );
    }

    /// Guard: native FAILURE with no captured `member_joined` cannot bridge
    /// (unpatched daemon), so it surfaces a clear error and never invokes
    /// the bridge.
    #[tokio::test]
    async fn native_then_bridge_without_captured_event_errors_on_native_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let bridged = Arc::new(AtomicBool::new(false));
        let b = bridged.clone();

        let out = Client::run_native_then_bridge(
            None::<crate::groups::join_bridge::CapturedSelfJoin>,
            || async {
                Err::<(), ChatError>(ChatError::JoinerNotConverged {
                    group_id: "g".to_owned(),
                    waited_ms: 1,
                })
            },
            move |_cap| async move {
                b.store(true, Ordering::SeqCst);
                Ok::<(), ChatError>(())
            },
        )
        .await;

        match out {
            Err(ChatError::Invalid(msg)) => assert!(
                msg.contains("bridge") && msg.contains("no inline member_joined"),
                "expected a clear cannot-bridge error, got: {msg}"
            ),
            other => panic!("expected ChatError::Invalid, got {other:?}"),
        }
        assert!(
            !bridged.load(Ordering::SeqCst),
            "bridge must not run without a captured event"
        );
    }

    /// Graceful degrade: native SUCCESS with no captured `member_joined`
    /// (an unpatched daemon where warm gossip still converged) is accepted
    /// on its own -- native is the only path that daemon offers, so erroring
    /// would needlessly fail an otherwise-good join.
    #[tokio::test]
    async fn native_then_bridge_without_captured_event_accepts_native_success() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let bridged = Arc::new(AtomicBool::new(false));
        let b = bridged.clone();

        let out = Client::run_native_then_bridge(
            None::<crate::groups::join_bridge::CapturedSelfJoin>,
            || async { Ok::<(), ChatError>(()) },
            move |_cap| async move {
                b.store(true, Ordering::SeqCst);
                Ok::<(), ChatError>(())
            },
        )
        .await;

        assert!(
            out.is_ok(),
            "native success with no captured event must be accepted"
        );
        assert!(
            !bridged.load(Ordering::SeqCst),
            "bridge cannot run without a captured event"
        );
    }

    #[tokio::test]
    async fn daemonless_build_is_offline_and_agent_id_persists() {
        let dir = TempDir::new().unwrap();
        let build = || async {
            Client::builder()
                .daemonless(true)
                .data_dir(dir.path().to_path_buf())
                .passphrase("test-pass".to_owned())
                .build()
                .await
                .unwrap()
        };
        // No relay_url, no daemon, no network: must still build (needs_chat
        // is true via data_dir) and expose a stable 64-hex agent id.
        let c1 = build().await;
        let id1 = c1.local_agent_id_hex().expect("chat state present");
        assert_eq!(id1.len(), 64);
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
        drop(c1);
        let c2 = build().await;
        assert_eq!(c2.local_agent_id_hex().unwrap(), id1);
    }

    #[tokio::test]
    async fn daemonless_with_explicit_base_url_still_probes_daemon_version() {
        let dir = TempDir::new().unwrap();
        // Port 1 refuses instantly; an explicit base_url in daemonless mode
        // claims a daemon lives there, so the TreeKEM version probe must run
        // and surface its transport failure instead of being bypassed.
        let err = Client::builder()
            .daemonless(true)
            .base_url("http://127.0.0.1:1")
            .token(String::new())
            .data_dir(dir.path().to_path_buf())
            .passphrase("test-pass".to_owned())
            .build()
            .await
            .expect_err("probe against a dead explicit base_url must fail the build");
        let msg = err.to_string();
        assert!(
            msg.contains("/version probe"),
            "expected the version-probe error, got: {msg}"
        );
    }

    // ── M4 actor identity helpers ─────────────────────────────────

    #[test]
    fn validate_actor_handle_accepts_valid_handles() {
        assert!(validate_actor_handle("josh").is_ok());
        assert!(validate_actor_handle("alice_42").is_ok());
        assert!(validate_actor_handle("ab-c-d").is_ok());
        assert!(validate_actor_handle("x").is_ok());
        // Right at the 64-char cap.
        let max = "a".repeat(64);
        assert!(validate_actor_handle(&max).is_ok());
    }

    #[test]
    fn validate_actor_handle_rejects_uppercase() {
        // Handles are lowercase-only so the signed attestation, actor
        // URL, and registry record share one canonical form (SO-3).
        let err = validate_actor_handle("Alice_42").unwrap_err();
        assert!(format!("{err}").contains("[a-z0-9_-]"));
        assert!(validate_actor_handle("JOSH").is_err());
        assert!(validate_actor_handle("Josh").is_err());
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

    // ── M4 Stage 5.3 PublicPost receive path ─────────────────────

    #[tokio::test]
    async fn dispatch_inbound_public_post_surfaces_decoded_delivery() {
        let (client, _dir) = test_client_no_denylist();
        let mut rx = client
            .subscribe_to_public_posts()
            .expect("chat-state client exposes a public-post surface");
        let body = br#"{"type":"Create","object":{"type":"Note","content":"hi"}}"#.to_vec();
        let env = fetchit_relay_proto::TransitEnvelope::public_post(
            "https://mastodon.example/users/alice",
            body.clone(),
            1_700_000_000_000,
        )
        .unwrap();

        let delivery = client
            .dispatch_inbound_public_post(&env)
            .expect("dispatch decodes + surfaces");
        assert_eq!(
            delivery.verified_actor_url,
            "https://mastodon.example/users/alice"
        );
        assert_eq!(delivery.activity_json, body);

        // The subscriber received the same delivery on the broadcast.
        let received = rx.try_recv().expect("subscriber got the post");
        assert_eq!(received, delivery);
    }

    #[tokio::test]
    async fn dispatch_inbound_public_post_rejects_non_public_post_kind() {
        let (client, _dir) = test_client_no_denylist();
        let mut env = fetchit_relay_proto::TransitEnvelope::public_post(
            "https://mastodon.example/users/eve",
            b"{}".to_vec(),
            0,
        )
        .unwrap();
        // A DM must never be drained through the PublicPost exemption.
        env.kind = fetchit_relay_proto::EnvelopeKind::Dm;
        let err = client.dispatch_inbound_public_post(&env).unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    // ── M6.7 PairRecordPush receive path ─────────────────────────

    #[tokio::test]
    async fn pair_record_push_from_unknown_sender_is_ignored() {
        let (client, dir) = test_client_no_denylist();
        // A push from an agent we hold no contact card for.
        let unknown = fetchit_relay_proto::identity::AgentId::from_bytes([0x11u8; 32]);
        let machine = fetchit_relay_proto::identity::MachineId::from_bytes([0x22u8; 32]);
        let env = fetchit_relay_proto::TransitEnvelope::pair_record_push(
            unknown,
            machine,
            b"unused-record-bytes".to_vec(),
            1_700_000_000_000,
        )
        .unwrap();
        // No contact card for the sender: the known-contact gate returns a
        // no-op success BEFORE the record is even decoded (the bytes above are
        // deliberately not a valid record), so a stranger cannot fill the cache.
        client
            .dispatch_inbound_pair_record_push(&env)
            .await
            .expect("unknown-sender push is a no-op success");
        let cache_dir = dir.path().join("contact_pair_records");
        assert!(
            !cache_dir.exists() || std::fs::read_dir(&cache_dir).unwrap().next().is_none(),
            "no contact record should be cached from an unknown sender"
        );
    }

    // ── M3 D9 regenerate_card_with_relays ────────────────────────

    /// Build a chat-state-enabled `Client` without going through
    /// `from_parts` (which probes `/version` and refuses without a
    /// reachable x0xd). The HTTP, router, and transports are stubbed
    /// to whatever a hermetic test needs.
    fn test_client_no_denylist() -> (Client, tempfile::TempDir) {
        test_client_with_router(Router::new())
    }

    fn test_client_with_router(router: Router) -> (Client, tempfile::TempDir) {
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
            outbox: Arc::new(tokio::sync::Mutex::new(
                crate::outbox::store::OutboxStore::new(),
            )),
            outbox_tx: tokio::sync::broadcast::channel(OUTBOX_CHANNEL_CAP).0,
            outbox_retry_tx: Arc::new(std::sync::Mutex::new(None)),
            bridge_inbound_shadow: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeInboundShadow::new(),
            )),
            members_singleflight: Arc::new(crate::members_singleflight::MembersSingleflight::new()),
            public_post_tx: tokio::sync::broadcast::channel(PUBLIC_POST_CHANNEL_CAP).0,
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
            denylist_consumer: None,
            denylist_dropped_inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            failover_watcher_abort: Arc::new(std::sync::Mutex::new(None)),
            advertised_relays: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            engine_a_supported: Arc::new(std::sync::OnceLock::new()),
            multi_home_inbound: None,
            primary_relay_url: Arc::new(tokio::sync::RwLock::new(None)),
            neg_resolve_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            // The test vault above is passphrase-mode, so the retained
            // custody must match -- fedi paths in tests then exercise
            // the same custody resolution mobile uses in production.
            custody_passphrase: Some(Arc::new(Zeroizing::new("d9-test".to_owned()))),
            group_kinds: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            multi_home: None,
            fediverse: None,
            relay_failover_cb: Arc::new(tokio::sync::RwLock::new(None)),
            group_recovery: crate::groups::epoch_recovery::GroupStatusMap::new(),
            recovery_cursors: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recovering: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        };
        (client, dir)
    }

    // ── M6.7 PairRecordPush send path ────────────────────────────

    /// A syntactically-valid `PairRecordV4` for wire/enumeration tests. The
    /// signature is a placeholder -- these tests exercise serde framing and
    /// fanout shape, not signature verification (that lives in
    /// `pair_record_v4`).
    fn sample_pair_record_v4() -> fetchit_relay_proto::pair_record::PairRecordV4 {
        use fetchit_relay_proto::pair_record::{DeviceEntryV4, PairRecordV4};
        PairRecordV4 {
            record_version: 4,
            user_id_hex: "aa".repeat(32),
            user_ml_dsa_pubkey_b64: "dXNlcg==".to_owned(),
            revision: 7,
            issued_at_ms: 1_700_000_000_000,
            devices: vec![DeviceEntryV4 {
                agent_id_hex: "bb".repeat(32),
                ml_dsa_pubkey_b64: "ZGV2".to_owned(),
                kem_pubkey_b64: "a2Vt".to_owned(),
                advertised_relays: vec!["wss://relay.example/ws".to_owned()],
                cert_b64: "Y2VydA==".to_owned(),
                added_at_ms: 1_700_000_000_001,
                primary: true,
            }],
            user_signature_b64: "c2ln".to_owned(),
        }
    }

    fn push_member_device(agent_hex: &str, status: MemberDeviceStatus) -> MemberDevice {
        MemberDevice {
            agent_id_hex: agent_hex.to_owned(),
            kem_public_key_b64: String::new(),
            agent_public_key_b64: None,
            added_at_epoch: 0,
            status,
        }
    }

    fn push_member(devices: Vec<MemberDevice>) -> Member {
        Member {
            user_id_hex: None,
            devices,
            joined_at_epoch: 0,
        }
    }

    #[test]
    fn pair_record_push_recipients_excludes_self_dedupes_and_drops_revoked() {
        let me = "aa".repeat(32);
        let peer_a = "bb".repeat(32);
        let peer_b = "cc".repeat(32);
        let peer_c = "dd".repeat(32);

        // DM 1: our device + a peer with one active (peer_a) and one revoked
        // (peer_b) device.
        let dm1 = Conversation::new_dm(
            push_member(vec![push_member_device(&me, MemberDeviceStatus::Active)]),
            push_member(vec![
                push_member_device(&peer_a, MemberDeviceStatus::Active),
                push_member_device(&peer_b, MemberDeviceStatus::Revoked),
            ]),
            None,
        )
        .unwrap();
        // DM 2: our device again + a peer that re-lists peer_a (must dedupe)
        // plus a fresh active device peer_c.
        let dm2 = Conversation::new_dm(
            push_member(vec![push_member_device(&me, MemberDeviceStatus::Active)]),
            push_member(vec![
                push_member_device(&peer_a, MemberDeviceStatus::Active),
                push_member_device(&peer_c, MemberDeviceStatus::Active),
            ]),
            None,
        )
        .unwrap();

        let recipients = pair_record_push_recipients(&[dm1, dm2], &me);
        // self dropped, peer_b (revoked) dropped, peer_a deduped across DMs.
        assert_eq!(recipients, vec![peer_a, peer_c]);
    }

    #[test]
    fn pair_record_push_record_bytes_round_trip_matches_receive_decode() {
        // SEND encodes the record with serde_json into the push wrapper;
        // RECEIVE (dispatch_inbound_pair_record_push) postcard-decodes the
        // wrapper then serde_json-decodes the record. Lock that agreement so
        // the two halves never drift on the record framing.
        let record = sample_pair_record_v4();
        let record_bytes = serde_json::to_vec(&record).unwrap();
        let transit = fetchit_relay_proto::TransitEnvelope::pair_record_push(
            fetchit_relay_proto::identity::AgentId::from_bytes([3u8; 32]),
            fetchit_relay_proto::identity::MachineId::from_bytes([4u8; 32]),
            record_bytes,
            123,
        )
        .unwrap();
        let payload =
            fetchit_relay_proto::PairRecordPushPayload::from_ciphertext(&transit.ciphertext)
                .unwrap();
        let decoded: fetchit_relay_proto::pair_record::PairRecordV4 =
            serde_json::from_slice(&payload.record_bytes).unwrap();
        assert_eq!(decoded, record);
    }

    #[tokio::test]
    async fn push_pair_record_to_active_contacts_with_no_conversations_sends_nothing() {
        let (client, _dir) = test_client_no_denylist();
        let record = sample_pair_record_v4();
        let sent = client
            .push_pair_record_to_active_contacts(&record)
            .await
            .unwrap();
        assert_eq!(sent, 0, "no conversations -> no pushes attempted");
    }

    #[test]
    fn decode_pushed_pair_record_v4_accepts_a_valid_record() {
        let record = sample_pair_record_v4();
        let record_bytes = serde_json::to_vec(&record).unwrap();
        let ciphertext =
            postcard::to_allocvec(&fetchit_relay_proto::PairRecordPushPayload { record_bytes })
                .unwrap();
        let decoded = decode_pushed_pair_record_v4(&ciphertext).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn decode_pushed_pair_record_v4_rejects_oversized_record_bytes() {
        // A known contact must not be able to deliver a record_bytes blob the
        // relay envelope cap permits but the HTTP-fetch path would reject: cap
        // it before the JSON parse, matching the read_body_capped cap.
        let oversized = fetchit_relay_proto::PairRecordPushPayload {
            record_bytes: vec![0u8; crate::pair_record::MAX_RELAY_BODY_BYTES + 1],
        };
        let ciphertext = postcard::to_allocvec(&oversized).unwrap();
        let err = decode_pushed_pair_record_v4(&ciphertext).unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(_)),
            "oversized record_bytes is rejected before the JSON parse"
        );
    }

    /// Transport stub that records every `(recipient, envelope)` it is asked to
    /// send and always reports the peer reachable, so a push actually fires.
    struct RecordingTransport {
        sent: Arc<
            std::sync::Mutex<Vec<(crate::identity::AgentId, crate::transport::OutboundEnvelope)>>,
        >,
    }

    #[async_trait]
    impl crate::transport::Transport for RecordingTransport {
        fn name(&self) -> &'static str {
            "recording"
        }
        fn reachability(&self, _to: &crate::identity::AgentId) -> crate::transport::Reachability {
            crate::transport::Reachability::Always
        }
        async fn send(
            &self,
            to: &crate::identity::AgentId,
            envelope: crate::transport::OutboundEnvelope,
            _hints: Option<&crate::card::RendezvousHintsV1>,
        ) -> Result<crate::transport::SendReceipt> {
            self.sent.lock().unwrap().push((to.clone(), envelope));
            Ok(crate::transport::SendReceipt {
                accepted_at_ms: 0,
                message_id: None,
                transport_name: "recording",
            })
        }
        fn take_inbound(
            &self,
        ) -> Option<tokio::sync::mpsc::UnboundedReceiver<crate::transport::InboundEnvelope>>
        {
            None
        }
    }

    #[tokio::test]
    async fn push_pair_record_fires_dm_shaped_pairrecordpush_to_each_active_peer_device() {
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = Router::new();
        router.add(Arc::new(RecordingTransport { sent: sent.clone() }));
        let (client, _dir) = test_client_with_router(router);

        // Seed one DM: our own device + a peer with one active device (peer_a)
        // and one revoked device (peer_b, which must NOT receive a push).
        let me = client.local_agent_id_hex().expect("chat state present");
        let peer_a = "bb".repeat(32);
        let peer_b = "cc".repeat(32);
        let dm = Conversation::new_dm(
            push_member(vec![push_member_device(&me, MemberDeviceStatus::Active)]),
            push_member(vec![
                push_member_device(&peer_a, MemberDeviceStatus::Active),
                push_member_device(&peer_b, MemberDeviceStatus::Revoked),
            ]),
            None,
        )
        .unwrap();
        client
            .registry_arc()
            .expect("chat state present")
            .save(&dm)
            .await
            .unwrap();

        let record = sample_pair_record_v4();
        let count = client
            .push_pair_record_to_active_contacts(&record)
            .await
            .unwrap();
        assert_eq!(count, 1, "exactly the one active peer device is pushed");

        let sends = sent.lock().unwrap();
        assert_eq!(sends.len(), 1);
        let (to, env) = &sends[0];
        assert_eq!(
            to,
            &crate::identity::AgentId(peer_a),
            "addressed to the active peer device, not the revoked one or self"
        );
        assert_eq!(
            env.kind,
            crate::transport::OutboundKind::Dm,
            "the push rides the Dm envelope shape"
        );
        let transit = env.transit.as_ref().expect("carries the pre-built transit");
        assert_eq!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::PairRecordPush,
            "transit kind stays PairRecordPush so the receiver re-discriminates it"
        );
        // The carried record round-trips back to exactly what we pushed.
        let payload =
            fetchit_relay_proto::PairRecordPushPayload::from_ciphertext(&transit.ciphertext)
                .unwrap();
        let decoded: fetchit_relay_proto::pair_record::PairRecordV4 =
            serde_json::from_slice(&payload.record_bytes).unwrap();
        assert_eq!(decoded, record);
    }

    #[tokio::test]
    async fn enqueue_dm_optimistic_echo_then_failed_on_unreachable() {
        let (client, _dir) = test_client_no_denylist();
        let mut rx = client.subscribe_outbox().expect("chat state present");
        let peer = crate::identity::AgentId("bb".repeat(32));

        let id = client
            .enqueue_dm(&peer, "hello", "alice", None, None)
            .await
            .expect("enqueue returns a bubble id");

        // Optimistic echo: the Sending bubble is broadcast BEFORE the send
        // is attempted (desktop parity -- the UI shows it immediately).
        let first = rx.recv().await.expect("optimistic echo");
        assert_eq!(first.bubble.id, id);
        assert_eq!(first.bubble.status, crate::outbox::OutboxStatus::Sending);
        assert_eq!(first.bubble.body, "hello");
        assert_eq!(first.bubble.peer, peer);

        // The empty Router reaches no peer, so the send fails and the
        // bubble is recorded Failed via the shared record_send_outcome path.
        let second = rx.recv().await.expect("outcome echo");
        assert_eq!(second.bubble.id, id);
        assert_eq!(second.bubble.status, crate::outbox::OutboxStatus::Failed);
        assert!(second.bubble.last_error.is_some());

        // Snapshot reflects the single terminal-state bubble.
        let snap = client.outbox_snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, id);
        assert_eq!(snap[0].status, crate::outbox::OutboxStatus::Failed);
    }

    #[tokio::test]
    async fn retry_outbox_is_safe_noop_before_driver_starts() {
        // The retry sender is unpublished until start_outbox_driver runs, so
        // retry_outbox must be a no-op (no panic, no block) -- the shell may
        // wire a Retry button before the driver is up.
        let (client, _dir) = test_client_no_denylist();
        client.retry_outbox();
        client.retry_outbox();
    }

    #[tokio::test]
    async fn outbox_accessors_expose_the_live_handles() {
        // A shell driving its own inbound pump needs the SAME store + event
        // sender the engine uses, so dispatch_inbound_with_outbox marks the
        // durable outbox (not just the UI) Delivered.
        let (client, _dir) = test_client_no_denylist();
        let mut rx = client.subscribe_outbox().expect("chat state present");
        let events = client.outbox_events().expect("chat state present");
        let outbox = client.outbox_arc().expect("chat state present");

        let bubble = crate::outbox::OutboxBubble {
            id: "b1".into(),
            peer: crate::identity::AgentId("cc".repeat(32)),
            body: "hi".into(),
            status: crate::outbox::OutboxStatus::Delivered,
            message_id: Some("m1".into()),
            enqueued_at_ms: 1,
            last_error: None,
            group: None,
        };

        // The returned sender feeds the channel subscribe_outbox reads.
        events
            .send(crate::outbox::OutboxEvent {
                bubble: bubble.clone(),
            })
            .expect("a receiver is subscribed");
        let got = rx.recv().await.expect("event delivered");
        assert_eq!(got.bubble.id, "b1");
        assert_eq!(got.bubble.status, crate::outbox::OutboxStatus::Delivered);

        // The returned Arc is the live, mutable store.
        outbox.lock().await.upsert(bubble);
        assert_eq!(outbox.lock().await.snapshot().len(), 1);
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
            outbox: Arc::new(tokio::sync::Mutex::new(
                crate::outbox::store::OutboxStore::new(),
            )),
            outbox_tx: tokio::sync::broadcast::channel(OUTBOX_CHANNEL_CAP).0,
            outbox_retry_tx: Arc::new(std::sync::Mutex::new(None)),
            bridge_inbound_shadow: Arc::new(tokio::sync::Mutex::new(
                crate::groups_reachability::BridgeInboundShadow::new(),
            )),
            members_singleflight: Arc::new(crate::members_singleflight::MembersSingleflight::new()),
            public_post_tx: tokio::sync::broadcast::channel(PUBLIC_POST_CHANNEL_CAP).0,
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
            denylist_consumer: None,
            denylist_dropped_inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            failover_watcher_abort: Arc::new(std::sync::Mutex::new(None)),
            advertised_relays: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            engine_a_supported: Arc::new(std::sync::OnceLock::new()),
            multi_home_inbound: Some(Arc::new(std::sync::Mutex::new(Some(inbound_rx)))),
            primary_relay_url: Arc::new(tokio::sync::RwLock::new(None)),
            neg_resolve_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            custody_passphrase: Some(Arc::new(Zeroizing::new("d9-test".to_owned()))),
            group_kinds: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            multi_home: None,
            fediverse: None,
            relay_failover_cb: Arc::new(tokio::sync::RwLock::new(None)),
            group_recovery: crate::groups::epoch_recovery::GroupStatusMap::new(),
            recovery_cursors: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            recovering: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
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
            false,
        )
        .await
        .expect("REST-only client construction");
        assert!(
            client.denylist.is_none(),
            "fresh REST-only client has no denylist wired"
        );
        assert!(
            client.subscribe_to_block_events().is_none(),
            "no BlockEvent subscriber before install"
        );

        let http: Arc<dyn fetchit_trust_client::HttpClient + Send + Sync + 'static> =
            Arc::new(PendingHttp);
        client
            .install_m3_denylist("https://etchit.io/v1".into(), None, http)
            .expect("install succeeds");
        assert!(client.denylist.is_some(), "denylist installed");
        assert!(
            client.subscribe_to_block_events().is_some(),
            "G4: BlockEvent subscriber available after install for the desktop pump"
        );
        assert_eq!(
            client.denylist_dropped_inbound_count(),
            0,
            "counter starts at zero"
        );
    }

    // ── M4 Stage 5.2 publish driver ───────────────────────────────

    #[tokio::test]
    async fn publish_public_post_errors_without_transport() {
        // test_client_no_denylist builds a chat client with no fediverse
        // transport (REST-only shape) — the guard must fire before any
        // identity load or network, so this stays hermetic.
        let (client, _dir) = test_client_no_denylist();
        let post = fetchit_fedi::PublicPost {
            author_handle: "@josh@etchit.io".to_owned(),
            body_md: "hi".to_owned(),
            created_at_ms: 0,
            reply_to_actor_url: None,
            mentions: vec![],
        };
        let err = client.publish_public_post("josh", &post).await.unwrap_err();
        match err {
            ChatError::Invalid(msg) => assert!(
                msg.contains("fediverse transport not configured"),
                "expected no-transport guard, got: {msg}"
            ),
            other => panic!("expected ChatError::Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_and_register_actor_one_taps_a_minimal_profile_when_none_exists() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        // One-tap: a fresh identity with no published profile (relay 404)
        // must NOT dead-end. Mint publishes a minimal handle-only record to
        // the relay (the POST .expect(1) proves it), then mints. Hermetic:
        // the registry is unreachable, so registration degrades to pending
        // but the mint still succeeds.
        let (client, _dir) = test_client_no_denylist();
        let relay_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/profile/.+$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&relay_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/profile"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&relay_server)
            .await;
        let relay = format!("{}/", relay_server.uri()).parse().unwrap();
        let registry = "http://unused.invalid/".parse().unwrap();
        let outcome = client
            .mint_and_register_actor("alice", "etchit.io", &relay, &registry, 1)
            .await
            .expect("one-tap mint publishes the minimal profile then mints");
        assert!(
            outcome.actor_url.contains("alice"),
            "minted actor url, got {}",
            outcome.actor_url
        );
        // Registry was unreachable: registration is pending, not a failure.
        assert!(!outcome.registered);
        assert!(outcome.registration_error.is_some());
        // relay_server drop asserts the .expect(1) minimal-publish POST fired.
    }

    #[tokio::test]
    async fn actor_vault_round_trips_under_retained_passphrase_custody() {
        // The client retains its build-time custody, so a vault minted
        // through it must reload with no per-call passphrase. This is
        // the c2e0e0df bug class: a `None` passed against a
        // passphrase-mode vault compiled fine and failed only at
        // runtime on mobile; retention makes the mismatch impossible.
        let (client, _dir) = test_client_no_denylist();
        client
            .mint_actor_identity("alice", "etchit.io")
            .await
            .expect("mint under retained passphrase custody");
        let loaded = client
            .load_actor_identity("alice")
            .await
            .expect("load resolves the same retained custody")
            .expect("identity persisted");
        assert_eq!(loaded.handle, "alice");
    }

    #[tokio::test]
    async fn ensure_actor_v2_and_register_reports_pending_when_no_profile() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        // On hub open with no published profile (relay 404), the pass must
        // NOT error -- it reports a pending state so the pane stays usable.
        let (client, _dir) = test_client_no_denylist();
        let relay_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&relay_server)
            .await;
        let relay = format!("{}/", relay_server.uri()).parse().unwrap();
        let registry = "http://unused.invalid/".parse().unwrap();
        let outcome = client
            .ensure_actor_v2_and_register("alice", &relay, &registry, 1)
            .await
            .expect("ensure pass reports pending, never errors on a blocker");
        assert!(!outcome.upgraded);
        assert!(!outcome.registered);
        assert!(outcome.pending.is_some());
    }

    #[tokio::test]
    async fn lookup_fedi_handle_rejects_a_malformed_handle() {
        // A handle that isn't `@user@host` fails at parse, before any network
        // (hermetic). WebFinger/actor/verify branches are covered by the
        // composed pieces' own tests.
        let (client, _dir) = test_client_no_denylist();
        let err = client.lookup_fedi_handle("not-a-handle").await.unwrap_err();
        assert!(matches!(err, ChatError::Invalid(ref m) if m.contains("handle")));
    }

    #[tokio::test]
    async fn import_pair_uri_dispatches_v3_share_uris_to_the_v3_parser() {
        // A `fetchit://share/v3/…` URI must route to the v3 parser
        // (`from_v3_share_uri`), not the x0x pair parser. A malformed v3 URI
        // fails at parse before any network (hermetic), and `import_pair_uri`
        // surfaces the v3 parser's own error — proving the dispatch, since the
        // x0x parser would reject the scheme with a different message.
        let (client, _dir) = test_client_no_denylist();
        let bad = "fetchit://share/v3/deadbeef";
        let via_import = client.import_pair_uri(bad).await.unwrap_err().to_string();
        let via_v3 = crate::profile::from_v3_share_uri(bad)
            .unwrap_err()
            .to_string();
        assert!(
            via_import.contains(&via_v3),
            "import error `{via_import}` should carry the v3 parse error `{via_v3}`",
        );
    }

    #[test]
    fn assemble_recipients_dedups_reply_to_against_mentions() {
        let alice = Url::parse("https://m.example/users/alice").unwrap();
        let mentions = vec![("@alice@m.example".to_owned(), alice.clone())];

        // reply_to that equals an existing mention → single recipient.
        let same = assemble_recipients(&mentions, Some("https://m.example/users/alice")).unwrap();
        assert_eq!(same, vec![alice.clone()]);

        // distinct reply_to → appended as a second recipient.
        let distinct = assemble_recipients(&mentions, Some("https://m.example/users/bob")).unwrap();
        assert_eq!(distinct.len(), 2);
        assert_eq!(distinct[0], alice);

        // no reply_to → mentions only.
        let none = assemble_recipients(&mentions, None).unwrap();
        assert_eq!(none, vec![alice]);
    }

    #[test]
    fn assemble_recipients_rejects_invalid_reply_to() {
        let err = assemble_recipients(&[], Some("not a url")).unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("reply_to_actor_url")),
            "expected reply_to parse error, got: {err:?}"
        );
    }

    // ── T8b home-relay failover ───────────────────────────────────────────────

    use fetchit_relay_client::ConnState;
    use fetchit_relay_proto::EffectiveCapabilities;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::watch;

    fn st_connected() -> ConnState {
        ConnState::Connected {
            effective_capabilities: EffectiveCapabilities::default_profile(),
        }
    }
    fn st_disconnected() -> ConnState {
        ConnState::Disconnected {
            reason: "test".into(),
            retry_at: None,
        }
    }
    fn st_permanent() -> ConnState {
        ConnState::PermanentlyDisconnected {
            reason: "test".into(),
            attempts: 3,
        }
    }

    /// Records `(dead_url)` for each action invocation and returns a
    /// canned result; counts resubscribe calls so a test can prove the
    /// watcher re-subscribed to the new slot 0 after a migration.
    struct WatcherProbe {
        actions: StdMutex<Vec<String>>,
        resubscribes: std::sync::atomic::AtomicUsize,
    }
    impl WatcherProbe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                actions: StdMutex::new(Vec::new()),
                resubscribes: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn actions(&self) -> Vec<String> {
            self.actions.lock().unwrap().clone()
        }
        fn resubscribe_count(&self) -> usize {
            self.resubscribes.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A `Disconnected` that stays disconnected past `failover_after`
    /// triggers exactly one migration, the action sees the dead URL, and
    /// the watcher then re-subscribes (sticky) to the NEW slot 0.
    ///
    /// The resubscribe stub models a real swap: the FIRST subscription is
    /// the dying relay (`rx`, driven Disconnected below); after the
    /// migration it hands back a fresh, healthy (`Connected`) receiver, so
    /// a correct watcher fails over exactly once and then sits quiet.
    #[tokio::test(start_paused = true)]
    async fn disconnected_past_window_triggers_failover() {
        let (tx, rx) = watch::channel(vec![st_connected()]);
        // Keep the post-migration sender alive for the whole test so its
        // receiver never closes.
        let (_new_tx, new_rx) = watch::channel(vec![st_connected()]);
        let probe = WatcherProbe::new();
        let probe_rs = Arc::clone(&probe);
        let probe_ac = Arc::clone(&probe);
        let rx_for_sub = rx.clone();

        let watcher = tokio::spawn(async move {
            run_failover_watcher(
                move || {
                    let n = probe_rs
                        .resubscribes
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // First subscription = the dying relay; subsequent =
                    // the healthy migrated slot 0.
                    if n == 0 {
                        Some(rx_for_sub.clone())
                    } else {
                        Some(new_rx.clone())
                    }
                },
                || Some("wss://dead.test/v1/ws".to_string()),
                Duration::from_millis(50),
                Duration::from_millis(50),
                move |dead| {
                    let p = Arc::clone(&probe_ac);
                    async move {
                        p.actions.lock().unwrap().push(dead);
                        Ok::<String, ()>("wss://new.test/v1/ws".to_string())
                    }
                },
            )
            .await;
        });

        // Drop to Disconnected and let the window elapse.
        tx.send(vec![st_disconnected()]).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(
            probe.actions(),
            vec!["wss://dead.test/v1/ws".to_string()],
            "a sustained Disconnected past the window must trigger exactly one failover with the dead url",
        );
        // resubscribe is called at least twice: once for the initial
        // subscription and once more after the successful migration.
        assert!(
            probe.resubscribe_count() >= 2,
            "watcher must re-subscribe after a successful migration, got {} calls",
            probe.resubscribe_count(),
        );
        watcher.abort();
    }

    /// A return to `Connected` before the window elapses resets the
    /// timer: no failover fires.
    #[tokio::test(start_paused = true)]
    async fn disconnected_then_reconnected_resets_timer() {
        let (tx, rx) = watch::channel(vec![st_connected()]);
        let probe = WatcherProbe::new();
        let probe_ac = Arc::clone(&probe);
        let rx_for_sub = rx.clone();

        let watcher = tokio::spawn(async move {
            run_failover_watcher(
                move || Some(rx_for_sub.clone()),
                || Some("wss://dead.test/v1/ws".to_string()),
                Duration::from_millis(100),
                Duration::from_millis(100),
                move |dead| {
                    let p = Arc::clone(&probe_ac);
                    async move {
                        p.actions.lock().unwrap().push(dead);
                        Ok::<String, ()>("wss://new.test/v1/ws".to_string())
                    }
                },
            )
            .await;
        });

        tx.send(vec![st_disconnected()]).unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        // Reconnect before the 100ms window elapses.
        tx.send(vec![st_connected()]).unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert!(
            probe.actions().is_empty(),
            "a reconnect within the window must reset the timer and skip failover, got {:?}",
            probe.actions(),
        );
        watcher.abort();
    }

    /// `PermanentlyDisconnected` triggers a failover immediately —
    /// without waiting for the disconnect window.
    ///
    /// The resubscribe stub models the swap exactly like the sticky test
    /// above: the FIRST subscription is the dying relay (driven Permanent
    /// below); post-migration subscriptions hand back a fresh healthy
    /// `Connected` receiver so the watcher parks on `changed().await`. A
    /// stub that kept returning the stuck-Permanent receiver would spin
    /// the watcher in an unyielding trigger/action cycle and starve the
    /// current-thread test runtime (the abort below would never land).
    #[tokio::test(start_paused = true)]
    async fn permanently_disconnected_triggers_immediately() {
        let (tx, rx) = watch::channel(vec![st_connected()]);
        // Keep the post-migration sender alive for the whole test so its
        // receiver never closes.
        let (_new_tx, new_rx) = watch::channel(vec![st_connected()]);
        let probe = WatcherProbe::new();
        let probe_rs = Arc::clone(&probe);
        let probe_ac = Arc::clone(&probe);
        let rx_for_sub = rx.clone();

        let watcher = tokio::spawn(async move {
            run_failover_watcher(
                move || {
                    let n = probe_rs
                        .resubscribes
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n == 0 {
                        Some(rx_for_sub.clone())
                    } else {
                        Some(new_rx.clone())
                    }
                },
                || Some("wss://dead.test/v1/ws".to_string()),
                // A long window: if the trigger waited for it, the test
                // would see no action in its short sleep below.
                Duration::from_secs(600),
                Duration::from_millis(50),
                move |dead| {
                    let p = Arc::clone(&probe_ac);
                    async move {
                        p.actions.lock().unwrap().push(dead);
                        Ok::<String, ()>("wss://new.test/v1/ws".to_string())
                    }
                },
            )
            .await;
        });

        tx.send(vec![st_permanent()]).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            probe.actions(),
            vec!["wss://dead.test/v1/ws".to_string()],
            "PermanentlyDisconnected must trigger immediately, not wait for the window",
        );
        watcher.abort();
    }

    /// When the action fails (no candidate / `replace_primary` error) the
    /// watcher backs off and retries rather than spinning tight or
    /// crashing. With a terminal state + a short backoff it re-attempts,
    /// so we observe more than one action over the window.
    #[tokio::test(start_paused = true)]
    async fn action_failure_backs_off_and_retries() {
        let (tx, rx) = watch::channel(vec![st_connected()]);
        let probe = WatcherProbe::new();
        let probe_ac = Arc::clone(&probe);
        let rx_for_sub = rx.clone();

        let watcher = tokio::spawn(async move {
            run_failover_watcher(
                move || Some(rx_for_sub.clone()),
                || Some("wss://dead.test/v1/ws".to_string()),
                Duration::from_millis(50),
                Duration::from_millis(50),
                move |dead| {
                    let p = Arc::clone(&probe_ac);
                    async move {
                        p.actions.lock().unwrap().push(dead);
                        Err::<String, ()>(())
                    }
                },
            )
            .await;
        });

        tx.send(vec![st_permanent()]).unwrap();
        tokio::time::sleep(Duration::from_millis(180)).await;

        let n = probe.actions().len();
        assert!(
            n >= 2,
            "on action failure the watcher must back off and retry (saw {n} attempts), not give up after one",
        );
        watcher.abort();
    }

    /// Candidate selection: the first advertised relay that is not the
    /// dead primary wins.
    #[test]
    fn pick_failover_candidate_skips_dead_primary() {
        let advertised = vec![
            "wss://a.test/v1/ws".to_string(),
            "wss://b.test/v1/ws".to_string(),
            "wss://c.test/v1/ws".to_string(),
        ];
        assert_eq!(
            pick_failover_candidate(&advertised, "wss://a.test/v1/ws"),
            Some("wss://b.test/v1/ws".to_string()),
            "the dead primary must be skipped; the next entry wins",
        );
    }

    /// Candidate selection: an empty list, or a list containing only the
    /// dead primary, yields no candidate (no-fallback path).
    #[test]
    fn pick_failover_candidate_none_when_only_dead_or_empty() {
        assert_eq!(pick_failover_candidate(&[], "wss://a.test/v1/ws"), None);
        assert_eq!(
            pick_failover_candidate(&["wss://a.test/v1/ws".to_string()], "wss://a.test/v1/ws"),
            None,
            "a list with only the dead primary must yield no candidate",
        );
    }

    /// `primary_relay_url` is interior-mutable: a write through the
    /// `Arc<RwLock<..>>` is visible through a second `Client` clone
    /// (they share the same lock).
    #[tokio::test]
    async fn primary_relay_url_is_shared_across_clones() {
        let (client, _dir) = test_client_no_denylist();
        let clone = client.clone();

        // Seed a value, then mutate through the original handle.
        *client.primary_relay_url.write().await = Some("wss://before.test/v1/ws".to_string());
        assert_eq!(
            clone.primary_relay_url.read().await.clone(),
            Some("wss://before.test/v1/ws".to_string()),
            "the clone must observe the seeded primary (shared lock)",
        );

        *clone.primary_relay_url.write().await = Some("wss://after.test/v1/ws".to_string());
        assert_eq!(
            client.primary_relay_url.read().await.clone(),
            Some("wss://after.test/v1/ws".to_string()),
            "a write through one clone must be visible through the other",
        );
    }

    // ── T9 migrate_primary ────────────────────────────────────────────────

    /// No-op denylist gate for the test multi-home transport.
    struct MigrateNoopDenylist;
    impl fetchit_trust::DenylistQuery for MigrateNoopDenylist {
        fn is_blocked(&self, _: fetchit_trust::EntryKind, _: &str) -> bool {
            false
        }
    }

    /// Stub relay builder: returns a `RelayHandle::mock(url)` for any URL.
    /// Mock handles have no inner `RelayTransport`, so
    /// `MultiHomeTransport::replace_primary` skips the liveness wait and the
    /// swap commits immediately -- exactly the seam `migrate_primary` needs
    /// to be unit-testable without a live relay.
    #[derive(Default)]
    struct MigrateStubBuilder;

    #[async_trait]
    impl crate::transport::RelayBuilder for MigrateStubBuilder {
        async fn build(
            &self,
            url: &str,
        ) -> std::result::Result<Arc<crate::transport::RelayHandle>, crate::transport::TransportError>
        {
            Ok(Arc::new(crate::transport::RelayHandle::mock(
                url.to_owned(),
            )))
        }
    }

    /// Build a test client wired with a real `MultiHomeTransport` (over the
    /// mock builder) so `migrate_primary`'s full state-transition path runs.
    /// The primary is seeded to `primary`; advertised relays start as
    /// `[primary]`. The forwarding-record + pair-record HTTP halves point at
    /// an unreachable host and are best-effort, so they no-op without
    /// affecting the asserted state transitions (wire coverage lives in the
    /// T3/T7 wiremock suites + the live mission).
    async fn test_client_with_mh(primary: &str) -> (Client, tempfile::TempDir) {
        let (mut client, dir) = test_client_no_denylist();
        let denylist: Arc<dyn fetchit_trust::DenylistQuery> = Arc::new(MigrateNoopDenylist);
        let builder: Arc<dyn crate::transport::RelayBuilder> = Arc::new(MigrateStubBuilder);
        let mh = crate::transport::MultiHomeTransport::new(
            primary.to_owned(),
            denylist,
            Arc::new(|_env| {}),
            builder,
        )
        .await
        .expect("mock multi-home transport builds");
        client.multi_home = Some(Arc::new(mh));
        *client.primary_relay_url.write().await = Some(primary.to_owned());
        *client.advertised_relays.write().await = vec![primary.to_owned()];
        (client, dir)
    }

    /// REST-only client (no multi-home) rejects `migrate_primary` with an
    /// Invalid error -- it is a relay-mode-only API.
    #[tokio::test]
    async fn migrate_primary_rest_only_rejected() {
        let (client, _dir) = test_client_no_denylist();
        let err = client
            .migrate_primary("wss://new.test/v1/ws")
            .await
            .expect_err("no multi-home must reject");
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    /// Migrating to the same url already pinned is a no-op success and does
    /// not fire the callback.
    #[tokio::test]
    async fn migrate_primary_same_url_is_noop() {
        let (client, _dir) = test_client_with_mh("wss://same.test/v1/ws").await;
        let fired = Arc::new(std::sync::Mutex::new(Vec::<RelayFailoverEvent>::new()));
        let sink = Arc::clone(&fired);
        client.set_relay_failover_callback(Arc::new(move |ev| {
            sink.lock().unwrap().push(ev);
        }));

        client
            .migrate_primary("wss://same.test/v1/ws")
            .await
            .expect("same-url migration is a no-op success");

        assert_eq!(
            client.primary_relay_url.read().await.clone(),
            Some("wss://same.test/v1/ws".to_string()),
        );
        assert!(
            fired.lock().unwrap().is_empty(),
            "a same-url no-op must not fire the failover callback",
        );
    }

    /// Happy path: migrating to a fresh url swaps slot 0, updates the live
    /// primary, replaces the old url in the advertised list, and fires
    /// `Migrated { from, to }`. Uses `wss://` urls so the best-effort card
    /// regenerate (which validates the relay scheme) actually commits the
    /// advertised-list swap.
    #[tokio::test]
    async fn migrate_primary_swaps_state_and_fires_migrated() {
        let old = "wss://old.test/v1/ws";
        let new = "wss://new.test/v1/ws";
        let (client, _dir) = test_client_with_mh(old).await;

        let fired = Arc::new(std::sync::Mutex::new(Vec::<RelayFailoverEvent>::new()));
        let sink = Arc::clone(&fired);
        client.set_relay_failover_callback(Arc::new(move |ev| {
            sink.lock().unwrap().push(ev);
        }));

        client
            .migrate_primary(new)
            .await
            .expect("migration over the mock transport succeeds");

        // Live primary now points at the new relay.
        assert_eq!(
            client.primary_relay_url.read().await.clone(),
            Some(new.to_string()),
            "primary must be updated to the new url",
        );
        // Advertised list swapped old -> new.
        assert_eq!(
            client.advertised_relays.read().await.clone(),
            vec![new.to_string()],
            "the old url must be replaced by the new one in the advertised list",
        );
        // Callback fired once with Migrated carrying both urls.
        let events = fired.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "exactly one failover event must fire");
        match &events[0] {
            RelayFailoverEvent::Migrated { from, to } => {
                assert_eq!(from, old);
                assert_eq!(to, new);
            }
            other @ RelayFailoverEvent::Failed { .. } => {
                panic!("expected Migrated, got {other:?}")
            }
        }
    }

    /// Best-effort semantics (client.rs:1113-1122): when the OLD relay is
    /// unreachable so the forwarding POST fails, the migration still returns
    /// Ok, the primary cell holds the new url, and Migrated fires. The
    /// layer-2 heal is advisory; its failure must not unwind the committed
    /// swap.
    #[tokio::test]
    async fn migrate_primary_old_relay_unreachable_still_migrates() {
        // A closed loopback port: the forwarding POST gets connection-refused
        // fast (no timeout wait) and is swallowed as best-effort.
        let old = "http://127.0.0.1:1/v1/ws";
        let new = "wss://new.test/v1/ws";
        let (client, _dir) = test_client_with_mh(old).await;

        let fired = Arc::new(std::sync::Mutex::new(Vec::<RelayFailoverEvent>::new()));
        let sink = Arc::clone(&fired);
        client.set_relay_failover_callback(Arc::new(move |ev| {
            sink.lock().unwrap().push(ev);
        }));

        client
            .migrate_primary(new)
            .await
            .expect("migration succeeds even when the old-relay forwarding POST fails");

        assert_eq!(
            client.primary_relay_url.read().await.clone(),
            Some(new.to_string()),
            "primary cell must hold the new url",
        );
        let events = fired.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "Migrated must still fire");
        assert!(
            matches!(&events[0], RelayFailoverEvent::Migrated { to, .. } if to == new),
            "event must be Migrated to the new url, got {:?}",
            events[0]
        );
    }

    /// Migrating to a url that already occupies an outbound slot (1/2):
    /// `replace_primary` always installs the new url into slot 0 regardless
    /// of the LRU slots, so slot 0 ends up the new url with no panic. The
    /// transient duplicate in slot 1/2 is benign (the next `acquire_slot`
    /// reuses by url).
    #[tokio::test]
    async fn migrate_primary_to_url_in_outbound_slot_keeps_slot0_consistent() {
        use fetchit_relay_proto::{
            AgentId as RelayAgentId, EnvelopeKind, MachineId, TransitEnvelope, WIRE_VERSION,
        };

        let old = "wss://old.test/v1/ws";
        let new = "wss://new.test/v1/ws";
        let (client, _dir) = test_client_with_mh(old).await;

        // Open slot 1 on `new` via an outbound send through the multi-home
        // transport, so `new` already occupies an LRU slot before migration.
        let mh = client.multi_home.clone().expect("multi-home wired");
        let envelope = TransitEnvelope {
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
        };
        let to = crate::identity::AgentId("1".repeat(64));
        let hints = crate::card::RendezvousHintsV1 {
            relays: vec![new.to_string()],
        };
        mh.send_inner(&to, envelope, &hints)
            .await
            .expect("mock send opens slot 1 on the new url");
        assert!(
            mh.slots_for_test()[1]
                .as_ref()
                .is_some_and(|s| s.relay_url == new),
            "precondition: new url must occupy slot 1",
        );

        client
            .migrate_primary(new)
            .await
            .expect("migration to a slot-occupying url succeeds without panic");

        let slots = mh.slots_for_test();
        assert_eq!(
            slots[0].as_ref().map(|s| s.relay_url.clone()),
            Some(new.to_string()),
            "slot 0 must be the new url after migration",
        );
        assert_eq!(
            client.primary_relay_url.read().await.clone(),
            Some(new.to_string()),
        );
    }

    /// `stop_failover_watcher` is idempotent: a second call (or a call when
    /// no watcher was ever spawned) is a no-op and never panics.
    #[tokio::test]
    async fn stop_failover_watcher_twice_is_noop() {
        let (client, _dir) = test_client_with_mh("wss://primary.test/v1/ws").await;
        client.stop_failover_watcher();
        client.stop_failover_watcher();
    }

    /// `migrate_primary` with extra advertised entries preserves the others
    /// and swaps only the matching old url.
    #[tokio::test]
    async fn migrate_primary_preserves_other_advertised_entries() {
        let old = "wss://old.test/v1/ws";
        let new = "wss://new.test/v1/ws";
        let (client, _dir) = test_client_with_mh(old).await;
        *client.advertised_relays.write().await =
            vec![old.to_string(), "wss://other.test/v1/ws".to_string()];

        client
            .migrate_primary(new)
            .await
            .expect("migration succeeds");

        assert_eq!(
            client.advertised_relays.read().await.clone(),
            vec![new.to_string(), "wss://other.test/v1/ws".to_string()],
            "only the matching old entry is swapped; others are preserved",
        );
    }
}
