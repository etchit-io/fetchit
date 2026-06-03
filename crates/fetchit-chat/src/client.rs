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
        Self::from_parts(ep.base_url, ep.token, None, None, None, false, None).await
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
    ) -> Result<Self> {
        let http = Arc::new(Http::new(base_url.clone(), token.clone())?);
        let needs_chat =
            relay_url.is_some() || data_dir.is_some() || passphrase.is_some() || enable_lan_direct;

        let (router, chat, relay, lan, lan_bound_addr) = if needs_chat {
            build_with_chat(
                &http,
                &base_url,
                token,
                relay_url,
                data_dir,
                passphrase,
                enable_lan_direct,
                contact_pubkey_lookup,
            )
            .await?
        } else {
            (Router::new(), None, None, None, None)
        };

        let router = Arc::new(router);
        if let Some(chat) = chat.as_ref() {
            spawn_auto_rekey_sweeper(&router, chat);
        }

        Ok(Self {
            http,
            router,
            chat,
            relay,
            lan,
            lan_bound_addr,
        })
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
        messages::Endpoint::new(
            &self.http,
            &self.router,
            self.chat.as_ref().map(|c| &c.identity),
            self.chat.as_ref().map(|c| &c.registry),
            self.chat.as_ref().map(|c| &c.signer),
            self.chat.as_ref().map(|c| &c.layout),
            self.chat.as_ref().map_or([0u8; 32], |c| c.local_machine_id),
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
    #[must_use]
    pub fn take_transport_inbound(
        &self,
        name: &str,
    ) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
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
            .relay_client()
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
            .relay_client()
            .unwatch_presence(agents)
            .map_err(|e| ChatError::MessageTransport(format!("unwatch_presence: {e}")))
    }

    /// Await the next relay-emitted `PresenceUpdate`. Returns `None`
    /// if no relay transport is wired or the supervisor has shut down.
    pub async fn next_relay_presence(&self) -> Option<fetchit_relay_proto::PresenceUpdate> {
        let relay = self.relay.as_ref()?;
        relay.relay_client().next_presence().await
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
        Some(relay.relay_client().connection_state())
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
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn build_with_chat(
    http: &Http,
    base_url: &str,
    token: String,
    relay_url: Option<Url>,
    data_dir: Option<PathBuf>,
    passphrase: Option<String>,
    enable_lan_direct: bool,
    contact_pubkey_lookup: Option<ContactPubkeyLookup>,
) -> Result<(
    Router,
    Option<ChatState>,
    Option<Arc<RelayTransport>>,
    Option<Arc<LanDirectTransport>>,
    Option<std::net::SocketAddr>,
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
    let x0xd_signer = Arc::new(
        X0xdSigner::connect(
            Url::parse(base_url).map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?,
            token,
        )
        .await
        .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?,
    );
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

    let mut relay_handle: Option<Arc<RelayTransport>> = None;
    if let Some(url) = relay_url {
        let relay = RelayTransport::connect(url, x0xd_signer.clone()).await?;
        relay_handle = Some(relay.clone());
        router.add(relay);
    }

    Ok((
        router,
        Some(ChatState {
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
        }),
        relay_handle,
        lan_handle,
        lan_bound_addr,
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
fn spawn_auto_rekey_sweeper(router: &Arc<Router>, chat: &ChatState) {
    let registry = chat.registry.clone();
    let identity = chat.identity.clone();
    let signer = chat.signer.clone();
    let router = router.clone();
    let machine_id = chat.local_machine_id;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(AUTO_REKEY_SWEEP_INTERVAL);
        // First tick fires immediately; skip so we don't rotate on
        // launch.
        tick.tick().await;
        loop {
            tick.tick().await;
            match sweep_auto_rekey(&registry, &identity, &router, machine_id, &signer).await {
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
            if let Err(e) = router.send(&recipient, transport_out).await {
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
    use base64::Engine as _;
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
}
