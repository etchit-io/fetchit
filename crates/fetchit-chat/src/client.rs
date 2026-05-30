//! Top-level chat client. Owns the HTTP wrapper to x0xd, a Router of
//! message transports, the local chat identity vault, and the
//! conversation registry.

use crate::at_rest::{
    fresh_argon_salt, kdf_id_argon2, kdf_id_keychain, read_argon_salt, read_kdf_id, MasterKey,
    MasterKeySource, ARGON_SALT_LEN,
};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::{build_welcome_outbox, ConversationRegistry};
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
            .field("passphrase", &self.passphrase.as_deref().map(|_| "<redacted>"))
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
        let needs_chat = relay_url.is_some()
            || data_dir.is_some()
            || passphrase.is_some()
            || enable_lan_direct;

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

/// Borrow the live relay transport when one is wired. Returns
/// `None` for REST-only clients. The chat layer uses this to drive
/// relay-level capabilities (e.g. the presence watch set) that don't
/// fit cleanly behind the `Transport` trait.
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
            Arc::new(move |aid: &identity::AgentId| {
                registry_for_lookup.peer_ml_dsa_pubkey(aid)
            })
        });
        let local_aid = identity::AgentId(agent_id_hex.clone());
        let bind = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
        );
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
    use crate::chat_crypto::random_symmetric_key;
    use rand::rngs::OsRng;

    let cached = registry.snapshot_cached().await;
    let mut rekeyed = 0usize;
    for mut conv in cached {
        if !conv.auto_rekey_due() {
            continue;
        }
        let new_key = random_symmetric_key(&mut OsRng);
        conv.advance_epoch(new_key);
        let welcomes = build_welcome_outbox(&conv, identity, machine_id, signer.as_ref()).await?;
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
        registry.save(&conv).await?;
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
            let master =
                MasterKey::resolve(&MasterKeySource::Passphrase(pass.to_owned()), Some(&salt))?;
            Ok((master, kdf_id, Some(salt)))
        } else {
            let master = MasterKey::resolve(&MasterKeySource::Keychain, None)?;
            Ok((master, kdf_id, None))
        }
    } else if let Some(pass) = passphrase {
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase(pass.to_owned()), Some(&salt))?;
        Ok((master, kdf_id_argon2(), Some(salt)))
    } else {
        let master = MasterKey::resolve(&MasterKeySource::Keychain, None)?;
        Ok((master, kdf_id_keychain(), None))
    }
}
