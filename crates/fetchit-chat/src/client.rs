//! Top-level chat client. Owns the HTTP wrapper to x0xd, a Router of
//! message transports, the local chat identity vault, and the
//! conversation registry.

use crate::at_rest::{
    fresh_argon_salt, kdf_id_argon2, kdf_id_keychain, read_argon_salt, read_kdf_id, MasterKey,
    MasterKeySource, ARGON_SALT_LEN,
};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::ConversationRegistry;
use crate::discovery::{discover_local, DaemonEndpoint};
use crate::error::{ChatError, Result};
use crate::events::{open_stream, Event, EventStream};
use crate::http::Http;
use crate::local_store::StoreLayout;
use crate::relay_transport::RelayTransport;
use crate::transport::{InboundEnvelope, Router};
use crate::{contacts, groups, identity, messages, presence};
use fetchit_relay_client::{Signer, X0xdSigner};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;

/// File name that gates whether vault state already exists for this
/// data dir. The chat identity vault is the first file written, so its
/// presence implies the rest of the layout was initialised under a
/// matching KDF / salt pair.
const IDENTITY_VAULT_FILE: &str = "identity.json.enc";

/// Builder for [`Client`] with optional overrides.
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    base_url: Option<String>,
    token: Option<String>,
    relay_url: Option<Url>,
    data_dir: Option<PathBuf>,
    passphrase: Option<String>,
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
        Self::from_parts(ep.base_url, ep.token, None, None, None).await
    }

    /// Start a builder for custom configuration.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    async fn from_parts(
        base_url: String,
        token: String,
        relay_url: Option<Url>,
        data_dir: Option<PathBuf>,
        passphrase: Option<String>,
    ) -> Result<Self> {
        let http = Arc::new(Http::new(base_url.clone(), token.clone())?);
        let needs_chat = relay_url.is_some() || data_dir.is_some() || passphrase.is_some();

        let (router, chat) = if needs_chat {
            build_with_chat(&http, &base_url, token, relay_url, data_dir, passphrase).await?
        } else {
            (Router::new(), None)
        };

        Ok(Self {
            http,
            router: Arc::new(router),
            chat,
        })
    }

    /// Identity endpoint: read your agent, generate cards, import others.
    #[must_use]
    pub fn identity(&self) -> identity::Endpoint<'_> {
        identity::Endpoint::new(&self.http)
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

async fn build_with_chat(
    http: &Http,
    base_url: &str,
    token: String,
    relay_url: Option<Url>,
    data_dir: Option<PathBuf>,
    passphrase: Option<String>,
) -> Result<(Router, Option<ChatState>)> {
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
        master,
        kdf_id,
        argon_salt,
    ));

    let signer: Arc<dyn Signer> = Arc::new(
        X0xdSigner::connect(
            Url::parse(base_url).map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?,
            token.clone(),
        )
        .await
        .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?,
    );

    let mut router = Router::new();
    if let Some(url) = relay_url {
        let transport_signer = X0xdSigner::connect(
            Url::parse(base_url).map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?,
            token,
        )
        .await
        .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?;
        let relay = RelayTransport::connect(url, transport_signer).await?;
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
