//! Top-level chat client. Owns the HTTP wrapper to x0xd, a Router of
//! message transports, and hands out typed endpoint wrappers.

use crate::discovery::{discover_local, DaemonEndpoint};
use crate::error::{ChatError, Result};
use crate::events::{open_stream, Event, EventStream};
use crate::http::Http;
use crate::relay_transport::RelayTransport;
use crate::transport::{InboundEnvelope, Router};
use crate::{contacts, groups, identity, messages, presence};
use fetchit_relay_client::X0xdSigner;
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;

/// Builder for [`Client`] with optional overrides.
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    base_url: Option<String>,
    token: Option<String>,
    relay_url: Option<Url>,
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

    /// Build the client. Falls back to [`discover_local`] for any
    /// x0xd connection field not explicitly set.
    ///
    /// # Errors
    /// Returns discovery, HTTP, or relay-handshake failures.
    pub async fn build(self) -> Result<Client> {
        let (base_url, token) = match (self.base_url, self.token) {
            (Some(u), Some(t)) => (u, t),
            (u, t) => {
                let ep = discover_local().await?;
                (u.unwrap_or(ep.base_url), t.unwrap_or(ep.token))
            }
        };
        Client::from_parts(base_url, token, self.relay_url).await
    }
}

/// Strongly-typed client for the chat surface — wraps x0xd's REST API
/// and the relay-routed message transport.
#[derive(Clone)]
pub struct Client {
    http: Arc<Http>,
    router: Arc<Router>,
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
        Self::from_parts(ep.base_url, ep.token, None).await
    }

    /// Start a builder for custom configuration.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    async fn from_parts(base_url: String, token: String, relay_url: Option<Url>) -> Result<Self> {
        let http = Arc::new(Http::new(base_url.clone(), token.clone())?);
        let mut router = Router::new();
        if let Some(url) = relay_url {
            let base = Url::parse(&base_url)
                .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
            let signer = X0xdSigner::connect(base, token)
                .await
                .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?;
            let relay = RelayTransport::connect(url, signer).await?;
            router.add(relay);
        }
        Ok(Self {
            http,
            router: Arc::new(router),
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
        messages::Endpoint::new(&self.http, &self.router)
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
        f.debug_struct("Client")
            .field("transports", &self.router.len())
            .finish_non_exhaustive()
    }
}
