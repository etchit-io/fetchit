//! Top-level chat client. Owns the HTTP transport and hands out
//! typed endpoint wrappers for each functional area.

use crate::discovery::{DaemonEndpoint, discover_local};
use crate::error::Result;
use crate::events::{Event, EventStream, open_stream};
use crate::transport::Http;
use crate::{contacts, groups, identity, messages, presence};
use std::sync::Arc;

/// Builder for [`Client`] with optional overrides.
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    base_url: Option<String>,
    token: Option<String>,
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

    /// Build the client. Falls back to [`discover_local`] for any
    /// field not explicitly set.
    pub async fn build(self) -> Result<Client> {
        let (base_url, token) = match (self.base_url, self.token) {
            (Some(u), Some(t)) => (u, t),
            (u, t) => {
                let ep = discover_local().await?;
                (u.unwrap_or(ep.base_url), t.unwrap_or(ep.token))
            }
        };
        Client::from_parts(base_url, token)
    }
}

/// Strongly-typed client for the x0xd REST + WebSocket API.
#[derive(Debug, Clone)]
pub struct Client {
    http: Arc<Http>,
}

impl Client {
    /// Discover a running daemon on this machine and connect to it.
    pub async fn auto() -> Result<Self> {
        Self::builder().build().await
    }

    /// Build from an already-resolved endpoint.
    pub fn from_endpoint(ep: DaemonEndpoint) -> Result<Self> {
        Self::from_parts(ep.base_url, ep.token)
    }

    /// Start a builder for custom configuration.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    fn from_parts(base_url: String, token: String) -> Result<Self> {
        Ok(Self {
            http: Arc::new(Http::new(base_url, token)?),
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

    /// Direct messaging endpoint.
    #[must_use]
    pub fn messages(&self) -> messages::Endpoint<'_> {
        messages::Endpoint::new(&self.http)
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

    /// Open the unified SSE event stream — DMs, presence changes,
    /// contact updates, subscribed gossip topics.
    pub async fn events(&self) -> Result<EventStream<impl futures_util::Stream<Item = Result<Event>>>> {
        open_stream(&self.http, "/events").await
    }

    /// Open the DM-only SSE event stream.
    pub async fn direct_events(&self) -> Result<EventStream<impl futures_util::Stream<Item = Result<Event>>>> {
        open_stream(&self.http, "/direct/events").await
    }

    /// Open the presence-only SSE event stream.
    pub async fn presence_events(&self) -> Result<EventStream<impl futures_util::Stream<Item = Result<Event>>>> {
        open_stream(&self.http, "/presence/events").await
    }

    /// Cheap reachability probe. Returns `Ok(())` if the daemon's
    /// `/health` endpoint responds with success.
    pub async fn health(&self) -> Result<()> {
        let _: serde_json::Value = self.http.get_json("/health").await?;
        Ok(())
    }
}
