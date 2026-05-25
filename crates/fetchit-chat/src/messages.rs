//! Direct messages — point-to-point E2E over QUIC. Never broadcast.
//!
//! Inbound DMs arrive on the daemon's SSE stream
//! (`GET /direct/events` or the unified `/events`). The daemon does
//! not retain DM history server-side; persistent transcripts live on
//! the consumer (the fetch>it desktop app stores them locally).

use crate::error::Result;
use crate::identity::AgentId;
use crate::transport::Http;
use serde::{Deserialize, Serialize};

/// A direct message — inbound or outbound.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectMessage {
    /// Sender's agent id.
    pub from: AgentId,
    /// Recipient's agent id.
    pub to: AgentId,
    /// Plaintext body (already decrypted by the daemon).
    pub body: String,
    /// Unix epoch milliseconds.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// Daemon-assigned message id.
    #[serde(default)]
    pub message_id: Option<String>,
}

/// Endpoint wrapper. Build via [`Client::messages`](crate::Client::messages).
#[derive(Debug)]
pub struct Endpoint<'a> {
    http: &'a Http,
}

#[derive(Serialize)]
struct SendRequest<'a> {
    agent_id: &'a str,
    body: &'a str,
}

#[derive(Serialize)]
struct ConnectRequest<'a> {
    agent_id: &'a str,
}

#[derive(Deserialize)]
struct SendResponse {
    #[serde(default)]
    message_id: Option<String>,
}

#[derive(Deserialize)]
struct ConnectionsResponse {
    #[serde(default)]
    connections: Vec<AgentId>,
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(http: &'a Http) -> Self {
        Self { http }
    }

    /// Establish a direct QUIC channel to a peer. Optional — sending
    /// opens a channel implicitly — but pre-warming reduces first-
    /// message latency.
    pub async fn connect(&self, agent_id: &AgentId) -> Result<()> {
        let _: serde_json::Value = self
            .http
            .post_json(
                "/agents/connect",
                &ConnectRequest {
                    agent_id: &agent_id.0,
                },
            )
            .await?;
        Ok(())
    }

    /// Send a direct message. Returns the daemon-assigned message id.
    pub async fn send(&self, to: &AgentId, body: &str) -> Result<Option<String>> {
        let resp: SendResponse = self
            .http
            .post_json(
                "/direct/send",
                &SendRequest {
                    agent_id: &to.0,
                    body,
                },
            )
            .await?;
        Ok(resp.message_id)
    }

    /// List currently-open direct connections.
    pub async fn connections(&self) -> Result<Vec<AgentId>> {
        let resp: ConnectionsResponse = self.http.get_json("/direct/connections").await?;
        Ok(resp.connections)
    }
}
