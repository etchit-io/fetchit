//! Direct messages — point-to-point E2E over QUIC. Never broadcast.
//!
//! Inbound DMs arrive on the daemon's SSE stream
//! (`GET /direct/events` or the unified `/events`). The daemon does
//! not retain DM history server-side; persistent transcripts live on
//! the consumer (the fetch>it desktop app stores them locally).
//!
//! Wire shape — `POST /direct/send` takes `{agent_id, payload}` where
//! `payload` is base64-encoded JSON: `{text, sender_name, ts}`. The
//! daemon transports the envelope as opaque bytes; the convention is
//! shared between client implementations (CLI / GUI / fetch>it).

use crate::error::Result;
use crate::identity::AgentId;
use crate::transport::Http;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

/// A direct message — inbound or outbound, after the base64+JSON
/// envelope has been unwrapped.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectMessage {
    /// Sender's agent id.
    pub from: AgentId,
    /// Recipient's agent id. Inbound events from `/direct/events`
    /// don't carry this — the recipient is always the local agent
    /// — so it's optional.
    #[serde(default)]
    pub to: Option<AgentId>,
    /// Plaintext body extracted from the envelope's `text` field.
    pub body: String,
    /// Display name from the envelope's `sender_name` field.
    #[serde(default)]
    pub sender_name: Option<String>,
    /// Envelope timestamp (ms) if present, else the daemon's
    /// `received_at`.
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// Daemon-assigned message id.
    #[serde(default)]
    pub message_id: Option<String>,
    /// Whether the daemon verified the sender's ML-DSA signature.
    #[serde(default)]
    pub verified: Option<bool>,
}

/// Endpoint wrapper. Build via [`Client::messages`](crate::Client::messages).
#[derive(Debug)]
pub struct Endpoint<'a> {
    http: &'a Http,
}

#[derive(Serialize)]
struct SendRequest<'a> {
    agent_id: &'a str,
    payload: String,
}

#[derive(Serialize)]
struct Envelope<'a> {
    text: &'a str,
    sender_name: &'a str,
    ts: u64,
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

    /// Send a direct message. `sender_name` is the display name shown
    /// to the recipient inside the JSON envelope. Returns the daemon-
    /// assigned message id.
    pub async fn send(
        &self,
        to: &AgentId,
        text: &str,
        sender_name: &str,
    ) -> Result<Option<String>> {
        let envelope = Envelope {
            text,
            sender_name,
            ts: now_ms(),
        };
        let envelope_bytes = serde_json::to_vec(&envelope)?;
        let payload = STANDARD.encode(&envelope_bytes);
        let resp: SendResponse = self
            .http
            .post_json(
                "/direct/send",
                &SendRequest {
                    agent_id: &to.0,
                    payload,
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
