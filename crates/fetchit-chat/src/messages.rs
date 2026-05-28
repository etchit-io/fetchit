//! Direct messages — point-to-point E2E delivery via a [`Router`] of
//! message transports.
//!
//! Outbound: caller invokes [`Endpoint::send`], which wraps the body
//! in the JSON envelope (`{text, sender_name, ts}`) and routes through
//! the highest-priority reachable transport.
//!
//! Inbound: not handled here. Direct messages arrive on each
//! transport's inbound channel (`relay`, future `lan-direct`). The
//! desktop event pump consumes those receivers via
//! [`crate::Client::take_transport_inbound`] and decodes each frame
//! through [`decode_direct_message`].

use crate::error::Result;
use crate::http::Http;
use crate::identity::AgentId;
use crate::transport::{InboundEnvelope, OutboundEnvelope, OutboundKind, Router};
use serde::{Deserialize, Serialize};

/// A direct message — inbound or outbound, after the JSON envelope
/// has been unwrapped.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectMessage {
    /// Sender's agent id.
    pub from: AgentId,
    /// Recipient's agent id. Inbound deliveries don't carry this —
    /// the recipient is always the local agent.
    #[serde(default)]
    pub to: Option<AgentId>,
    /// Plaintext body extracted from the envelope's `text` field.
    pub body: String,
    /// Display name from the envelope's `sender_name` field.
    #[serde(default)]
    pub sender_name: Option<String>,
    /// Envelope timestamp (ms since the Unix epoch).
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// Stable message id assigned by the transport (relay dedupe key,
    /// LAN-direct sequence, …).
    #[serde(default)]
    pub message_id: Option<String>,
    /// Whether the transport verified the sender's signature. The
    /// relay always returns `Some(true)` since it verifies ML-DSA-65
    /// at auth time.
    #[serde(default)]
    pub verified: Option<bool>,
}

/// JSON envelope wrapping a DM body. Shared with other client
/// implementations on the wire.
#[derive(Serialize, Deserialize)]
struct Envelope {
    text: String,
    #[serde(default)]
    sender_name: Option<String>,
    ts: u64,
}

/// Endpoint wrapper. Build via [`crate::Client::messages`].
pub struct Endpoint<'a> {
    http: &'a Http,
    router: &'a Router,
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(http: &'a Http, router: &'a Router) -> Self {
        Self { http, router }
    }

    /// Send a direct message. `sender_name` is the display name the
    /// recipient sees. Returns the transport-assigned message id when
    /// available.
    ///
    /// # Errors
    /// [`ChatError::NoTransportAvailable`] if no transport can reach
    /// the recipient. Returns the transport's underlying error
    /// otherwise.
    pub async fn send(
        &self,
        to: &AgentId,
        text: &str,
        sender_name: &str,
    ) -> Result<Option<String>> {
        let timestamp_ms = now_ms();
        let envelope = Envelope {
            text: text.to_owned(),
            sender_name: Some(sender_name.to_owned()),
            ts: timestamp_ms,
        };
        let payload = serde_json::to_vec(&envelope)?;
        let out = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload,
            timestamp_ms,
        };
        let receipt = self.router.send(to, out).await?;
        Ok(receipt.message_id)
    }

    /// List currently-open x0xd direct connections — pure compat
    /// signal. Relay-routed delivery does not need pre-connect.
    pub async fn connections(&self) -> Result<Vec<AgentId>> {
        #[derive(Deserialize)]
        struct ConnectionsResponse {
            #[serde(default)]
            connections: Vec<AgentId>,
        }
        let resp: ConnectionsResponse = self.http.get_json("/direct/connections").await?;
        Ok(resp.connections)
    }

    /// Pre-warm a direct x0xd channel. No-op for relay-routed sends;
    /// kept for API parity.
    pub async fn connect(&self, agent_id: &AgentId) -> Result<()> {
        #[derive(Serialize)]
        struct ConnectRequest<'a> {
            agent_id: &'a str,
        }
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
}

/// Decode an [`InboundEnvelope`] (raw bytes from a transport) into a
/// [`DirectMessage`]. Used by the desktop event pump.
///
/// # Errors
/// Returns [`ChatError::Decode`] if the payload isn't valid JSON in
/// the expected envelope shape. Empty payloads decode to a `DirectMessage`
/// with an empty body — caller does not need to special-case them.
pub fn decode_direct_message(inbound: InboundEnvelope) -> Result<DirectMessage> {
    if inbound.payload.is_empty() {
        return Ok(DirectMessage {
            from: inbound.from,
            to: None,
            body: String::new(),
            sender_name: None,
            timestamp_ms: Some(inbound.timestamp_ms),
            message_id: None,
            verified: Some(true),
        });
    }
    let env: Envelope = serde_json::from_slice(&inbound.payload)?;
    Ok(DirectMessage {
        from: inbound.from,
        to: None,
        body: env.text,
        sender_name: env.sender_name,
        timestamp_ms: Some(env.ts),
        message_id: None,
        verified: Some(true),
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_round_trip_extracts_fields() {
        let env = Envelope {
            text: "hello".into(),
            sender_name: Some("Alice".into()),
            ts: 1_700_000_000_000,
        };
        let payload = serde_json::to_vec(&env).unwrap();
        let inbound = InboundEnvelope {
            kind: OutboundKind::Dm,
            from: AgentId("a".repeat(64)),
            payload,
            timestamp_ms: 1_700_000_000_000,
            transport_name: "relay",
        };
        let dm = decode_direct_message(inbound).unwrap();
        assert_eq!(dm.body, "hello");
        assert_eq!(dm.sender_name.as_deref(), Some("Alice"));
        assert_eq!(dm.from.0, "a".repeat(64));
        assert_eq!(dm.timestamp_ms, Some(1_700_000_000_000));
        assert_eq!(dm.verified, Some(true));
    }

    #[test]
    fn empty_payload_yields_empty_body() {
        let inbound = InboundEnvelope {
            kind: OutboundKind::Dm,
            from: AgentId("a".repeat(64)),
            payload: Vec::new(),
            timestamp_ms: 1,
            transport_name: "relay",
        };
        let dm = decode_direct_message(inbound).unwrap();
        assert_eq!(dm.body, "");
        assert_eq!(dm.sender_name, None);
    }

    #[test]
    fn malformed_payload_errors() {
        let inbound = InboundEnvelope {
            kind: OutboundKind::Dm,
            from: AgentId("a".repeat(64)),
            payload: b"not-json".to_vec(),
            timestamp_ms: 1,
            transport_name: "relay",
        };
        assert!(decode_direct_message(inbound).is_err());
    }
}
