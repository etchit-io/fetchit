//! Direct messages — conversation-encrypted point-to-point delivery.
//!
//! `Endpoint::send` looks up (or bootstraps) a `Conversation` with the
//! recipient, builds a Welcome outbox on first contact + a Message
//! outbox every send, and routes each `TransitEnvelope` through a
//! [`Router`] of message transports. Inbound is handled separately by
//! the desktop pump via [`conversation::dispatch_inbound`].
//!
//! Legacy plaintext-envelope decode helper [`decode_direct_message`]
//! is preserved for transports that don't speak the v2 conversation
//! wire format (and for the live-relay self-DM test).

use crate::card::{extended_card_from_uri, verify_card_extension};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::{
    build_message_outbox, build_welcome_outbox, Conversation, ConversationRegistry, Member,
    MemberDevice, MemberDeviceStatus, OutboundEnvelope as ChatOutbound,
};
use crate::error::{ChatError, Result};
use crate::http::Http;
use crate::identity::AgentId;
use crate::local_store::{write_json_atomic, StoreLayout};
use crate::transport::{
    InboundEnvelope, OutboundEnvelope as TransportOutbound, OutboundKind, Router,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A direct message — inbound or outbound, after the JSON envelope
/// has been unwrapped. Used only by transports that still speak the
/// legacy plaintext-envelope wire format.
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

/// Legacy JSON envelope wrapping a DM body.
#[derive(Serialize, Deserialize)]
struct LegacyEnvelope {
    text: String,
    #[serde(default)]
    sender_name: Option<String>,
    ts: u64,
}

/// On-disk record of a peer's share card. The v2 fields supply the
/// peer's KEM public key (needed to bootstrap a conversation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContactCard {
    /// Peer's 64-char hex agent id (also the file stem).
    pub agent_id_hex: String,
    /// Display name carried in the x0x card.
    pub display_name: String,
    /// ML-KEM-768 public key (base64).
    pub kem_public_key_b64: String,
}

impl StoredContactCard {
    /// Build a stored card from a share URI. Extracts the v2 KEM
    /// public key field. When the share URI carries the issuer's
    /// ML-DSA-65 public key, the signature is verified; otherwise the
    /// extraction is trusted on the URI bearer (matches the relay's
    /// `AcceptAllVerifier` posture for v1).
    ///
    /// # Errors
    /// Invalid URI, missing v2 fields, or ML-DSA verification failure
    /// when the issuer key is present.
    pub fn from_share_uri(uri: &str) -> Result<Self> {
        let card_json = extended_card_from_uri(uri)?;
        let obj = card_json
            .as_object()
            .ok_or_else(|| ChatError::Invalid("share card must be a JSON object".into()))?;
        let agent_id_hex = obj
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ChatError::Invalid("share card missing agent_id".into()))?
            .to_owned();
        let display_name = obj
            .get("display_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let kem_public_key_b64 = if let Some(agent_pk_b64) = obj
            .get("public_key_b64")
            .or_else(|| obj.get("agent_public_key_b64"))
            .and_then(serde_json::Value::as_str)
        {
            let agent_pk = B64
                .decode(agent_pk_b64)
                .map_err(|e| ChatError::Invalid(format!("agent pk b64: {e}")))?;
            verify_card_extension(&card_json, &agent_pk)?.kem_public_key_b64
        } else {
            obj.get("fetchit_kem_public_key_b64")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    ChatError::Invalid("card missing fetchit_kem_public_key_b64".into())
                })?
                .to_owned()
        };
        Ok(Self {
            agent_id_hex,
            display_name,
            kem_public_key_b64,
        })
    }

    /// Persist this card to `layout.contact_path(self.agent_id_hex)`.
    ///
    /// # Errors
    /// IO or JSON serialization failures.
    pub fn save(&self, layout: &StoreLayout) -> Result<()> {
        let path = layout.contact_path(&self.agent_id_hex);
        write_json_atomic(&path, self)
    }

    /// Load a stored card from disk by agent id.
    ///
    /// Returns `Ok(None)` when no card is on disk.
    ///
    /// # Errors
    /// IO or JSON parse failures.
    pub fn load(layout: &StoreLayout, agent_id_hex: &str) -> Result<Option<Self>> {
        let path = layout.contact_path(agent_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let card: Self = serde_json::from_slice(&bytes)
            .map_err(|e| ChatError::Invalid(format!("stored card parse: {e}")))?;
        Ok(Some(card))
    }
}

/// Endpoint wrapper. Build via [`crate::Client::messages`].
pub struct Endpoint<'a> {
    http: &'a Http,
    router: &'a Router,
    identity: Option<&'a Arc<FetchitIdentity>>,
    registry: Option<&'a Arc<ConversationRegistry>>,
    signer: Option<&'a Arc<dyn Signer>>,
    layout: Option<&'a StoreLayout>,
    local_machine_id: [u8; 32],
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(
        http: &'a Http,
        router: &'a Router,
        identity: Option<&'a Arc<FetchitIdentity>>,
        registry: Option<&'a Arc<ConversationRegistry>>,
        signer: Option<&'a Arc<dyn Signer>>,
        layout: Option<&'a StoreLayout>,
        local_machine_id: [u8; 32],
    ) -> Self {
        Self {
            http,
            router,
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
        }
    }

    /// Send a direct message. On first contact, bootstraps a fresh
    /// conversation (Welcome outbox) before the message outbox. Every
    /// outbound `TransitEnvelope` is routed verbatim through the
    /// transport `Router` (so KEM ciphertext, signature, and epoch
    /// survive the hop).
    ///
    /// Returns the transport-assigned message id of the LAST envelope
    /// sent (for fanout > 1, callers see only the final receipt).
    ///
    /// # Errors
    /// `ChatError::NoTransportAvailable` when the router has no
    /// reachable transport; `ChatError::Invalid` when no stored card
    /// is available for the recipient or the client was built in
    /// REST-only mode without chat-encryption state.
    pub async fn send(
        &self,
        to: &AgentId,
        body: &str,
        sender_name: &str,
    ) -> Result<Option<String>> {
        // Surface a "no transport" error before the chat-state check
        // so callers that build a Client without a relay still see the
        // historical error variant.
        if self.router.is_empty() {
            return Err(ChatError::NoTransportAvailable);
        }
        let identity = self
            .identity
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let registry = self
            .registry
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let layout = self
            .layout
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        let conv = match registry.find_dm_with(&to.0).await? {
            Some(c) => c,
            None => {
                self.bootstrap_conversation(to, sender_name, identity, registry, signer, layout)
                    .await?
            }
        };

        let outbox = build_message_outbox(
            &conv,
            body,
            sender_name,
            identity,
            self.local_machine_id,
            signer.as_ref(),
        )
        .await?;
        self.dispatch_outbox(outbox).await
    }

    async fn bootstrap_conversation(
        &self,
        to: &AgentId,
        _sender_name: &str,
        identity: &Arc<FetchitIdentity>,
        registry: &Arc<ConversationRegistry>,
        signer: &Arc<dyn Signer>,
        layout: &StoreLayout,
    ) -> Result<Conversation> {
        let peer_card = StoredContactCard::load(layout, &to.0)?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no stored card for {} — import their share card first",
                to.short()
            ))
        })?;
        let peer_member = Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: peer_card.agent_id_hex.clone(),
                kem_public_key_b64: peer_card.kem_public_key_b64.clone(),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let local_member = Member {
            user_id_hex: identity.user_id_hex().map(str::to_owned),
            devices: vec![MemberDevice {
                agent_id_hex: identity.agent_id_hex().to_owned(),
                kem_public_key_b64: B64.encode(identity.kem_public_key()),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let conv = Conversation::new_dm(local_member, peer_member, None)?;
        let welcome =
            build_welcome_outbox(&conv, identity, self.local_machine_id, signer.as_ref()).await?;
        registry.save(&conv).await?;
        self.dispatch_outbox(welcome).await?;
        Ok(conv)
    }

    async fn dispatch_outbox(&self, outbox: Vec<ChatOutbound>) -> Result<Option<String>> {
        let mut last_id = None;
        for ob in outbox {
            let recipient_hex = hex::encode(ob.recipient_agent_id.as_bytes());
            let recipient = AgentId(recipient_hex);
            let timestamp_ms = ob.envelope.timestamp_ms;
            let transport_out = TransportOutbound {
                kind: OutboundKind::Dm,
                from_machine_id: Some(self.local_machine_id),
                payload: Vec::new(),
                timestamp_ms,
                transit: Some(ob.envelope),
            };
            let receipt = self.router.send(&recipient, transport_out).await?;
            last_id = receipt.message_id;
        }
        Ok(last_id)
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
/// [`DirectMessage`]. Used by transports that don't speak the v2
/// conversation wire format (e.g. the legacy x0xd direct path and the
/// live-relay self-DM round-trip test).
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
    let env: LegacyEnvelope = serde_json::from_slice(&inbound.payload)?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_round_trip_extracts_fields() {
        let env = LegacyEnvelope {
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
            transit: None,
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
            transit: None,
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
            transit: None,
        };
        assert!(decode_direct_message(inbound).is_err());
    }
}
