//! `Transport` impl backed by `fetchit-relay-client`.
//!
//! Drives a live WebSocket session against a fetchit relay using the
//! local x0xd as the signing oracle. Outbound chat envelopes are
//! wrapped in `TransitEnvelope`s and sent to the relay; inbound
//! deliveries are decoded and pumped onto an mpsc channel that the
//! chat layer consumes.

use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use crate::transport::{
    InboundEnvelope, OutboundEnvelope, OutboundKind, Reachability, SendReceipt, Transport,
};
use async_trait::async_trait;
use fetchit_relay_client::{Client as RelayClient, ClientConfig, X0xdSigner};
use fetchit_relay_proto::{
    AgentId as RelayAgentId, DedupeKey, EnvelopeKind as RelayKind, GroupId as RelayGroupId,
    MachineId, TransitEnvelope,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use url::Url;

const TRANSPORT_NAME: &str = "relay";

/// Cross-internet chat transport routed through a `fetchit-relay-server`
/// instance.
pub struct RelayTransport {
    client: Arc<RelayClient>,
    counter: AtomicU64,
    inbound: StdMutex<Option<mpsc::UnboundedReceiver<InboundEnvelope>>>,
    /// Local agent id captured from the signer at connect time. Used
    /// to populate `TransitEnvelope::sender_agent_id` for outbound
    /// sends; the relay rejects sends whose `sender_agent_id` doesn't
    /// match the bearer-token identity, so they must agree.
    local_agent_id: RelayAgentId,
}

impl RelayTransport {
    /// Connect to a relay at `base_url`, using a previously-built
    /// [`X0xdSigner`] for ML-DSA-65 auth.
    ///
    /// Spawns a background task that pumps inbound deliveries from the
    /// relay into the channel exposed via [`Transport::take_inbound`].
    ///
    /// # Errors
    /// Returns [`ChatError::MessageTransport`] on any handshake or
    /// connection failure.
    pub async fn connect(base_url: Url, signer: Arc<X0xdSigner>) -> Result<Arc<Self>> {
        use fetchit_relay_client::Signer;
        let local_agent_id = RelayAgentId::from_bytes(signer.agent_id());
        let config = ClientConfig::new(base_url);
        let relay_client = RelayClient::connect(config, signer)
            .await
            .map_err(|e| ChatError::MessageTransport(format!("relay connect: {e}")))?;
        let client = Arc::new(relay_client);
        // TODO(perf): bound this channel once we measure realistic inbound rates.
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_inbound_pump(client.clone(), tx);
        Ok(Arc::new(Self {
            client,
            counter: AtomicU64::new(0),
            inbound: StdMutex::new(Some(rx)),
            local_agent_id,
        }))
    }

    /// Borrow the local agent id this transport is bound to. The
    /// relay server enforces that outbound `sender_agent_id` equals
    /// the bearer-token identity, so callers can treat this as
    /// authoritative.
    #[must_use]
    pub fn local_agent_id(&self) -> &RelayAgentId {
        &self.local_agent_id
    }

    /// Borrow the underlying relay client (for telemetry / debugging only).
    #[must_use]
    pub fn relay_client(&self) -> &Arc<RelayClient> {
        &self.client
    }

    fn next_dedupe_key(&self) -> DedupeKey {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        let ts_part = now_ms().to_le_bytes();
        bytes[8..].copy_from_slice(&ts_part);
        DedupeKey::from_bytes(bytes)
    }
}

#[async_trait]
impl Transport for RelayTransport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn reachability(&self, _: &AgentId) -> Reachability {
        Reachability::Always
    }

    async fn send(&self, to: &AgentId, envelope: OutboundEnvelope) -> Result<SendReceipt> {
        let to_relay = agent_id_to_relay(to)?;
        let transit = if let Some(prebuilt) = envelope.transit {
            // The chat-v2 path hands us a fully-sealed envelope —
            // forward it verbatim so the KEM ciphertext, nonce, epoch,
            // and signature survive intact.
            prebuilt
        } else {
            let machine_id = MachineId::from_bytes(envelope.from_machine_id.unwrap_or([0u8; 32]));
            let (kind, group_id) = match envelope.kind {
                OutboundKind::Dm => (RelayKind::Dm, None),
                OutboundKind::Group { ref group_id } => {
                    let bytes = parse_hex_32(group_id)
                        .map_err(|e| ChatError::Invalid(format!("group id: {e}")))?;
                    (RelayKind::GroupChat, Some(RelayGroupId::from_bytes(bytes)))
                }
            };
            TransitEnvelope {
                version: 2,
                kind,
                group_id,
                tenant_id: None,
                sender_agent_id: self.local_agent_id,
                sender_machine_id: machine_id,
                timestamp_ms: envelope.timestamp_ms,
                epoch: 0,
                ciphertext: envelope.payload,
                nonce: Vec::new(),
                kem_ciphertext: Vec::new(),
                sender_signature: Vec::new(),
            }
        };
        let dedupe_key = self.next_dedupe_key();
        let receipt = self
            .client
            .send(to_relay, transit, dedupe_key)
            .await
            .map_err(|e| ChatError::MessageTransport(format!("relay send: {e}")))?;
        Ok(SendReceipt {
            accepted_at_ms: receipt.accepted_at_ms,
            message_id: Some(hex::encode(dedupe_key.as_bytes())),
            transport_name: TRANSPORT_NAME,
        })
    }

    fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
        self.inbound.lock().ok().and_then(|mut g| g.take())
    }
}

fn spawn_inbound_pump(client: Arc<RelayClient>, tx: mpsc::UnboundedSender<InboundEnvelope>) {
    tokio::spawn(async move {
        loop {
            let Some(delivery) = client.next_delivery().await else {
                break;
            };
            let env = delivery.envelope;
            let kind = match env.kind {
                RelayKind::Dm => OutboundKind::Dm,
                RelayKind::GroupChat | RelayKind::DeliveryReceipt => OutboundKind::Group {
                    group_id: env
                        .group_id
                        .map(|g| hex::encode(g.as_bytes()))
                        .unwrap_or_default(),
                },
                RelayKind::AdminEvent => continue,
            };
            let from = AgentId(hex::encode(env.sender_agent_id.as_bytes()));
            let inbound = InboundEnvelope {
                kind,
                from,
                payload: env.ciphertext.clone(),
                timestamp_ms: env.timestamp_ms,
                transport_name: TRANSPORT_NAME,
                transit: Some(env),
            };
            if tx.send(inbound).is_err() {
                break;
            }
        }
    });
}

fn agent_id_to_relay(id: &AgentId) -> Result<RelayAgentId> {
    let bytes = parse_hex_32(&id.0).map_err(|e| ChatError::Invalid(format!("agent id: {e}")))?;
    Ok(RelayAgentId::from_bytes(bytes))
}

fn parse_hex_32(s: &str) -> std::result::Result<[u8; 32], String> {
    let raw = hex::decode(s).map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_32_accepts_64_chars() {
        let h = "a".repeat(64);
        let bytes = parse_hex_32(&h).unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        assert!(parse_hex_32("ab").is_err());
    }
}
