//! `Transport` impl backed by `fetchit-relay-client`.
//!
//! Drives a live WebSocket session against a fetchit relay using the
//! local x0xd as the signing oracle. Outbound chat envelopes are
//! wrapped in [`fetchit_relay_proto::TransitEnvelope`]s and sent to
//! the relay; inbound deliveries are decoded and pumped onto an mpsc
//! channel that the chat layer consumes.
//!
//! # Sealing status (M2 floor)
//!
//! Every send MUST carry a prebuilt sealed `TransitEnvelope` on
//! [`OutboundEnvelope::transit`]; the conversation/group layer is the
//! only sanctioned producer. Callers that pass `transit: None` get
//! [`ChatError::SealedRequired`] — the legacy v1 fabricated escape
//! hatch has been removed at M2 so there is no unsealed wire shape
//! left in this module.

use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use crate::transport::{
    InboundEnvelope, OutboundEnvelope, OutboundKind, Reachability, SendReceipt, Transport,
};
use async_trait::async_trait;
use fetchit_relay_client::{Client as RelayClient, ClientConfig, Signer};
use fetchit_relay_proto::{AgentId as RelayAgentId, DedupeKey, EnvelopeKind as RelayKind};
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
    /// Connect to a relay at `base_url`, using any [`Signer`]
    /// implementation for ML-DSA-65 auth (production: `X0xdSigner`;
    /// tests can use `StaticKeySigner`).
    ///
    /// Spawns a background task that pumps inbound deliveries from the
    /// relay into the channel exposed via [`Transport::take_inbound`].
    ///
    /// # Errors
    /// Returns [`ChatError::MessageTransport`] on any handshake or
    /// connection failure.
    pub async fn connect(base_url: Url, signer: Arc<dyn Signer>) -> Result<Arc<Self>> {
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
        // Sealed-only post-M2 — every caller must hand us a fully
        // sealed envelope produced by the conversation/group layer.
        // The v1 fabricated escape hatch has been removed.
        let transit = envelope.transit.ok_or(ChatError::SealedRequired {
            caller: "RelayTransport::send",
        })?;
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

    use fetchit_relay_client::StaticKeySigner;
    use fetchit_relay_proto::Region;
    use fetchit_relay_server::{AcceptAllVerifier, Server, ServerConfig};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn start_relay_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = ServerConfig::defaults(addr, Region::Nyc);
        let server = Server::new(cfg).with_verifier(Arc::new(AcceptAllVerifier));
        let (router, _state) = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        addr
    }

    /// `RelayTransport::send` MUST reject any envelope that doesn't
    /// carry a prebuilt sealed `TransitEnvelope`. The v1 fabricated
    /// fallback was removed at M2 — there is no wire-level escape
    /// hatch left, and this is the contract callers see.
    #[tokio::test]
    async fn send_without_prebuilt_envelope_returns_sealed_required() {
        let addr = start_relay_server().await;
        let base = url::Url::parse(&format!("http://{addr}/")).unwrap();
        let signer: Arc<dyn Signer + Send + Sync> =
            Arc::new(StaticKeySigner::from_public_key(b"alice-pubkey".to_vec()));
        let transport = RelayTransport::connect(base, signer).await.unwrap();

        let to = AgentId(hex::encode([0x33u8; 32]));
        let outbound = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: Some([0x22; 32]),
            payload: b"unsealed".to_vec(),
            timestamp_ms: 1_700_000_000_000,
            transit: None,
        };

        let err = transport.send(&to, outbound).await.unwrap_err();
        assert!(
            matches!(
                err,
                ChatError::SealedRequired { caller } if caller == "RelayTransport::send",
            ),
            "expected SealedRequired{{caller=RelayTransport::send}}, got {err:?}",
        );
    }
}
