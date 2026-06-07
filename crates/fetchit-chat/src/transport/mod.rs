//! Pluggable message-transport for outbound chat envelopes.
//!
//! A [`Transport`] moves an opaque payload from the local agent to a
//! peer's agent. The chat layer owns a [`Router`] holding one or more
//! transports — [`crate::relay_transport::RelayTransport`] for
//! cross-internet, LAN-direct for same network, future WebRTC for
//! cross-NAT direct — and picks the best one per send. Each transport
//! exposes its own inbound stream the desktop pumps into the UI.
//!
//! Transports never see plaintext content directly: the chat layer
//! seals the body before handing it over, and the transport just
//! routes opaque bytes. (v1 ships pre-encryption — the field nominally
//! holds ciphertext but is actually plaintext; ML-KEM-768 sealing
//! lands in the next milestone.)

use crate::card::RendezvousHintsV1;
use crate::error::{ChatError, Result};
use crate::identity::AgentId;
use async_trait::async_trait;
use fetchit_relay_proto::TransitEnvelope;
use std::sync::Arc;
use tokio::sync::mpsc;

mod multi_home;
mod nonce_dedup;

pub use multi_home::{
    MultiHomeTransport, RealRelayBuilder, RelayBuilder, RelayHandle, Slot, TransportError,
};
pub use nonce_dedup::NonceDedup;

/// Out-of-band hint to the router about whether a given transport
/// should be attempted for a recipient right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// Transport can always attempt (relay).
    Always,
    /// Transport can attempt only if the peer is discoverable on the
    /// same network (LAN-direct).
    IfReachable,
    /// Transport cannot reach this peer right now.
    No,
}

/// Server-or-peer acceptance receipt for one outbound envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendReceipt {
    /// Acceptance time as reported by the receiving side, milliseconds
    /// since the Unix epoch.
    pub accepted_at_ms: u64,
    /// Opaque message id when the transport assigns one. The relay
    /// uses the dedupe-key hex; LAN-direct may leave this `None`.
    pub message_id: Option<String>,
    /// Name of the transport that handled this send (for telemetry).
    pub transport_name: &'static str,
}

/// Classification of one outbound envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundKind {
    /// One-to-one direct message.
    Dm,
    /// Message addressed to a group. The recipient list is supplied
    /// separately by the caller — transports don't know group state.
    Group {
        /// Daemon-side group id, hex-encoded.
        group_id: String,
    },
}

/// One outbound chat envelope before it hits the wire.
///
/// Sender identity is supplied by the transport (each transport
/// already holds the local agent's identity via its signer), so the
/// chat layer doesn't have to look it up to send.
#[derive(Clone, Debug)]
pub struct OutboundEnvelope {
    /// What this envelope represents.
    pub kind: OutboundKind,
    /// Sending agent's machine fingerprint, 32 bytes. `None` lets the
    /// transport fall back to zeros.
    pub from_machine_id: Option<[u8; 32]>,
    /// Opaque body bytes. Whatever sealing convention the chat layer
    /// uses today.
    pub payload: Vec<u8>,
    /// Sender-asserted timestamp (ms since the Unix epoch).
    pub timestamp_ms: u64,
    /// Optional pre-built `TransitEnvelope` — when set, transports
    /// MUST forward it verbatim (preserves KEM ciphertext, nonce,
    /// epoch, signature for the conversation v2 path). When `None`,
    /// transports fabricate a v1-shape envelope from the other fields.
    pub transit: Option<TransitEnvelope>,
}

/// One inbound message decoded enough for the chat layer to route.
#[derive(Clone, Debug)]
pub struct InboundEnvelope {
    /// What kind of envelope this is.
    pub kind: OutboundKind,
    /// Sending agent.
    pub from: AgentId,
    /// Opaque body bytes (chat layer unseals).
    pub payload: Vec<u8>,
    /// Sender-asserted timestamp (ms since the Unix epoch).
    pub timestamp_ms: u64,
    /// Name of the transport that delivered it (for telemetry / dedup).
    pub transport_name: &'static str,
    /// Original `TransitEnvelope` when the transport carried one — the
    /// chat-v2 path (`conversation::dispatch_inbound`) needs the full
    /// envelope (KEM ciphertext, signature, epoch, nonce). Transports
    /// without a wire `TransitEnvelope` leave it `None`.
    pub transit: Option<TransitEnvelope>,
}

/// A message-transport that can send and receive chat envelopes.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Stable identifier — used in `SendReceipt`, dedup, logs.
    fn name(&self) -> &'static str;

    /// Whether this transport should be attempted for `to` right now.
    fn reachability(&self, to: &AgentId) -> Reachability;

    /// Try to deliver `envelope` to `to`.
    ///
    /// `hints` carries the recipient's advertised
    /// [`RendezvousHintsV1`] when the caller has resolved it from the
    /// contact card. Slot-routing transports
    /// (e.g. `MultiHomeTransport`) use it to pick the destination
    /// relay; single-WS and LAN-direct transports ignore it. `None`
    /// means the caller did not look hints up (legacy path) and is
    /// distinct from `Some(empty)` which means the card explicitly
    /// advertises no hints.
    ///
    /// # Errors
    /// Returns `ChatError::Transport*` for wire failures; the router
    /// may try another transport in response.
    async fn send(
        &self,
        to: &AgentId,
        envelope: OutboundEnvelope,
        hints: Option<&RendezvousHintsV1>,
    ) -> Result<SendReceipt>;

    /// Take the inbound stream once. Subsequent calls return `None`.
    /// The chat layer pumps this into the unified event stream.
    fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>>;
}

/// Owns multiple transports and picks the best one per send.
///
/// Priority is registration order: first transport with a non-`No`
/// reachability that accepts the send wins. If it errors, the router
/// falls through to the next.
#[derive(Default)]
pub struct Router {
    transports: Vec<Arc<dyn Transport>>,
}

impl Router {
    /// Construct an empty router. Add transports via [`Router::add`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `transport` at the lowest priority (tried last).
    pub fn add(&mut self, transport: Arc<dyn Transport>) {
        self.transports.push(transport);
    }

    /// Borrow every registered transport in priority order. Useful for
    /// pumping inbound streams.
    #[must_use]
    pub fn transports(&self) -> &[Arc<dyn Transport>] {
        &self.transports
    }

    /// Number of registered transports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// True if no transports are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Pick the highest-priority transport that can reach `to`,
    /// attempt the send, fall through to the next on error.
    ///
    /// `hints` is forwarded verbatim to each transport's
    /// [`Transport::send`]; pass `None` when the caller has not
    /// resolved the recipient's [`RendezvousHintsV1`].
    ///
    /// # Errors
    /// Returns [`ChatError::NoTransportAvailable`] if no transport
    /// reports a non-`No` reachability for `to`. Returns the last
    /// transport's error if every reachable transport failed.
    pub async fn send(
        &self,
        to: &AgentId,
        envelope: OutboundEnvelope,
        hints: Option<&RendezvousHintsV1>,
    ) -> Result<SendReceipt> {
        if self.transports.is_empty() {
            return Err(ChatError::NoTransportAvailable);
        }
        let mut any_reachable = false;
        let mut last_err: Option<ChatError> = None;
        for transport in &self.transports {
            if transport.reachability(to) == Reachability::No {
                continue;
            }
            any_reachable = true;
            match transport.send(to, envelope.clone(), hints).await {
                Ok(receipt) => return Ok(receipt),
                Err(e) => last_err = Some(e),
            }
        }
        if !any_reachable {
            return Err(ChatError::NoTransportAvailable);
        }
        Err(last_err.unwrap_or(ChatError::NoTransportAvailable))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    struct ScriptedTransport {
        name: &'static str,
        reach: Reachability,
        send_results: Mutex<Vec<Result<SendReceipt>>>,
        attempts: AtomicU32,
    }

    impl ScriptedTransport {
        fn new(name: &'static str, reach: Reachability, results: Vec<Result<SendReceipt>>) -> Self {
            Self {
                name,
                reach,
                send_results: Mutex::new(results),
                attempts: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl Transport for ScriptedTransport {
        fn name(&self) -> &'static str {
            self.name
        }
        fn reachability(&self, _: &AgentId) -> Reachability {
            self.reach
        }
        async fn send(
            &self,
            _: &AgentId,
            _: OutboundEnvelope,
            _: Option<&RendezvousHintsV1>,
        ) -> Result<SendReceipt> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let mut g = self.send_results.lock().unwrap();
            if g.is_empty() {
                return Err(ChatError::NoTransportAvailable);
            }
            g.remove(0)
        }
        fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
            None
        }
    }

    fn receipt(name: &'static str) -> SendReceipt {
        SendReceipt {
            accepted_at_ms: 1,
            message_id: None,
            transport_name: name,
        }
    }

    fn env() -> OutboundEnvelope {
        OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: None,
            payload: b"x".to_vec(),
            timestamp_ms: 1,
            transit: None,
        }
    }

    #[tokio::test]
    async fn empty_router_returns_no_transport() {
        let r = Router::new();
        let err = r
            .send(&AgentId("b".repeat(64)), env(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ChatError::NoTransportAvailable));
    }

    #[tokio::test]
    async fn first_reachable_transport_wins() {
        let t1 = Arc::new(ScriptedTransport::new(
            "a",
            Reachability::Always,
            vec![Ok(receipt("a"))],
        ));
        let t2 = Arc::new(ScriptedTransport::new(
            "b",
            Reachability::Always,
            vec![Ok(receipt("b"))],
        ));
        let mut r = Router::new();
        r.add(t1.clone());
        r.add(t2.clone());
        let receipt = r.send(&AgentId("b".repeat(64)), env(), None).await.unwrap();
        assert_eq!(receipt.transport_name, "a");
        assert_eq!(t1.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(t2.attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn falls_through_to_next_on_error() {
        let t1 = Arc::new(ScriptedTransport::new(
            "a",
            Reachability::Always,
            vec![Err(ChatError::Invalid("nope".into()))],
        ));
        let t2 = Arc::new(ScriptedTransport::new(
            "b",
            Reachability::Always,
            vec![Ok(receipt("b"))],
        ));
        let mut r = Router::new();
        r.add(t1.clone());
        r.add(t2.clone());
        let receipt = r.send(&AgentId("b".repeat(64)), env(), None).await.unwrap();
        assert_eq!(receipt.transport_name, "b");
        assert_eq!(t1.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(t2.attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_unreachable_transports() {
        let t1 = Arc::new(ScriptedTransport::new("a", Reachability::No, vec![]));
        let t2 = Arc::new(ScriptedTransport::new(
            "b",
            Reachability::Always,
            vec![Ok(receipt("b"))],
        ));
        let mut r = Router::new();
        r.add(t1.clone());
        r.add(t2.clone());
        let receipt = r.send(&AgentId("b".repeat(64)), env(), None).await.unwrap();
        assert_eq!(receipt.transport_name, "b");
        assert_eq!(t1.attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn all_unreachable_returns_no_transport() {
        let t = Arc::new(ScriptedTransport::new("a", Reachability::No, vec![]));
        let mut r = Router::new();
        r.add(t);
        let err = r
            .send(&AgentId("b".repeat(64)), env(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ChatError::NoTransportAvailable));
    }

    #[tokio::test]
    async fn all_errored_returns_last_error() {
        let t = Arc::new(ScriptedTransport::new(
            "a",
            Reachability::Always,
            vec![Err(ChatError::Invalid("boom".into()))],
        ));
        let mut r = Router::new();
        r.add(t);
        let err = r
            .send(&AgentId("b".repeat(64)), env(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    /// R-tail-1: hints supplied to `Router::send` reach the picked
    /// transport's `send` verbatim, so a future `MultiHomeTransport`
    /// can slot-route by them.
    #[tokio::test]
    async fn router_passes_hints_to_transport() {
        struct HintCapturingTransport {
            last_hints: Mutex<Option<RendezvousHintsV1>>,
        }

        #[async_trait]
        impl Transport for HintCapturingTransport {
            fn name(&self) -> &'static str {
                "hint-capture"
            }
            fn reachability(&self, _: &AgentId) -> Reachability {
                Reachability::Always
            }
            async fn send(
                &self,
                _: &AgentId,
                _: OutboundEnvelope,
                hints: Option<&RendezvousHintsV1>,
            ) -> Result<SendReceipt> {
                *self.last_hints.lock().unwrap() = hints.cloned();
                Ok(SendReceipt {
                    accepted_at_ms: 1,
                    message_id: None,
                    transport_name: "hint-capture",
                })
            }
            fn take_inbound(&self) -> Option<mpsc::UnboundedReceiver<InboundEnvelope>> {
                None
            }
        }

        let captor = Arc::new(HintCapturingTransport {
            last_hints: Mutex::new(None),
        });
        let mut r = Router::new();
        r.add(captor.clone());

        let hints = RendezvousHintsV1 {
            relays: vec!["wss://primary.test/v1/ws".to_owned()],
        };
        r.send(&AgentId("b".repeat(64)), env(), Some(&hints))
            .await
            .unwrap();

        let captured = captor.last_hints.lock().unwrap().clone();
        assert_eq!(captured.unwrap().relays, hints.relays);
    }
}
