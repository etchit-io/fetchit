//! WebSocket frame schema.
//!
//! Two top-level enums separate the directions: [`ClientFrame`] is
//! emitted by clients, [`ServerFrame`] by the relay. Each binary
//! WebSocket message carries one postcard-encoded frame.

use crate::capability::{CapabilityToken, EffectiveCapabilities};
use crate::envelope::TransitEnvelope;
use crate::identity::{AgentId, DedupeKey, TenantId};
use crate::region::Region;
use serde::{Deserialize, Serialize};

/// Top-level message emitted by a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFrame {
    /// First frame on a fresh WebSocket; negotiates session.
    Hello(Hello),
    /// Subscribe to the inbox stream and start receiving `Deliver` frames.
    Subscribe(Subscribe),
    /// Submit one envelope for routing.
    Send(SendFrame),
    /// Update the per-connection presence watch set.
    ///
    /// The client may add agents to watch and remove agents it no longer
    /// cares about in the same frame. The relay tracks the watch set per
    /// connection; on register/unregister of a watched agent it pushes a
    /// [`PresenceUpdate`]. The watch set is cleared on disconnect — the
    /// supervisor re-sends it after reconnect.
    WatchPresence(WatchPresence),
    /// Keepalive request.
    Ping(Ping),
    /// Client-initiated graceful close.
    Bye(Bye),
    /// Confirms durable transit entries were delivered so the relay can
    /// reclaim them. Appended last so the discriminants of every earlier
    /// variant stay stable on the postcard wire.
    TransitAck(TransitAck),
}

/// Top-level message emitted by the relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerFrame {
    /// Response to a client `Hello`.
    Ready(Ready),
    /// Confirmation that a `Send` was accepted into the routing buffer.
    Ack(Ack),
    /// Inbound envelope addressed to the connected agent.
    Deliver(Deliver),
    /// Soft rejection with a retry hint.
    Throttle(Throttle),
    /// Liveness signal for a watched agent.
    ///
    /// Emitted when a watched agent registers (online) or unregisters
    /// (offline) on the relay. The client uses this to drive UI presence
    /// indicators; it is *not* an end-to-end signal — only that the relay
    /// currently has a session for that agent.
    PresenceUpdate(PresenceUpdate),
    /// Keepalive response.
    Pong(Pong),
    /// Server-initiated close (e.g. shutdown, token expiry).
    Bye(Bye),
    /// The deposit's recipient migrated away from this relay.
    ///
    /// Emitted INSTEAD of [`Ack`] when the recipient has no live session
    /// here and the relay holds a live signed forwarding record for them:
    /// the unambiguous departed signal. An offline recipient with no
    /// forwarding record buffers as usual. The frame deliberately carries
    /// no relay list: the sender re-resolves through the SIGNED forwarding
    /// record (ML-DSA verify + monotonic watermark), so the relay gains no
    /// power to redirect deposits.
    ///
    /// Appended last so the discriminants of every earlier variant are
    /// stable on the postcard wire.
    Moved(Moved),
}

/// Opening handshake from the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Client-side build identifier (semver string or git sha).
    pub client_version: String,
    /// Tenant binding for this session. `None` = public pool.
    pub tenant_id: Option<TenantId>,
    /// Client preference for which region to land in, best-effort.
    pub preferred_region: Option<Region>,
    /// Optional capability token widening the default session profile.
    pub capabilities: Option<CapabilityToken>,
}

/// Handshake response from the relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ready {
    /// Server build identifier.
    pub server_version: String,
    /// Region the connection actually landed in.
    pub region: Region,
    /// Resolved session limits after applying default + token claims.
    pub effective_capabilities: EffectiveCapabilities,
}

/// Client wants to start receiving inbox deliveries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscribe {
    /// Subscription topic name; "inbox" is the only v1 topic.
    pub topic: String,
}

/// Update the client's per-connection presence watch set.
///
/// `add` adds the listed agents to the watch set; `remove` drops them.
/// Either list may be empty. Sending both empty is a no-op.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchPresence {
    /// Agents to start watching.
    pub add: Vec<AgentId>,
    /// Agents to stop watching.
    pub remove: Vec<AgentId>,
}

/// Liveness update for a watched agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceUpdate {
    /// The agent whose state changed.
    pub agent_id: AgentId,
    /// `true` if the relay currently has a session for that agent,
    /// `false` if it just dropped.
    pub online: bool,
}

/// Client submits one envelope for routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendFrame {
    /// Recipient agent id.
    pub to: AgentId,
    /// The envelope to deliver.
    pub envelope: TransitEnvelope,
    /// Idempotency key for the ack.
    pub dedupe_key: DedupeKey,
}

/// Relay confirms a send was buffered or fanned out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// Echoes the originating `SendFrame::dedupe_key`.
    pub dedupe_key: DedupeKey,
    /// Server timestamp of acceptance, milliseconds since the Unix epoch.
    pub accepted_at_ms: u64,
}

/// The deposit's recipient migrated away from this relay.
///
/// See [`ServerFrame::Moved`] for the emission contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moved {
    /// Echoes the originating [`SendFrame::dedupe_key`], so the sender
    /// can resolve the matching in-flight send.
    pub dedupe_key: DedupeKey,
}

/// Inbound envelope pushed to the connected agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deliver {
    /// The envelope being delivered.
    pub envelope: TransitEnvelope,
    /// Durable-store id of this entry when replayed from the transit
    /// store (echo it in [`TransitAck`] to confirm delivery and let the
    /// relay reclaim it). `0` for a direct push that needs no ack.
    pub transit_seq: u64,
    /// Server timestamp at delivery, milliseconds since the Unix epoch.
    pub delivered_at_ms: u64,
}

/// Client confirmation that the listed durable transit ids were
/// delivered and may be reclaimed by the relay.
///
/// Transport-level and blind: the ids echo [`Deliver::transit_seq`] from
/// durable replays (a `0` is never sent). This is NOT the sealed
/// end-to-end delivery receipt, which the relay cannot read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitAck {
    /// The [`Deliver::transit_seq`] values the client has accepted.
    pub acked_ids: Vec<u64>,
}

/// Soft rejection with a retry hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throttle {
    /// Suggested backoff before retry, in milliseconds.
    pub retry_after_ms: u32,
    /// Which limit was hit.
    pub reason: ThrottleReason,
}

/// Reason a `Throttle` was emitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThrottleReason {
    /// Recipient buffer is full.
    PerRecipientCapacity,
    /// Sender exceeded per-minute send rate.
    PerSenderRate,
    /// Single envelope exceeded per-envelope byte cap.
    EnvelopeTooLarge,
}

/// Keepalive request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    /// Random bytes to echo in the matching `Pong`.
    pub nonce: u64,
}

/// Keepalive response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    /// Echoes [`Ping::nonce`].
    pub nonce: u64,
}

/// Graceful close.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bye {
    /// Why the connection is closing.
    pub reason: ByeReason,
}

/// Reason a `Bye` was emitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByeReason {
    /// Client signed off cleanly.
    ClientGoodbye,
    /// Server is shutting down (e.g. deploy).
    ServerShutdown,
    /// Bearer token expired during the session.
    AuthExpired,
    /// A protocol violation was detected.
    ProtocolError,
    /// A newer connection registered the same agent id; this session is
    /// the displaced one. The client should reconnect — the supervisor's
    /// reader breaks on `Bye`, which triggers a fresh handshake.
    DisplacedByNewSession,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::capability::EffectiveCapabilities;
    use crate::envelope::{EnvelopeKind, TransitEnvelope, WIRE_VERSION};
    use crate::identity::{AGENT_ID_LEN, DEDUPE_KEY_LEN, MACHINE_ID_LEN};

    fn sample_envelope() -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1u8; AGENT_ID_LEN]),
            sender_machine_id: crate::identity::MachineId::from_bytes([2u8; MACHINE_ID_LEN]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 0,
            ciphertext: vec![0xaa; 32],
            nonce: vec![0xbb; 12],
            kem_ciphertext: vec![0xcc; 32],
            sender_signature: vec![0xdd; 32],
        }
    }

    #[test]
    fn hello_roundtrips() {
        let frame = ClientFrame::Hello(Hello {
            client_version: "fetchit-relay-client/0.1.0".to_owned(),
            tenant_id: None,
            preferred_region: Some(Region::Nyc),
            capabilities: None,
        });
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let decoded: ClientFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn transit_ack_roundtrips() {
        let frame = ClientFrame::TransitAck(TransitAck {
            acked_ids: vec![1, 2, 9],
        });
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let decoded: ClientFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn ready_roundtrips() {
        let frame = ServerFrame::Ready(Ready {
            server_version: "fetchit-relay/0.1.0".to_owned(),
            region: Region::Nyc,
            effective_capabilities: EffectiveCapabilities::default_profile(),
        });
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn send_and_ack_roundtrip() {
        let send = ClientFrame::Send(SendFrame {
            to: AgentId::from_bytes([7u8; AGENT_ID_LEN]),
            envelope: sample_envelope(),
            dedupe_key: DedupeKey::from_bytes([9u8; DEDUPE_KEY_LEN]),
        });
        let bytes = postcard::to_allocvec(&send).unwrap();
        let decoded: ClientFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(send, decoded);

        let ack = ServerFrame::Ack(Ack {
            dedupe_key: DedupeKey::from_bytes([9u8; DEDUPE_KEY_LEN]),
            accepted_at_ms: 1_700_000_001_000,
        });
        let bytes = postcard::to_allocvec(&ack).unwrap();
        let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ack, decoded);
    }

    #[test]
    fn moved_roundtrips() {
        let frame = ServerFrame::Moved(Moved {
            dedupe_key: DedupeKey::from_bytes([3u8; DEDUPE_KEY_LEN]),
        });
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn moved_does_not_shift_existing_discriminants() {
        // Moved is appended LAST: the wire bytes of every pre-existing
        // ServerFrame variant must be identical to what an old binary
        // produced, or mixed-version relays and clients misparse each
        // other. Pin Ack's encoding (discriminant 1) explicitly.
        let ack = ServerFrame::Ack(Ack {
            dedupe_key: DedupeKey::from_bytes([9u8; DEDUPE_KEY_LEN]),
            accepted_at_ms: 1_000,
        });
        let bytes = postcard::to_allocvec(&ack).unwrap();
        assert_eq!(bytes[0], 1, "Ack must keep postcard discriminant 1");
        let bye = ServerFrame::Bye(Bye {
            reason: ByeReason::ServerShutdown,
        });
        let bytes = postcard::to_allocvec(&bye).unwrap();
        assert_eq!(bytes[0], 6, "Bye must keep postcard discriminant 6");
        let moved = ServerFrame::Moved(Moved {
            dedupe_key: DedupeKey::from_bytes([3u8; DEDUPE_KEY_LEN]),
        });
        let bytes = postcard::to_allocvec(&moved).unwrap();
        assert_eq!(bytes[0], 7, "Moved is the appended discriminant 7");
    }

    #[test]
    fn deliver_carries_transit_seq() {
        let d = ServerFrame::Deliver(Deliver {
            envelope: sample_envelope(),
            transit_seq: 42,
            delivered_at_ms: 1_700_000_002_000,
        });
        let bytes = postcard::to_allocvec(&d).unwrap();
        let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(d, decoded);
    }

    #[test]
    fn throttle_roundtrips() {
        let t = ServerFrame::Throttle(Throttle {
            retry_after_ms: 1_000,
            reason: ThrottleReason::PerSenderRate,
        });
        let bytes = postcard::to_allocvec(&t).unwrap();
        let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn ping_pong_roundtrip() {
        let ping = ClientFrame::Ping(Ping { nonce: 0xdead_beef });
        let bytes = postcard::to_allocvec(&ping).unwrap();
        let decoded: ClientFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ping, decoded);

        let pong = ServerFrame::Pong(Pong { nonce: 0xdead_beef });
        let bytes = postcard::to_allocvec(&pong).unwrap();
        let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(pong, decoded);
    }

    #[test]
    fn watch_presence_roundtrips() {
        let frame = ClientFrame::WatchPresence(WatchPresence {
            add: vec![
                AgentId::from_bytes([1u8; AGENT_ID_LEN]),
                AgentId::from_bytes([2u8; AGENT_ID_LEN]),
            ],
            remove: vec![AgentId::from_bytes([3u8; AGENT_ID_LEN])],
        });
        let bytes = postcard::to_allocvec(&frame).unwrap();
        let decoded: ClientFrame = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn presence_update_roundtrips() {
        for online in [true, false] {
            let frame = ServerFrame::PresenceUpdate(PresenceUpdate {
                agent_id: AgentId::from_bytes([7u8; AGENT_ID_LEN]),
                online,
            });
            let bytes = postcard::to_allocvec(&frame).unwrap();
            let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(frame, decoded);
        }
    }

    #[test]
    fn bye_roundtrips() {
        for reason in [
            ByeReason::ClientGoodbye,
            ByeReason::ServerShutdown,
            ByeReason::AuthExpired,
            ByeReason::ProtocolError,
            ByeReason::DisplacedByNewSession,
        ] {
            let b = ServerFrame::Bye(Bye { reason });
            let bytes = postcard::to_allocvec(&b).unwrap();
            let decoded: ServerFrame = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(b, decoded);
        }
    }
}
