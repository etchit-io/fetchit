//! Wire types shared between the fetchit relay server and its clients.
//!
//! The relay is a transient pass-through router: it sees opaque envelopes
//! addressed to an [`identity::AgentId`] and forwards them. This crate
//! defines the message schema only — there is no network code here.
//!
//! Encoded with [`postcard`] for compact binary frames over WebSocket.

#![forbid(unsafe_code)]

pub mod auth;
pub mod capability;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod identity;
pub mod region;

pub use auth::{
    auth_signing_bytes, AuthChallenge, AuthVerifyRequest, AuthVerifyResponse, AUTH_CHALLENGE_DOMAIN,
};
pub use capability::{
    Capability, CapabilityClaims, CapabilityToken, EffectiveCapabilities, FeatureFlag,
    DEFAULT_MAX_ENVELOPES_PER_MIN, DEFAULT_MAX_ENVELOPE_BYTES, DEFAULT_MAX_GROUP_SIZE,
};
pub use envelope::{EnvelopeKind, TransitEnvelope, WIRE_VERSION};
pub use error::ProtoError;
pub use frame::{
    Ack, Bye, ByeReason, ClientFrame, Deliver, Hello, Ping, Pong, PresenceUpdate, Ready, SendFrame,
    ServerFrame, Subscribe, Throttle, ThrottleReason, WatchPresence,
};
pub use identity::{
    derive_agent_id, AgentId, DedupeKey, GroupId, MachineId, TenantId, AGENT_ID_DOMAIN,
};
pub use region::Region;

/// Protocol version negotiated in the `Hello` / `Ready` exchange.
pub const PROTOCOL_VERSION: u16 = 2;

/// Encode a value as a postcard byte vector.
///
/// # Errors
/// Returns [`ProtoError::Encode`] if serialization fails.
pub fn to_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    postcard::to_allocvec(value).map_err(ProtoError::Encode)
}

/// Decode a value from postcard bytes.
///
/// # Errors
/// Returns [`ProtoError::Decode`] if deserialization fails.
pub fn from_bytes<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ProtoError> {
    postcard::from_bytes(bytes).map_err(ProtoError::Decode)
}
