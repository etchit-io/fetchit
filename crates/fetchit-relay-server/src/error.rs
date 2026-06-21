//! Server error type.

use thiserror::Error;

/// Errors surfaced by the relay server.
#[derive(Debug, Error)]
pub enum ServerError {
    /// IO failure (socket bind, accept, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Config could not be loaded.
    #[error("config: {0}")]
    Config(String),

    /// Wire-protocol encode / decode failure.
    #[error("proto: {0}")]
    Proto(#[from] fetchit_relay_proto::ProtoError),

    /// Auth challenge or verify failed.
    #[error("auth rejected: {0}")]
    AuthRejected(String),

    /// Bearer token is unknown or expired.
    #[error("bearer token invalid")]
    BearerInvalid,

    /// Capability token did not validate or didn't match the session.
    #[error("capability claim invalid: {0}")]
    CapabilityInvalid(String),

    /// Capability token's allowed-region set excludes this server's region.
    #[error("region '{region}' not permitted by capability token")]
    RegionDenied {
        /// Server region that was rejected.
        region: String,
    },

    /// Per-sender rate limit was hit.
    #[error("rate limit hit")]
    RateLimited,

    /// Envelope exceeds per-session size cap.
    #[error("envelope exceeds size cap ({size} > {cap})")]
    EnvelopeTooLarge {
        /// Encoded byte size of the offending envelope.
        size: usize,
        /// Per-session cap applied.
        cap: usize,
    },

    /// Recipient's transit buffer is at capacity.
    #[error("transit buffer full for recipient")]
    TransitBufferFull,

    /// A durable transit-store backend operation failed (open, read,
    /// write, or delete). Carries a human-readable cause, never payload.
    #[error("transit store backend error: {0}")]
    TransitStore(String),
}
