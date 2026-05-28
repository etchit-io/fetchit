//! Errors surfaced by encoding, decoding, and validating wire types.

use thiserror::Error;

/// Failures from the proto layer.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Postcard serialization failed.
    #[error("postcard encode: {0}")]
    Encode(#[source] postcard::Error),

    /// Postcard deserialization failed.
    #[error("postcard decode: {0}")]
    Decode(#[source] postcard::Error),

    /// A byte-length identifier had the wrong size.
    #[error("invalid identifier length: expected {expected} bytes, got {got}")]
    InvalidIdentifierLength {
        /// Required byte count.
        expected: usize,
        /// Actual byte count provided.
        got: usize,
    },

    /// A hex string identifier could not be parsed.
    #[error("invalid hex identifier: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// A capability claim exceeded the bound declared by the issuer.
    #[error("capability claim out of range")]
    CapabilityOutOfRange,
}
