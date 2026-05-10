//! Error types surfaced by [`fetchit-core`](crate).

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type for `fetchit-core`.
///
/// Variants are deliberately coarse — UI shells should map these to
/// human-readable messages rather than inspecting nested causes. The
/// `#[non_exhaustive]` attribute lets us add variants in minor releases
/// without breaking pattern-matching downstream.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The supplied string is not a valid 64-character lowercase-hex
    /// Autonomi address.
    #[error("invalid Autonomi address: {0}")]
    InvalidAddress(String),

    /// The network backend could not return bytes for an address. The
    /// inner string carries the backend's diagnostic; do not try to
    /// machine-parse it.
    #[error("network fetch failed: {0}")]
    Network(String),

    /// No registered handler claimed the bytes. In practice this should
    /// only fire if the binary fallback handler has been excluded.
    #[error("no handler matched the fetched bytes")]
    NoHandlerMatched,

    /// A handler accepted the bytes but failed to render them.
    #[error("handler '{kind}' failed to render: {reason}")]
    Render {
        /// The [`ContentHandler::kind`](crate::ContentHandler::kind)
        /// of the handler that failed.
        kind: &'static str,
        /// Human-readable cause.
        reason: String,
    },
}
