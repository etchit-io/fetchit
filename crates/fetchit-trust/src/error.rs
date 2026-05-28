//! Trust service error type.

use thiserror::Error;

/// Errors surfaced by the trust service.
#[derive(Debug, Error)]
pub enum TrustError {
    /// IO failure (bind, persist, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Config could not be loaded.
    #[error("config: {0}")]
    Config(String),

    /// JSON serialization / deserialization failure on persistence.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Issuer keypair load or generation failure.
    #[error("issuer key: {0}")]
    IssuerKey(String),

    /// Postcard encoding for signed denylist bodies.
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
}
