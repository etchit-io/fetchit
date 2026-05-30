//! Typed error surface for chat-client operations.

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ChatError>;

/// All failure modes the client can surface.
#[derive(Debug, Error)]
pub enum ChatError {
    /// The daemon's data directory or auth token was not discoverable.
    #[error("x0xd not discoverable: {0}")]
    NotDiscoverable(String),

    /// HTTP transport / connection error.
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// WebSocket connection or framing error.
    #[error("websocket: {0}")]
    WebSocket(String),

    /// The daemon returned a non-success status with a body.
    #[error("daemon returned {status}: {body}")]
    Daemon {
        /// HTTP status code.
        status: u16,
        /// Response body, truncated for log safety.
        body: String,
    },

    /// JSON serialization / deserialization mismatch.
    #[error("decode: {0}")]
    Decode(#[from] serde_json::Error),

    /// Malformed input (bad agent id, malformed card, etc.).
    #[error("invalid input: {0}")]
    Invalid(String),

    /// I/O error reading discovery files.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// No message transport could reach the recipient.
    #[error("no transport available for recipient")]
    NoTransportAvailable,

    /// A message-transport operation failed.
    #[error("message transport: {0}")]
    MessageTransport(String),

    /// The local chat identity vault is missing or hasn't been
    /// bootstrapped. Call `Client::ensure_identity` or pass the right
    /// passphrase.
    #[error("chat identity not initialised at {path}")]
    IdentityNotInitialised {
        /// Where the identity vault was looked up.
        path: String,
    },
}

impl From<x0xd_client::DiscoveryError> for ChatError {
    fn from(e: x0xd_client::DiscoveryError) -> Self {
        match e {
            x0xd_client::DiscoveryError::Io(io) => Self::Io(io),
            other => Self::NotDiscoverable(other.to_string()),
        }
    }
}
