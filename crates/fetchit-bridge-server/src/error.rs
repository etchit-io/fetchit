//! Bridge error type.

/// Errors surfaced by the bridge server.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// Configuration could not be loaded.
    #[error("config: {0}")]
    Config(String),
    /// A persistence-layer failure.
    #[error("store: {0}")]
    Store(String),
    /// The store mutex was poisoned by a panicked holder.
    #[error("store lock poisoned")]
    StoreLockPoisoned,
}

impl From<rusqlite::Error> for BridgeError {
    fn from(e: rusqlite::Error) -> Self {
        BridgeError::Store(e.to_string())
    }
}
