//! Stage 2.1: `DenylistConsumer` — coordinates HTTP fetch, signature
//! verification, in-memory index, and disk cache. Stub for C1.
//! Real implementation lands in C4-C9.

use fetchit_trust::EntryKind;
use thiserror::Error;

/// Errors produced by the trust-client crate.
#[derive(Debug, Error)]
pub enum TrustError {
    /// HTTP layer failure (network, status, decode).
    #[error("http: {0}")]
    Http(String),
    /// Postcard / JSON decode failure.
    #[error("decode: {0}")]
    Decode(String),
    /// ML-DSA-65 signature verification failed.
    #[error("bad signature: {0}")]
    BadSignature(String),
    /// Filesystem / cache I/O failure.
    #[error("io: {0}")]
    Io(String),
}

/// Periodic-refresh denylist consumer. Stub; real impl in C4-C9.
#[allow(dead_code)]
#[derive(Debug)]
pub struct DenylistConsumer {
    kind_supported: [EntryKind; 4],
}

/// Emitted on the broadcast channel whenever a refresh produces a
/// delta against the previous in-memory index. Stub shape; real
/// fields land in C6.
#[derive(Clone, Debug)]
pub struct BlockEvent {
    /// Which `EntryKind` changed.
    pub kind: EntryKind,
    /// Values added in this refresh.
    pub added: Vec<String>,
    /// Values removed in this refresh.
    pub removed: Vec<String>,
}
