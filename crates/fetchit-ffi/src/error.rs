//! [`FetchitError`] -- FFI-shaped error type that maps from
//! [`fetchit_core::Error`] and presents a stable Kotlin (Android) surface.

use thiserror::Error;

/// Top-level error visible across the FFI boundary.
///
/// Variants are coarse on purpose -- Kotlin callers map these to UI
/// messages rather than inspecting nested causes. The `Internal`
/// variant absorbs anything we have not yet given a dedicated mapping
/// for, so adding new variants in `fetchit-core` does not break the
/// FFI contract.
///
/// Field name `reason` (not `message`) is deliberate -- uniffi's
/// generated Kotlin bindings produce `class Variant(val message: String) :
/// Exception()` which collides with `kotlin.Throwable.message`.
#[derive(Debug, Error, uniffi::Error)]
pub enum FetchitError {
    /// The supplied address is not valid 64-character hex.
    #[error("invalid address: {reason}")]
    InvalidAddress {
        /// Human-readable diagnostic.
        reason: String,
    },
    /// A network operation (connect, fetch, decode) failed.
    #[error("network: {reason}")]
    Network {
        /// Human-readable diagnostic.
        reason: String,
    },
    /// No registered handler claimed the fetched bytes.
    #[error("no handler matched the fetched bytes")]
    NoHandlerMatched,
    /// A handler accepted the bytes but failed to render.
    #[error("render '{kind}': {reason}")]
    Render {
        /// `ContentHandler::kind` of the failing handler.
        kind: String,
        /// Human-readable diagnostic.
        reason: String,
    },
    /// Catch-all for newly-added `fetchit-core` errors not yet mapped
    /// individually.
    #[error("internal: {reason}")]
    Internal {
        /// Human-readable diagnostic.
        reason: String,
    },
}

impl From<fetchit_core::Error> for FetchitError {
    fn from(e: fetchit_core::Error) -> Self {
        match e {
            fetchit_core::Error::InvalidAddress(s) => Self::InvalidAddress { reason: s },
            fetchit_core::Error::Network(s) => Self::Network { reason: s },
            fetchit_core::Error::NoHandlerMatched => Self::NoHandlerMatched,
            fetchit_core::Error::Render { kind, reason } => Self::Render {
                kind: kind.to_owned(),
                reason,
            },
            other => Self::Internal {
                reason: format!("unmapped fetchit-core error: {other}"),
            },
        }
    }
}
