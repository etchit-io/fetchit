//! Consumer-side denylist verifier for fetch>it clients.
//!
//! Used by both `fetchit-chat` (`RelayUrl` + `AgentId` enforcement) and
//! `fetchit-core` / desktop (`XorName` enforcement for the reader UI).
//!
//! Stage 2 of the M3 Relay Federation plan. Periodic refresh from
//! `https://etchit.io/v1/denylist?kind={xor_name,agent_id,relay_url,actor_url}`,
//! ML-DSA-65 signature verification against a hardcoded etchit-io
//! public key, in-memory hot lookup index, and disk persistence for
//! offline boot.
#![forbid(unsafe_code)]

mod cache;
mod consumer;
mod http;
mod index;

pub use consumer::{BlockEvent, DenylistConsumer, TrustError, DEFAULT_POLL_INTERVAL};
pub use http::HttpClient;
#[cfg(feature = "reqwest")]
pub use http::ReqwestClient;

// TODO(v1.0-launch): replace with real etchit-io ML-DSA-65 pubkey
// minted by ops + signed-off by Josh. The placeholder bytes below are
// generated from `IssuerSigner::generate("placeholder")` and exist so
// the crate ships a buildable surface during pre-launch development.
// The placeholder key has NO production trust value — callers
// MUST replace the fixture before any production deploy.
const PLACEHOLDER_ETCHITIO_PUBKEY: &[u8] = include_bytes!("../fixtures/placeholder_pubkey.bin");

/// Bytes of the etchit-io ML-DSA-65 public key clients trust as the
/// denylist issuer at v1.0 launch.
///
/// # Pre-launch placeholder
/// Until v1.0 the bytes are a deterministic placeholder committed at
/// `crates/fetchit-trust-client/fixtures/placeholder_pubkey.bin`.
/// Production callers MUST swap in the real key before deploying.
///
/// # Returns
/// 1952 bytes, the ML-DSA-65 public key length.
#[must_use]
pub fn etchitio_pubkey() -> Vec<u8> {
    PLACEHOLDER_ETCHITIO_PUBKEY.to_vec()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn etchitio_pubkey_returns_1952_bytes() {
        let bytes = etchitio_pubkey();
        assert_eq!(bytes.len(), 1952, "ML-DSA-65 public key is 1952 bytes");
    }

    #[test]
    fn etchitio_pubkey_is_stable_across_calls() {
        assert_eq!(etchitio_pubkey(), etchitio_pubkey());
    }
}
