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
/// Re-exported so consumers of [`BlockEvent`] can name + match its
/// `kind` field without depending on the trust crate directly.
pub use fetchit_trust::EntryKind;
pub use http::HttpClient;
#[cfg(feature = "reqwest")]
pub use http::ReqwestClient;

// The real etchit-io denylist issuer public key (`key_id` etchit-io-v1),
// minted by the trust service on first boot and baked here. It's a
// PUBLIC key, safe to commit and distribute; the matching private key
// lives only on the trust host. Rotating the issuer means redeploying
// the trust service with a fresh keypair and re-baking this fixture.
const ETCHITIO_PUBKEY: &[u8] = include_bytes!("../fixtures/etchitio_pubkey.bin");

/// Bytes of the etchit-io ML-DSA-65 public key clients trust as the
/// denylist issuer (`key_id` etchit-io-v1). The `DenylistConsumer`
/// verifies every signed denylist manifest against this key.
///
/// # Returns
/// 1952 bytes, the ML-DSA-65 public key length.
#[must_use]
pub fn etchitio_pubkey() -> Vec<u8> {
    ETCHITIO_PUBKEY.to_vec()
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
