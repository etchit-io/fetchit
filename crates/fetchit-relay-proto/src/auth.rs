//! Stateless challenge-response auth handshake.
//!
//! 1. Client `POST /v1/auth/challenge` → server returns 32 random
//!    bytes plus an expiry.
//! 2. Client signs `auth_signing_bytes(challenge)` with ML-DSA-65 and
//!    POSTs `/v1/auth/verify` with the signature plus their public key.
//! 3. Server verifies and returns a short-lived opaque bearer token
//!    used for the WebSocket upgrade.
//!
//! Both ends apply [`auth_signing_bytes`] before signing or verifying,
//! so a relay signature cannot be cross-protocol-replayed against a
//! different x0x consumer of the same agent key.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};

/// Domain-separation tag prepended to every relay auth challenge before
/// the agent signs it. Must match exactly on both sides of the handshake.
pub const AUTH_CHALLENGE_DOMAIN: &[u8] = b"fetchit-relay/v1/auth/challenge\0";

/// Build the canonical byte string that must be signed (and verified)
/// for a relay auth handshake.
///
/// Returns `AUTH_CHALLENGE_DOMAIN || challenge`.
#[must_use]
pub fn auth_signing_bytes(challenge: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_CHALLENGE_DOMAIN.len() + challenge.len());
    out.extend_from_slice(AUTH_CHALLENGE_DOMAIN);
    out.extend_from_slice(challenge);
    out
}

/// Random bytes the client must sign to prove key control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// 32-byte random nonce.
    pub challenge: [u8; 32],
    /// Wall-clock expiry, milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

/// Client's signed response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyRequest {
    /// Agent id (must be the hash of `agent_public_key`).
    pub agent_id: AgentId,
    /// ML-DSA-65 public key, raw bytes.
    pub agent_public_key: Vec<u8>,
    /// The exact challenge bytes returned by `/auth/challenge`.
    pub challenge: [u8; 32],
    /// ML-DSA-65 signature over `challenge`.
    pub signature: Vec<u8>,
}

/// Bearer token issued on successful verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyResponse {
    /// Opaque bearer the WebSocket upgrade must include.
    pub token: String,
    /// Token expiry, milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::AGENT_ID_LEN;

    #[test]
    fn challenge_roundtrips() {
        let c = AuthChallenge {
            challenge: [42u8; 32],
            expires_at_ms: 1_700_000_900_000,
        };
        let bytes = postcard::to_allocvec(&c).unwrap();
        let decoded: AuthChallenge = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn verify_request_roundtrips() {
        let r = AuthVerifyRequest {
            agent_id: AgentId::from_bytes([3u8; AGENT_ID_LEN]),
            agent_public_key: vec![0u8; 1952],
            challenge: [42u8; 32],
            signature: vec![0u8; 3293],
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let decoded: AuthVerifyRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn verify_response_roundtrips() {
        let r = AuthVerifyResponse {
            token: "abc.def.ghi".to_owned(),
            expires_at_ms: 1_700_000_900_000,
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let decoded: AuthVerifyResponse = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }
}
