//! `bridge-auth-v1` — the request-signing wire shape shared by the
//! bridge (verify side) and the chat client (sign side) for M7's
//! mutating social endpoints.
//!
//! The bridge holds no private keys: a device signs each state-changing
//! request with the ML-DSA-65 agent key whose attestation its actor
//! registered with, and the bridge verifies against that stored key.
//! This module is the ONE definition of the canonical bytes both sides
//! must agree on — keeping it in `fetchit-fedi` (a dependency of both
//! `fetchit-bridge-server` and `fetchit-chat`) prevents the two ends
//! from drifting.
//!
//! ## Wire shape
//!
//! Three request headers:
//! ```text
//! X-Fetchit-Agent: <64-hex agent id>
//! X-Fetchit-Ts:    <unix milliseconds, decimal>
//! X-Fetchit-Sig:   <STANDARD base64 ML-DSA-65 signature>
//! ```
//!
//! The signature is produced by the x0x `Signer` trait, i.e. over the
//! 0.29 external-agent-sign framing (`agent_sign_input`) of
//! [`canonical_request`]. The bridge re-applies that framing before
//! verifying.

use sha2::{Digest, Sha256};

/// Header carrying the 64-hex agent id.
pub const HEADER_AGENT: &str = "x-fetchit-agent";
/// Header carrying the unix-ms timestamp.
pub const HEADER_TS: &str = "x-fetchit-ts";
/// Header carrying the STANDARD-base64 ML-DSA-65 signature.
pub const HEADER_SIG: &str = "x-fetchit-sig";

/// Maximum allowed `|now - ts|` in milliseconds (5 minutes).
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// Domain separator prefixing the canonical bytes.
const DOMAIN: &[u8] = b"fetchit-bridge-auth-v1";

/// The canonical bytes a client signs (pre-`agent_sign_input` framing).
///
/// ```text
/// b"fetchit-bridge-auth-v1" || 0x00
///   || METHOD || 0x00 || path || 0x00
///   || u64_be(ts_ms) || sha256(body)
/// ```
///
/// `method` is uppercased; `path` is the exact request path (no query —
/// no authed endpoint uses one). The body hash pins the payload; the
/// timestamp bounds replay to ±[`MAX_SKEW_MS`].
#[must_use]
pub fn canonical_request(method: &str, path: &str, ts_ms: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + method.len() + path.len() + 64);
    out.extend_from_slice(DOMAIN);
    out.push(0);
    out.extend_from_slice(method.to_ascii_uppercase().as_bytes());
    out.push(0);
    out.extend_from_slice(path.as_bytes());
    out.push(0);
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out.extend_from_slice(&Sha256::digest(body));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_deterministic_and_field_separated() {
        let a = canonical_request("POST", "/actors/josh/following", 1000, b"{}");
        let b = canonical_request("post", "/actors/josh/following", 1000, b"{}");
        assert_eq!(a, b, "method is uppercased");
        // any field change flips the bytes
        assert_ne!(
            a,
            canonical_request("GET", "/actors/josh/following", 1000, b"{}")
        );
        assert_ne!(
            a,
            canonical_request("POST", "/actors/eve/following", 1000, b"{}")
        );
        assert_ne!(
            a,
            canonical_request("POST", "/actors/josh/following", 1001, b"{}")
        );
        assert_ne!(
            a,
            canonical_request("POST", "/actors/josh/following", 1000, b"{ }")
        );
        // starts with the domain sep, ends with a 32-byte digest
        assert!(a.starts_with(DOMAIN));
        assert_eq!(
            a.len(),
            DOMAIN.len() + 1 + 4 + 1 + "/actors/josh/following".len() + 1 + 8 + 32
        );
    }
}
