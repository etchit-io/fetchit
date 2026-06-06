//! Client-side denylist consumer.
//!
//! Stage 2 Task 2.1 of M3 federation core
//! (`docs/superpowers/plans/2026-06-06-m3-federation-core-plan.md`).
//! Reads a published [`DenylistResponse`], verifies the issuer's
//! ML-DSA-65 signature over the canonical
//! [`crate::types::DenylistToSign`] payload, caches the targeted
//! `TargetIdentity` set, and answers fast lookups.
//!
//! HTTP fetch + refresh scheduling land in a follow-up commit. The
//! types here are pure verify-and-lookup so they slot into both the
//! chat-peer's send/receive gates and any other client that
//! consumes the published denylist.

use crate::error::TrustError;
use crate::types::{
    DenylistEntry, DenylistResponse, DenylistToSign, EntryKind, TargetIdentity,
};
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};
use std::collections::HashSet;

/// Canonical-bytes shape the issuer signs and the consumer verifies.
///
/// # Errors
/// Returns [`TrustError::IssuerKey`] when the postcard encoding fails.
pub fn signing_bytes(response: &DenylistResponse) -> Result<Vec<u8>, TrustError> {
    let payload = DenylistToSign {
        etag: response.etag.as_str(),
        generated_at_ms: response.generated_at_ms,
        kind: response.kind,
        entries: &response.entries,
    };
    postcard::to_allocvec(&payload).map_err(|e| TrustError::IssuerKey(format!("encode: {e}")))
}

/// Verify the issuer's signature over the canonical payload.
///
/// # Errors
/// Returns [`TrustError::IssuerKey`] when the public key parse, the
/// signature parse, the encode, or the verify itself fails. Also
/// returns it when the signature does not match — same variant
/// because the caller's recourse is the same in every case: discard
/// the response.
pub fn verify_signature(
    response: &DenylistResponse,
    issuer_public_key_bytes: &[u8],
) -> Result<(), TrustError> {
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, issuer_public_key_bytes)
        .map_err(|e| TrustError::IssuerKey(format!("pk: {e}")))?;
    let sig_bytes = hex::decode(&response.issuer_signature_hex)
        .map_err(|e| TrustError::IssuerKey(format!("sig hex: {e}")))?;
    let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .map_err(|e| TrustError::IssuerKey(format!("sig: {e}")))?;
    let message = signing_bytes(response)?;
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    if dsa
        .verify(&pk, &message, &signature)
        .map_err(|e| TrustError::IssuerKey(format!("verify: {e}")))?
    {
        Ok(())
    } else {
        Err(TrustError::IssuerKey("signature mismatch".into()))
    }
}

/// A verified denylist snapshot ready for fast `is_blocked` lookups.
pub struct VerifiedDenylist {
    response: DenylistResponse,
    blocked: HashSet<TargetIdentity>,
}

impl VerifiedDenylist {
    /// Construct from a [`DenylistResponse`] after verifying the
    /// issuer's signature.
    ///
    /// # Errors
    /// Returns the same variants as [`verify_signature`].
    pub fn from_response(
        response: DenylistResponse,
        issuer_public_key_bytes: &[u8],
    ) -> Result<Self, TrustError> {
        verify_signature(&response, issuer_public_key_bytes)?;
        let blocked = response.entries.iter().map(|e| e.target.clone()).collect();
        Ok(Self { response, blocked })
    }

    /// Construct without signature verification.
    ///
    /// Reserved for tests and for chain-of-custody flows where the
    /// caller has already verified the response upstream.
    #[must_use]
    pub fn new_unchecked(response: DenylistResponse) -> Self {
        let blocked = response.entries.iter().map(|e| e.target.clone()).collect();
        Self { response, blocked }
    }

    /// True when `target` appears in the denylist.
    #[must_use]
    pub fn is_blocked(&self, target: &TargetIdentity) -> bool {
        self.blocked.contains(target)
    }

    /// Convenience: check a 64-hex agent id.
    #[must_use]
    pub fn is_blocked_agent_hex(&self, agent_id_hex: &str) -> bool {
        self.is_blocked(&TargetIdentity::new(EntryKind::AgentId, agent_id_hex))
    }

    /// Convenience: check a 64-hex Autonomi `XorName`.
    #[must_use]
    pub fn is_blocked_xor_name_hex(&self, xor_name_hex: &str) -> bool {
        self.is_blocked(&TargetIdentity::new(EntryKind::XorName, xor_name_hex))
    }

    /// Borrow the underlying response — useful for ops/diagnostic
    /// surfaces that want `etag` / `generated_at_ms` / `issuer_key_id`.
    #[must_use]
    pub fn response(&self) -> &DenylistResponse {
        &self.response
    }

    /// Borrow the cached entry set.
    #[must_use]
    pub fn entries(&self) -> &[DenylistEntry] {
        &self.response.entries
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signer::IssuerSigner;
    use crate::types::ReportKind;

    fn sample_response(signer: &IssuerSigner, kind: EntryKind) -> DenylistResponse {
        let entries = vec![DenylistEntry {
            target: TargetIdentity::new(kind, "a".repeat(64)),
            added_at_ms: 1_700_000_000_000,
            reason: ReportKind::Spam,
        }];
        let to_sign = DenylistToSign {
            etag: "etag-1",
            generated_at_ms: 1_700_000_000_001,
            kind,
            entries: &entries,
        };
        let sign_bytes = postcard::to_allocvec(&to_sign).unwrap();
        let sig = signer.sign(&sign_bytes).unwrap();
        DenylistResponse {
            etag: "etag-1".into(),
            generated_at_ms: 1_700_000_000_001,
            kind,
            entries,
            issuer_signature_hex: hex::encode(sig),
            issuer_key_id: signer.key_id.clone(),
        }
    }

    #[test]
    fn verified_denylist_round_trips_via_issuer_signature() {
        let signer = IssuerSigner::generate("test").unwrap();
        let response = sample_response(&signer, EntryKind::AgentId);
        let verified = VerifiedDenylist::from_response(response, &signer.public_key_bytes())
            .expect("signature should verify");
        assert!(verified.is_blocked_agent_hex(&"a".repeat(64)));
        assert!(!verified.is_blocked_agent_hex(&"b".repeat(64)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let signer = IssuerSigner::generate("test").unwrap();
        let mut response = sample_response(&signer, EntryKind::AgentId);
        // Tamper after signing: add an extra entry the issuer didn't include.
        response.entries.push(DenylistEntry {
            target: TargetIdentity::new(EntryKind::AgentId, "f".repeat(64)),
            added_at_ms: 1_700_000_000_002,
            reason: ReportKind::Other,
        });
        let res = VerifiedDenylist::from_response(response, &signer.public_key_bytes());
        assert!(res.is_err(), "tampered entries must fail verification");
    }

    #[test]
    fn verify_rejects_wrong_issuer_key() {
        let signer = IssuerSigner::generate("issuer-a").unwrap();
        let other = IssuerSigner::generate("issuer-b").unwrap();
        let response = sample_response(&signer, EntryKind::AgentId);
        let res = VerifiedDenylist::from_response(response, &other.public_key_bytes());
        assert!(res.is_err(), "wrong issuer key must fail verification");
    }
}
