//! Signature verification trait + provided implementations.
//!
//! The trait isolates the relay from the specific PQ-crypto crate.
//! [`MlDsa65Verifier`] is the production backend that calls into
//! `saorsa-pqc`; [`AcceptAllVerifier`] is for tests.

use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

/// Verifies ML-DSA-65 signatures over arbitrary message bytes.
pub trait SignatureVerifier: Send + Sync {
    /// Returns `true` when `signature` is a valid ML-DSA-65 signature
    /// of `message` under `public_key`.
    fn verify_ml_dsa_65(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Test / dev verifier that accepts every signature.
///
/// Never use outside `cfg(test)` or controlled local-dev environments.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceptAllVerifier;

impl SignatureVerifier for AcceptAllVerifier {
    fn verify_ml_dsa_65(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
        true
    }
}

/// Production verifier — calls `saorsa-pqc`'s ML-DSA-65 implementation.
pub struct MlDsa65Verifier {
    dsa: MlDsa,
}

impl Default for MlDsa65Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDsa65Verifier {
    /// Construct a verifier bound to the ML-DSA-65 variant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dsa: MlDsa::new(MlDsaVariant::MlDsa65),
        }
    }
}

impl SignatureVerifier for MlDsa65Verifier {
    fn verify_ml_dsa_65(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, public_key) else {
            return false;
        };
        let Ok(sig) = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, signature) else {
            return false;
        };
        self.dsa.verify(&pk, message, &sig).unwrap_or(false)
    }
}

pub use fetchit_relay_proto::derive_agent_id;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accept_all_verifies_garbage() {
        let v = AcceptAllVerifier;
        assert!(v.verify_ml_dsa_65(&[1, 2], &[3, 4], &[5, 6]));
    }

    #[test]
    fn real_verifier_rejects_garbage() {
        let v = MlDsa65Verifier::new();
        assert!(!v.verify_ml_dsa_65(&[1, 2], &[3, 4], &[5, 6]));
    }

    #[test]
    fn real_verifier_accepts_genuine_signature() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let msg = b"hello relay";
        let sig = dsa.sign(&sk, msg).unwrap();
        let v = MlDsa65Verifier::new();
        assert!(v.verify_ml_dsa_65(&pk.to_bytes(), msg, &sig.to_bytes()));
    }

    #[test]
    fn real_verifier_rejects_wrong_message() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let sig = dsa.sign(&sk, b"signed-this").unwrap();
        let v = MlDsa65Verifier::new();
        assert!(!v.verify_ml_dsa_65(&pk.to_bytes(), b"but-verifying-that", &sig.to_bytes()));
    }

    #[test]
    fn agent_id_matches_proto_derivation() {
        let pk = b"some-public-key-bytes";
        let id = derive_agent_id(pk);
        assert_eq!(id, fetchit_relay_proto::derive_agent_id(pk));
    }
}
