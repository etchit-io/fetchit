//! Pluggable signer abstraction.
//!
//! [`Signer`] and [`X0xdSigner`] now live in the `x0xd-client` crate
//! so non-chat consumers (e.g. publishers) can use them without
//! pulling the saorsa-pqc dep tree; this module re-exports them so
//! existing callers keep working.
//!
//! Two implementations are exclusive to this crate because they hold
//! ML-DSA-65 key material via `saorsa-pqc`:
//!
//! - [`MlDsaSigner`] — local ML-DSA-65 keypair. Use when there is no
//!   x0xd around.
//! - [`StaticKeySigner`] — deterministic fixture for tests that pair
//!   the client with the server's `AcceptAllVerifier`.

use async_trait::async_trait;
use fetchit_relay_proto::{agent_sign_input, derive_agent_id};
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaVariant};

pub use x0xd_client::{Signer, X0xdSigner};

/// Test signer with deterministic outputs.
///
/// Use only in tests or controlled local-dev; pairs with the server's
/// `AcceptAllVerifier`.
pub struct StaticKeySigner {
    agent_id: [u8; 32],
    public_key: Vec<u8>,
    fixed_signature: Vec<u8>,
}

impl StaticKeySigner {
    /// Build a signer from a public key — agent id is derived using
    /// the shared [`derive_agent_id`] convention.
    #[must_use]
    pub fn from_public_key(public_key: Vec<u8>) -> Self {
        let agent_id = derive_agent_id(&public_key);
        Self {
            agent_id,
            public_key,
            fixed_signature: vec![0u8; 64],
        }
    }
}

#[async_trait]
impl Signer for StaticKeySigner {
    fn agent_id(&self) -> [u8; 32] {
        self.agent_id
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.fixed_signature.clone())
    }
}

/// Production signer backed by a real ML-DSA-65 keypair.
pub struct MlDsaSigner {
    dsa: MlDsa,
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
    public_key_bytes: Vec<u8>,
    agent_id: [u8; 32],
}

impl MlDsaSigner {
    /// Generate a fresh ML-DSA-65 keypair.
    ///
    /// # Errors
    /// Returns a string error if `saorsa-pqc` keygen fails.
    pub fn generate() -> Result<Self, String> {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (public_key, secret_key) = dsa.generate_keypair().map_err(|e| e.to_string())?;
        let public_key_bytes = public_key.to_bytes();
        let agent_id = derive_agent_id(&public_key_bytes);
        Ok(Self {
            dsa,
            public_key,
            secret_key,
            public_key_bytes,
            agent_id,
        })
    }

    /// Reconstruct from previously-serialised raw keypair bytes.
    ///
    /// # Errors
    /// Returns a string error when either byte string is malformed.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, String> {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let public_key = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, public_key)
            .map_err(|e| e.to_string())?;
        let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, secret_key)
            .map_err(|e| e.to_string())?;
        let public_key_bytes = public_key.to_bytes();
        let agent_id = derive_agent_id(&public_key_bytes);
        Ok(Self {
            dsa,
            public_key,
            secret_key,
            public_key_bytes,
            agent_id,
        })
    }

    /// Reconstruct a signer deterministically from a 32-byte seed.
    ///
    /// The same `seed` always yields the same keypair, hence the same
    /// [`agent_id`](Signer::agent_id). That determinism is what makes
    /// seed backup and restore possible: the 32 seed bytes alone recover
    /// the full identity. Backed by FIPS-204 ML-DSA-65 seeded key
    /// generation (`saorsa-pqc`'s `generate_keypair_from_seed`), which is
    /// infallible, so this constructor cannot fail.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (public_key, secret_key) = dsa.generate_keypair_from_seed(seed);
        let public_key_bytes = public_key.to_bytes();
        let agent_id = derive_agent_id(&public_key_bytes);
        Self {
            dsa,
            public_key,
            secret_key,
            public_key_bytes,
            agent_id,
        }
    }

    /// The signer's secret-key bytes (caller is responsible for safe storage).
    #[must_use]
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes()
    }

    /// Borrow the signer's public key value.
    #[must_use]
    pub fn public_key_value(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
}

#[async_trait]
impl Signer for MlDsaSigner {
    fn agent_id(&self) -> [u8; 32] {
        self.agent_id
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        // Reproduce x0x >= 0.29's mandatory external-agent-sign framing so a
        // daemonless signature is byte-identical to what an x0xd `/agent/sign`
        // call produces for the same `message` (see `X0xdSigner`). Without this
        // wrap the desktop (daemon) and mobile (daemonless) signing paths would
        // fail to cross-verify.
        let framed = agent_sign_input(message);
        self.dsa
            .sign(&self.secret_key, &framed)
            .map(|sig| sig.to_bytes())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_signer_signs_and_self_verifies() {
        let signer = MlDsaSigner::generate().unwrap();
        let msg = b"verify me";
        let sig = signer.sign(msg).await.unwrap();

        // sign() wraps with the external-agent-sign framing, so the raw
        // ML-DSA signature is over `agent_sign_input(msg)`.
        let framed = agent_sign_input(msg);
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(signer.public_key_value(), &framed, &sig_value)
            .unwrap());
    }

    #[tokio::test]
    async fn from_bytes_round_trips() {
        let original = MlDsaSigner::generate().unwrap();
        let pk = original.public_key();
        let sk = original.secret_key_bytes();
        let restored = MlDsaSigner::from_bytes(&pk, &sk).unwrap();
        assert_eq!(restored.agent_id(), original.agent_id());
        assert_eq!(restored.public_key(), original.public_key());

        let msg = b"after restore";
        let sig = restored.sign(msg).await.unwrap();
        let framed = agent_sign_input(msg);
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(restored.public_key_value(), &framed, &sig_value)
            .unwrap());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let a = MlDsaSigner::from_seed(&seed);
        let b = MlDsaSigner::from_seed(&seed);
        assert_eq!(a.agent_id(), b.agent_id());
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.secret_key_bytes(), b.secret_key_bytes());
    }

    #[test]
    fn from_seed_differs_by_seed() {
        let a = MlDsaSigner::from_seed(&[1u8; 32]);
        let b = MlDsaSigner::from_seed(&[2u8; 32]);
        assert_ne!(a.agent_id(), b.agent_id());
        assert_ne!(a.public_key(), b.public_key());
    }

    #[tokio::test]
    async fn from_seed_signs_and_self_verifies() {
        let signer = MlDsaSigner::from_seed(&[7u8; 32]);
        let msg = b"seed-derived signer signs";
        let sig = signer.sign(msg).await.unwrap();
        let framed = agent_sign_input(msg);
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(signer.public_key_value(), &framed, &sig_value)
            .unwrap());
    }

    #[test]
    fn from_seed_reproduces_golden_agent_id() {
        // Cross-platform / cross-pin reproducibility contract: seed
        // `[42u8; 32]` must always derive this exact agent_id. If this
        // ever fails, seeded keygen drifted and a restore would yield a
        // different identity than the backup. The same value must
        // reproduce on aarch64 (Android device-verify).
        let signer = MlDsaSigner::from_seed(&[42u8; 32]);
        assert_eq!(
            hex::encode(signer.agent_id()),
            "d53d604e4fb156e5bad3cf6ac68926dbae6c6e6d3b99f2744db3406447a3b6f0"
        );
    }
}
