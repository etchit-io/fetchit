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
use fetchit_relay_proto::derive_agent_id;
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
        self.dsa
            .sign(&self.secret_key, message)
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

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(signer.public_key_value(), msg, &sig_value)
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
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(restored.public_key_value(), msg, &sig_value)
            .unwrap());
    }
}
