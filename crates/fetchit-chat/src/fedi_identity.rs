//! Chat-internal primitives for minting the RSA-2048 keypair that
//! backs a fediverse Actor's HTTP Signature key.
//!
//! This module lives in `fetchit-chat` (not `fetchit-fedi`) because it
//! holds the key custody: the RSA private key is persisted under
//! [`StoreLayout::fedi_dir`](crate::local_store::StoreLayout::fedi_dir)
//! by the chat layer alongside the ML-DSA-65 attestation. `fetchit-fedi`
//! receives the already-generated material via
//! `fetchit_fedi::ActorIdentity::new`. The dep direction stays
//! unidirectional (`chat → fedi`).
//!
//! ## Security note (informational)
//!
//! `rustcrypto/rsa` carries RUSTSEC-2023-0071 — Marvin timing
//! sidechannel in PKCS#1 v1.5 **decryption**. Fetchit's bridge surface
//! is signing-only (HTTP Signatures over the POST body), so the
//! vulnerable code path is not on our surface. The eventual
//! `SECURITY.md` amendment will note this explicitly so a future audit
//! reader doesn't chase a non-issue.

use crate::error::ChatError;
use fetchit_fedi::attestation::{signing_input, MlDsaAttestation};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::RsaPrivateKey;

/// Generated RSA-2048 keypair material in the encodings the chat-side
/// mint factory needs to feed both the on-disk vault and
/// `fetchit_fedi::ActorIdentity::new`.
#[derive(Clone, Debug)]
pub struct RsaPrivateKeyMaterial {
    /// PEM-encoded PKCS#8 private key, ready to persist into the
    /// encrypted vault and to feed `fetchit_fedi::HttpSignatureKey`.
    pub priv_pem: String,
    /// `SubjectPublicKeyInfo` DER bytes of the public half.
    ///
    /// This is the **wire-format SPKI DER** required by
    /// `fetchit_fedi::attestation::signing_input` (NOT PKCS#1
    /// `RSAPublicKey`). The signing-input docstring spells out why:
    /// verifiers reconstructing the input PEM-decode the Actor's
    /// `publicKey.publicKeyPem` field to SPKI DER, so the signer must
    /// match.
    pub spki_der: Vec<u8>,
}

/// Generate a fresh RSA-2048 keypair, returning the PEM private + SPKI
/// DER public encodings.
///
/// Wrapped in [`tokio::task::spawn_blocking`] because RSA-2048 keygen
/// takes ~100-300 ms and would otherwise stall every other task on the
/// tokio worker thread for that duration.
///
/// # Errors
///
/// - [`ChatError::Invalid`] wrapping the inner keygen or PEM/DER
///   encoding failure (none expected for valid 2048-bit primes; the
///   error path is documented for forward-compatibility audits).
/// - [`ChatError::Invalid`] if the `spawn_blocking` task panics — the
///   panic message is preserved.
pub async fn generate_rsa_2048() -> Result<RsaPrivateKeyMaterial, ChatError> {
    let join_result = tokio::task::spawn_blocking(|| -> Result<RsaPrivateKeyMaterial, String> {
        let mut rng = rand::rngs::OsRng;
        let priv_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("rsa keygen: {e}"))?;

        let priv_pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| format!("rsa pkcs8 pem: {e}"))?
            .to_string();

        let spki_der = priv_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| format!("rsa spki der: {e}"))?
            .into_vec();

        Ok(RsaPrivateKeyMaterial { priv_pem, spki_der })
    })
    .await;

    match join_result {
        Ok(Ok(material)) => Ok(material),
        Ok(Err(msg)) => Err(ChatError::Invalid(msg)),
        Err(join_err) => Err(ChatError::Invalid(format!(
            "rsa keygen task panicked: {join_err}"
        ))),
    }
}

/// Sign the M4 actor attestation under `signer`'s ML-DSA-65 chat key.
///
/// Hands the locked-format `signing_input` bytes to the signer, then
/// packages the signature + signer pubkey into the `MlDsaAttestation`
/// the bridge-side verifier expects. The chat-side mint factory
/// (lands 1.2b-iv) calls this with the chat-identity signer and the
/// freshly-generated RSA pubkey.
///
/// # Errors
/// - [`ChatError::Invalid`] wrapping a [`fetchit_fedi::attestation::SigningInputError`]
///   if any field fails the canonical-format validation (lowercase
///   64-hex `agent_id_hex`, non-empty `handle`, etc.).
/// - [`ChatError::Invalid`] wrapping the signer error string when the
///   ML-DSA sign call fails.
pub async fn sign_actor_attestation(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    spki_der: &[u8],
    signer: &dyn x0xd_client::Signer,
) -> Result<MlDsaAttestation, ChatError> {
    let input = signing_input(handle, actor_url, agent_id_hex, spki_der)
        .map_err(|e| ChatError::Invalid(format!("signing_input: {e}")))?;
    let signature = signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sign: {e}")))?;
    Ok(MlDsaAttestation::new(signer.public_key(), signature))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    #[tokio::test]
    async fn generate_rsa_2048_produces_decodable_material() {
        let material = generate_rsa_2048().await.unwrap();
        assert!(material.priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(material.priv_pem.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(!material.spki_der.is_empty());

        // SPKI DER must round-trip through the rsa crate's parser.
        let pub_key = rsa::RsaPublicKey::from_public_key_der(&material.spki_der).unwrap();
        // 2048-bit modulus = 256-byte size minus the leading-zero
        // stripping rsa may apply; sanity-check it is in the
        // 256 ± 1 byte band rather than asserting exact equality
        // because rsa::RsaPublicKey::size returns the rounded byte
        // count of the modulus.
        let modulus_bytes = pub_key.size();
        assert_eq!(
            modulus_bytes, 256,
            "RSA-2048 modulus should be exactly 256 bytes"
        );
    }

    #[tokio::test]
    async fn generate_rsa_2048_produces_distinct_keys_per_call() {
        let a = generate_rsa_2048().await.unwrap();
        let b = generate_rsa_2048().await.unwrap();
        assert_ne!(
            a.spki_der, b.spki_der,
            "two keygen calls must produce different keys"
        );
        assert_ne!(a.priv_pem, b.priv_pem);
    }

    const VALID_AGENT_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Mock `Signer` that returns deterministic pubkey + signature
    /// bytes for assertion. Mirrors the pattern in
    /// `groups/welcome_inbound.rs::tests::StubSigner`.
    struct StubSigner {
        pub_key: Vec<u8>,
        sig: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl x0xd_client::Signer for StubSigner {
        fn agent_id(&self) -> [u8; 32] {
            [0u8; 32]
        }
        fn public_key(&self) -> Vec<u8> {
            self.pub_key.clone()
        }
        async fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Ok(self.sig.clone())
        }
    }

    struct FailingSigner;

    #[async_trait::async_trait]
    impl x0xd_client::Signer for FailingSigner {
        fn agent_id(&self) -> [u8; 32] {
            [0u8; 32]
        }
        fn public_key(&self) -> Vec<u8> {
            vec![0u8; 32]
        }
        async fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Err("simulated signing failure".into())
        }
    }

    #[tokio::test]
    async fn sign_actor_attestation_returns_pubkey_and_signature_from_signer() {
        let signer = StubSigner {
            pub_key: vec![0xAA; 32],
            sig: vec![0xBB; 64],
        };
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();

        let att = sign_actor_attestation(
            "josh",
            &actor_url,
            VALID_AGENT_HEX,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &signer,
        )
        .await
        .unwrap();

        assert_eq!(att.ml_dsa_pubkey, vec![0xAA; 32]);
        assert_eq!(att.signature, vec![0xBB; 64]);
    }

    #[tokio::test]
    async fn sign_actor_attestation_propagates_signing_input_validation() {
        let signer = StubSigner {
            pub_key: vec![0xAA; 32],
            sig: vec![0xBB; 64],
        };
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();

        let err = sign_actor_attestation("josh", &actor_url, "not-64-hex", &[0x01], &signer)
            .await
            .unwrap_err();

        let msg = format!("{err}");
        assert!(
            msg.contains("signing_input") && msg.contains("agent_id_hex"),
            "expected signing_input + agent_id_hex in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_actor_attestation_propagates_signer_failure() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let err =
            sign_actor_attestation("josh", &actor_url, VALID_AGENT_HEX, &[0x01], &FailingSigner)
                .await
                .unwrap_err();

        let msg = format!("{err}");
        assert!(
            msg.contains("ml-dsa sign") && msg.contains("simulated"),
            "expected ml-dsa sign + simulated in error; got: {msg}"
        );
    }
}
