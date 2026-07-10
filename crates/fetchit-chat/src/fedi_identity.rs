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

use crate::at_rest::MasterKey;
use crate::chat_crypto::{derive_aead_key, AEAD_KEY_LEN};
use crate::error::ChatError;
use fetchit_fedi::attestation::{
    signing_input, signing_input_v2, ActorAttestationV2, MlDsaAttestation,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::RsaPrivateKey;

/// HKDF `info` string used to derive the fediverse-bridge vault key
/// from the chat-identity master key.
///
/// **Frozen.** Bumping this is a v2 migration: every previously
/// persisted `<handle>.json.enc` would fail to decrypt under the new
/// info string. The `-v1` suffix matches the
/// [`fetchit_fedi::attestation::DOMAIN_SEPARATOR`] versioning style.
pub const FEDI_VAULT_INFO: &[u8] = b"fetchit-fedi-vault-v1";

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

/// Derive the fediverse vault key from the chat-identity master key.
///
/// Uses HKDF-SHA-256 (the same primitive `chat_crypto` already uses
/// for KEM derivation) with the FROZEN [`FEDI_VAULT_INFO`] string. The
/// chat conversation vault uses a different info string, so a compromise
/// of the fedi vault key cannot decrypt conversation vaults and vice
/// versa, even though both keys live under one unlock surface (the
/// user's single passphrase or one OS-keychain entry).
///
/// Returns a 32-byte AEAD key suitable for ChaCha20-Poly1305 seal/open.
#[must_use]
pub fn derive_fedi_vault_key(master_key: &MasterKey) -> zeroize::Zeroizing<[u8; AEAD_KEY_LEN]> {
    derive_aead_key(master_key.as_bytes(), FEDI_VAULT_INFO)
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
///
/// - [`ChatError::Invalid`] wrapping a
///   [`fetchit_fedi::attestation::SigningInputError`] if any field
///   fails the canonical-format validation (lowercase 64-hex
///   `agent_id_hex`, non-empty `handle`, etc.).
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

/// Sign a v2 actor attestation over the extended field tuple (adds
/// `profile_addr`, `relay_hint`, `hint_epoch_ms` to the binding). Same
/// signer and error surface as [`sign_actor_attestation`].
///
/// # Errors
///
/// - [`ChatError::Invalid`] wrapping a
///   [`fetchit_fedi::attestation::SigningInputError`] on field
///   validation (lowercase 64-hex `profile_addr`, bounded
///   `relay_hint`, etc.).
/// - [`ChatError::Invalid`] wrapping the signer error string when the
///   ML-DSA sign call fails.
#[allow(clippy::too_many_arguments)]
pub async fn sign_actor_attestation_v2(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    spki_der: &[u8],
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
    signer: &dyn x0xd_client::Signer,
) -> Result<ActorAttestationV2, ChatError> {
    let input = signing_input_v2(
        handle,
        actor_url,
        agent_id_hex,
        spki_der,
        profile_addr,
        relay_hint,
        hint_epoch_ms,
    )
    .map_err(|e| ChatError::Invalid(format!("signing_input_v2: {e}")))?;
    let signature = signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sign: {e}")))?;
    Ok(ActorAttestationV2 {
        version: 2,
        profile_addr: profile_addr.to_string(),
        relay_hint: relay_hint.to_string(),
        hint_epoch_ms,
        ml_dsa_pubkey: signer.public_key(),
        signature,
    })
}

/// Register (or re-assert on 409) `identity` with the fediverse directory at
/// `base`, mirroring the desktop `register_with_directory`: POST `v1/actors`,
/// and on a [`fetchit_fedi::registry::RegistryError::HandleTaken`] (409) fall
/// back to PUT so re-asserting our OWN handle after an attestation refresh
/// self-heals. A genuine squat by another agent fails the PUT's continuity
/// check and surfaces honestly. Lifted into the engine so the desktop command
/// and the FFI mint/ensure paths share one registration path (DRY).
///
/// Returns `(registered, error)`. Registration failure is REPORTED, never
/// fatal: a mint/ensure degrades to "pending" rather than failing, so a
/// bridge outage never blocks getting a local identity.
pub async fn register_or_update_actor(
    base: &url::Url,
    identity: &fetchit_fedi::actor::ActorIdentity,
    http: &reqwest::Client,
) -> (bool, Option<String>) {
    let Some(attestation_v2) = identity.ml_dsa_attestation_v2.clone() else {
        return (false, Some("no v2 attestation on identity".into()));
    };
    let req = fetchit_fedi::registry::RegisterActorRequest {
        handle: identity.handle.clone(),
        rsa_spki_der: identity.spki_der.clone(),
        attestation_v2,
    };
    match fetchit_fedi::registry::register_actor(base, &req, http).await {
        Ok(_) => (true, None),
        Err(fetchit_fedi::registry::RegistryError::HandleTaken) => {
            match fetchit_fedi::registry::update_actor(base, &req, http).await {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            }
        }
        Err(e) => (false, Some(e.to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn actor_fixture(with_v2: bool) -> fetchit_fedi::actor::ActorIdentity {
        fetchit_fedi::actor::ActorIdentity {
            handle: "alice".into(),
            actor_url: "https://etchit.io/actors/alice".parse().unwrap(),
            agent_id_hex: "aa".repeat(32),
            rsa_priv_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n".into(),
            spki_der: vec![1, 2, 3, 4],
            ml_dsa_attestation: MlDsaAttestation::new(vec![0xAA; 8], vec![0xBB; 8]),
            ml_dsa_attestation_v2: with_v2.then(|| ActorAttestationV2 {
                version: 2,
                profile_addr: "cc".repeat(32),
                relay_hint: "https://relay.example/".into(),
                hint_epoch_ms: 1,
                ml_dsa_pubkey: vec![0xAA; 8],
                signature: vec![0xBB; 8],
            }),
        }
    }

    #[tokio::test]
    async fn register_or_update_actor_registers_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("v1/actors"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"actor_url": "https://etchit.io/actors/alice"}),
                ),
            )
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let (registered, err) =
            register_or_update_actor(&base, &actor_fixture(true), &reqwest::Client::new()).await;
        assert!(registered);
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn register_or_update_actor_falls_back_to_put_on_409() {
        // Re-asserting our OWN handle after an attestation refresh: POST 409,
        // then PUT self-heals (mirrors the desktop register_with_directory).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("v1/actors"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&server)
            .await;
        // update_actor PUTs to the handle-specific path v1/actors/<handle>.
        Mock::given(method("PUT"))
            .and(path("/v1/actors/alice"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"actor_url": "https://etchit.io/actors/alice"}),
                ),
            )
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let (registered, err) =
            register_or_update_actor(&base, &actor_fixture(true), &reqwest::Client::new()).await;
        assert!(registered, "409 on POST self-heals via PUT");
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn register_or_update_actor_reports_missing_v2_attestation() {
        // No v2 attestation -> cannot build the request; reported, not fatal.
        let base = "http://unused.invalid/".parse().unwrap();
        let (registered, err) =
            register_or_update_actor(&base, &actor_fixture(false), &reqwest::Client::new()).await;
        assert!(!registered);
        assert!(err.unwrap().contains("v2 attestation"));
    }

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

    #[test]
    fn fedi_vault_info_is_frozen() {
        assert_eq!(FEDI_VAULT_INFO, b"fetchit-fedi-vault-v1");
    }

    #[test]
    fn fedi_vault_key_pins_to_known_ikm_golden_vector() {
        // FROZEN golden vector. If this test fails, you have either
        // bumped FEDI_VAULT_INFO, switched HKDF primitives, or both —
        // any of which is a v2 wire migration. Do not "fix" the test
        // by updating the expected bytes without versioning the info
        // string.
        let known_master = MasterKey::from_bytes_for_test([0x42u8; AEAD_KEY_LEN]);
        let derived = derive_fedi_vault_key(&known_master);

        // Computed once via HKDF-SHA-256(salt=None, ikm=[0x42;32],
        // info=b"fetchit-fedi-vault-v1", L=32).
        let expected = [
            0x3e, 0x02, 0x1b, 0x0f, 0xb5, 0x30, 0x65, 0xb3, 0x6e, 0xb6, 0x2e, 0xaa, 0xab, 0xf3,
            0x27, 0x23, 0xe4, 0xe7, 0x25, 0x67, 0xe2, 0xc3, 0xbf, 0x7f, 0xdb, 0xe8, 0x9a, 0xca,
            0xf0, 0x9f, 0x5e, 0xd5,
        ];
        assert_eq!(*derived, expected);
    }

    #[test]
    fn fedi_vault_key_differs_from_other_info_strings() {
        // A bug that accidentally lifted the wrong info string would
        // produce a non-distinct key. Confirm domain separation works.
        let known_master = MasterKey::from_bytes_for_test([0x42u8; AEAD_KEY_LEN]);
        let fedi = derive_fedi_vault_key(&known_master);
        let other = derive_aead_key(known_master.as_bytes(), b"some-other-info-v1");
        assert_ne!(fedi, other);
    }

    #[test]
    fn fedi_vault_key_differs_when_ikm_changes() {
        let m1 = MasterKey::from_bytes_for_test([0x11u8; AEAD_KEY_LEN]);
        let m2 = MasterKey::from_bytes_for_test([0x22u8; AEAD_KEY_LEN]);
        assert_ne!(derive_fedi_vault_key(&m1), derive_fedi_vault_key(&m2));
    }

    /// Mock `Signer` that returns deterministic pubkey + signature
    /// bytes for assertion.
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

    /// Real ML-DSA-65 signer so the v2 sign half can be verified
    /// against `verify_binding_v2` end to end.
    struct RealSigner {
        pk: Vec<u8>,
        sk: saorsa_pqc::api::sig::MlDsaSecretKey,
    }

    impl RealSigner {
        fn generate() -> Self {
            use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
            let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
            let (pk, sk) = dsa.generate_keypair().unwrap();
            Self {
                pk: pk.to_bytes(),
                sk,
            }
        }
    }

    #[async_trait::async_trait]
    impl x0xd_client::Signer for RealSigner {
        fn agent_id(&self) -> [u8; 32] {
            fetchit_relay_proto::derive_agent_id(&self.pk)
        }
        fn public_key(&self) -> Vec<u8> {
            self.pk.clone()
        }
        async fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, String> {
            use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
            let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
            Ok(dsa
                .sign(&self.sk, &fetchit_relay_proto::agent_sign_input(message))
                .map_err(|e| e.to_string())?
                .to_bytes())
        }
    }

    #[tokio::test]
    async fn sign_actor_attestation_v2_round_trips_through_verify() {
        let signer = RealSigner::generate();
        let agent_id_hex = hex::encode(x0xd_client::Signer::agent_id(&signer));
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();

        let att = sign_actor_attestation_v2(
            "josh",
            &actor_url,
            &agent_id_hex,
            &[7, 7],
            &"a".repeat(64),
            "https://relay.example/",
            99,
            &signer,
        )
        .await
        .unwrap();

        assert_eq!(att.version, 2);
        assert_eq!(att.profile_addr, "a".repeat(64));
        assert_eq!(att.relay_hint, "https://relay.example/");
        assert_eq!(att.hint_epoch_ms, 99);

        let derived =
            fetchit_fedi::attestation::verify_binding_v2("josh", &actor_url, &[7, 7], &att)
                .unwrap();
        assert_eq!(derived, agent_id_hex);
    }

    #[tokio::test]
    async fn sign_actor_attestation_v2_propagates_field_validation() {
        let signer = StubSigner {
            pub_key: vec![0xAA; 32],
            sig: vec![0xBB; 64],
        };
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();

        let err = sign_actor_attestation_v2(
            "josh",
            &actor_url,
            VALID_AGENT_HEX,
            &[0x01],
            "NOT-64-HEX",
            "https://relay.example/",
            1,
            &signer,
        )
        .await
        .unwrap_err();

        let msg = format!("{err}");
        assert!(
            msg.contains("signing_input_v2") && msg.contains("profile_addr"),
            "expected signing_input_v2 + profile_addr in error; got: {msg}"
        );
    }
}
