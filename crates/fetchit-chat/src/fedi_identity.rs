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
use crate::fedi_mint_state::RegistrationState;
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

/// Verify the vault's stored attestations under the CURRENT agent key and
/// re-sign any that no longer hold, returning whether anything was re-signed
/// (the caller persists the vault when `true`).
///
/// Two staleness classes are healed:
///
/// - **Signing-format drift** — attestations minted before the x0x 0.29
///   external-agent-sign framing are signed over the raw input; every
///   current verifier (bridge registration included) reconstructs the
///   framed input, so those signatures can never verify again. Re-signing
///   through the live signer produces the framed shape.
/// - **Agent-key rotation** — an attestation validly signed by a previous
///   agent key binds the actor to a dead chat identity; rebinding under
///   the live key keeps handle-to-agent resolution truthful.
///
/// A healed v2 attestation preserves its `profile_addr`/`relay_hint` and
/// bumps `hint_epoch_ms` to strictly increase (registries reject
/// non-increasing epochs). `vault.agent_id_hex` follows the live key.
///
/// # Errors
///
/// [`ChatError::Invalid`] when re-signing fails (signer error or canonical
/// field validation).
pub async fn heal_actor_attestations(
    vault: &mut crate::fedi_vault::ActorIdentityVault,
    signer: &dyn x0xd_client::Signer,
    now_ms: u64,
) -> Result<bool, ChatError> {
    let signer_pk = signer.public_key();
    let live_agent_hex = hex::encode(signer.agent_id());
    let mut healed = false;

    let v1_holds = vault.ml_dsa_attestation.ml_dsa_pubkey == signer_pk
        && fetchit_fedi::attestation::verify_binding(
            &vault.handle,
            &vault.actor_url,
            &vault.spki_der,
            &vault.ml_dsa_attestation,
        )
        .is_ok();
    if !v1_holds {
        vault.ml_dsa_attestation = sign_actor_attestation(
            &vault.handle,
            &vault.actor_url,
            &live_agent_hex,
            &vault.spki_der,
            signer,
        )
        .await?;
        healed = true;
    }

    if let Some(v2) = vault.ml_dsa_attestation_v2.clone() {
        let v2_holds = v2.ml_dsa_pubkey == signer_pk
            && fetchit_fedi::attestation::verify_binding_v2(
                &vault.handle,
                &vault.actor_url,
                &vault.spki_der,
                &v2,
            )
            .is_ok();
        if !v2_holds {
            let epoch = now_ms.max(v2.hint_epoch_ms.saturating_add(1));
            vault.ml_dsa_attestation_v2 = Some(
                sign_actor_attestation_v2(
                    &vault.handle,
                    &vault.actor_url,
                    &live_agent_hex,
                    &vault.spki_der,
                    &v2.profile_addr,
                    &v2.relay_hint,
                    epoch,
                    signer,
                )
                .await?,
            );
            healed = true;
        }
    }

    if healed {
        vault.agent_id_hex = live_agent_hex;
    }
    Ok(healed)
}

/// Register (or re-assert) `identity` with the fediverse directory at
/// `base` by posting the actor's own JSON-LD document to `actors` — the
/// shape the deployed bridge ingests, verifies (embedded ML-DSA
/// attestation), stores, and serves. Lifted into the engine so the
/// desktop command and the FFI mint/ensure paths share one registration
/// path (DRY).
///
/// The returned [`RegistrationState`] is the classification the shells
/// act on. The bridge answers `200` when the SAME agent id re-registers
/// (an idempotent update — success, and how an attestation refresh
/// self-heals) and `409` ONLY when the handle row belongs to a different
/// agent id, so a conflict is unambiguous and terminal: no amount of
/// retrying wins that name back. Everything else is transient.
///
/// Registration failure is REPORTED, never fatal: a mint/ensure degrades
/// rather than failing, so a bridge outage never blocks getting a local
/// identity.
pub async fn register_or_update_actor(
    base: &url::Url,
    identity: &fetchit_fedi::actor::ActorIdentity,
    http: &reqwest::Client,
) -> RegistrationState {
    // The deployed bridge registers by ingesting the actor's own JSON-LD
    // document (the shape it stores + serves), NOT the compact
    // RegisterActorRequest. Build it from the identity and POST it; the bridge
    // verifies the embedded attestation and is idempotent on re-registration
    // of the same identity, so re-asserting our own handle self-heals.
    let actor = match fetchit_fedi::actor::Actor::from_identity(identity) {
        Ok(a) => a,
        Err(e) => {
            return RegistrationState::Transient {
                reason: format!("build actor doc: {e}"),
            }
        }
    };
    let doc = actor.to_json_ld();
    match fetchit_fedi::registry::register_actor_doc(base, &doc, http).await {
        Ok(()) => RegistrationState::Registered,
        Err(fetchit_fedi::registry::RegistryError::HandleTaken) => RegistrationState::NameTaken,
        Err(e) => RegistrationState::Transient {
            reason: e.to_string(),
        },
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
    async fn register_or_update_actor_posts_actor_doc_to_actors() {
        // The bridge ingests the actor JSON-LD document at POST /actors and
        // answers with a plain-text body; success is the status, not a JSON
        // payload. Assert we POST the doc to /actors and treat 200 as success.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .respond_with(ResponseTemplate::new(200).set_body_string("updated"))
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let state =
            register_or_update_actor(&base, &actor_fixture(true), &reqwest::Client::new()).await;
        assert_eq!(state, RegistrationState::Registered);
    }

    #[tokio::test]
    async fn register_or_update_actor_classifies_409_as_terminal_name_taken() {
        // A 409 means a DIFFERENT identity holds the handle (a squat); the
        // bridge answers our own re-registration with 200, so 409 is a real
        // conflict surfaced honestly, never claimed as success — and never
        // retried, because re-POSTing the same handle can only 409 again.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let state =
            register_or_update_actor(&base, &actor_fixture(true), &reqwest::Client::new()).await;
        assert_eq!(state, RegistrationState::NameTaken);
        assert!(state.is_terminal());
    }

    #[tokio::test]
    async fn register_or_update_actor_treats_our_own_re_register_as_success() {
        // The idempotent half of the 409 contract: the bridge answers 200
        // ("updated") when the SAME agent id re-registers, which is how an
        // attestation refresh self-heals. That must stay success, NOT be
        // mistaken for a conflict.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .respond_with(ResponseTemplate::new(200).set_body_string("updated"))
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let state =
            register_or_update_actor(&base, &actor_fixture(true), &reqwest::Client::new()).await;
        assert_eq!(state, RegistrationState::Registered);
        assert!(!state.is_terminal());
    }

    #[tokio::test]
    async fn register_or_update_actor_classifies_5xx_as_retryable() {
        // A bridge fault is NOT the user's problem to solve: it stays
        // retryable so the self-heal pass keeps trying.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let state =
            register_or_update_actor(&base, &actor_fixture(true), &reqwest::Client::new()).await;
        assert!(
            matches!(state, RegistrationState::Transient { ref reason } if reason.contains("503")),
            "got {state:?}"
        );
        assert!(!state.is_terminal());
    }

    #[tokio::test]
    async fn register_or_update_actor_registers_without_v2_attestation() {
        // The bridge verifies the v1 attestation carried in the actor doc; a
        // v2 attestation is not required to register, so a v1-only identity
        // (fresh mint, pre-upgrade) registers successfully.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/actors"))
            .respond_with(ResponseTemplate::new(201).set_body_string("registered"))
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri()).parse().unwrap();
        let state =
            register_or_update_actor(&base, &actor_fixture(false), &reqwest::Client::new()).await;
        assert_eq!(state, RegistrationState::Registered);
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

    impl RealSigner {
        /// Sign WITHOUT the external-agent-sign framing — the byte shape
        /// every pre-x0x-0.29 build produced. Models vault attestations
        /// minted before the framing cutover (00796c4).
        fn sign_raw(&self, message: &[u8]) -> Vec<u8> {
            use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
            MlDsa::new(MlDsaVariant::MlDsa65)
                .sign(&self.sk, message)
                .unwrap()
                .to_bytes()
        }
    }

    fn heal_vault(
        signer: &RealSigner,
        v1: MlDsaAttestation,
        v2: Option<ActorAttestationV2>,
    ) -> crate::fedi_vault::ActorIdentityVault {
        crate::fedi_vault::ActorIdentityVault {
            handle: "josh".into(),
            actor_url: "https://etchit.io/actors/josh".parse().unwrap(),
            agent_id_hex: hex::encode(x0xd_client::Signer::agent_id(signer)),
            rsa_priv_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n".into(),
            spki_der: vec![7, 7],
            ml_dsa_attestation: v1,
            ml_dsa_attestation_v2: v2,
        }
    }

    #[tokio::test]
    async fn heal_re_signs_a_pre_framing_v1_attestation() {
        let signer = RealSigner::generate();
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let agent_hex = hex::encode(x0xd_client::Signer::agent_id(&signer));
        // The exact stale shape: signed by the SAME key, but over the raw
        // signing input (no agent-sign framing), as pre-cutover mints did.
        let input = signing_input("josh", &actor_url, &agent_hex, &[7, 7]).unwrap();
        let stale = MlDsaAttestation::new(signer.pk.clone(), signer.sign_raw(&input));
        assert!(
            fetchit_fedi::attestation::verify_binding("josh", &actor_url, &[7, 7], &stale).is_err(),
            "fixture must be rejected by the current verifier"
        );

        let mut vault = heal_vault(&signer, stale, None);
        let healed = heal_actor_attestations(&mut vault, &signer, 1_000)
            .await
            .unwrap();

        assert!(healed);
        let derived = fetchit_fedi::attestation::verify_binding(
            "josh",
            &actor_url,
            &[7, 7],
            &vault.ml_dsa_attestation,
        )
        .unwrap();
        assert_eq!(derived, agent_hex);
        assert_eq!(vault.agent_id_hex, agent_hex);
    }

    #[tokio::test]
    async fn heal_is_a_no_op_when_attestations_verify() {
        let signer = RealSigner::generate();
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let agent_hex = hex::encode(x0xd_client::Signer::agent_id(&signer));
        let current = sign_actor_attestation("josh", &actor_url, &agent_hex, &[7, 7], &signer)
            .await
            .unwrap();

        let mut vault = heal_vault(&signer, current.clone(), None);
        let healed = heal_actor_attestations(&mut vault, &signer, 1_000)
            .await
            .unwrap();

        assert!(!healed);
        assert_eq!(vault.ml_dsa_attestation, current);
    }

    #[tokio::test]
    async fn heal_rebinds_to_a_rotated_agent_key() {
        let old = RealSigner::generate();
        let new = RealSigner::generate();
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let old_hex = hex::encode(x0xd_client::Signer::agent_id(&old));
        // Valid under the OLD key — verifies fine, but binds a dead agent.
        let old_att = sign_actor_attestation("josh", &actor_url, &old_hex, &[7, 7], &old)
            .await
            .unwrap();

        let mut vault = heal_vault(&old, old_att, None);
        let healed = heal_actor_attestations(&mut vault, &new, 1_000)
            .await
            .unwrap();

        assert!(healed);
        let new_hex = hex::encode(x0xd_client::Signer::agent_id(&new));
        assert_eq!(vault.agent_id_hex, new_hex);
        let derived = fetchit_fedi::attestation::verify_binding(
            "josh",
            &actor_url,
            &[7, 7],
            &vault.ml_dsa_attestation,
        )
        .unwrap();
        assert_eq!(derived, new_hex);
    }

    #[tokio::test]
    async fn heal_re_signs_stale_v2_and_bumps_epoch() {
        let signer = RealSigner::generate();
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let agent_hex = hex::encode(x0xd_client::Signer::agent_id(&signer));
        let profile_addr = "a".repeat(64);
        let relay_hint = "https://relay.example/";
        // v1 current, v2 stale (raw-signed, pre-cutover).
        let v1 = sign_actor_attestation("josh", &actor_url, &agent_hex, &[7, 7], &signer)
            .await
            .unwrap();
        let v2_input = signing_input_v2(
            "josh",
            &actor_url,
            &agent_hex,
            &[7, 7],
            &profile_addr,
            relay_hint,
            5,
        )
        .unwrap();
        let stale_v2 = ActorAttestationV2 {
            version: 2,
            profile_addr: profile_addr.clone(),
            relay_hint: relay_hint.into(),
            hint_epoch_ms: 5,
            ml_dsa_pubkey: signer.pk.clone(),
            signature: signer.sign_raw(&v2_input),
        };

        let mut vault = heal_vault(&signer, v1.clone(), Some(stale_v2));
        // now_ms BEHIND the stored epoch: the bump must still strictly increase.
        let healed = heal_actor_attestations(&mut vault, &signer, 3)
            .await
            .unwrap();

        assert!(healed);
        assert_eq!(vault.ml_dsa_attestation, v1, "valid v1 must be untouched");
        let v2 = vault.ml_dsa_attestation_v2.as_ref().unwrap();
        assert_eq!(v2.hint_epoch_ms, 6);
        assert_eq!(v2.profile_addr, profile_addr);
        assert_eq!(v2.relay_hint, relay_hint);
        let derived =
            fetchit_fedi::attestation::verify_binding_v2("josh", &actor_url, &[7, 7], v2).unwrap();
        assert_eq!(derived, agent_hex);
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
