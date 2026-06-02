//! ML-KEM-768 + ChaCha20-Poly1305 + HKDF crypto helpers for the chat
//! layer. Pure functions over byte slices; all key material is supplied
//! by the caller. No I/O, no shared state, no global RNG handle — call
//! sites pass their own RNG when randomness is needed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use saorsa_pqc::api::sig::MlDsaVariant;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature};
use sha2::Sha256;

use crate::error::ChatError;

/// Length of a ChaCha20-Poly1305 symmetric key in bytes.
pub const AEAD_KEY_LEN: usize = 32;
/// Length of a ChaCha20-Poly1305 nonce in bytes.
pub const AEAD_NONCE_LEN: usize = 12;
/// Length of an ML-KEM-768 shared secret in bytes.
pub const KEM_SHARED_SECRET_LEN: usize = 32;
/// Length of an ML-KEM-768 public key in bytes.
pub const KEM_PUBLIC_KEY_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext in bytes.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
/// Length of an ML-KEM-768 secret key in bytes.
pub const KEM_SECRET_KEY_LEN: usize = 2400;

/// Domain prefix for AEAD AAD over chat envelopes. Bumps if the wire
/// format changes — invalidates all v1 ciphertexts.
pub const AAD_DOMAIN: &[u8] = b"lit/v1";

/// Domain string for HKDF when deriving the welcome AEAD key from a
/// fresh KEM shared secret.
pub const KDF_INFO_WELCOME: &[u8] = b"lit/welcome/v1";

/// Domain string for HKDF when deriving the master key from a
/// passphrase via Argon2id (used by `at_rest` module; defined here for
/// the single source of truth).
pub const KDF_INFO_VAULT: &[u8] = b"lit/vault/v1";

/// Domain string for ML-DSA signing canonical envelope bytes.
pub const SIGN_DOMAIN_ENVELOPE: &[u8] = b"lit/envelope/v1";

/// Domain string for ML-DSA signing extended share-cards.
pub const SIGN_DOMAIN_CARD: &[u8] = b"fetchit-chat/v1/card";

/// Domain string for ML-DSA channel-binding signatures exchanged inside
/// the LAN-direct Noise XX handshake. Binds the X25519 static to the
/// `agent_id`; verifier reconstructs these bytes (plus the handshake
/// hash) before calling [`ml_dsa_verify`].
pub const SIGN_DOMAIN_LAN_NOISE: &[u8] = b"fetchit/lan-noise/v1";

/// Canonical bytes for the LAN-Noise channel-binding signature.
///
/// Layout:
/// ```text
/// SIGN_DOMAIN_LAN_NOISE
/// || version_byte
/// || agent_id (32)
/// || x25519_static_pub (32)
/// || created_at_ms (u64 BE)
/// ```
///
/// The signer commits to *these* bytes concatenated with the live Noise
/// handshake hash (so a relay or MITM that re-runs the handshake against
/// a different peer changes the hash and the signature fails to verify).
/// `version_byte = 1` for the v1 binding.
#[must_use]
pub fn lan_binding_bytes(
    agent_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    created_at_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGN_DOMAIN_LAN_NOISE.len() + 1 + 32 + 32 + 8);
    out.extend_from_slice(SIGN_DOMAIN_LAN_NOISE);
    out.push(1);
    out.extend_from_slice(agent_id);
    out.extend_from_slice(x25519_pub);
    out.extend_from_slice(&created_at_ms.to_be_bytes());
    out
}

// ── KEM ────────────────────────────────────────────────────────────────

/// Encapsulate a fresh symmetric secret against `recipient_kem_pub`.
/// Returns the KEM ciphertext (1088 B) and the 32-byte shared secret.
///
/// # Errors
/// Returns `ChatError::Invalid` for malformed inputs.
pub fn kem_encapsulate(
    recipient_kem_pub: &[u8],
) -> Result<(Vec<u8>, [u8; KEM_SHARED_SECRET_LEN]), ChatError> {
    use saorsa_pqc::api::kem::{MlKem, MlKemPublicKey, MlKemVariant};
    if recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN {
        return Err(ChatError::Invalid(format!(
            "kem pub key wrong length: {}",
            recipient_kem_pub.len()
        )));
    }
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let pk = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, recipient_kem_pub)
        .map_err(|e| ChatError::Invalid(format!("kem pub parse: {e}")))?;
    let (ss, ct) = kem
        .encapsulate(&pk)
        .map_err(|e| ChatError::Invalid(format!("kem encap: {e}")))?;
    let ct_bytes = ct.to_bytes();
    let ss_arr = ss.to_bytes();
    Ok((ct_bytes, ss_arr))
}

/// Decapsulate a KEM ciphertext with our secret key.
///
/// # Errors
/// Returns `ChatError::Invalid` if either input is malformed or decap fails.
pub fn kem_decapsulate(
    our_kem_sec: &[u8],
    kem_ciphertext: &[u8],
) -> Result<[u8; KEM_SHARED_SECRET_LEN], ChatError> {
    use saorsa_pqc::api::kem::{MlKem, MlKemCiphertext, MlKemSecretKey, MlKemVariant};
    if our_kem_sec.len() != KEM_SECRET_KEY_LEN {
        return Err(ChatError::Invalid("kem secret key wrong length".into()));
    }
    if kem_ciphertext.len() != KEM_CIPHERTEXT_LEN {
        return Err(ChatError::Invalid("kem ciphertext wrong length".into()));
    }
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let sk = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, our_kem_sec)
        .map_err(|e| ChatError::Invalid(format!("kem sec parse: {e}")))?;
    let ct = MlKemCiphertext::from_bytes(MlKemVariant::MlKem768, kem_ciphertext)
        .map_err(|e| ChatError::Invalid(format!("kem ct parse: {e}")))?;
    let ss = kem
        .decapsulate(&sk, &ct)
        .map_err(|e| ChatError::Invalid(format!("kem decap: {e}")))?;
    Ok(ss.to_bytes())
}

/// Generate a fresh ML-KEM-768 keypair. Returns `(public_key_bytes, secret_key_bytes)`.
///
/// # Errors
/// Returns `ChatError::Invalid` if the underlying primitive fails.
pub fn kem_keygen() -> Result<(Vec<u8>, Vec<u8>), ChatError> {
    use saorsa_pqc::api::kem::{MlKem, MlKemVariant};
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let (pk, sk) = kem
        .generate_keypair()
        .map_err(|e| ChatError::Invalid(format!("kem keygen: {e}")))?;
    Ok((pk.to_bytes(), sk.to_bytes()))
}

// ── HKDF ───────────────────────────────────────────────────────────────

/// Derive a 32-byte symmetric key from a KEM shared secret using
/// HKDF-SHA-256 with the supplied info string.
#[must_use]
#[allow(clippy::expect_used)]
pub fn derive_aead_key(shared_secret: &[u8], info: &[u8]) -> [u8; AEAD_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; AEAD_KEY_LEN];
    hk.expand(info, &mut out)
        .expect("HKDF expand cannot fail for 32-byte output");
    out
}

// ── AEAD ───────────────────────────────────────────────────────────────

/// Seal `plaintext` under `key` with `nonce` and `aad`.
///
/// # Errors
/// Returns `ChatError::Invalid` on key length mismatch or AEAD failure.
pub fn aead_seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ChatError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| ChatError::Invalid(format!("aead seal: {e}")))
}

/// Open `ciphertext` under `key` with `nonce` and `aad`. Returns the plaintext.
///
/// # Errors
/// Returns `ChatError::Invalid` on tag mismatch or any AEAD error
/// (deliberately not distinguished — tag-mismatch == tampering).
pub fn aead_open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ChatError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| ChatError::Invalid(format!("aead open: {e}")))
}

/// Random 12-byte AEAD nonce.
#[must_use]
pub fn random_nonce(rng: &mut impl RngCore) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut n);
    n
}

/// Random 32-byte symmetric key (used for `Conversation.current_key`).
#[must_use]
pub fn random_symmetric_key(rng: &mut impl RngCore) -> [u8; AEAD_KEY_LEN] {
    let mut k = [0u8; AEAD_KEY_LEN];
    rng.fill_bytes(&mut k);
    k
}

// ── AAD construction ───────────────────────────────────────────────────

/// Canonical AAD for a message ciphertext bound to a conversation + epoch.
/// `concat(AAD_DOMAIN, group_id, epoch.to_be_bytes())`.
/// epoch is encoded big-endian to match other wire-signed integers.
#[must_use]
pub fn message_aad(group_id: &[u8; 32], epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 32 + 4);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

// ── Envelope canonicalisation ──────────────────────────────────────────

/// Canonical bytes for signing/verifying a `TransitEnvelope`'s
/// `sender_signature`. Postcard-encoded with the signature field zeroed
/// (length-preserved as Vec<u8> of length 0) so signer and verifier
/// agree on the exact byte sequence.
///
/// # Errors
/// Returns `ChatError::Invalid` if postcard encoding fails.
pub fn canonical_envelope_bytes(
    env: &fetchit_relay_proto::TransitEnvelope,
) -> Result<Vec<u8>, ChatError> {
    let mut clone = env.clone();
    clone.sender_signature = Vec::new();
    postcard::to_allocvec(&clone).map_err(|e| ChatError::Invalid(format!("postcard: {e}")))
}

// ── ML-DSA verify helpers (signing handled by X0xdSigner already) ─────

/// Verify an ML-DSA-65 signature over `message` using `public_key_bytes`.
///
/// # Errors
/// Returns `ChatError::Invalid` if the key or signature is malformed or
/// the signature fails verification.
pub fn ml_dsa_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), ChatError> {
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, public_key_bytes)
        .map_err(|e| ChatError::Invalid(format!("ml-dsa pub parse: {e}")))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, signature_bytes)
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sig parse: {e}")))?;
    match dsa.verify(&pk, message, &sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ChatError::Invalid("ml-dsa signature invalid".into())),
        Err(e) => Err(ChatError::Invalid(format!("ml-dsa verify: {e}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn kem_round_trip() {
        let (pk, sk) = kem_keygen().unwrap();
        let (ct, ss_a) = kem_encapsulate(&pk).unwrap();
        let ss_b = kem_decapsulate(&sk, &ct).unwrap();
        assert_eq!(
            ss_a, ss_b,
            "encap/decap must produce the same shared secret"
        );
    }

    #[test]
    fn aead_round_trip_with_aad() {
        let mut rng = OsRng;
        let key = random_symmetric_key(&mut rng);
        let nonce = random_nonce(&mut rng);
        let aad = message_aad(&[7u8; 32], 5);
        let pt = b"hello relay";
        let ct = aead_seal(&key, &nonce, pt, &aad).unwrap();
        let opened = aead_open(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn aead_rejects_wrong_aad() {
        let mut rng = OsRng;
        let key = random_symmetric_key(&mut rng);
        let nonce = random_nonce(&mut rng);
        let aad_a = message_aad(&[1u8; 32], 0);
        let aad_b = message_aad(&[2u8; 32], 0);
        let ct = aead_seal(&key, &nonce, b"x", &aad_a).unwrap();
        assert!(aead_open(&key, &nonce, &ct, &aad_b).is_err());
    }

    #[test]
    fn hkdf_deterministic() {
        let ss = [9u8; KEM_SHARED_SECRET_LEN];
        let k1 = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let k2 = derive_aead_key(&ss, KDF_INFO_WELCOME);
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_domain_separation() {
        let ss = [9u8; KEM_SHARED_SECRET_LEN];
        let kw = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let kv = derive_aead_key(&ss, KDF_INFO_VAULT);
        assert_ne!(kw, kv, "different info strings must produce different keys");
    }

    #[test]
    fn message_aad_includes_group_id_and_epoch() {
        let g = [0u8; 32];
        let aad0 = message_aad(&g, 0);
        let aad1 = message_aad(&g, 1);
        assert_ne!(aad0, aad1);
        let g2 = [1u8; 32];
        let aad0_g2 = message_aad(&g2, 0);
        assert_ne!(aad0, aad0_g2);
    }

    #[test]
    fn message_aad_epoch_layout() {
        let epoch: u32 = 0x0123_4567;
        let aad = message_aad(&[0u8; 32], epoch);
        assert_eq!(
            &aad[aad.len() - 4..],
            &epoch.to_be_bytes(),
            "epoch must occupy the final 4 bytes in big-endian order"
        );
    }

    #[test]
    fn lan_binding_bytes_layout() {
        let agent_id = [0xaa; 32];
        let x25519_pub = [0x55; 32];
        let ts: u64 = 0x0123_4567_89ab_cdef;
        let bytes = lan_binding_bytes(&agent_id, &x25519_pub, ts);
        let mut want = Vec::new();
        want.extend_from_slice(SIGN_DOMAIN_LAN_NOISE);
        want.push(1);
        want.extend_from_slice(&agent_id);
        want.extend_from_slice(&x25519_pub);
        want.extend_from_slice(&ts.to_be_bytes());
        assert_eq!(bytes, want);
    }

    #[tokio::test]
    async fn lan_binding_sign_and_verify_roundtrip() {
        use fetchit_relay_client::{MlDsaSigner, Signer};
        let signer = MlDsaSigner::generate().unwrap();
        let agent_id = [0x11; 32];
        let x25519_pub = [0x22; 32];
        let bytes = lan_binding_bytes(&agent_id, &x25519_pub, 1_700_000_000_000);
        let sig = signer.sign(&bytes).await.unwrap();
        ml_dsa_verify(&signer.public_key(), &bytes, &sig).unwrap();
    }

    #[tokio::test]
    async fn lan_binding_tamper_fails_verify() {
        use fetchit_relay_client::{MlDsaSigner, Signer};
        let signer = MlDsaSigner::generate().unwrap();
        let agent_id = [0x11; 32];
        let x25519_pub = [0x22; 32];
        let bytes = lan_binding_bytes(&agent_id, &x25519_pub, 1_700_000_000_000);
        let sig = signer.sign(&bytes).await.unwrap();
        let mut tampered = bytes.clone();
        tampered[SIGN_DOMAIN_LAN_NOISE.len() + 1 + 16] ^= 1;
        assert!(ml_dsa_verify(&signer.public_key(), &tampered, &sig).is_err());
    }

    #[tokio::test]
    async fn lan_binding_wrong_domain_fails_verify() {
        use fetchit_relay_client::{MlDsaSigner, Signer};
        let signer = MlDsaSigner::generate().unwrap();
        let agent_id = [0x33; 32];
        let x25519_pub = [0x44; 32];
        let bytes = lan_binding_bytes(&agent_id, &x25519_pub, 0);
        let sig = signer.sign(&bytes).await.unwrap();
        // Swap the LAN domain for the envelope domain — same shape, but a
        // signature over the LAN binding must not validate as an envelope.
        let mut wrong_domain = Vec::new();
        wrong_domain.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
        wrong_domain.extend_from_slice(&bytes[SIGN_DOMAIN_LAN_NOISE.len()..]);
        assert!(ml_dsa_verify(&signer.public_key(), &wrong_domain, &sig).is_err());
    }

    #[test]
    fn canonical_envelope_zeroes_signature() {
        use fetchit_relay_proto::{AgentId, EnvelopeKind, MachineId, TransitEnvelope};
        let env_a = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1u8; 32]),
            sender_machine_id: MachineId::from_bytes([2u8; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![1, 2, 3],
            nonce: vec![0; 12],
            kem_ciphertext: vec![],
            sender_signature: vec![0xff; 32],
        };
        let mut env_b = env_a.clone();
        env_b.sender_signature = vec![0xee; 32];
        assert_eq!(
            canonical_envelope_bytes(&env_a).unwrap(),
            canonical_envelope_bytes(&env_b).unwrap(),
            "canonical bytes must be insensitive to sender_signature"
        );
    }
}
