//! ML-DSA-65 attestation binding a fetch>it Actor's RSA-2048 pubkey to
//! its chat-identity ML-DSA key.
//!
//! Per plan decision `[III]`, the per-POST ML-DSA cosignature was dropped
//! and the Actor JSON-LD attestation is the **authoritative PQ
//! binding**. This module owns the canonical signing-input byte format
//! that both the chat-side signer and any verifier (fetch>it node or
//! third-party PQ-aware bridge) must agree on, byte-for-byte.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for the attestation signing input. Prefixed to the
/// canonical bytes so a signature over this input cannot be confused
/// with a signature over any other fetch>it artifact.
///
/// **Frozen.** Bridge-side verifiers depend on this exact byte string;
/// changing it is a v2 migration, not a patch.
pub const DOMAIN_SEPARATOR: &[u8] = b"fetchit-fedi-actor-attestation-v1";

/// ML-DSA-65 attestation: the pubkey that produced the signature plus
/// the signature itself.
///
/// The signed bytes are produced by [`signing_input`] from the same
/// `(handle, actor_url, agent_id_hex, rsa_pubkey_der)` tuple that the
/// chat-side `mint_actor_identity` builds.
///
/// # Wire representation
///
/// In-memory the byte fields are raw `Vec<u8>`. When serialised (to
/// the on-disk fedi vault or to the Actor JSON-LD `publicKey`
/// extension), both fields are emitted as base64 strings via the
/// `b64` serde-with helper — one canonical encoding everywhere the
/// attestation crosses a wire or a disk boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsaAttestation {
    /// ML-DSA-65 public key bytes (raw, not encoded). The chat-identity
    /// pubkey under which the signature verifies.
    #[serde(with = "b64")]
    pub ml_dsa_pubkey: Vec<u8>,
    /// ML-DSA-65 signature over [`signing_input`] of the actor fields.
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

/// Serde-with helper that encodes `Vec<u8>` as base64 strings on the
/// wire (and at rest) while keeping the in-memory type as raw bytes.
///
/// Uses the standard alphabet padded
/// `base64::engine::general_purpose::STANDARD` so the JSON shape stays
/// portable across any base64 consumer (including future JSON-LD
/// verifiers). The `+/` alphabet matches `ActivityPub` HTTP-Signatures
/// + Mastodon `publicKeyPem` conventions.
pub(crate) mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

impl MlDsaAttestation {
    /// Pure-data constructor.
    #[must_use]
    pub fn new(ml_dsa_pubkey: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            ml_dsa_pubkey,
            signature,
        }
    }
}

/// Domain separator for the v2 attestation signing input. v2 extends
/// the attested tuple with the profile address and relay hint so a
/// verified actor record is sufficient to bootstrap a private contact.
///
/// **Frozen.** Same rule as [`DOMAIN_SEPARATOR`]: changing it is a v3
/// migration, not a patch.
pub const DOMAIN_SEPARATOR_V2: &[u8] = b"fetchit-fedi-actor-attestation-v2";

/// Hard cap on `relay_hint` byte length. Mirrors
/// `fetchit-chat::card::MAX_HINT_URL_LEN` (this crate sits below
/// fetchit-chat in the dependency graph, so the value is restated).
pub const MAX_RELAY_HINT_LEN: usize = 256;

/// v2 actor attestation: the signed binding now also covers the
/// Autonomi profile address and a relay hint, making the record a
/// self-contained pointer for the v3 share-URI bootstrap.
///
/// Wire shape: JSON with base64 byte fields (same `b64` helper as
/// v1) plus an explicit integer `version` so consumers dispatch
/// without sniffing fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorAttestationV2 {
    /// Always `2`. [`verify_binding_v2`] rejects anything else.
    pub version: u8,
    /// Autonomi address of the actor's profile manifest, lowercase 64-hex.
    pub profile_addr: String,
    /// Relay URL serving the actor's profile-index record. Bounded by
    /// [`MAX_RELAY_HINT_LEN`]; URL well-formedness is the consumer's
    /// check (it fails closed to the public-only rendering).
    pub relay_hint: String,
    /// Freshness stamp. Same monotonicity semantics as card v2
    /// rendezvous hints: registries and clients reject updates whose
    /// epoch does not strictly increase.
    pub hint_epoch_ms: u64,
    /// ML-DSA-65 public key bytes (raw).
    #[serde(with = "b64")]
    pub ml_dsa_pubkey: Vec<u8>,
    /// ML-DSA-65 signature over [`signing_input_v2`].
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

/// Canonical signing-input bytes for an Actor attestation.
///
/// Layout:
/// ```text
/// DOMAIN_SEPARATOR
/// || u32_be(len(handle))         || handle.as_bytes()
/// || u32_be(len(actor_url))      || actor_url.as_bytes()
/// || u32_be(len(agent_id_hex))   || agent_id_hex.as_bytes()
/// || u32_be(len(rsa_pubkey_der)) || rsa_pubkey_der
/// ```
///
/// Length prefixes prevent canonicalization ambiguity when adjacent
/// fields contain bytes that could be misinterpreted as separators.
/// `actor_url` is rendered via [`url::Url::as_str`] so its serialisation
/// is fixed by the `url` crate's normalisation, not by the caller.
///
/// # Field constraints (locked wire format)
///
/// These are part of the wire format, not implementation details. A
/// verifier reconstructing the signing input from an `Actor` JSON-LD
/// document MUST receive the same bytes; otherwise signatures look
/// invalid for entirely benign-looking encoding differences.
///
/// - **`handle`** — non-empty UTF-8. Returns
///   [`SigningInputError::EmptyHandle`] otherwise.
/// - **`actor_url`** — its `Url::as_str()` rendering. The pinned `url`
///   crate version is therefore part of the wire format; bumping `url`
///   is a v2 migration.
/// - **`agent_id_hex`** — lowercase 64-hex (chars `0..=9` and `a..=f`,
///   exactly 64 bytes). Returns
///   [`SigningInputError::InvalidAgentIdHex`] otherwise. The chat-side
///   `mint_actor_identity` derives this from
///   `FetchitIdentity::agent_id_hex()`, which already returns the
///   canonical form.
/// - **`rsa_pubkey_der`** — `SubjectPublicKeyInfo` DER (NOT PKCS#1
///   `RSAPublicKey`). A verifier reconstructing the signing input from
///   the `Actor`'s `publicKey.publicKeyPem` PEM-decodes that field to
///   SPKI DER and feeds it here; signing over PKCS#1 instead would
///   produce different bytes and break verification.
/// - **Field length** — each field's byte length must fit in `u32`.
///   Returns [`SigningInputError::FieldTooLong`] otherwise (practically
///   unreachable; multi-gigabyte input).
pub fn signing_input(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    rsa_pubkey_der: &[u8],
) -> Result<Vec<u8>, SigningInputError> {
    if handle.is_empty() {
        return Err(SigningInputError::EmptyHandle);
    }
    if !is_lowercase_64_hex(agent_id_hex) {
        return Err(SigningInputError::InvalidAgentIdHex {
            len: agent_id_hex.len(),
        });
    }

    let actor_url_str = actor_url.as_str();
    let total = DOMAIN_SEPARATOR
        .len()
        .saturating_add(4 + handle.len())
        .saturating_add(4 + actor_url_str.len())
        .saturating_add(4 + agent_id_hex.len())
        .saturating_add(4 + rsa_pubkey_der.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(DOMAIN_SEPARATOR);
    push_lp(&mut out, handle.as_bytes())?;
    push_lp(&mut out, actor_url_str.as_bytes())?;
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    push_lp(&mut out, rsa_pubkey_der)?;
    Ok(out)
}

fn is_lowercase_64_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SigningInputError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| SigningInputError::FieldTooLong { len: bytes.len() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Canonical signing-input bytes for a v2 attestation.
///
/// Layout:
/// ```text
/// DOMAIN_SEPARATOR_V2
/// || u32_be(len(handle))         || handle
/// || u32_be(len(actor_url))      || actor_url
/// || u32_be(len(agent_id_hex))   || agent_id_hex
/// || u32_be(len(rsa_pubkey_der)) || rsa_pubkey_der
/// || u32_be(len(profile_addr))   || profile_addr
/// || u32_be(len(relay_hint))     || relay_hint
/// || u64_be(hint_epoch_ms)
/// ```
///
/// The first four fields carry the same constraints as
/// [`signing_input`] (they are the same wire format, restated under
/// the v2 domain separator). `profile_addr` must be lowercase 64-hex.
/// `relay_hint` must be non-empty and at most [`MAX_RELAY_HINT_LEN`]
/// bytes. `hint_epoch_ms` is fixed-width 8-byte big-endian, no length
/// prefix.
///
/// # Errors
/// A [`SigningInputError`] variant on any field-constraint violation.
pub fn signing_input_v2(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    rsa_pubkey_der: &[u8],
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
) -> Result<Vec<u8>, SigningInputError> {
    if handle.is_empty() {
        return Err(SigningInputError::EmptyHandle);
    }
    if !is_lowercase_64_hex(agent_id_hex) {
        return Err(SigningInputError::InvalidAgentIdHex {
            len: agent_id_hex.len(),
        });
    }
    if !is_lowercase_64_hex(profile_addr) {
        return Err(SigningInputError::InvalidProfileAddr {
            len: profile_addr.len(),
        });
    }
    if relay_hint.is_empty() || relay_hint.len() > MAX_RELAY_HINT_LEN {
        return Err(SigningInputError::InvalidRelayHint {
            len: relay_hint.len(),
        });
    }

    let actor_url_str = actor_url.as_str();
    let total = DOMAIN_SEPARATOR_V2
        .len()
        .saturating_add(4 + handle.len())
        .saturating_add(4 + actor_url_str.len())
        .saturating_add(4 + agent_id_hex.len())
        .saturating_add(4 + rsa_pubkey_der.len())
        .saturating_add(4 + profile_addr.len())
        .saturating_add(4 + relay_hint.len())
        .saturating_add(8);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(DOMAIN_SEPARATOR_V2);
    push_lp(&mut out, handle.as_bytes())?;
    push_lp(&mut out, actor_url_str.as_bytes())?;
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    push_lp(&mut out, rsa_pubkey_der)?;
    push_lp(&mut out, profile_addr.as_bytes())?;
    push_lp(&mut out, relay_hint.as_bytes())?;
    out.extend_from_slice(&hint_epoch_ms.to_be_bytes());
    Ok(out)
}

/// Errors from constructing the canonical signing input.
#[derive(Debug, Error)]
pub enum SigningInputError {
    /// A field's byte length exceeds `u32::MAX` and so cannot fit in the
    /// length prefix.
    #[error("attestation field length {len} exceeds u32::MAX")]
    FieldTooLong {
        /// Offending field length in bytes.
        len: usize,
    },
    /// `handle` was empty. Empty handles silently produce a structurally
    /// valid attestation that no real actor can match — almost always a
    /// caller bug.
    #[error("attestation handle must be non-empty")]
    EmptyHandle,
    /// `agent_id_hex` was not lowercase 64-hex. Verifiers reconstruct
    /// this field exactly; passing uppercase, mixed-case, `0x`-prefixed,
    /// or wrong-length input silently breaks signature verification.
    #[error("attestation agent_id_hex must be lowercase 64-hex (got len {len})")]
    InvalidAgentIdHex {
        /// Length of the offending input in bytes.
        len: usize,
    },
    /// `profile_addr` was not lowercase 64-hex (v2 only).
    #[error("attestation profile_addr must be lowercase 64-hex (got len {len})")]
    InvalidProfileAddr {
        /// Length of the offending input in bytes.
        len: usize,
    },
    /// `relay_hint` was empty or exceeded [`MAX_RELAY_HINT_LEN`] (v2 only).
    #[error("attestation relay_hint must be 1..=256 bytes (got {len})")]
    InvalidRelayHint {
        /// Length of the offending input in bytes.
        len: usize,
    },
}

/// Errors from [`verify_binding`]. Any variant means the actor MUST
/// NOT be treated as bound to a chat identity.
#[derive(Debug, Error)]
pub enum AttestationVerifyError {
    /// Reconstructing the canonical signing input failed (empty
    /// handle, oversized field). The derived agent id is well-formed
    /// by construction, so this points at the actor fields.
    #[error("attestation signing-input: {0}")]
    SigningInput(#[from] SigningInputError),
    /// `ml_dsa_pubkey` is not a valid ML-DSA-65 public key.
    #[error("attestation ml_dsa_pubkey rejected: {0}")]
    PubkeyParse(String),
    /// `signature` is not a structurally valid ML-DSA-65 signature.
    #[error("attestation signature rejected: {0}")]
    SignatureParse(String),
    /// The ML-DSA backend errored while verifying.
    #[error("attestation ML-DSA verify errored: {0}")]
    VerifyBackend(String),
    /// The signature does not verify over the reconstructed input
    /// under the attested public key.
    #[error("attestation signature does not verify under the attested key")]
    SignatureInvalid,
    /// The attestation's `version` field is not the expected `2`
    /// (v2 only).
    #[error("attestation version {got} where 2 expected")]
    WrongVersion {
        /// The version value found on the wire.
        got: u8,
    },
}

/// Cryptographically verify an attestation against the actor fields it
/// claims to bind, returning the **derived** chat `agent_id_hex`.
///
/// The agent id is never read from a claim: it is derived from the
/// attested ML-DSA-65 pubkey via [`fetchit_relay_proto::derive_agent_id`]
/// (`SHA-256("AUTONOMI_PEER_ID_V2:" || pubkey)`, the rule x0x applies to
/// every agent identity; upstream
/// `ant_quic::derive_peer_id_from_public_key`). The canonical
/// [`signing_input`] is then reconstructed from
/// `(handle, actor_url, derived_hex, spki_der)` and the ML-DSA-65
/// signature checked under the attested pubkey.
///
/// Deriving instead of trusting a claimed id is what makes the binding
/// unforgeable: a signer who embeds someone else's agent id produces an
/// input that no longer matches what this function reconstructs from
/// their own pubkey, so the signature rejects. Conversely, a valid
/// result proves the holder of the ML-DSA key that *hashes to* the
/// returned agent id signed exactly this `(handle, actor_url, RSA key)`
/// tuple.
///
/// # Errors
///
/// See [`AttestationVerifyError`].
pub fn verify_binding(
    handle: &str,
    actor_url: &url::Url,
    spki_der: &[u8],
    attestation: &MlDsaAttestation,
) -> Result<String, AttestationVerifyError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(
        &attestation.ml_dsa_pubkey,
    ));
    let input = signing_input(handle, actor_url, &derived, spki_der)?;
    // Attestation is signed through the agent `Signer`: verify over the
    // external-agent-sign framing.
    let input = fetchit_relay_proto::agent_sign_input(&input);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &attestation.ml_dsa_pubkey)
        .map_err(|e| AttestationVerifyError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &attestation.signature)
        .map_err(|e| AttestationVerifyError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| AttestationVerifyError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(AttestationVerifyError::SignatureInvalid);
    }
    Ok(derived)
}

/// Cryptographically verify a v2 attestation against the actor fields
/// it claims to bind, returning the **derived** chat `agent_id_hex`.
///
/// Identical derive-then-verify construction to [`verify_binding`];
/// the reconstructed input additionally covers the attestation's own
/// `profile_addr`, `relay_hint`, and `hint_epoch_ms` fields, so
/// tampering with any of them invalidates the signature.
///
/// # Errors
///
/// Any [`AttestationVerifyError`] means the actor MUST NOT be treated
/// as bound to a chat identity (callers fail closed to public-only).
pub fn verify_binding_v2(
    handle: &str,
    actor_url: &url::Url,
    spki_der: &[u8],
    attestation: &ActorAttestationV2,
) -> Result<String, AttestationVerifyError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    if attestation.version != 2 {
        return Err(AttestationVerifyError::WrongVersion {
            got: attestation.version,
        });
    }
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(
        &attestation.ml_dsa_pubkey,
    ));
    let input = signing_input_v2(
        handle,
        actor_url,
        &derived,
        spki_der,
        &attestation.profile_addr,
        &attestation.relay_hint,
        attestation.hint_epoch_ms,
    )?;
    // Attestation is signed through the agent `Signer`: verify over the
    // external-agent-sign framing.
    let input = fetchit_relay_proto::agent_sign_input(&input);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &attestation.ml_dsa_pubkey)
        .map_err(|e| AttestationVerifyError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &attestation.signature)
        .map_err(|e| AttestationVerifyError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| AttestationVerifyError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(AttestationVerifyError::SignatureInvalid);
    }
    Ok(derived)
}

/// Test-only factory: mint a real ML-DSA-65 keypair, derive the agent
/// id from the pubkey, and sign the canonical input. Returns the
/// attestation plus the derived lowercase `agent_id_hex`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn test_attested(
    handle: &str,
    actor_url: &url::Url,
    spki_der: &[u8],
) -> (MlDsaAttestation, String) {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(&pk.to_bytes()));
    let input = signing_input(handle, actor_url, &derived, spki_der).unwrap();
    let sig = dsa
        .sign(&sk, &fetchit_relay_proto::agent_sign_input(&input))
        .unwrap()
        .to_bytes();
    (MlDsaAttestation::new(pk.to_bytes(), sig), derived)
}

/// Test-only factory for v2: mint a real ML-DSA-65 keypair, derive the
/// agent id from the pubkey, and sign the canonical v2 input. Returns
/// the attestation plus the derived lowercase `agent_id_hex`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn test_attested_v2(
    handle: &str,
    actor_url: &url::Url,
    spki_der: &[u8],
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
) -> (ActorAttestationV2, String) {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(&pk.to_bytes()));
    let input = signing_input_v2(
        handle,
        actor_url,
        &derived,
        spki_der,
        profile_addr,
        relay_hint,
        hint_epoch_ms,
    )
    .unwrap();
    let sig = dsa
        .sign(&sk, &fetchit_relay_proto::agent_sign_input(&input))
        .unwrap()
        .to_bytes();
    (
        ActorAttestationV2 {
            version: 2,
            profile_addr: profile_addr.to_string(),
            relay_hint: relay_hint.to_string(),
            hint_epoch_ms,
            ml_dsa_pubkey: pk.to_bytes(),
            signature: sig,
        },
        derived,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    const VALID_AGENT_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_AGENT_HEX: &str =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn domain_separator_is_frozen() {
        assert_eq!(DOMAIN_SEPARATOR, b"fetchit-fedi-actor-attestation-v1");
    }

    #[test]
    fn signing_input_layout_is_canonical() {
        let bytes = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_SEPARATOR);
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"josh");
        expected.extend_from_slice(&29u32.to_be_bytes());
        expected.extend_from_slice(b"https://etchit.io/actors/josh");
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(VALID_AGENT_HEX.as_bytes());
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(bytes, expected);
    }

    #[test]
    fn signing_input_differs_when_any_field_changes() {
        let base = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[0x01],
        )
        .unwrap();

        let other_handle = signing_input(
            "alice",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[0x01],
        )
        .unwrap();
        let other_url = signing_input(
            "josh",
            &url("https://etchit.io/actors/alice"),
            VALID_AGENT_HEX,
            &[0x01],
        )
        .unwrap();
        let other_agent = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            OTHER_AGENT_HEX,
            &[0x01],
        )
        .unwrap();
        let other_key = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[0x02],
        )
        .unwrap();

        assert_ne!(base, other_handle);
        assert_ne!(base, other_url);
        assert_ne!(base, other_agent);
        assert_ne!(base, other_key);
    }

    #[test]
    fn signing_input_rejects_empty_handle() {
        let err = signing_input(
            "",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[0x01],
        )
        .unwrap_err();
        assert!(matches!(err, SigningInputError::EmptyHandle));
    }

    #[test]
    fn signing_input_rejects_short_agent_id_hex() {
        let err = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            "deadbeef",
            &[0x01],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SigningInputError::InvalidAgentIdHex { len: 8 }
        ));
    }

    #[test]
    fn signing_input_rejects_uppercase_agent_id_hex() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(upper.len(), 64);
        let err = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            upper,
            &[0x01],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SigningInputError::InvalidAgentIdHex { len: 64 }
        ));
    }

    #[test]
    fn signing_input_rejects_non_hex_agent_id() {
        let bad = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeG";
        assert_eq!(bad.len(), 64);
        let err =
            signing_input("josh", &url("https://etchit.io/actors/josh"), bad, &[0x01]).unwrap_err();
        assert!(matches!(
            err,
            SigningInputError::InvalidAgentIdHex { len: 64 }
        ));
    }

    #[test]
    fn attestation_constructor_holds_bytes_verbatim() {
        let pk = vec![1, 2, 3];
        let sig = vec![4, 5, 6, 7];
        let att = MlDsaAttestation::new(pk.clone(), sig.clone());
        assert_eq!(att.ml_dsa_pubkey, pk);
        assert_eq!(att.signature, sig);
    }

    #[test]
    fn attestation_serializes_byte_fields_as_base64_strings() {
        // FROZEN wire shape. Vault files + JSON-LD `publicKey`
        // extensions both rely on this exact encoding.
        let att = MlDsaAttestation::new(vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0x01, 0x02, 0x03]);
        let json = serde_json::to_string(&att).unwrap();
        assert_eq!(json, r#"{"ml_dsa_pubkey":"3q2+7w==","signature":"AQID"}"#);
    }

    #[test]
    fn attestation_round_trips_through_json() {
        let att = MlDsaAttestation::new(vec![0x11; 32], vec![0x22; 64]);
        let json = serde_json::to_string(&att).unwrap();
        let recovered: MlDsaAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, att);
    }

    #[test]
    fn attestation_rejects_invalid_base64_on_deserialize() {
        // Garbage in the byte fields should produce a parser error,
        // not a corrupt attestation.
        let bad = r#"{"ml_dsa_pubkey":"!!!not-valid-b64!!!","signature":"AQID"}"#;
        let result: Result<MlDsaAttestation, _> = serde_json::from_str(bad);
        assert!(result.is_err());
    }

    #[test]
    fn verify_binding_round_trips_with_real_keys() {
        let u = url("https://etchit.io/actors/josh");
        let der = [0xAA_u8; 16];
        let (att, derived) = test_attested("josh", &u, &der);
        let got = verify_binding("josh", &u, &der, &att).unwrap();
        assert_eq!(got, derived);
    }

    #[test]
    fn verify_binding_rejects_signature_from_a_different_key() {
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
        let u = url("https://etchit.io/actors/josh");
        let der = [0xAA_u8; 16];
        let (att, _) = test_attested("josh", &u, &der);
        // Swap in a different keypair's pubkey: the derived id changes
        // and the signature cannot verify under the substituted key.
        let (other_pk, _) = MlDsa::new(MlDsaVariant::MlDsa65)
            .generate_keypair()
            .unwrap();
        let forged = MlDsaAttestation::new(other_pk.to_bytes(), att.signature);
        let err = verify_binding("josh", &u, &der, &forged).unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_binding_rejects_tampered_handle() {
        let u = url("https://etchit.io/actors/josh");
        let der = [0xAA_u8; 16];
        let (att, _) = test_attested("josh", &u, &der);
        let err = verify_binding("alice", &u, &der, &att).unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_binding_rejects_garbage_pubkey() {
        let u = url("https://etchit.io/actors/josh");
        let att = MlDsaAttestation::new(vec![1, 2, 3], vec![0; 8]);
        let err = verify_binding("josh", &u, &[0x01], &att).unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::PubkeyParse(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_binding_rejects_forged_agent_id_claim() {
        // The attack the derive step exists to kill: sign the canonical
        // input carrying SOMEONE ELSE's agent id under your own key.
        // The verifier derives the id from the attested pubkey instead
        // of trusting a claim, reconstructs a different input, and the
        // signature rejects.
        use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
        let u = url("https://etchit.io/actors/josh");
        let der = [0xAA_u8; 16];
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let input = signing_input("josh", &u, VALID_AGENT_HEX, &der).unwrap();
        let sig = dsa.sign(&sk, &input).unwrap().to_bytes();
        let att = MlDsaAttestation::new(pk.to_bytes(), sig);
        let err = verify_binding("josh", &u, &der, &att).unwrap_err();
        assert!(
            matches!(err, AttestationVerifyError::SignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn v2_domain_separator_is_frozen() {
        assert_eq!(DOMAIN_SEPARATOR_V2, b"fetchit-fedi-actor-attestation-v2");
    }

    #[test]
    fn signing_input_v2_layout_is_canonical() {
        let relay = "https://relay.example:8088/";
        let profile_addr = "a".repeat(64);
        let bytes = signing_input_v2(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &profile_addr,
            relay,
            1_750_000_000_000,
        )
        .unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_SEPARATOR_V2);
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"josh");
        expected.extend_from_slice(&29u32.to_be_bytes());
        expected.extend_from_slice(b"https://etchit.io/actors/josh");
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(VALID_AGENT_HEX.as_bytes());
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(profile_addr.as_bytes());
        expected.extend_from_slice(&u32::try_from(relay.len()).unwrap().to_be_bytes());
        expected.extend_from_slice(relay.as_bytes());
        expected.extend_from_slice(&1_750_000_000_000u64.to_be_bytes());

        assert_eq!(bytes, expected);
    }

    #[test]
    fn signing_input_v2_differs_when_any_field_changes() {
        let mk = |profile: &str, relay: &str, epoch: u64| {
            signing_input_v2(
                "josh",
                &url("https://etchit.io/actors/josh"),
                VALID_AGENT_HEX,
                &[0x01],
                profile,
                relay,
                epoch,
            )
            .unwrap()
        };
        let base = mk(&"a".repeat(64), "https://relay.example/", 7);
        assert_ne!(base, mk(&"b".repeat(64), "https://relay.example/", 7));
        assert_ne!(base, mk(&"a".repeat(64), "https://other.example/", 7));
        assert_ne!(base, mk(&"a".repeat(64), "https://relay.example/", 8));
    }

    #[test]
    fn signing_input_v2_rejects_bad_profile_addr() {
        for bad in ["UPPERCASE", "a", "", "g"] {
            let r = signing_input_v2(
                "josh",
                &url("https://etchit.io/actors/josh"),
                VALID_AGENT_HEX,
                &[0x01],
                bad,
                "https://relay.example/",
                1,
            );
            assert!(
                matches!(r, Err(SigningInputError::InvalidProfileAddr { .. })),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn signing_input_v2_rejects_empty_and_oversized_relay_hint() {
        let mk = |hint: &str| {
            signing_input_v2(
                "josh",
                &url("https://etchit.io/actors/josh"),
                VALID_AGENT_HEX,
                &[0x01],
                &"a".repeat(64),
                hint,
                1,
            )
        };
        assert!(matches!(
            mk(""),
            Err(SigningInputError::InvalidRelayHint { .. })
        ));
        let long = format!("https://{}/", "x".repeat(MAX_RELAY_HINT_LEN));
        assert!(matches!(
            mk(&long),
            Err(SigningInputError::InvalidRelayHint { .. })
        ));
    }

    #[test]
    fn verify_binding_v2_round_trips_with_real_keys() {
        let actor_url = url("https://etchit.io/actors/josh");
        let (att, derived) = test_attested_v2(
            "josh",
            &actor_url,
            &[9, 9],
            &"a".repeat(64),
            "https://relay.example/",
            42,
        );
        let got = verify_binding_v2("josh", &actor_url, &[9, 9], &att).unwrap();
        assert_eq!(got, derived);
    }

    #[test]
    fn verify_binding_v2_rejects_wrong_version() {
        let actor_url = url("https://etchit.io/actors/josh");
        let (mut att, _) = test_attested_v2(
            "josh",
            &actor_url,
            &[9, 9],
            &"a".repeat(64),
            "https://relay.example/",
            42,
        );
        att.version = 1;
        assert!(matches!(
            verify_binding_v2("josh", &actor_url, &[9, 9], &att),
            Err(AttestationVerifyError::WrongVersion { got: 1 })
        ));
    }

    #[test]
    fn verify_binding_v2_rejects_tampered_fields() {
        let actor_url = url("https://etchit.io/actors/josh");
        let mk = || {
            test_attested_v2(
                "josh",
                &actor_url,
                &[9, 9],
                &"a".repeat(64),
                "https://relay.example/",
                42,
            )
            .0
        };

        let mut tampered_profile = mk();
        tampered_profile.profile_addr = "b".repeat(64);
        assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &tampered_profile).is_err());

        let mut tampered_relay = mk();
        tampered_relay.relay_hint = "https://evil.example/".into();
        assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &tampered_relay).is_err());

        let mut tampered_epoch = mk();
        tampered_epoch.hint_epoch_ms = 43;
        assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &tampered_epoch).is_err());

        // Tampered context fields (not carried on the attestation).
        assert!(verify_binding_v2("mallory", &actor_url, &[9, 9], &mk()).is_err());
        assert!(verify_binding_v2("josh", &actor_url, &[8, 8], &mk()).is_err());
    }

    #[test]
    fn verify_binding_v2_derives_agent_id_rather_than_trusting_a_claim() {
        // Swap key A's pubkey onto key B's attestation: the verifier
        // derives B-input under A's pubkey, and A's pubkey never
        // signed it, so verification must reject.
        let actor_url = url("https://etchit.io/actors/josh");
        let (att_a, _) = test_attested_v2(
            "josh",
            &actor_url,
            &[9, 9],
            &"a".repeat(64),
            "https://relay.example/",
            42,
        );
        let (mut att_b, _) = test_attested_v2(
            "josh",
            &actor_url,
            &[9, 9],
            &"a".repeat(64),
            "https://relay.example/",
            42,
        );
        att_b.ml_dsa_pubkey = att_a.ml_dsa_pubkey.clone();
        assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &att_b).is_err());
    }

    #[test]
    fn attestation_v2_round_trips_through_json() {
        let a = ActorAttestationV2 {
            version: 2,
            profile_addr: "a".repeat(64),
            relay_hint: "https://relay.example/".into(),
            hint_epoch_ms: 5,
            ml_dsa_pubkey: vec![0xDE, 0xAD],
            signature: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"version\":2"), "got {json}");
        assert!(json.contains("\"3q0=\""), "got {json}");
        let back: ActorAttestationV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}
