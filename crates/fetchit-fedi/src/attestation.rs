//! ML-DSA-65 attestation binding a fetch>it Actor's RSA-2048 pubkey to
//! its chat-identity ML-DSA key.
//!
//! Per plan decision [III], the per-POST ML-DSA cosignature was dropped
//! and the Actor JSON-LD attestation is the **authoritative PQ
//! binding**. This module owns the canonical signing-input byte format
//! that both the chat-side signer and any verifier (fetch>it node or
//! third-party PQ-aware bridge) must agree on, byte-for-byte.

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaAttestation {
    /// ML-DSA-65 public key bytes (raw, not encoded). The chat-identity
    /// pubkey under which the signature verifies.
    pub ml_dsa_pubkey: Vec<u8>,
    /// ML-DSA-65 signature over [`signing_input`] of the actor fields.
    pub signature: Vec<u8>,
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
}
