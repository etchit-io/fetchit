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
/// Returns an error only when a length exceeds `u32::MAX`, which would
/// require a multi-gigabyte input — practically unreachable but explicit
/// for forward-compatibility audits.
pub fn signing_input(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    rsa_pubkey_der: &[u8],
) -> Result<Vec<u8>, SigningInputError> {
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    #[test]
    fn domain_separator_is_frozen() {
        assert_eq!(DOMAIN_SEPARATOR, b"fetchit-fedi-actor-attestation-v1");
    }

    #[test]
    fn signing_input_layout_is_canonical() {
        let bytes = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            "0123456789abcdef",
            &[0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_SEPARATOR);
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"josh");
        expected.extend_from_slice(&29u32.to_be_bytes());
        expected.extend_from_slice(b"https://etchit.io/actors/josh");
        expected.extend_from_slice(&16u32.to_be_bytes());
        expected.extend_from_slice(b"0123456789abcdef");
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(bytes, expected);
    }

    #[test]
    fn signing_input_differs_when_any_field_changes() {
        let base = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            "abcd",
            &[0x01],
        )
        .unwrap();

        let other_handle = signing_input(
            "alice",
            &url("https://etchit.io/actors/josh"),
            "abcd",
            &[0x01],
        )
        .unwrap();
        let other_url = signing_input(
            "josh",
            &url("https://etchit.io/actors/alice"),
            "abcd",
            &[0x01],
        )
        .unwrap();
        let other_agent = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            "ffff",
            &[0x01],
        )
        .unwrap();
        let other_key = signing_input(
            "josh",
            &url("https://etchit.io/actors/josh"),
            "abcd",
            &[0x02],
        )
        .unwrap();

        assert_ne!(base, other_handle);
        assert_ne!(base, other_url);
        assert_ne!(base, other_agent);
        assert_ne!(base, other_key);
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
