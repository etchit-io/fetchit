//! Spoken verification phrases over already-exchanged agent ids.
//!
//! Both peers derive the same four dictionary words from the two agent ids
//! and a purpose tag; reading them aloud (or comparing on screen) confirms
//! that no man-in-the-middle swapped identities during the QR / share-URI
//! exchange. The words are a VERIFICATION AID, never an identity — see
//! `fetchit-words` for the derivation (order-independent, domain-separated,
//! same dictionary x0x tooling renders).

use crate::error::{ChatError, Result};

/// What the two peers are confirming. Distinct purposes yield unrelated
/// phrases, so a phrase captured in one flow cannot be replayed in another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyPurpose {
    /// First-contact pairing (QR / share-URI exchange).
    Pairing,
    /// Linking an additional device to the same account (M6).
    DeviceLink,
    /// Confirming a group invite out-of-band.
    GroupInvite,
}

impl VerifyPurpose {
    fn context(self) -> &'static [u8] {
        match self {
            Self::Pairing => b"pair",
            Self::DeviceLink => b"device-link",
            Self::GroupInvite => b"group-invite",
        }
    }
}

/// Four words both peers can read aloud to confirm `own` and `peer` are
/// the identities each side actually holds. Argument order does not
/// matter; both sides compute the same phrase.
///
/// # Errors
///
/// Returns [`ChatError::Invalid`] when either id is not 64 lowercase-hex
/// chars, or if the word encoder rejects the derived digest (it does not
/// for valid input; the branch exists because the upstream API is
/// fallible).
pub fn verification_words(
    own_hex: &str,
    peer_hex: &str,
    purpose: VerifyPurpose,
) -> Result<[String; 4]> {
    let own = decode_id(own_hex)?;
    let peer = decode_id(peer_hex)?;
    fetchit_words::verification_phrase(&own, &peer, purpose.context())
        .map_err(|e| ChatError::Invalid(format!("word encoding failed: {e}")))
}

fn decode_id(hex_id: &str) -> Result<[u8; 32]> {
    let trimmed = hex_id.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ChatError::Invalid(format!(
            "agent id must be 64 hex chars, got {} chars",
            trimmed.len()
        )));
    }
    let bytes = hex::decode(trimmed.to_ascii_lowercase())
        .map_err(|e| ChatError::Invalid(format!("agent id hex: {e}")))?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn both_sides_compute_the_same_phrase() {
        let ours = verification_words(A, B, VerifyPurpose::Pairing).unwrap();
        let theirs = verification_words(B, A, VerifyPurpose::Pairing).unwrap();
        assert_eq!(ours, theirs);
        assert!(ours.iter().all(|w| !w.is_empty()));
    }

    #[test]
    fn purposes_yield_unrelated_phrases() {
        let pair = verification_words(A, B, VerifyPurpose::Pairing).unwrap();
        let link = verification_words(A, B, VerifyPurpose::DeviceLink).unwrap();
        let invite = verification_words(A, B, VerifyPurpose::GroupInvite).unwrap();
        assert_ne!(pair, link);
        assert_ne!(pair, invite);
        assert_ne!(link, invite);
    }

    #[test]
    fn uppercase_hex_is_accepted_and_canonicalised() {
        let lower = verification_words(A, B, VerifyPurpose::Pairing).unwrap();
        let upper = verification_words(&A.to_uppercase(), B, VerifyPurpose::Pairing).unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn short_or_non_hex_ids_are_rejected() {
        assert!(verification_words("abc", B, VerifyPurpose::Pairing).is_err());
        let bad = "zz".repeat(32);
        assert!(verification_words(&bad, B, VerifyPurpose::Pairing).is_err());
    }
}
