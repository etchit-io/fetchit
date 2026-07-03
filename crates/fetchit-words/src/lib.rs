//! Four-word verification phrases over already-exchanged identities.
//!
//! Two jobs, both offline and pure:
//!
//! 1. [`agent_words`] renders an agent id as the same four dictionary words
//!    x0x's own tooling shows for that id (`four-word-networking`
//!    `IdentityEncoder`), so a fetch>it user and an `x0x` CLI user looking at
//!    the same identity read the same words.
//! 2. [`verification_phrase`] derives an order-independent four-word phrase
//!    binding two agent ids and a context, for spoken out-of-band
//!    confirmation of a pairing, device link, or group invite.
//!
//! The words are a VERIFICATION AID over an identity that was already
//! exchanged through another channel (QR code, share URI, pair record). They
//! are not an identity, not an address, and not a lookup key.

use four_word_networking::IdentityEncoder;
use sha2::{Digest, Sha256};

/// Domain-separation prefix for the pairwise verification hash.
///
/// All other hashed fields are fixed-length (two 32-byte ids), so the
/// variable-length context can ride last with no length prefix.
const PHRASE_DOMAIN: &[u8] = b"fetchit/words/v1\0";

/// Errors from word encoding.
#[derive(Debug, thiserror::Error)]
pub enum WordsError {
    /// The underlying dictionary encoder rejected the input.
    #[error("four-word encoding failed: {0}")]
    Encode(String),
}

/// Four dictionary words for an agent id, identical to the rendering x0x's
/// own tools produce for the same id.
///
/// Only the first 6 bytes (48 bits) of the id feed the words; two ids that
/// share their first 6 bytes render identically. That is inherent to the
/// upstream encoding and acceptable for a human-verification aid.
///
/// # Errors
///
/// Returns [`WordsError::Encode`] if the dictionary encoder rejects the
/// input (it does not for 32-byte ids; the branch exists because the
/// upstream API is fallible).
pub fn agent_words(agent_id: &[u8; 32]) -> Result<[String; 4], WordsError> {
    words_for(agent_id)
}

/// Order-independent four-word phrase binding two agent ids and a context.
///
/// Both peers compute the same phrase regardless of argument order. Distinct
/// `context` values (for example `b"pair"`, `b"device-link"`, or a group id)
/// yield unrelated phrases. This offers 48 bits of comparison strength:
/// right for a spoken out-of-band check, not for machine authentication.
///
/// # Errors
///
/// Returns [`WordsError::Encode`] if the dictionary encoder rejects the
/// derived digest (it does not for SHA-256 output; see [`agent_words`]).
pub fn verification_phrase(
    a: &[u8; 32],
    b: &[u8; 32],
    context: &[u8],
) -> Result<[String; 4], WordsError> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(PHRASE_DOMAIN);
    hasher.update(lo);
    hasher.update(hi);
    hasher.update(context);
    let digest = hasher.finalize();
    words_for(&digest)
}

/// Encode the leading 48 bits of `bytes` through the shared x0x dictionary.
fn words_for(bytes: &[u8]) -> Result<[String; 4], WordsError> {
    let encoder = IdentityEncoder::new();
    let words = encoder
        .encode_agent(bytes)
        .map_err(|e| WordsError::Encode(e.to_string()))?;
    Ok(words.agent_words().clone())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn id(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn agent_words_is_deterministic_and_four_nonempty_words() {
        let words = agent_words(&id(0x2a)).unwrap();
        let again = agent_words(&id(0x2a)).unwrap();
        assert_eq!(words, again);
        assert!(words.iter().all(|w| !w.is_empty()));
    }

    #[test]
    fn agent_words_uses_the_48_bit_prefix() {
        // Same first 6 bytes, different tail: identical words (documented).
        let mut a = id(0x11);
        let mut b = id(0x11);
        a[31] = 0xaa;
        b[31] = 0xbb;
        assert_eq!(agent_words(&a).unwrap(), agent_words(&b).unwrap());

        // Different first byte: different words.
        let mut c = id(0x11);
        c[0] = 0x99;
        assert_ne!(agent_words(&a).unwrap(), agent_words(&c).unwrap());
    }

    #[test]
    fn verification_phrase_is_order_independent() {
        let a = id(0x01);
        let b = id(0x02);
        assert_eq!(
            verification_phrase(&a, &b, b"pair").unwrap(),
            verification_phrase(&b, &a, b"pair").unwrap()
        );
    }

    #[test]
    fn verification_phrase_separates_contexts() {
        let a = id(0x01);
        let b = id(0x02);
        assert_ne!(
            verification_phrase(&a, &b, b"pair").unwrap(),
            verification_phrase(&a, &b, b"device-link").unwrap()
        );
    }

    #[test]
    fn verification_phrase_binds_both_parties() {
        let a = id(0x01);
        let b = id(0x02);
        let c = id(0x03);
        assert_ne!(
            verification_phrase(&a, &b, b"pair").unwrap(),
            verification_phrase(&a, &c, b"pair").unwrap()
        );
    }

    #[test]
    fn verification_phrase_is_domain_separated_from_agent_words() {
        let a = id(0x01);
        let b = id(0x02);
        let phrase = verification_phrase(&a, &b, b"pair").unwrap();
        assert_ne!(phrase, agent_words(&a).unwrap());
        assert_ne!(phrase, agent_words(&b).unwrap());
    }
}
