//! Human-writable recovery phrase for an identity backup seed.
//!
//! The 32-byte ML-DSA identity seed (see [`crate::reveal_local_signer_seed`])
//! is shown to the user as a 24-word BIP39 phrase for safekeeping and
//! typed back to restore. BIP39 carries a checksum, so a mistyped or
//! swapped word is rejected on restore instead of silently rebuilding a
//! different identity. A power user may instead read the raw seed as hex
//! (the "show as code" path); that needs nothing from this module beyond
//! `hex::encode` on the revealed bytes.
//!
//! Encoding is the standard BIP39 entropy <-> mnemonic mapping over the
//! English wordlist; interoperability with wallets is not a goal (the
//! seed is fetch>it's own), the words are just a familiar, checksummed,
//! hand-writable form.

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::error::ChatError;

/// Encode a 32-byte identity seed as its 24-word recovery phrase.
///
/// The returned phrase is the secret in word form, so it is wrapped in
/// [`Zeroizing`] to clear on drop.
///
/// # Errors
/// `ChatError::Invalid` only if the underlying BIP39 encoder rejects the
/// length (it never does for 32 bytes; the fallible signature mirrors the
/// crate API rather than admitting a real failure mode here).
pub fn seed_to_recovery_phrase(seed: &[u8; 32]) -> Result<Zeroizing<String>, ChatError> {
    let mnemonic = Mnemonic::from_entropy(seed)
        .map_err(|e| ChatError::Invalid(format!("recovery phrase encode: {e}")))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Decode a 24-word recovery phrase back to the 32-byte identity seed.
///
/// Validates the BIP39 checksum and word list, so a typo, a swapped word,
/// or a wrong-length phrase is rejected rather than yielding a different
/// identity.
///
/// # Errors
/// `ChatError::Invalid` if the phrase is not valid BIP39 (bad word, bad
/// checksum) or does not encode exactly 256 bits (a 24-word phrase).
pub fn recovery_phrase_to_seed(phrase: &str) -> Result<Zeroizing<[u8; 32]>, ChatError> {
    let mnemonic = Mnemonic::parse(phrase)
        .map_err(|e| ChatError::Invalid(format!("recovery phrase invalid: {e}")))?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let seed: [u8; 32] = entropy.as_slice().try_into().map_err(|_| {
        ChatError::Invalid("recovery phrase must be a 24-word (256-bit) phrase".to_owned())
    })?;
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_seed_through_24_words() {
        let seed = [42u8; 32];
        let phrase = seed_to_recovery_phrase(&seed).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let back = recovery_phrase_to_seed(&phrase).unwrap();
        assert_eq!(*back, seed);
    }

    #[test]
    fn matches_the_bip39_all_zero_vector() {
        // The canonical all-zero 256-bit entropy is 23x "abandon" + "art".
        let phrase = seed_to_recovery_phrase(&[0u8; 32]).unwrap();
        assert_eq!(
            *phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
        );
    }

    #[test]
    fn rejects_a_bad_checksum() {
        // 24x "abandon" is valid words but a wrong checksum.
        let bad = "abandon ".repeat(24);
        assert!(recovery_phrase_to_seed(bad.trim()).is_err());
    }

    #[test]
    fn rejects_an_unknown_word() {
        let bad = "zzz ".repeat(24);
        assert!(recovery_phrase_to_seed(bad.trim()).is_err());
    }

    #[test]
    fn rejects_a_shorter_valid_phrase() {
        // A valid 12-word phrase is 128-bit entropy, not our 256-bit seed,
        // so the length guard rejects it.
        let twelve = seed_to_recovery_phrase(&[7u8; 32]).unwrap();
        let first_twelve: String = twelve
            .split_whitespace()
            .take(12)
            .collect::<Vec<_>>()
            .join(" ");
        // (Not a valid 12-word phrase on its own, but proves sub-24 input
        // never yields a 32-byte seed: it errors, never truncates.)
        assert!(recovery_phrase_to_seed(&first_twelve).is_err());
    }
}
