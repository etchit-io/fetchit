//! [`Address`] — a validated 32-byte Autonomi content address.

use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// A 32-byte Autonomi network address.
///
/// Constructed only via [`Address::from_str`] (or the [`FromStr`]
/// impl), which enforces the 64-character lowercase-hex shape used
/// throughout the Autonomi ecosystem. Mixed-case input is normalised on
/// parse so equality is independent of how the user typed the address.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Address([u8; 32]);

impl Address {
    /// Length, in hex characters, of the canonical string form.
    pub const HEX_LEN: usize = 64;

    /// Borrow the raw 32-byte representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render the address as the canonical 64-character lowercase-hex
    /// string. Allocates.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != Self::HEX_LEN {
            return Err(Error::InvalidAddress(format!(
                "expected {} hex characters, got {}",
                Self::HEX_LEN,
                s.len()
            )));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)
            .map_err(|e| Error::InvalidAddress(format!("not valid hex: {e}")))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const VALID_LOWER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_UPPER: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn parses_lowercase_hex() {
        let addr: Address = VALID_LOWER.parse().expect("valid lowercase address");
        assert_eq!(addr.to_string(), VALID_LOWER);
    }

    #[test]
    fn parses_uppercase_and_normalises_to_lowercase() {
        let addr: Address = VALID_UPPER.parse().expect("valid uppercase address");
        assert_eq!(addr.to_string(), VALID_LOWER);
    }

    #[test]
    fn parses_mixed_case_and_normalises() {
        let mixed = "0123456789AbCdEf0123456789aBcDeF0123456789AbCdEf0123456789aBcDeF";
        let addr: Address = mixed.parse().expect("valid mixed-case address");
        assert_eq!(addr.to_string(), VALID_LOWER);
    }

    #[test]
    fn rejects_too_short() {
        let short = &VALID_LOWER[..63];
        let err = short.parse::<Address>().expect_err("should reject");
        assert!(matches!(err, Error::InvalidAddress(_)));
    }

    #[test]
    fn rejects_too_long() {
        let long = format!("{VALID_LOWER}0");
        let err = long.parse::<Address>().expect_err("should reject");
        assert!(matches!(err, Error::InvalidAddress(_)));
    }

    #[test]
    fn rejects_non_hex_character() {
        let mut bad = String::from(VALID_LOWER);
        bad.replace_range(0..1, "z");
        let err = bad.parse::<Address>().expect_err("should reject");
        assert!(matches!(err, Error::InvalidAddress(_)));
    }

    #[test]
    fn rejects_empty() {
        let err = "".parse::<Address>().expect_err("should reject");
        assert!(matches!(err, Error::InvalidAddress(_)));
    }

    #[test]
    fn round_trip_through_display() {
        let addr: Address = VALID_LOWER.parse().expect("valid");
        let again: Address = addr.to_string().parse().expect("round-trip");
        assert_eq!(addr, again);
    }

    #[test]
    fn equality_is_case_insensitive() {
        let lower: Address = VALID_LOWER.parse().expect("valid");
        let upper: Address = VALID_UPPER.parse().expect("valid");
        assert_eq!(lower, upper);
    }
}
