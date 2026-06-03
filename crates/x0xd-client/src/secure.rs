//! Typed wrappers over x0xd's MLS HTTP+SSE surface (TreeKEM-backed since
//! x0xd v0.20.1). Consumers are `fetchit-chat::groups` for the encrypted
//! group send/receive path; the daemon owns the MLS ratchet.

use serde::{Deserialize, Serialize};

/// One encrypted application-data frame returned by `/secure/encrypt`
/// and accepted by `/secure/decrypt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFrame {
    /// Base64 `ChaCha20-Poly1305` ciphertext.
    pub ciphertext_b64: String,
    /// Base64 12-byte nonce.
    pub nonce_b64: String,
    /// MLS epoch (`secret_epoch` on the wire).
    pub secret_epoch: u32,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_frame_round_trips_via_serde_json() {
        let f = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 7,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EncryptedFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn encrypted_frame_rejects_missing_epoch() {
        let bad = r#"{"ciphertext_b64":"Y3Q=","nonce_b64":"bm9uY2U="}"#;
        assert!(serde_json::from_str::<EncryptedFrame>(bad).is_err());
    }
}
