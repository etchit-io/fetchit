//! M2.5 Welcome contingency bridge (#251 Layer 2).
//!
//! Two payload shapes, sealed under ML-KEM-768 to the recipient's
//! chat-card KEM pubkey with ChaCha20-Poly1305 AEAD:
//!
//! - `WelcomeRequestPayload`: joiner asks the owner to ship the pending
//!   Welcome blob bytes for `group_id` to `joiner_agent_id`.
//! - `WelcomeBlobPayload`: owner replies with the bytes.
//!
//! Both gate behind `bundled_x0xd_below_v0_21_3` at the call site.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::chat_crypto::{
    aead_open, aead_seal, derive_aead_key, kem_decapsulate, kem_encapsulate, random_nonce,
    AAD_DOMAIN, AEAD_NONCE_LEN, KEM_PUBLIC_KEY_LEN,
};
use crate::error::{ChatError, Result};

const KDF_INFO_WELCOME_BRIDGE: &[u8] = b"fetchit.welcome-bridge.v1";

/// Joiner asks the owner to ship the pending Welcome blob for `group_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WelcomeRequestPayload {
    /// Group the joiner needs a Welcome blob for.
    pub group_id: String,
    /// Agent id the owner should address the reply to.
    pub joiner_agent_id: String,
    /// Unix epoch ms at time of request.
    pub ts_ms: u64,
}

/// Owner ships the MLS Welcome blob bytes for `group_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WelcomeBlobPayload {
    /// Group the blob covers.
    pub group_id: String,
    /// Base64-encoded raw Welcome bytes from x0xd.
    pub blob_b64: String,
    /// Unix epoch ms at time of reply.
    pub ts_ms: u64,
}

/// Returns the AAD for all welcome-bridge envelopes.
#[must_use]
pub fn welcome_bridge_aad() -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 20);
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(b"|welcome-bridge-v1|");
    out
}

/// Wire parts produced by [`seal_welcome_request`] or [`seal_welcome_blob`].
#[derive(Debug, Clone)]
pub struct SealedWelcomeParts {
    /// ML-KEM-768 ciphertext encapsulated to the recipient's pubkey.
    pub kem_ciphertext: Vec<u8>,
    /// 12-byte AEAD nonce.
    pub nonce: Vec<u8>,
    /// ChaCha20-Poly1305 ciphertext (includes the 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// Seal a [`WelcomeRequestPayload`] to `recipient_kem_pub`.
///
/// # Errors
/// - [`ChatError::Invalid`] when `recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN`.
/// - KEM encapsulation or AEAD seal errors.
pub fn seal_welcome_request(
    recipient_kem_pub: &[u8],
    payload: &WelcomeRequestPayload,
) -> Result<SealedWelcomeParts> {
    let plaintext = postcard::to_allocvec(payload)
        .map_err(|e| ChatError::Invalid(format!("welcome-request postcard: {e}")))?;
    seal_inner(recipient_kem_pub, &plaintext)
}

/// Seal a [`WelcomeBlobPayload`] to `recipient_kem_pub`.
///
/// # Errors
/// Same as [`seal_welcome_request`].
pub fn seal_welcome_blob(
    recipient_kem_pub: &[u8],
    payload: &WelcomeBlobPayload,
) -> Result<SealedWelcomeParts> {
    let plaintext = postcard::to_allocvec(payload)
        .map_err(|e| ChatError::Invalid(format!("welcome-blob postcard: {e}")))?;
    seal_inner(recipient_kem_pub, &plaintext)
}

fn seal_inner(recipient_kem_pub: &[u8], plaintext: &[u8]) -> Result<SealedWelcomeParts> {
    if recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN {
        return Err(ChatError::Invalid(
            "welcome-bridge recipient KEM pubkey wrong length".into(),
        ));
    }
    let (kem_ciphertext, shared_secret) = kem_encapsulate(recipient_kem_pub)?;
    let aead_key = derive_aead_key(&shared_secret, KDF_INFO_WELCOME_BRIDGE);
    let nonce = random_nonce(&mut OsRng);
    let aad = welcome_bridge_aad();
    let ciphertext = aead_seal(&aead_key, &nonce, plaintext, &aad)?;
    Ok(SealedWelcomeParts {
        kem_ciphertext,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Unseal a [`WelcomeRequestPayload`] from the wire parts.
///
/// # Errors
/// AEAD open / KEM decap / postcard decode errors.
pub fn unseal_welcome_request(
    recipient_kem_secret: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<WelcomeRequestPayload> {
    let plaintext = unseal_inner(recipient_kem_secret, kem_ciphertext, nonce, ciphertext)?;
    postcard::from_bytes(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("welcome-request unseal: {e}")))
}

/// Unseal a [`WelcomeBlobPayload`] from the wire parts.
///
/// # Errors
/// AEAD open / KEM decap / postcard decode errors.
pub fn unseal_welcome_blob(
    recipient_kem_secret: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<WelcomeBlobPayload> {
    let plaintext = unseal_inner(recipient_kem_secret, kem_ciphertext, nonce, ciphertext)?;
    postcard::from_bytes(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("welcome-blob unseal: {e}")))
}

fn unseal_inner(
    recipient_kem_secret: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != AEAD_NONCE_LEN {
        return Err(ChatError::Invalid(
            "welcome-bridge nonce wrong length".into(),
        ));
    }
    let shared_secret = kem_decapsulate(recipient_kem_secret, kem_ciphertext)?;
    let aead_key = derive_aead_key(&shared_secret, KDF_INFO_WELCOME_BRIDGE);
    let mut nonce_arr = [0u8; AEAD_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let aad = welcome_bridge_aad();
    aead_open(&aead_key, &nonce_arr, ciphertext, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_crypto::kem_keygen;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    #[test]
    fn welcome_request_round_trips_through_seal_then_unseal() {
        let (kem_pub, kem_secret) = kem_keygen().unwrap();
        let payload = WelcomeRequestPayload {
            group_id: "gid-1234".into(),
            joiner_agent_id: "aid-joiner".into(),
            ts_ms: 1_000_000_000,
        };
        let sealed = seal_welcome_request(&kem_pub, &payload).unwrap();
        let back = unseal_welcome_request(
            &kem_secret,
            &sealed.kem_ciphertext,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn welcome_blob_round_trips_with_33k_bytes() {
        let (kem_pub, kem_secret) = kem_keygen().unwrap();
        let blob_b64 = B64.encode(vec![0xABu8; 33 * 1024]);
        let payload = WelcomeBlobPayload {
            group_id: "gid".into(),
            blob_b64,
            ts_ms: 1,
        };
        let sealed = seal_welcome_blob(&kem_pub, &payload).unwrap();
        let back = unseal_welcome_blob(
            &kem_secret,
            &sealed.kem_ciphertext,
            &sealed.nonce,
            &sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn seal_welcome_request_rejects_wrong_length_recipient_pubkey() {
        let payload = WelcomeRequestPayload {
            group_id: "g".into(),
            joiner_agent_id: "j".into(),
            ts_ms: 0,
        };
        let err = seal_welcome_request(&[0u8; 16], &payload).unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)));
    }
}
