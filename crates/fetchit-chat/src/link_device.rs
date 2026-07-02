//! The enrollment **offer** a NEW device makes when linking itself to an
//! existing account (M6.4).
//!
//! The offer carries the device's freshly minted public identity —
//! everything the already-trusted device needs to mint an
//! [`AgentCertificate`](crate::fabric::AgentCertificate) for it — plus a
//! one-time nonce and an expiry.
//!
//! It is **transport-agnostic**. The raw offer is ~3 KB (two post-quantum
//! public keys: a 1952-byte ML-DSA-65 key and a 1184-byte ML-KEM-768 key),
//! which far exceeds a scannable QR's byte capacity, so the offer is conveyed
//! over the enrollment channel (e.g. a relay-sealed blob addressed by a
//! compact QR pointer) rather than inlined in the QR itself. This module owns
//! only the offer **value** and its self-consistency checks; the delivery
//! channel is a separate concern.

use crate::chat_crypto::{aead_open, aead_seal, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_proto::derive_agent_id;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Raw length of an ML-DSA-65 public key. Matches the value hard-coded across
/// the crate (`profile.rs`, `pair.rs`); a deliberate pin bump updates both.
const ML_DSA_PUBKEY_BYTES: usize = 1952;

/// Raw length of an ML-KEM-768 public key (`chat_identity.rs`, `profile.rs`).
const ML_KEM_PUBKEY_BYTES: usize = 1184;

/// Decoded bounds on the one-time nonce: enough entropy to be unguessable
/// without bloating the sealed offer.
const NONCE_MIN_BYTES: usize = 16;
const NONCE_MAX_BYTES: usize = 64;

/// AEAD associated data binding a sealed blob to the link-device enrollment
/// protocol, so a ciphertext sealed for another purpose can never open here.
const LINK_OFFER_AAD: &[u8] = b"fetchit-link-offer-v1";

/// A new device's link-to-account offer. Serialized (JSON) as the plaintext
/// that the enrollment channel seals and the existing device recovers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkDeviceOffer {
    /// The new device's agent id, `hex(derive_agent_id(agent ML-DSA pubkey))`.
    /// Redundant with the key (it binds it) but kept so the confirming device
    /// can display/log the id without re-deriving; [`validate`] re-checks it.
    ///
    /// [`validate`]: LinkDeviceOffer::validate
    pub agent_id_hex: String,
    /// The new device's ML-DSA-65 signing key, STANDARD base64 — the same
    /// encoding the minted `AgentCertificate` this feeds carries.
    pub agent_ml_dsa_pubkey_b64: String,
    /// The new device's ML-KEM-768 key (the DM-fanout target), STANDARD base64.
    pub kem_pubkey_b64: String,
    /// One-time anti-replay nonce, STANDARD base64.
    pub nonce_b64: String,
    /// Absolute expiry, milliseconds since the Unix epoch.
    pub exp_ms: u64,
}

/// Why a [`LinkDeviceOffer`] failed [`validate`](LinkDeviceOffer::validate).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinkDeviceOfferError {
    /// `agent_id_hex` is not 64 lowercase hex characters.
    #[error("agent_id_hex must be 64 lowercase hex chars")]
    BadAgentIdHex,
    /// A base64 field did not decode.
    #[error("a public-key or nonce field is not valid base64")]
    BadBase64,
    /// A public key decoded to the wrong length for its algorithm.
    #[error("a public key is not the expected length (ML-DSA-65 {ML_DSA_PUBKEY_BYTES} B, ML-KEM-768 {ML_KEM_PUBKEY_BYTES} B)")]
    BadPubkey,
    /// `agent_id_hex` does not derive from the advertised ML-DSA key.
    #[error("agent_id_hex does not match derive_agent_id(agent ML-DSA pubkey)")]
    AgentIdMismatch,
    /// The nonce decoded outside `NONCE_MIN_BYTES..=NONCE_MAX_BYTES`.
    #[error("nonce must decode to {NONCE_MIN_BYTES}..={NONCE_MAX_BYTES} bytes")]
    BadNonce,
    /// `exp_ms` is zero (unset).
    #[error("expiry must be a non-zero epoch-ms timestamp")]
    BadExpiry,
}

impl LinkDeviceOffer {
    /// Validate the offer's internal consistency: `agent_id_hex` is 64
    /// lowercase hex **and** binds the ML-DSA key, both keys decode to their
    /// exact algorithm lengths, the nonce is a sane size, and the expiry is
    /// set. Does not check freshness against a clock — see [`is_expired`].
    ///
    /// [`is_expired`]: LinkDeviceOffer::is_expired
    ///
    /// # Errors
    /// A [`LinkDeviceOfferError`] variant for the first failing check.
    pub fn validate(&self) -> Result<(), LinkDeviceOfferError> {
        if self.agent_id_hex.len() != 64
            || !self
                .agent_id_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(LinkDeviceOfferError::BadAgentIdHex);
        }
        let ml_dsa = decode_pubkey(&self.agent_ml_dsa_pubkey_b64, ML_DSA_PUBKEY_BYTES)?;
        let _kem = decode_pubkey(&self.kem_pubkey_b64, ML_KEM_PUBKEY_BYTES)?;
        // The agent id MUST derive from the advertised ML-DSA key — mirrors the
        // mint fail-fast in fabric.rs; a mismatch is a malformed or hostile
        // offer whose cert could never verify.
        if hex::encode(derive_agent_id(&ml_dsa)) != self.agent_id_hex {
            return Err(LinkDeviceOfferError::AgentIdMismatch);
        }
        let nonce = B64
            .decode(&self.nonce_b64)
            .map_err(|_| LinkDeviceOfferError::BadBase64)?;
        if !(NONCE_MIN_BYTES..=NONCE_MAX_BYTES).contains(&nonce.len()) {
            return Err(LinkDeviceOfferError::BadNonce);
        }
        if self.exp_ms == 0 {
            return Err(LinkDeviceOfferError::BadExpiry);
        }
        Ok(())
    }

    /// Has this offer expired at `now_ms` (epoch milliseconds)? The offer is
    /// dead exactly at `exp_ms`.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.exp_ms
    }

    /// Seal this offer for relay transport: JSON-serialize, then
    /// ChaCha20-Poly1305 under a single-use `key`. The 12-byte `nonce` is
    /// prepended to the ciphertext so the blob is self-contained — the relay
    /// stores exactly these opaque bytes under the pointer token.
    ///
    /// `key` is fresh per enrollment (it rides the QR fragment), so the
    /// `nonce` need not be unique across offers; prepending a random one is
    /// defence in depth against accidental key reuse.
    ///
    /// # Errors
    /// [`ChatError`] on JSON serialization or AEAD failure.
    pub fn seal(
        &self,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; AEAD_NONCE_LEN],
    ) -> Result<Vec<u8>, ChatError> {
        let plaintext = serde_json::to_vec(self)
            .map_err(|e| ChatError::Invalid(format!("link offer serialize: {e}")))?;
        let ct = aead_seal(key, nonce, &plaintext, LINK_OFFER_AAD)?;
        let mut blob = Vec::with_capacity(AEAD_NONCE_LEN + ct.len());
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    /// Recover an offer from a sealed `blob` (`nonce || ciphertext`) under
    /// `key`. The result is deserialized but NOT yet trusted — the caller must
    /// run [`validate`](Self::validate) and [`is_expired`](Self::is_expired).
    ///
    /// # Errors
    /// [`ChatError`] on a truncated blob, an AEAD tag mismatch (tampering or
    /// the wrong key), or malformed JSON.
    pub fn open(blob: &[u8], key: &[u8; AEAD_KEY_LEN]) -> Result<Self, ChatError> {
        if blob.len() < AEAD_NONCE_LEN {
            return Err(ChatError::Invalid("link offer blob is truncated".into()));
        }
        let (nonce_bytes, ct) = blob.split_at(AEAD_NONCE_LEN);
        let nonce: [u8; AEAD_NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| ChatError::Invalid("link offer nonce".into()))?;
        let plaintext = aead_open(key, &nonce, ct, LINK_OFFER_AAD)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| ChatError::Invalid(format!("link offer parse: {e}")))
    }
}

/// Base64-decode a public key and require it to be exactly `expected_len`.
fn decode_pubkey(b64: &str, expected_len: usize) -> Result<Vec<u8>, LinkDeviceOfferError> {
    let raw = B64
        .decode(b64)
        .map_err(|_| LinkDeviceOfferError::BadBase64)?;
    if raw.len() != expected_len {
        return Err(LinkDeviceOfferError::BadPubkey);
    }
    Ok(raw)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_client::{MlDsaSigner, Signer};

    /// A well-formed offer whose agent id binds its (real) ML-DSA key.
    fn valid_offer(seed: u8) -> LinkDeviceOffer {
        let signer = MlDsaSigner::from_seed(&[seed; 32]);
        LinkDeviceOffer {
            agent_id_hex: hex::encode(signer.agent_id()),
            agent_ml_dsa_pubkey_b64: B64.encode(signer.public_key()),
            kem_pubkey_b64: B64.encode([0u8; ML_KEM_PUBKEY_BYTES]),
            nonce_b64: B64.encode([7u8; 16]),
            exp_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn validates_a_well_formed_offer() {
        valid_offer(3).validate().unwrap();
    }

    #[test]
    fn round_trips_through_json() {
        let offer = valid_offer(5);
        let bytes = serde_json::to_vec(&offer).unwrap();
        let back: LinkDeviceOffer = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(offer, back);
        back.validate().unwrap();
    }

    #[test]
    fn rejects_agent_id_not_binding_the_ml_dsa_key() {
        let mut offer = valid_offer(3);
        // A different device's (valid-format) agent id.
        offer.agent_id_hex = hex::encode(MlDsaSigner::from_seed(&[9u8; 32]).agent_id());
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::AgentIdMismatch));
    }

    #[test]
    fn rejects_non_hex_agent_id() {
        let mut offer = valid_offer(3);
        offer.agent_id_hex = "z".repeat(64);
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadAgentIdHex));
    }

    #[test]
    fn rejects_uppercase_agent_id() {
        let mut offer = valid_offer(3);
        offer.agent_id_hex = offer.agent_id_hex.to_uppercase();
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadAgentIdHex));
    }

    #[test]
    fn rejects_wrong_length_agent_id() {
        let mut offer = valid_offer(3);
        offer.agent_id_hex = "abcd".to_string();
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadAgentIdHex));
    }

    #[test]
    fn rejects_wrong_size_ml_dsa_key() {
        let mut offer = valid_offer(3);
        offer.agent_ml_dsa_pubkey_b64 = B64.encode([0u8; 100]);
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadPubkey));
    }

    #[test]
    fn rejects_wrong_size_kem_key() {
        let mut offer = valid_offer(3);
        offer.kem_pubkey_b64 = B64.encode([0u8; 100]);
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadPubkey));
    }

    #[test]
    fn rejects_non_base64_ml_dsa_key() {
        let mut offer = valid_offer(3);
        offer.agent_ml_dsa_pubkey_b64 = "not*base64*".to_string();
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadBase64));
    }

    #[test]
    fn rejects_short_and_long_nonce() {
        let mut short = valid_offer(3);
        short.nonce_b64 = B64.encode([0u8; 8]);
        assert_eq!(short.validate(), Err(LinkDeviceOfferError::BadNonce));
        let mut long = valid_offer(3);
        long.nonce_b64 = B64.encode([0u8; 65]);
        assert_eq!(long.validate(), Err(LinkDeviceOfferError::BadNonce));
    }

    #[test]
    fn rejects_zero_expiry() {
        let mut offer = valid_offer(3);
        offer.exp_ms = 0;
        assert_eq!(offer.validate(), Err(LinkDeviceOfferError::BadExpiry));
    }

    #[test]
    fn is_expired_is_inclusive_at_exp_ms() {
        let mut offer = valid_offer(3);
        offer.exp_ms = 1_000;
        assert!(!offer.is_expired(999));
        assert!(offer.is_expired(1_000));
        assert!(offer.is_expired(1_001));
    }

    #[test]
    fn seal_then_open_round_trips_and_prepends_the_nonce() {
        let offer = valid_offer(4);
        let key = [0x5a; AEAD_KEY_LEN];
        let nonce = [0x11; AEAD_NONCE_LEN];
        let blob = offer.seal(&key, &nonce).unwrap();
        assert_eq!(&blob[..AEAD_NONCE_LEN], &nonce, "nonce must lead the blob");
        let back = LinkDeviceOffer::open(&blob, &key).unwrap();
        assert_eq!(offer, back);
        back.validate().unwrap();
    }

    #[test]
    fn open_rejects_a_tampered_blob() {
        let offer = valid_offer(4);
        let key = [0x5a; AEAD_KEY_LEN];
        let mut blob = offer.seal(&key, &[0x11; AEAD_NONCE_LEN]).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a ciphertext bit
        assert!(LinkDeviceOffer::open(&blob, &key).is_err());
    }

    #[test]
    fn open_rejects_the_wrong_key() {
        let offer = valid_offer(4);
        let blob = offer
            .seal(&[0x5a; AEAD_KEY_LEN], &[0x11; AEAD_NONCE_LEN])
            .unwrap();
        assert!(LinkDeviceOffer::open(&blob, &[0x5b; AEAD_KEY_LEN]).is_err());
    }

    #[test]
    fn open_rejects_a_truncated_blob() {
        assert!(LinkDeviceOffer::open(&[0u8; 4], &[0x5a; AEAD_KEY_LEN]).is_err());
    }
}
