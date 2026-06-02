//! Per-device ML-KEM-768 keypair used for chat-layer content encryption.
//! Distinct from x0xd's KEM keypair (which we don't use because x0xd
//! has no decap endpoint).
//!
//! Persisted as a vault file at `<data_dir>/identity.json.enc`.

use crate::at_rest::{open_from_path, seal_to_path, MasterKey};
use crate::chat_crypto::{kem_keygen, KEM_PUBLIC_KEY_LEN, KEM_SECRET_KEY_LEN};
use crate::error::ChatError;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const IDENTITY_FILE: &str = "identity.json.enc";

/// On-disk identity payload (plaintext after vault open). Contains
/// secret KEM bytes — never log, never send over a wire.
#[derive(Clone, Serialize, Deserialize)]
struct IdentityVaultPayload {
    /// Schema version of the identity JSON inside the vault.
    version: u16,
    /// x0xd agent id this fetchit identity is bound to. We re-bind on
    /// `agent_id` change (e.g. user rotates x0xd identity).
    agent_id_hex: String,
    /// Opt-in logical-user identifier. None for single-device installs;
    /// multi-device builds populate it during device pairing.
    user_id_hex: Option<String>,
    /// ML-KEM-768 public key bytes (1184 B base64).
    kem_public_key_b64: String,
    /// ML-KEM-768 secret key bytes (2400 B base64). Sensitive.
    kem_secret_key_b64: String,
    /// Timestamp the identity was minted, ms since Unix epoch.
    created_at_ms: u64,
}

impl Drop for IdentityVaultPayload {
    fn drop(&mut self) {
        self.kem_secret_key_b64.zeroize();
    }
}

/// In-memory chat identity for the local device.
#[derive(Clone)]
pub struct FetchitIdentity {
    agent_id_hex: String,
    user_id_hex: Option<String>,
    kem_public_key: Vec<u8>,
    kem_secret_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for FetchitIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchitIdentity")
            .field("agent_id_hex", &self.agent_id_hex)
            .field("user_id_hex", &self.user_id_hex)
            .field("kem_public_key_len", &self.kem_public_key.len())
            .field("kem_secret_key_len", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl FetchitIdentity {
    /// Load the identity from the vault at `data_dir/identity.json.enc`,
    /// generating it if absent.
    ///
    /// `agent_id_hex` is supplied by the caller (already resolved from
    /// x0xd). If the stored identity is bound to a different `agent_id`,
    /// regenerates (we never reuse a chat identity across x0x rotations).
    ///
    /// # Errors
    /// I/O, AEAD, or KEM keygen failures.
    pub fn load_or_create(
        data_dir: &Path,
        master: &MasterKey,
        agent_id_hex: &str,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        let path = data_dir.join(IDENTITY_FILE);
        if path.exists() {
            let bytes = open_from_path(&path, master)?;
            let payload: IdentityVaultPayload = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("identity payload parse: {e}")))?;
            if payload.agent_id_hex == agent_id_hex {
                return Self::from_payload(&payload);
            }
        }
        Self::create_and_persist(data_dir, master, agent_id_hex, kdf_id, argon_salt)
    }

    fn create_and_persist(
        data_dir: &Path,
        master: &MasterKey,
        agent_id_hex: &str,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let (pk, sk) = kem_keygen()?;
        let kem_secret_key_b64 = Zeroizing::new(B64.encode(&sk));
        let payload = IdentityVaultPayload {
            version: 1,
            agent_id_hex: agent_id_hex.to_owned(),
            user_id_hex: None,
            kem_public_key_b64: B64.encode(&pk),
            kem_secret_key_b64: kem_secret_key_b64.as_str().to_owned(),
            created_at_ms: now_ms(),
        };
        let mut plaintext = serde_json::to_vec(&payload)
            .map_err(|e| ChatError::Invalid(format!("identity payload serialize: {e}")))?;
        let path = data_dir.join(IDENTITY_FILE);
        let seal_result = seal_to_path(&path, &plaintext, master, kdf_id, argon_salt);
        plaintext.zeroize();
        seal_result?;
        Self::from_payload(&payload)
    }

    fn from_payload(payload: &IdentityVaultPayload) -> Result<Self, ChatError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let kem_public_key = B64
            .decode(&payload.kem_public_key_b64)
            .map_err(|e| ChatError::Invalid(format!("kem pub b64: {e}")))?;
        let kem_secret_key = Zeroizing::new(
            B64.decode(&payload.kem_secret_key_b64)
                .map_err(|e| ChatError::Invalid(format!("kem sec b64: {e}")))?,
        );
        if kem_public_key.len() != KEM_PUBLIC_KEY_LEN {
            return Err(ChatError::Invalid("kem pub length".into()));
        }
        if kem_secret_key.len() != KEM_SECRET_KEY_LEN {
            return Err(ChatError::Invalid("kem sec length".into()));
        }
        Ok(Self {
            agent_id_hex: payload.agent_id_hex.clone(),
            user_id_hex: payload.user_id_hex.clone(),
            kem_public_key,
            kem_secret_key,
        })
    }

    /// Borrow the bound `agent_id` (hex).
    #[must_use]
    pub fn agent_id_hex(&self) -> &str {
        &self.agent_id_hex
    }

    /// Borrow the opt-in `user_id` (hex) if assigned.
    #[must_use]
    pub fn user_id_hex(&self) -> Option<&str> {
        self.user_id_hex.as_deref()
    }

    /// Borrow the KEM public key bytes (used in extended card publishing).
    #[must_use]
    pub fn kem_public_key(&self) -> &[u8] {
        &self.kem_public_key
    }

    /// Borrow the KEM secret key bytes (used in decap on inbound welcomes).
    /// Sensitive — never log.
    #[must_use]
    pub fn kem_secret_key(&self) -> &[u8] {
        &self.kem_secret_key
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKeySource};
    use tempfile::tempdir;

    #[test]
    fn first_launch_creates_identity() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let id = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            "deadbeef00000000000000000000000000000000000000000000000000000000",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(id.kem_public_key().len(), KEM_PUBLIC_KEY_LEN);
        assert_eq!(id.kem_secret_key().len(), KEM_SECRET_KEY_LEN);
        assert!(dir.path().join(IDENTITY_FILE).exists());
    }

    #[test]
    fn second_load_returns_same_identity() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let aid = "deadbeef00000000000000000000000000000000000000000000000000000000";
        let a =
            FetchitIdentity::load_or_create(dir.path(), &master, aid, kdf_id_argon2(), Some(&salt))
                .unwrap();
        let b =
            FetchitIdentity::load_or_create(dir.path(), &master, aid, kdf_id_argon2(), Some(&salt))
                .unwrap();
        assert_eq!(a.kem_public_key(), b.kem_public_key());
        assert_eq!(a.kem_secret_key(), b.kem_secret_key());
    }

    #[test]
    fn agent_id_rotation_regenerates() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let a = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            "aaaa0000000000000000000000000000000000000000000000000000000000aa",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let b = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            "bbbb0000000000000000000000000000000000000000000000000000000000bb",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_ne!(
            a.kem_public_key(),
            b.kem_public_key(),
            "rotating x0x agent_id must regenerate the KEM keypair"
        );
        assert_ne!(
            a.kem_secret_key(),
            b.kem_secret_key(),
            "rotating x0x agent_id must regenerate the secret key as well"
        );
    }
}
