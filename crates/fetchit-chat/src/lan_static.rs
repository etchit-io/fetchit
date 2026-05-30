//! Sealed vault for the LAN-direct Noise X25519 static keypair.
//!
//! Sibling to [`crate::chat_identity`]: same `MasterKey`, same vault
//! format, separate file (`<data_dir>/lan_static.json.enc`). Keeping
//! the X25519 static in its own file means the LAN feature can be
//! cleanly disabled by deleting one path and the chat KEM identity
//! is untouched on LAN-key rotation.
//!
//! Rebinds on `agent_id` rotation, mirroring [`crate::chat_identity`].

use crate::at_rest::{open_from_path, seal_to_path, MasterKey, ARGON_SALT_LEN};
use crate::error::ChatError;
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Filename of the sealed LAN-static vault inside the data dir.
pub const LAN_STATIC_FILE: &str = "lan_static.json.enc";

/// Length of an X25519 public or secret key in bytes.
pub const X25519_KEY_LEN: usize = 32;

/// On-disk payload (plaintext after vault open). Holds secret bytes —
/// never log, never send over a wire.
#[derive(Clone, Serialize, Deserialize)]
struct LanStaticVaultPayload {
    /// Schema version of the JSON inside the vault.
    version: u16,
    /// `agent_id` (hex) this keypair is bound to. Rotated keys
    /// regenerate when this changes.
    agent_id_hex: String,
    /// X25519 public key (32 B base64 = 44 chars).
    x25519_pub_b64: String,
    /// X25519 secret key (32 B base64 = 44 chars). Sensitive.
    x25519_sec_b64: String,
    /// Wall-clock minted time (ms since Unix epoch).
    created_at_ms: u64,
}

impl Drop for LanStaticVaultPayload {
    fn drop(&mut self) {
        self.x25519_sec_b64.zeroize();
    }
}

/// In-memory LAN-direct static identity for the local device.
#[derive(Clone)]
pub struct LanStaticIdentity {
    agent_id_hex: String,
    x25519_pub: [u8; X25519_KEY_LEN],
    x25519_sec: Zeroizing<[u8; X25519_KEY_LEN]>,
    created_at_ms: u64,
}

impl std::fmt::Debug for LanStaticIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanStaticIdentity")
            .field("agent_id_hex", &self.agent_id_hex)
            .field("x25519_pub", &hex::encode(self.x25519_pub))
            .field("x25519_sec", &"<redacted>")
            .field("created_at_ms", &self.created_at_ms)
            .finish_non_exhaustive()
    }
}

impl LanStaticIdentity {
    /// Load the static keypair from `<data_dir>/lan_static.json.enc`,
    /// generating a fresh one if the file is absent.
    ///
    /// If the stored payload is bound to a different `agent_id`, the
    /// keypair is regenerated — the LAN identity rotates in lock-step
    /// with the chat identity.
    ///
    /// # Errors
    /// I/O, AEAD, or serialization failures.
    pub fn load_or_create(
        data_dir: &Path,
        master: &MasterKey,
        agent_id_hex: &str,
        kdf_id: u8,
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        let path = data_dir.join(LAN_STATIC_FILE);
        if path.exists() {
            let bytes = open_from_path(&path, master)?;
            let payload: LanStaticVaultPayload = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("lan_static payload parse: {e}")))?;
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
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use rand::rngs::OsRng;

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sec_bytes = secret.to_bytes();
        let pub_bytes = public.to_bytes();

        let mut sec_b64 = Zeroizing::new(B64.encode(sec_bytes));
        let payload = LanStaticVaultPayload {
            version: 1,
            agent_id_hex: agent_id_hex.to_owned(),
            x25519_pub_b64: B64.encode(pub_bytes),
            x25519_sec_b64: sec_b64.as_str().to_owned(),
            created_at_ms: now_ms(),
        };
        sec_b64.zeroize();

        let mut plaintext = serde_json::to_vec(&payload)
            .map_err(|e| ChatError::Invalid(format!("lan_static payload serialize: {e}")))?;
        let path = data_dir.join(LAN_STATIC_FILE);
        let seal_result = seal_to_path(&path, &plaintext, master, kdf_id, argon_salt);
        plaintext.zeroize();
        seal_result?;
        Self::from_payload(&payload)
    }

    fn from_payload(payload: &LanStaticVaultPayload) -> Result<Self, ChatError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;

        let pub_vec = B64
            .decode(&payload.x25519_pub_b64)
            .map_err(|e| ChatError::Invalid(format!("x25519 pub b64: {e}")))?;
        let sec_vec = Zeroizing::new(
            B64.decode(&payload.x25519_sec_b64)
                .map_err(|e| ChatError::Invalid(format!("x25519 sec b64: {e}")))?,
        );
        if pub_vec.len() != X25519_KEY_LEN {
            return Err(ChatError::Invalid("x25519 pub length".into()));
        }
        if sec_vec.len() != X25519_KEY_LEN {
            return Err(ChatError::Invalid("x25519 sec length".into()));
        }
        let mut x25519_pub = [0u8; X25519_KEY_LEN];
        x25519_pub.copy_from_slice(&pub_vec);
        let mut x25519_sec = Zeroizing::new([0u8; X25519_KEY_LEN]);
        x25519_sec.copy_from_slice(&sec_vec);
        Ok(Self {
            agent_id_hex: payload.agent_id_hex.clone(),
            x25519_pub,
            x25519_sec,
            created_at_ms: payload.created_at_ms,
        })
    }

    /// Borrow the bound `agent_id` (hex).
    #[must_use]
    pub fn agent_id_hex(&self) -> &str {
        &self.agent_id_hex
    }

    /// Borrow the X25519 public key bytes.
    #[must_use]
    pub fn x25519_public(&self) -> &[u8; X25519_KEY_LEN] {
        &self.x25519_pub
    }

    /// Borrow the X25519 secret key bytes. Sensitive — never log.
    #[must_use]
    pub fn x25519_secret(&self) -> &[u8; X25519_KEY_LEN] {
        &self.x25519_sec
    }

    /// Wall-clock time the keypair was minted, ms since Unix epoch.
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
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
    fn first_launch_creates_x25519_keypair() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let id = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            "deadbeef00000000000000000000000000000000000000000000000000000000",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(id.x25519_public().len(), X25519_KEY_LEN);
        assert_eq!(id.x25519_secret().len(), X25519_KEY_LEN);
        assert!(dir.path().join(LAN_STATIC_FILE).exists());
    }

    #[test]
    fn pub_key_matches_secret_derivation() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let id = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            "deadbeef00000000000000000000000000000000000000000000000000000000",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let derived = PublicKey::from(&StaticSecret::from(*id.x25519_secret()));
        assert_eq!(derived.to_bytes(), *id.x25519_public());
    }

    #[test]
    fn second_load_returns_same_keypair() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let aid = "deadbeef00000000000000000000000000000000000000000000000000000000";
        let a = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            aid,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let b = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            aid,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(a.x25519_public(), b.x25519_public());
        assert_eq!(a.x25519_secret(), b.x25519_secret());
    }

    #[test]
    fn agent_id_rotation_regenerates_keypair() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let a = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            "aaaa0000000000000000000000000000000000000000000000000000000000aa",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let b = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            "bbbb0000000000000000000000000000000000000000000000000000000000bb",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_ne!(
            a.x25519_public(),
            b.x25519_public(),
            "rotating x0x agent_id must regenerate the LAN static keypair"
        );
        assert_ne!(
            a.x25519_secret(),
            b.x25519_secret(),
            "rotating x0x agent_id must regenerate the secret as well"
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let id = LanStaticIdentity::load_or_create(
            dir.path(),
            &master,
            "cafe0000000000000000000000000000000000000000000000000000000000ca",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let rendered = format!("{id:?}");
        assert!(rendered.contains("<redacted>"));
        let sec_hex = hex::encode(id.x25519_secret());
        assert!(!rendered.contains(&sec_hex));
    }
}
