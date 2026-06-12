//! Daemonless local signing identity.
//!
//! On desktop, x0xd owns the ML-DSA-65 keypair and the chat layer
//! signs through `/agent/sign` (`X0xdSigner`). The daemonless profile
//! (Android, or any host without a daemon) instead persists a local
//! keypair in the chat vault, sealed with the same master key as the
//! KEM identity. The agent id is `derive_agent_id(public_key)`, so a
//! local-key agent is a first-class citizen of the relay protocol —
//! pair records and bearer handshakes verify against the public key.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_client::MlDsaSigner;
use fetchit_relay_client::Signer as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::at_rest::{fresh_argon_salt, open_from_path, seal_to_path, MasterKey};
use crate::error::ChatError;

/// Vault file name under the chat data dir, next to `identity.json.enc`.
pub(crate) const LOCAL_SIGNER_FILE: &str = "local_signer.json.enc";

#[derive(Serialize, Deserialize)]
struct LocalSignerPayload {
    version: u8,
    ml_dsa_public_key_b64: String,
    ml_dsa_secret_key_b64: String,
    /// Random per-install token fed to `derive_machine_id`; NOT derived
    /// from the keypair so a restored identity on a new device still
    /// gets a distinct machine fingerprint.
    machine_token: String,
}

impl Drop for LocalSignerPayload {
    fn drop(&mut self) {
        self.ml_dsa_secret_key_b64.zeroize();
    }
}

/// The local signing identity: an [`MlDsaSigner`] plus the per-install
/// machine token, both persisted encrypted at
/// `data_dir/local_signer.json.enc`.
pub(crate) struct LocalSignerVault {
    /// The ML-DSA-65 signer holding the local keypair.
    pub(crate) signer: MlDsaSigner,
    /// Per-install random token used to derive a machine fingerprint.
    pub(crate) machine_token: String,
}

impl LocalSignerVault {
    /// Load the vault, generating and persisting a fresh keypair when
    /// the file does not exist. A decrypt or parse failure on an
    /// EXISTING file is an error, never a silent regeneration —
    /// regenerating would orphan every pairing bound to the agent id.
    ///
    /// # Errors
    /// `ChatError::Invalid` on AEAD failure, JSON parse error, or
    /// malformed key bytes. `ChatError::Io` on filesystem errors.
    pub(crate) fn load_or_create(
        data_dir: &Path,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        let path = data_dir.join(LOCAL_SIGNER_FILE);
        if path.exists() {
            let bytes = open_from_path(&path, master)?;
            let payload: LocalSignerPayload = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("local signer payload parse: {e}")))?;
            if payload.version != 1 {
                return Err(ChatError::Invalid(format!(
                    "local signer vault version {} unsupported (expected 1)",
                    payload.version
                )));
            }
            let pk = B64
                .decode(&payload.ml_dsa_public_key_b64)
                .map_err(|e| ChatError::Invalid(format!("local signer pub b64: {e}")))?;
            let sk = Zeroizing::new(
                B64.decode(&payload.ml_dsa_secret_key_b64)
                    .map_err(|e| ChatError::Invalid(format!("local signer sec b64: {e}")))?,
            );
            let signer = MlDsaSigner::from_bytes(&pk, &sk)
                .map_err(|e| ChatError::Invalid(format!("local signer rebuild: {e}")))?;
            return Ok(Self {
                signer,
                machine_token: payload.machine_token.clone(),
            });
        }

        let signer = MlDsaSigner::generate()
            .map_err(|e| ChatError::Invalid(format!("local signer keygen: {e}")))?;
        let machine_token = hex::encode(fresh_argon_salt());
        let sk_bytes = Zeroizing::new(signer.secret_key_bytes());
        let payload = LocalSignerPayload {
            version: 1,
            ml_dsa_public_key_b64: B64.encode(signer.public_key()),
            ml_dsa_secret_key_b64: B64.encode(sk_bytes.as_slice()),
            machine_token: machine_token.clone(),
        };
        let mut plaintext = serde_json::to_vec(&payload)
            .map_err(|e| ChatError::Invalid(format!("local signer serialize: {e}")))?;
        let seal_result = seal_to_path(&path, &plaintext, master, kdf_id, argon_salt);
        plaintext.zeroize();
        seal_result?;
        Ok(Self {
            signer,
            machine_token,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn test_master(salt: &[u8; crate::at_rest::ARGON_SALT_LEN]) -> MasterKey {
        MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("test-pass".to_owned())),
            Some(salt),
        )
        .unwrap()
    }

    #[test]
    fn create_then_reload_round_trips_agent_id() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);

        let v1 =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();
        let v2 =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();
        assert_eq!(v1.signer.agent_id(), v2.signer.agent_id());
        assert_eq!(v1.machine_token, v2.machine_token);
        assert!(dir.path().join(LOCAL_SIGNER_FILE).exists());
    }

    #[test]
    fn wrong_master_key_errors_instead_of_regenerating() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        let created =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();

        let other_salt = fresh_argon_salt();
        let wrong = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("other-pass".to_owned())),
            Some(&other_salt),
        )
        .unwrap();
        // A decrypt failure must surface as an error — silently minting a
        // fresh identity would orphan every contact pairing.
        let res = LocalSignerVault::load_or_create(
            dir.path(),
            &wrong,
            kdf_id_argon2(),
            Some(&other_salt),
        );
        assert!(res.is_err());
        // and the original vault is untouched
        let again =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();
        assert_eq!(again.signer.agent_id(), created.signer.agent_id());
    }
}
