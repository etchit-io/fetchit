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
use rand::RngCore;
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
    /// Base64 of the 32-byte ML-DSA seed the keypair was derived from.
    /// Present for identities minted seed-first; absent for legacy
    /// randomly-generated vaults, which have no recoverable seed and so
    /// cannot be backed up — those must rotate to a fresh identity to
    /// gain one. Additive and optional, so old and new vaults stay
    /// mutually readable without a version bump.
    #[serde(default)]
    identity_seed_b64: Option<String>,
    /// Random per-install token fed to `derive_machine_id`; NOT derived
    /// from the keypair so a restored identity on a new device still
    /// gets a distinct machine fingerprint.
    machine_token: String,
}

impl Drop for LocalSignerPayload {
    fn drop(&mut self) {
        self.ml_dsa_secret_key_b64.zeroize();
        if let Some(seed) = self.identity_seed_b64.as_mut() {
            seed.zeroize();
        }
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
    /// The same orphaning risk applies across vault files: deleting
    /// `local_signer.json.enc` while `identity.json.enc` survives mints
    /// a fresh agent id on the next build, and the KEM identity then
    /// regenerates to match. Back up or restore the chat data dir as a
    /// unit, never file-by-file.
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

        // Mint seed-first so the identity is backup-recoverable: the
        // 32-byte seed is persisted and `from_seed` reproduces the exact
        // keypair (hence agent id) from it alone.
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signer = MlDsaSigner::from_seed(&seed);
        let vault = Self::persist_new(&path, master, kdf_id, argon_salt, signer, &seed)?;
        seed.zeroize();
        Ok(vault)
    }

    /// Read the 32-byte identity seed from an existing vault, decrypting
    /// only long enough to extract it. The platform layer gates this
    /// behind a biometric prompt before any display. Returns `Ok(None)`
    /// for legacy vaults minted before seed persistence — those
    /// identities have no recoverable seed and must rotate to a fresh
    /// one to gain a backup.
    ///
    /// # Errors
    /// `ChatError::Invalid` if no vault exists, decryption or parsing
    /// fails, or the stored seed is malformed; `ChatError::Io` on
    /// filesystem errors.
    pub(crate) fn reveal_identity_seed(
        data_dir: &Path,
        master: &MasterKey,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, ChatError> {
        let path = data_dir.join(LOCAL_SIGNER_FILE);
        if !path.exists() {
            return Err(ChatError::Invalid(
                "no local signer vault to reveal".to_owned(),
            ));
        }
        let bytes = Zeroizing::new(open_from_path(&path, master)?);
        let payload: LocalSignerPayload = serde_json::from_slice(&bytes)
            .map_err(|e| ChatError::Invalid(format!("local signer payload parse: {e}")))?;
        let Some(seed_b64) = payload.identity_seed_b64.as_ref() else {
            return Ok(None);
        };
        let raw = Zeroizing::new(
            B64.decode(seed_b64)
                .map_err(|e| ChatError::Invalid(format!("local signer seed b64: {e}")))?,
        );
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| ChatError::Invalid("local signer seed wrong length".to_owned()))?;
        Ok(Some(Zeroizing::new(seed)))
    }

    /// Reveal the identity backup seed encoded as its 24-word BIP39
    /// recovery phrase, ready to display for safekeeping. `Ok(None)` for
    /// legacy vaults with no recoverable seed (see [`Self::reveal_identity_seed`]).
    ///
    /// # Errors
    /// Propagates [`Self::reveal_identity_seed`] failures, plus
    /// `ChatError::Invalid` if the BIP39 encoder rejects the seed.
    pub(crate) fn reveal_recovery_phrase(
        data_dir: &Path,
        master: &MasterKey,
    ) -> Result<Option<Zeroizing<String>>, ChatError> {
        match Self::reveal_identity_seed(data_dir, master)? {
            Some(seed) => Ok(Some(crate::recovery_phrase::seed_to_recovery_phrase(&seed)?)),
            None => Ok(None),
        }
    }

    /// Seal a NEW vault whose identity is derived from a restored backup
    /// `seed`, reproducing the exact ML-DSA agent id. Refuses (does not
    /// overwrite) when a local signer vault already exists under `data_dir`,
    /// so restore can never clobber a live identity.
    ///
    /// # Errors
    /// `ChatError::Invalid` if a vault already exists; otherwise as
    /// [`Self::persist_new`].
    pub(crate) fn restore_from_seed(
        data_dir: &Path,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
        seed: &[u8; 32],
    ) -> Result<Self, ChatError> {
        let path = data_dir.join(LOCAL_SIGNER_FILE);
        if path.exists() {
            return Err(ChatError::Invalid(
                "a local signer identity already exists under this data dir; \
                 refusing to overwrite it on restore"
                    .to_owned(),
            ));
        }
        let signer = MlDsaSigner::from_seed(seed);
        Self::persist_new(&path, master, kdf_id, argon_salt, signer, seed)
    }

    /// Seal a brand-new vault for `signer` derived from `seed`. Shared by
    /// fresh-identity creation and seed restore.
    fn persist_new(
        path: &Path,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
        signer: MlDsaSigner,
        seed: &[u8; 32],
    ) -> Result<Self, ChatError> {
        let machine_token = hex::encode(fresh_argon_salt());
        let sk_bytes = Zeroizing::new(signer.secret_key_bytes());
        let payload = LocalSignerPayload {
            version: 1,
            ml_dsa_public_key_b64: B64.encode(signer.public_key()),
            ml_dsa_secret_key_b64: B64.encode(sk_bytes.as_slice()),
            identity_seed_b64: Some(B64.encode(seed)),
            machine_token: machine_token.clone(),
        };
        let mut plaintext = serde_json::to_vec(&payload)
            .map_err(|e| ChatError::Invalid(format!("local signer serialize: {e}")))?;
        let seal_result = seal_to_path(path, &plaintext, master, kdf_id, argon_salt);
        plaintext.zeroize();
        seal_result?;
        Ok(Self {
            signer,
            machine_token,
        })
    }
}

/// Reveal the 32-byte identity backup seed for the local signing
/// identity stored under `data_dir`, deriving the vault master key from
/// `passphrase` (`None` = OS-keychain custody, the desktop default).
///
/// Returns `Ok(None)` for legacy identities minted before seed backup
/// existed — those have no recoverable seed and must rotate to a fresh
/// identity to gain one. The platform layer is responsible for gating
/// this call behind a biometric prompt before the seed is shown.
///
/// # Errors
/// `ChatError::Invalid` if no identity vault exists under `data_dir`, the
/// passphrase is wrong, or stored material is malformed; `ChatError::Io`
/// on filesystem errors.
pub fn reveal_local_signer_seed(
    data_dir: &Path,
    passphrase: Option<&str>,
) -> Result<Option<Zeroizing<[u8; 32]>>, ChatError> {
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    LocalSignerVault::reveal_identity_seed(data_dir, &master)
}

/// Reveal the local signing identity's 24-word BIP39 recovery phrase for the
/// identity stored under `data_dir`, deriving the vault master key from
/// `passphrase` (`None` = OS-keychain custody, the desktop default).
/// `Ok(None)` for legacy identities minted before seed backup
/// existed. The platform layer must gate this behind a biometric / re-auth
/// prompt before the phrase is shown.
///
/// # Errors
/// As [`reveal_local_signer_seed`], plus `ChatError::Invalid` if the stored
/// seed cannot be BIP39-encoded.
pub fn reveal_local_signer_recovery_phrase(
    data_dir: &Path,
    passphrase: Option<&str>,
) -> Result<Option<Zeroizing<String>>, ChatError> {
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    LocalSignerVault::reveal_recovery_phrase(data_dir, &master)
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

    #[test]
    fn new_identity_persists_recoverable_seed() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        let vault =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();
        let seed = LocalSignerVault::reveal_identity_seed(dir.path(), &master)
            .unwrap()
            .expect("a freshly minted identity has a recoverable seed");
        // The persisted seed reconstructs the exact same identity.
        let rebuilt = MlDsaSigner::from_seed(&seed);
        assert_eq!(rebuilt.agent_id(), vault.signer.agent_id());
    }

    #[test]
    fn reveal_seed_is_stable_across_reload() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        let _ = LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let s1 = LocalSignerVault::reveal_identity_seed(dir.path(), &master)
            .unwrap()
            .unwrap();
        let _ = LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let s2 = LocalSignerVault::reveal_identity_seed(dir.path(), &master)
            .unwrap()
            .unwrap();
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn reveal_returns_none_for_legacy_vault_without_seed() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        // Hand-seal a v1 payload with NO identity_seed_b64 (a pre-backup
        // vault). reveal must report it has no recoverable seed.
        let legacy = serde_json::json!({
            "version": 1,
            "ml_dsa_public_key_b64": "AA",
            "ml_dsa_secret_key_b64": "AA",
            "machine_token": "deadbeef",
        });
        let plaintext = serde_json::to_vec(&legacy).unwrap();
        let path = dir.path().join(LOCAL_SIGNER_FILE);
        seal_to_path(&path, &plaintext, &master, kdf_id_argon2(), Some(&salt)).unwrap();
        let revealed = LocalSignerVault::reveal_identity_seed(dir.path(), &master).unwrap();
        assert!(revealed.is_none());
    }

    #[test]
    fn reveal_recovery_phrase_round_trips_to_the_seed() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        let _ = LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let seed = LocalSignerVault::reveal_identity_seed(dir.path(), &master)
            .unwrap()
            .unwrap();
        let phrase = LocalSignerVault::reveal_recovery_phrase(dir.path(), &master)
            .unwrap()
            .unwrap();
        // A 24-word BIP39 phrase that decodes back to the exact backup seed.
        assert_eq!(phrase.split_whitespace().count(), 24);
        let back = crate::recovery_phrase::recovery_phrase_to_seed(&phrase).unwrap();
        assert_eq!(*back, *seed);
    }

    #[test]
    fn reveal_recovery_phrase_is_none_for_legacy_vault() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        let legacy = serde_json::json!({
            "version": 1,
            "ml_dsa_public_key_b64": "AA",
            "ml_dsa_secret_key_b64": "AA",
            "machine_token": "deadbeef",
        });
        let plaintext = serde_json::to_vec(&legacy).unwrap();
        let path = dir.path().join(LOCAL_SIGNER_FILE);
        seal_to_path(&path, &plaintext, &master, kdf_id_argon2(), Some(&salt)).unwrap();
        assert!(LocalSignerVault::reveal_recovery_phrase(dir.path(), &master)
            .unwrap()
            .is_none());
    }
}
