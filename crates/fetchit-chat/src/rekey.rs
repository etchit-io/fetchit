//! Vault custody rekey: re-seal every at-rest file under a new master
//! key, switching between OS-keychain and Argon2id-passphrase custody.
//!
//! Order matters: conversations and fedi actor identities first,
//! `identity.json.enc` LAST. The identity header is the custody-mode
//! authority `resolve_master_key` consults at boot, so a crash before
//! the final write leaves the store fully bootable under the old key.
//! Each file is resumable: one that no longer opens under the old key
//! but opens under the new key is counted as already migrated.
//!
//! Honest caveat: a keychain-target rekey rotates the keychain entry
//! before the file pass. A crash inside the pass can strand
//! not-yet-migrated files with no recoverable key. The window is one
//! file loop; the documented product recovery floor (new identity,
//! contacts re-added by QR) applies. Do not "fix" this with a
//! key-next-to-data escrow file.

use crate::at_rest::{
    fresh_argon_salt, kdf_id_argon2, kdf_id_keychain, open_from_path, read_kdf_id,
    rotate_keychain_master, seal_to_path, MasterKey, MasterKeySource, ARGON_SALT_LEN,
};
use crate::error::ChatError;
use crate::fedi_vault::{load_actor_identity, save_actor_identity};
use crate::local_store::StoreLayout;
use std::path::Path;
use zeroize::Zeroizing;

const IDENTITY_FILE: &str = "identity.json.enc";
const ENC_SUFFIX: &str = ".json.enc";

/// Which custody mode the on-disk vault is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyStatus {
    /// No identity vault exists yet (chat never booted).
    NoVault,
    /// Master key lives in the OS keystore.
    Keychain,
    /// Master key derives from a user passphrase (Argon2id).
    Passphrase,
}

/// Report the custody mode by inspecting the identity vault header.
#[must_use]
pub fn custody_status(root: &Path) -> CustodyStatus {
    let identity = root.join(IDENTITY_FILE);
    if !identity.exists() {
        return CustodyStatus::NoVault;
    }
    match read_kdf_id(&identity) {
        Ok(k) if k == kdf_id_argon2() => CustodyStatus::Passphrase,
        Ok(_) => CustodyStatus::Keychain,
        Err(_) => CustodyStatus::NoVault,
    }
}

/// Re-seal every vault file under `new`. Returns the number of files
/// rewritten (already-migrated files are skipped and not counted).
///
/// # Errors
/// `ChatError` when any file opens under neither key, or on IO/AEAD
/// failures. On error the identity file has not been rewritten.
pub fn rekey_store_files(
    layout: &StoreLayout,
    old: &MasterKey,
    new: &MasterKey,
    new_kdf_id: u8,
    new_salt: Option<&[u8; ARGON_SALT_LEN]>,
) -> Result<usize, ChatError> {
    let mut rewritten = 0usize;
    for entry in list_enc_files(&layout.conversations_dir)? {
        rewritten += rekey_fcv1_file(&entry, old, new, new_kdf_id, new_salt)?;
    }
    rewritten += rekey_fedi_dir(layout, old, new)?;
    let identity = layout.root.join(IDENTITY_FILE);
    if identity.exists() {
        rewritten += rekey_fcv1_file(&identity, old, new, new_kdf_id, new_salt)?;
    }
    Ok(rewritten)
}

/// Orchestrated custody switch for a store rooted at `root`.
///
/// `current_passphrase` unlocks the existing vault when it is in
/// passphrase mode (ignored in keychain mode). `new_passphrase = Some`
/// targets passphrase custody under a fresh salt; `None` targets
/// keychain custody under a freshly rotated keychain key.
///
/// No vault on disk is a no-op returning `Ok(0)`: the caller sets the
/// passphrase the next client build will use instead.
///
/// # Errors
/// Key resolution, IO, or AEAD failures; see [`rekey_store_files`].
pub fn rekey_to(
    root: &Path,
    current_passphrase: Option<&str>,
    new_passphrase: Option<&str>,
) -> Result<usize, ChatError> {
    let layout = StoreLayout::ensure(root.to_path_buf())?;
    let identity = layout.root.join(IDENTITY_FILE);
    if !identity.exists() {
        return Ok(0);
    }
    let (old, _kdf, _salt) = crate::client::resolve_master_key(&identity, current_passphrase)?;
    if let Some(pass) = new_passphrase {
        if pass.trim().is_empty() {
            return Err(ChatError::Invalid("passphrase must not be empty".into()));
        }
        let salt = fresh_argon_salt();
        let new = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new(pass.to_owned())),
            Some(&salt),
        )?;
        rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&salt))
    } else {
        let new = rotate_keychain_master()?;
        rekey_store_files(&layout, &old, &new, kdf_id_keychain(), None)
    }
}

fn list_enc_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, ChatError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && path.to_string_lossy().ends_with(ENC_SUFFIX) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Returns 1 when the file was rewritten, 0 when already migrated.
fn rekey_fcv1_file(
    path: &Path,
    old: &MasterKey,
    new: &MasterKey,
    new_kdf_id: u8,
    new_salt: Option<&[u8; ARGON_SALT_LEN]>,
) -> Result<usize, ChatError> {
    match open_from_path(path, old) {
        Ok(plain) => {
            seal_to_path(path, &plain, new, new_kdf_id, new_salt)?;
            Ok(1)
        }
        Err(_) if open_from_path(path, new).is_ok() => Ok(0),
        Err(e) => Err(ChatError::Invalid(format!(
            "rekey: {} opens under neither key: {e}",
            path.display()
        ))),
    }
}

/// Fedi actor identities are sealed under an HKDF of the master key
/// (`fedi_identity::derive_fedi_vault_key`), so a master change must
/// re-seal them too. Same skip-if-already-new resume rule.
fn rekey_fedi_dir(
    layout: &StoreLayout,
    old: &MasterKey,
    new: &MasterKey,
) -> Result<usize, ChatError> {
    let mut rewritten = 0usize;
    for path in list_enc_files(&layout.fedi_dir)? {
        let Some(handle) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(ENC_SUFFIX))
        else {
            continue;
        };
        match load_actor_identity(handle, old, layout) {
            Ok(Some(vault)) => {
                save_actor_identity(&vault, new, layout)?;
                rewritten += 1;
            }
            Ok(None) => {}
            Err(_) if load_actor_identity(handle, new, layout).is_ok() => {}
            Err(e) => {
                return Err(ChatError::Invalid(format!(
                    "rekey: fedi vault {} opens under neither key: {e}",
                    path.display()
                )));
            }
        }
    }
    Ok(rewritten)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use crate::fedi_vault::ActorIdentityVault;
    use fetchit_fedi::attestation::MlDsaAttestation;
    use tempfile::tempdir;

    fn master(b: u8) -> MasterKey {
        MasterKey::from_bytes_for_test([b; AEAD_KEY_LEN])
    }

    fn seed_store(root: &Path, m: &MasterKey, salt: &[u8; ARGON_SALT_LEN]) -> StoreLayout {
        let layout = StoreLayout::ensure(root.to_path_buf()).unwrap();
        seal_to_path(
            &layout.conversation_path("aa"),
            b"conv-a",
            m,
            kdf_id_argon2(),
            Some(salt),
        )
        .unwrap();
        seal_to_path(
            &layout.conversation_path("bb"),
            b"conv-b",
            m,
            kdf_id_argon2(),
            Some(salt),
        )
        .unwrap();
        seal_to_path(
            &layout.root.join(IDENTITY_FILE),
            b"identity",
            m,
            kdf_id_argon2(),
            Some(salt),
        )
        .unwrap();
        layout
    }

    fn sample_actor() -> ActorIdentityVault {
        ActorIdentityVault {
            handle: "josh".into(),
            actor_url: "https://etchit.io/actors/josh".parse().unwrap(),
            agent_id_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            rsa_priv_pem:
                "-----BEGIN PRIVATE KEY-----\nsynthetic-test-key\n-----END PRIVATE KEY-----\n"
                    .into(),
            spki_der: vec![0xDE, 0xAD, 0xBE, 0xEF],
            ml_dsa_attestation: MlDsaAttestation::new(vec![0xAA; 32], vec![0xBB; 64]),
        }
    }

    #[test]
    fn rekey_flips_every_file_and_contents_survive() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        let n = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).unwrap();
        assert_eq!(n, 3);
        for p in [
            layout.conversation_path("aa"),
            layout.conversation_path("bb"),
            layout.root.join(IDENTITY_FILE),
        ] {
            assert!(
                open_from_path(&p, &old).is_err(),
                "{} still opens under old",
                p.display()
            );
            let plain = open_from_path(&p, &new).unwrap();
            assert!(!plain.is_empty());
        }
    }

    #[test]
    fn rekey_skips_files_already_under_the_new_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        seal_to_path(
            &layout.conversation_path("aa"),
            b"conv-a",
            &new,
            kdf_id_argon2(),
            Some(&new_salt),
        )
        .unwrap();
        let n = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).unwrap();
        assert_eq!(n, 2, "already-migrated file is skipped, not an error");
        assert!(open_from_path(&layout.conversation_path("aa"), &new).is_ok());
    }

    #[test]
    fn rekey_errors_when_a_file_opens_under_neither_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        seal_to_path(
            &layout.conversation_path("cc"),
            b"alien",
            &master(9),
            kdf_id_argon2(),
            Some(&old_salt),
        )
        .unwrap();
        assert!(rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).is_err());
    }

    #[test]
    fn conversation_failure_leaves_identity_under_the_old_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        seal_to_path(
            &layout.conversation_path("cc"),
            b"alien",
            &master(9),
            kdf_id_argon2(),
            Some(&old_salt),
        )
        .unwrap();
        let _ = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt));
        // Identity is rewritten last, so the failed pass must not have
        // touched it: the store still boots under the old key.
        assert!(open_from_path(&layout.root.join(IDENTITY_FILE), &old).is_ok());
    }

    #[test]
    fn rekey_reseals_fedi_actor_identities_under_the_new_derived_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        let actor = sample_actor();
        save_actor_identity(&actor, &old, &layout).unwrap();

        let n = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).unwrap();
        assert_eq!(n, 4, "three FCV1 files + one fedi vault");
        assert!(load_actor_identity("josh", &old, &layout).is_err());
        let recovered = load_actor_identity("josh", &new, &layout).unwrap().unwrap();
        assert_eq!(recovered, actor);
    }

    #[test]
    fn custody_status_reports_mode_from_identity_header() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        assert_eq!(custody_status(&layout.root), CustodyStatus::NoVault);
        let salt = fresh_argon_salt();
        seal_to_path(
            &layout.root.join(IDENTITY_FILE),
            b"identity",
            &master(1),
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(custody_status(&layout.root), CustodyStatus::Passphrase);
    }

    #[test]
    fn rekey_to_without_a_vault_is_a_noop() {
        let dir = tempdir().unwrap();
        assert_eq!(rekey_to(dir.path(), None, Some("hunter2")).unwrap(), 0);
    }

    #[test]
    fn rekey_to_rejects_blank_passphrase() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        seed_store(dir.path(), &master(1), &salt);
        assert!(rekey_to(dir.path(), None, Some("  ")).is_err());
    }

    #[test]
    fn rekey_to_passphrase_to_passphrase_round_trips() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        // Seed a REAL passphrase-mode store so resolve_master_key can
        // unlock it from the header + supplied passphrase alone.
        let m1 = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("first".into())),
            Some(&salt),
        )
        .unwrap();
        let layout = seed_store(dir.path(), &m1, &salt);
        let n = rekey_to(dir.path(), Some("first"), Some("second")).unwrap();
        assert_eq!(n, 3);
        // The store now opens under the "second" passphrase with the
        // fresh salt written into the identity header.
        let new_salt = crate::at_rest::read_argon_salt(&layout.root.join(IDENTITY_FILE)).unwrap();
        assert_ne!(new_salt, salt);
        let m2 = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("second".into())),
            Some(&new_salt),
        )
        .unwrap();
        assert!(open_from_path(&layout.root.join(IDENTITY_FILE), &m2).is_ok());
    }

    #[test]
    #[ignore = "requires OS keystore (Linux Secret Service / macOS Keychain / Windows DPAPI)"]
    fn rekey_to_keychain_round_trip() {
        // Exercises the real keystore: passphrase -> keychain -> files
        // open under the rotated keychain key. Run explicitly on a box
        // with a live Secret Service; never in CI.
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let m1 = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("first".into())),
            Some(&salt),
        )
        .unwrap();
        let layout = seed_store(dir.path(), &m1, &salt);
        let n = rekey_to(dir.path(), Some("first"), None).unwrap();
        assert_eq!(n, 3);
        assert_eq!(custody_status(&layout.root), CustodyStatus::Keychain);
    }
}
