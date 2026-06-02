//! At-rest encryption vault for fetchit-chat secrets.
//!
//! Files ending `.json.enc` are AEAD-sealed with a device-local
//! master key. The master key is held in the OS keystore; when that
//! is unavailable (headless Linux, etc.), a passphrase derives it
//! via Argon2id.
//!
//! Wire format of a `.enc` file (header + ciphertext, no JSON):
//! ```text
//! [u8;  4] magic       = "FCV1"
//! [u8;  1] kdf_id      = 0 (keychain) | 1 (Argon2id passphrase)
//! [u8; 16] argon_salt  = zero when kdf_id=0
//! [u8; 12] nonce       (ChaCha20-Poly1305)
//! [u8;  N] ciphertext + tag (AEAD output)
//! ```
//!
//! Argon2id parameters: m=64 MiB, t=3, p=4. These are the OWASP-
//! recommended defaults for interactive logins as of 2024.

use crate::chat_crypto::{aead_open, aead_seal, random_nonce, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use crate::error::ChatError;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// File magic identifying a FCV1 vault.
pub const VAULT_MAGIC: &[u8; 4] = b"FCV1";
/// Argon2 salt length in bytes.
pub const ARGON_SALT_LEN: usize = 16;
/// Total header length: magic + `kdf_id` + salt + nonce.
pub const HEADER_LEN: usize = 4 + 1 + ARGON_SALT_LEN + AEAD_NONCE_LEN;

const KDF_ID_KEYCHAIN: u8 = 0;
const KDF_ID_ARGON2: u8 = 1;

const KEYRING_SERVICE: &str = "fetchit-chat-v1";
const KEYRING_USER: &str = "master-key";

/// How the master key is sourced.
#[derive(Clone, Debug)]
pub enum MasterKeySource {
    /// Pulled from the OS keystore (macOS Keychain, Linux Secret Service,
    /// Windows DPAPI). Created on first use, fetched thereafter.
    Keychain,
    /// Derived from a passphrase via Argon2id. Used when no keystore is
    /// available. The inner `Zeroizing<String>` clears its heap bytes
    /// when dropped so the user's passphrase doesn't linger in memory.
    Passphrase(Zeroizing<String>),
}

/// 32-byte symmetric key used for vault seal/open.
///
/// Derives `ZeroizeOnDrop` so the key material is wiped from memory the
/// moment the value (or any clone) goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; AEAD_KEY_LEN]);

impl MasterKey {
    /// Borrow the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.0
    }

    /// Resolve a master key from the requested source.
    ///
    /// For `Keychain`: returns the existing key, or generates a fresh
    /// one and stores it on first use. For `Passphrase`: the salt is
    /// supplied by the caller (read from an existing vault file or
    /// generated fresh on first use).
    ///
    /// # Errors
    /// `ChatError::Invalid` if the keystore is unreachable or the
    /// Argon2id derivation fails.
    pub fn resolve(
        source: &MasterKeySource,
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        match source {
            MasterKeySource::Keychain => Self::resolve_keychain(),
            MasterKeySource::Passphrase(p) => {
                let salt = argon_salt.ok_or_else(|| {
                    ChatError::Invalid("passphrase mode requires an argon_salt".into())
                })?;
                Self::resolve_passphrase(p, salt)
            }
        }
    }

    fn resolve_keychain() -> Result<Self, ChatError> {
        Self::resolve_keychain_with_service(KEYRING_SERVICE, KEYRING_USER)
    }

    /// Keychain resolve against an arbitrary service/user pair.
    ///
    /// Production code calls [`Self::resolve_keychain`] which uses the
    /// fixed `fetchit-chat-v1` / `master-key` pair. Tests use a distinct
    /// service name so they never read or write the user's real master
    /// key. Kept `pub(crate)` — not part of the public API.
    pub(crate) fn resolve_keychain_with_service(
        service: &str,
        user: &str,
    ) -> Result<Self, ChatError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let entry = keyring::Entry::new(service, user)
            .map_err(|e| ChatError::Invalid(format!("keyring open: {e}")))?;
        match entry.get_password() {
            Ok(b64) => {
                let bytes = B64
                    .decode(&b64)
                    .map_err(|e| ChatError::Invalid(format!("keyring decode: {e}")))?;
                if bytes.len() != AEAD_KEY_LEN {
                    return Err(ChatError::Invalid("keyring entry wrong length".into()));
                }
                let mut k = [0u8; AEAD_KEY_LEN];
                k.copy_from_slice(&bytes);
                Ok(Self(k))
            }
            Err(keyring::Error::NoEntry) => {
                let mut k = [0u8; AEAD_KEY_LEN];
                rand::rngs::OsRng.fill_bytes(&mut k);
                let b64 = B64.encode(k);
                entry
                    .set_password(&b64)
                    .map_err(|e| ChatError::Invalid(format!("keyring set: {e}")))?;
                Ok(Self(k))
            }
            Err(e) => Err(ChatError::Invalid(format!("keyring get: {e}"))),
        }
    }

    fn resolve_passphrase(
        passphrase: &str,
        salt: &[u8; ARGON_SALT_LEN],
    ) -> Result<Self, ChatError> {
        let params = Params::new(64 * 1024, 3, 4, Some(AEAD_KEY_LEN))
            .map_err(|e| ChatError::Invalid(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; AEAD_KEY_LEN];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| ChatError::Invalid(format!("argon2 hash: {e}")))?;
        Ok(Self(out))
    }
}

/// AEAD-seal `plaintext` under the master key with vault header metadata.
/// Writes header + ciphertext to `path` atomically (`path.tmp` then rename).
///
/// `argon_salt` must be `Some` when the master was passphrase-derived.
///
/// # Errors
/// IO or AEAD errors.
pub fn seal_to_path(
    path: &Path,
    plaintext: &[u8],
    master: &MasterKey,
    kdf_id: u8,
    argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
) -> Result<(), ChatError> {
    use std::io::Write;

    let mut rng = rand::rngs::OsRng;
    let nonce = random_nonce(&mut rng);
    let aad = b"lit/vault/v1";
    let ct = aead_seal(master.as_bytes(), &nonce, plaintext, aad)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(kdf_id);
    out.extend_from_slice(argon_salt.unwrap_or(&[0u8; ARGON_SALT_LEN]));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Unique tmp suffix so concurrent writes to the same target don't
    // race on a shared `*.tmp` file.
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp_name = format!(
        "{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"),
        hex::encode(suffix),
    );
    let tmp = path.with_file_name(tmp_name);

    // Create with owner-only mode at open time so there's no umask
    // window between creation and chmod. `create_new` paired with the
    // random suffix guarantees a fresh inode.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&out)?;
    drop(f);

    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read + AEAD-open a vault file under the master key.
///
/// Returns the plaintext bytes. The vault header is consumed and not
/// returned — callers read the salt separately via [`read_argon_salt`]
/// when bootstrapping a passphrase-mode session.
///
/// # Errors
/// IO, malformed-header, AEAD failures (tag mismatch).
pub fn open_from_path(path: &Path, master: &MasterKey) -> Result<Vec<u8>, ChatError> {
    let bytes = fs::read(path)?;
    if bytes.len() < HEADER_LEN {
        return Err(ChatError::Invalid("vault file too short".into()));
    }
    if &bytes[..4] != VAULT_MAGIC {
        return Err(ChatError::Invalid("vault magic mismatch".into()));
    }
    let nonce_start = 4 + 1 + ARGON_SALT_LEN;
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&bytes[nonce_start..nonce_start + AEAD_NONCE_LEN]);
    let ct = &bytes[HEADER_LEN..];
    let aad = b"lit/vault/v1";
    aead_open(master.as_bytes(), &nonce, ct, aad)
}

/// Inspect a vault file's KDF id without decrypting. Useful at boot to
/// decide whether to prompt for a passphrase.
///
/// # Errors
/// IO or malformed-header.
pub fn read_kdf_id(path: &Path) -> Result<u8, ChatError> {
    use std::io::Read;
    let mut buf = [0u8; 5];
    let mut f = fs::File::open(path)?;
    f.read_exact(&mut buf)?;
    if &buf[..4] != VAULT_MAGIC {
        return Err(ChatError::Invalid("vault magic mismatch".into()));
    }
    Ok(buf[4])
}

/// Inspect a vault file's Argon2 salt. Returns the salt only when
/// `kdf_id == Argon2id`; otherwise returns an error.
///
/// # Errors
/// IO, malformed-header, or non-passphrase vault.
pub fn read_argon_salt(path: &Path) -> Result<[u8; ARGON_SALT_LEN], ChatError> {
    use std::io::Read;
    let mut buf = [0u8; 4 + 1 + ARGON_SALT_LEN];
    let mut f = fs::File::open(path)?;
    f.read_exact(&mut buf)?;
    if &buf[..4] != VAULT_MAGIC {
        return Err(ChatError::Invalid("vault magic mismatch".into()));
    }
    if buf[4] != KDF_ID_ARGON2 {
        return Err(ChatError::Invalid("vault is not passphrase-mode".into()));
    }
    let mut salt = [0u8; ARGON_SALT_LEN];
    salt.copy_from_slice(&buf[5..5 + ARGON_SALT_LEN]);
    Ok(salt)
}

/// Generate a fresh Argon2 salt.
#[must_use]
pub fn fresh_argon_salt() -> [u8; ARGON_SALT_LEN] {
    let mut salt = [0u8; ARGON_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// KDF identifier for keystore-resolved master keys.
#[must_use]
pub fn kdf_id_keychain() -> u8 {
    KDF_ID_KEYCHAIN
}
/// KDF identifier for passphrase-resolved (Argon2id) master keys.
#[must_use]
pub fn kdf_id_argon2() -> u8 {
    KDF_ID_ARGON2
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    #[test]
    fn master_key_implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MasterKey>();
    }

    #[test]
    fn master_key_zeroize_clears_bytes() {
        let salt = fresh_argon_salt();
        let mut master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        // Sanity: the derived key is not already all-zero.
        assert_ne!(master.as_bytes(), &[0u8; AEAD_KEY_LEN]);
        master.zeroize();
        assert_eq!(master.as_bytes(), &[0u8; AEAD_KEY_LEN]);
    }

    #[test]
    fn passphrase_source_carries_zeroizing_string() {
        let src = MasterKeySource::Passphrase(Zeroizing::new("hunter2".to_owned()));
        match src {
            MasterKeySource::Passphrase(z) => {
                let _: &Zeroizing<String> = &z;
                assert_eq!(&*z, "hunter2");
            }
            MasterKeySource::Keychain => panic!("expected Passphrase"),
        }
    }

    #[test]
    fn passphrase_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("hunter2".into())),
            Some(&salt),
        )
        .unwrap();
        let plaintext = b"top secret bytes";
        seal_to_path(&path, plaintext, &master, kdf_id_argon2(), Some(&salt)).unwrap();
        let opened = open_from_path(&path, &master).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m1 = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("a".into())),
            Some(&salt),
        )
        .unwrap();
        seal_to_path(&path, b"x", &m1, kdf_id_argon2(), Some(&salt)).unwrap();
        let m2 = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("b".into())),
            Some(&salt),
        )
        .unwrap();
        assert!(open_from_path(&path, &m2).is_err());
    }

    #[test]
    fn read_kdf_id_matches_seal_kdf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        seal_to_path(&path, b"x", &m, kdf_id_argon2(), Some(&salt)).unwrap();
        assert_eq!(read_kdf_id(&path).unwrap(), kdf_id_argon2());
    }

    #[test]
    fn read_argon_salt_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        seal_to_path(&path, b"x", &m, kdf_id_argon2(), Some(&salt)).unwrap();
        let recovered = read_argon_salt(&path).unwrap();
        assert_eq!(recovered, salt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        seal_to_path(
            &path,
            b"some_bytes_for_testing",
            &m,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(open_from_path(&path, &m).is_err());
    }

    #[test]
    #[ignore = "requires OS keystore (Linux Secret Service / macOS Keychain / Windows DPAPI)"]
    fn keychain_round_trip() {
        // Test-only service/user pair — must not collide with the
        // production constants or a developer running `--ignored`
        // would overwrite their real master key.
        const TEST_SERVICE: &str = "fetchit-chat-test-v1";
        const TEST_USER: &str = "keychain-round-trip";
        assert_ne!(TEST_SERVICE, KEYRING_SERVICE);

        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let master = MasterKey::resolve_keychain_with_service(TEST_SERVICE, TEST_USER).unwrap();
        seal_to_path(
            &path,
            b"keychain stored secret",
            &master,
            kdf_id_keychain(),
            None,
        )
        .unwrap();
        let opened = open_from_path(&path, &master).unwrap();
        assert_eq!(opened, b"keychain stored secret");

        // Best-effort cleanup so re-running the test starts fresh.
        if let Ok(entry) = keyring::Entry::new(TEST_SERVICE, TEST_USER) {
            let _ = entry.delete_credential();
        }
    }
}
