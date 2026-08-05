//! Encrypted-at-rest persistence for fediverse-bridge actor
//! identities.
//!
//! Sealed under a key HKDF-derived from the chat-identity master key
//! via [`derive_fedi_vault_key`] so a compromise of the fedi-vault key
//! cannot decrypt conversation vaults and vice versa, even though both
//! live under one unlock surface.
//!
//! On-disk file format (`<root>/fedi/<handle>.json.enc`):
//!
//! ```text
//! [u8;  4] magic     = "FFV1"
//! [u8; 12] nonce     (ChaCha20-Poly1305)
//! [u8;  N] ciphertext + tag (AEAD output over JSON-serialised vault)
//! ```
//!
//! No KDF id / salt in the header: the fedi-vault key is always
//! HKDF-derived from the chat-identity master, and the master's own
//! derivation chain is recorded in the chat vault header (not
//! duplicated here).

use crate::at_rest::MasterKey;
use crate::chat_crypto::{aead_open, aead_seal, random_nonce, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use crate::error::ChatError;
use crate::fedi_identity::derive_fedi_vault_key;
use crate::local_store::StoreLayout;
use fetchit_fedi::attestation::MlDsaAttestation;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// File magic identifying a Fetchit Fedi Vault v1 file.
pub const FEDI_VAULT_MAGIC: &[u8; 4] = b"FFV1";

/// AAD bound into every AEAD seal/open. Domain-separated from the
/// chat vault's `lit/vault/v1` AAD so a swapped-blob attack between
/// the two vault families fails the tag check.
pub const FEDI_VAULT_AAD: &[u8] = b"fetchit-fedi-vault-v1";

/// Wire-header length: magic + nonce.
pub const FEDI_HEADER_LEN: usize = 4 + AEAD_NONCE_LEN;

/// Persistent record of a minted fediverse actor identity.
///
/// Serialised via serde JSON to the encrypted vault. The byte fields of
/// the embedded [`MlDsaAttestation`] go through the `b64` serde-with
/// helper on the fedi-side type so the encoding is canonical
/// everywhere the attestation appears (vault, JSON-LD Actor).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorIdentityVault {
    /// Handle local-part, e.g. `"josh"` for `@josh@etchit.io`.
    pub handle: String,
    /// Canonical actor URL.
    pub actor_url: url::Url,
    /// 64-hex chat agent id this actor is bound to.
    pub agent_id_hex: String,
    /// RSA-2048 private key in PEM PKCS#8 form.
    pub rsa_priv_pem: String,
    /// `SubjectPublicKeyInfo` DER bytes of the RSA-2048 public key.
    /// Persisted alongside the private PEM so JSON-LD rendering (via
    /// [`fetchit_fedi::actor::Actor::from_identity`]) can emit
    /// `publicKeyPem` without a fedi-side RSA parser dep.
    pub spki_der: Vec<u8>,
    /// ML-DSA-65 attestation binding the RSA pubkey to the
    /// chat-identity key.
    pub ml_dsa_attestation: MlDsaAttestation,
    /// v2 attestation (adds profile addr + relay hint to the signed
    /// binding). `None` on records minted before M5; the upgrade path
    /// re-signs in place without touching the RSA material.
    #[serde(default)]
    pub ml_dsa_attestation_v2: Option<fetchit_fedi::attestation::ActorAttestationV2>,
    /// The `icon` URL published on the actor document, set when the user
    /// picks a profile picture. `None` means no picture. Nothing here is
    /// secret — it rides the vault because it is part of the actor
    /// identity the document is rendered from.
    #[serde(default)]
    pub icon_url: Option<String>,
    /// `mediaType` published beside [`Self::icon_url`].
    #[serde(default)]
    pub icon_media_type: Option<String>,
}

/// Seal an [`ActorIdentityVault`] under the master-derived fedi key
/// and atomically write to `layout.actor_identity_path(&vault.handle)`.
///
/// Atomic semantics: writes to a uniquely-named `<final>.tmp.<hex>`
/// sibling at `0o600` mode (Unix), then `rename`s into place. The
/// random suffix means concurrent writers targeting the same handle
/// can't race on the temp file.
///
/// # Errors
/// - [`ChatError::Invalid`] wrapping serde-json failures.
/// - [`ChatError::Invalid`] wrapping AEAD failures (none expected for
///   well-formed input; the error path exists for forward-compat).
/// - [`ChatError`] for IO failures on the parent-dir create, the
///   tmp-file open, or the rename.
pub fn save_actor_identity(
    vault: &ActorIdentityVault,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<(), ChatError> {
    let key = derive_fedi_vault_key(master);
    let plain =
        serde_json::to_vec(vault).map_err(|e| ChatError::Invalid(format!("vault encode: {e}")))?;
    write_sealed_atomic(
        &layout.actor_identity_path(&vault.handle),
        *FEDI_VAULT_MAGIC,
        &key,
        FEDI_VAULT_AAD,
        &plain,
    )
}

/// Seal `plain` under `key`/`aad` and atomically write
/// `magic ‖ nonce ‖ ciphertext` to `path`: 0600 permissions, unique tmp
/// name, rename into place, tmp cleaned up on any failure (per Alice
/// \[F1\]). Shared by this identity vault and the fedi DM thread store
/// ([`crate::fedi_thread`]) so both file families ride one reviewed
/// writer.
pub(crate) fn write_sealed_atomic(
    path: &Path,
    magic: [u8; 4],
    key: &[u8; AEAD_KEY_LEN],
    aad: &[u8],
    plain: &[u8],
) -> Result<(), ChatError> {
    use std::io::Write;

    let mut rng = OsRng;
    let nonce = random_nonce(&mut rng);
    let ct = aead_seal(key, &nonce, plain, aad)?;

    let mut out = Vec::with_capacity(FEDI_HEADER_LEN + ct.len());
    out.extend_from_slice(&magic);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let tmp_name = format!(
        "{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"),
        hex::encode(suffix),
    );
    let tmp = path.with_file_name(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    // Activate cleanup AFTER successful open — the guard removes `tmp`
    // on any panic or `?` early-return until the final rename succeeds.
    // Prevents `.tmp.<hex>` debris in `fedi_dir` from transient IO
    // errors (per Alice [F1]).
    let guard = TmpGuard(tmp.clone());
    f.write_all(&out)?;
    drop(f);

    fs::rename(&tmp, path)?;
    // Rename succeeded — the tmp path now refers to `path`. Disarm
    // the guard so the destination isn't deleted.
    std::mem::forget(guard);
    Ok(())
}

/// Removes its inner path on drop. Disarmed via `mem::forget` once the
/// final rename succeeds; until then any panic or `?` early-return
/// cleans the tmp file.
struct TmpGuard(PathBuf);

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Read and decrypt the [`ActorIdentityVault`] for `handle` from
/// `layout.actor_identity_path(handle)`.
///
/// Returns `Ok(None)` when no vault file exists for the handle (the
/// caller's "first run" path). All other failures — IO, malformed
/// header, AEAD tag mismatch, JSON parse — surface as `Err`.
///
/// # Errors
/// IO, malformed-header (`FFV1` magic), AEAD failures (tag mismatch
/// from a tampered ciphertext or a wrong master key), JSON parse.
pub fn load_actor_identity(
    handle: &str,
    master: &MasterKey,
    layout: &StoreLayout,
) -> Result<Option<ActorIdentityVault>, ChatError> {
    let key = derive_fedi_vault_key(master);
    let Some(plain) = read_sealed(
        &layout.actor_identity_path(handle),
        *FEDI_VAULT_MAGIC,
        &key,
        FEDI_VAULT_AAD,
    )?
    else {
        return Ok(None);
    };
    let vault: ActorIdentityVault = serde_json::from_slice(&plain)
        .map_err(|e| ChatError::Invalid(format!("vault decode: {e}")))?;
    Ok(Some(vault))
}

/// Delete the sealed identity for `handle`, returning whether a file was
/// removed. Used to discard an identity the directory refused as a name
/// conflict, which would otherwise linger in
/// [`list_actor_handles`] and shadow the handle the user goes on to
/// mint.
///
/// # Errors
/// IO errors other than "already absent".
pub fn remove_actor_identity(handle: &str, layout: &StoreLayout) -> Result<bool, ChatError> {
    match fs::remove_file(layout.actor_identity_path(handle)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ChatError::from(e)),
    }
}

/// Read and open one `magic ‖ nonce ‖ ciphertext` sealed file.
/// `Ok(None)` when `path` does not exist — the caller decides what an
/// absent store means. Shared with [`crate::fedi_thread`].
///
/// # Errors
/// [`ChatError::Invalid`] on a truncated file or magic mismatch; AEAD
/// errors when the key/AAD don't open the ciphertext; IO errors from
/// the read.
pub(crate) fn read_sealed(
    path: &Path,
    magic: [u8; 4],
    key: &[u8; AEAD_KEY_LEN],
    aad: &[u8],
) -> Result<Option<Vec<u8>>, ChatError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(ChatError::from)?;
    if bytes.len() < FEDI_HEADER_LEN {
        return Err(ChatError::Invalid("sealed store file too short".into()));
    }
    if bytes[..4] != magic {
        return Err(ChatError::Invalid("sealed store magic mismatch".into()));
    }
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&bytes[4..FEDI_HEADER_LEN]);
    Ok(Some(aead_open(
        key,
        &nonce,
        &bytes[FEDI_HEADER_LEN..],
        aad,
    )?))
}

/// List the handles of every actor identity minted into this vault, by
/// enumerating `<root>/fedi/<handle>.json.enc`. Sorted for deterministic
/// order. The `handle_resolutions.json` continuity ledger shares the dir
/// but is skipped (not a `.json.enc` vault file).
///
/// Fail-safe: an unreadable or absent fedi dir (nothing minted yet) yields
/// an empty list, never an error -- it backs the FFI `actor_status`
/// onboarding gate, which must answer "no handle" cleanly.
#[must_use]
pub fn list_actor_handles(layout: &StoreLayout) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(&layout.fedi_dir) else {
        return Vec::new();
    };
    let mut handles: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".json.enc").map(str::to_owned))
        .collect();
    handles.sort();
    handles
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::AEAD_KEY_LEN;
    use tempfile::tempdir;

    fn sample_vault() -> ActorIdentityVault {
        ActorIdentityVault {
            handle: "josh".into(),
            actor_url: "https://etchit.io/actors/josh".parse().unwrap(),
            agent_id_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            rsa_priv_pem:
                "-----BEGIN PRIVATE KEY-----\nsynthetic-test-key\n-----END PRIVATE KEY-----\n"
                    .into(),
            spki_der: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
            ml_dsa_attestation: MlDsaAttestation::new(vec![0xAA; 32], vec![0xBB; 64]),
            ml_dsa_attestation_v2: None,
            icon_url: None,
            icon_media_type: None,
        }
    }

    fn fixture_master(byte: u8) -> MasterKey {
        MasterKey::from_bytes_for_test([byte; AEAD_KEY_LEN])
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        let v = sample_vault();

        save_actor_identity(&v, &master, &layout).unwrap();
        let recovered = load_actor_identity(&v.handle, &master, &layout)
            .unwrap()
            .expect("vault file should exist after save");
        assert_eq!(recovered, v);
    }

    #[test]
    fn vault_round_trips_v2_attestation() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        let mut v = sample_vault();
        v.ml_dsa_attestation_v2 = Some(fetchit_fedi::attestation::ActorAttestationV2 {
            version: 2,
            profile_addr: "a".repeat(64),
            relay_hint: "https://relay.example/".into(),
            hint_epoch_ms: 7,
            ml_dsa_pubkey: vec![0xAA; 8],
            signature: vec![0xBB; 8],
        });

        save_actor_identity(&v, &master, &layout).unwrap();
        let recovered = load_actor_identity(&v.handle, &master, &layout)
            .unwrap()
            .expect("vault file should exist after save");
        assert_eq!(recovered, v);
        assert!(recovered.ml_dsa_attestation_v2.is_some());
    }

    #[test]
    fn list_actor_handles_enumerates_minted_and_skips_the_resolutions_ledger() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        // No handle minted yet -> empty (the FFI actor_status onboarding gate).
        assert!(list_actor_handles(&layout).is_empty());

        let mut a = sample_vault();
        a.handle = "alice".into();
        save_actor_identity(&a, &master, &layout).unwrap();
        let mut b = sample_vault();
        b.handle = "bob".into();
        save_actor_identity(&b, &master, &layout).unwrap();
        // The continuity ledger shares the fedi dir but is NOT a vault file.
        std::fs::write(layout.fedi_resolutions_path(), b"{}").unwrap();

        assert_eq!(
            list_actor_handles(&layout),
            vec!["alice".to_string(), "bob".to_string()],
            "enumerates *.json.enc handles, sorted, skipping the ledger"
        );
    }

    #[test]
    fn remove_actor_identity_drops_the_handle_from_the_listing() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        let mut a = sample_vault();
        a.handle = "alice".into();
        save_actor_identity(&a, &master, &layout).unwrap();

        assert!(remove_actor_identity("alice", &layout).unwrap());
        assert!(list_actor_handles(&layout).is_empty());
        // Idempotent: removing an absent identity is not an error.
        assert!(!remove_actor_identity("alice", &layout).unwrap());
    }

    #[test]
    fn legacy_vault_json_without_v2_field_deserializes_to_none() {
        // The exact JSON shape pre-M5 vaults hold inside the AEAD; the
        // new field must default rather than fail the decode.
        let json = r#"{
            "handle": "josh",
            "actor_url": "https://etchit.io/actors/josh",
            "agent_id_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "rsa_priv_pem": "PEM",
            "spki_der": [1, 2, 3],
            "ml_dsa_attestation": { "ml_dsa_pubkey": "QQ==", "signature": "Qg==" }
        }"#;
        let v: ActorIdentityVault = serde_json::from_str(json).unwrap();
        assert!(v.ml_dsa_attestation_v2.is_none());
        assert!(
            v.icon_url.is_none() && v.icon_media_type.is_none(),
            "a vault minted before profile pictures must still decode"
        );
    }

    #[test]
    fn vault_round_trips_the_published_icon() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        let mut v = sample_vault();
        v.icon_url = Some("https://etchit.io/actors/josh/avatar".into());
        v.icon_media_type = Some("image/jpeg".into());

        save_actor_identity(&v, &master, &layout).unwrap();
        let recovered = load_actor_identity(&v.handle, &master, &layout)
            .unwrap()
            .expect("vault file should exist after save");
        assert_eq!(recovered, v);
    }

    #[test]
    fn load_returns_none_when_no_vault_file() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        assert!(load_actor_identity("nobody", &master, &layout)
            .unwrap()
            .is_none());
    }

    #[test]
    fn load_fails_under_wrong_master_key() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let saver = fixture_master(0x42);
        let attacker = fixture_master(0x99);
        let v = sample_vault();

        save_actor_identity(&v, &saver, &layout).unwrap();
        let err = load_actor_identity(&v.handle, &attacker, &layout).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("aead") || msg.to_lowercase().contains("decrypt"),
            "expected AEAD/decrypt failure; got: {msg}"
        );
    }

    #[test]
    fn load_fails_when_ciphertext_is_tampered() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        let v = sample_vault();

        save_actor_identity(&v, &master, &layout).unwrap();

        let path = layout.actor_identity_path(&v.handle);
        let mut bytes = fs::read(&path).unwrap();
        // Flip one byte of the ciphertext (past the FFV1 + nonce
        // header) to invalidate the tag.
        let target = FEDI_HEADER_LEN + 5;
        bytes[target] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();

        assert!(load_actor_identity(&v.handle, &master, &layout).is_err());
    }

    #[test]
    fn read_sealed_rejects_short_input() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.bin");
        fs::write(&path, b"FFV1tiny").unwrap();
        let key = [0u8; AEAD_KEY_LEN];
        assert!(read_sealed(&path, *FEDI_VAULT_MAGIC, &key, FEDI_VAULT_AAD).is_err());
    }

    #[test]
    fn read_sealed_rejects_wrong_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("badmagic.bin");
        let mut bad = vec![b'X', b'X', b'X', b'X'];
        bad.extend_from_slice(&[0u8; AEAD_NONCE_LEN + 32]);
        fs::write(&path, &bad).unwrap();
        let key = [0u8; AEAD_KEY_LEN];
        let err = read_sealed(&path, *FEDI_VAULT_MAGIC, &key, FEDI_VAULT_AAD).unwrap_err();
        assert!(format!("{err}").contains("magic"));
    }

    #[test]
    fn tmp_guard_removes_file_on_drop() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("scratch.bin");
        fs::write(&target, b"hello").unwrap();
        assert!(target.exists());

        {
            let _guard = TmpGuard(target.clone());
        }
        assert!(
            !target.exists(),
            "TmpGuard::drop should have removed the tmp file"
        );
    }

    #[test]
    fn save_leaves_no_tmp_siblings_on_success() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let master = fixture_master(0x42);
        let v = sample_vault();
        save_actor_identity(&v, &master, &layout).unwrap();

        let entries: Vec<_> = fs::read_dir(&layout.fedi_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        for name in &entries {
            let s = name.to_string_lossy();
            assert!(
                !s.contains(".tmp."),
                "no .tmp.<hex> sibling should remain after success: {s}"
            );
        }
    }
}
