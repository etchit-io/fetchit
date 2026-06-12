//! On-disk layout for fetchit-chat state under `~/.config/fetchit/`.
//!
//! Plaintext under `contacts/` and `user_manifests/` (cards aren't
//! secret). Encrypted vault under `identity.json.enc` and
//! `conversations/<group_id>.json.enc`.
//!
//! All file writes go through an atomic write helper:
//! `write_json_atomic` with 0600 permissions on Unix (mode applied at
//! file creation; no umask window).

use crate::error::ChatError;
use rand::RngCore;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// The default data dir for desktop builds: platform-specific user
/// config dir, plus `fetchit/chat`.
///
/// # Errors
/// Returns `ChatError::Invalid` if the platform doesn't have a config
/// dir (e.g. Windows without a Roaming setup).
pub fn default_data_dir() -> Result<PathBuf, ChatError> {
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| ChatError::Invalid("no platform config dir".into()))?;
    Ok(dirs.config_dir().join("fetchit").join("chat"))
}

/// Top-level data layout under a chat data dir.
#[derive(Clone, Debug)]
pub struct StoreLayout {
    /// `<data_dir>/`
    pub root: PathBuf,
    /// `<data_dir>/contacts/`
    pub contacts_dir: PathBuf,
    /// `<data_dir>/conversations/`
    pub conversations_dir: PathBuf,
    /// `<data_dir>/user_manifests/` — populated by the multi-device
    /// build; created here for forward compatibility.
    pub user_manifests_dir: PathBuf,
    /// `<data_dir>/fedi/` — actor identities for the M4 fediverse
    /// bridge. Lives as a sibling of the chat dirs (not nested inside
    /// `conversations/`) so the "compromise scope = bridge posting
    /// only, chat unaffected" boundary is visibly enforced on disk
    /// too. See M4 plan decision 1.1.
    pub fedi_dir: PathBuf,
}

impl StoreLayout {
    /// Build a layout rooted at `root` and ensure every subdirectory
    /// exists with 0700 permissions on Unix.
    ///
    /// # Errors
    /// IO failures on directory creation or chmod.
    pub fn ensure(root: PathBuf) -> Result<Self, ChatError> {
        let contacts_dir = root.join("contacts");
        let conversations_dir = root.join("conversations");
        let user_manifests_dir = root.join("user_manifests");
        let fedi_dir = root.join("fedi");
        for dir in [
            &root,
            &contacts_dir,
            &conversations_dir,
            &user_manifests_dir,
            &fedi_dir,
        ] {
            fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(dir)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(dir, perms)?;
            }
        }
        Ok(Self {
            root,
            contacts_dir,
            conversations_dir,
            user_manifests_dir,
            fedi_dir,
        })
    }

    /// File path for a stored contact card, keyed by hex agent id.
    #[must_use]
    pub fn contact_path(&self, agent_id_hex: &str) -> PathBuf {
        self.contacts_dir.join(format!("{agent_id_hex}.json"))
    }

    /// File path for a conversation vault, keyed by hex group id.
    #[must_use]
    pub fn conversation_path(&self, group_id_hex: &str) -> PathBuf {
        self.conversations_dir
            .join(format!("{group_id_hex}.json.enc"))
    }

    /// File path for a persisted fediverse actor identity, keyed by
    /// handle local-part (e.g. `"josh"` for `@josh@etchit.io`).
    ///
    /// Encrypted on disk via the same chat-identity-derived vault key
    /// as conversation vaults; the `.json.enc` suffix marks it
    /// distinct from plaintext card files.
    #[must_use]
    pub fn actor_identity_path(&self, handle: &str) -> PathBuf {
        self.fedi_dir.join(format!("{handle}.json.enc"))
    }

    /// Path of the handle-resolution continuity ledger (M5.1): a JSON
    /// map of canonical fediverse handle to the agent id it last
    /// verifiably resolved to. Plaintext: every value in it is public
    /// directory data.
    #[must_use]
    pub fn fedi_resolutions_path(&self) -> PathBuf {
        self.fedi_dir.join("handle_resolutions.json")
    }
}

/// Atomic plaintext-JSON write at 0600 perms.
///
/// Writes to a uniquely-named `<filename>.tmp.<hex suffix>` sibling,
/// then `rename`s into place. The tmp file is opened with mode 0o600
/// at creation time on Unix, so there is no umask window between
/// creation and chmod. The unique suffix means concurrent writers
/// targeting the same final path don't collide on the tmp file.
///
/// # Errors
/// IO or JSON serialization failures.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ChatError> {
    use std::io::Write;

    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| ChatError::Invalid(format!("json to_vec: {e}")))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
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
    f.write_all(&bytes)?;
    drop(f);

    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ensure_creates_subdirs() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        assert!(layout.root.exists());
        assert!(layout.contacts_dir.exists());
        assert!(layout.conversations_dir.exists());
        assert!(layout.user_manifests_dir.exists());
        assert!(layout.fedi_dir.exists());
    }

    #[test]
    fn contact_path_uses_hex_agent_id() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let p = layout.contact_path("abc123");
        assert!(p.to_string_lossy().ends_with("abc123.json"));
    }

    #[test]
    fn actor_identity_path_uses_handle_under_fedi_dir() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let p = layout.actor_identity_path("josh");
        assert!(p.starts_with(&layout.fedi_dir));
        assert!(p.to_string_lossy().ends_with("josh.json.enc"));
    }

    #[test]
    fn fedi_dir_is_sibling_of_chat_dirs() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        assert_eq!(layout.fedi_dir.parent(), Some(layout.root.as_path()));
        assert_eq!(layout.contacts_dir.parent(), Some(layout.root.as_path()));
        assert_ne!(layout.fedi_dir, layout.conversations_dir);
    }

    #[cfg(unix)]
    #[test]
    fn fedi_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let mode = fs::metadata(&layout.fedi_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn write_json_atomic_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contact.json");
        let value = serde_json::json!({ "name": "Alice" });
        write_json_atomic(&path, &value).unwrap();
        let bytes = fs::read(&path).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(recovered, value);
    }

    #[test]
    fn write_json_atomic_creates_missing_parent_dirs() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("sub").join("nested");
        let path = nested.join("contact.json");
        assert!(
            !nested.exists(),
            "preconditon: nested parent shouldn't pre-exist"
        );
        write_json_atomic(&path, &serde_json::json!({ "k": "v" })).unwrap();
        assert!(path.exists(), "file should be created at the nested path");
        assert!(nested.exists(), "parent dirs should have been created");
        let recovered: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(recovered, serde_json::json!({ "k": "v" }));
    }

    #[cfg(unix)]
    #[test]
    fn write_json_atomic_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("contact.json");
        write_json_atomic(&path, &serde_json::json!({})).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
