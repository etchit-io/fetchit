//! Seed an external x0xd's agent identity from the chat vault.
//!
//! The desktop shell spawns a bundled x0xd binary rather than embedding the
//! daemon, and x0xd loads its agent keypair from `identity_dir/agent.key`
//! (see upstream `x0x/src/server/mod.rs`, the `config.identity_dir`
//! resolution). Identity unification requires that key to BE the chat
//! vault's ML-DSA-65 keypair — otherwise the daemon mints its own agent id,
//! groups it owns are keyed under that id, and joiners who resolve the owner
//! by the vault id 404 (the same split the Android in-process embed closes
//! by seeding before serve).
//!
//! The `agent.key` byte format is upstream x0x's: bincode 1.x of
//! `{ public_key: Vec<u8>, secret_key: Vec<u8> }`, written 0600. We encode
//! it here rather than linking the full `x0x` daemon library into the
//! desktop app; the format is pinned against the BUNDLED x0xd version the
//! desktop ships (same deliberate-bump policy as the `ant-core` pin), and
//! [`tests::agent_key_bytes_pin_the_upstream_bincode_layout`] locks the
//! exact byte layout so a silent drift fails the suite.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::client::provision_local_signer_keypair;
use crate::error::{ChatError, Result};

/// Mirror of upstream x0x `storage.rs`'s `SerializedKeypair`: bincode 1.x,
/// field order `public_key` then `secret_key`.
#[derive(Serialize, Deserialize)]
struct SerializedKeypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl Drop for SerializedKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Provision (or load) the seed-first chat-vault identity under `data_dir`
/// and write it as `identity_dir/agent.key` in x0xd's on-disk format, so a
/// spawned daemon boots as the SAME agent as the chat vault. Returns the
/// unified agent id (hex).
///
/// Overwrites an existing `agent.key` unconditionally: the vault is the
/// canonical identity, and an install whose daemon self-minted a different
/// id must converge on the vault id (one-time rotation, after which the
/// write is idempotent — the vault keypair is stable).
///
/// `passphrase`: `None` = OS-keychain custody (the desktop default).
///
/// # Errors
/// Vault provisioning failures as [`ChatError`]; `ChatError::Io` on
/// filesystem errors writing the key.
pub fn seed_x0xd_agent_key(
    data_dir: &Path,
    passphrase: Option<&str>,
    identity_dir: &Path,
) -> Result<String> {
    let provisioned = provision_local_signer_keypair(data_dir, passphrase)?;
    let bytes = zeroize::Zeroizing::new(
        bincode::serialize(&SerializedKeypair {
            public_key: provisioned.public_key.clone(),
            secret_key: provisioned.secret_key.to_vec(),
        })
        .map_err(|e| ChatError::Invalid(format!("agent.key encode: {e}")))?,
    );
    std::fs::create_dir_all(identity_dir)?;
    let path = identity_dir.join("agent.key");
    write_private(&path, &bytes)?;
    Ok(provisioned.agent_id_hex)
}

/// Write `bytes` to `path` with owner-only permissions (0600 on unix),
/// mirroring upstream `write_private_file`. The file is CREATED 0600
/// (no write-then-chmod window where the secret key sits readable), and
/// a pre-existing file is re-permissioned before the truncating write in
/// case it was created looser.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn agent_key_bytes_pin_the_upstream_bincode_layout() {
        // The compatibility contract with the bundled x0xd: bincode 1.x of
        // { public_key: Vec<u8>, secret_key: Vec<u8> } is two u64-LE
        // length-prefixed byte runs, public first. If this layout ever
        // drifts, the daemon would silently mint a fresh identity instead
        // of loading ours — fail loudly here instead.
        let encoded = bincode::serialize(&SerializedKeypair {
            public_key: vec![0xAA, 0xBB],
            secret_key: vec![0x01, 0x02, 0x03],
        })
        .unwrap();
        let expected = [
            2, 0, 0, 0, 0, 0, 0, 0, // public_key len, u64 LE
            0xAA, 0xBB, // public_key bytes
            3, 0, 0, 0, 0, 0, 0, 0, // secret_key len, u64 LE
            0x01, 0x02, 0x03, // secret_key bytes
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn seeds_the_vault_keypair_and_is_idempotent() {
        let data = TempDir::new().unwrap();
        let x0xd = TempDir::new().unwrap();
        let id_dir = x0xd.path().join("identity");

        let id1 = seed_x0xd_agent_key(data.path(), Some("pass"), &id_dir).unwrap();
        let key1 = std::fs::read(id_dir.join("agent.key")).unwrap();
        // Same vault -> same agent id, byte-identical key file.
        let id2 = seed_x0xd_agent_key(data.path(), Some("pass"), &id_dir).unwrap();
        let key2 = std::fs::read(id_dir.join("agent.key")).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(key1, key2);
        assert_eq!(id1.len(), 64, "agent id is 64-hex");

        // The written bytes decode back to the vault's keypair.
        let kp: SerializedKeypair = bincode::deserialize(&key1).unwrap();
        let prov =
            crate::client::provision_local_signer_keypair(data.path(), Some("pass")).unwrap();
        assert_eq!(kp.public_key, prov.public_key);
        assert_eq!(kp.secret_key, prov.secret_key.to_vec());
    }

    #[cfg(unix)]
    #[test]
    fn agent_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let data = TempDir::new().unwrap();
        let x0xd = TempDir::new().unwrap();
        let id_dir = x0xd.path().join("identity");
        seed_x0xd_agent_key(data.path(), Some("pass"), &id_dir).unwrap();
        let mode = std::fs::metadata(id_dir.join("agent.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn overwrites_a_foreign_agent_key() {
        // An install whose daemon self-minted writes a DIFFERENT agent.key;
        // seeding must converge it on the vault identity (one-time rotation).
        let data = TempDir::new().unwrap();
        let x0xd = TempDir::new().unwrap();
        let id_dir = x0xd.path().join("identity");
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::write(id_dir.join("agent.key"), b"foreign self-minted key").unwrap();

        seed_x0xd_agent_key(data.path(), Some("pass"), &id_dir).unwrap();
        let now = std::fs::read(id_dir.join("agent.key")).unwrap();
        assert_ne!(now, b"foreign self-minted key");
        let kp: SerializedKeypair = bincode::deserialize(&now).unwrap();
        assert!(!kp.public_key.is_empty());
        // The foreign file was created with default (umask) permissions;
        // overwriting must normalize it to owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(id_dir.join("agent.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
