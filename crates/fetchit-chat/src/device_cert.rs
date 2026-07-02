//! This device's own [`AgentCertificate`] — the account owner's signature
//! binding THIS device to the account `user_id` (M6.1 re-root).
//!
//! On first M6 launch a pre-existing single-device install "re-roots":
//! it self-certifies its existing agent as a device of the account. The
//! account owner's user key ([`crate::fabric::UserKeypair`], derived on
//! demand from the vault via [`crate::local_signer::with_user_key`]) signs
//! a certificate over the device's agent id and its ML-DSA / ML-KEM keys,
//! which is then persisted plaintext (the cert is public — it is published
//! inside the device's `PairRecordV4` entry and re-verified out-of-record).
//!
//! [`ensure_device_certificate`] is idempotent and, on the common path
//! (a cert already exists for the current agent), needs **no passphrase**:
//! it is a file read plus an agent-id check. Only the one-time first mint
//! (or a re-mint after an agent-id rotation) needs the user key, so the
//! caller can trigger it at a single passphrase-available moment and every
//! later launch is free.

use crate::at_rest::MasterKey;
use crate::error::ChatError;
use crate::fabric::{mint_agent_certificate, AgentCertificate};
use crate::local_store::write_json_atomic;
use std::path::{Path, PathBuf};

/// Path of this device's persisted certificate. Plaintext JSON (the cert
/// carries no secret), 0600 like every other store file.
fn device_cert_path(data_dir: &Path) -> PathBuf {
    data_dir.join("device_cert.json")
}

/// Load this device's persisted [`AgentCertificate`], if one exists.
///
/// # Errors
/// I/O errors other than "not found", or a malformed cert file.
pub fn load_device_certificate(data_dir: &Path) -> Result<Option<AgentCertificate>, ChatError> {
    match std::fs::read(device_cert_path(data_dir)) {
        Ok(bytes) => {
            let cert = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("device cert parse: {e}")))?;
            Ok(Some(cert))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Ensure this device holds an [`AgentCertificate`] binding it to the
/// account, minting and persisting one on first launch (or re-minting
/// after an agent-id rotation).
///
/// Idempotent: if a persisted cert already binds `agent_id_hex`, it is
/// returned as-is without touching the vault — the common, passphrase-free
/// path. Only a first mint or a rebind opens the vault (via `passphrase`,
/// or the OS keychain when `passphrase` is `None`, as elsewhere).
///
/// `agent_ml_dsa_pubkey` and `kem_pubkey` are the raw key bytes the device
/// actually uses; the caller sources them from its loaded identity so the
/// cert stays consistent with the device's `DeviceEntryV4`.
///
/// # Errors
/// [`ChatError`] on vault-unlock failure, a missing recoverable seed, or a
/// persistence failure.
pub fn ensure_device_certificate(
    data_dir: &Path,
    passphrase: Option<&str>,
    agent_id_hex: &str,
    agent_ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    added_at_ms: u64,
) -> Result<AgentCertificate, ChatError> {
    if let Some(existing) = load_device_certificate(data_dir)? {
        if existing.agent_id_hex == agent_id_hex {
            return Ok(existing);
        }
    }
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    ensure_device_certificate_from_master(
        data_dir,
        &master,
        agent_id_hex,
        agent_ml_dsa_pubkey,
        kem_pubkey,
        added_at_ms,
    )
}

/// [`ensure_device_certificate`] with an already-resolved [`MasterKey`]:
/// the internal seam the passphrase entry and the unit tests share.
///
/// # Errors
/// As [`ensure_device_certificate`].
pub(crate) fn ensure_device_certificate_from_master(
    data_dir: &Path,
    master: &MasterKey,
    agent_id_hex: &str,
    agent_ml_dsa_pubkey: &[u8],
    kem_pubkey: &[u8],
    added_at_ms: u64,
) -> Result<AgentCertificate, ChatError> {
    if let Some(existing) = load_device_certificate(data_dir)? {
        if existing.agent_id_hex == agent_id_hex {
            return Ok(existing);
        }
    }
    let cert = crate::local_signer::with_user_key_from_master(data_dir, master, |user| {
        mint_agent_certificate(
            user,
            agent_id_hex,
            agent_ml_dsa_pubkey,
            kem_pubkey,
            added_at_ms,
        )
    })?;
    write_json_atomic(&device_cert_path(data_dir), &cert)?;
    Ok(cert)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKeySource};
    use crate::fabric::verify_agent_certificate;
    use crate::local_signer::{with_user_key_from_master, LocalSignerVault};
    use fetchit_relay_client::{MlDsaSigner, Signer};
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    /// A vault with a recoverable identity seed + a master key to open it.
    fn seeded_vault() -> (tempfile::TempDir, MasterKey) {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        (dir, master)
    }

    /// A standalone device agent (its own ML-DSA key): id + raw pubkey.
    fn device_agent(seed: u8) -> (String, Vec<u8>) {
        let signer = MlDsaSigner::from_seed(&[seed; 32]);
        (hex::encode(signer.agent_id()), signer.public_key())
    }

    #[test]
    fn mints_and_persists_a_verifiable_cert_on_first_launch() {
        let (dir, master) = seeded_vault();
        let (agent_id, agent_pk) = device_agent(9);
        assert!(load_device_certificate(dir.path()).unwrap().is_none());

        let cert = ensure_device_certificate_from_master(
            dir.path(),
            &master,
            &agent_id,
            &agent_pk,
            &[0x42; 64],
            1_700_000_000_000,
        )
        .unwrap();

        // The cert binds the right agent and verifies against the account
        // user key derived from the same vault.
        assert_eq!(cert.agent_id_hex, agent_id);
        let user_pk =
            with_user_key_from_master(dir.path(), &master, |u| Ok(u.public_key_bytes().to_vec()))
                .unwrap();
        verify_agent_certificate(&cert, &user_pk).unwrap();
        // And it was persisted.
        assert_eq!(load_device_certificate(dir.path()).unwrap().unwrap(), cert);
    }

    #[test]
    fn is_idempotent_for_the_same_agent() {
        let (dir, master) = seeded_vault();
        let (agent_id, agent_pk) = device_agent(9);
        let first = ensure_device_certificate_from_master(
            dir.path(),
            &master,
            &agent_id,
            &agent_pk,
            &[0x42; 64],
            1_000,
        )
        .unwrap();
        let second = ensure_device_certificate_from_master(
            dir.path(),
            &master,
            &agent_id,
            &agent_pk,
            &[0x42; 64],
            2_000, // different timestamp: the persisted cert must win
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rebinds_after_an_agent_id_rotation() {
        let (dir, master) = seeded_vault();
        let (agent_a, pk_a) = device_agent(1);
        let (agent_b, pk_b) = device_agent(2);
        let first = ensure_device_certificate_from_master(
            dir.path(),
            &master,
            &agent_a,
            &pk_a,
            &[7; 64],
            1,
        )
        .unwrap();
        assert_eq!(first.agent_id_hex, agent_a);
        // A different agent id (x0x rotation) re-mints for the new agent.
        let second = ensure_device_certificate_from_master(
            dir.path(),
            &master,
            &agent_b,
            &pk_b,
            &[7; 64],
            2,
        )
        .unwrap();
        assert_eq!(second.agent_id_hex, agent_b);
        assert_ne!(agent_a, agent_b);
    }

    #[test]
    fn load_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        assert!(load_device_certificate(dir.path()).unwrap().is_none());
    }
}
