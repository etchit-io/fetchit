//! The account's user-signed [`PairRecordV4`] device list — minted at a
//! passphrase moment, cached plaintext, and republished verbatim.
//!
//! M6.2 splits the v4 record's lifecycle across two custody postures:
//!
//! - **Minting** needs the account user key ([`crate::fabric::UserKeypair`]),
//!   derived on demand from the vault via [`crate::local_signer::with_user_key`]
//!   and dropped immediately (never retained). So the record is (re-)signed
//!   ONLY at an explicit passphrase moment — a first-launch self-cert, an
//!   enroll, or a revoke — where the `revision` steps forward.
//! - **Republishing** needs no key: the signed record is public, cached as
//!   plaintext JSON (`pair_record_v4.json`, the same class as
//!   `device_cert.json`), and re-POSTed byte-for-byte on every connect /
//!   home-relay failover. The relay's `revision` CAS makes a duplicate
//!   re-POST a harmless 409, while a failover-target relay that lacks the
//!   record accepts it — so reachability propagates without a re-sign.
//!
//! This is why the cache holds the SIGNED record only and the user key is
//! never kept around to reproduce it: freshening reachability is a verbatim
//! republish, and a new device list is a new user-signed revision.

use crate::at_rest::MasterKey;
use crate::error::ChatError;
use crate::local_store::write_json_atomic;
use fetchit_relay_proto::pair_record::{DeviceEntryV4, PairRecordV4};
use std::path::{Path, PathBuf};

/// Path of the cached signed v4 record. Plaintext JSON (the record is
/// public — it is served verbatim by the relay), 0600 like every store file.
fn pair_record_v4_path(data_dir: &Path) -> PathBuf {
    data_dir.join("pair_record_v4.json")
}

/// Load the cached signed [`PairRecordV4`], if one has been minted.
///
/// # Errors
/// I/O errors other than "not found", or a malformed cache file.
pub fn load_pair_record_v4(data_dir: &Path) -> Result<Option<PairRecordV4>, ChatError> {
    match std::fs::read(pair_record_v4_path(data_dir)) {
        Ok(bytes) => {
            let record = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("pair record v4 parse: {e}")))?;
            Ok(Some(record))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Persist `record` as the cached signed v4 record, overwriting any prior.
///
/// # Errors
/// A persistence failure.
pub fn save_pair_record_v4(data_dir: &Path, record: &PairRecordV4) -> Result<(), ChatError> {
    write_json_atomic(&pair_record_v4_path(data_dir), record)
}

/// The `revision` the next mint should carry: one past the cached record's,
/// or `1` on a first mint. The relay enforces strict-monotonic revisions per
/// `user_id` (anti-rollback), so a mint must always step forward.
///
/// # Errors
/// A malformed cache file (via [`load_pair_record_v4`]).
pub fn next_pair_record_v4_revision(data_dir: &Path) -> Result<u64, ChatError> {
    match load_pair_record_v4(data_dir)? {
        Some(record) => Ok(record.revision.saturating_add(1)),
        None => Ok(1),
    }
}

/// Mint a fresh user-signed [`PairRecordV4`] over `devices` and cache it.
///
/// Opens the vault (via `passphrase`, or the OS keychain when `None`, as
/// elsewhere), derives the account user key, signs the record, drops the key,
/// and persists the signed record plaintext. This is an explicit
/// passphrase-moment operation — a first-launch self-cert, an enroll, or a
/// revoke — never a background republish.
///
/// `revision` should come from [`next_pair_record_v4_revision`] (or the
/// relay's current revision + 1 on a recovery), and `issued_at_ms` is the
/// wall-clock issuance time (the relay's logical-clock watermark).
///
/// # Errors
/// [`ChatError`] on vault-unlock failure, a missing recoverable seed, a
/// structural or signing failure, or a persistence failure.
pub fn mint_and_cache_pair_record_v4(
    data_dir: &Path,
    passphrase: Option<&str>,
    revision: u64,
    issued_at_ms: u64,
    devices: &[DeviceEntryV4],
) -> Result<PairRecordV4, ChatError> {
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    mint_and_cache_pair_record_v4_from_master(data_dir, &master, revision, issued_at_ms, devices)
}

/// [`mint_and_cache_pair_record_v4`] with an already-resolved [`MasterKey`]:
/// the internal seam the passphrase entry and the unit tests share.
///
/// # Errors
/// As [`mint_and_cache_pair_record_v4`].
pub(crate) fn mint_and_cache_pair_record_v4_from_master(
    data_dir: &Path,
    master: &MasterKey,
    revision: u64,
    issued_at_ms: u64,
    devices: &[DeviceEntryV4],
) -> Result<PairRecordV4, ChatError> {
    let record = crate::local_signer::with_user_key_from_master(data_dir, master, |user| {
        crate::fabric::mint_pair_record_v4(user, revision, issued_at_ms, devices)
    })?;
    save_pair_record_v4(data_dir, &record)?;
    Ok(record)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKeySource};
    use crate::local_signer::LocalSignerVault;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use fetchit_relay_client::{MlDsaSigner, Signer};
    use fetchit_relay_proto::pair_record::verify_pair_record_v4;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    /// A vault with a recoverable identity seed + a master key to open it
    /// (mirrors `device_cert.rs`, so `with_user_key_from_master` can derive
    /// the account user key).
    fn seeded_vault() -> (tempfile::TempDir, MasterKey) {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt)).unwrap();
        (dir, master)
    }

    /// A well-formed [`DeviceEntryV4`] whose `agent_id_hex` correctly binds
    /// its ML-DSA key (so the record's per-device binding check passes). The
    /// `cert_b64` is opaque here — it is bound into the user signature but not
    /// re-verified on resolve — so any base64 is fine.
    fn device_entry(seed: u8, primary: bool) -> DeviceEntryV4 {
        let signer = MlDsaSigner::from_seed(&[seed; 32]);
        DeviceEntryV4 {
            agent_id_hex: hex::encode(signer.agent_id()),
            ml_dsa_pubkey_b64: B64.encode(signer.public_key()),
            kem_pubkey_b64: B64.encode([seed; 1184]),
            advertised_relays: vec!["https://relay.example".to_string()],
            cert_b64: B64.encode([seed; 32]),
            added_at_ms: 1_700_000_000_000,
            primary,
        }
    }

    #[test]
    fn load_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        assert!(load_pair_record_v4(dir.path()).unwrap().is_none());
    }

    #[test]
    fn mints_caches_and_the_record_verifies() {
        let (dir, master) = seeded_vault();
        let devices = vec![device_entry(3, true)];
        assert!(load_pair_record_v4(dir.path()).unwrap().is_none());

        let record = mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1_700_000_000_000,
            &devices,
        )
        .unwrap();

        // User-signed and structurally valid (the user key from THIS vault
        // signed it — proves the custody path derived the right key).
        verify_pair_record_v4(&record).unwrap();
        assert_eq!(record.revision, 1);
        assert_eq!(record.devices, devices);
        // Persisted verbatim.
        assert_eq!(load_pair_record_v4(dir.path()).unwrap().unwrap(), record);
    }

    #[test]
    fn next_revision_is_one_when_absent() {
        let dir = tempdir().unwrap();
        assert_eq!(next_pair_record_v4_revision(dir.path()).unwrap(), 1);
    }

    #[test]
    fn next_revision_is_cached_plus_one() {
        let (dir, master) = seeded_vault();
        mint_and_cache_pair_record_v4_from_master(dir.path(), &master, 4, 1, &[device_entry(3, true)])
            .unwrap();
        assert_eq!(next_pair_record_v4_revision(dir.path()).unwrap(), 5);
    }

    #[test]
    fn save_overwrites_prior_record() {
        let (dir, master) = seeded_vault();
        mint_and_cache_pair_record_v4_from_master(dir.path(), &master, 1, 1, &[device_entry(3, true)])
            .unwrap();
        let second = mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            2,
            2,
            &[device_entry(3, true)],
        )
        .unwrap();
        assert_eq!(load_pair_record_v4(dir.path()).unwrap().unwrap(), second);
        assert_eq!(load_pair_record_v4(dir.path()).unwrap().unwrap().revision, 2);
    }
}
