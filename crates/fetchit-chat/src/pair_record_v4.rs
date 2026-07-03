//! The account's user-signed [`PairRecordV4`] device list -- minted at a
//! passphrase moment, cached plaintext, and republished verbatim.
//!
//! M6.2 splits the v4 record's lifecycle across two custody postures:
//!
//! - **Minting** needs the account user key ([`crate::fabric::UserKeypair`]),
//!   derived on demand from the vault via [`crate::local_signer::with_user_key`]
//!   and dropped immediately (never retained). So the record is (re-)signed
//!   ONLY at an explicit passphrase moment -- a first-launch self-cert, an
//!   enroll, or a revoke -- where the `revision` steps forward.
//! - **Republishing** needs no key: the signed record is public, cached as
//!   plaintext JSON (`pair_record_v4.json`, the same class as
//!   `device_cert.json`), and re-POSTed byte-for-byte on every connect /
//!   home-relay failover. The relay's `revision` CAS makes a duplicate
//!   re-POST a harmless 409, while a failover-target relay that lacks the
//!   record accepts it -- so reachability propagates without a re-sign.
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
/// public -- it is served verbatim by the relay), 0600 like every store file.
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
/// passphrase-moment operation -- a first-launch self-cert, an enroll, or a
/// revoke -- never a background republish.
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

/// Outcome of a single `POST /v1/pair-record-v4` attempt, mirroring
/// [`crate::pair_record::PostOutcome`] on the anti-rollback `revision`.
#[derive(Debug)]
pub enum PostV4Outcome {
    /// The relay accepted the record (2xx).
    Accepted,
    /// The relay rejected with 409 Conflict: our `revision` was not strictly
    /// greater than the relay's stored revision for this `user_id`. The body
    /// carries the value a fresh mint must exceed.
    RevisionReject {
        /// The relay's current stored `revision` for this account.
        current_revision: u64,
    },
}

/// 409 response body from the relay's v4 anti-rollback guard.
#[derive(serde::Deserialize)]
struct RevisionRejectBody {
    current_revision: u64,
}

/// `POST <relay>/v1/pair-record-v4` with a 10-second timeout.
///
/// - 2xx -> [`PostV4Outcome::Accepted`].
/// - 409 -> parse the `{"current_revision": N}` body ->
///   [`PostV4Outcome::RevisionReject`].
/// - Any other non-2xx -> [`ChatError::Invalid`] with the status code.
///
/// # Errors
/// A transport failure, or [`ChatError::Invalid`] for a non-2xx other than
/// 409.
pub async fn post_pair_record_v4(
    relay: &url::Url,
    record: &PairRecordV4,
    http: &reqwest::Client,
) -> Result<PostV4Outcome, ChatError> {
    crate::relay_http::guard_relay_url(relay)
        .await
        .map_err(|e| ChatError::Invalid(format!("relay blocked: {e}")))?;
    let url = relay
        .join("v1/pair-record-v4")
        .map_err(|e| ChatError::Invalid(format!("build relay url: {e}")))?;
    let resp = crate::relay_http::relay_send_with_retry(|| {
        http.post(url.clone())
            .json(record)
            .timeout(std::time::Duration::from_secs(10))
    })
    .await?;
    let status = resp.status();
    if status.is_success() {
        return Ok(PostV4Outcome::Accepted);
    }
    if status.as_u16() == 409 {
        // The real 409 body is a few bytes of JSON; the cap guards a
        // hostile/buggy relay. Shares the V1 body cap.
        let raw =
            crate::relay_http::read_body_capped(resp, crate::pair_record::MAX_RELAY_BODY_BYTES)
                .await
                .map_err(|e| ChatError::Invalid(e.to_string()))?;
        let body: RevisionRejectBody = serde_json::from_slice(&raw)
            .map_err(|e| ChatError::Invalid(format!("409 body decode: {e}")))?;
        return Ok(PostV4Outcome::RevisionReject {
            current_revision: body.current_revision,
        });
    }
    Err(ChatError::Invalid(format!(
        "relay returned {s} publishing pair record v4",
        s = status.as_u16()
    )))
}

/// Republish the cached signed v4 record to `relay` verbatim, if one exists.
///
/// A no-op when no record has been minted (a pre-M6 identity, or before the
/// first self-cert), so the V1 publish path is unaffected for accounts
/// without a device list. The record is re-POSTed byte-for-byte with NO
/// re-sign: the relay's `revision` CAS makes a duplicate a harmless 409
/// (treated as success here, since the relay already holds this-or-newer),
/// while a failover-target relay that lacks the record accepts it. Freshening
/// reachability therefore never needs the user key.
///
/// For M6.2's single minter a `RevisionReject` cannot indicate a stale local
/// cache, since only this device mints. Under multi-device minting a
/// `RevisionReject` would instead mean a sibling device published a newer
/// revision; reconciling the then-stale local cache is a separate self-sync
/// concern, not this republish path's.
///
/// # Errors
/// [`ChatError`] on a malformed cache file, or a transport / non-2xx-non-409
/// relay failure.
pub async fn republish_cached_pair_record_v4(
    data_dir: &Path,
    relay: &url::Url,
    http: &reqwest::Client,
) -> Result<(), ChatError> {
    let Some(record) = load_pair_record_v4(data_dir)? else {
        return Ok(());
    };
    match post_pair_record_v4(relay, &record, http).await? {
        PostV4Outcome::Accepted | PostV4Outcome::RevisionReject { .. } => Ok(()),
    }
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
        LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        (dir, master)
    }

    /// A well-formed [`DeviceEntryV4`] whose `agent_id_hex` correctly binds
    /// its ML-DSA key (so the record's per-device binding check passes). The
    /// `cert_b64` is opaque here -- it is bound into the user signature but not
    /// re-verified on resolve -- so any base64 is fine.
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

    /// A minimal [`PairRecordV4`] for the HTTP-outcome tests, which exercise
    /// status mapping only (the relay POST does not verify the body).
    fn bare_record() -> PairRecordV4 {
        PairRecordV4 {
            record_version: 4,
            user_id_hex: "ab".repeat(32),
            user_ml_dsa_pubkey_b64: "AA".to_string(),
            revision: 1,
            issued_at_ms: 1,
            devices: vec![],
            user_signature_b64: "AA".to_string(),
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
        // signed it -- proves the custody path derived the right key).
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
        mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            4,
            1,
            &[device_entry(3, true)],
        )
        .unwrap();
        assert_eq!(next_pair_record_v4_revision(dir.path()).unwrap(), 5);
    }

    #[test]
    fn save_overwrites_prior_record() {
        let (dir, master) = seeded_vault();
        mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1,
            &[device_entry(3, true)],
        )
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
        assert_eq!(
            load_pair_record_v4(dir.path()).unwrap().unwrap().revision,
            2
        );
    }

    #[tokio::test]
    async fn post_v4_accepted_on_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        match post_pair_record_v4(&relay, &bare_record(), &http)
            .await
            .unwrap()
        {
            PostV4Outcome::Accepted => {}
            other @ PostV4Outcome::RevisionReject { .. } => {
                panic!("expected Accepted, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn post_v4_revision_reject_on_409() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({"current_revision": 42u64})),
            )
            .mount(&server)
            .await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        match post_pair_record_v4(&relay, &bare_record(), &http)
            .await
            .unwrap()
        {
            PostV4Outcome::RevisionReject { current_revision } => {
                assert_eq!(current_revision, 42);
            }
            other @ PostV4Outcome::Accepted => panic!("expected RevisionReject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_v4_errors_on_other_non_2xx() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        assert!(post_pair_record_v4(&relay, &bare_record(), &http)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn republish_is_noop_without_a_cached_record() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        // A 500 that must never be hit: no cache -> no POST.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let dir = tempdir().unwrap();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        republish_cached_pair_record_v4(dir.path(), &relay, &http)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn republish_posts_the_cached_record() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
        let (dir, master) = seeded_vault();
        mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1,
            &[device_entry(3, true)],
        )
        .unwrap();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        republish_cached_pair_record_v4(dir.path(), &relay, &http)
            .await
            .unwrap();
        // .expect(1) verifies exactly one POST fired (checked on server drop).
    }

    #[tokio::test]
    async fn republish_treats_409_as_success() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({"current_revision": 7u64})),
            )
            .mount(&server)
            .await;
        let (dir, master) = seeded_vault();
        mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1,
            &[device_entry(3, true)],
        )
        .unwrap();
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        // A verbatim re-POST the relay already holds is a harmless 409.
        republish_cached_pair_record_v4(dir.path(), &relay, &http)
            .await
            .unwrap();
    }
}
