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
use crate::fabric::AgentCertificate;
use crate::local_store::write_json_atomic;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fetchit_relay_proto::pair_record::{verify_pair_record_v4, DeviceEntryV4, PairRecordV4};
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

/// Build a [`DeviceEntryV4`] for the device certified by `cert`, reachable at
/// `relays`. The five identity fields come off the cert; `primary` is false (a
/// newly enrolled device is never the canonical device #1) and `cert_b64` is
/// the STANDARD-base64 of the JSON-serialized certificate.
fn device_entry_from_cert(
    cert: &AgentCertificate,
    relays: Vec<String>,
) -> Result<DeviceEntryV4, ChatError> {
    let cert_bytes = serde_json::to_vec(cert)
        .map_err(|e| ChatError::Invalid(format!("serialize device cert: {e}")))?;
    Ok(DeviceEntryV4 {
        agent_id_hex: cert.agent_id_hex.clone(),
        ml_dsa_pubkey_b64: cert.agent_ml_dsa_pubkey_b64.clone(),
        kem_pubkey_b64: cert.kem_pubkey_b64.clone(),
        advertised_relays: relays,
        cert_b64: B64.encode(cert_bytes),
        added_at_ms: cert.added_at_ms,
        primary: false,
    })
}

/// Append the device certified by `cert` to the account device list and mint
/// the next revision, caching the result. The `_from_master` seam
/// [`append_device_and_publish`] shares with the unit tests (already-resolved
/// [`MasterKey`], explicit `issued_at_ms`, no relay POST).
///
/// Loads the cached [`PairRecordV4`] (the existing device must already hold one
/// from its own self-cert), then REPLACES the entry for the cert's agent id if
/// present or appends it (idempotent re-enrollment), and mints + caches at the
/// cached revision + 1.
///
/// # Errors
/// [`ChatError`] if no cached record exists, or on a signing / persistence /
/// structural failure (e.g. exceeding the device cap).
pub(crate) fn append_and_mint_from_master(
    data_dir: &Path,
    master: &MasterKey,
    cert: &AgentCertificate,
    relays: Vec<String>,
    issued_at_ms: u64,
) -> Result<PairRecordV4, ChatError> {
    let Some(current) = load_pair_record_v4(data_dir)? else {
        return Err(ChatError::Invalid(
            "no cached device record; the existing device must self-cert before enrolling another"
                .to_owned(),
        ));
    };
    let entry = device_entry_from_cert(cert, relays)?;
    let mut devices = current.devices;
    match devices
        .iter_mut()
        .find(|d| d.agent_id_hex == entry.agent_id_hex)
    {
        Some(slot) => *slot = entry,
        None => devices.push(entry),
    }
    let revision = current.revision.saturating_add(1);
    mint_and_cache_pair_record_v4_from_master(data_dir, master, revision, issued_at_ms, &devices)
}

/// [`append_and_mint_from_master`] plus the relay POST: the async seam the
/// public entry and the wiremock tests share.
///
/// # Errors
/// As [`append_and_mint_from_master`], or a relay failure. A
/// [`PostV4Outcome::RevisionReject`] becomes an error: the relay holds a newer
/// revision (a sibling published concurrently), so this enroll must be re-run
/// against that newer record rather than silently succeed.
pub(crate) async fn append_publish_from_master(
    data_dir: &Path,
    master: &MasterKey,
    cert: &AgentCertificate,
    new_device_relays: &[String],
    relay: &url::Url,
    http: &reqwest::Client,
    issued_at_ms: u64,
) -> Result<PairRecordV4, ChatError> {
    // The new device's own relays (the `r=` in its enrollment URI, where it
    // published its offer) become its `DeviceEntryV4` reachability, so M6.3 DM
    // fanout reaches it on the first resolve. Fall back to the POST relay only
    // when the caller supplies none.
    let relays = if new_device_relays.is_empty() {
        vec![relay.to_string()]
    } else {
        new_device_relays.to_vec()
    };
    let record = append_and_mint_from_master(data_dir, master, cert, relays, issued_at_ms)?;
    match post_pair_record_v4(relay, &record, http).await? {
        PostV4Outcome::Accepted => Ok(record),
        PostV4Outcome::RevisionReject { current_revision } => Err(ChatError::Invalid(format!(
            "enroll publish rejected: relay holds a newer revision {current_revision}, re-run"
        ))),
    }
}

/// Enroll a confirmed device: append its account certificate to the device list
/// at the next revision and publish the new record to `post_relay`.
///
/// The existing (enrolling) device opens its vault (`passphrase`, or the OS
/// keychain when `None`), appends or replaces the entry for `cert`'s device,
/// mints a user-signed record at revision N+1, caches it, and POSTs it. Returns
/// the new signed record for the caller to hand to the devices-group invite.
///
/// The new device's `advertised_relays` come from `new_device_relays` (the
/// `r=` relays in its enrollment URI, i.e. where it published its offer), so
/// its `DeviceEntryV4` carries real reachability from day one; when that slice
/// is empty they fall back to `post_relay`.
///
/// # Errors
/// [`ChatError`] on a malformed `post_relay`, if the existing device has no
/// cached record yet, on a vault-unlock / signing failure, or on a relay
/// rejection.
pub async fn append_device_and_publish(
    data_dir: &Path,
    passphrase: Option<&str>,
    cert: &AgentCertificate,
    new_device_relays: &[String],
    post_relay: &str,
    http: &reqwest::Client,
) -> Result<PairRecordV4, ChatError> {
    let relay = url::Url::parse(post_relay)
        .map_err(|e| ChatError::Invalid(format!("post relay url: {e}")))?;
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    let issued_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    append_publish_from_master(
        data_dir,
        &master,
        cert,
        new_device_relays,
        &relay,
        http,
        issued_at_ms,
    )
    .await
}

/// Remove device `agent_id_hex` from the account's own device list and mint a
/// user-signed record at revision N+1 (the M6.7 revoke publish-side). Mirror of
/// [`append_and_mint_from_master`]: load the cached record, drop the entry, then
/// mint and cache. If the removed device was the primary, the first remaining
/// device is promoted (exactly-one-primary, else the mint rejects).
///
/// # Errors
/// No cached record, the device is not in the list, or removing it would leave
/// zero devices (use account recovery for the last device), or a signing failure.
pub(crate) fn remove_and_mint_from_master(
    data_dir: &Path,
    master: &MasterKey,
    agent_id_hex: &str,
    issued_at_ms: u64,
) -> Result<PairRecordV4, ChatError> {
    let Some(current) = load_pair_record_v4(data_dir)? else {
        return Err(ChatError::Invalid(
            "no cached device record; nothing to revoke".to_owned(),
        ));
    };
    let removed_was_primary = current
        .devices
        .iter()
        .find(|d| d.agent_id_hex == agent_id_hex)
        .ok_or_else(|| {
            ChatError::Invalid(format!(
                "device {agent_id_hex} is not in the account device list"
            ))
        })?
        .primary;
    let mut devices: Vec<DeviceEntryV4> = current
        .devices
        .into_iter()
        .filter(|d| d.agent_id_hex != agent_id_hex)
        .collect();
    if devices.is_empty() {
        return Err(ChatError::Invalid(
            "cannot revoke the only device; use account recovery instead".to_owned(),
        ));
    }
    // Removing the primary leaves the list with none; promote the first
    // survivor so the exactly-one-primary structural rule holds at mint.
    if removed_was_primary && !devices.iter().any(|d| d.primary) {
        devices[0].primary = true;
    }
    let revision = current.revision.saturating_add(1);
    mint_and_cache_pair_record_v4_from_master(data_dir, master, revision, issued_at_ms, &devices)
}

/// [`remove_and_mint_from_master`] plus the relay POST -- the async seam the
/// public entry and the wiremock tests share (mirror of
/// [`append_publish_from_master`]).
///
/// # Errors
/// As [`remove_and_mint_from_master`], or a relay failure. A
/// [`PostV4Outcome::RevisionReject`] becomes an error: the relay holds a newer
/// revision (a sibling published concurrently), so re-run against that record.
pub(crate) async fn revoke_publish_from_master(
    data_dir: &Path,
    master: &MasterKey,
    agent_id_hex: &str,
    relay: &url::Url,
    http: &reqwest::Client,
    issued_at_ms: u64,
) -> Result<PairRecordV4, ChatError> {
    let record = remove_and_mint_from_master(data_dir, master, agent_id_hex, issued_at_ms)?;
    match post_pair_record_v4(relay, &record, http).await? {
        PostV4Outcome::Accepted => Ok(record),
        PostV4Outcome::RevisionReject { current_revision } => Err(ChatError::Invalid(format!(
            "revoke publish rejected: relay holds a newer revision {current_revision}, re-run"
        ))),
    }
}

/// Revoke a device from this account and publish the smaller record (M6.7).
///
/// The surviving device opens its vault (`passphrase`, or the OS keychain when
/// `None`), drops `agent_id_hex` from its device list, mints a user-signed
/// record at revision N+1, caches it, and POSTs it. Contacts drop the revoked
/// device on their next resolve; the anti-rollback watermark keeps the revoked
/// device from replaying an older record. Returns the new signed record so the
/// caller can push it to active contacts + drive the devices-group leaf removal.
///
/// # Errors
/// A malformed `post_relay`, no cached record, the device is not listed, an
/// attempt to remove the only device, a vault-unlock / signing failure, or a
/// relay rejection.
pub async fn revoke_device_and_publish(
    data_dir: &Path,
    passphrase: Option<&str>,
    agent_id_hex: &str,
    post_relay: &str,
    http: &reqwest::Client,
) -> Result<PairRecordV4, ChatError> {
    let relay = url::Url::parse(post_relay)
        .map_err(|e| ChatError::Invalid(format!("post relay url: {e}")))?;
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    let issued_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    revoke_publish_from_master(data_dir, &master, agent_id_hex, &relay, http, issued_at_ms).await
}

/// `true` when `user_id_hex` is a 64-char lowercase-hex user id. Validated
/// before it is used as a filesystem path segment (no traversal).
fn is_user_id_hex(user_id_hex: &str) -> bool {
    user_id_hex.len() == 64
        && user_id_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Path of a cached CONTACT's last-accepted signed v4 record, keyed by their
/// `user_id_hex`. Public plaintext (the record is public), under a per-account
/// subdir so contacts do not collide with this device's own record.
fn contact_pair_record_v4_path(data_dir: &Path, user_id_hex: &str) -> PathBuf {
    data_dir
        .join("contact_pair_records")
        .join(format!("{user_id_hex}.json"))
}

/// Load a contact's last-accepted [`PairRecordV4`] from the local cache.
///
/// # Errors
/// A malformed `user_id_hex`, an I/O error other than "not found", or a
/// malformed cache file.
pub fn load_contact_pair_record_v4(
    data_dir: &Path,
    user_id_hex: &str,
) -> Result<Option<PairRecordV4>, ChatError> {
    if !is_user_id_hex(user_id_hex) {
        return Err(ChatError::Invalid("user id is not 64-hex".to_owned()));
    }
    match std::fs::read(contact_pair_record_v4_path(data_dir, user_id_hex)) {
        Ok(bytes) => {
            let record = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("contact pair record v4 parse: {e}")))?;
            Ok(Some(record))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Cache a contact's accepted [`PairRecordV4`], keyed by its own `user_id_hex`.
fn save_contact_pair_record_v4(data_dir: &Path, record: &PairRecordV4) -> Result<(), ChatError> {
    if !is_user_id_hex(&record.user_id_hex) {
        return Err(ChatError::Invalid(
            "record user id is not 64-hex".to_owned(),
        ));
    }
    write_json_atomic(
        &contact_pair_record_v4_path(data_dir, &record.user_id_hex),
        record,
    )
}

/// `GET <relay>/v1/pair-record-v4/<user_id>` with a 10-second timeout.
/// `Some(record)` on 2xx, `None` on 404, [`ChatError`] otherwise. The record
/// is NOT verified here -- [`resolve_pair_record_v4`] does that.
async fn get_pair_record_v4(
    relay: &url::Url,
    user_id_hex: &str,
    http: &reqwest::Client,
) -> Result<Option<PairRecordV4>, ChatError> {
    crate::relay_http::guard_relay_url(relay)
        .await
        .map_err(|e| ChatError::Invalid(format!("relay blocked: {e}")))?;
    let url = relay
        .join(&format!("v1/pair-record-v4/{user_id_hex}"))
        .map_err(|e| ChatError::Invalid(format!("build relay url: {e}")))?;
    let resp = crate::relay_http::relay_send_with_retry(|| {
        http.get(url.clone())
            .timeout(std::time::Duration::from_secs(10))
    })
    .await?;
    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(ChatError::Invalid(format!(
            "relay returned {s} resolving pair record v4",
            s = status.as_u16()
        )));
    }
    let raw = crate::relay_http::read_body_capped(resp, crate::pair_record::MAX_RELAY_BODY_BYTES)
        .await
        .map_err(|e| ChatError::Invalid(e.to_string()))?;
    let record = serde_json::from_slice(&raw)
        .map_err(|e| ChatError::Invalid(format!("pair record v4 body decode: {e}")))?;
    Ok(Some(record))
}

/// Resolve a contact's current device list from `relay`, applying the
/// anti-rollback defense (M6 design hard-req 1).
///
/// GETs the contact's [`PairRecordV4`], verifies it end-to-end
/// ([`verify_pair_record_v4`]: user signature + per-device bindings +
/// structural rules) AND that it is FOR the requested `user_id_hex`, then
/// compares its `revision` against the last accepted for this contact (the
/// cached record's revision, the anti-rollback watermark). A record whose
/// revision is strictly greater is accepted and cached; anything else -- a
/// rollback, a stale copy, a wrong-user record, a bad signature, or an
/// unreachable relay -- is REJECTED and the last-accepted cached record is
/// returned unchanged. `None` only when the contact has never published and
/// nothing is cached, so DM fanout falls back to the single-device path.
///
/// # Errors
/// [`ChatError`] on a malformed `user_id_hex` or a local cache read/write
/// failure. A relay-side failure degrades to the cached record, never an error.
pub async fn resolve_pair_record_v4(
    data_dir: &Path,
    user_id_hex: &str,
    relay: &url::Url,
    http: &reqwest::Client,
) -> Result<Option<PairRecordV4>, ChatError> {
    let cached = load_contact_pair_record_v4(data_dir, user_id_hex)?;
    let last_seen = cached.as_ref().map_or(0, |r| r.revision);

    // A transient relay problem (unreachable, non-2xx, malformed body) must not
    // break fanout: keep the cached last-accepted device list.
    let fetched = match get_pair_record_v4(relay, user_id_hex, http).await {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(cached),
        Err(e) => {
            log::debug!("resolve_pair_record_v4: relay fetch failed, using cached: {e}");
            return Ok(cached);
        }
    };

    // Accept only a record that is FOR this contact, verifies end-to-end, and
    // strictly beats the watermark; otherwise reject and keep the cached copy.
    let acceptable = fetched.user_id_hex == user_id_hex
        && verify_pair_record_v4(&fetched).is_ok()
        && fetched.revision > last_seen;
    if !acceptable {
        return Ok(cached);
    }
    save_contact_pair_record_v4(data_dir, &fetched)?;
    Ok(Some(fetched))
}

/// The device agents present in `old` but absent from `new` -- the devices a
/// newer `PairRecordV4` revision removed. Feed these to
/// `OutboxStore::drop_bubbles_for_peers` to cancel their pending outbox sends,
/// so a message is never retried at a device no longer in the account.
#[must_use]
pub fn removed_device_agents(
    old: &PairRecordV4,
    new: &PairRecordV4,
) -> Vec<crate::identity::AgentId> {
    let kept: std::collections::HashSet<&str> = new
        .devices
        .iter()
        .map(|d| d.agent_id_hex.as_str())
        .collect();
    old.devices
        .iter()
        .filter(|d| !kept.contains(d.agent_id_hex.as_str()))
        .map(|d| crate::identity::AgentId(d.agent_id_hex.clone()))
        .collect()
}

/// Accept a proactively-pushed [`PairRecordV4`] (M6.7 revoke-push receive).
///
/// Mirrors the acceptance gate of [`resolve_pair_record_v4`] but takes the
/// record straight from the push instead of fetching it from the relay. A
/// `PairRecordPush` is unsealed and public, so the record's OWN user
/// signature plus the anti-rollback revision check are the only authority a
/// contact trusts. Accepts iff the record is for `expected_user_id_hex` (the
/// pushing contact -- never cache under a different contact's key), its user
/// signature verifies, AND its `revision` STRICTLY beats the cached
/// watermark. On accept, caches it and returns `(old_cached, new)` so the
/// caller can diff removed devices via [`removed_device_agents`] and cancel
/// their pending outbox sends; on reject, returns `None` and leaves the
/// cache untouched.
///
/// # Errors
/// A malformed `expected_user_id_hex`, a malformed record user id, or a
/// cache I/O error.
pub fn accept_pushed_pair_record_v4(
    data_dir: &Path,
    expected_user_id_hex: &str,
    record: PairRecordV4,
) -> Result<Option<(Option<PairRecordV4>, PairRecordV4)>, ChatError> {
    let cached = load_contact_pair_record_v4(data_dir, expected_user_id_hex)?;
    let last_seen = cached.as_ref().map_or(0, |r| r.revision);
    let acceptable = record.user_id_hex == expected_user_id_hex
        && verify_pair_record_v4(&record).is_ok()
        && record.revision > last_seen;
    if !acceptable {
        return Ok(None);
    }
    save_contact_pair_record_v4(data_dir, &record)?;
    Ok(Some((cached, record)))
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
    fn accept_pushed_record_gates_on_user_verify_and_strictly_newer_revision() {
        let (contact_dir, contact_master) = seeded_vault();
        let (my_dir, _me) = seeded_vault();
        let ts = 1_700_000_000_000;

        // The contact's rev-1 record (two devices), signed by the contact's key.
        let devices_v1 = vec![device_entry(3, true), device_entry(4, false)];
        let rec_v1 = mint_and_cache_pair_record_v4_from_master(
            contact_dir.path(),
            &contact_master,
            1,
            ts,
            &devices_v1,
        )
        .unwrap();
        let cuid = rec_v1.user_id_hex.clone();

        // First push accepted (no cache yet): returns (None, new) and caches.
        let (old0, new0) = accept_pushed_pair_record_v4(my_dir.path(), &cuid, rec_v1.clone())
            .unwrap()
            .expect("first push accepted");
        assert!(old0.is_none());
        assert_eq!(new0.revision, 1);
        assert_eq!(
            load_contact_pair_record_v4(my_dir.path(), &cuid)
                .unwrap()
                .unwrap()
                .revision,
            1
        );

        // Replay of the same revision is rejected (must be STRICTLY newer).
        assert!(
            accept_pushed_pair_record_v4(my_dir.path(), &cuid, rec_v1.clone())
                .unwrap()
                .is_none()
        );

        // Rev-2 removing device 4: accepted, returns the old cached + new so the
        // caller can diff the removed device.
        let devices_v2 = vec![device_entry(3, true)];
        let rec_v2 = mint_and_cache_pair_record_v4_from_master(
            contact_dir.path(),
            &contact_master,
            2,
            ts + 1,
            &devices_v2,
        )
        .unwrap();
        let (old1, new1) = accept_pushed_pair_record_v4(my_dir.path(), &cuid, rec_v2.clone())
            .unwrap()
            .expect("newer push accepted");
        let old1 = old1.expect("prior cached record present");
        assert_eq!(old1.revision, 1);
        assert_eq!(new1.revision, 2);
        assert_eq!(
            removed_device_agents(&old1, &new1),
            vec![crate::identity::AgentId(devices_v1[1].agent_id_hex.clone())]
        );

        // A record whose user_id is not the expected contact is rejected even
        // though it verifies -- never cache under the wrong contact's key.
        assert!(
            accept_pushed_pair_record_v4(my_dir.path(), &"ff".repeat(32), rec_v2.clone())
                .unwrap()
                .is_none()
        );

        // A tampered record (revision bumped without re-signing) fails verify
        // and is rejected, proving verify gates BEFORE the revision compare.
        let mut tampered = rec_v2.clone();
        tampered.revision = 99;
        assert!(accept_pushed_pair_record_v4(my_dir.path(), &cuid, tampered)
            .unwrap()
            .is_none());
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

    /// Mint a real account-signed [`AgentCertificate`] for a device.
    fn device_cert(
        dir: &std::path::Path,
        master: &MasterKey,
        seed: u8,
    ) -> crate::fabric::AgentCertificate {
        let signer = MlDsaSigner::from_seed(&[seed; 32]);
        crate::local_signer::with_user_key_from_master(dir, master, |user| {
            crate::fabric::mint_agent_certificate(
                user,
                &hex::encode(signer.agent_id()),
                &signer.public_key(),
                &[seed; 1184],
                1_700_000_000_000,
            )
        })
        .unwrap()
    }

    /// A cached device-1 record at revision 1 (the enroll precondition).
    fn seed_device_one_record(dir: &std::path::Path, master: &MasterKey) {
        mint_and_cache_pair_record_v4_from_master(dir, master, 1, 1, &[device_entry(1, true)])
            .unwrap();
    }

    #[test]
    fn append_errors_without_a_cached_record() {
        let (dir, master) = seeded_vault();
        let cert = device_cert(dir.path(), &master, 2);
        let out =
            append_and_mint_from_master(dir.path(), &master, &cert, vec!["https://a".into()], 1);
        assert!(out.is_err(), "cannot append to a nonexistent device list");
    }

    // ───────────────────────── M6.7 revoke publish-side ────────────────

    #[test]
    fn revoke_drops_the_device_and_bumps_revision() {
        let (dir, master) = seeded_vault();
        // Two-device account: dev 1 (primary) + dev 2.
        mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1,
            &[device_entry(1, true), device_entry(2, false)],
        )
        .unwrap();
        let dev2 = device_entry(2, false).agent_id_hex;
        let out = remove_and_mint_from_master(dir.path(), &master, &dev2, 2).unwrap();
        assert_eq!(out.revision, 2, "revoke bumps the revision");
        assert_eq!(out.devices.len(), 1, "the revoked device is gone");
        assert!(
            out.devices.iter().all(|d| d.agent_id_hex != dev2),
            "dev 2 must not be in the new record",
        );
        verify_pair_record_v4(&out).expect("the smaller record stays user-signed + valid");
    }

    #[test]
    fn revoke_errors_on_a_device_not_in_the_list() {
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master);
        let stranger = device_entry(9, false).agent_id_hex;
        assert!(
            remove_and_mint_from_master(dir.path(), &master, &stranger, 2).is_err(),
            "revoking a non-device must error",
        );
    }

    #[test]
    fn revoke_refuses_to_remove_the_only_device() {
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master); // one device (seed 1, primary)
        let dev1 = device_entry(1, true).agent_id_hex;
        assert!(
            remove_and_mint_from_master(dir.path(), &master, &dev1, 2).is_err(),
            "cannot revoke the last device; that is account recovery",
        );
    }

    #[test]
    fn revoke_of_the_primary_promotes_a_survivor() {
        let (dir, master) = seeded_vault();
        mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1,
            &[device_entry(1, true), device_entry(2, false)],
        )
        .unwrap();
        let dev1 = device_entry(1, true).agent_id_hex;
        let out = remove_and_mint_from_master(dir.path(), &master, &dev1, 2).unwrap();
        assert_eq!(out.devices.len(), 1);
        assert!(
            out.devices[0].primary,
            "removing the primary must promote the survivor",
        );
        verify_pair_record_v4(&out).expect("exactly-one-primary must hold after promotion");
    }

    #[test]
    fn append_and_mint_adds_a_device_and_bumps_revision() {
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master);
        let cert = device_cert(dir.path(), &master, 2);
        let record =
            append_and_mint_from_master(dir.path(), &master, &cert, vec!["https://r.ex".into()], 5)
                .unwrap();

        verify_pair_record_v4(&record).unwrap();
        assert_eq!(record.revision, 2);
        assert_eq!(record.devices.len(), 2);
        let entry = record
            .devices
            .iter()
            .find(|d| d.agent_id_hex == cert.agent_id_hex)
            .unwrap();
        assert_eq!(entry.ml_dsa_pubkey_b64, cert.agent_ml_dsa_pubkey_b64);
        assert_eq!(entry.kem_pubkey_b64, cert.kem_pubkey_b64);
        assert!(!entry.primary);
        assert_eq!(entry.advertised_relays, vec!["https://r.ex".to_string()]);
        // cert_b64 round-trips back to the exact certificate.
        let raw = B64.decode(&entry.cert_b64).unwrap();
        let back: crate::fabric::AgentCertificate = serde_json::from_slice(&raw).unwrap();
        assert_eq!(back, cert);
        assert_eq!(load_pair_record_v4(dir.path()).unwrap().unwrap(), record);
    }

    #[test]
    fn append_is_idempotent_replacing_the_same_agent() {
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master);
        let cert = device_cert(dir.path(), &master, 2);
        append_and_mint_from_master(dir.path(), &master, &cert, vec!["https://a".into()], 2)
            .unwrap();
        // Re-append the SAME agent with new relays: replace, do not duplicate.
        let record =
            append_and_mint_from_master(dir.path(), &master, &cert, vec!["https://b".into()], 3)
                .unwrap();
        assert_eq!(record.devices.len(), 2, "replaced in place, not duplicated");
        let entry = record
            .devices
            .iter()
            .find(|d| d.agent_id_hex == cert.agent_id_hex)
            .unwrap();
        assert_eq!(entry.advertised_relays, vec!["https://b".to_string()]);
        assert_eq!(record.revision, 3);
    }

    #[tokio::test]
    async fn append_publish_uses_the_new_device_relays() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master);
        let cert = device_cert(dir.path(), &master, 2);
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let dev_relays = vec!["https://dev.ex".to_string()];
        let record =
            append_publish_from_master(dir.path(), &master, &cert, &dev_relays, &relay, &http, 9)
                .await
                .unwrap();
        assert_eq!(record.revision, 2);
        assert_eq!(record.devices.len(), 2);
        // The entry carries the NEW DEVICE relays, not the POST relay.
        let entry = record
            .devices
            .iter()
            .find(|d| d.agent_id_hex == cert.agent_id_hex)
            .unwrap();
        assert_eq!(entry.advertised_relays, dev_relays);
    }

    #[tokio::test]
    async fn append_publish_errors_on_revision_reject() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({"current_revision": 99u64})),
            )
            .mount(&server)
            .await;
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master);
        let cert = device_cert(dir.path(), &master, 2);
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let out =
            append_publish_from_master(dir.path(), &master, &cert, &[], &relay, &http, 9).await;
        assert!(out.is_err(), "a revision reject on enroll is an error");
    }

    #[tokio::test]
    async fn append_publish_falls_back_to_post_relay_when_relays_empty() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let (dir, master) = seeded_vault();
        seed_device_one_record(dir.path(), &master);
        let cert = device_cert(dir.path(), &master, 2);
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let http = reqwest::Client::new();
        let record = append_publish_from_master(dir.path(), &master, &cert, &[], &relay, &http, 9)
            .await
            .unwrap();
        let entry = record
            .devices
            .iter()
            .find(|d| d.agent_id_hex == cert.agent_id_hex)
            .unwrap();
        // Empty new-device relays fall back to the POST relay.
        assert_eq!(entry.advertised_relays, vec![relay.to_string()]);
    }

    fn user_kp(seed: u8) -> crate::fabric::UserKeypair {
        crate::fabric::UserKeypair::from_seed(&[seed; 32])
    }

    fn valid_record(user: &crate::fabric::UserKeypair, revision: u64) -> PairRecordV4 {
        crate::fabric::mint_pair_record_v4(user, revision, 1_000, &[device_entry(3, true)]).unwrap()
    }

    /// A GET mock serving `record` at any path, plus the relay URL to hit it.
    async fn serve_get(record: PairRecordV4) -> (wiremock::MockServer, url::Url) {
        use wiremock::matchers::method;
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(record))
            .mount(&server)
            .await;
        let url = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        (server, url)
    }

    /// A GET mock returning `code` (no body).
    async fn serve_status(code: u16) -> (wiremock::MockServer, url::Url) {
        use wiremock::matchers::method;
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(code))
            .mount(&server)
            .await;
        let url = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        (server, url)
    }

    #[test]
    fn contact_record_cache_round_trips() {
        let dir = tempdir().unwrap();
        let user = user_kp(8);
        let rec = valid_record(&user, 3);
        let uid = user.user_id_hex();
        assert!(load_contact_pair_record_v4(dir.path(), &uid)
            .unwrap()
            .is_none());
        save_contact_pair_record_v4(dir.path(), &rec).unwrap();
        assert_eq!(
            load_contact_pair_record_v4(dir.path(), &uid)
                .unwrap()
                .unwrap(),
            rec
        );
    }

    #[test]
    fn load_contact_rejects_a_non_hex_user_id() {
        let dir = tempdir().unwrap();
        assert!(load_contact_pair_record_v4(dir.path(), "../evil").is_err());
    }

    #[tokio::test]
    async fn resolve_accepts_first_then_rejects_a_rollback() {
        let dir = tempdir().unwrap();
        let user = user_kp(8);
        let uid = user.user_id_hex();
        let http = reqwest::Client::new();

        let (_s2, r2) = serve_get(valid_record(&user, 2)).await;
        let got = resolve_pair_record_v4(dir.path(), &uid, &r2, &http)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.revision, 2);

        // A rollback to rev-1 is rejected; the cached rev-2 stands.
        let (_s1, r1) = serve_get(valid_record(&user, 1)).await;
        let got = resolve_pair_record_v4(dir.path(), &uid, &r1, &http)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.revision, 2);
    }

    #[tokio::test]
    async fn resolve_accepts_a_newer_revision() {
        let dir = tempdir().unwrap();
        let user = user_kp(8);
        let uid = user.user_id_hex();
        let http = reqwest::Client::new();
        save_contact_pair_record_v4(dir.path(), &valid_record(&user, 2)).unwrap();
        let (_s, r) = serve_get(valid_record(&user, 3)).await;
        let got = resolve_pair_record_v4(dir.path(), &uid, &r, &http)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.revision, 3);
    }

    #[tokio::test]
    async fn resolve_falls_back_to_cached_on_404_and_on_error() {
        let dir = tempdir().unwrap();
        let user = user_kp(8);
        let uid = user.user_id_hex();
        let http = reqwest::Client::new();
        save_contact_pair_record_v4(dir.path(), &valid_record(&user, 2)).unwrap();

        let (_s404, r404) = serve_status(404).await;
        assert_eq!(
            resolve_pair_record_v4(dir.path(), &uid, &r404, &http)
                .await
                .unwrap()
                .unwrap()
                .revision,
            2
        );

        let (_s500, r500) = serve_status(500).await;
        assert_eq!(
            resolve_pair_record_v4(dir.path(), &uid, &r500, &http)
                .await
                .unwrap()
                .unwrap()
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn resolve_is_none_when_never_published() {
        let dir = tempdir().unwrap();
        let uid = user_kp(8).user_id_hex();
        let http = reqwest::Client::new();
        let (_s, r) = serve_status(404).await;
        assert!(resolve_pair_record_v4(dir.path(), &uid, &r, &http)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn resolve_rejects_a_record_for_a_different_user() {
        let dir = tempdir().unwrap();
        let alice = user_kp(8);
        let bob = user_kp(9);
        let http = reqwest::Client::new();
        // The relay serves Bob's record when we asked for Alice: reject it.
        let (_s, r) = serve_get(valid_record(&bob, 5)).await;
        assert!(
            resolve_pair_record_v4(dir.path(), &alice.user_id_hex(), &r, &http)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn resolve_rejects_a_bad_signature() {
        let dir = tempdir().unwrap();
        let user = user_kp(8);
        let uid = user.user_id_hex();
        let http = reqwest::Client::new();
        let mut tampered = valid_record(&user, 2);
        tampered.user_signature_b64 = B64.encode([0u8; 64]); // not a valid signature
        let (_s, r) = serve_get(tampered).await;
        assert!(resolve_pair_record_v4(dir.path(), &uid, &r, &http)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn removed_device_agents_lists_only_the_dropped_devices() {
        let d1 = device_entry(1, true);
        let d2 = device_entry(2, false);
        let d3 = device_entry(3, false);
        let old = PairRecordV4 {
            devices: vec![d1.clone(), d2.clone()],
            ..bare_record()
        };
        let new = PairRecordV4 {
            devices: vec![d2, d3],
            ..bare_record()
        };
        // Only d1 was dropped; d2 kept, d3 added.
        assert_eq!(
            removed_device_agents(&old, &new),
            vec![crate::identity::AgentId(d1.agent_id_hex)]
        );
    }

    #[tokio::test]
    async fn removed_device_detection_needs_the_old_record_before_resolve() {
        // The M6.7 revoke seam that fanout wires: resolve_pair_record_v4
        // OVERWRITES the cache on accept, so the removed-device diff must
        // capture the OLD record BEFORE calling resolve. This locks that
        // the correct ordering surfaces a device dropped across a revision
        // bump, and that diffing the post-resolve cache against the new
        // record (the footgun) finds nothing.
        let dir = tempdir().unwrap();
        let user = user_kp(8);
        let uid = user.user_id_hex();
        let http = reqwest::Client::new();

        let dev_a = device_entry(3, true);
        let dev_b = device_entry(4, false);
        let old =
            crate::fabric::mint_pair_record_v4(&user, 2, 1_000, &[dev_a.clone(), dev_b.clone()])
                .unwrap();
        let new = crate::fabric::mint_pair_record_v4(&user, 3, 1_000, std::slice::from_ref(&dev_a))
            .unwrap();

        // Prime the cache as if `old` (rev 2) was the last accepted list.
        save_contact_pair_record_v4(dir.path(), &old).unwrap();

        // Correct fanout ordering: snapshot the OLD list, THEN resolve.
        let before = load_contact_pair_record_v4(dir.path(), &uid)
            .unwrap()
            .unwrap();
        let (_s, r) = serve_get(new.clone()).await;
        let after = resolve_pair_record_v4(dir.path(), &uid, &r, &http)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.revision, 3, "the rev-3 removal record is accepted");

        // Correct ordering surfaces exactly the removed device B.
        assert_eq!(
            removed_device_agents(&before, &after),
            vec![crate::identity::AgentId(dev_b.agent_id_hex.clone())],
            "load-before-resolve detects the revoked device",
        );

        // Footgun lock: resolve already overwrote the cache, so a
        // load-AFTER-resolve yields `new`; diffing it against `after`
        // finds nothing and a revoked device would keep receiving.
        let post = load_contact_pair_record_v4(dir.path(), &uid)
            .unwrap()
            .unwrap();
        assert!(
            removed_device_agents(&post, &after).is_empty(),
            "load-after-resolve misses the revocation (the ordering hazard)",
        );
    }
}
