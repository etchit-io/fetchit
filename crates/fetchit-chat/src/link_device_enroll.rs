//! M6.4 enrollment completion (existing-device side).
//!
//! After the existing device confirms a scanned link offer and mints the new
//! device's [`AgentCertificate`], and after
//! the account roster is republished at revision N+1 (M6.2), the new device
//! must be admitted into the account's private **devices-group** -- the
//! invisible MLS self-sync channel (design section VI) that later carries
//! contacts, settings, and DM mirrors.
//!
//! M6.4 wires enrollment all the way up to that admission boundary but does
//! **not** perform the MLS work: the real create-or-get + `TreeKEM` invite is
//! M6.6. The boundary is a [`DevicesGroupSink`] trait so M6.6 drops the live
//! implementation in without touching the enrollment composition, and
//! [`PendingDevicesGroupSink`] is the M6.4 no-op stub that lets enrollment land
//! and device-verify (cert mint + roster publish) before the channel exists.

use crate::error::ChatError;
use crate::fabric::AgentCertificate;
use async_trait::async_trait;

/// The devices-group side of enrollment: admit a freshly certified device into
/// the account's private devices-group (design section VI), creating the group
/// on the first enrollment.
///
/// Kept a trait so the M6.4 [`PendingDevicesGroupSink`] stub and the M6.6 live
/// MLS implementation are interchangeable behind [`finish_enrollment`].
#[async_trait]
pub trait DevicesGroupSink: Send + Sync {
    /// Admit the device certified by `cert` into the account devices-group.
    ///
    /// Returns `true` when the admission was actually performed (the M6.6 live
    /// impl) and `false` when it was deferred (the M6.4 stub) -- surfaced in
    /// [`EnrollOutcome::devices_group_admitted`] so a shell can honestly show
    /// "linked, syncing" versus "linked, sync pending".
    ///
    /// # Errors
    /// [`ChatError`] when the (M6.6) MLS create-or-get / invite fails. The M6.4
    /// stub never errors.
    async fn admit_device(&self, cert: &AgentCertificate) -> Result<bool, ChatError>;

    /// Remove device `agent_id_hex` from the account devices-group and rekey
    /// (post-compromise security) -- the inverse of [`Self::admit_device`].
    /// Driven by the M6.7 revocation orchestration: the pair record is the
    /// source of truth, and its revoke path calls in here for the MLS
    /// leaf-removal + rekey.
    ///
    /// Takes the bare `agent_id_hex` because the leaf to drop is all MLS needs,
    /// and the revoke path already has it from `removed_device_agents` (no cert
    /// re-parse). Returns `true` when the removal + rekey was performed (the
    /// M6.6 live impl) and `false` when deferred (the M6.4 stub).
    ///
    /// # Errors
    /// [`ChatError`] when the (M6.6) MLS remove / rekey fails. The M6.4 stub
    /// never errors.
    async fn remove_device(&self, agent_id_hex: &str) -> Result<bool, ChatError>;
}

/// M6.4 devices-group stub: logs the pending admission/removal and performs no
/// MLS work, returning `false` (deferred). Replaced by the real create-or-get +
/// `TreeKEM` invite/remove in M6.6, so enrollment can land and device-verify
/// (cert mint + roster publish) before the self-sync channel exists.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingDevicesGroupSink;

#[async_trait]
impl DevicesGroupSink for PendingDevicesGroupSink {
    async fn admit_device(&self, cert: &AgentCertificate) -> Result<bool, ChatError> {
        log::info!(
            "enroll: devices-group admission for device {} deferred to M6.6",
            cert.agent_id_hex
        );
        Ok(false)
    }

    async fn remove_device(&self, agent_id_hex: &str) -> Result<bool, ChatError> {
        log::info!("revoke: devices-group removal for device {agent_id_hex} deferred to M6.6");
        Ok(false)
    }
}

/// Outcome of a completed enrollment (existing-device side): what the shell
/// shows the user after they confirm and the cert + roster land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollOutcome {
    /// The newly linked device's agent id (hex).
    pub agent_id_hex: String,
    /// The account roster revision published for this enrollment (N+1).
    pub record_revision: u64,
    /// `true` once the devices-group admission is live (M6.6); `false` while it
    /// is the M6.4 stub.
    pub devices_group_admitted: bool,
}

/// Compose an [`EnrollOutcome`] from the already-produced enrollment parts: the
/// minted `cert`, the published roster `record_revision` (M6.2), and the
/// devices-group admission via `sink`.
///
/// Parameterized over the roster revision (rather than performing the M6.2
/// publish itself) so the composition is unit-testable without a relay and so
/// the roster publish and the devices-group admission stay decoupled.
///
/// # Errors
/// [`ChatError`] when `sink.admit_device` fails.
pub async fn finish_enrollment(
    cert: &AgentCertificate,
    record_revision: u64,
    sink: &dyn DevicesGroupSink,
) -> Result<EnrollOutcome, ChatError> {
    let devices_group_admitted = sink.admit_device(cert).await?;
    Ok(EnrollOutcome {
        agent_id_hex: cert.agent_id_hex.clone(),
        record_revision,
        devices_group_admitted,
    })
}

/// Complete an enrollment from an already-resolved `master` + already-fetched
/// `offer`: mint the new device's account certificate, republish the roster at
/// revision N+1 with the new device (`new_device_relays` seeding its entry
/// reachability), and admit it to the devices-group via `sink` -- all off the
/// one unlocked `master` (`confirm_offer_from_master` signs the cert,
/// `append_publish_from_master` signs the record). The internal seam
/// [`enroll_confirmed_device`] shares with the unit tests (no vault unlock, no
/// relay offer-fetch).
///
/// # Errors
/// [`ChatError`] on an expired offer, no cached account record, or a relay
/// rejection (incl. a concurrent-sibling revision conflict).
// Threads the enrollment context (vault, master, offer, relays, clock, http,
// devices-group sink) it composes; factoring into a struct would hide the seam
// the FFI + tests wire, per the crate convention (cf. `lan_noise`).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enroll_from_master(
    data_dir: &std::path::Path,
    master: &crate::at_rest::MasterKey,
    offer: &crate::link_device::LinkDeviceOffer,
    new_device_relays: &[String],
    post_relay: &url::Url,
    now_ms: u64,
    http: &reqwest::Client,
    sink: &dyn DevicesGroupSink,
) -> Result<EnrollOutcome, ChatError> {
    let cert = crate::link_device_flow::confirm_offer_from_master(data_dir, master, offer, now_ms)?;
    let record = crate::pair_record_v4::append_publish_from_master(
        data_dir,
        master,
        &cert,
        new_device_relays,
        post_relay,
        http,
        now_ms,
    )
    .await?;
    finish_enrollment(&cert, record.revision, sink).await
}

/// Complete an enrollment on the existing device: fetch + validate the scanned
/// `offer`, mint the new device's account certificate, republish the account
/// roster at revision N+1, and (M6.4 stub / M6.6 real) admit the new device to
/// the devices-group -- all under a **single** vault unlock.
///
/// `uri` is the scanned `fetchit://link/v1/...` pointer; `passphrase` unlocks
/// this device's vault (`None` uses the OS keychain); `post_relay` is the
/// account relay the roster is published to; `now_ms` bounds offer freshness
/// and stamps the cert + record. The new device's own advertised relays are
/// read from the URI (`r=`, where it published its offer) so its roster entry
/// is reachable from the first resolve.
///
/// # Errors
/// [`ChatError`] on an expired / malformed offer, a wrong passphrase, no cached
/// account record, or a relay rejection.
pub async fn enroll_confirmed_device(
    data_dir: &std::path::Path,
    passphrase: Option<&str>,
    uri: &str,
    post_relay: &url::Url,
    now_ms: u64,
    sink: &dyn DevicesGroupSink,
) -> Result<EnrollOutcome, ChatError> {
    // SSRF-guarded client for both the offer fetch and the roster POST; the
    // per-request `guard_relay_url` inside those paths does the range checks.
    let http = crate::relay_http::guarded_client();
    let parsed = crate::link_device_uri::parse_link_device_uri(uri)
        .map_err(|e| ChatError::Invalid(format!("parse link uri: {e}")))?;
    let offer = crate::link_device_flow::fetch_link_offer(uri, &http).await?;
    let identity_vault = data_dir.join(crate::chat_identity::IDENTITY_FILE);
    let (master, _kdf_id, _argon_salt) =
        crate::client::resolve_master_key(&identity_vault, passphrase)?;
    enroll_from_master(
        data_dir,
        &master,
        &offer,
        &parsed.relays,
        post_relay,
        now_ms,
        &http,
        sink,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_cert() -> AgentCertificate {
        AgentCertificate {
            cert_version: 1,
            user_id_hex: "aa".repeat(32),
            agent_id_hex: "bb".repeat(32),
            agent_ml_dsa_pubkey_b64: String::new(),
            kem_pubkey_b64: String::new(),
            added_at_ms: 1_700_000_000_000,
            sig_b64: String::new(),
        }
    }

    #[tokio::test]
    async fn stub_defers_admission() {
        let admitted = PendingDevicesGroupSink
            .admit_device(&sample_cert())
            .await
            .unwrap();
        assert!(!admitted, "the M6.4 stub defers admission to M6.6");
    }

    #[tokio::test]
    async fn stub_defers_removal() {
        let removed = PendingDevicesGroupSink
            .remove_device(&"aa".repeat(32))
            .await
            .unwrap();
        assert!(!removed, "the M6.4 stub defers removal to M6.6");
    }

    #[tokio::test]
    async fn finish_enrollment_carries_cert_identity_and_revision() {
        let cert = sample_cert();
        let outcome = finish_enrollment(&cert, 7, &PendingDevicesGroupSink)
            .await
            .unwrap();
        assert_eq!(outcome.agent_id_hex, cert.agent_id_hex);
        assert_eq!(outcome.record_revision, 7);
        assert!(
            !outcome.devices_group_admitted,
            "stub leaves admission pending"
        );
    }

    #[tokio::test]
    async fn enroll_from_master_appends_the_new_device_and_publishes() {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use crate::link_device::LinkDeviceOffer;
        use crate::local_signer::LocalSignerVault;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use fetchit_relay_client::{MlDsaSigner, Signer};
        use fetchit_relay_proto::pair_record::DeviceEntryV4;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use zeroize::Zeroizing;

        // Existing device: a vault + a cached revision-1 roster holding device #1.
        let dir = tempfile::tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let d1 = MlDsaSigner::from_seed(&[1u8; 32]);
        let device1 = DeviceEntryV4 {
            agent_id_hex: hex::encode(d1.agent_id()),
            ml_dsa_pubkey_b64: B64.encode(d1.public_key()),
            kem_pubkey_b64: B64.encode([1u8; 1184]),
            advertised_relays: vec!["https://account.example".to_string()],
            cert_b64: B64.encode([1u8; 32]),
            added_at_ms: 1_600_000_000_000,
            primary: true,
        };
        crate::pair_record_v4::mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1_600_000_000_000,
            &[device1],
        )
        .unwrap();

        // New device: a fresh offer whose real ML-DSA binds its agent id.
        let newdev = MlDsaSigner::from_seed(&[2u8; 32]);
        let offer = LinkDeviceOffer::mint(
            hex::encode(newdev.agent_id()),
            &newdev.public_key(),
            &[0u8; 1184],
            &[7u8; 16],
            1_800_000_000_000,
        );

        // Relay accepts the revision-2 publish.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let relay = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let new_relays = vec!["https://newdevice.example".to_string()];

        let outcome = enroll_from_master(
            dir.path(),
            &master,
            &offer,
            &new_relays,
            &relay,
            1_700_000_000_000,
            &reqwest::Client::new(),
            &PendingDevicesGroupSink,
        )
        .await
        .unwrap();

        assert_eq!(outcome.agent_id_hex, hex::encode(newdev.agent_id()));
        assert_eq!(outcome.record_revision, 2, "device-1 rev-1 -> enroll rev-2");
        assert!(!outcome.devices_group_admitted, "M6.4 devices-group stub");

        // The published roster now lists both devices, and the new one carries
        // its own URI relays -- not the account POST relay.
        let cached = crate::pair_record_v4::load_pair_record_v4(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(cached.revision, 2);
        assert_eq!(cached.devices.len(), 2);
        let new_entry = cached
            .devices
            .iter()
            .find(|d| d.agent_id_hex == hex::encode(newdev.agent_id()))
            .expect("new device present in the republished roster");
        assert_eq!(new_entry.advertised_relays, new_relays);
    }

    /// M6.4 enroll end-to-end over a REAL relay-server (not a mock): the new
    /// device publishes its offer, the existing device fetches it back and
    /// enrolls, and the relay accepts the revision-2 roster -- exercising the
    /// whole `/v1/blob` + `/v1/pair-record-v4` round-trip on the wire.
    #[tokio::test]
    async fn enroll_round_trips_through_a_real_relay_server() {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use crate::link_device_flow::{create_link_offer, fetch_link_offer};
        use crate::local_signer::LocalSignerVault;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use fetchit_relay_client::{MlDsaSigner, Signer};
        use fetchit_relay_proto::pair_record::DeviceEntryV4;
        use fetchit_relay_proto::Region;
        use zeroize::Zeroizing;

        // A real relay serving /v1/blob (offer) + /v1/pair-record-v4 (roster),
        // on a fresh loopback port (serialized to dodge the probe/rebind race).
        let bound = crate::link_device_flow::spawn_ephemeral_relay(Region::Nyc).await;
        let relay = url::Url::parse(&format!("http://{bound}/")).unwrap();
        let relays = vec![format!("http://{bound}")];
        let http = crate::relay_http::guarded_client();

        // Existing device A: vault + cached revision-1 roster holding device #1.
        let dir = tempfile::tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let d1 = MlDsaSigner::from_seed(&[1u8; 32]);
        let device1 = DeviceEntryV4 {
            agent_id_hex: hex::encode(d1.agent_id()),
            ml_dsa_pubkey_b64: B64.encode(d1.public_key()),
            kem_pubkey_b64: B64.encode([1u8; 1184]),
            advertised_relays: relays.clone(),
            cert_b64: B64.encode([1u8; 32]),
            added_at_ms: 1_600_000_000_000,
            primary: true,
        };
        crate::pair_record_v4::mint_and_cache_pair_record_v4_from_master(
            dir.path(),
            &master,
            1,
            1_600_000_000_000,
            &[device1],
        )
        .unwrap();

        // New device B: real create_link_offer seals + PUTs the offer to the relay.
        let newdev = MlDsaSigner::from_seed(&[2u8; 32]);
        let created = create_link_offer(
            hex::encode(newdev.agent_id()),
            &newdev.public_key(),
            &[0u8; 1184],
            &relays,
            1_800_000_000_000,
            &http,
        )
        .await
        .unwrap();

        // Existing device A: GET the offer back off the relay, then enroll --
        // mint the cert + POST the revision-2 roster to the real relay.
        let offer = fetch_link_offer(&created.uri, &http).await.unwrap();
        let outcome = enroll_from_master(
            dir.path(),
            &master,
            &offer,
            &relays,
            &relay,
            1_700_000_000_000,
            &http,
            &PendingDevicesGroupSink,
        )
        .await
        .unwrap();

        // An Ok outcome means the relay POST was 2xx (not a RevisionReject), so
        // the enroll round-tripped end-to-end over the wire.
        assert_eq!(outcome.agent_id_hex, hex::encode(newdev.agent_id()));
        assert_eq!(outcome.record_revision, 2);
        assert!(!outcome.devices_group_admitted);
        let cached = crate::pair_record_v4::load_pair_record_v4(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            cached.devices.len(),
            2,
            "both devices in the published roster"
        );
    }
}
