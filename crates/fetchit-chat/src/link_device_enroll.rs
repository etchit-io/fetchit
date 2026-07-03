//! M6.4 enrollment completion (existing-device side).
//!
//! After the existing device confirms a scanned link offer and mints the new
//! device's [`AgentCertificate`](crate::fabric::AgentCertificate), and after
//! the account roster is republished at revision N+1 (M6.2), the new device
//! must be admitted into the account's private **devices-group** -- the
//! invisible MLS self-sync channel (design section VI) that later carries
//! contacts, settings, and DM mirrors.
//!
//! M6.4 wires enrollment all the way up to that admission boundary but does
//! **not** perform the MLS work: the real create-or-get + TreeKEM invite is
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
}

/// M6.4 devices-group stub: logs the pending admission and performs no MLS
/// work, returning `false` (deferred). Replaced by the real create-or-get +
/// TreeKEM invite in M6.6, so enrollment can land and device-verify (cert mint
/// + roster publish) before the self-sync channel exists.
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
}
