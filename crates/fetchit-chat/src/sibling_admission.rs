//! M6.5a sibling group admission (admin path): the authority guard, the
//! devices-group handshake payload, and the admit orchestration.
//!
//! When a user joins a chat group on one device, their other devices must land
//! in that same group with zero UI (design section V, "sibling admission").
//! The sibling derives a per-group `TreeKEM` `KeyPackage` locally — only it can
//! mint one (its own secret + the group id) — and ships it to an already
//! in-group device over the private devices-group as a [`SiblingJoinRequest`].
//! That in-group device authorizes the request ([`authorize_sibling_admission`])
//! and admits the sibling with `x0xd`'s invite-free `TreeKEM` direct-add
//! ([`SiblingGroupAdder`]).
//!
//! This module owns the security-critical, transport-free pieces: the request
//! payload, the authority guard, and [`handle_sibling_join_request`] (the
//! guard + idempotent-nonce + direct-add composition). The real `x0xd` HTTP
//! direct-add and the devices-group carrier (M6.6 `DevicesGroupSink`) are
//! concrete impls wired on top of these seams.

use crate::error::ChatError;
use crate::fabric::{verify_agent_certificate, AgentCertificate};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A sibling's request to be admitted into a chat group it is not yet in,
/// carried to an in-group device over the account devices-group.
///
/// The `KeyPackage` is derivable only by the requesting sibling itself (its own
/// secret + the group id), so a valid one for `group_id_hex` authenticates the
/// party joining; `cert` proves that sibling belongs to *this* account.
/// `nonce` is monotonic per `(account, group)` so an in-group device can drop a
/// duplicate it has already admitted (idempotent re-enroll / retry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingJoinRequest {
    /// The chat group the sibling wants into (64-hex group id).
    pub group_id_hex: String,
    /// The sibling's per-group `TreeKEM` `KeyPackage`, `STANDARD` base64 — the
    /// exact bytes `x0xd`'s direct-add takes as `treekem_key_package_b64`.
    pub treekem_key_package_b64: String,
    /// The sibling's account certificate; the in-group device verifies it
    /// chains to our own account before admitting.
    pub cert: AgentCertificate,
    /// Monotonic per `(account, group)` — an in-group device drops a nonce it
    /// has already admitted.
    pub nonce: u64,
}

/// Decide whether an in-group device may admit the sibling described by `cert`,
/// given the target group's secure plane.
///
/// Two independent gates, cheapest binding first:
/// 1. **Account authority** — the sibling's certificate MUST chain to *our*
///    account user key (`our_user_pubkey`). A device only ever admits its own
///    account's siblings; a cert that does not chain to us can only be a bug or
///    a tampered devices-group message, so we refuse before touching group
///    state or calling `x0xd`. This is the fabricated-sibling defense.
/// 2. **`TreeKem` plane only** — a legacy `Gss`-plane group has no Welcome, so
///    a direct-add there would leave the sibling a read-blind roster member
///    (design open-question #1 caveat). Refuse rather than half-admit.
///
/// # Errors
/// [`ChatError::Invalid`] if the certificate does not chain to our account, or
/// the group is not on the `TreeKem` plane.
pub fn authorize_sibling_admission(
    cert: &AgentCertificate,
    our_user_pubkey: &[u8],
    group_is_treekem: bool,
) -> Result<(), ChatError> {
    verify_agent_certificate(cert, our_user_pubkey).map_err(|e| {
        ChatError::Invalid(format!("sibling cert does not chain to our account: {e}"))
    })?;
    if !group_is_treekem {
        return Err(ChatError::Invalid(
            "sibling admission requires a TreeKem-plane group".into(),
        ));
    }
    Ok(())
}

/// The chat-group side of sibling admission: perform the invite-free `TreeKEM`
/// direct-add of an already-authorized sibling into a group.
///
/// Kept a trait (mirroring the M6.4 `DevicesGroupSink` idiom) so the
/// orchestration is unit-testable with a fake and the real `x0xd` call
/// (`POST /groups/:id/members` with `treekem_key_package_b64`) lands as one
/// concrete impl.
#[async_trait]
pub trait SiblingGroupAdder: Send + Sync {
    /// Direct-add sibling `agent_id_hex` into `group_id_hex` with its
    /// `treekem_key_package_b64`, so `x0xd` stages the Welcome and
    /// direct-delivers `MemberAdded` + the welcome ref to the sibling. The
    /// three map onto `x0xd`'s `POST /groups/:id/members` body — `agent_id`
    /// (required) plus `treekem_key_package_b64` (required for a `TreeKEM`
    /// group).
    ///
    /// # Errors
    /// [`ChatError`] when the `x0xd` direct-add fails (e.g. the group is gone
    /// or the `KeyPackage` is rejected).
    async fn direct_add(
        &self,
        group_id_hex: &str,
        agent_id_hex: &str,
        treekem_key_package_b64: &str,
    ) -> Result<(), ChatError>;
}

/// Outcome of handling a [`SiblingJoinRequest`] on an in-group device.
///
/// Refusals surface as an `Err` from [`handle_sibling_join_request`]; the ack
/// sent back over the devices-group maps `Ok(_)` / `Err(_)` to its own wire
/// result variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// The sibling was direct-added (Welcome staged + delivered).
    Admitted,
    /// This nonce was already admitted — an idempotent no-op (retry /
    /// re-enroll), no second admit performed.
    AlreadyAdmitted,
}

/// Handle a [`SiblingJoinRequest`] on an in-group device: authorize it against
/// our account and the group plane, drop a nonce already admitted, else
/// direct-add the sibling.
///
/// `admitted_nonce` is the highest nonce already admitted for this
/// `(account, group)` (the caller persists it); `request.nonce <=
/// admitted_nonce` is treated as a duplicate. `group_is_treekem` comes from the
/// group detail (`x0xd` `GET /groups/<id>`). Authority is checked *before* the
/// nonce so a replayed request with a forged cert can never be dedup-accepted.
///
/// # Errors
/// [`ChatError`] if the request fails [`authorize_sibling_admission`] or the
/// direct-add fails. On any refusal the `adder` is never called.
pub async fn handle_sibling_join_request(
    request: &SiblingJoinRequest,
    our_user_pubkey: &[u8],
    group_is_treekem: bool,
    admitted_nonce: Option<u64>,
    adder: &dyn SiblingGroupAdder,
) -> Result<AdmitOutcome, ChatError> {
    authorize_sibling_admission(&request.cert, our_user_pubkey, group_is_treekem)?;
    if admitted_nonce.is_some_and(|seen| request.nonce <= seen) {
        return Ok(AdmitOutcome::AlreadyAdmitted);
    }
    adder
        .direct_add(
            &request.group_id_hex,
            &request.cert.agent_id_hex,
            &request.treekem_key_package_b64,
        )
        .await?;
    Ok(AdmitOutcome::Admitted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fabric::{mint_agent_certificate, UserKeypair};
    use fetchit_relay_client::{MlDsaSigner, Signer};

    /// Our account's user pubkey + a valid cert for one of our sibling devices.
    fn our_account_and_sibling_cert() -> (Vec<u8>, AgentCertificate) {
        let user = UserKeypair::from_seed(&[5u8; 32]);
        let device = MlDsaSigner::from_seed(&[9u8; 32]);
        let cert = mint_agent_certificate(
            &user,
            &hex::encode(device.agent_id()),
            &device.public_key(),
            &[0x42; 64],
            1_000,
        )
        .unwrap();
        (user.public_key_bytes().to_vec(), cert)
    }

    /// A valid join request from one of our siblings, at `nonce`.
    fn our_request(nonce: u64) -> (Vec<u8>, SiblingJoinRequest) {
        let (our_pk, cert) = our_account_and_sibling_cert();
        let req = SiblingJoinRequest {
            group_id_hex: "2c".repeat(32),
            treekem_key_package_b64: "a2V5cGFja2FnZQ==".to_string(),
            cert,
            nonce,
        };
        (our_pk, req)
    }

    /// A fake `SiblingGroupAdder` that records the direct-adds it was asked to
    /// perform, so a test can assert both the outcome and that (for a refusal)
    /// no `x0xd` call happened.
    struct RecordingAdder {
        calls: std::sync::Mutex<Vec<(String, String, String)>>,
    }
    impl RecordingAdder {
        fn new() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<(String, String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl SiblingGroupAdder for RecordingAdder {
        async fn direct_add(&self, group: &str, agent: &str, kp: &str) -> Result<(), ChatError> {
            self.calls
                .lock()
                .unwrap()
                .push((group.to_string(), agent.to_string(), kp.to_string()));
            Ok(())
        }
    }

    #[test]
    fn authorizes_our_sibling_into_a_treekem_group() {
        let (our_pk, cert) = our_account_and_sibling_cert();
        authorize_sibling_admission(&cert, &our_pk, true).unwrap();
    }

    #[test]
    fn refuses_a_cert_that_does_not_chain_to_our_account() {
        // A validly-signed cert for a DIFFERENT account must not authorize an
        // admit into ours — the fabricated-sibling defense.
        let (_our_pk, cert) = our_account_and_sibling_cert();
        let other_account = UserKeypair::from_seed(&[123u8; 32]);
        assert!(
            authorize_sibling_admission(&cert, other_account.public_key_bytes(), true).is_err()
        );
    }

    #[test]
    fn refuses_a_non_treekem_group() {
        // Cert is valid, but a Gss-plane group would leave a read-blind member.
        let (our_pk, cert) = our_account_and_sibling_cert();
        assert!(authorize_sibling_admission(&cert, &our_pk, false).is_err());
    }

    #[test]
    fn request_round_trips_through_json() {
        let (_our_pk, cert) = our_account_and_sibling_cert();
        let req = SiblingJoinRequest {
            group_id_hex: "2c".repeat(32),
            treekem_key_package_b64: "a2V5cGFja2FnZQ==".to_string(),
            cert,
            nonce: 7,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: SiblingJoinRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[tokio::test]
    async fn admits_an_authorized_sibling() {
        let (our_pk, req) = our_request(1);
        let adder = RecordingAdder::new();
        let outcome = handle_sibling_join_request(&req, &our_pk, true, None, &adder)
            .await
            .unwrap();
        assert_eq!(outcome, AdmitOutcome::Admitted);
        assert_eq!(
            adder.calls(),
            vec![(
                req.group_id_hex.clone(),
                req.cert.agent_id_hex.clone(),
                req.treekem_key_package_b64.clone()
            )],
            "the sibling's group + agent id + KeyPackage are what we direct-add"
        );
    }

    #[tokio::test]
    async fn refuses_a_foreign_cert_without_calling_x0xd() {
        let (_our_pk, req) = our_request(1);
        let other_account = UserKeypair::from_seed(&[200u8; 32]);
        let adder = RecordingAdder::new();
        let result =
            handle_sibling_join_request(&req, other_account.public_key_bytes(), true, None, &adder)
                .await;
        assert!(result.is_err());
        assert!(
            adder.calls().is_empty(),
            "a non-sibling never reaches the direct-add"
        );
    }

    #[tokio::test]
    async fn is_idempotent_on_a_replayed_nonce() {
        let (our_pk, req) = our_request(5);
        let adder = RecordingAdder::new();
        let outcome = handle_sibling_join_request(&req, &our_pk, true, Some(5), &adder)
            .await
            .unwrap();
        assert_eq!(outcome, AdmitOutcome::AlreadyAdmitted);
        assert!(
            adder.calls().is_empty(),
            "a replayed nonce is not re-added to the group"
        );
    }

    #[tokio::test]
    async fn refuses_a_non_treekem_group_without_calling_x0xd() {
        let (our_pk, req) = our_request(1);
        let adder = RecordingAdder::new();
        let result = handle_sibling_join_request(&req, &our_pk, false, None, &adder).await;
        assert!(result.is_err());
        assert!(adder.calls().is_empty());
    }
}
