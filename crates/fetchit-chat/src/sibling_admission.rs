//! M6.5a sibling group admission (admin path): the authority guard, the
//! devices-group handshake payload, and the admit orchestration.
//!
//! When a user joins a chat group on one device, their other devices must land
//! in that same group with zero UI (design section V, "sibling admission").
//! The sibling derives a per-group `TreeKEM` `KeyPackage` locally — only it can
//! mint one (its own secret + the group id) — signs `(group, key_package,
//! nonce)` with its device key, and ships the [`SiblingJoinRequest`] to an
//! already in-group device over the private devices-group. That in-group
//! device authorizes the request ([`authorize_sibling_admission`]) — chaining
//! the cert to our account, confirming the sibling is a *current* (non-revoked)
//! device, and verifying the request signature — then admits it with `x0xd`'s
//! invite-free `TreeKEM` direct-add ([`SiblingGroupAdder`]).
//!
//! This module owns the security-critical, transport-free pieces: the request
//! payload and its signature ([`sign_sibling_join_request`]), the authority
//! guard, and [`handle_sibling_join_request`] (the guard + idempotent-nonce +
//! direct-add composition). The `x0xd` HTTP direct-add ships here as the
//! production [`SiblingGroupAdder`]. The devices-group carrier that fans a
//! request out and elects the single admitter is M6.6 (`DevicesGroupSink`).

use crate::error::ChatError;
use crate::fabric::{push_lp, verify_agent_certificate, verify_ml_dsa65, AgentCertificate};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fetchit_relay_client::Signer;
use fetchit_relay_proto::pair_record::DeviceEntryV4;
use serde::{Deserialize, Serialize};

/// Domain-separation tag for the sibling-join request signature. Binds the
/// signature to this protocol so a device signature over `(group, kp,
/// nonce)` here can never be replayed as a signature in another context.
const SIBLING_JOIN_SIG_DOMAIN: &[u8] = b"fetchit-sibling-join-sig-v1";

/// A sibling's request to be admitted into a chat group it is not yet in,
/// carried to an in-group device over the account devices-group.
///
/// `cert` proves the sibling belongs to *this* account, and `sig_b64` — the
/// sibling device's ML-DSA signature over `(group_id, key_package, nonce)` —
/// proves the request came from that device and binds *this* `KeyPackage` to
/// it. Without the signature the cert alone proves nothing (it is published
/// in the account's `PairRecordV4` and served verbatim by the relay), and an
/// attacker could splice its own `KeyPackage` under a legitimate sibling's
/// `agent_id`. `nonce` is monotonic per `(sibling agent_id, group)` so an
/// in-group device drops a duplicate it has already admitted (idempotent
/// re-enroll / retry); two different siblings never share a counter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingJoinRequest {
    /// The chat group the sibling wants into (64-hex group id).
    pub group_id_hex: String,
    /// The sibling's per-group `TreeKEM` `KeyPackage`, `STANDARD` base64 — the
    /// exact bytes `x0xd`'s direct-add takes as `treekem_key_package_b64`.
    pub treekem_key_package_b64: String,
    /// The sibling's account certificate; the in-group device verifies it
    /// chains to our own account *and* is a current (non-revoked) device
    /// before admitting.
    pub cert: AgentCertificate,
    /// Monotonic per `(sibling agent_id, group)` — an in-group device drops a
    /// nonce it has already admitted for this sibling.
    pub nonce: u64,
    /// The sibling device's ML-DSA-65 signature, `STANDARD` base64, over
    /// [`sibling_join_signing_input`] (`group_id`, `key_package`, `nonce`),
    /// verified against `cert.agent_ml_dsa_pubkey_b64`. Authenticates the
    /// request and binds the `KeyPackage` to the signing device.
    pub sig_b64: String,
}

/// Canonical signing input for a [`SiblingJoinRequest`]:
/// `SIBLING_JOIN_SIG_DOMAIN || lp(group_id_hex) || lp(key_package_b64) ||
/// u64_be(nonce)`, where `lp(x) = u32_be(len) || x` (the account-fabric
/// length-prefix convention). Domain-separated so the signature is valid
/// only in this protocol.
///
/// # Errors
/// [`ChatError::Invalid`] if a field exceeds `u32::MAX` bytes.
pub fn sibling_join_signing_input(
    group_id_hex: &str,
    treekem_key_package_b64: &str,
    nonce: u64,
) -> Result<Vec<u8>, ChatError> {
    let mut out = SIBLING_JOIN_SIG_DOMAIN.to_vec();
    push_lp(&mut out, group_id_hex.as_bytes())?;
    push_lp(&mut out, treekem_key_package_b64.as_bytes())?;
    out.extend_from_slice(&nonce.to_be_bytes());
    Ok(out)
}

/// Produce the `sig_b64` for a [`SiblingJoinRequest`]: the requesting sibling
/// signs [`sibling_join_signing_input`] with its device key. The account
/// side calls this when building the request it ships over the devices-group.
///
/// # Errors
/// [`ChatError::Invalid`] on a signing-input build failure or a signer error.
pub async fn sign_sibling_join_request(
    device_signer: &dyn Signer,
    group_id_hex: &str,
    treekem_key_package_b64: &str,
    nonce: u64,
) -> Result<String, ChatError> {
    let input = sibling_join_signing_input(group_id_hex, treekem_key_package_b64, nonce)?;
    let sig = device_signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("sibling-join sign: {e}")))?;
    Ok(B64.encode(sig))
}

/// Decide whether an in-group device may admit the sibling that authored
/// `request`, given our account roster and the target group's secure plane.
///
/// Four gates, all required:
/// 1. **Account authority** — the sibling's certificate MUST chain to *our*
///    account user key (`our_user_pubkey`). A cert that does not chain to us
///    can only be a bug or a tampered devices-group message. This is the
///    fabricated-sibling defense.
/// 2. **Current-roster membership (revocation)** — the cert's `agent_id` MUST
///    still be a device entry in `current_devices` (the account's CURRENT
///    signed `PairRecordV4`), with a matching device key. A certificate is a
///    point-in-time attestation the user key cannot un-sign, so a *revoked*
///    device keeps a valid cert forever; the current roster — not the cert —
///    is the authority on who is a device *now*. Without this a compromised,
///    revoked device could admit itself into any group the account is in.
/// 3. **Request authenticity + `KeyPackage` binding** — `request.sig_b64` MUST
///    be a valid device-key ML-DSA signature over
///    [`sibling_join_signing_input`]. The cert is public (served by the relay),
///    so possession proves nothing; this signature proves the request — and
///    *this* `KeyPackage` — came from the sibling's device key, closing the
///    KeyPackage-splice hole (x0xd Welcomes the KP holder, not the `agent_id`).
/// 4. **`TreeKem` plane only** — a legacy `Gss`-plane group has no Welcome, so
///    a direct-add would leave the sibling a read-blind roster member. Refuse.
///
/// `current_devices` is the caller's already-verified account record (the
/// caller runs `verify_pair_record_v4` before passing `record.devices`), so
/// this function stays pure — no I/O, no network.
///
/// # Errors
/// [`ChatError::Invalid`] if any gate fails: the cert does not chain to our
/// account, the sibling is not a current device (or its key mismatches), the
/// request signature does not verify, or the group is not `TreeKem`-plane.
pub fn authorize_sibling_admission(
    request: &SiblingJoinRequest,
    our_user_pubkey: &[u8],
    current_devices: &[DeviceEntryV4],
    group_is_treekem: bool,
) -> Result<(), ChatError> {
    let cert = &request.cert;
    // 1. Account authority.
    verify_agent_certificate(cert, our_user_pubkey).map_err(|e| {
        ChatError::Invalid(format!("sibling cert does not chain to our account: {e}"))
    })?;
    // 2. Current-roster membership + device-key match (revocation gate).
    let entry = current_devices
        .iter()
        .find(|d| d.agent_id_hex == cert.agent_id_hex)
        .ok_or_else(|| {
            ChatError::Invalid(
                "sibling is not a current device of this account (revoked or unknown)".into(),
            )
        })?;
    if entry.ml_dsa_pubkey_b64 != cert.agent_ml_dsa_pubkey_b64 {
        return Err(ChatError::Invalid(
            "sibling cert device key does not match the current record entry".into(),
        ));
    }
    // 3. Request authenticity + KeyPackage binding.
    let device_pubkey = B64
        .decode(&cert.agent_ml_dsa_pubkey_b64)
        .map_err(|e| ChatError::Invalid(format!("sibling device pubkey b64: {e}")))?;
    let sig = B64
        .decode(&request.sig_b64)
        .map_err(|e| ChatError::Invalid(format!("sibling-join sig b64: {e}")))?;
    let input = sibling_join_signing_input(
        &request.group_id_hex,
        &request.treekem_key_package_b64,
        request.nonce,
    )?;
    verify_ml_dsa65(&device_pubkey, &input, &sig).map_err(|e| {
        ChatError::Invalid(format!(
            "sibling-join request signature does not verify: {e}"
        ))
    })?;
    // 4. TreeKem plane only.
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
    /// Returns whether the add was fresh: `true` on a new member, `false`
    /// when the sibling was already a member (x0xd `409`) — an idempotent
    /// no-op so a second concurrent admitter converges instead of erroring.
    ///
    /// # Errors
    /// [`ChatError`] when the `x0xd` direct-add fails for any reason other
    /// than already-a-member (e.g. the group is gone or the `KeyPackage` is
    /// rejected).
    async fn direct_add(
        &self,
        group_id_hex: &str,
        agent_id_hex: &str,
        treekem_key_package_b64: &str,
    ) -> Result<bool, ChatError>;
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
/// our account roster and the group plane, drop a nonce already admitted, else
/// direct-add the sibling.
///
/// `current_devices` is the account's CURRENT signed device roster (the caller
/// verifies the record and passes `record.devices`); it drives the revocation
/// gate in [`authorize_sibling_admission`]. `admitted_nonce` is the highest
/// nonce already admitted for this `(sibling agent_id, group)` pair — keyed
/// **per sibling**, not per account, so two siblings never share a counter and
/// one cannot strand the other. `request.nonce <= admitted_nonce` is a
/// duplicate. The caller MUST persist the watermark only *after* an `Admitted`
/// outcome, so a failed direct-add never consumes a nonce. `group_is_treekem`
/// comes from the group detail (`x0xd` `GET /groups/<id>`). Authority is
/// checked *before* the nonce so a replayed request with a forged cert can
/// never be dedup-accepted.
///
/// **Single-admitter:** the M6.6 devices-group fanout delivers a request to
/// every in-group device, but only the elected admitter (the primary device)
/// should call this — x0xd serialises per-daemon only, so two daemons
/// concurrently direct-adding the same sibling mint divergent `epoch+1`
/// commits (epoch desync). Until that election lands, an already-member `409`
/// is folded to [`AdmitOutcome::AlreadyAdmitted`] here rather than erroring, so
/// a redundant second admit converges cleanly.
///
/// # Errors
/// [`ChatError`] if the request fails [`authorize_sibling_admission`] or the
/// direct-add fails for a reason other than already-a-member. On any refusal
/// the `adder` is never called.
pub async fn handle_sibling_join_request(
    request: &SiblingJoinRequest,
    our_user_pubkey: &[u8],
    current_devices: &[DeviceEntryV4],
    group_is_treekem: bool,
    admitted_nonce: Option<u64>,
    adder: &dyn SiblingGroupAdder,
) -> Result<AdmitOutcome, ChatError> {
    authorize_sibling_admission(request, our_user_pubkey, current_devices, group_is_treekem)?;
    if admitted_nonce.is_some_and(|seen| request.nonce <= seen) {
        return Ok(AdmitOutcome::AlreadyAdmitted);
    }
    let freshly_added = adder
        .direct_add(
            &request.group_id_hex,
            &request.cert.agent_id_hex,
            &request.treekem_key_package_b64,
        )
        .await?;
    Ok(if freshly_added {
        AdmitOutcome::Admitted
    } else {
        AdmitOutcome::AlreadyAdmitted
    })
}

/// Production [`SiblingGroupAdder`]: the x0xd secure-groups endpoint performs
/// the direct-add over HTTP (`add_treekem_member`). The M6.6 devices-group
/// dispatch constructs one from the account's x0xd handle and hands it to
/// [`handle_sibling_join_request`]. `X0xdError` folds into [`ChatError`] via
/// the crate's existing `From` impl.
#[async_trait]
impl SiblingGroupAdder for x0xd_client::SecureGroupsEndpoint {
    async fn direct_add(
        &self,
        group_id_hex: &str,
        agent_id_hex: &str,
        treekem_key_package_b64: &str,
    ) -> Result<bool, ChatError> {
        Ok(self
            .add_treekem_member(group_id_hex, agent_id_hex, treekem_key_package_b64)
            .await?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fabric::{mint_agent_certificate, UserKeypair};
    use crate::pair_record_v4::device_entry_from_cert;
    use fetchit_relay_client::MlDsaSigner;

    fn group() -> String {
        "2c".repeat(32)
    }

    /// Our account's user pubkey, a device signer, and a valid cert for that
    /// sibling device.
    fn our_account_and_sibling() -> (Vec<u8>, MlDsaSigner, AgentCertificate) {
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
        (user.public_key_bytes().to_vec(), device, cert)
    }

    /// The account's CURRENT signed roster, holding exactly `cert`'s device.
    fn roster_with(cert: &AgentCertificate) -> Vec<DeviceEntryV4> {
        vec![device_entry_from_cert(cert, vec![]).unwrap()]
    }

    /// A valid, device-signed join request from one of our siblings at `nonce`,
    /// with the current roster that includes it.
    async fn our_request(nonce: u64) -> (Vec<u8>, Vec<DeviceEntryV4>, SiblingJoinRequest) {
        let (our_pk, device, cert) = our_account_and_sibling();
        let roster = roster_with(&cert);
        let group_id_hex = group();
        let kp = "a2V5cGFja2FnZQ==".to_string();
        let sig_b64 = sign_sibling_join_request(&device, &group_id_hex, &kp, nonce)
            .await
            .unwrap();
        let req = SiblingJoinRequest {
            group_id_hex,
            treekem_key_package_b64: kp,
            cert,
            nonce,
            sig_b64,
        };
        (our_pk, roster, req)
    }

    /// A fake `SiblingGroupAdder` recording the direct-adds it was asked to
    /// perform, so a test can assert both the outcome and that (for a refusal)
    /// no `x0xd` call happened. `already_member` makes `direct_add` report the
    /// x0xd `409` no-op (`false`).
    struct RecordingAdder {
        calls: std::sync::Mutex<Vec<(String, String, String)>>,
        already_member: bool,
    }
    impl RecordingAdder {
        fn new() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                already_member: false,
            }
        }
        fn already_member() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                already_member: true,
            }
        }
        fn calls(&self) -> Vec<(String, String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl SiblingGroupAdder for RecordingAdder {
        async fn direct_add(&self, group: &str, agent: &str, kp: &str) -> Result<bool, ChatError> {
            self.calls
                .lock()
                .unwrap()
                .push((group.to_string(), agent.to_string(), kp.to_string()));
            Ok(!self.already_member)
        }
    }

    #[tokio::test]
    async fn authorizes_our_signed_current_sibling_into_a_treekem_group() {
        let (our_pk, roster, req) = our_request(1).await;
        authorize_sibling_admission(&req, &our_pk, &roster, true).unwrap();
    }

    #[tokio::test]
    async fn refuses_a_cert_that_does_not_chain_to_our_account() {
        // A validly-signed cert for a DIFFERENT account must not authorize an
        // admit into ours — the fabricated-sibling defense.
        let (_our_pk, roster, req) = our_request(1).await;
        let other = UserKeypair::from_seed(&[123u8; 32]);
        assert!(
            authorize_sibling_admission(&req, other.public_key_bytes(), &roster, true).is_err()
        );
    }

    #[tokio::test]
    async fn refuses_a_revoked_or_unknown_sibling() {
        // The cert is a valid point-in-time attestation, but the device is not
        // in the CURRENT roster (revoked, or never enrolled): refuse. This is
        // the compromised-then-revoked-device attack.
        let (our_pk, _roster, req) = our_request(1).await;
        assert!(
            authorize_sibling_admission(&req, &our_pk, &[], true).is_err(),
            "a device absent from the current record must not be admitted"
        );
    }

    #[tokio::test]
    async fn refuses_a_key_swapped_cert() {
        // The roster records a different device key for this agent_id than the
        // cert presents (key swap): refuse even though the agent_id matches.
        let (our_pk, mut roster, req) = our_request(1).await;
        roster[0].ml_dsa_pubkey_b64 = B64.encode([0u8; 32]);
        assert!(authorize_sibling_admission(&req, &our_pk, &roster, true).is_err());
    }

    #[tokio::test]
    async fn refuses_a_kp_spliced_request() {
        // The request was signed over its original KeyPackage; swapping in a
        // different KeyPackage after signing breaks the signature — the
        // KeyPackage-splice defense (x0xd Welcomes the KP holder, not the id).
        let (our_pk, roster, mut req) = our_request(1).await;
        req.treekem_key_package_b64 = "c3BsaWNlZA==".to_string();
        assert!(authorize_sibling_admission(&req, &our_pk, &roster, true).is_err());
    }

    #[tokio::test]
    async fn refuses_a_tampered_nonce() {
        // The signature covers the nonce, so bumping it after signing (to beat
        // a dedup watermark) invalidates the request.
        let (our_pk, roster, mut req) = our_request(1).await;
        req.nonce = 999;
        assert!(authorize_sibling_admission(&req, &our_pk, &roster, true).is_err());
    }

    #[tokio::test]
    async fn refuses_a_non_treekem_group() {
        // Everything valid, but a Gss-plane group would leave a read-blind member.
        let (our_pk, roster, req) = our_request(1).await;
        assert!(authorize_sibling_admission(&req, &our_pk, &roster, false).is_err());
    }

    #[tokio::test]
    async fn request_round_trips_through_json() {
        let (_our_pk, _roster, req) = our_request(7).await;
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: SiblingJoinRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[tokio::test]
    async fn admits_an_authorized_sibling() {
        let (our_pk, roster, req) = our_request(1).await;
        let adder = RecordingAdder::new();
        let outcome = handle_sibling_join_request(&req, &our_pk, &roster, true, None, &adder)
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
        let (_our_pk, roster, req) = our_request(1).await;
        let other = UserKeypair::from_seed(&[200u8; 32]);
        let adder = RecordingAdder::new();
        let result = handle_sibling_join_request(
            &req,
            other.public_key_bytes(),
            &roster,
            true,
            None,
            &adder,
        )
        .await;
        assert!(result.is_err());
        assert!(
            adder.calls().is_empty(),
            "a non-sibling never reaches the direct-add"
        );
    }

    #[tokio::test]
    async fn refuses_a_revoked_sibling_without_calling_x0xd() {
        let (our_pk, _roster, req) = our_request(1).await;
        let adder = RecordingAdder::new();
        let result = handle_sibling_join_request(&req, &our_pk, &[], true, None, &adder).await;
        assert!(result.is_err());
        assert!(
            adder.calls().is_empty(),
            "a revoked sibling never reaches the direct-add"
        );
    }

    #[tokio::test]
    async fn is_idempotent_on_a_replayed_nonce() {
        let (our_pk, roster, req) = our_request(5).await;
        let adder = RecordingAdder::new();
        let outcome = handle_sibling_join_request(&req, &our_pk, &roster, true, Some(5), &adder)
            .await
            .unwrap();
        assert_eq!(outcome, AdmitOutcome::AlreadyAdmitted);
        assert!(
            adder.calls().is_empty(),
            "a replayed nonce is not re-added to the group"
        );
    }

    #[tokio::test]
    async fn already_member_409_is_reported_as_already_admitted() {
        // A concurrent second admitter direct-adds a sibling x0xd already
        // holds: the 409 converges to AlreadyAdmitted, not an error.
        let (our_pk, roster, req) = our_request(1).await;
        let adder = RecordingAdder::already_member();
        let outcome = handle_sibling_join_request(&req, &our_pk, &roster, true, None, &adder)
            .await
            .unwrap();
        assert_eq!(outcome, AdmitOutcome::AlreadyAdmitted);
        assert_eq!(
            adder.calls().len(),
            1,
            "the add was attempted; x0xd reported already-member"
        );
    }

    #[tokio::test]
    async fn refuses_a_non_treekem_group_without_calling_x0xd() {
        let (our_pk, roster, req) = our_request(1).await;
        let adder = RecordingAdder::new();
        let result = handle_sibling_join_request(&req, &our_pk, &roster, false, None, &adder).await;
        assert!(result.is_err());
        assert!(adder.calls().is_empty());
    }
}
