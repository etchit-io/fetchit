//! M6.5a sibling group admission (admin path): the authority guard and the
//! devices-group handshake payload.
//!
//! When a user joins a chat group on one device, their other devices must land
//! in that same group with zero UI (design section V, "sibling admission").
//! The sibling derives a per-group `TreeKEM` `KeyPackage` locally — only it can
//! mint one (its own secret + the group id) — and ships it to an already
//! in-group device over the private devices-group as a [`SiblingJoinRequest`].
//! That in-group device admits it with `x0xd`'s invite-free `TreeKEM`
//! direct-add.
//!
//! This module owns the two security-critical, transport-free pieces: the
//! request payload, and [`authorize_sibling_admission`] — the guard that
//! decides whether an in-group device may spend a real group admit on a given
//! request. The `x0xd` direct-add call and the devices-group carrier (M6.6) are
//! wired on top of these.

use crate::error::ChatError;
use crate::fabric::{verify_agent_certificate, AgentCertificate};
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
}
