//! Account fabric: the user-root key that binds a person's devices.
//!
//! M6 linked devices. Each device keeps its own ML-DSA-65 agent key and
//! its own MLS leaf; what makes them one account is a **user key** the
//! account owner holds. The user key is derived deterministically from
//! the same 32-byte root seed the 24-word recovery phrase already
//! restores (`recovery_phrase` + `local_signer`), under a domain
//! separate from the device identity key, so:
//!
//! - the phrase alone recovers the account root — no extra backup — and
//! - the user key is cryptographically independent of any device's agent
//!   key: compromising one device's key never yields the account key.
//!
//! The forever-pinned account anchor `user_id` (which contacts TOFU-pin)
//! is derived from the user *public* key via
//! [`fetchit_relay_proto::derive_user_id`] under its own
//! `fetchit-user-id-v1` domain — deliberately NOT the
//! `AUTONOMI_PEER_ID_V2` agent/peer-id domain, so an upstream peer-id
//! bump can never move a pinned account. `UserKeypair`, `AgentCertificate`
//! (a user-key signature binding a device agent to the `user_id`), and
//! its frozen `fetchit-agent-cert-v1` signing layout land in this module
//! alongside the seed derivation below.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-SHA-256 `info` separating the account user key from the device
/// identity key.
///
/// **Frozen.** The derived user key — and therefore the pinned
/// `user_id` contacts anchor on — depends on this exact byte string;
/// changing it is a migration, not a patch.
pub const USER_KEY_HKDF_INFO: &[u8] = b"fetchit-user-key-v1";

/// Derive the 32-byte account **user seed** from a device **root seed**
/// (the identity seed the recovery phrase restores).
///
/// Deterministic and domain-separated: the same root seed always yields
/// the same user seed, so the phrase recovers the account key; and the
/// HKDF `info` ([`USER_KEY_HKDF_INFO`]) makes the user seed independent
/// of the root seed and of any other key derived from it.
///
/// The returned seed is [`Zeroizing`]; feed it straight into the user
/// keypair constructor and let it drop.
#[must_use]
#[allow(clippy::expect_used)]
pub fn derive_user_seed(root_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, root_seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(USER_KEY_HKDF_INFO, out.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn user_seed_derives_deterministically_from_root() {
        let root = [7u8; 32];
        assert_eq!(*derive_user_seed(&root), *derive_user_seed(&root));
    }

    #[test]
    fn user_seed_is_domain_separated_from_root() {
        // The account key must never equal the device identity key it is
        // derived from — that separation is the whole point of the HKDF.
        let root = [7u8; 32];
        assert_ne!(*derive_user_seed(&root), root);
    }

    #[test]
    fn distinct_roots_yield_distinct_user_seeds() {
        assert_ne!(*derive_user_seed(&[1u8; 32]), *derive_user_seed(&[2u8; 32]));
    }
}
