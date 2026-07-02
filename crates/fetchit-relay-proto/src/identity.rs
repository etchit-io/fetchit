//! Identifier newtypes used across the wire.

use crate::error::ProtoError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Domain-separation prefix used by ant-quic / x0x when deriving an
/// `AgentId` from an ML-DSA-65 public key. Mirroring it here keeps our
/// agent ids interchangeable with the upstream identity layer.
pub const AGENT_ID_DOMAIN: &[u8] = b"AUTONOMI_PEER_ID_V2:";

/// Byte length of an agent id (ML-DSA-65 public-key hash).
pub const AGENT_ID_LEN: usize = 32;

/// Byte length of a machine fingerprint.
pub const MACHINE_ID_LEN: usize = 32;

/// Byte length of a group id.
pub const GROUP_ID_LEN: usize = 32;

/// Byte length of an idempotency key for a send.
pub const DEDUPE_KEY_LEN: usize = 16;

/// Derive an [`AgentId`] from an ML-DSA-65 public key, matching the
/// upstream `ant_quic::derive_peer_id_from_public_key` convention.
///
/// Specifically:
/// ```text
/// agent_id = SHA-256(AGENT_ID_DOMAIN || public_key_bytes)
/// ```
#[must_use]
pub fn derive_agent_id(public_key: &[u8]) -> [u8; AGENT_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(AGENT_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

/// Domain-separation prefix for deriving a fetchit **user id** (the M6
/// account root) from the account's ML-DSA-65 public key. Distinct from
/// [`AGENT_ID_DOMAIN`] so a user id and an agent id derived from the same
/// key bytes never collide, and so the user-id namespace stays
/// independent of the upstream peer-id convention.
pub const USER_ID_DOMAIN: &[u8] = b"fetchit-user-id-v1:";

/// Byte length of a user id (account-root ML-DSA-65 public-key hash).
pub const USER_ID_LEN: usize = 32;

/// Derive a user id from the account-root ML-DSA-65 public key:
/// ```text
/// user_id = SHA-256(USER_ID_DOMAIN || public_key_bytes)
/// ```
///
/// The 24-word recovery phrase seeds this key, so the user id is the
/// stable account identifier a contact pins under M6; device ids move
/// beneath it. Certificate minting and the v4 pair record both derive
/// through this one function so the two never disagree.
#[must_use]
pub fn derive_user_id(public_key: &[u8]) -> [u8; USER_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(USER_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

/// Stable 32-byte identifier for an agent (one keypair).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub [u8; AGENT_ID_LEN]);

impl AgentId {
    /// Wrap raw bytes as an [`AgentId`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AGENT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AGENT_ID_LEN] {
        &self.0
    }

    /// Lowercase hex string form (64 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 8 hex chars — useful for compact log lines.
    #[must_use]
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({})", self.short())
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for AgentId {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        bytes
            .try_into()
            .map(Self)
            .map_err(|v: Vec<u8>| ProtoError::InvalidIdentifierLength {
                expected: AGENT_ID_LEN,
                got: v.len(),
            })
    }
}

/// Tenant scope binding a connection to an administrative domain.
///
/// `None` connections operate in the public default pool. A bound
/// connection is gated on the issuer's capability claims for the same
/// tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct from any string-like value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 32-byte machine fingerprint for one physical device under an agent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MachineId(pub [u8; MACHINE_ID_LEN]);

impl MachineId {
    /// Wrap raw bytes as a [`MachineId`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MACHINE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MACHINE_ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for MachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MachineId({}...)", hex::encode(&self.0[..4]))
    }
}

/// 32-byte group id referenced by group-chat envelopes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub [u8; GROUP_ID_LEN]);

impl GroupId {
    /// Wrap raw bytes as a [`GroupId`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; GROUP_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; GROUP_ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupId({}...)", hex::encode(&self.0[..4]))
    }
}

/// 16-byte idempotency key for a send frame, used to correlate acks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DedupeKey(pub [u8; DEDUPE_KEY_LEN]);

impl DedupeKey {
    /// Wrap raw bytes as a [`DedupeKey`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DEDUPE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEDUPE_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DedupeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DedupeKey({})", hex::encode(self.0))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_hex_roundtrip() {
        let bytes = [7u8; AGENT_ID_LEN];
        let id = AgentId::from_bytes(bytes);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed: AgentId = hex.parse().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn agent_id_rejects_short_hex() {
        let err = "deadbeef".parse::<AgentId>().unwrap_err();
        assert!(matches!(
            err,
            ProtoError::InvalidIdentifierLength { expected: 32, .. }
        ));
    }

    #[test]
    fn agent_id_rejects_non_hex() {
        let err = "ZZ".repeat(32).parse::<AgentId>().unwrap_err();
        assert!(matches!(err, ProtoError::InvalidHex(_)));
    }

    #[test]
    fn tenant_id_display() {
        let t = TenantId::new("acme-co");
        assert_eq!(t.as_str(), "acme-co");
        assert_eq!(format!("{t}"), "acme-co");
    }

    #[test]
    fn derive_uses_autonomi_peer_id_v2_domain() {
        let pk = b"some-public-key";
        let derived = derive_agent_id(pk);
        let mut h = Sha256::new();
        h.update(b"AUTONOMI_PEER_ID_V2:");
        h.update(pk);
        let expected: [u8; AGENT_ID_LEN] = h.finalize().into();
        assert_eq!(derived, expected);
    }

    #[test]
    fn derive_differs_from_bare_sha256() {
        let pk = b"some-public-key";
        let with_domain = derive_agent_id(pk);
        let without_domain: [u8; 32] = Sha256::digest(pk).into();
        assert_ne!(with_domain, without_domain);
    }

    #[test]
    fn agent_id_short_form_is_8_hex_chars() {
        let id = AgentId::from_bytes([0xab; AGENT_ID_LEN]);
        assert_eq!(id.short().len(), 8);
        assert_eq!(id.short(), "abababab");
    }

    #[test]
    fn derive_user_id_uses_its_own_domain() {
        let pk = b"account-root-public-key";
        let derived = derive_user_id(pk);
        let mut h = Sha256::new();
        h.update(b"fetchit-user-id-v1:");
        h.update(pk);
        let expected: [u8; USER_ID_LEN] = h.finalize().into();
        assert_eq!(derived, expected);
    }

    #[test]
    fn derive_user_id_differs_from_agent_id_for_same_key() {
        // A user id and an agent id derived from identical key bytes must
        // never collide: distinct domains keep the namespaces separate.
        let pk = b"same-key-bytes";
        assert_ne!(derive_user_id(pk), derive_agent_id(pk));
    }
}
