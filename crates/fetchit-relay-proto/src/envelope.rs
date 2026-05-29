//! Opaque message envelope shipped between agents.
//!
//! The relay only ever sees the outer fields (sender id, recipient
//! routing in the [`crate::frame::SendFrame`], timestamps, signature).
//! Plaintext bodies live in [`TransitEnvelope::ciphertext`] sealed
//! under ML-KEM-768 to the recipient.

use crate::identity::{AgentId, GroupId, MachineId, TenantId};
use serde::{Deserialize, Serialize};

/// Discriminator for what the ciphertext payload represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeKind {
    /// One-to-one direct message.
    Dm,
    /// Group chat message, addressed via `group_id`.
    GroupChat,
    /// Administrative event for a tenant's audit stream.
    AdminEvent,
    /// End-to-end delivery receipt for a previously-delivered message.
    ///
    /// The ciphertext carries a JSON-encoded
    /// `DeliveryReceiptPayload { message_id, received_at_ms }` sealed under
    /// the conversation's symmetric key. The receipt envelope reuses
    /// `group_id` and `epoch` so the recipient (i.e. the *sender* of the
    /// original message) can look up the right key, and the relay can
    /// route it like any other payload — receipts are not special-cased
    /// in the routing path.
    DeliveryReceipt,
}

/// One ciphertext-carrying message routed by the relay.
///
/// The relay never decrypts these. Only the outer integrity fields
/// (sender id, timestamp, signature) are inspected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitEnvelope {
    /// Envelope-format version. Bumped to 2 when `epoch` was added for
    /// PQ-sealed chat. v1 envelopes did not carry an epoch; the field is
    /// required in v2.
    pub version: u16,
    /// Which conversation surface this envelope belongs to.
    pub kind: EnvelopeKind,
    /// Group identifier, present for [`EnvelopeKind::GroupChat`] and
    /// some [`EnvelopeKind::AdminEvent`] flows.
    pub group_id: Option<GroupId>,
    /// Tenant binding when the envelope is scoped to a tenant.
    pub tenant_id: Option<TenantId>,
    /// Agent id of the sender (claim must match the auth identity).
    pub sender_agent_id: AgentId,
    /// Sending device's machine fingerprint.
    pub sender_machine_id: MachineId,
    /// Sender-asserted timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Conversation epoch under which `ciphertext` was sealed.
    /// Recipients dispatch to the matching symmetric key for this
    /// epoch; the conversation layer owns the key-lookup semantics
    /// (a brief grace window covers in-flight envelopes during epoch
    /// transitions). Welcome envelopes set this to the epoch the
    /// carried key belongs to.
    pub epoch: u32,
    /// ChaCha20-Poly1305 ciphertext sealed under the recipient's key.
    pub ciphertext: Vec<u8>,
    /// 12-byte nonce for the AEAD seal.
    pub nonce: Vec<u8>,
    /// ML-KEM-768 encapsulation of the recipient symmetric key.
    pub kem_ciphertext: Vec<u8>,
    /// ML-DSA-65 signature over the canonicalized envelope bytes.
    pub sender_signature: Vec<u8>,
}

impl TransitEnvelope {
    /// Total byte size on the wire (postcard encoded).
    ///
    /// Useful for size-based throttle decisions.
    ///
    /// # Errors
    /// Returns the postcard error if encoding fails.
    pub fn encoded_len(&self) -> Result<usize, postcard::Error> {
        Ok(postcard::to_allocvec(self)?.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::{AGENT_ID_LEN, MACHINE_ID_LEN};

    fn sample_envelope() -> TransitEnvelope {
        TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1u8; AGENT_ID_LEN]),
            sender_machine_id: MachineId::from_bytes([2u8; MACHINE_ID_LEN]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 0,
            ciphertext: vec![0xaa; 64],
            nonce: vec![0xbb; 12],
            kem_ciphertext: vec![0xcc; 1088],
            sender_signature: vec![0xdd; 3293],
        }
    }

    #[test]
    fn envelope_postcard_roundtrips() {
        let env = sample_envelope();
        let bytes = postcard::to_allocvec(&env).unwrap();
        let decoded: TransitEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(env, decoded);
    }

    #[test]
    fn admin_event_kind_roundtrips() {
        let mut env = sample_envelope();
        env.kind = EnvelopeKind::AdminEvent;
        env.tenant_id = Some(TenantId::new("acme"));
        let bytes = postcard::to_allocvec(&env).unwrap();
        let decoded: TransitEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kind, EnvelopeKind::AdminEvent);
        assert_eq!(decoded.tenant_id, Some(TenantId::new("acme")));
    }

    #[test]
    fn delivery_receipt_kind_roundtrips() {
        let mut env = sample_envelope();
        env.kind = EnvelopeKind::DeliveryReceipt;
        env.kem_ciphertext = Vec::new();
        let bytes = postcard::to_allocvec(&env).unwrap();
        let decoded: TransitEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kind, EnvelopeKind::DeliveryReceipt);
        assert!(decoded.kem_ciphertext.is_empty());
    }
}
