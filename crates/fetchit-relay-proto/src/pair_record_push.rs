//! Wire shape for M6.7 proactive pair-record revoke-push.
//!
//! When a sender's device set changes (a device is revoked or added) it
//! proactively pushes its freshly re-signed
//! [`PairRecordV4`](crate::pair_record::PairRecordV4) to every active
//! contact, so contacts converge on the new roster without waiting to
//! re-resolve. The push travels as an [`EnvelopeKind::PairRecordPush`]
//! envelope whose [`TransitEnvelope::ciphertext`] carries a postcard
//! [`PairRecordPushPayload`].
//!
//! ## The record is already signed — the push travels UNSEALED
//!
//! `record_bytes` are the length-prefixed `PairRecordV4` wire bytes with
//! the record's own ML-DSA-65 user signature already attached. Like a
//! bridged [`PublicPost`](crate::PublicPostPayload), a `PairRecordPush`
//! is **unsealed**: the record is public — self-signed by the user's
//! account key and served openly by the relay — so a per-recipient seal
//! would add zero confidentiality. The wrapper is pure transport framing
//! and the crypto fields (`nonce` / `kem_ciphertext` / `sender_signature`)
//! stay empty on the wire. The only authority a contact trusts is the
//! record's own signature, re-verified on receipt via
//! [`verify_pair_record_v4`](crate::pair_record::verify_pair_record_v4)
//! (plus the M6.7 anti-rollback revision check). The envelope layer never
//! re-derives, re-signs, or seals the record; that verification lives in
//! the layer above and is out of scope for this crate.

use crate::envelope::{EnvelopeKind, TransitEnvelope, WIRE_VERSION};
use crate::identity::{AgentId, MachineId};
use serde::{Deserialize, Serialize};

/// Transport wrapper carried verbatim in [`TransitEnvelope::ciphertext`]
/// for an [`EnvelopeKind::PairRecordPush`] envelope.
///
/// See the [module docs](self) for why the record signature — not this
/// wrapper — is the authority a receiving contact verifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRecordPushPayload {
    /// The already-signed, length-prefixed
    /// [`PairRecordV4`](crate::pair_record::PairRecordV4) wire bytes. The
    /// envelope layer treats these as opaque; the receiver re-verifies
    /// the record's own user signature after decoding.
    pub record_bytes: Vec<u8>,
}

impl PairRecordPushPayload {
    /// Decode a wrapper from the (unsealed) `ciphertext` bytes of an
    /// [`EnvelopeKind::PairRecordPush`] envelope.
    ///
    /// # Errors
    /// Postcard decode error if `bytes` is not a valid wrapper.
    pub fn from_ciphertext(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

impl TransitEnvelope {
    /// Build an [`EnvelopeKind::PairRecordPush`] envelope carrying
    /// `record_bytes` as a postcard [`PairRecordPushPayload`] in
    /// `ciphertext`, attributed to the pushing agent.
    ///
    /// This produces the FINAL wire form -- there is no separate seal step.
    /// It fills the cleartext routing fields (`sender_agent_id`,
    /// `sender_machine_id`, `timestamp_ms`), stamps `kind` and
    /// [`WIRE_VERSION`], and postcard-encodes the payload into `ciphertext`
    /// via the same path [`PublicPostPayload`](crate::PublicPostPayload)
    /// uses. Exactly like a bridged public post, a `PairRecordPush` is
    /// **unsealed**: the record carries its own user signature and is
    /// public, so `nonce` / `kem_ciphertext` / `sender_signature` are left
    /// empty by design, not pending a later seal.
    ///
    /// # Errors
    /// Postcard encode error (in practice infallible for these types).
    pub fn pair_record_push(
        sender_agent_id: AgentId,
        sender_machine_id: MachineId,
        record_bytes: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<Self, postcard::Error> {
        let payload = PairRecordPushPayload { record_bytes };
        let ciphertext = postcard::to_allocvec(&payload)?;
        Ok(Self {
            version: WIRE_VERSION,
            kind: EnvelopeKind::PairRecordPush,
            group_id: None,
            tenant_id: None,
            sender_agent_id,
            sender_machine_id,
            timestamp_ms,
            epoch: 0,
            ciphertext,
            nonce: Vec::new(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::{AGENT_ID_LEN, MACHINE_ID_LEN};

    const SAMPLE_RECORD: &[u8] = b"signed-pair-record-v4-wire-bytes";
    const SAMPLE_TS: u64 = 1_700_000_000_000;

    fn sample_sender() -> AgentId {
        AgentId::from_bytes([7u8; AGENT_ID_LEN])
    }

    fn sample_machine() -> MachineId {
        MachineId::from_bytes([9u8; MACHINE_ID_LEN])
    }

    #[test]
    fn pair_record_push_ctor_sets_kind_and_routing_fields() {
        let env = TransitEnvelope::pair_record_push(
            sample_sender(),
            sample_machine(),
            SAMPLE_RECORD.to_vec(),
            SAMPLE_TS,
        )
        .expect("encode");
        assert_eq!(env.version, WIRE_VERSION);
        assert_eq!(env.kind, EnvelopeKind::PairRecordPush);
        assert_eq!(env.sender_agent_id, sample_sender());
        assert_eq!(env.sender_machine_id, sample_machine());
        assert_eq!(env.timestamp_ms, SAMPLE_TS);
        assert_eq!(env.epoch, 0);
        assert!(env.group_id.is_none());
        assert!(env.tenant_id.is_none());
        // Unsealed by design (like PublicPost): the record is self-signed
        // and public, so the crypto fields stay empty on the wire -- there
        // is no later seal step to populate them.
        assert!(env.nonce.is_empty());
        assert!(env.kem_ciphertext.is_empty());
        assert!(env.sender_signature.is_empty());
    }

    #[test]
    fn pair_record_push_payload_roundtrips_through_ciphertext() {
        let env = TransitEnvelope::pair_record_push(
            sample_sender(),
            sample_machine(),
            SAMPLE_RECORD.to_vec(),
            SAMPLE_TS,
        )
        .expect("encode");
        let decoded = PairRecordPushPayload::from_ciphertext(&env.ciphertext).expect("decode");
        assert_eq!(decoded.record_bytes, SAMPLE_RECORD);
    }

    #[test]
    fn pair_record_push_envelope_postcard_roundtrips() {
        let env = TransitEnvelope::pair_record_push(
            sample_sender(),
            sample_machine(),
            SAMPLE_RECORD.to_vec(),
            SAMPLE_TS,
        )
        .expect("encode");
        let bytes = postcard::to_allocvec(&env).expect("encode envelope");
        let back: TransitEnvelope = postcard::from_bytes(&bytes).expect("decode envelope");
        assert_eq!(back, env);
        assert_eq!(back.kind, EnvelopeKind::PairRecordPush);
    }

    #[test]
    fn pair_record_push_payload_is_standalone_postcard_roundtrip() {
        let payload = PairRecordPushPayload {
            record_bytes: SAMPLE_RECORD.to_vec(),
        };
        let bytes = postcard::to_allocvec(&payload).expect("encode");
        let back = PairRecordPushPayload::from_ciphertext(&bytes).expect("decode");
        assert_eq!(back, payload);
    }
}
