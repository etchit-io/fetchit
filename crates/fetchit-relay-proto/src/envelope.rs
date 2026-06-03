//! Opaque message envelope shipped between agents.
//!
//! The relay only ever sees the outer fields (sender id, recipient
//! routing in the [`crate::frame::SendFrame`], timestamps, signature).
//! Plaintext bodies live in [`TransitEnvelope::ciphertext`] sealed
//! under ML-KEM-768 to the recipient.

use crate::identity::{AgentId, GroupId, MachineId, TenantId};
use serde::{Deserialize, Serialize};

/// Wire-protocol version. Bumped to 3 at M2 (2026-06-02) when the
/// v1 unsealed-fabricated escape hatch was removed and every send
/// is required to be sealed. Relay servers accept both 2 and 3
/// inbound during a transition window; v3 is the only version
/// emitted on send paths post-M2.
pub const WIRE_VERSION: u16 = 3;

/// Sunset date for the v2-accept transition window in
/// [`crate::envelope::TransitEnvelope::version`] / the relay-server's
/// inbound gate. Once `SystemTime::now()` is past this point CI fails
/// loudly via the trip-wire test in this module, forcing a revisit:
/// either confirm the active-peer set has fully migrated and narrow
/// the relay's `matches!(envelope.version, 2 | 3)` gate to v3-only,
/// or push the date forward with rationale.
///
/// NOT a runtime gate — the relay staying up must not depend on the
/// wall clock — but a CI signal so the v2-accept window can't drift
/// indefinitely while every other PR turns green.
pub const WIRE_VERSION_V2_SUNSET: &str = "2026-12-01";

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
    /// M2 PQ-`TreeKEM` private-group send. Distinct from
    /// [`EnvelopeKind::GroupChat`] because the legacy chat-v2 path uses
    /// `GroupChat` with empty `kem_ciphertext` for subsequent-message
    /// envelopes (the ML-KEM-768 payload only travels on Welcome) —
    /// wire-identical to a private-group send if we discriminated on
    /// `kind == GroupChat && kem_ciphertext.is_empty()`. The dedicated
    /// variant makes the discriminator unambiguous so the inbound
    /// router never misroutes a legacy chat-v2 Message into x0xd's
    /// `EncryptedFrame` decode path.
    ///
    /// Appended at the end of the enum to keep existing variant indices
    /// (and therefore the postcard byte representation of every prior
    /// variant) stable.
    PrivateGroupChat,
    /// M2.5 bridge — x0xd group-metadata event (`MemberJoined`,
    /// `MemberAdded`, `Welcome`, `Commit`, …) wrapped as a DM payload so
    /// the receiving daemon can `POST /publish` the inner JSON event
    /// on the group's `metadata_topic`, advancing local MLS state via
    /// Saorsa pubsub's local-loopback. Used when the gossip mesh
    /// between sender and recipient is unreachable (symmetric NAT,
    /// CGNAT, etc.).
    ///
    /// `TransitEnvelope.ciphertext` carries a postcard-encoded
    /// `X0xdGroupMetadataEventWrapper { topic, payload_b64 }` sealed
    /// under the recipient's ML-KEM-768 key per the existing PQ DM
    /// path. Recipient unwraps and POSTs to local x0xd `/publish`;
    /// the inner JSON event carries its own ML-DSA-65 signature
    /// (binding the original group authority) which x0xd verifies via
    /// `apply_named_group_metadata_event` — the bridge is pure
    /// transport, the inner-event signature is the only authority.
    ///
    /// Appended at the end of the enum to keep existing variant indices
    /// stable for postcard wire-compat.
    ///
    /// See `private/m2.5-bridge-collapsed-spec.md` on the `m2.5-design`
    /// branch for the full spec.
    X0xdGroupMetadataEvent,
}

/// One ciphertext-carrying message routed by the relay.
///
/// The relay never decrypts these. Only the outer integrity fields
/// (sender id, timestamp, signature) are inspected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitEnvelope {
    /// Envelope-format version. v2 added `epoch` for PQ-sealed chat;
    /// v3 (M2, 2026-06-02) marks the wire shape after the unsealed
    /// fabricated send path was removed. New sends always emit
    /// [`WIRE_VERSION`]; relays accept v2 + v3 during the transition.
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
            version: WIRE_VERSION,
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
    fn v2_accept_window_sunset_has_not_passed() {
        // P1 trip-wire from Bob's review: the relay-server accepts
        // both v2 and v3 envelopes "during a transition window" but
        // nothing in code forces the window to actually sunset. When
        // a future maintainer reads the gate they have no signal
        // that the transition is over. This test fails CI once
        // `WIRE_VERSION_V2_SUNSET` is past — by then the relay-side
        // burn-down metric (`envelope_accepted_legacy_v2`) should
        // show v2 traffic has drained and the gate can be narrowed
        // to v3-only. NOT a runtime check; the relay must not depend
        // on wall-clock for liveness.
        //
        // Sunset string is parsed in-place rather than via chrono so
        // fetchit-relay-proto's deps stay minimal.
        let (year, month, day) = parse_iso_date(WIRE_VERSION_V2_SUNSET);
        let sunset_unix = days_from_civil(year, month, day) * 86_400;
        let sunset = std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(u64::try_from(sunset_unix).unwrap());
        let now = std::time::SystemTime::now();
        assert!(
            now < sunset,
            "WIRE_VERSION_V2_SUNSET ({WIRE_VERSION_V2_SUNSET}) has passed — \
             confirm the relay-side v2-accept burn-down metric has drained, \
             then narrow the ws.rs version gate to v3-only and bump this date",
        );
    }

    /// Parse `YYYY-MM-DD` into `(year, month, day)`. Test-only helper
    /// for the v2-sunset trip-wire.
    fn parse_iso_date(s: &str) -> (i32, u32, u32) {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 10, "expected YYYY-MM-DD");
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        let year: i32 = s[0..4].parse().unwrap();
        let month: u32 = s[5..7].parse().unwrap();
        let day: u32 = s[8..10].parse().unwrap();
        (year, month, day)
    }

    /// Howard Hinnant's days-from-civil algorithm: returns days since
    /// 1970-01-01 for a Gregorian (year, month, day) triple. Avoids
    /// pulling in chrono just for one CI trip-wire.
    #[allow(clippy::cast_sign_loss)] // (y - era*400) is in [0, 399] by construction
    fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u32;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        i64::from(era) * 146_097 + i64::from(doe) - 719_468
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

    #[test]
    fn private_group_chat_kind_roundtrips() {
        // The discriminator added for M2: wire-shape carry confirmed so
        // the inbound router can rely on `kind == PrivateGroupChat` to
        // route x0xd-sealed frames without confusing them with legacy
        // chat-v2 `GroupChat` Message envelopes that happen to ship an
        // empty `kem_ciphertext`.
        let mut env = sample_envelope();
        env.kind = EnvelopeKind::PrivateGroupChat;
        env.kem_ciphertext = Vec::new();
        let bytes = postcard::to_allocvec(&env).unwrap();
        let decoded: TransitEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kind, EnvelopeKind::PrivateGroupChat);
        assert!(decoded.kem_ciphertext.is_empty());
    }

    #[test]
    fn x0xd_group_metadata_event_kind_roundtrips() {
        // C1 from private/m2.5-bridge-collapsed-spec.md — the bridge
        // discriminator so the inbound chat-peer dispatcher can route
        // an x0xd-group-metadata-event-wrapped DM (carrying a
        // postcard-encoded { topic, payload_b64 } in the sealed
        // ciphertext) to the local /publish POST path instead of the
        // chat / group-chat / receipt paths.
        let mut env = sample_envelope();
        env.kind = EnvelopeKind::X0xdGroupMetadataEvent;
        // Plausible wrapper-sized ciphertext: a small metadata_topic
        // string plus a base64-encoded MemberJoined JSON event would
        // typically land in the low single-digit KiB range. This
        // assertion only checks the wire-shape carry, so any sealed
        // payload size works.
        env.ciphertext = vec![0xee; 1024];
        let bytes = postcard::to_allocvec(&env).unwrap();
        let decoded: TransitEnvelope = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.kind, EnvelopeKind::X0xdGroupMetadataEvent);
        assert_eq!(decoded.ciphertext, vec![0xee; 1024]);
    }
}
