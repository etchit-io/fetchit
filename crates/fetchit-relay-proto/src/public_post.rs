//! Wire shape for M4 fediverse-bridge public posts.
//!
//! An inbound `ActivityPub` activity that passed every `/inbox`
//! pre-flight gate on a `fediverse-inbox`-enabled relay is fanned out
//! to connected chat sessions as an [`EnvelopeKind::PublicPost`]
//! envelope. Unlike every other envelope kind the body is **not**
//! chat-layer ciphertext: it carries a [`PublicPostPayload`]
//! (postcard-encoded) in [`TransitEnvelope::ciphertext`].
//!
//! ## Attribution rides the wrapper, never the body
//!
//! The activity body's self-asserted `actor` field is
//! attacker-controlled — an HTTP Signature proves which *instance*
//! sent the activity, not who the content is *from*. The relay
//! therefore verifies the signing instance at the trust boundary,
//! canonicalises the signing actor URL through the SAME path the
//! denylist uses (`TargetIdentity::try_new(EntryKind::ActorUrl, ..)`),
//! and stamps that vouched value into
//! [`PublicPostPayload::verified_actor_url`]. Clients cannot verify
//! the HTTP Signature themselves, so they trust the relay's vouched
//! attribution: a real client↔relay trust boundary documented in
//! `docs/SECURITY.md`, not a hole.

use crate::envelope::{EnvelopeKind, TransitEnvelope, WIRE_VERSION};
use crate::identity::{AgentId, MachineId, AGENT_ID_LEN, MACHINE_ID_LEN};
use serde::{Deserialize, Serialize};

/// All-zeros sentinel [`AgentId`] stamped as the `sender_agent_id` of
/// every bridge-originated [`EnvelopeKind::PublicPost`] envelope.
///
/// A real agent id is `SHA-256(domain || ml_dsa_pubkey)`, so all-zeros
/// is cryptographically non-collidable with any keypair-derived id —
/// no connected agent can ever authenticate as this id, which means
/// the inbound-WS `sender == auth.agent_id` check already prevents a
/// client from claiming it as a sender. The sentinel exists so the
/// chat-layer drain can recognise a bridged public post structurally.
///
/// # Routing invariant
///
/// This id is a *source* marker only and MUST NEVER be a routing
/// **target**: a `PublicPost` is broadcast-only. The relay-server's
/// session-lookup send path rejects it as a target so a crafted
/// envelope cannot make the relay attempt a directed delivery TO the
/// bridge sentinel.
pub const FEDIVERSE_BRIDGE_SENDER: AgentId = AgentId::from_bytes([0u8; AGENT_ID_LEN]);

/// All-zeros sentinel [`MachineId`] for bridge-originated envelopes —
/// the bridge is not a physical device under an agent. Same
/// non-collidable rationale as [`FEDIVERSE_BRIDGE_SENDER`].
const FEDIVERSE_BRIDGE_MACHINE: MachineId = MachineId::from_bytes([0u8; MACHINE_ID_LEN]);

/// Out-of-band attribution wrapper carried verbatim in
/// [`TransitEnvelope::ciphertext`] for an [`EnvelopeKind::PublicPost`]
/// envelope.
///
/// See the [module docs](self) for why attribution rides this wrapper
/// rather than the activity body's self-asserted `actor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPostPayload {
    /// The HTTP-Signature-verified, denylist-canonical actor URL the
    /// relay vouches the post is from. Attribution rides HERE, never
    /// the activity body's self-asserted `actor`. Canonical form
    /// matches `TargetIdentity::try_new(EntryKind::ActorUrl, ..)` so a
    /// client's `is_blocked(ActorUrl, ..)` compares like-for-like.
    pub verified_actor_url: String,
    /// Raw `application/activity+json` bytes of the `Create { Note }`
    /// activity, handed to the content handler verbatim. The relay
    /// never parses this.
    pub activity_json: Vec<u8>,
}

impl PublicPostPayload {
    /// Decode a wrapper from the `ciphertext` of an
    /// [`EnvelopeKind::PublicPost`] envelope.
    ///
    /// # Errors
    /// Postcard decode error if `bytes` is not a valid wrapper.
    pub fn from_ciphertext(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

impl TransitEnvelope {
    /// Build a bridge-originated [`EnvelopeKind::PublicPost`] envelope
    /// carrying `verified_actor_url` + `activity_json` as a postcard
    /// [`PublicPostPayload`] in `ciphertext`.
    ///
    /// The envelope is unsealed by design: `PublicPost` is the SOLE
    /// exemption from the chat sig/KEM verify regime, so
    /// `sender_signature`, `kem_ciphertext`, and `nonce` are empty and
    /// `sender_agent_id` is the [`FEDIVERSE_BRIDGE_SENDER`] sentinel.
    /// The receiving client MUST gate both the verify regime and the
    /// rendering on `kind` atomically, so a DM can never be smuggled
    /// through the exemption and a `PublicPost` always renders as a
    /// clearly-marked bridged post attributed to `verified_actor_url`.
    ///
    /// `timestamp_ms` is the relay's receipt time for the inbound
    /// activity (the fediverse actor's own publish time is inside the
    /// `activity_json`).
    ///
    /// # Errors
    /// Postcard encode error (in practice infallible for these types).
    pub fn public_post(
        verified_actor_url: impl Into<String>,
        activity_json: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<Self, postcard::Error> {
        let payload = PublicPostPayload {
            verified_actor_url: verified_actor_url.into(),
            activity_json,
        };
        let ciphertext = postcard::to_allocvec(&payload)?;
        Ok(Self {
            version: WIRE_VERSION,
            kind: EnvelopeKind::PublicPost,
            group_id: None,
            tenant_id: None,
            sender_agent_id: FEDIVERSE_BRIDGE_SENDER,
            sender_machine_id: FEDIVERSE_BRIDGE_MACHINE,
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

    const SAMPLE_ACTOR: &str = "https://mastodon.example/users/alice";
    const SAMPLE_BODY: &[u8] = br#"{"type":"Create","object":{"type":"Note","content":"hi"}}"#;
    const SAMPLE_TS: u64 = 1_700_000_000_000;

    #[test]
    fn fediverse_bridge_sender_is_all_zeros() {
        assert_eq!(FEDIVERSE_BRIDGE_SENDER.as_bytes(), &[0u8; AGENT_ID_LEN]);
    }

    #[test]
    fn public_post_ctor_uses_sentinel_and_empty_crypto() {
        let env = TransitEnvelope::public_post(SAMPLE_ACTOR, SAMPLE_BODY.to_vec(), SAMPLE_TS)
            .expect("encode");
        assert_eq!(env.version, WIRE_VERSION);
        assert_eq!(env.kind, EnvelopeKind::PublicPost);
        assert_eq!(env.sender_agent_id, FEDIVERSE_BRIDGE_SENDER);
        assert_eq!(env.sender_machine_id, FEDIVERSE_BRIDGE_MACHINE);
        assert_eq!(env.timestamp_ms, SAMPLE_TS);
        assert_eq!(env.epoch, 0);
        assert!(env.group_id.is_none());
        assert!(env.tenant_id.is_none());
        // The verify exemption is structural: no chat-layer crypto.
        assert!(env.nonce.is_empty());
        assert!(env.kem_ciphertext.is_empty());
        assert!(env.sender_signature.is_empty());
    }

    #[test]
    fn public_post_payload_roundtrips_through_ciphertext() {
        let env = TransitEnvelope::public_post(SAMPLE_ACTOR, SAMPLE_BODY.to_vec(), SAMPLE_TS)
            .expect("encode");
        let decoded = PublicPostPayload::from_ciphertext(&env.ciphertext).expect("decode");
        assert_eq!(decoded.verified_actor_url, SAMPLE_ACTOR);
        assert_eq!(decoded.activity_json, SAMPLE_BODY);
    }

    #[test]
    fn public_post_envelope_postcard_roundtrips() {
        let env = TransitEnvelope::public_post(SAMPLE_ACTOR, SAMPLE_BODY.to_vec(), SAMPLE_TS)
            .expect("encode");
        let bytes = postcard::to_allocvec(&env).expect("encode envelope");
        let back: TransitEnvelope = postcard::from_bytes(&bytes).expect("decode envelope");
        assert_eq!(back, env);
        assert_eq!(back.kind, EnvelopeKind::PublicPost);
    }

    #[test]
    fn public_post_payload_is_standalone_postcard_roundtrip() {
        let payload = PublicPostPayload {
            verified_actor_url: SAMPLE_ACTOR.to_owned(),
            activity_json: SAMPLE_BODY.to_vec(),
        };
        let bytes = postcard::to_allocvec(&payload).expect("encode");
        let back = PublicPostPayload::from_ciphertext(&bytes).expect("decode");
        assert_eq!(back, payload);
    }
}
