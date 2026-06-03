//! M2.5 group-metadata bridge — sender-side helpers (pure functions).
//!
//! When the Saorsa gossip mesh between two daemons can't deliver an
//! x0xd `NamedGroupMetadataEvent` (residential symmetric NAT, CGNAT,
//! etc.), the chat-peer wraps the signed event as a DM-shaped envelope
//! and rides it across the existing fetchit-relay path. The receiver's
//! chat-peer hands the inner JSON payload to local x0xd `POST /publish`;
//! pubsub-loopback advances local MLS state via the same apply path
//! that gossip-delivered events would take.
//!
//! This module is pure helpers — no transport, no I/O beyond reading a
//! locally-stored share-card. C3 wires the seal + outbox dispatch and
//! the receive-side `/publish` round-trip; C4 wires the consent +
//! reachability decision in front of it.
//!
//! Full spec: `private/m2.5-bridge-collapsed-spec.md` on the
//! `m2.5-design` branch.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{ChatError, Result};
use crate::local_store::StoreLayout;
use crate::messages::StoredContactCard;

/// Domain tag for the `MemberJoined` canonical-bytes formula. Must
/// match upstream x0xd `MEMBER_JOINED_DOMAIN` (rev `6d96ca5`, source
/// `src/bin/x0xd.rs:6658`). If upstream bumps this to `v3` or
/// otherwise changes the formula, the parity fixture in this module
/// fails — the drift signal.
pub const MEMBER_JOINED_DOMAIN: &[u8] = b"x0x.named_group.member_joined.v2";

/// Numeric byte encoding of x0x's `GroupRole`, mirroring upstream
/// `GroupRole::as_u8` at `src/groups/member.rs:35` (rev `6d96ca5`).
/// Values are stable across releases per upstream's doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeRole {
    /// Group owner.
    Owner,
    /// Admin (privilege below owner).
    Admin,
    /// Moderator.
    Moderator,
    /// Plain member.
    Member,
    /// Guest (lowest privilege).
    Guest,
}

impl BridgeRole {
    /// Stable on-wire byte encoding used in canonical signing bytes.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::Moderator => 2,
            Self::Member => 3,
            Self::Guest => 4,
        }
    }

    /// Serde wire string for the JSON event body. Matches upstream's
    /// `#[serde(rename_all = "snake_case")]` on `GroupRole`.
    #[must_use]
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Moderator => "moderator",
            Self::Member => "member",
            Self::Guest => "guest",
        }
    }
}

/// Payload that rides inside `TransitEnvelope.ciphertext` for an
/// `EnvelopeKind::X0xdGroupMetadataEvent` send.
///
/// `topic` is x0xd's `metadata_topic` for the target group (from
/// `GET /groups/<gid>` → `details.metadata_topic`). `payload_b64` is
/// base64(JSON-encoded signed event) — exactly the bytes the receiver
/// hands to its local `POST /publish`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct X0xdGroupMetadataEventWrapper {
    /// x0xd metadata topic the inner event addresses.
    pub topic: String,
    /// Base64-encoded JSON event bytes (signed by the originating
    /// agent's ML-DSA-65 key).
    pub payload_b64: String,
}

impl X0xdGroupMetadataEventWrapper {
    /// Postcard-encode the wrapper. Output is the plaintext that goes
    /// into the existing PQ DM seal as the inner payload.
    ///
    /// # Errors
    /// Returns `ChatError::Invalid` if postcard serialization fails
    /// (no realistic path on a fixed schema).
    pub fn to_postcard(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| ChatError::Invalid(format!("bridge wrapper encode: {e}")))
    }

    /// Postcard-decode a wrapper from sealed-payload bytes.
    ///
    /// # Errors
    /// Returns `ChatError::Invalid` on malformed input.
    pub fn from_postcard(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes)
            .map_err(|e| ChatError::Invalid(format!("bridge wrapper decode: {e}")))
    }
}

/// Inputs for a signed `MemberJoined` event. Field order matches
/// upstream `canonical_member_joined_bytes` exactly.
#[derive(Debug)]
pub struct MemberJoinedInputs<'a> {
    /// Group identifier (x0xd's local `group_id`).
    pub group_id: &'a str,
    /// Stable cross-replay group id (`None` when not yet stable).
    pub stable_group_id: Option<&'a str>,
    /// Hex agent id of the joining member.
    pub member_agent_id: &'a str,
    /// Member's ML-DSA-65 agent public key (base64).
    pub member_public_key_b64: &'a str,
    /// Member's role at the time of the event.
    pub role: BridgeRole,
    /// Member's optional human-readable display name.
    pub display_name: Option<&'a str>,
    /// Hex agent id of the inviter (group owner / admin).
    pub inviter_agent_id: &'a str,
    /// Single-use invite secret carried in the invite URI.
    pub invite_secret: &'a str,
    /// Unix-epoch milliseconds of the event.
    pub ts_ms: u64,
    /// Optional base64 `TreeKEM` key package for the joiner.
    pub treekem_key_package_b64: Option<&'a str>,
}

/// Build the canonical signing bytes for a `MemberJoined` event,
/// mirroring upstream `canonical_member_joined_bytes` exactly. The
/// returned bytes are passed to the local ML-DSA-65 signer
/// (`POST /agent/sign`); the resulting signature lands in
/// `signature_b64` on the JSON event body.
///
/// Layout (LP = u32 big-endian length || bytes):
///
/// ```text
/// MEMBER_JOINED_DOMAIN
/// LP(group_id) LP(stable_group_id_or_empty)
/// LP(member_agent_id) LP(member_public_key_b64)
/// role_byte
/// LP(display_name_or_empty)
/// LP(inviter_agent_id) LP(invite_secret)
/// u64_be(ts_ms)
/// LP(treekem_key_package_b64_or_empty)
/// ```
///
/// Drift guard: the parity fixture in this module's tests pins the
/// v2 formula. If upstream bumps to v3, that test fails red.
#[must_use]
pub fn canonical_member_joined_bytes(inputs: &MemberJoinedInputs<'_>) -> Vec<u8> {
    fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    let mut buf = Vec::with_capacity(MEMBER_JOINED_DOMAIN.len() + 256);
    buf.extend_from_slice(MEMBER_JOINED_DOMAIN);
    push_lp(&mut buf, inputs.group_id.as_bytes());
    push_lp(&mut buf, inputs.stable_group_id.unwrap_or("").as_bytes());
    push_lp(&mut buf, inputs.member_agent_id.as_bytes());
    push_lp(&mut buf, inputs.member_public_key_b64.as_bytes());
    buf.push(inputs.role.as_u8());
    push_lp(&mut buf, inputs.display_name.unwrap_or("").as_bytes());
    push_lp(&mut buf, inputs.inviter_agent_id.as_bytes());
    push_lp(&mut buf, inputs.invite_secret.as_bytes());
    buf.extend_from_slice(&inputs.ts_ms.to_be_bytes());
    push_lp(
        &mut buf,
        inputs.treekem_key_package_b64.unwrap_or("").as_bytes(),
    );
    buf
}

/// Build the JSON event body that goes into the wrapper's
/// `payload_b64` (after base64 encoding). The signature is computed
/// separately over [`canonical_member_joined_bytes`] and passed in as
/// `signature_b64` — this function only assembles the JSON shape
/// upstream expects.
#[must_use]
pub fn build_member_joined_event(
    inputs: &MemberJoinedInputs<'_>,
    signature_b64: &str,
) -> serde_json::Value {
    serde_json::json!({
        "event": "member_joined",
        "group_id": inputs.group_id,
        "stable_group_id": inputs.stable_group_id,
        "member_agent_id": inputs.member_agent_id,
        "member_public_key_b64": inputs.member_public_key_b64,
        "role": inputs.role.as_wire_str(),
        "display_name": inputs.display_name,
        "inviter_agent_id": inputs.inviter_agent_id,
        "invite_secret": inputs.invite_secret,
        "ts_ms": inputs.ts_ms,
        "treekem_key_package_b64": inputs.treekem_key_package_b64,
        "signature_b64": signature_b64,
    })
}

/// Base64-encode the JSON event bytes for inclusion in
/// `X0xdGroupMetadataEventWrapper.payload_b64`.
///
/// # Errors
/// Returns `ChatError::Invalid` if `serde_json::to_vec` fails.
pub fn encode_payload_b64(event_json: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(event_json)
        .map_err(|e| ChatError::Invalid(format!("event json encode: {e}")))?;
    Ok(B64.encode(bytes))
}

/// Look up the recipient's ML-KEM-768 public key from their stored
/// share-card. This is the P1.A gate: bridge sends require a prior
/// share-card exchange. When the card is missing the caller gets
/// [`ChatError::ShareCardMissing`] so the desktop UI can route to an
/// "Import their contact card first" modal.
///
/// # Errors
/// - [`ChatError::ShareCardMissing`] when no card is on disk for
///   `agent_id_hex`.
/// - [`ChatError::Invalid`] when the stored card's `kem_public_key_b64`
///   fails base64 decode.
/// - Any I/O error surfaced by [`StoredContactCard::load`].
pub fn recipient_kem_key(layout: &StoreLayout, agent_id_hex: &str) -> Result<Vec<u8>> {
    let card = StoredContactCard::load(layout, agent_id_hex)?.ok_or_else(|| {
        let short = agent_id_hex
            .get(..agent_id_hex.len().min(12))
            .unwrap_or(agent_id_hex)
            .to_owned();
        ChatError::ShareCardMissing {
            agent_id_short: short,
        }
    })?;
    B64.decode(&card.kem_public_key_b64)
        .map_err(|e| ChatError::Invalid(format!("share-card KEM pubkey b64 decode: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::messages::StoredContactCard;

    /// Hand-derived parity fixture for `canonical_member_joined_bytes`.
    /// Mirrors the formula at upstream x0xd `src/bin/x0xd.rs:6680+`
    /// (rev `6d96ca5`). Any upstream change to the v2 formula — domain
    /// tag, LP shape, field order — fails this assertion, which is the
    /// signal to mirror the new formula here (or bump to v3).
    #[test]
    fn canonical_member_joined_matches_upstream_v2_formula() {
        let inputs = MemberJoinedInputs {
            group_id: "g1",
            stable_group_id: None,
            member_agent_id: "aabb",
            member_public_key_b64: "Zg==",
            role: BridgeRole::Member,
            display_name: None,
            inviter_agent_id: "cd",
            invite_secret: "x",
            ts_ms: 1,
            treekem_key_package_b64: None,
        };
        let bytes = canonical_member_joined_bytes(&inputs);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"x0x.named_group.member_joined.v2");
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(b"g1");
        expected.extend_from_slice(&0u32.to_be_bytes());
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"aabb");
        expected.extend_from_slice(&4u32.to_be_bytes());
        expected.extend_from_slice(b"Zg==");
        expected.push(3);
        expected.extend_from_slice(&0u32.to_be_bytes());
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(b"cd");
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.push(b'x');
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(&0u32.to_be_bytes());

        assert_eq!(bytes, expected, "canonical-bytes drift vs upstream v2");
    }

    #[test]
    fn domain_tag_is_v2_thirty_two_bytes() {
        assert_eq!(MEMBER_JOINED_DOMAIN, b"x0x.named_group.member_joined.v2");
        assert_eq!(MEMBER_JOINED_DOMAIN.len(), 32);
    }

    #[test]
    fn role_as_u8_matches_upstream_group_role() {
        assert_eq!(BridgeRole::Owner.as_u8(), 0);
        assert_eq!(BridgeRole::Admin.as_u8(), 1);
        assert_eq!(BridgeRole::Moderator.as_u8(), 2);
        assert_eq!(BridgeRole::Member.as_u8(), 3);
        assert_eq!(BridgeRole::Guest.as_u8(), 4);
    }

    #[test]
    fn role_wire_str_matches_upstream_snake_case() {
        assert_eq!(BridgeRole::Owner.as_wire_str(), "owner");
        assert_eq!(BridgeRole::Admin.as_wire_str(), "admin");
        assert_eq!(BridgeRole::Moderator.as_wire_str(), "moderator");
        assert_eq!(BridgeRole::Member.as_wire_str(), "member");
        assert_eq!(BridgeRole::Guest.as_wire_str(), "guest");
    }

    #[test]
    fn wrapper_postcard_roundtrip() {
        let w = X0xdGroupMetadataEventWrapper {
            topic: "x0x.named_group/abc123/metadata".into(),
            payload_b64: "eyJldmVudCI6Im1lbWJlcl9qb2luZWQifQ==".into(),
        };
        let bytes = w.to_postcard().unwrap();
        let back = X0xdGroupMetadataEventWrapper::from_postcard(&bytes).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn wrapper_from_postcard_rejects_garbage() {
        let err = X0xdGroupMetadataEventWrapper::from_postcard(b"not-postcard-data").unwrap_err();
        assert!(
            err.to_string().contains("bridge wrapper decode"),
            "expected typed decode error, got: {err}"
        );
    }

    #[test]
    fn build_member_joined_event_includes_all_fields() {
        let inputs = MemberJoinedInputs {
            group_id: "g",
            stable_group_id: Some("sg"),
            member_agent_id: "aid",
            member_public_key_b64: "kemb64",
            role: BridgeRole::Member,
            display_name: Some("Alice"),
            inviter_agent_id: "inviter",
            invite_secret: "secret",
            ts_ms: 42,
            treekem_key_package_b64: Some("tkp"),
        };
        let json = build_member_joined_event(&inputs, "sigb64");
        let obj = json.as_object().unwrap();
        assert_eq!(obj["event"], "member_joined");
        assert_eq!(obj["group_id"], "g");
        assert_eq!(obj["stable_group_id"], "sg");
        assert_eq!(obj["member_agent_id"], "aid");
        assert_eq!(obj["member_public_key_b64"], "kemb64");
        assert_eq!(obj["role"], "member");
        assert_eq!(obj["display_name"], "Alice");
        assert_eq!(obj["inviter_agent_id"], "inviter");
        assert_eq!(obj["invite_secret"], "secret");
        assert_eq!(obj["ts_ms"], 42);
        assert_eq!(obj["treekem_key_package_b64"], "tkp");
        assert_eq!(obj["signature_b64"], "sigb64");
    }

    #[test]
    fn build_member_joined_event_serializes_none_as_json_null() {
        let inputs = MemberJoinedInputs {
            group_id: "g",
            stable_group_id: None,
            member_agent_id: "aid",
            member_public_key_b64: "k",
            role: BridgeRole::Owner,
            display_name: None,
            inviter_agent_id: "i",
            invite_secret: "s",
            ts_ms: 0,
            treekem_key_package_b64: None,
        };
        let json = build_member_joined_event(&inputs, "sig");
        let obj = json.as_object().unwrap();
        assert!(obj["stable_group_id"].is_null());
        assert!(obj["display_name"].is_null());
        assert!(obj["treekem_key_package_b64"].is_null());
    }

    #[test]
    fn encode_payload_b64_roundtrips_json_event() {
        let json = serde_json::json!({"event": "member_joined", "x": 1});
        let b64 = encode_payload_b64(&json).unwrap();
        let bytes = B64.decode(&b64).unwrap();
        let back: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn recipient_kem_key_share_card_missing_yields_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let err = recipient_kem_key(&layout, "deadbeefcafebabe1234").unwrap_err();
        match err {
            ChatError::ShareCardMissing { agent_id_short } => {
                assert_eq!(agent_id_short, "deadbeefcafe");
            }
            other => panic!("expected ShareCardMissing, got {other:?}"),
        }
    }

    #[test]
    fn recipient_kem_key_returns_raw_bytes_when_card_present() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let aid_hex = "0".repeat(64);
        let raw = vec![0xaa; 1184];
        let card = StoredContactCard {
            agent_id_hex: aid_hex.clone(),
            display_name: "Bob".into(),
            kem_public_key_b64: B64.encode(&raw),
            agent_public_key_b64: None,
        };
        card.save(&layout).unwrap();
        let got = recipient_kem_key(&layout, &aid_hex).unwrap();
        assert_eq!(got, raw);
    }

    #[test]
    fn recipient_kem_key_card_with_bad_b64_yields_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let aid_hex = "1".repeat(64);
        let card = StoredContactCard {
            agent_id_hex: aid_hex.clone(),
            display_name: "Mallory".into(),
            kem_public_key_b64: "not-valid-base64!!!!".into(),
            agent_public_key_b64: None,
        };
        card.save(&layout).unwrap();
        let err = recipient_kem_key(&layout, &aid_hex).unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref s) if s.contains("b64 decode")),
            "expected b64-decode invalid, got {err:?}"
        );
    }
}
