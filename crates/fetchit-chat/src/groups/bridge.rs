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
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::chat_crypto::{
    aead_open, aead_seal, canonical_envelope_bytes, derive_aead_key, kem_decapsulate,
    kem_encapsulate, random_nonce, AAD_DOMAIN, AEAD_NONCE_LEN, KDF_INFO_BRIDGE, KEM_PUBLIC_KEY_LEN,
    SIGN_DOMAIN_ENVELOPE,
};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::OutboundEnvelope;
use crate::error::{ChatError, Result};
use crate::local_store::StoreLayout;
use crate::messages::StoredContactCard;
use fetchit_relay_proto::{AgentId, EnvelopeKind, MachineId, TransitEnvelope, WIRE_VERSION};
use x0xd_client::SecureGroupsEndpoint;

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

/// AAD bytes used when sealing / unsealing a bridge envelope's
/// ciphertext. Domain-separated from the welcome / message paths so a
/// sealed bridge wrapper cannot be replayed against either of those
/// AEAD contexts. The other binding (sender, kind, timestamp,
/// ciphertext) lives on the envelope's ML-DSA-65 signature over
/// `canonical_envelope_bytes`.
#[must_use]
pub fn bridge_aad() -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 12);
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(b"|bridge-v1|");
    out
}

/// Output of [`seal_bridge_wrapper`] — the three byte arrays the caller
/// stamps onto `TransitEnvelope.kem_ciphertext`, `.nonce`, and
/// `.ciphertext` for the M2.5 bridge send shape.
#[derive(Debug, Clone)]
pub struct SealedBridgeParts {
    /// ML-KEM-768 ciphertext encapsulating the AEAD secret to the
    /// recipient's KEM public key (`KEM_CIPHERTEXT_LEN` bytes).
    pub kem_ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// AEAD ciphertext of the postcard-encoded
    /// [`X0xdGroupMetadataEventWrapper`].
    pub ciphertext: Vec<u8>,
}

/// Seal an [`X0xdGroupMetadataEventWrapper`] for delivery to a peer
/// whose ML-KEM-768 public key is `recipient_kem_pub` (typically pulled
/// from their stored share-card via [`recipient_kem_key`]).
///
/// The output is one-shot: a fresh KEM encapsulation, a fresh nonce,
/// derived AEAD key under [`KDF_INFO_BRIDGE`], AEAD-sealed over
/// [`bridge_aad`]. The caller is responsible for stamping the parts
/// onto a `TransitEnvelope` (`kind = X0xdGroupMetadataEvent`, recipient
/// `to`, ML-DSA-65 envelope signature) and pushing it to the outbox.
///
/// # Errors
/// - [`ChatError::Invalid`] if `recipient_kem_pub` is not
///   `KEM_PUBLIC_KEY_LEN` bytes.
/// - KEM encapsulation or AEAD seal errors (no realistic path on
///   correctly-shaped inputs).
pub fn seal_bridge_wrapper(
    recipient_kem_pub: &[u8],
    wrapper: &X0xdGroupMetadataEventWrapper,
) -> Result<SealedBridgeParts> {
    if recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN {
        return Err(ChatError::Invalid(format!(
            "bridge recipient KEM pub key length: expected {KEM_PUBLIC_KEY_LEN}, got {}",
            recipient_kem_pub.len()
        )));
    }
    let plaintext = wrapper.to_postcard()?;
    let (kem_ciphertext, ss) = kem_encapsulate(recipient_kem_pub)?;
    let aead_key = derive_aead_key(&ss, KDF_INFO_BRIDGE);
    let nonce = random_nonce(&mut OsRng);
    let aad = bridge_aad();
    let ciphertext = aead_seal(&aead_key, &nonce, &plaintext, &aad)?;
    Ok(SealedBridgeParts {
        kem_ciphertext,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Unseal a bridge envelope and recover the inner
/// [`X0xdGroupMetadataEventWrapper`]. Used by the receiving chat-peer
/// before handing the wrapper's `payload_b64` to local x0xd
/// `POST /publish`.
///
/// `our_kem_sec` is the recipient's ML-KEM-768 secret key
/// ([`FetchitIdentity::kem_secret_key`]).
///
/// # Errors
/// - [`ChatError::Invalid`] when the nonce length is wrong, KEM
///   decapsulation fails (wrong recipient or corrupted KEM ciphertext),
///   AEAD-open fails (tampered ciphertext, mismatched recipient, wrong
///   domain), or the inner postcard wrapper is malformed.
pub fn unseal_bridge_wrapper(
    our_kem_sec: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<X0xdGroupMetadataEventWrapper> {
    if nonce.len() != AEAD_NONCE_LEN {
        return Err(ChatError::Invalid(format!(
            "bridge nonce length: expected {AEAD_NONCE_LEN}, got {}",
            nonce.len()
        )));
    }
    let ss = kem_decapsulate(our_kem_sec, kem_ciphertext)
        .map_err(|e| ChatError::Invalid(format!("bridge kem decap: {e}")))?;
    let aead_key = derive_aead_key(&ss, KDF_INFO_BRIDGE);
    let mut nonce_arr = [0u8; AEAD_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let aad = bridge_aad();
    let plaintext = aead_open(&aead_key, &nonce_arr, ciphertext, &aad)
        .map_err(|e| ChatError::Invalid(format!("bridge aead open: {e}")))?;
    X0xdGroupMetadataEventWrapper::from_postcard(&plaintext)
}

/// Build a signed, sealed `TransitEnvelope` carrying an
/// [`X0xdGroupMetadataEventWrapper`] for delivery to a single
/// recipient.
///
/// The envelope shape mirrors the welcome path
/// ([`crate::conversation::build_welcome_outbox`]): KEM-encapsulate to
/// the recipient's KEM pubkey, AEAD-seal the wrapper bytes,
/// ML-DSA-65 sign the canonical envelope bytes. No conversation /
/// registry state is touched — bridge envelopes are one-shot.
///
/// # Errors
/// - [`ChatError::Invalid`] when `recipient_kem_pub` length is wrong,
///   AEAD seal fails, or postcard encoding fails.
/// - Forwarded signer errors when ML-DSA-65 signing the envelope.
pub async fn build_bridge_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    recipient_agent_id: &[u8; 32],
    recipient_kem_pub: &[u8],
    topic: String,
    payload_b64: String,
    local_agent_id: &[u8; 32],
    local_machine_id: &[u8; 32],
    signer: &S,
) -> Result<OutboundEnvelope> {
    let wrapper = X0xdGroupMetadataEventWrapper { topic, payload_b64 };
    let parts = seal_bridge_wrapper(recipient_kem_pub, &wrapper)?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    let mut env = TransitEnvelope {
        version: WIRE_VERSION,
        kind: EnvelopeKind::X0xdGroupMetadataEvent,
        group_id: None,
        tenant_id: None,
        sender_agent_id: AgentId::from_bytes(*local_agent_id),
        sender_machine_id: MachineId::from_bytes(*local_machine_id),
        timestamp_ms: now_ms,
        epoch: 0,
        ciphertext: parts.ciphertext,
        nonce: parts.nonce,
        kem_ciphertext: parts.kem_ciphertext,
        sender_signature: Vec::new(),
    };

    let canonical = canonical_envelope_bytes(&env)?;
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
    sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
    sign_bytes.extend_from_slice(&canonical);
    let sig = signer
        .sign(&sign_bytes)
        .await
        .map_err(|e| ChatError::Invalid(format!("bridge envelope sign: {e}")))?;
    env.sender_signature = sig;

    Ok(OutboundEnvelope {
        recipient_agent_id: AgentId::from_bytes(*recipient_agent_id),
        envelope: env,
    })
}

/// Receive-side glue: unseal a bridge envelope and POST its inner JSON
/// payload to local x0xd `/publish`. Pubsub-loopback then advances
/// local MLS state via the standard
/// `apply_named_group_metadata_event` path.
///
/// Designed to be called from the inbound dispatch loop
/// ([`crate::Client::default_dispatch_one`] and the chat-peer binary)
/// for any `TransitEnvelope` with
/// `kind == EnvelopeKind::X0xdGroupMetadataEvent`.
///
/// Retry / persistence on `/publish` failure is intentionally not
/// handled here; callers that need it should wrap this fn and pump
/// failures into the outbox-style replay queue (P2 follow-up). The
/// returned error is descriptive enough to drive that decision.
///
/// # Errors
/// - [`ChatError::Invalid`] when the envelope kind doesn't match,
///   unseal fails (tampered ciphertext, wrong recipient KEM key,
///   nonce length, malformed wrapper).
/// - Forwarded `x0xd_client::X0xdError` when local `/publish` rejects
///   the payload (mapped to [`ChatError::MessageTransport`]).
pub async fn handle_inbound_bridge_envelope(
    secure: &SecureGroupsEndpoint,
    identity: &FetchitIdentity,
    transit: &TransitEnvelope,
) -> Result<()> {
    if transit.kind != EnvelopeKind::X0xdGroupMetadataEvent {
        return Err(ChatError::Invalid(format!(
            "handle_inbound_bridge_envelope called on kind={:?}",
            transit.kind
        )));
    }
    check_bridge_event_freshness(transit.timestamp_ms, now_ms())?;
    let wrapper = unseal_bridge_wrapper(
        identity.kem_secret_key(),
        &transit.kem_ciphertext,
        &transit.nonce,
        &transit.ciphertext,
    )?;
    secure.publish(&wrapper.topic, &wrapper.payload_b64).await?;
    Ok(())
}

/// Freshness window for inbound bridge envelopes. Defense in depth
/// against replay of a legitimately-sealed envelope captured from a
/// prior session: the AEAD AAD already binds `timestamp_ms` so
/// tampering is detected at unseal, but a captured-and-replayed
/// envelope unseals cleanly because it carries the original
/// signature + AAD. A ±30min window accommodates the practical
/// upper bound on the bridge path's queue latency (relay buffer +
/// reconnect + offline catch-up) plus typical NTP clock drift on
/// either endpoint.
pub(crate) const BRIDGE_FRESHNESS_WINDOW_MS: u64 = 30 * 60 * 1000;

/// Reject a bridge envelope whose wire-layer `timestamp_ms` drifts
/// more than [`BRIDGE_FRESHNESS_WINDOW_MS`] from local wall-clock
/// `now_ms`. Defense in depth on the bridge inbound path; the M2.5
/// design already pins replay via invite single-use, `state_hash`
/// chain, and epoch verification at the local x0xd apply path.
fn check_bridge_event_freshness(transit_ts_ms: u64, now_ms: u64) -> Result<()> {
    let drift = transit_ts_ms.abs_diff(now_ms);
    if drift > BRIDGE_FRESHNESS_WINDOW_MS {
        return Err(ChatError::Invalid(format!(
            "bridge envelope ts_ms outside ±30min freshness window: \
             ts_ms={transit_ts_ms} now_ms={now_ms} drift_ms={drift}"
        )));
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::kem_keygen;
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
    fn seal_unseal_roundtrip_with_real_kem_keypair() {
        let (pk, sk) = kem_keygen().unwrap();
        let original = X0xdGroupMetadataEventWrapper {
            topic: "x0x.named_group/group-abc/metadata".into(),
            payload_b64: "eyJldmVudCI6Im1lbWJlcl9qb2luZWQifQ==".into(),
        };
        let parts = seal_bridge_wrapper(&pk, &original).unwrap();
        assert_eq!(parts.nonce.len(), AEAD_NONCE_LEN);
        assert!(!parts.kem_ciphertext.is_empty());
        assert!(!parts.ciphertext.is_empty());

        let recovered =
            unseal_bridge_wrapper(&sk, &parts.kem_ciphertext, &parts.nonce, &parts.ciphertext)
                .unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn seal_rejects_wrong_recipient_kem_key_length() {
        let wrapper = X0xdGroupMetadataEventWrapper {
            topic: "t".into(),
            payload_b64: "x".into(),
        };
        let err = seal_bridge_wrapper(&[0u8; 64], &wrapper).unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref s) if s.contains("KEM pub key length")),
            "expected length error, got {err:?}"
        );
    }

    #[test]
    fn unseal_rejects_wrong_recipient_secret() {
        let (pk_a, _sk_a) = kem_keygen().unwrap();
        let (_pk_b, sk_b) = kem_keygen().unwrap();
        let wrapper = X0xdGroupMetadataEventWrapper {
            topic: "t".into(),
            payload_b64: "x".into(),
        };
        let parts = seal_bridge_wrapper(&pk_a, &wrapper).unwrap();
        // sk_b is NOT the matching secret for pk_a — decap should
        // either fail or produce a different shared secret which then
        // fails AEAD-open.
        let err = unseal_bridge_wrapper(
            &sk_b,
            &parts.kem_ciphertext,
            &parts.nonce,
            &parts.ciphertext,
        )
        .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(_)),
            "expected Invalid, got {err:?}"
        );
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        let (pk, sk) = kem_keygen().unwrap();
        let wrapper = X0xdGroupMetadataEventWrapper {
            topic: "t".into(),
            payload_b64: "x".into(),
        };
        let parts = seal_bridge_wrapper(&pk, &wrapper).unwrap();
        let mut bad_ct = parts.ciphertext.clone();
        bad_ct[0] ^= 0xff;
        let err =
            unseal_bridge_wrapper(&sk, &parts.kem_ciphertext, &parts.nonce, &bad_ct).unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref s) if s.contains("aead open")),
            "expected aead open error, got {err:?}"
        );
    }

    #[test]
    fn unseal_rejects_wrong_nonce_length() {
        let (_pk, sk) = kem_keygen().unwrap();
        let err = unseal_bridge_wrapper(&sk, &[0u8; 1088], &[0u8; 11], &[0u8; 32]).unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref s) if s.contains("nonce length")),
            "expected nonce-length error, got {err:?}"
        );
    }

    /// Stub signer used only to exercise `build_bridge_outbox` —
    /// returns a fixed-length zero "signature" so the envelope shape is
    /// well-formed without depending on real ML-DSA.
    struct StubSigner;

    #[async_trait::async_trait]
    impl fetchit_relay_client::Signer for StubSigner {
        fn agent_id(&self) -> [u8; 32] {
            [0u8; 32]
        }
        fn public_key(&self) -> Vec<u8> {
            vec![0u8; 32]
        }
        async fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Ok(vec![0u8; 64])
        }
    }

    #[tokio::test]
    async fn build_bridge_outbox_produces_signed_x0xd_envelope() {
        let (pk, _sk) = kem_keygen().unwrap();
        let recipient = [1u8; 32];
        let local_aid = [2u8; 32];
        let local_machine = [3u8; 32];

        let out = build_bridge_outbox(
            &recipient,
            &pk,
            "x0x.named_group/g/metadata".into(),
            "eyJldmVudCI6Im1lbWJlcl9qb2luZWQifQ==".into(),
            &local_aid,
            &local_machine,
            &StubSigner,
        )
        .await
        .unwrap();

        assert_eq!(
            out.envelope.kind,
            EnvelopeKind::X0xdGroupMetadataEvent,
            "kind must mark this as a bridge envelope so the receiver dispatch hits the right arm"
        );
        assert!(
            out.envelope.group_id.is_none(),
            "bridge envelope group_id is intentionally None — wrapper.topic carries the routing"
        );
        assert_eq!(out.envelope.epoch, 0);
        assert_eq!(out.envelope.sender_agent_id.as_bytes(), &local_aid);
        assert_eq!(out.recipient_agent_id.as_bytes(), &recipient);
        assert!(!out.envelope.kem_ciphertext.is_empty());
        assert!(!out.envelope.ciphertext.is_empty());
        assert_eq!(out.envelope.nonce.len(), AEAD_NONCE_LEN);
        assert_eq!(
            out.envelope.sender_signature.len(),
            64,
            "stub signature length"
        );
    }

    #[test]
    fn bridge_aad_is_domain_separated_from_welcome() {
        let aad = bridge_aad();
        assert!(aad.starts_with(AAD_DOMAIN));
        assert!(aad.windows(11).any(|w| w == b"|bridge-v1|"));
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

    #[test]
    fn freshness_accepts_within_window() {
        let now: u64 = 1_700_000_000_000;
        assert!(check_bridge_event_freshness(now, now).is_ok());
        assert!(check_bridge_event_freshness(now - 29 * 60 * 1000, now).is_ok());
        assert!(check_bridge_event_freshness(now + 29 * 60 * 1000, now).is_ok());
        assert!(check_bridge_event_freshness(now - BRIDGE_FRESHNESS_WINDOW_MS, now).is_ok());
        assert!(check_bridge_event_freshness(now + BRIDGE_FRESHNESS_WINDOW_MS, now).is_ok());
    }

    #[test]
    fn freshness_rejects_past_drift() {
        let now: u64 = 1_700_000_000_000;
        let too_old = now - BRIDGE_FRESHNESS_WINDOW_MS - 1;
        let err = check_bridge_event_freshness(too_old, now).unwrap_err();
        match err {
            ChatError::Invalid(msg) => {
                assert!(msg.contains("freshness window"), "msg: {msg}");
                assert!(msg.contains("drift_ms"), "msg: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn freshness_rejects_future_drift() {
        let now: u64 = 1_700_000_000_000;
        let too_new = now + BRIDGE_FRESHNESS_WINDOW_MS + 1;
        let err = check_bridge_event_freshness(too_new, now).unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)), "got {err:?}");
    }
}
