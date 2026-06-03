//! Direct messages — conversation-encrypted point-to-point delivery.
//!
//! `Endpoint::send` looks up (or bootstraps) a `Conversation` with the
//! recipient, builds a Welcome outbox on first contact + a Message
//! outbox every send, and routes each `TransitEnvelope` through a
//! [`Router`] of message transports. Inbound is handled separately by
//! the desktop pump via [`conversation::dispatch_inbound`].
//!
//! Legacy plaintext-envelope decode helper [`decode_direct_message`]
//! is preserved for transports that don't speak the v2 conversation
//! wire format (and for the live-relay self-DM test).

use crate::card::{extended_card_from_uri, verify_card_extension};
use crate::chat_crypto::{canonical_envelope_bytes, SIGN_DOMAIN_ENVELOPE};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::{
    build_message_outbox, build_receipt_outbox, build_welcome_outbox, Conversation,
    ConversationRegistry, HistoryEntry, Member, MemberDevice, MemberDeviceStatus,
    OutboundEnvelope as ChatOutbound,
};
use crate::error::{ChatError, Result};
use crate::http::Http;
use crate::identity::AgentId;
use crate::local_store::{write_json_atomic, StoreLayout};
use crate::transport::{
    InboundEnvelope, OutboundEnvelope as TransportOutbound, OutboundKind, Router,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use fetchit_relay_proto::{
    AgentId as ProtoAgentId, EnvelopeKind, GroupId as ProtoGroupId, MachineId, TransitEnvelope,
    WIRE_VERSION,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use x0xd_client::{EncryptedFrame, SecureGroupsEndpoint};

/// A direct message — inbound or outbound, after the JSON envelope
/// has been unwrapped. Used only by transports that still speak the
/// legacy plaintext-envelope wire format.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DirectMessage {
    /// Sender's agent id.
    pub from: AgentId,
    /// Recipient's agent id. Inbound deliveries don't carry this —
    /// the recipient is always the local agent.
    #[serde(default)]
    pub to: Option<AgentId>,
    /// Plaintext body extracted from the envelope's `text` field.
    pub body: String,
    /// Display name from the envelope's `sender_name` field.
    #[serde(default)]
    pub sender_name: Option<String>,
    /// Envelope timestamp (ms since the Unix epoch).
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    /// Stable message id assigned by the transport (relay dedupe key,
    /// LAN-direct sequence, …).
    #[serde(default)]
    pub message_id: Option<String>,
    /// Whether the sender's per-message signature was cryptographically
    /// verified by THIS process against a cached card pubkey.
    ///
    /// * `Some(true)` — the `TransitEnvelope`'s ML-DSA-65 signature was
    ///   verified by `conversation::dispatch_inbound` against the
    ///   sender's cached pubkey. End-to-end signed.
    /// * `Some(false)` — message lacks an in-process-verifiable
    ///   signature (legacy plaintext path) OR no card cached for the
    ///   sender. The UI surfaces this as "unverified sender".
    /// * `None` — outbound bubble; verification doesn't apply to
    ///   messages this device sent.
    ///
    /// Session-level relay auth (`auth_verify_ok_total`) does NOT
    /// imply `Some(true)` — that authenticates the relay session,
    /// not individual messages.
    #[serde(default)]
    pub verified: Option<bool>,
}

/// Legacy JSON envelope wrapping a DM body.
#[derive(Serialize, Deserialize)]
struct LegacyEnvelope {
    text: String,
    #[serde(default)]
    sender_name: Option<String>,
    ts: u64,
}

/// On-disk record of a peer's share card. The v2 fields supply the
/// peer's KEM public key (needed to bootstrap a conversation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContactCard {
    /// Peer's 64-char hex agent id (also the file stem).
    pub agent_id_hex: String,
    /// Display name carried in the x0x card.
    pub display_name: String,
    /// ML-KEM-768 public key (base64).
    pub kem_public_key_b64: String,
    /// Sender's ML-DSA-65 public key (base64). `None` when the import
    /// source didn't carry one — older or trust-on-first-use cards.
    /// Populated by [`Self::from_share_uri`] whenever the share-card
    /// JSON includes `fetchit_agent_public_key_b64` (v2-extended cards),
    /// `public_key_b64`, or `agent_public_key_b64`.
    #[serde(default)]
    pub agent_public_key_b64: Option<String>,
}

impl StoredContactCard {
    /// Build a stored card from a share URI. Extracts the v2 KEM
    /// public key field. When the share URI carries the issuer's
    /// ML-DSA-65 public key, the signature is verified; otherwise the
    /// extraction is trusted on the URI bearer (matches the relay's
    /// `AcceptAllVerifier` posture for v1).
    ///
    /// # Errors
    /// Invalid URI, missing v2 fields, or ML-DSA verification failure
    /// when the issuer key is present.
    pub fn from_share_uri(uri: &str) -> Result<Self> {
        let card_json = extended_card_from_uri(uri)?;
        let obj = card_json
            .as_object()
            .ok_or_else(|| ChatError::Invalid("share card must be a JSON object".into()))?;
        let agent_id_hex = obj
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ChatError::Invalid("share card missing agent_id".into()))?
            .to_owned();
        let display_name = obj
            .get("display_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();

        let agent_pk_b64_opt = obj
            .get("fetchit_agent_public_key_b64")
            .or_else(|| obj.get("public_key_b64"))
            .or_else(|| obj.get("agent_public_key_b64"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        let kem_public_key_b64 = if let Some(ref agent_pk_b64) = agent_pk_b64_opt {
            let agent_pk = B64
                .decode(agent_pk_b64)
                .map_err(|e| ChatError::Invalid(format!("agent pk b64: {e}")))?;
            verify_card_extension(&card_json, &agent_pk)?.kem_public_key_b64
        } else {
            obj.get("fetchit_kem_public_key_b64")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    ChatError::Invalid("card missing fetchit_kem_public_key_b64".into())
                })?
                .to_owned()
        };
        Ok(Self {
            agent_id_hex,
            display_name,
            kem_public_key_b64,
            agent_public_key_b64: agent_pk_b64_opt,
        })
    }

    /// Persist this card to `layout.contact_path(self.agent_id_hex)`.
    ///
    /// # Errors
    /// IO or JSON serialization failures.
    pub fn save(&self, layout: &StoreLayout) -> Result<()> {
        let path = layout.contact_path(&self.agent_id_hex);
        write_json_atomic(&path, self)
    }

    /// Load a stored card from disk by agent id.
    ///
    /// Returns `Ok(None)` when no card is on disk.
    ///
    /// # Errors
    /// IO or JSON parse failures.
    pub fn load(layout: &StoreLayout, agent_id_hex: &str) -> Result<Option<Self>> {
        let path = layout.contact_path(agent_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let card: Self = serde_json::from_slice(&bytes)
            .map_err(|e| ChatError::Invalid(format!("stored card parse: {e}")))?;
        Ok(Some(card))
    }
}

/// Endpoint wrapper. Build via [`crate::Client::messages`].
pub struct Endpoint<'a> {
    http: &'a Http,
    router: &'a Router,
    identity: Option<&'a Arc<FetchitIdentity>>,
    registry: Option<&'a Arc<ConversationRegistry>>,
    signer: Option<&'a Arc<dyn Signer>>,
    layout: Option<&'a StoreLayout>,
    local_machine_id: [u8; 32],
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(
        http: &'a Http,
        router: &'a Router,
        identity: Option<&'a Arc<FetchitIdentity>>,
        registry: Option<&'a Arc<ConversationRegistry>>,
        signer: Option<&'a Arc<dyn Signer>>,
        layout: Option<&'a StoreLayout>,
        local_machine_id: [u8; 32],
    ) -> Self {
        Self {
            http,
            router,
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
        }
    }

    /// Send a direct message. On first contact, bootstraps a fresh
    /// conversation (Welcome outbox) before the message outbox. Every
    /// outbound `TransitEnvelope` is routed verbatim through the
    /// transport `Router` (so KEM ciphertext, signature, and epoch
    /// survive the hop).
    ///
    /// Returns the transport-assigned message id of the LAST envelope
    /// sent (for fanout > 1, callers see only the final receipt).
    ///
    /// # Errors
    /// `ChatError::NoTransportAvailable` when the router has no
    /// reachable transport; `ChatError::Invalid` when no stored card
    /// is available for the recipient or the client was built in
    /// REST-only mode without chat-encryption state.
    pub async fn send(
        &self,
        to: &AgentId,
        body: &str,
        sender_name: &str,
    ) -> Result<Option<String>> {
        // Surface a "no transport" error before the chat-state check
        // so callers that build a Client without a relay still see the
        // historical error variant.
        if self.router.is_empty() {
            return Err(ChatError::NoTransportAvailable);
        }
        let identity = self
            .identity
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let registry = self
            .registry
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let layout = self
            .layout
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        let conv = match registry.find_dm_with(&to.0).await? {
            Some(c) => c,
            None => {
                self.bootstrap_conversation(to, sender_name, identity, registry, signer, layout)
                    .await?
            }
        };

        let message_id = random_message_id();
        let outbox = build_message_outbox(
            &conv,
            body,
            sender_name,
            &message_id,
            identity,
            self.local_machine_id,
            signer.as_ref(),
        )
        .await?;
        self.dispatch_outbox(outbox).await?;
        Ok(Some(message_id))
    }

    async fn bootstrap_conversation(
        &self,
        to: &AgentId,
        _sender_name: &str,
        identity: &Arc<FetchitIdentity>,
        registry: &Arc<ConversationRegistry>,
        signer: &Arc<dyn Signer>,
        layout: &StoreLayout,
    ) -> Result<Conversation> {
        // Race guard: a concurrent inbound welcome (or a sibling
        // outbound `send` that beat us to the punch) may have installed
        // a DM with this peer in the window between `send`'s lookup and
        // here. Re-resolve once more before minting a fresh group so we
        // don't accrete a duplicate conversation in the registry.
        if let Some(existing) = registry.find_dm_with(&to.0).await? {
            return Ok(existing);
        }
        let peer_card = StoredContactCard::load(layout, &to.0)?.ok_or_else(|| {
            ChatError::Invalid(format!(
                "no stored card for {} — import their share card first",
                to.short()
            ))
        })?;
        let peer_member = Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: peer_card.agent_id_hex.clone(),
                kem_public_key_b64: peer_card.kem_public_key_b64.clone(),
                // Carry the peer's ML-DSA pubkey through if we have it;
                // welcomes the peer eventually sends us will self-attest
                // anyway, but mirroring the field here keeps the local
                // member-list consistent with what we'll re-broadcast.
                agent_public_key_b64: peer_card.agent_public_key_b64.clone(),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let local_member = Member {
            user_id_hex: identity.user_id_hex().map(str::to_owned),
            devices: vec![MemberDevice {
                agent_id_hex: identity.agent_id_hex().to_owned(),
                kem_public_key_b64: B64.encode(identity.kem_public_key()),
                // Self-attest the local ML-DSA pubkey so first-contact
                // recipients can bind it to our sender_agent_id via the
                // AUTONOMI_PEER_ID_V2 derivation.
                agent_public_key_b64: Some(B64.encode(signer.public_key())),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        };
        let conv = Conversation::new_dm(local_member, peer_member, None)?;
        let welcome =
            build_welcome_outbox(&conv, identity, self.local_machine_id, signer.as_ref()).await?;
        registry.save(&conv).await?;
        self.dispatch_outbox(welcome).await?;
        Ok(conv)
    }

    /// Emit a `DeliveryReceipt` envelope for a previously-decoded
    /// message. The receipt rides the conversation's current key,
    /// addressed to the original sender's agent id.
    ///
    /// # Errors
    /// `ChatError::NoTransportAvailable` when the router has no
    /// reachable transport, `ChatError::Invalid` when the chat state
    /// is missing or the conversation isn't in the registry.
    pub async fn send_receipt(
        &self,
        group_id_hex: &str,
        message_id: &str,
        recipient_agent_id_hex: &str,
        received_at_ms: u64,
    ) -> Result<()> {
        if self.router.is_empty() {
            return Err(ChatError::NoTransportAvailable);
        }
        let identity = self
            .identity
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let registry = self
            .registry
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        let conv = registry.get(group_id_hex).await?.ok_or_else(|| {
            ChatError::Invalid(format!("no conversation for group_id {group_id_hex}"))
        })?;
        let outbox = build_receipt_outbox(
            &conv,
            message_id,
            received_at_ms,
            recipient_agent_id_hex,
            identity,
            self.local_machine_id,
            signer.as_ref(),
        )
        .await?;
        let _ = self.dispatch_outbox(outbox).await?;
        Ok(())
    }

    /// Send `body` into a private-secure (PQ `TreeKEM`) group.
    ///
    /// Encrypts the plaintext via x0xd's `/secure/encrypt`, postcard-
    /// encodes the resulting [`EncryptedFrame`] into
    /// [`TransitEnvelope::ciphertext`], signs the envelope with the
    /// local ML-DSA-65 key, and routes it through the message
    /// [`Router`]. x0xd owns the `TreeKEM` ratchet — the wire-level
    /// `TransitEnvelope` is the routing-and-signing tunnel.
    ///
    /// The envelope is addressed at the routing layer to the local
    /// agent (loopback through the relay): per
    /// `private/m2-decisions.md` the v1 group fanout layer is deferred
    /// and the chat layer does not yet maintain a member roster here.
    /// Per-recipient fanout will replace the loopback target without
    /// changing this method's signature.
    ///
    /// `group_id` is the x0xd group id as returned by
    /// `groups::create_private` (64-char hex). The 32-byte
    /// [`ProtoGroupId`] on the wire is the hex-decoded value.
    ///
    /// Returns the transport-assigned message id of the sent envelope.
    ///
    /// # Errors
    /// * [`ChatError::NoTransportAvailable`] — no transport registered.
    /// * [`ChatError::Invalid`] — client built without chat state, the
    ///   `group_id` isn't 64-char hex, or postcard / base64 decode of
    ///   the x0xd-returned frame failed.
    /// * [`ChatError::MessageTransport`] — x0xd refused `/secure/encrypt`
    ///   or the transport failed to deliver.
    pub async fn send_private_group(
        &self,
        group_id: &str,
        body: &str,
        _sender_name: &str,
    ) -> Result<Option<String>> {
        if self.router.is_empty() {
            return Err(ChatError::NoTransportAvailable);
        }
        let identity = self
            .identity
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        let group_id_bytes = parse_group_id_hex(group_id)?;
        let secure = self.secure_groups()?;
        let frame = secure.encrypt(group_id, body.as_bytes()).await?;
        let envelope = build_private_group_envelope(
            &frame,
            group_id_bytes,
            identity.agent_id_hex(),
            self.local_machine_id,
            signer.as_ref(),
        )
        .await?;

        let message_id = random_message_id();
        // M2 simplification: loopback the envelope through the routing
        // layer addressed to the local agent. The plaintext route into
        // the recipient's inbox is in the envelope's `group_id`; a
        // future fanout layer will replace this loopback target with
        // one envelope per peer device per Decision 1 of
        // `private/m2-decisions.md`.
        let recipient = AgentId(identity.agent_id_hex().to_owned());
        let timestamp_ms = envelope.timestamp_ms;
        let transport_out = TransportOutbound {
            kind: OutboundKind::Group {
                group_id: group_id.to_owned(),
            },
            from_machine_id: Some(self.local_machine_id),
            payload: Vec::new(),
            timestamp_ms,
            transit: Some(envelope),
        };
        let receipt = self.router.send(&recipient, transport_out).await?;
        Ok(receipt.message_id.or(Some(message_id)))
    }

    /// Process an inbound private-group [`TransitEnvelope`]: decode the
    /// postcard'd [`EncryptedFrame`] out of `ciphertext`, drive x0xd's
    /// `/secure/decrypt` to recover the plaintext, and surface a
    /// [`HistoryEntry`] that callers can fold into their conversation
    /// vault.
    ///
    /// `group_id_hex` is the x0xd group id as a 64-char hex string —
    /// the same value passed to [`Self::send_private_group`]. It is
    /// supplied separately (rather than derived from `env.group_id`)
    /// because callers typically resolve it from a local conversation
    /// lookup and pass it through verbatim, avoiding a round-trip
    /// through `hex::encode` on the hot path.
    ///
    /// Persistence of the returned entry is the caller's
    /// responsibility — the registry update API is left to the
    /// chat-state owner so this method stays usable from contexts
    /// (e.g. the headless peer) that don't carry a Conversation
    /// to mutate in place.
    ///
    /// # Errors
    /// * [`ChatError::Invalid`] — client built without chat state, the
    ///   ciphertext doesn't postcard-decode as an [`EncryptedFrame`],
    ///   or the recovered plaintext is not valid UTF-8.
    /// * [`ChatError::MessageTransport`] — x0xd refused
    ///   `/secure/decrypt` (stale epoch, wrong group, sender mismatch).
    pub async fn receive_private_group_envelope(
        &self,
        env: &TransitEnvelope,
        group_id_hex: &str,
    ) -> Result<HistoryEntry> {
        let frame: EncryptedFrame = postcard::from_bytes(&env.ciphertext)
            .map_err(|e| ChatError::Invalid(format!("postcard frame: {e}")))?;
        let sender_agent_id_hex = hex::encode(env.sender_agent_id.as_bytes());
        let secure = self.secure_groups()?;
        let plaintext = secure
            .decrypt(group_id_hex, &frame, Some(&sender_agent_id_hex))
            .await?;
        let body = String::from_utf8(plaintext)
            .map_err(|e| ChatError::Invalid(format!("body utf8: {e}")))?;
        Ok(HistoryEntry {
            sender_agent_id_hex,
            sender_name: None,
            body,
            ts_ms: env.timestamp_ms,
            message_id: hex::encode(envelope_dedupe_bytes(env)),
        })
    }

    /// Build a [`SecureGroupsEndpoint`] against the same x0xd that
    /// `self.http` dials. Constructed lazily — `Http` owns the base
    /// URL + token, and the endpoint is cheap (one `reqwest::Client`
    /// builder call).
    fn secure_groups(&self) -> Result<SecureGroupsEndpoint> {
        let base = url::Url::parse(self.http.base_url())
            .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
        SecureGroupsEndpoint::new(base, self.http.token().to_owned()).map_err(ChatError::from)
    }

    async fn dispatch_outbox(&self, outbox: Vec<ChatOutbound>) -> Result<Option<String>> {
        let mut last_id = None;
        for ob in outbox {
            let recipient_hex = hex::encode(ob.recipient_agent_id.as_bytes());
            let recipient = AgentId(recipient_hex);
            let timestamp_ms = ob.envelope.timestamp_ms;
            let transport_out = TransportOutbound {
                kind: OutboundKind::Dm,
                from_machine_id: Some(self.local_machine_id),
                payload: Vec::new(),
                timestamp_ms,
                transit: Some(ob.envelope),
            };
            let receipt = self.router.send(&recipient, transport_out).await?;
            last_id = receipt.message_id;
        }
        Ok(last_id)
    }

    /// List currently-open x0xd direct connections — pure compat
    /// signal. Relay-routed delivery does not need pre-connect.
    pub async fn connections(&self) -> Result<Vec<AgentId>> {
        #[derive(Deserialize)]
        struct ConnectionsResponse {
            #[serde(default)]
            connections: Vec<AgentId>,
        }
        let resp: ConnectionsResponse = self.http.get_json("/direct/connections").await?;
        Ok(resp.connections)
    }

    /// Pre-warm a direct x0xd channel. No-op for relay-routed sends;
    /// kept for API parity.
    pub async fn connect(&self, agent_id: &AgentId) -> Result<()> {
        #[derive(Serialize)]
        struct ConnectRequest<'a> {
            agent_id: &'a str,
        }
        let _: serde_json::Value = self
            .http
            .post_json(
                "/agents/connect",
                &ConnectRequest {
                    agent_id: &agent_id.0,
                },
            )
            .await?;
        Ok(())
    }
}

fn random_message_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Decode the 64-char hex x0xd group id into the 32-byte wire shape
/// carried in [`TransitEnvelope::group_id`].
fn parse_group_id_hex(group_id_hex: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(group_id_hex, &mut out)
        .map_err(|e| ChatError::Invalid(format!("group_id hex: {e}")))?;
    Ok(out)
}

/// Compute a 16-byte dedupe-style id for an envelope. Used as the
/// [`HistoryEntry::message_id`] for inbound private-group messages
/// when the transport hasn't already minted one.
fn envelope_dedupe_bytes(env: &TransitEnvelope) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"lit/group/dedupe/v1\0");
    h.update(env.sender_agent_id.as_bytes());
    h.update(env.timestamp_ms.to_be_bytes());
    h.update(env.epoch.to_be_bytes());
    h.update(&env.ciphertext);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Construct a signed [`TransitEnvelope`] wrapping an x0xd
/// [`EncryptedFrame`]. Factored out of [`Endpoint::send_private_group`]
/// so the test module can drive envelope shape assertions without a
/// live router.
async fn build_private_group_envelope<S: Signer + ?Sized>(
    frame: &EncryptedFrame,
    group_id_bytes: [u8; 32],
    local_agent_hex: &str,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<TransitEnvelope> {
    let ciphertext = postcard::to_allocvec(frame)
        .map_err(|e| ChatError::Invalid(format!("postcard frame: {e}")))?;
    // x0xd's nonce travels INSIDE the EncryptedFrame (and thus inside
    // `ciphertext`); the wire-level `nonce` is informational only here
    // — relays do not look at it for the private-group path. We carry
    // the same bytes so wire observers see a consistent shape and a
    // future cross-check can fail closed if they ever disagree.
    let nonce_bytes = B64
        .decode(&frame.nonce_b64)
        .map_err(|e| ChatError::Invalid(format!("frame nonce b64: {e}")))?;
    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(local_agent_hex, &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let mut env = TransitEnvelope {
        version: WIRE_VERSION,
        kind: EnvelopeKind::GroupChat,
        group_id: Some(ProtoGroupId::from_bytes(group_id_bytes)),
        tenant_id: None,
        sender_agent_id: ProtoAgentId::from_bytes(local_agent_bytes),
        sender_machine_id: MachineId::from_bytes(local_machine_id),
        timestamp_ms: now_ms(),
        epoch: frame.secret_epoch,
        ciphertext,
        nonce: nonce_bytes,
        // No envelope-layer KEM: x0xd's TreeKEM rides inside the frame.
        // The empty kem_ciphertext also signals the inbound path to
        // route through `receive_private_group_envelope` rather than
        // the welcome-decrypt branch in `dispatch_inbound`.
        kem_ciphertext: Vec::new(),
        sender_signature: Vec::new(),
    };
    let canonical = canonical_envelope_bytes(&env)?;
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
    sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
    sign_bytes.extend_from_slice(&canonical);
    let sig = signer
        .sign(&sign_bytes)
        .await
        .map_err(|e| ChatError::Invalid(format!("envelope sign: {e}")))?;
    env.sender_signature = sig;
    Ok(env)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Decode an [`InboundEnvelope`] (raw bytes from a transport) into a
/// [`DirectMessage`]. Used by transports that don't speak the v2
/// conversation wire format (e.g. the legacy x0xd direct path and the
/// live-relay self-DM round-trip test).
///
/// # Errors
/// Returns [`ChatError::Decode`] if the payload isn't valid JSON in
/// the expected envelope shape. Empty payloads decode to a `DirectMessage`
/// with an empty body — caller does not need to special-case them.
pub fn decode_direct_message(inbound: InboundEnvelope) -> Result<DirectMessage> {
    // Legacy plaintext schema carries no per-message signature, so the
    // honest answer here is always `Some(false)`. Production messaging
    // rides the TransitEnvelope path through `dispatch_inbound`, which
    // performs real ML-DSA-65 verification and emits `Some(true)`.
    // The earlier `Some(true)` here was a synthesized claim with no
    // cryptographic basis — withdrawn per the M0 honesty floor.
    if inbound.payload.is_empty() {
        return Ok(DirectMessage {
            from: inbound.from,
            to: None,
            body: String::new(),
            sender_name: None,
            timestamp_ms: Some(inbound.timestamp_ms),
            message_id: None,
            verified: Some(false),
        });
    }
    let env: LegacyEnvelope = serde_json::from_slice(&inbound.payload)?;
    Ok(DirectMessage {
        from: inbound.from,
        to: None,
        body: env.text,
        sender_name: env.sender_name,
        timestamp_ms: Some(env.ts),
        message_id: None,
        verified: Some(false),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::transport::{Reachability, SendReceipt, Transport};
    use async_trait::async_trait;
    use fetchit_relay_client::MlDsaSigner;
    use std::sync::Mutex as StdMutex;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Capturing transport: stores the most recent `TransitEnvelope` it
    /// was asked to send, then returns a synthetic receipt. Used by the
    /// `send_private_group` test to assert envelope shape without a
    /// live relay session.
    struct CapturingTransport {
        captured: Arc<StdMutex<Option<TransitEnvelope>>>,
    }

    impl CapturingTransport {
        fn new() -> (Arc<Self>, Arc<StdMutex<Option<TransitEnvelope>>>) {
            let captured = Arc::new(StdMutex::new(None));
            (
                Arc::new(Self {
                    captured: captured.clone(),
                }),
                captured,
            )
        }
    }

    #[async_trait]
    impl Transport for CapturingTransport {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn reachability(&self, _: &AgentId) -> Reachability {
            Reachability::Always
        }
        async fn send(&self, _: &AgentId, envelope: TransportOutbound) -> Result<SendReceipt> {
            *self.captured.lock().unwrap() = envelope.transit.clone();
            Ok(SendReceipt {
                accepted_at_ms: 1,
                message_id: Some("captured-msg-id".to_owned()),
                transport_name: "capture",
            })
        }
        fn take_inbound(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>> {
            None
        }
    }

    /// Build a minimal identity bound to `signer`'s ML-DSA public key —
    /// the same `AUTONOMI_PEER_ID_V2` derivation `dispatch_inbound`'s
    /// welcome path checks against. No on-disk vault is required for
    /// the private-group send path because the envelope's signature is
    /// the only thing keyed off the identity.
    fn fixture_identity(signer: &Arc<MlDsaSigner>) -> (FetchitIdentity, std::path::PathBuf) {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use fetchit_relay_proto::derive_agent_id;
        use zeroize::Zeroizing;
        let dir = tempfile::tempdir().unwrap();
        let aid = hex::encode(derive_agent_id(&signer.public_key()));
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let id = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            &aid,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let path = dir.keep();
        (id, path)
    }

    /// 64-hex group id matching the wire-shape x0xd returns from
    /// `POST /groups`. Doubles as a known value for envelope assertions.
    const TEST_GROUP_HEX: &str = "4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e";

    #[tokio::test]
    async fn send_private_group_encrypts_then_signs_and_postcards_frame() {
        // Wiremock x0xd's POST /groups/<G>/secure/encrypt — return a
        // synthetic EncryptedFrame and assert downstream the envelope
        // captured by the transport carries the postcard-encoded frame
        // in `ciphertext`, version=WIRE_VERSION, kind=GroupChat,
        // epoch=secret_epoch, sender_signature non-empty.
        let server = MockServer::start().await;
        let expected_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&expected_path))
            .and(body_partial_json(serde_json::json!({
                "payload_b64": B64.encode(b"hello group"),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 7,
            })))
            .mount(&server)
            .await;

        let http = Http::new(format!("{}/", server.uri()), "tok".to_owned()).unwrap();
        let (transport, captured) = CapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_concrete = Arc::new(MlDsaSigner::generate().unwrap());
        let signer_arc: Arc<dyn Signer> = signer_concrete.clone();
        let (identity, _tmp) = fixture_identity(&signer_concrete);
        let identity = Arc::new(identity);
        // The send_private_group path only consults `identity`,
        // `signer`, and `router`; the registry + layout slots are
        // unused for the secure-group send, so we leave them None.
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&identity),
            None,
            Some(&signer_arc),
            None,
            [0u8; 32],
        );

        let msg_id = endpoint
            .send_private_group(TEST_GROUP_HEX, "hello group", "Alice")
            .await
            .unwrap();
        assert!(msg_id.is_some(), "send must surface a message id");

        let env = captured
            .lock()
            .unwrap()
            .clone()
            .expect("transport must have captured a TransitEnvelope");

        assert_eq!(env.version, WIRE_VERSION);
        assert!(matches!(env.kind, EnvelopeKind::GroupChat));
        assert_eq!(env.epoch, 7, "envelope epoch must echo secret_epoch");
        assert!(
            env.kem_ciphertext.is_empty(),
            "no envelope-layer KEM on private-group path",
        );
        assert!(
            !env.sender_signature.is_empty(),
            "ML-DSA-65 signature must be populated",
        );
        let frame: EncryptedFrame = postcard::from_bytes(&env.ciphertext)
            .expect("envelope ciphertext must postcard-decode as EncryptedFrame");
        assert_eq!(frame.secret_epoch, 7);
        assert_eq!(frame.ciphertext_b64, "Y2lwaGVydGV4dA==");
        assert_eq!(frame.nonce_b64, "MTIzNDU2Nzg5MGFi");
        // Wire-level nonce mirrors the frame's nonce per the build
        // helper's contract; a future cross-check would otherwise have
        // no shape to assert against.
        assert_eq!(env.nonce, B64.decode("MTIzNDU2Nzg5MGFi").unwrap());
        let group_id = env.group_id.expect("envelope must carry group_id");
        assert_eq!(hex::encode(group_id.as_bytes()), TEST_GROUP_HEX);
    }

    #[tokio::test]
    async fn receive_private_group_envelope_decrypts_via_x0xd_and_yields_history_entry() {
        // Wiremock x0xd's POST /groups/<G>/secure/decrypt — return the
        // recovered plaintext as base64. Construct an inbound
        // TransitEnvelope carrying a postcard'd EncryptedFrame in
        // `ciphertext` and feed it through receive_private_group_envelope.
        // Assert the HistoryEntry fields match the wire shape.
        let server = MockServer::start().await;
        let expected_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        let sender_bytes = [0xAA; 32];
        let sender_hex = hex::encode(sender_bytes);
        Mock::given(method("POST"))
            .and(path(&expected_path))
            .and(body_partial_json(serde_json::json!({
                "sender_agent_id": sender_hex,
                "secret_epoch": 9,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": B64.encode(b"hi from peer"),
            })))
            .mount(&server)
            .await;

        let http = Http::new(format!("{}/", server.uri()), "tok".to_owned()).unwrap();
        let router = Router::new();
        let endpoint = Endpoint::new(&http, &router, None, None, None, None, [0u8; 32]);

        let frame = EncryptedFrame {
            ciphertext_b64: "Y2lwaGVydGV4dA==".to_owned(),
            nonce_b64: "MTIzNDU2Nzg5MGFi".to_owned(),
            secret_epoch: 9,
        };
        let frame_bytes = postcard::to_allocvec(&frame).unwrap();
        let mut group_id_bytes = [0u8; 32];
        hex::decode_to_slice(TEST_GROUP_HEX, &mut group_id_bytes).unwrap();
        let inbound = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(ProtoGroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: ProtoAgentId::from_bytes(sender_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1_700_000_000_000,
            epoch: 9,
            ciphertext: frame_bytes,
            nonce: B64.decode("MTIzNDU2Nzg5MGFi").unwrap(),
            kem_ciphertext: Vec::new(),
            sender_signature: vec![0u8; 64],
        };

        let entry = endpoint
            .receive_private_group_envelope(&inbound, TEST_GROUP_HEX)
            .await
            .unwrap();

        assert_eq!(entry.sender_agent_id_hex, sender_hex);
        assert_eq!(entry.body, "hi from peer");
        assert_eq!(entry.ts_ms, 1_700_000_000_000);
        assert_eq!(entry.sender_name, None);
        assert!(
            !entry.message_id.is_empty(),
            "message_id must be a synthesized dedupe key",
        );
        // Determinism check on the synthesized id — same envelope must
        // map to the same id so callers' dedupe paths can rely on it.
        let entry2 = endpoint
            .receive_private_group_envelope(&inbound, TEST_GROUP_HEX)
            .await
            .unwrap();
        assert_eq!(entry.message_id, entry2.message_id);
    }

    #[test]
    fn parse_group_id_hex_rejects_short_input() {
        assert!(parse_group_id_hex("abcd").is_err());
    }

    #[test]
    fn parse_group_id_hex_round_trips_real_x0xd_id() {
        let bytes = parse_group_id_hex(TEST_GROUP_HEX).unwrap();
        assert_eq!(hex::encode(bytes), TEST_GROUP_HEX);
    }

    #[test]
    fn decode_round_trip_extracts_fields() {
        let env = LegacyEnvelope {
            text: "hello".into(),
            sender_name: Some("Alice".into()),
            ts: 1_700_000_000_000,
        };
        let payload = serde_json::to_vec(&env).unwrap();
        let inbound = InboundEnvelope {
            kind: OutboundKind::Dm,
            from: AgentId("a".repeat(64)),
            payload,
            timestamp_ms: 1_700_000_000_000,
            transport_name: "relay",
            transit: None,
        };
        let dm = decode_direct_message(inbound).unwrap();
        assert_eq!(dm.body, "hello");
        assert_eq!(dm.sender_name.as_deref(), Some("Alice"));
        assert_eq!(dm.from.0, "a".repeat(64));
        assert_eq!(dm.timestamp_ms, Some(1_700_000_000_000));
        // Honesty floor (M0): the legacy plaintext schema carries no
        // per-message signature, so `verified` MUST surface as
        // `Some(false)` here. `Some(true)` is the production
        // TransitEnvelope path through `conversation::dispatch_inbound`.
        assert_eq!(dm.verified, Some(false));
    }

    #[test]
    fn empty_payload_yields_empty_body() {
        let inbound = InboundEnvelope {
            kind: OutboundKind::Dm,
            from: AgentId("a".repeat(64)),
            payload: Vec::new(),
            timestamp_ms: 1,
            transport_name: "relay",
            transit: None,
        };
        let dm = decode_direct_message(inbound).unwrap();
        assert_eq!(dm.body, "");
        assert_eq!(dm.sender_name, None);
        // Empty payload is still the legacy path — surface honest.
        assert_eq!(dm.verified, Some(false));
    }

    #[test]
    fn malformed_payload_errors() {
        let inbound = InboundEnvelope {
            kind: OutboundKind::Dm,
            from: AgentId("a".repeat(64)),
            payload: b"not-json".to_vec(),
            timestamp_ms: 1,
            transport_name: "relay",
            transit: None,
        };
        assert!(decode_direct_message(inbound).is_err());
    }
}
