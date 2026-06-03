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
use crate::chat_crypto::{
    canonical_envelope_bytes, ml_dsa_verify, AEAD_KEY_LEN, SIGN_DOMAIN_ENVELOPE,
};
use crate::chat_identity::FetchitIdentity;
use crate::conversation::{
    build_message_outbox, build_receipt_outbox, build_welcome_outbox, Conversation,
    ConversationRegistry, HistoryEntry, Member, MemberDevice, MemberDeviceStatus, MutateAction,
    OutboundEnvelope as ChatOutbound, Role, TrustState,
};
use crate::error::{ChatError, Result};
use crate::groups::{Group, GroupId as ChatGroupId};
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
use std::collections::{BTreeMap, VecDeque};
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

    /// Create a private-secure group via x0xd AND seed a local
    /// [`Conversation`] for it in the registry. Use this instead of the
    /// bare HTTP wrapper [`crate::groups::Endpoint::create_private`] —
    /// without the local conversation seed, [`Self::send_private_group`]
    /// has no place to record outbound history and
    /// [`Self::receive_private_group_envelope`] can't dedup/persist.
    ///
    /// The seeded conversation carries only the local member at
    /// creation time. Peers join via the standard
    /// `groups::invite` + `groups::join` flow on x0xd's side; the local
    /// member list grows lazily on first received envelope (see
    /// `receive_private_group_envelope` for the lazy fallback).
    ///
    /// The conversation's `current_key_b64` is a fixed all-zeros
    /// placeholder — x0xd's `TreeKEM` owns the real key state, and the
    /// fetchit-layer key/epoch fields are unused on the private-group
    /// path. They stay populated so the on-disk shape matches the DM
    /// path and a future caller that mistakes a private-group conv for
    /// a DM doesn't trip the b64-length-32 invariant.
    ///
    /// # Errors
    /// * Whatever [`crate::groups::Endpoint::create_private`] surfaces.
    /// * [`ChatError::Invalid`] — client built without chat state.
    pub async fn create_private_group(
        &self,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<Group> {
        let identity = self
            .identity
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let registry = self
            .registry
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| ChatError::Invalid("client built without chat state".into()))?;

        let groups = crate::groups::Endpoint::new(self.http);
        let group = groups.create_private(name, display_name).await?;
        let conv = self_only_private_group_conversation(
            group.group_id.as_str(),
            group.name.clone(),
            identity,
            signer.as_ref(),
        );
        registry.save(&conv).await?;
        Ok(group)
    }

    /// Send `body` into a private-secure (PQ `TreeKEM`) group.
    ///
    /// Encrypts the plaintext via x0xd's `/secure/encrypt`, postcard-
    /// encodes the resulting [`EncryptedFrame`] into
    /// [`TransitEnvelope::ciphertext`], signs the envelope with the
    /// local ML-DSA-65 key, and routes ONE envelope per active member
    /// of the group (excluding the local agent) through the message
    /// [`Router`]. x0xd owns the `TreeKEM` ratchet — the wire-level
    /// `TransitEnvelope` is the routing-and-signing tunnel.
    ///
    /// Roster is queried from x0xd via
    /// [`crate::groups::Endpoint::members`]; only `state == "active"`
    /// entries receive envelopes. A 1-member group (just the sender)
    /// is a no-op fanout — no envelopes go on the wire — and the
    /// returned message id is the locally-minted one because no
    /// transport receipt exists.
    ///
    /// `group_id` is the x0xd group id as returned by
    /// `groups::create_private` (64-char hex). The 32-byte
    /// [`ProtoGroupId`] on the wire is the hex-decoded value.
    ///
    /// Returns the transport-assigned message id of the LAST envelope
    /// sent (mirrors the fanout semantics of [`Self::dispatch_outbox`]).
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

        // Build the envelope once, fan out N-1 copies — one per active
        // member excluding self. The envelope's `group_id` is what the
        // receiver uses to look up the conversation; the routing-layer
        // recipient on each hop just steers the relay's per-recipient
        // queue.
        let groups = crate::groups::Endpoint::new(self.http);
        let chat_group_id = ChatGroupId::parse(group_id)?;
        let roster = groups.members(&chat_group_id).await?;
        let local_agent_hex = identity.agent_id_hex();
        let timestamp_ms = envelope.timestamp_ms;
        let mut last_receipt_id: Option<String> = None;
        let mut delivered = false;
        for member in roster {
            if member.0 == local_agent_hex {
                continue;
            }
            let transport_out = TransportOutbound {
                kind: OutboundKind::Group {
                    group_id: group_id.to_owned(),
                },
                from_machine_id: Some(self.local_machine_id),
                payload: Vec::new(),
                timestamp_ms,
                transit: Some(envelope.clone()),
            };
            let receipt = self.router.send(&member, transport_out).await?;
            last_receipt_id = receipt.message_id.or(last_receipt_id);
            delivered = true;
        }
        // 1-member group (just the sender) is a legitimate state — no
        // peers to address. Surface a locally-minted message id so the
        // caller's UI bookkeeping (sending → sent state machine) still
        // has a stable anchor.
        if !delivered {
            return Ok(Some(random_message_id()));
        }
        Ok(last_receipt_id.or_else(|| Some(random_message_id())))
    }

    /// Process an inbound private-group [`TransitEnvelope`]: verify the
    /// sender's ML-DSA-65 signature against the cached card pubkey,
    /// dedup against the conversation's seen-nonces window, decode the
    /// postcard'd [`EncryptedFrame`] out of `ciphertext`, drive x0xd's
    /// `/secure/decrypt` to recover the plaintext, push the resulting
    /// [`HistoryEntry`] onto the conversation's local transcript, and
    /// return it.
    ///
    /// `group_id_hex` is the x0xd group id as a 64-char hex string —
    /// the same value passed to [`Self::send_private_group`]. It is
    /// supplied separately (rather than derived from `env.group_id`)
    /// because callers typically resolve it from a local conversation
    /// lookup and pass it through verbatim, avoiding a round-trip
    /// through `hex::encode` on the hot path.
    ///
    /// On replay (the envelope's outer nonce is already in the
    /// conversation's per-sender sliding window) this method returns
    /// `Ok(PrivateGroupReceive::Replay)`; callers must NOT surface the
    /// `HistoryEntry` to the user.
    ///
    /// On first receive for a group the local doesn't yet have a
    /// conversation for (Bob joins Alice's group via x0xd invite; his
    /// local has no `Conversation` yet) this method lazily creates the
    /// shell conversation before recording the entry, so live-test
    /// mechanics work without a separate `join_private` endpoint.
    ///
    /// # Errors
    /// * [`ChatError::Invalid`] — client built without chat state, the
    ///   ciphertext doesn't postcard-decode as an [`EncryptedFrame`],
    ///   the recovered plaintext is not valid UTF-8, no card on file
    ///   for the envelope's `sender_agent_id`, the card carries no
    ///   ML-DSA pubkey, or the envelope signature fails verification.
    /// * [`ChatError::MessageTransport`] — x0xd refused
    ///   `/secure/decrypt` (stale epoch, wrong group, sender mismatch).
    pub async fn receive_private_group_envelope(
        &self,
        env: &TransitEnvelope,
        group_id_hex: &str,
    ) -> Result<PrivateGroupReceive> {
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

        // Sender verification BEFORE any state mutation. Same shape as
        // `conversation::inbound::verify_sender` — load the cached card,
        // confirm it carries a v2 ML-DSA pubkey, verify the envelope
        // signature over `SIGN_DOMAIN_ENVELOPE || canonical_envelope_bytes`.
        let sender_agent_id_hex = hex::encode(env.sender_agent_id.as_bytes());
        let stored_card =
            StoredContactCard::load(layout, &sender_agent_id_hex)?.ok_or_else(|| {
                ChatError::Invalid(format!(
                    "no card for envelope sender {}",
                    &sender_agent_id_hex[..8.min(sender_agent_id_hex.len())]
                ))
            })?;
        let agent_pk_b64 = stored_card.agent_public_key_b64.as_deref().ok_or_else(|| {
            ChatError::Invalid(format!(
                "card for {} has no ML-DSA pubkey",
                &sender_agent_id_hex[..8.min(sender_agent_id_hex.len())]
            ))
        })?;
        let agent_pub = B64
            .decode(agent_pk_b64)
            .map_err(|e| ChatError::Invalid(format!("card agent_public_key_b64: {e}")))?;
        let canonical = canonical_envelope_bytes(env)?;
        let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        ml_dsa_verify(&agent_pub, &sign_bytes, &env.sender_signature)
            .map_err(|_| ChatError::Invalid("envelope signature verify failed".into()))?;

        // Lazy conversation creation: if Bob accepted an invite via
        // x0xd but his local has no Conversation yet, seed a shell
        // before the dedup+history mutation runs. Use the same
        // self-only constructor `create_private_group` uses so the
        // on-disk shape matches.
        if registry.get(group_id_hex).await?.is_none() {
            let conv =
                self_only_private_group_conversation(group_id_hex, None, identity, signer.as_ref());
            registry.save(&conv).await?;
        }

        // Validate the nonce shape BEFORE we touch x0xd's /secure/decrypt
        // — a malformed nonce is unrecoverable and a wasted daemon
        // round-trip would just surface the same error noisier.
        if env.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&env.nonce);

        // x0xd's /secure/decrypt is the only path that can fail with
        // remote state we don't control (stale epoch, KEM mismatch).
        // Run it BEFORE the dedup mutation so a replay-detection close
        // doesn't poison the seen-nonces window on a real decrypt
        // failure. The replay surface here is bounded — x0xd's TreeKEM
        // gates the decrypt key, so re-decrypting the same ciphertext
        // can't escalate beyond the post-dedup drop.
        let frame: EncryptedFrame = postcard::from_bytes(&env.ciphertext)
            .map_err(|e| ChatError::Invalid(format!("postcard frame: {e}")))?;
        let secure = self.secure_groups()?;
        let plaintext = secure
            .decrypt(group_id_hex, &frame, Some(&sender_agent_id_hex))
            .await?;
        let body = String::from_utf8(plaintext)
            .map_err(|e| ChatError::Invalid(format!("body utf8: {e}")))?;

        let entry = HistoryEntry {
            sender_agent_id_hex: sender_agent_id_hex.clone(),
            sender_name: None,
            body,
            ts_ms: env.timestamp_ms,
            message_id: hex::encode(envelope_dedupe_bytes(env)),
        };
        let entry_for_closure = entry.clone();

        // Atomic dedup + history mutation. The mutate_in_place closure
        // holds the by-group_id mutex across the check + push + persist
        // so a concurrent inbound on the same group can't slip an extra
        // copy past the window. Replay surfaces as `Skip(None)`; fresh
        // surfaces as `Persist(Some(entry))`.
        let outcome = registry
            .mutate_in_place(group_id_hex, |conv| {
                if conv.check_and_record_nonce(&sender_agent_id_hex, nonce_bytes) {
                    return MutateAction::Skip(None);
                }
                conv.push_history(entry_for_closure.clone());
                MutateAction::Persist(Some(entry_for_closure.clone()))
            })
            .await?;

        match outcome {
            Some(_persisted) => Ok(PrivateGroupReceive::Persisted(entry)),
            None => Ok(PrivateGroupReceive::Replay),
        }
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

/// Build a `Conversation` shell for a private-secure group containing
/// only the local member. The peer roster grows lazily as invites land
/// (lazy fallback in `receive_private_group_envelope`). All key-state
/// fields are zero-placeholders because x0xd's `TreeKEM` owns the real
/// key material — see [`Endpoint::create_private_group`] for the
/// rationale.
fn self_only_private_group_conversation<S: Signer + ?Sized>(
    group_id_hex: &str,
    name: Option<String>,
    identity: &FetchitIdentity,
    signer: &S,
) -> Conversation {
    let local_member = Member {
        user_id_hex: identity.user_id_hex().map(str::to_owned),
        devices: vec![MemberDevice {
            agent_id_hex: identity.agent_id_hex().to_owned(),
            kem_public_key_b64: B64.encode(identity.kem_public_key()),
            agent_public_key_b64: Some(B64.encode(signer.public_key())),
            added_at_epoch: 0,
            status: MemberDeviceStatus::Active,
        }],
        joined_at_epoch: 0,
    };
    let now = now_ms();
    Conversation {
        group_id_hex: group_id_hex.to_owned(),
        name,
        members: vec![local_member],
        current_epoch: 0,
        // Placeholder key — x0xd's TreeKEM owns the real key material;
        // the fetchit-layer current_key is never used on this path.
        // Kept all-zeros at AEAD_KEY_LEN so the b64-decode invariant
        // (`current_key().len() == AEAD_KEY_LEN`) holds if a stale
        // caller accidentally treats this conv as a DM.
        current_key_b64: B64.encode([0u8; AEAD_KEY_LEN]),
        prior_keys: Vec::new(),
        own_role: Role::Admin,
        created_at_ms: now,
        last_rekey_at_ms: now,
        auto_rekey_interval_ms: crate::conversation::DEFAULT_AUTO_REKEY_INTERVAL_MS,
        // Locally-initiated group is trusted by construction. For the
        // lazy-create path (a peer's invite landed us in), we still mark
        // Confirmed because the relay-side ML-DSA verify is what gates
        // inbound on this private-group path, not the fetchit trust
        // posture.
        trust_state: TrustState::Confirmed,
        seen_nonces: BTreeMap::new(),
        history: VecDeque::new(),
    }
}

/// Routing predicate: is this `TransitEnvelope` a private-secure group
/// frame produced by [`Endpoint::send_private_group`]?
///
/// The discriminator is `kind == GroupChat && kem_ciphertext.is_empty()`.
/// The legacy chat-layer group path always populates `kem_ciphertext`
/// (per-recipient ML-KEM-768 encapsulation); the private-group path
/// does NOT, because x0xd's `TreeKEM` rides inside `ciphertext` instead.
///
/// This predicate is the sole gate that peer.rs uses to route between
/// `conversation::dispatch_inbound` (legacy KEM path) and
/// [`Endpoint::receive_private_group_envelope`] (x0xd /secure/decrypt
/// path). A future DM transport that legitimately leaves
/// `kem_ciphertext` empty would misroute — guard the invariant.
#[must_use]
pub fn is_private_group_envelope(env: &TransitEnvelope) -> bool {
    matches!(env.kind, EnvelopeKind::GroupChat) && env.kem_ciphertext.is_empty()
}

/// Outcome of [`Endpoint::receive_private_group_envelope`]: either a
/// freshly-decoded entry that was appended to the conversation's
/// history, or a replay (same envelope seen before this conversation's
/// per-sender sliding window).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateGroupReceive {
    /// Envelope was fresh: decrypted, verified, dedup-recorded, history
    /// extended, vault persisted. Carries the `HistoryEntry` so callers
    /// can surface it to the UI.
    Persisted(HistoryEntry),
    /// Envelope's outer nonce was already in the conversation's
    /// per-sender sliding window. No state change; caller MUST NOT
    /// surface anything.
    Replay,
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

    /// Mount `POST /groups/<G>/secure/encrypt` returning a fixed
    /// `EncryptedFrame` and `GET /groups/<G>/members` returning
    /// `[local, peer]`. Returned as a pair so the send tests can drive
    /// the encrypt+fanout flow against a single `MockServer` without
    /// per-test boilerplate.
    async fn mount_encrypt_and_two_member_roster(
        server: &MockServer,
        local_agent_hex: &str,
        peer_agent_hex: &str,
    ) {
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 7,
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_agent_hex, "state": "active"},
                    {"agent_id": peer_agent_hex, "state": "active"},
                ]
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn send_private_group_encrypts_then_signs_and_postcards_frame() {
        // Wiremock x0xd's POST /groups/<G>/secure/encrypt — return a
        // synthetic EncryptedFrame and assert downstream the envelope
        // captured by the transport carries the postcard-encoded frame
        // in `ciphertext`, version=WIRE_VERSION, kind=GroupChat,
        // epoch=secret_epoch, sender_signature non-empty. Also mount
        // GET /members so the fanout layer has a real peer to address.
        let server = MockServer::start().await;
        let signer_concrete = Arc::new(MlDsaSigner::generate().unwrap());
        let signer_arc: Arc<dyn Signer> = signer_concrete.clone();
        let (identity, _tmp) = fixture_identity(&signer_concrete);
        let identity = Arc::new(identity);
        let peer_hex = "b".repeat(64);
        mount_encrypt_and_two_member_roster(&server, identity.agent_id_hex(), &peer_hex).await;
        // Assert the encrypt body explicitly via a partial-json
        // matcher so a future param rename trips the test.
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
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

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = CapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        // The send_private_group path only consults `identity`,
        // `signer`, `router`, and now the http (for the roster query).
        // The registry + layout slots are unused for the bare send.
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
