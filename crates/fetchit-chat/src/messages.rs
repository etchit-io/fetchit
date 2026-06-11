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
    /// `message_id` of the earlier message this one replies to, when
    /// the sender marked it as a reply. The UI resolves the quoted
    /// preview from local history.
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    /// Optional inline image attachment (spec 2.4). Already validated
    /// on the receive path — the UI may render it directly.
    #[serde(default)]
    pub attachment: Option<crate::attachment::Attachment>,
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
    /// M3 R-tail-5: relay hints the peer advertised in the
    /// `fetchit_rendezvous_hints` v1 slot of their share card.
    /// `None` for legacy v1 cards (no hints field) AND for v3
    /// profile-paired contacts (their hints live in the
    /// `ProfileManifest`, not parsed here yet). Send-path callers
    /// fall back to the local primary URL when this is `None` so
    /// [`crate::transport::MultiHomeTransport`] keeps routing via
    /// slot 0 for legacy contacts.
    #[serde(default)]
    pub rendezvous_hints: Option<crate::card::RendezvousHintsV1>,
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
        // M3 R-tail-5: lift the `fetchit_rendezvous_hints` slot off
        // the URI so [`crate::transport::MultiHomeTransport`] can
        // route outbound DMs / fanout envelopes to slots 1/2 when the
        // peer's advertised primary differs from ours. Missing slot
        // (legacy v1 card) and decoder-rejected payload both surface
        // as `None`; send-path callers synthesize a primary-URL
        // fallback so the slot-0 default keeps working.
        let rendezvous_hints = obj
            .get("fetchit_rendezvous_hints")
            .and_then(|v| serde_json::from_value::<crate::card::RendezvousHints>(v.clone()).ok())
            .filter(|h| h.v == 1)
            .and_then(|h| crate::card::RendezvousHintsV1::from_value(&h.data).ok());
        Ok(Self {
            agent_id_hex,
            display_name,
            kem_public_key_b64,
            agent_public_key_b64: agent_pk_b64_opt,
            rendezvous_hints,
        })
    }

    /// Resolve `recipient`'s advertised relay hints from their stored
    /// contact card on disk. Returns `None` when the contact is not
    /// imported, when the on-disk card is a legacy v1 card without
    /// the `v2_rendezvous_hints` slot, or when the slot's payload
    /// fails decoder validation.
    ///
    /// Cheap: one filesystem stat + (when present) a single JSON
    /// deserialize, no network calls. Fanout paths can call this
    /// N times per group send without measurable cost.
    ///
    /// `None` here is semantically distinct from `Some(empty)` — the
    /// recipient hasn't advertised a specific relay set, so the
    /// sender should fall back to its own primary URL. See
    /// [`Self::resolve_recipient_hints_or_fallback`] for the
    /// caller-side synthesis helper.
    ///
    /// # Errors
    /// Forwards IO and JSON-parse failures from [`Self::load`].
    pub fn resolve_recipient_hints(
        layout: &StoreLayout,
        agent_id_hex: &str,
    ) -> Result<Option<crate::card::RendezvousHintsV1>> {
        Ok(Self::load(layout, agent_id_hex)?.and_then(|c| c.rendezvous_hints))
    }

    /// Resolve `recipient`'s hints with a fallback to a synthetic
    /// `RendezvousHintsV1 { relays: [primary_fallback_url] }` when
    /// the on-disk card has no `fetchit_rendezvous_hints` slot.
    ///
    /// The fallback keeps existing v1-card contacts routable through
    /// [`crate::transport::MultiHomeTransport`]'s slot 0 (the local
    /// primary) so the legitimate `None` from a legacy card never
    /// reaches the strict-on-`None` transport layer.
    ///
    /// # Errors
    /// Forwards [`Self::load`] IO and JSON-parse failures.
    pub fn resolve_recipient_hints_or_fallback(
        layout: &StoreLayout,
        agent_id_hex: &str,
        primary_fallback_url: &str,
    ) -> Result<crate::card::RendezvousHintsV1> {
        let hints = Self::resolve_recipient_hints(layout, agent_id_hex)?.unwrap_or_else(|| {
            crate::card::RendezvousHintsV1 {
                relays: vec![primary_fallback_url.to_owned()],
            }
        });
        Ok(hints)
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
    members_singleflight: Option<&'a Arc<crate::members_singleflight::MembersSingleflight>>,
    /// M3 federation core: when wired, [`Self::send`] returns
    /// [`ChatError::Denied`] for blocked recipients before sealing.
    /// `None` = ungated.
    denylist: Option<&'a Arc<dyn crate::denylist::DenylistCheck>>,
    /// M3 R-tail-5: the local primary relay URL the send path uses
    /// to synthesize a fallback `RendezvousHintsV1` when the
    /// recipient's stored card has no `v2_rendezvous_hints` slot.
    /// `None` when the client was built without a relay URL
    /// (REST-only / unit-test mode); send paths then pass through
    /// `None` and the no-transport gate trips first anyway.
    primary_relay_url: Option<&'a str>,
}

impl<'a> Endpoint<'a> {
    /// Pre-M3 8-arg constructor, retained for the existing test suite
    /// (which builds endpoints without a denylist consumer).
    /// Production code uses [`Self::new_with_denylist`] via
    /// [`crate::Client::messages`].
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        http: &'a Http,
        router: &'a Router,
        identity: Option<&'a Arc<FetchitIdentity>>,
        registry: Option<&'a Arc<ConversationRegistry>>,
        signer: Option<&'a Arc<dyn Signer>>,
        layout: Option<&'a StoreLayout>,
        local_machine_id: [u8; 32],
        members_singleflight: Option<&'a Arc<crate::members_singleflight::MembersSingleflight>>,
    ) -> Self {
        Self::new_with_denylist(
            http,
            router,
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
            members_singleflight,
            None,
            None,
        )
    }

    /// Same as [`Self::new`] but with an explicit denylist consumer
    /// slot and the local primary relay URL. Used by
    /// [`crate::Client::messages`] in production; the 8-arg
    /// [`Self::new`] is the test-facing path that leaves the gate
    /// disabled and the primary URL unset.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_denylist(
        http: &'a Http,
        router: &'a Router,
        identity: Option<&'a Arc<FetchitIdentity>>,
        registry: Option<&'a Arc<ConversationRegistry>>,
        signer: Option<&'a Arc<dyn Signer>>,
        layout: Option<&'a StoreLayout>,
        local_machine_id: [u8; 32],
        members_singleflight: Option<&'a Arc<crate::members_singleflight::MembersSingleflight>>,
        denylist: Option<&'a Arc<dyn crate::denylist::DenylistCheck>>,
        primary_relay_url: Option<&'a str>,
    ) -> Self {
        Self {
            http,
            router,
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
            members_singleflight,
            denylist,
            primary_relay_url,
        }
    }

    /// M3 R-tail-5 helper: resolve `recipient_agent_id_hex`'s
    /// advertised relay hints from their stored contact card, falling
    /// back to a synthesized `RendezvousHintsV1 { relays: [primary] }`
    /// against the local primary URL so
    /// [`crate::transport::MultiHomeTransport`] always receives
    /// `Some(hints)` and can be strict-on-`None`.
    ///
    /// Returns `None` only when neither a card is on disk (or it
    /// carries no hints) NOR a primary URL is wired (REST-only mode).
    /// In that case the Router caller passes `None` through and the
    /// no-transport gate trips first anyway.
    ///
    /// Owned return (not `&RendezvousHintsV1`) so the synthesized
    /// fallback's lifetime survives the `.await` point on the
    /// subsequent `Router::send` call.
    fn resolve_hints_for(
        &self,
        recipient_agent_id_hex: &str,
    ) -> Option<crate::card::RendezvousHintsV1> {
        let layout = self.layout?;
        let card_hints = StoredContactCard::resolve_recipient_hints(layout, recipient_agent_id_hex)
            .ok()
            .flatten();
        if card_hints.is_some() {
            return card_hints;
        }
        // Legacy v1 card OR no card at all: synthesize a hint
        // pointing at the local primary so MultiHomeTransport routes
        // through slot 0 — that's the same wire behavior as the
        // pre-R-tail-5 None path, just expressed as Some(hints) so
        // the transport surface can be strict.
        self.primary_relay_url
            .map(|url| crate::card::RendezvousHintsV1 {
                relays: vec![url.to_owned()],
            })
    }

    /// Send a direct message. On first contact, bootstraps a fresh
    /// conversation (Welcome outbox) before the message outbox. Every
    /// outbound `TransitEnvelope` is routed verbatim through the
    /// transport `Router` (so KEM ciphertext, signature, and epoch
    /// survive the hop). `reply_to_message_id` marks the message as a
    /// reply to an earlier logical message id. `attachment` carries an
    /// optional inline image (spec 2.4); it is validated before sealing.
    ///
    /// Returns the transport-assigned message id of the LAST envelope
    /// sent (for fanout > 1, callers see only the final receipt).
    ///
    /// # Errors
    /// `ChatError::NoTransportAvailable` when the router has no
    /// reachable transport; `ChatError::Invalid` when no stored card
    /// is available for the recipient or the client was built in
    /// REST-only mode without chat-encryption state;
    /// [`ChatError::Denied`] when the recipient is on the wired
    /// denylist (M3 federation core).
    pub async fn send(
        &self,
        to: &AgentId,
        body: &str,
        sender_name: &str,
        reply_to_message_id: Option<&str>,
        attachment: Option<&crate::attachment::Attachment>,
    ) -> Result<Option<String>> {
        // M3 federation core: refuse outbound DMs to denylisted
        // peers BEFORE sealing or bootstrapping a conversation. Caller
        // sees the typed Denied variant and can surface a "this
        // contact is on the community denylist" UI without leaking
        // any details about why.
        if let Some(denylist) = self.denylist {
            if denylist.is_blocked(&to.0).await {
                return Err(ChatError::Denied {
                    agent_id_hex: to.0.clone(),
                });
            }
        }
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
            reply_to_message_id,
            attachment,
            identity,
            self.local_machine_id,
            signer.as_ref(),
        )
        .await?;
        self.dispatch_outbox(outbox).await?;
        // Persist the outbound entry so delivery receipts have a row to
        // mark and headless readers see sent DMs from disk. Bookkeeping —
        // the send already succeeded, so log rather than fail.
        let entry = HistoryEntry {
            sender_agent_id_hex: identity.agent_id_hex().to_owned(),
            sender_name: Some(sender_name.to_owned()),
            body: body.to_owned(),
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            message_id: message_id.clone(),
            attachment: attachment.cloned(),
            delivered_at_ms: None,
        };
        if let Err(e) = registry
            .mutate_in_place(&conv.group_id_hex, |c| {
                c.push_history(entry);
                MutateAction::Persist(())
            })
            .await
        {
            log::warn!("[chat] outbound history persist failed: {e}");
        }
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
    /// **Partial-delivery semantics.** Per-recipient transport failures
    /// do NOT short-circuit the fanout. The loop attempts every
    /// recipient; failures are logged via `eprintln!` with the failing
    /// `agent_id` but the loop continues. Outcome:
    /// * at least one delivery succeeded → returns `Ok(Some(id))`
    ///   where `id` is the last successful transport receipt (or a
    ///   locally-minted id if no transport surfaced one). The caller's
    ///   "sending → sent" state machine fires for the originating
    ///   message even when some recipients were unreachable.
    /// * every delivery failed → returns the FIRST per-recipient error
    ///   verbatim. Picked because subsequent failures often correlate
    ///   (one router-wide cause) and the first one is the most
    ///   diagnostic.
    /// * 1-member fanout (sender only) → returns `Ok(Some(locally-minted))`
    ///   as the no-op case above.
    ///
    /// # Errors
    /// * [`ChatError::NoTransportAvailable`] — no transport registered.
    /// * [`ChatError::Invalid`] — client built without chat state, the
    ///   `group_id` isn't 64-char hex, or postcard / base64 decode of
    ///   the x0xd-returned frame failed.
    /// * [`ChatError::MessageTransport`] — x0xd refused `/secure/encrypt`.
    ///   Per-recipient transport errors only surface when ALL recipients
    ///   failed (see partial-delivery semantics above).
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
        //
        // Partial-delivery loop (P2 from Bob's adversarial review): a
        // `?` short-circuit on per-recipient `Router::send` failures
        // hid the fact that the first N-1 recipients had been
        // delivered to before the Nth failed — the caller saw `Err`
        // with no signal that anything went out. Collect per-member
        // results, log failures via eprintln!, and only surface an
        // error when EVERY recipient failed. At least-one-success
        // returns Ok so the user's "sending → sent" UI fires.
        let groups = crate::groups::Endpoint::new(self.http);
        let chat_group_id = ChatGroupId::parse(group_id)?;
        let raw_roster = groups.members(&chat_group_id).await?;
        // Roster dedup: `groups::Endpoint::members` returns `Vec<AgentId>`
        // verbatim from `x0xd`'s `/members` response. If the daemon ever
        // emits the same `agent_id` twice in the roster (shouldn't, but
        // the wire shape doesn't enforce uniqueness), the fan-out loop
        // would address the same peer twice — double-delivery on the
        // wire + double-history on the receiver's side. Case-insensitive
        // BTreeSet drop matches the self-exclusion convention from
        // `a3c48dd`.
        let roster = {
            let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            raw_roster
                .into_iter()
                .filter(|m| seen.insert(m.0.to_ascii_lowercase()))
                .collect::<Vec<_>>()
        };
        let local_agent_hex = identity.agent_id_hex();
        // M3 federation core: refuse outbound group sends if ANY
        // roster member is on the community denylist. Same contract as
        // the DM gate in [`Self::send`] — the UI surfaces
        // [`ChatError::Denied`] so the user can remove the blocked
        // member before retrying. Self is excluded from the check
        // (the local can't denylist itself meaningfully) so a
        // self-only group still sends. The Denied error names the
        // first blocked member found so the UI can identify which
        // contact to surface in the toast.
        if let Some(denylist) = self.denylist {
            for member in &roster {
                if member.0.eq_ignore_ascii_case(local_agent_hex) {
                    continue;
                }
                let member_lower = member.0.to_ascii_lowercase();
                if denylist.is_blocked(&member_lower).await {
                    return Err(ChatError::Denied {
                        agent_id_hex: member.0.clone(),
                    });
                }
            }
        }
        let timestamp_ms = envelope.timestamp_ms;
        let mut last_receipt_id: Option<String> = None;
        let mut first_err: Option<ChatError> = None;
        let mut delivered = 0usize;
        let mut attempted = 0usize;
        for member in roster {
            // `identity.agent_id_hex()` is lowercase by construction
            // but `AgentId` is `#[serde(transparent)]`, so roster
            // entries deserialised from x0xd carry whatever case the
            // daemon emits. A case-sensitive `==` would let
            // mixed/uppercase agent_ids slip past self-exclusion and
            // fan the envelope back to the local — double-history at
            // best, redirect loops at worst. ASCII-hex case-fold is
            // safe because every byte is `0-9a-fA-F`.
            if member.0.eq_ignore_ascii_case(local_agent_hex) {
                continue;
            }
            attempted += 1;
            let transport_out = TransportOutbound {
                kind: OutboundKind::Group {
                    group_id: group_id.to_owned(),
                },
                from_machine_id: Some(self.local_machine_id),
                payload: Vec::new(),
                timestamp_ms,
                transit: Some(envelope.clone()),
            };
            // M3 R-tail-5: thread per-recipient relay hints into the
            // Router. Legacy v1 contacts (no hints slot on their card)
            // get a synthesized fallback to our own primary URL so
            // MultiHomeTransport's slot 0 still serves them; v2-card
            // contacts with a different primary route to slot 1/2.
            // The lookup is a single file stat + (when present) a
            // small JSON decode against `layout`, cheap enough to do
            // per-member in a fanout loop.
            let hints = self.resolve_hints_for(&member.0);
            match self
                .router
                .send(&member, transport_out, hints.as_ref())
                .await
            {
                Ok(receipt) => {
                    last_receipt_id = receipt.message_id.or(last_receipt_id);
                    delivered += 1;
                }
                Err(e) => {
                    eprintln!(
                        "[chat] private-group fanout: recipient {} failed: {e}",
                        &member.0[..8.min(member.0.len())],
                    );
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        // 1-member group (just the sender) is a legitimate state — no
        // peers to address. Surface a locally-minted message id so the
        // caller's UI bookkeeping (sending → sent state machine) still
        // has a stable anchor.
        if attempted == 0 {
            return Ok(Some(random_message_id()));
        }
        // Every recipient failed: surface the first per-recipient
        // error verbatim. (Picked the first because failures often
        // correlate — one router-wide cause — and the first one is
        // the most diagnostic.)
        if delivered == 0 {
            // Safety: attempted > 0 && delivered == 0 ⇒ first_err set.
            return Err(first_err.unwrap_or_else(|| {
                ChatError::MessageTransport("fanout: every recipient failed".into())
            }));
        }
        // Partial success or full success: caller's UI fires "sent".
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
    // The body chains the per-step prelude — verify, nonce check, decrypt,
    // dedupe, history mutation — and each step pulls a paragraph of inline
    // commentary keyed to the security argument. Splitting into helpers
    // would burn the through-line that makes the cross-checks legible. The
    // 104/100 line budget breach is deliberate.
    #[allow(clippy::too_many_lines)]
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

        // Validate the nonce shape BEFORE we touch x0xd's /secure/decrypt
        // — a malformed nonce is unrecoverable and a wasted daemon
        // round-trip would just surface the same error noisier.
        if env.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&env.nonce);

        // Defence-in-depth: the AEAD-bound nonce lives INSIDE the
        // frame the daemon decrypts. The outer envelope's `env.nonce`
        // must be authentically derivable from the inner ciphertext so
        // an attacker who captured a delivered envelope cannot mint a
        // new envelope with a fresh `env.nonce` while leaving the
        // ciphertext bytes unchanged — the per-sender replay window
        // tracks `env.nonce`, so a fresh outer nonce would otherwise
        // sail past dedup and the daemon would happily re-decrypt the
        // same frame (TreeKEM is stateless within an epoch). Rejecting
        // a mismatch BEFORE the replay check + the daemon round-trip
        // closes the entire outer-vs-inner-nonce-mismatch class.
        //
        // Plane dispatch (v0.21.3 ADR-0012):
        // - Legacy `SignedPublic`: `frame.nonce_b64` IS the AEAD nonce.
        //   `env.nonce` must equal the decoded value byte-for-byte.
        // - `TreeKEM`: the AEAD nonce is embedded in
        //   `frame.ciphertext_b64`; the daemon does not expose it. The
        //   sender carries `env.nonce =
        //   derive_treekem_outer_nonce(ciphertext_b64)`, so the receiver
        //   recomputes the same derivation and checks for equality.
        let frame: EncryptedFrame = postcard::from_bytes(&env.ciphertext)
            .map_err(|e| ChatError::Invalid(format!("postcard frame: {e}")))?;
        let expected_outer_nonce: Vec<u8> = if frame.is_treekem() {
            derive_treekem_outer_nonce(&frame.ciphertext_b64)
        } else {
            let nonce_b64 = frame
                .nonce_b64
                .as_deref()
                .ok_or_else(|| ChatError::Invalid("legacy frame missing nonce_b64".into()))?;
            B64.decode(nonce_b64)
                .map_err(|e| ChatError::Invalid(format!("frame nonce b64: {e}")))?
        };
        if expected_outer_nonce != env.nonce {
            return Err(ChatError::Invalid(
                "envelope nonce vs frame nonce mismatch".into(),
            ));
        }

        // x0xd's /secure/decrypt is the only path that can fail with
        // remote state we don't control (stale epoch, KEM mismatch).
        // Run it BEFORE the dedup mutation so a replay-detection close
        // doesn't poison the seen-nonces window on a real decrypt
        // failure. The replay surface here is bounded — x0xd's TreeKEM
        // gates the decrypt key, so re-decrypting the same ciphertext
        // can't escalate beyond the post-dedup drop.
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
            attachment: None,
            delivered_at_ms: None,
        };
        let entry_for_closure = entry.clone();

        // Anti-DoS gate on the lazy-bootstrap path. The `mutate_in_place_or_init`
        // closure below will spawn a fresh Conversation on disk if none exists
        // for `group_id_hex` yet. Without an authorisation check on that
        // bootstrap step, any sender we've already paired with (their ML-DSA
        // verify passes upstream of this) could stream envelopes for an
        // unbounded space of attacker-chosen `group_id_hex` values and force
        // the receiver to write a new vault file per group_id — disk-fill DoS.
        // x0xd is the source of truth for membership; we only bootstrap when
        // it confirms we are actually in the group. After bootstrap, every
        // subsequent receive uses the existing Conversation with no roster
        // query, so this is amortised to one HTTP call per first-receive per
        // group. Membership-revocation race (we got kicked between this check
        // and the mutate) is benign: subsequent receives just hit the
        // existing conv path; the disk-fill vector is closed regardless.
        if registry.get(group_id_hex).await?.is_none() {
            self.verify_group_membership(group_id_hex, identity.agent_id_hex())
                .await?;
        }

        // Atomic lazy-create + dedup + history mutation. The
        // `mutate_in_place_or_init` closure runs the bootstrap of a
        // fresh self-only conversation UNDER the per-group mutex iff
        // none exists yet, then runs the dedup check + history push
        // in the same locked critical section. Two concurrent receive
        // paths on the same brand-new group_id can therefore not both
        // observe `None` and race duplicate `save(empty_shell)` calls
        // that wipe each other's recorded nonce + history entry. The
        // bootstrap-then-mutate is atomic: the second receiver
        // observes the entry the first inserted.
        let group_id_owned = group_id_hex.to_owned();
        let identity_for_init = identity.clone();
        let signer_for_init = signer.clone();
        let outcome = registry
            .mutate_in_place_or_init(
                group_id_hex,
                move || {
                    self_only_private_group_conversation(
                        &group_id_owned,
                        None,
                        &identity_for_init,
                        signer_for_init.as_ref(),
                    )
                },
                |conv| {
                    if conv.check_and_record_nonce(&sender_agent_id_hex, nonce_bytes) {
                        return MutateAction::Skip(None);
                    }
                    conv.push_history(entry_for_closure.clone());
                    MutateAction::Persist(Some(entry_for_closure.clone()))
                },
            )
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
        let base = url::Url::parse(&self.http.base_url())
            .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
        SecureGroupsEndpoint::new(base, self.http.token().to_owned()).map_err(ChatError::from)
    }

    /// Confirm with `x0xd` that `self_agent_id_hex` is a member of
    /// `group_id_hex`. Used as the anti-`DoS` gate before
    /// `mutate_in_place_or_init` lazy-bootstraps a fresh on-disk
    /// `Conversation`: an ML-DSA-paired contact could otherwise mint
    /// envelopes against any string-shaped `group_id_hex` and force
    /// the receiver to spawn an unbounded number of vault entries
    /// (disk-fill `DoS`). `x0xd` is the source of truth for group
    /// membership; envelopes whose `group_id` doesn't list us as a
    /// member are rejected before any disk write.
    ///
    /// Comparison is case-insensitive to match
    /// `send_private_group`'s self-exclusion: `x0xd`'s roster shape
    /// has historically returned mixed-case agent IDs and the wire
    /// `AgentId` is `#[serde(transparent)]`.
    ///
    /// **Failure mode.** If `x0xd` is down or the `/members` endpoint
    /// returns non-2xx, this method propagates the error and the
    /// receiver becomes deaf to bootstrap of new groups until the
    /// daemon recovers. That is the pragmatic shape — `fetchit-chat`
    /// cannot operate without `x0xd` regardless (signing, decrypt,
    /// roster all live there) so a `/members` outage is observable
    /// upstream too. Existing conversations are unaffected (their
    /// receive path skips the gate per the `registry.get().is_some()`
    /// check at the call site).
    async fn verify_group_membership(
        &self,
        group_id_hex: &str,
        self_agent_id_hex: &str,
    ) -> Result<()> {
        let group_id = crate::groups::GroupId::parse(group_id_hex)?;
        let roster = match self.members_singleflight {
            Some(sf) => {
                sf.fetch_or_wait(group_id_hex, || async {
                    crate::groups::Endpoint::new(self.http)
                        .members(&group_id)
                        .await
                })
                .await?
            }
            None => {
                crate::groups::Endpoint::new(self.http)
                    .members(&group_id)
                    .await?
            }
        };
        if !roster
            .iter()
            .any(|m| m.0.eq_ignore_ascii_case(self_agent_id_hex))
        {
            let preview_len = 8.min(group_id_hex.len());
            return Err(ChatError::Invalid(format!(
                "not a member of group {}; refusing to bootstrap conversation",
                &group_id_hex[..preview_len]
            )));
        }
        Ok(())
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
            // M3 R-tail-5: look up the recipient's advertised relay
            // hints so MultiHomeTransport can route via slot 1/2 when
            // their primary differs from ours. Legacy v1 contacts
            // fall back to our own primary URL synthesized in
            // `resolve_hints_for`.
            let hints = self.resolve_hints_for(&recipient.0);
            let receipt = self
                .router
                .send(&recipient, transport_out, hints.as_ref())
                .await?;
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
    // Wire-level `env.nonce` is 12 bytes — the per-sender replay window
    // and (for the legacy path) a defence-in-depth cross-check against
    // the AEAD-bound nonce key off it.
    //
    // Legacy SignedPublic: `frame.nonce_b64` is the AEAD nonce. We carry
    // it as `env.nonce` so the receive-side inner/outer cross-check
    // closes the captured-envelope-replay vector (see
    // `receive_private_group_envelope`).
    //
    // TreeKEM (v0.21.3 ADR-0012): the AEAD nonce is BAKED INTO the
    // `ApplicationCiphertext` carried in `frame.ciphertext_b64`. The
    // daemon does not expose it. We DERIVE `env.nonce` as the first 12
    // bytes of `SHA256(domain || ciphertext_b64-bytes)` — a
    // deterministic-per-ciphertext value the receiver can recompute
    // and check, preserving the inner/outer integrity property: an
    // attacker minting a fresh `env.nonce` against an unchanged inner
    // ciphertext will fail the derivation check on the receive side.
    let nonce_bytes = if frame.is_treekem() {
        derive_treekem_outer_nonce(&frame.ciphertext_b64)
    } else {
        let nonce_b64 = frame
            .nonce_b64
            .as_deref()
            .ok_or_else(|| ChatError::Invalid("legacy encrypt frame missing nonce_b64".into()))?;
        B64.decode(nonce_b64)
            .map_err(|e| ChatError::Invalid(format!("frame nonce b64: {e}")))?
    };
    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(local_agent_hex, &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let mut env = TransitEnvelope {
        version: WIRE_VERSION,
        // M2 private-group sends carry their own envelope-kind so the
        // inbound router can discriminate them from legacy chat-v2
        // group Message envelopes without inspecting `kem_ciphertext`
        // (the two were wire-identical under the old discriminator).
        kind: EnvelopeKind::PrivateGroupChat,
        group_id: Some(ProtoGroupId::from_bytes(group_id_bytes)),
        tenant_id: None,
        sender_agent_id: ProtoAgentId::from_bytes(local_agent_bytes),
        sender_machine_id: MachineId::from_bytes(local_machine_id),
        timestamp_ms: now_ms(),
        epoch: frame.secret_epoch,
        ciphertext,
        nonce: nonce_bytes,
        // No envelope-layer KEM: x0xd's TreeKEM rides inside the frame.
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

/// Derive the 12-byte wire-level `env.nonce` for a `TreeKEM` frame.
///
/// `frame.nonce_b64` is `None` on the `TreeKEM` path (v0.21.3 ADR-0012: the
/// AEAD nonce is embedded in the `ApplicationCiphertext`). We still need a
/// deterministic 12-byte value to populate `TransitEnvelope::nonce` so the
/// per-sender replay window keeps working AND the receiver can re-derive
/// the same value as an inner/outer integrity check.
///
/// The derivation is `SHA256(domain || ciphertext_b64_bytes)` truncated to
/// 12 bytes. The domain string keeps this value distinct from any other
/// per-message hash we might compute over the ciphertext (e.g.
/// `envelope_dedupe_bytes`) so the two cannot collide and confuse a
/// future cross-check.
fn derive_treekem_outer_nonce(ciphertext_b64: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"lit/group/treekem/outer-nonce/v1\0");
    h.update(ciphertext_b64.as_bytes());
    let digest = h.finalize();
    digest[..12].to_vec()
}

/// Wall-clock millis since the Unix epoch. On a broken clock
/// (`SystemTime::duration_since(UNIX_EPOCH)` returning `Err`)
/// saturates to `u64::MAX` so the value falls OUTSIDE any sliding
/// window — matches the relay-transport convention so the two timers
/// don't diverge under clock skew. Returning `0` (the previous
/// behaviour) would let a broken clock accidentally land inside a
/// window, which is the opposite of what we want.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| {
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
        })
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
/// Discriminator is the dedicated [`EnvelopeKind::PrivateGroupChat`]
/// variant. The earlier `kind == GroupChat && kem_ciphertext.is_empty()`
/// shape was ambiguous: legacy chat-v2 Message envelopes (subsequent
/// messages after a Welcome) also use `kind == GroupChat` with empty
/// `kem_ciphertext` because the per-recipient ML-KEM-768 ride travels
/// on Welcome only. A receiver running that predicate misrouted
/// legacy DMs into [`Endpoint::receive_private_group_envelope`], where
/// the postcard-`EncryptedFrame` decode failed because the bytes are
/// an AEAD-sealed `MessagePayload` from the chat-v2 path.
///
/// This predicate is the sole gate peer.rs uses to route between
/// [`crate::conversation::dispatch_inbound`] (legacy chat-v2 path)
/// and [`Endpoint::receive_private_group_envelope`] (x0xd
/// /secure/decrypt path).
#[must_use]
pub fn is_private_group_envelope(env: &TransitEnvelope) -> bool {
    matches!(env.kind, EnvelopeKind::PrivateGroupChat)
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
            reply_to_message_id: None,
            attachment: None,
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
        reply_to_message_id: None,
        attachment: None,
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
        async fn send(
            &self,
            _: &AgentId,
            envelope: TransportOutbound,
            _: Option<&crate::card::RendezvousHintsV1>,
        ) -> Result<SendReceipt> {
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

    /// 64-hex agent id for a peer that is NOT the test's local
    /// identity. Used by tests that need a stand-in "other" agent in
    /// a roster or sender slot. 64 `c`'s — chosen for visual
    /// distinctness from the all-`a` / all-`b` patterns elsewhere.
    const OTHER_AGENT_HEX: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

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

    /// Smaller helper for `receive_private_group_envelope` tests that
    /// exercise lazy-bootstrap: mounts `GET /groups/<G>/members`
    /// returning a 1-entry roster containing `local_agent_hex`. The
    /// membership gate (anti-DoS) on the bootstrap path queries this
    /// endpoint; without the mock, every bootstrap path 404s.
    async fn mount_members_with_self_only(server: &MockServer, local_agent_hex: &str) {
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_agent_hex, "state": "active"},
                ]
            })))
            .mount(server)
            .await;
    }

    /// Helper for the receive-side not-a-member test: mounts a
    /// `GET /groups/<G>/members` that returns OK but with a roster
    /// that does NOT contain `local_agent_hex`. The anti-DoS gate
    /// should reject the bootstrap.
    async fn mount_members_without_self(server: &MockServer, other_agent_hex: &str) {
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": other_agent_hex, "state": "active"},
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
        // in `ciphertext`, version=WIRE_VERSION, kind=PrivateGroupChat,
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
            None,
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
        assert!(matches!(env.kind, EnvelopeKind::PrivateGroupChat));
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
        // Legacy mock encrypt — daemon returned `nonce_b64`, no
        // `secure_plane` tag, so the frame's plane stays `None` and the
        // build helper used `frame.nonce_b64` verbatim for `env.nonce`.
        assert_eq!(frame.nonce_b64.as_deref(), Some("MTIzNDU2Nzg5MGFi"));
        assert!(frame.plane.is_none());
        assert_eq!(env.nonce, B64.decode("MTIzNDU2Nzg5MGFi").unwrap());
        let group_id = env.group_id.expect("envelope must carry group_id");
        assert_eq!(hex::encode(group_id.as_bytes()), TEST_GROUP_HEX);
    }

    // ===================================================================
    // Private-group send/receive — failure paths + round-trip integration.
    // ===================================================================

    /// Full rig for the private-group receive tests: layout on a temp
    /// dir, a `FetchitIdentity` bound to a freshly-generated ML-DSA
    /// signer, a `ConversationRegistry`, and the in-memory pieces a
    /// `messages::Endpoint` needs at call time. Held by-value so each
    /// test's tempdir stays alive across the whole test; the
    /// `_tempdir` field is intentionally a guard.
    struct PrivateGroupRig {
        _tempdir: tempfile::TempDir,
        layout: crate::local_store::StoreLayout,
        identity: Arc<FetchitIdentity>,
        signer: Arc<MlDsaSigner>,
        registry: Arc<crate::conversation::ConversationRegistry>,
    }

    impl PrivateGroupRig {
        fn signer_arc(&self) -> Arc<dyn Signer> {
            self.signer.clone()
        }

        fn agent_hex(&self) -> &str {
            self.identity.agent_id_hex()
        }
    }

    /// Build a fresh rig. Each call mints a distinct ML-DSA identity so
    /// adversarial tests can produce mismatched-sender cards without
    /// stomping on a shared fixture.
    fn build_rig() -> PrivateGroupRig {
        use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
        use crate::conversation::ConversationRegistry;
        use crate::local_store::StoreLayout;
        use fetchit_relay_proto::derive_agent_id;
        use zeroize::Zeroizing;
        let tempdir = tempfile::tempdir().unwrap();
        let signer = Arc::new(MlDsaSigner::generate().unwrap());
        let aid = hex::encode(derive_agent_id(&signer.public_key()));
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let layout = StoreLayout::ensure(tempdir.path().join("store")).unwrap();
        let id = FetchitIdentity::load_or_create(
            tempdir.path(),
            &master,
            &aid,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let registry = Arc::new(ConversationRegistry::new(
            layout.clone(),
            Arc::new(master),
            kdf_id_argon2(),
            Some(salt),
        ));
        PrivateGroupRig {
            _tempdir: tempdir,
            layout,
            identity: Arc::new(id),
            signer,
            registry,
        }
    }

    /// Install `sender_signer`'s share card into `rig.layout` so that
    /// `receive_private_group_envelope` can resolve the sender's
    /// ML-DSA pubkey for signature verification.
    fn install_card_for(rig: &PrivateGroupRig, sender_signer: &MlDsaSigner, sender_hex: &str) {
        let card = StoredContactCard {
            agent_id_hex: sender_hex.to_owned(),
            display_name: "Peer".to_owned(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: Some(B64.encode(sender_signer.public_key())),
            rendezvous_hints: None,
        };
        card.save(&rig.layout).unwrap();
    }

    /// Build + sign a private-group envelope addressed to the test
    /// group. Signature is over the canonical envelope bytes using
    /// `sender_signer`, so the receive path's verify-prelude will
    /// accept it iff the matching card is installed.
    async fn craft_inbound_envelope(
        sender_signer: &MlDsaSigner,
        sender_hex: &str,
        body: &[u8],
        timestamp_ms: u64,
    ) -> TransitEnvelope {
        let frame = EncryptedFrame {
            ciphertext_b64: B64.encode(body),
            nonce_b64: Some("MTIzNDU2Nzg5MGFi".to_owned()),
            secret_epoch: 9,
            plane: None,
        };
        let frame_bytes = postcard::to_allocvec(&frame).unwrap();
        let mut group_id_bytes = [0u8; 32];
        hex::decode_to_slice(TEST_GROUP_HEX, &mut group_id_bytes).unwrap();
        let mut sender_bytes = [0u8; 32];
        hex::decode_to_slice(sender_hex, &mut sender_bytes).unwrap();
        let mut env = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::PrivateGroupChat,
            group_id: Some(ProtoGroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: ProtoAgentId::from_bytes(sender_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms,
            epoch: 9,
            ciphertext: frame_bytes,
            nonce: B64.decode("MTIzNDU2Nzg5MGFi").unwrap(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let canonical = canonical_envelope_bytes(&env).unwrap();
        let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        env.sender_signature = sender_signer.sign(&sign_bytes).await.unwrap();
        env
    }

    /// Mount `POST /groups/<G>/secure/decrypt` returning `payload_b64`
    /// — the receive path drives this to recover the plaintext.
    async fn mount_decrypt(server: &MockServer, plaintext: &[u8]) {
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": B64.encode(plaintext),
            })))
            .mount(server)
            .await;
    }

    // ---- send: trivial failure-path tests --------------------------------

    #[tokio::test]
    async fn send_private_group_returns_no_transport_when_router_empty() {
        let server = MockServer::start().await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let rig = build_rig();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap_err();
        assert!(matches!(err, ChatError::NoTransportAvailable));
    }

    #[tokio::test]
    async fn send_private_group_returns_invalid_when_chat_state_missing() {
        let server = MockServer::start().await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, _captured) = CapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let endpoint = Endpoint::new(&http, &router, None, None, None, None, [0u8; 32], None);
        let err = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("chat state")),
            "expected Invalid(chat state), got {err:?}",
        );
    }

    #[tokio::test]
    async fn send_private_group_surfaces_encrypt_4xx_as_message_transport_error() {
        let server = MockServer::start().await;
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(
                ResponseTemplate::new(503).set_body_string(r#"{"ok":false,"error":"daemon down"}"#),
            )
            .mount(&server)
            .await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, _captured) = CapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let rig = build_rig();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::MessageTransport(ref m) if m.contains("503")),
            "expected MessageTransport(503), got {err:?}",
        );
    }

    /// A `Signer` that always fails. Drives the
    /// `send_private_group_surfaces_signer_failure` test without
    /// poisoning the ambient `MlDsaSigner` fixture.
    struct FailingSigner {
        pk: Vec<u8>,
    }

    #[async_trait]
    impl Signer for FailingSigner {
        fn agent_id(&self) -> [u8; 32] {
            fetchit_relay_proto::derive_agent_id(&self.pk)
        }
        fn public_key(&self) -> Vec<u8> {
            self.pk.clone()
        }
        async fn sign(&self, _bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
            Err("signer-down".to_owned())
        }
    }

    #[tokio::test]
    async fn send_private_group_surfaces_signer_failure() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let peer_hex = "b".repeat(64);
        mount_encrypt_and_two_member_roster(&server, rig.agent_hex(), &peer_hex).await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, _captured) = CapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let failing: Arc<dyn Signer> = Arc::new(FailingSigner {
            pk: rig.signer.public_key(),
        });
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&failing),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("envelope sign")),
            "expected Invalid(envelope sign), got {err:?}",
        );
    }

    /// Capturing transport variant that records EVERY recipient + envelope
    /// pair so a fanout test can assert N distinct addressing.
    type CapturedSends = Arc<StdMutex<Vec<(AgentId, TransitEnvelope)>>>;

    struct ManyCapturingTransport {
        captured: CapturedSends,
    }

    impl ManyCapturingTransport {
        fn new() -> (Arc<Self>, CapturedSends) {
            let captured: CapturedSends = Arc::new(StdMutex::new(Vec::new()));
            (
                Arc::new(Self {
                    captured: captured.clone(),
                }),
                captured,
            )
        }
    }

    #[async_trait]
    impl Transport for ManyCapturingTransport {
        fn name(&self) -> &'static str {
            "many-capture"
        }
        fn reachability(&self, _: &AgentId) -> Reachability {
            Reachability::Always
        }
        async fn send(
            &self,
            to: &AgentId,
            envelope: TransportOutbound,
            _: Option<&crate::card::RendezvousHintsV1>,
        ) -> Result<SendReceipt> {
            if let Some(t) = envelope.transit {
                self.captured.lock().unwrap().push((to.clone(), t));
            }
            Ok(SendReceipt {
                accepted_at_ms: 1,
                message_id: Some("captured-msg-id".to_owned()),
                transport_name: "many-capture",
            })
        }
        fn take_inbound(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>> {
            None
        }
    }

    #[tokio::test]
    async fn send_private_group_fans_out_one_envelope_per_roster_member_excluding_self() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer1 = "b".repeat(64);
        let peer2 = "c".repeat(64);

        // Encrypt mock — single response covers every send.
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        // 3-member roster: local + two peers; only peers should receive.
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_hex, "state": "active"},
                    {"agent_id": peer1, "state": "active"},
                    {"agent_id": peer2, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        let recipients: std::collections::HashSet<String> =
            captured.iter().map(|(a, _)| a.0.clone()).collect();
        assert_eq!(
            captured.len(),
            2,
            "fanout must produce N-1 envelopes for an N-member roster",
        );
        assert!(recipients.contains(&peer1));
        assert!(recipients.contains(&peer2));
        assert!(
            !recipients.contains(&local_hex),
            "self must be excluded from fanout",
        );
    }

    #[tokio::test]
    async fn send_private_group_refuses_when_roster_contains_denylisted_member() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer_clean = "b".repeat(64);
        let peer_blocked = "c".repeat(64);

        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_hex, "state": "active"},
                    {"agent_id": peer_clean, "state": "active"},
                    {"agent_id": peer_blocked, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let denylist: Arc<dyn crate::denylist::DenylistCheck> =
            Arc::new(crate::denylist::tests::StaticDenylist::new([
                peer_blocked.clone()
            ]));
        let endpoint = Endpoint::new_with_denylist(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
            Some(&denylist),
            None,
        );

        let err = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Denied { ref agent_id_hex } if agent_id_hex == &peer_blocked),
            "expected Denied(peer_blocked), got {err:?}",
        );
        assert!(
            captured.lock().unwrap().is_empty(),
            "refused send must not fan out ANY envelopes — even to non-blocked members",
        );
    }

    /// Per-recipient failure-injection transport: records every
    /// recipient (matching the success case) and returns Err for the
    /// recipient hexes named in `fail_for`. Drives the partial-
    /// delivery semantics test without touching the real router /
    /// network.
    struct SelectiveFailureTransport {
        captured: CapturedSends,
        fail_for: std::collections::HashSet<String>,
    }

    impl SelectiveFailureTransport {
        fn new(fail_for: std::collections::HashSet<String>) -> (Arc<Self>, CapturedSends) {
            let captured: CapturedSends = Arc::new(StdMutex::new(Vec::new()));
            (
                Arc::new(Self {
                    captured: captured.clone(),
                    fail_for,
                }),
                captured,
            )
        }
    }

    #[async_trait]
    impl Transport for SelectiveFailureTransport {
        fn name(&self) -> &'static str {
            "selective-fail"
        }
        fn reachability(&self, _: &AgentId) -> Reachability {
            Reachability::Always
        }
        async fn send(
            &self,
            to: &AgentId,
            envelope: TransportOutbound,
            _: Option<&crate::card::RendezvousHintsV1>,
        ) -> Result<SendReceipt> {
            if let Some(t) = envelope.transit {
                self.captured.lock().unwrap().push((to.clone(), t));
            }
            if self.fail_for.contains(&to.0) {
                return Err(ChatError::MessageTransport(format!(
                    "synthetic failure for {}",
                    &to.0[..8]
                )));
            }
            Ok(SendReceipt {
                accepted_at_ms: 1,
                message_id: Some("captured-msg-id".to_owned()),
                transport_name: "selective-fail",
            })
        }
        fn take_inbound(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>> {
            None
        }
    }

    #[tokio::test]
    async fn send_private_group_partial_delivery_returns_ok_and_logs_failures() {
        // P2 from Bob's review: per-recipient `?` short-circuit hid
        // partial success. Mock 3 active members, fail member 2,
        // succeed members 1 + 3. Assert send returns Ok, the
        // capturing transport saw all 3 attempts (not just up to the
        // first failure), and stderr carries the failing recipient.
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer1 = "b".repeat(64);
        let peer2 = "c".repeat(64); // <- failure recipient
        let peer3 = "d".repeat(64);

        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_hex, "state": "active"},
                    {"agent_id": peer1, "state": "active"},
                    {"agent_id": peer2, "state": "active"},
                    {"agent_id": peer3, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let mut fail_for = std::collections::HashSet::new();
        fail_for.insert(peer2.clone());
        let (transport, captured) = SelectiveFailureTransport::new(fail_for);
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let msg_id = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .expect("partial success must still return Ok so caller UI shows 'sent'");
        assert!(msg_id.is_some());

        let captured = captured.lock().unwrap();
        let recipients: Vec<String> = captured.iter().map(|(a, _)| a.0.clone()).collect();
        assert_eq!(
            captured.len(),
            3,
            "fanout must attempt ALL non-self recipients even if one fails; \
             saw {recipients:?}",
        );
        assert!(recipients.contains(&peer1));
        assert!(recipients.contains(&peer2));
        assert!(recipients.contains(&peer3));
    }

    #[tokio::test]
    async fn send_private_group_total_failure_returns_first_error() {
        // P2 corollary: when EVERY recipient fails the caller's UI
        // needs to surface "not delivered" rather than the false
        // success that a swallowed-Err Ok would produce. Pick the
        // first per-recipient error verbatim.
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer1 = "b".repeat(64);
        let peer2 = "c".repeat(64);

        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_hex, "state": "active"},
                    {"agent_id": peer1, "state": "active"},
                    {"agent_id": peer2, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let mut fail_for = std::collections::HashSet::new();
        fail_for.insert(peer1.clone());
        fail_for.insert(peer2.clone());
        let (transport, _captured) = SelectiveFailureTransport::new(fail_for);
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ChatError::MessageTransport(ref m) if m.contains("synthetic failure"),
            ),
            "expected MessageTransport(synthetic failure), got {err:?}",
        );
    }

    #[tokio::test]
    async fn send_private_group_self_exclusion_is_case_insensitive() {
        // P1 from Bob's review: roster fanout filtered self with a
        // case-sensitive `==`. `identity.agent_id_hex()` is lowercase
        // by construction, but `AgentId` is `#[serde(transparent)]` so
        // roster entries carry whatever case x0xd emits. If the
        // daemon ever returns mixed/uppercase ids the case-sensitive
        // filter doesn't drop self, and the local fans the envelope
        // back to itself. Targeted fix: `eq_ignore_ascii_case` at the
        // filter site (ASCII-hex case-fold is safe — every byte is
        // 0-9a-fA-F).
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let local_hex_upper = local_hex.to_ascii_uppercase();
        let peer = "b".repeat(64);

        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        // Roster has self in UPPERCASE. With the old `==` filter,
        // self would NOT match and the envelope would fan out to
        // self too — captured.len() would be 2.
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_hex_upper, "state": "active"},
                    {"agent_id": peer, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        let recipients: Vec<String> = captured.iter().map(|(a, _)| a.0.clone()).collect();
        assert_eq!(
            captured.len(),
            1,
            "case-insensitive self-exclusion must drop the mixed-case \
             local; saw recipients {recipients:?}",
        );
        assert_eq!(
            recipients[0], peer,
            "only the peer must receive — self was uppercase but is still self",
        );
    }

    #[tokio::test]
    async fn send_private_group_dedupes_duplicate_roster_entries() {
        // NOTE from Bob's cross-review: `groups::Endpoint::members`
        // returns `Vec<AgentId>` verbatim from x0xd's `/members`
        // response — the wire shape doesn't enforce uniqueness. If
        // the daemon ever emits the same `agent_id` twice (shouldn't,
        // but defensive), the fan-out loop would address the same
        // peer twice: double-delivery on the wire, double-history on
        // the receiver. Dedup case-insensitively before iterating
        // (same case-fold convention as `a3c48dd` self-exclusion).
        //
        // Test shape: roster lists the same peer agent_id twice
        // (once lowercase, once uppercase to also pin the case-fold).
        // Expect exactly one envelope captured for that peer.
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer = "b".repeat(64);
        let peer_upper = peer.to_ascii_uppercase();

        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": local_hex, "state": "active"},
                    {"agent_id": peer, "state": "active"},
                    {"agent_id": peer_upper, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        let recipients: Vec<String> = captured.iter().map(|(a, _)| a.0.clone()).collect();
        assert_eq!(
            captured.len(),
            1,
            "duplicate roster entry must be deduped; saw recipients {recipients:?}",
        );
    }

    #[tokio::test]
    async fn send_private_group_empty_roster_returns_no_envelopes_sent() {
        let server = MockServer::start().await;
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(&server)
            .await;
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": []
            })))
            .mount(&server)
            .await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let rig = build_rig();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let msg_id = endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .unwrap();
        // Empty roster — no transport hops. Still surface a message id
        // so caller UI state-machines have a stable anchor.
        assert!(msg_id.is_some());
        assert!(
            captured.lock().unwrap().is_empty(),
            "0-peer fanout must NOT send any envelope",
        );
    }

    // ---- receive: failure paths ----------------------------------------

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_invalid_signature() {
        let server = MockServer::start().await;
        // Decrypt mount is unnecessary — verify rejects before x0xd
        // is contacted. We don't mount it so a regression that bypasses
        // the verify-first invariant surfaces as a different error.
        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let mut env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 1).await;
        // Mangle the signature so verify fails.
        if let Some(last) = env.sender_signature.last_mut() {
            *last ^= 0x01;
        }

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("envelope signature verify")),
            "expected Invalid(envelope signature verify), got {err:?}",
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_unknown_sender() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        // No card installed — verify can't even start.
        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 1).await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("no card for envelope sender")),
            "expected Invalid(no card), got {err:?}",
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_detects_replay() {
        let server = MockServer::start().await;
        mount_decrypt(&server, b"hi from peer").await;
        let rig = build_rig();
        mount_members_with_self_only(&server, rig.identity.agent_id_hex()).await;
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 100).await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );

        let first = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap();
        assert!(matches!(first, PrivateGroupReceive::Persisted(_)));
        let second = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap();
        assert!(
            matches!(second, PrivateGroupReceive::Replay),
            "second receipt of the same envelope must surface Replay, got {second:?}",
        );
        // History length is 1 — replay must NOT have appended.
        let conv = rig.registry.get(TEST_GROUP_HEX).await.unwrap().unwrap();
        assert_eq!(conv.history.len(), 1);
    }

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_malformed_postcard_ciphertext() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let mut env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 1).await;
        // Replace ciphertext with bytes that won't postcard-decode as
        // EncryptedFrame, then RE-SIGN so the verify-first invariant
        // doesn't bail before the postcard check fires.
        env.ciphertext = b"not-a-valid-postcard-frame".to_vec();
        let canonical = canonical_envelope_bytes(&env).unwrap();
        let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        env.sender_signature = sender_signer.sign(&sign_bytes).await.unwrap();

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("postcard frame")),
            "expected Invalid(postcard frame), got {err:?}",
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_decrypt_4xx() {
        let server = MockServer::start().await;
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"ok":false,"error":"stale epoch"}"#),
            )
            .mount(&server)
            .await;
        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 1).await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::MessageTransport(ref m) if m.contains("403")),
            "expected MessageTransport(403), got {err:?}",
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_non_utf8_plaintext() {
        let server = MockServer::start().await;
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        // Surface bytes that aren't valid UTF-8.
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": B64.encode([0xff_u8, 0xff, 0xff, 0xff]),
            })))
            .mount(&server)
            .await;
        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 1).await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("body utf8")),
            "expected Invalid(body utf8), got {err:?}",
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_pushes_to_conversation_history() {
        let server = MockServer::start().await;
        mount_decrypt(&server, b"hi from peer").await;
        let rig = build_rig();
        mount_members_with_self_only(&server, rig.identity.agent_id_hex()).await;
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 555).await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );

        // Pre-condition: registry has no conversation yet (lazy create).
        assert!(rig.registry.get(TEST_GROUP_HEX).await.unwrap().is_none());
        let out = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap();
        let PrivateGroupReceive::Persisted(entry) = out else {
            panic!("expected Persisted, got {out:?}");
        };
        assert_eq!(entry.body, "hi from peer");
        assert_eq!(entry.sender_agent_id_hex, sender_aid);
        assert_eq!(entry.ts_ms, 555);
        // Conversation was lazily created + the entry was pushed.
        let conv = rig.registry.get(TEST_GROUP_HEX).await.unwrap().unwrap();
        assert_eq!(conv.history.len(), 1);
        assert_eq!(conv.history.back().unwrap().body, "hi from peer");
    }

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_when_not_in_x0xd_roster() {
        // Anti-DoS gate on the lazy-bootstrap path. A paired contact
        // (sender card cached, ML-DSA-65 verify passes upstream) could
        // otherwise spam fake group_id_hex values and force the
        // receiver to bootstrap an unbounded number of Conversation
        // vault entries. x0xd is the source of truth for membership
        // — when its /groups/<id>/members roster excludes our
        // agent_id, we refuse to bootstrap and drop the envelope.
        let server = MockServer::start().await;
        mount_decrypt(&server, b"hi from peer").await;
        let rig = build_rig();
        // Mount a roster that does NOT contain the receiver.
        mount_members_without_self(&server, OTHER_AGENT_HEX).await;
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);
        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 200).await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );

        // Pre-condition: registry has no conversation yet.
        assert!(rig.registry.get(TEST_GROUP_HEX).await.unwrap().is_none());
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        match err {
            ChatError::Invalid(ref m) if m.contains("not a member of group") => {}
            other => panic!("expected Invalid(not a member of group...), got {other:?}"),
        }
        // Post-condition: NO Conversation was created — the gate
        // closed the disk-fill path.
        assert!(
            rig.registry.get(TEST_GROUP_HEX).await.unwrap().is_none(),
            "membership gate must NOT bootstrap a Conversation when rejected",
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_skips_roster_check_when_conversation_exists() {
        // The membership gate is on the LAZY-BOOTSTRAP path only —
        // once a Conversation exists in the registry, subsequent
        // receives use it directly with no roster query. This pins
        // the optimisation: we don't make x0xd round-trips on every
        // group message after the first, and a membership-revocation
        // race (we got kicked between bootstrap and a later receive)
        // doesn't break delivery for already-known groups.
        //
        // Test shape: DELIBERATELY do NOT mount `/groups/<G>/members`.
        // Then pre-seed the registry with a self-only Conversation
        // for TEST_GROUP_HEX. If the receive code path queried
        // members against the server, wiremock would 404 and the
        // call would error out. The success of this test demonstrates
        // the optimisation.
        let server = MockServer::start().await;
        mount_decrypt(&server, b"hi from peer").await;
        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);

        // Pre-seed the registry so the lazy-bootstrap path is NOT
        // exercised. Build a self-only conv the same way the
        // production lazy-bootstrap would and save it.
        let signer_arc = rig.signer_arc();
        let pre_seeded = self_only_private_group_conversation(
            TEST_GROUP_HEX,
            None,
            &rig.identity,
            signer_arc.as_ref(),
        );
        rig.registry.save(&pre_seeded).await.unwrap();

        let env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 999).await;
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );

        let out = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .expect("receive must succeed without a /members mock — gate is bootstrap-only");
        assert!(
            matches!(out, PrivateGroupReceive::Persisted(_)),
            "existing-conv path: expected Persisted, got {out:?}",
        );
        let conv = rig.registry.get(TEST_GROUP_HEX).await.unwrap().unwrap();
        assert_eq!(
            conv.history.len(),
            1,
            "entry persisted into pre-seeded conv"
        );
    }

    #[tokio::test]
    async fn receive_private_group_envelope_rejects_outer_vs_inner_nonce_mismatch() {
        // P1 from Bob's review: the receiver dedupe window keys off
        // `env.nonce` (the outer 12-byte field), but the AEAD-bound
        // nonce that x0xd's `/secure/decrypt` actually uses lives
        // INSIDE the postcard'd `EncryptedFrame.nonce_b64`. An
        // attacker who captured a delivered envelope can mint a new
        // envelope with a fresh-random `env.nonce` while keeping
        // `frame.nonce_b64` unchanged — the per-sender replay window
        // misses, the daemon happily re-decrypts (TreeKEM is
        // stateless within an epoch), and the plaintext re-surfaces.
        // The fix rejects mismatching outer/inner nonces BEFORE the
        // dedup check and BEFORE any x0xd round-trip.
        let server = MockServer::start().await;
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        // `expect(0)`: any /secure/decrypt traffic is a regression —
        // the mismatch check must trip first and short-circuit the
        // receive path entirely.
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let rig = build_rig();
        let sender_signer = MlDsaSigner::generate().unwrap();
        let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
            &sender_signer.public_key(),
        ));
        install_card_for(&rig, &sender_signer, &sender_aid);

        // Build the envelope normally, then swap `env.nonce` for a
        // fresh-random value while leaving the postcard'd
        // EncryptedFrame.nonce_b64 untouched — the wire shape an
        // attacker minting from a captured envelope would produce.
        let mut env = craft_inbound_envelope(&sender_signer, &sender_aid, b"hi", 1).await;
        let mut fresh_outer_nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut fresh_outer_nonce);
        env.nonce = fresh_outer_nonce.to_vec();
        // Re-sign over the canonical bytes so the verify-first
        // invariant doesn't bail before the mismatch check fires.
        let canonical = canonical_envelope_bytes(&env).unwrap();
        let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        env.sender_signature = sender_signer.sign(&sign_bytes).await.unwrap();

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let router = Router::new();
        let signer_arc = rig.signer_arc();
        let endpoint = Endpoint::new(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
        );
        let err = endpoint
            .receive_private_group_envelope(&env, TEST_GROUP_HEX)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ChatError::Invalid(ref m) if m.contains("envelope nonce vs frame nonce mismatch"),
            ),
            "expected Invalid(envelope nonce vs frame nonce mismatch), got {err:?}",
        );
        // History must NOT have grown — the entry was rejected
        // before the mutate path ran.
        assert!(
            rig.registry
                .get(TEST_GROUP_HEX)
                .await
                .unwrap()
                .is_none_or(|c| c.history.is_empty()),
            "rejected envelope must not append to history",
        );
        // wiremock's expect(0) asserts on Mock drop / verify().
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::too_many_lines)] // table-style concurrent fixture; clearer inline than helper-extracted
    async fn receive_private_group_envelope_concurrent_lazy_create_is_atomic() {
        // P0 from Bob's adversarial multi-lens review: two concurrent
        // receives for a brand-new group both observed
        // `registry.get == None`, both called `registry.save(empty)`,
        // and the second save clobbered the first's recorded nonce +
        // history entry. The fix routes the receive path through
        // `ConversationRegistry::mutate_in_place_or_init`, which
        // bootstraps the empty shell UNDER the per-group mutex.
        //
        // Test shape: N distinct senders (so each has a distinct
        // per-sender replay window and the entries genuinely
        // accumulate rather than collapsing into a single replay),
        // each emits one envelope, all five receivers fire in
        // parallel on a multi-thread runtime against a fresh
        // (cache-empty + disk-empty) registry. Post-condition:
        // exactly one Conversation exists in the registry with all
        // N entries in history, and each sender's per-sender
        // sliding window holds exactly one nonce.
        const N: usize = 5;
        let server = MockServer::start().await;
        // The receive path calls /secure/decrypt — return the same
        // plaintext for every call so each envelope decrypts to a
        // distinct body via its distinct ciphertext.
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": B64.encode(b"concurrent receive"),
            })))
            .mount(&server)
            .await;
        let rig = build_rig();
        mount_members_with_self_only(&server, rig.identity.agent_id_hex()).await;

        // Build N independent senders, install N cards, craft N
        // envelopes with distinct nonces+timestamps so dedupe keys
        // differ.
        let mut envelopes = Vec::with_capacity(N);
        for i in 0..N {
            let sender_signer = MlDsaSigner::generate().unwrap();
            let sender_aid = hex::encode(fetchit_relay_proto::derive_agent_id(
                &sender_signer.public_key(),
            ));
            install_card_for(&rig, &sender_signer, &sender_aid);
            // Distinct nonce per envelope — same wire-level shape as
            // x0xd would emit if every encrypt landed under a fresh
            // ratchet step.
            let mut raw_nonce = [0u8; 12];
            raw_nonce[0] = u8::try_from(i + 1).unwrap();
            let frame = EncryptedFrame {
                ciphertext_b64: B64.encode([u8::try_from(i + 1).unwrap()]),
                nonce_b64: Some(B64.encode(raw_nonce)),
                secret_epoch: 9,
                plane: None,
            };
            let frame_bytes = postcard::to_allocvec(&frame).unwrap();
            let mut group_id_bytes = [0u8; 32];
            hex::decode_to_slice(TEST_GROUP_HEX, &mut group_id_bytes).unwrap();
            let mut sender_bytes = [0u8; 32];
            hex::decode_to_slice(&sender_aid, &mut sender_bytes).unwrap();
            let mut env = TransitEnvelope {
                version: WIRE_VERSION,
                kind: EnvelopeKind::PrivateGroupChat,
                group_id: Some(ProtoGroupId::from_bytes(group_id_bytes)),
                tenant_id: None,
                sender_agent_id: ProtoAgentId::from_bytes(sender_bytes),
                sender_machine_id: MachineId::from_bytes([0u8; 32]),
                timestamp_ms: u64::try_from(1_000 + i).unwrap(),
                epoch: 9,
                ciphertext: frame_bytes,
                nonce: raw_nonce.to_vec(),
                kem_ciphertext: Vec::new(),
                sender_signature: Vec::new(),
            };
            let canonical = canonical_envelope_bytes(&env).unwrap();
            let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
            sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
            sign_bytes.extend_from_slice(&canonical);
            env.sender_signature = sender_signer.sign(&sign_bytes).await.unwrap();
            envelopes.push((sender_aid, env));
        }

        // Pre-condition: registry is empty on disk + in memory.
        assert!(rig.registry.get(TEST_GROUP_HEX).await.unwrap().is_none());

        // Spawn N concurrent receives. Each task takes owned clones
        // of the rig's Arc-shaped state, builds its own Endpoint
        // referencing those local Arcs, and rendezvouses at a barrier
        // before entering the receive path — without the barrier
        // serial spawn overhead can let task 0 finish its lazy
        // bootstrap before task 1 even starts, and the race window
        // collapses.
        let server_uri = server.uri();
        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut handles = Vec::with_capacity(N);
        for (_sender_aid, env) in &envelopes {
            let env = env.clone();
            let identity = rig.identity.clone();
            let registry = rig.registry.clone();
            let signer_arc: Arc<dyn Signer> = rig.signer.clone();
            let layout = rig.layout.clone();
            let server_uri = server_uri.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let http = Http::new(server_uri, "tok".to_owned()).unwrap();
                let router = Router::new();
                let endpoint = Endpoint::new(
                    &http,
                    &router,
                    Some(&identity),
                    Some(&registry),
                    Some(&signer_arc),
                    Some(&layout),
                    [0u8; 32],
                    None,
                );
                barrier.wait().await;
                endpoint
                    .receive_private_group_envelope(&env, TEST_GROUP_HEX)
                    .await
            }));
        }

        let mut persisted = 0usize;
        for h in handles {
            let outcome = h.await.unwrap().unwrap();
            if matches!(outcome, PrivateGroupReceive::Persisted(_)) {
                persisted += 1;
            }
        }
        assert_eq!(
            persisted, N,
            "all {N} distinct envelopes must surface Persisted, got {persisted}",
        );

        // Post-condition: exactly one conversation in the registry
        // carrying all N history entries and N independent per-sender
        // replay-window entries.
        let conv = rig.registry.get(TEST_GROUP_HEX).await.unwrap().unwrap();
        assert_eq!(
            conv.history.len(),
            N,
            "history must hold one entry per concurrent receive — \
             a TOCTOU clobber would lose entries here",
        );
        assert_eq!(
            conv.seen_nonces.len(),
            N,
            "each distinct sender must own a sliding window — \
             a clobber would have collapsed per-sender state",
        );
        for (sender_aid, _env) in &envelopes {
            let window = conv
                .seen_nonces
                .get(sender_aid)
                .expect("per-sender window must exist for every sender");
            assert_eq!(
                window.len(),
                1,
                "exactly one recorded nonce per sender — duplicates \
                 indicate the dedup ran on a stale clone",
            );
        }
    }

    // ---- Round-trip integration ----------------------------------------

    /// Wiremock that echoes the input plaintext from /secure/encrypt
    /// directly back as the /secure/decrypt payload — wires the loop so
    /// `send_private_group` + `receive_private_group_envelope` can be
    /// composed end-to-end against a single `MockServer`.
    async fn mount_echo_encrypt_decrypt(server: &MockServer, plaintext_b64: &str) {
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "MTIzNDU2Nzg5MGFi",
                "secret_epoch": 5,
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": plaintext_b64,
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn send_then_receive_private_group_roundtrip() {
        // Alice rig sends; the wire envelope is captured. Bob rig
        // receives the captured envelope against the SAME mock server
        // (it both encrypts and decrypts). Asserting the HistoryEntry
        // body matches the input proves the wire is healable end-to-end.
        let server = MockServer::start().await;
        let alice_rig = build_rig();
        let bob_rig = build_rig();

        // Alice fans out to Bob.
        let alice_hex = alice_rig.agent_hex().to_owned();
        let bob_hex = bob_rig.agent_hex().to_owned();
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": alice_hex, "state": "active"},
                    {"agent_id": bob_hex, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;
        mount_echo_encrypt_decrypt(&server, &B64.encode(b"hello bob")).await;

        // Wire Alice up to send.
        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let alice_signer_arc = alice_rig.signer_arc();
        let alice_endpoint = Endpoint::new(
            &http,
            &router,
            Some(&alice_rig.identity),
            Some(&alice_rig.registry),
            Some(&alice_signer_arc),
            Some(&alice_rig.layout),
            [0u8; 32],
            None,
        );
        alice_endpoint
            .send_private_group(TEST_GROUP_HEX, "hello bob", "Alice")
            .await
            .unwrap();

        // Drop the guard before the next await so clippy's
        // await_holding_lock check is satisfied.
        let (recipient, envelope) = {
            let guard = captured.lock().unwrap();
            assert_eq!(guard.len(), 1);
            guard[0].clone()
        };
        assert_eq!(recipient.0, bob_hex);
        assert!(is_private_group_envelope(&envelope));

        // Bob needs Alice's card on file for the receive verify.
        install_card_for(&bob_rig, &alice_rig.signer, &alice_hex);

        // Bob receives. Re-use the same MockServer so the decrypt mock
        // is hit by the receive path.
        let bob_router = Router::new();
        let bob_signer_arc = bob_rig.signer_arc();
        let bob_endpoint = Endpoint::new(
            &http,
            &bob_router,
            Some(&bob_rig.identity),
            Some(&bob_rig.registry),
            Some(&bob_signer_arc),
            Some(&bob_rig.layout),
            [0u8; 32],
            None,
        );
        let out = bob_endpoint
            .receive_private_group_envelope(&envelope, TEST_GROUP_HEX)
            .await
            .unwrap();
        let PrivateGroupReceive::Persisted(entry) = out else {
            panic!("expected Persisted, got {out:?}");
        };
        assert_eq!(entry.body, "hello bob");
        assert_eq!(entry.sender_agent_id_hex, alice_hex);
    }

    /// Mount the v0.21.3 `TreeKEM` shape on `/secure/encrypt` +
    /// `/secure/decrypt`: response carries `secure_plane: "treekem"` and
    /// (encrypt) NO `nonce_b64` field, since the nonce is baked into
    /// the `ApplicationCiphertext` returned in `ciphertext_b64`.
    async fn mount_echo_treekem_encrypt_decrypt(server: &MockServer, plaintext_b64: &str) {
        let encrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/encrypt");
        let decrypt_path = format!("/groups/{TEST_GROUP_HEX}/secure/decrypt");
        Mock::given(method("POST"))
            .and(path(&encrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "QXBwbGljYXRpb25DaXBoZXJ0ZXh0Qmxvbg==",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(&decrypt_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": plaintext_b64,
                "secret_epoch": 7,
                "secure_plane": "treekem",
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn send_then_receive_private_group_roundtrip_treekem() {
        // v0.21.3 wire shape: the daemon's TreeKEM encrypt response
        // omits `nonce_b64` and tags `secure_plane: "treekem"`. The
        // wire-level `env.nonce` is therefore derived from the
        // ciphertext bytes (see `derive_treekem_outer_nonce`). End-to-end
        // round-trip locks in: encrypt parses cleanly, build_envelope
        // populates `env.nonce` from the derivation, the receiver
        // re-derives the same value, the inner/outer cross-check passes,
        // and the decrypt POST omits `nonce_b64`.
        let server = MockServer::start().await;
        let alice_rig = build_rig();
        let bob_rig = build_rig();
        let alice_hex = alice_rig.agent_hex().to_owned();
        let bob_hex = bob_rig.agent_hex().to_owned();
        let members_path = format!("/groups/{TEST_GROUP_HEX}/members");
        Mock::given(method("GET"))
            .and(path(&members_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "members": [
                    {"agent_id": alice_hex, "state": "active"},
                    {"agent_id": bob_hex, "state": "active"},
                ]
            })))
            .mount(&server)
            .await;
        mount_echo_treekem_encrypt_decrypt(&server, &B64.encode(b"pq hello")).await;

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = ManyCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let alice_signer_arc = alice_rig.signer_arc();
        let alice_endpoint = Endpoint::new(
            &http,
            &router,
            Some(&alice_rig.identity),
            Some(&alice_rig.registry),
            Some(&alice_signer_arc),
            Some(&alice_rig.layout),
            [0u8; 32],
            None,
        );
        alice_endpoint
            .send_private_group(TEST_GROUP_HEX, "pq hello", "Alice")
            .await
            .unwrap();

        let (recipient, envelope) = {
            let guard = captured.lock().unwrap();
            assert_eq!(guard.len(), 1);
            guard[0].clone()
        };
        assert_eq!(recipient.0, bob_hex);
        assert!(is_private_group_envelope(&envelope));

        // Wire-format invariants for the TreeKEM path: the postcard'd
        // frame inside the envelope carries `plane: Some("treekem")` and
        // `nonce_b64: None`; `env.nonce` is the deterministic 12-byte
        // derivation of `frame.ciphertext_b64` so the receiver can
        // verify the inner/outer binding without a separate nonce.
        let frame: EncryptedFrame = postcard::from_bytes(&envelope.ciphertext).unwrap();
        assert!(frame.is_treekem(), "frame must tag plane=treekem");
        assert!(
            frame.nonce_b64.is_none(),
            "treekem frame must omit nonce_b64"
        );
        assert_eq!(
            envelope.nonce,
            derive_treekem_outer_nonce(&frame.ciphertext_b64),
            "env.nonce must equal derived value for inner/outer cross-check",
        );

        install_card_for(&bob_rig, &alice_rig.signer, &alice_hex);
        let bob_router = Router::new();
        let bob_signer_arc = bob_rig.signer_arc();
        let bob_endpoint = Endpoint::new(
            &http,
            &bob_router,
            Some(&bob_rig.identity),
            Some(&bob_rig.registry),
            Some(&bob_signer_arc),
            Some(&bob_rig.layout),
            [0u8; 32],
            None,
        );
        let out = bob_endpoint
            .receive_private_group_envelope(&envelope, TEST_GROUP_HEX)
            .await
            .unwrap();
        let PrivateGroupReceive::Persisted(entry) = out else {
            panic!("expected Persisted, got {out:?}");
        };
        assert_eq!(entry.body, "pq hello");
        assert_eq!(entry.sender_agent_id_hex, alice_hex);

        // Lock in the decrypt-request shape: TreeKEM decrypt POST must
        // omit `nonce_b64`. A future regression that reintroduces the
        // legacy field would still pass wiremock's partial-match, so
        // re-inspect the captured request body explicitly.
        let received = server.received_requests().await.unwrap();
        let decrypt = received
            .iter()
            .find(|r| r.url.path().ends_with("/secure/decrypt"))
            .expect("decrypt request captured");
        let body: serde_json::Value = serde_json::from_slice(&decrypt.body).unwrap();
        assert!(
            body.get("nonce_b64").is_none(),
            "treekem decrypt request must not carry nonce_b64: {body}",
        );
    }

    // ---- Routing predicate (table-driven) ------------------------------

    fn synth_env(kind: EnvelopeKind, kem_ct: Vec<u8>) -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind,
            group_id: Some(ProtoGroupId::from_bytes([0u8; 32])),
            tenant_id: None,
            sender_agent_id: ProtoAgentId::from_bytes([0u8; 32]),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 0,
            epoch: 0,
            ciphertext: Vec::new(),
            nonce: vec![0u8; 12],
            kem_ciphertext: kem_ct,
            sender_signature: Vec::new(),
        }
    }

    #[test]
    fn is_private_group_envelope_true_when_private_group_chat_kind() {
        let env = synth_env(EnvelopeKind::PrivateGroupChat, Vec::new());
        assert!(is_private_group_envelope(&env));
    }

    #[test]
    fn is_private_group_envelope_false_when_groupchat_with_kem() {
        // Legacy chat-v2 Welcome envelopes carry ML-KEM-768 in
        // `kem_ciphertext`. They route through `dispatch_inbound`,
        // never through the private-group decoder.
        let env = synth_env(EnvelopeKind::GroupChat, vec![0u8; 1088]);
        assert!(!is_private_group_envelope(&env));
    }

    #[test]
    fn is_private_group_envelope_false_for_legacy_groupchat_with_empty_kem() {
        // Legacy chat-v2 DM/group Message envelopes use kind=GroupChat
        // with empty `kem_ciphertext` (the ML-KEM-768 payload only
        // travels on Welcome; subsequent Messages don't carry it).
        // The old predicate `kind == GroupChat && kem.is_empty()` was
        // AMBIGUOUS — it matched these too and shoved an AEAD-sealed
        // MessagePayload into the postcard-EncryptedFrame decoder.
        // The new discriminator (kind == PrivateGroupChat) is
        // unambiguous: this case must reject.
        let env = synth_env(EnvelopeKind::GroupChat, Vec::new());
        assert!(
            !is_private_group_envelope(&env),
            "legacy chat-v2 Message shape (GroupChat + empty kem) must NOT match private-group predicate",
        );
    }

    #[test]
    fn is_private_group_envelope_false_when_dm() {
        let env = synth_env(EnvelopeKind::Dm, Vec::new());
        assert!(!is_private_group_envelope(&env));
    }

    #[test]
    fn is_private_group_envelope_false_when_delivery_receipt() {
        let env = synth_env(EnvelopeKind::DeliveryReceipt, Vec::new());
        assert!(!is_private_group_envelope(&env));
    }

    #[test]
    fn is_private_group_envelope_false_when_admin_event() {
        let env = synth_env(EnvelopeKind::AdminEvent, Vec::new());
        assert!(!is_private_group_envelope(&env));
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

    // ---- R-tail-5 ------------------------------------------------------

    /// M3 R-tail-5: [`StoredContactCard::from_share_uri`] lifts the
    /// `fetchit_rendezvous_hints` slot off a v2 share URI into the
    /// in-memory [`StoredContactCard::rendezvous_hints`] field, and
    /// [`StoredContactCard::resolve_recipient_hints`] surfaces it
    /// back through the layout/disk lookup. The fanout sites consume
    /// this exact path on every `Router::send` to pick a slot.
    #[tokio::test]
    async fn resolve_recipient_hints_round_trips_v2_card() {
        use crate::card::RendezvousHintsV1;
        use crate::local_store::StoreLayout;
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let hints = RendezvousHintsV1 {
            relays: vec!["wss://nyc.test/v1/ws".to_owned()],
        };
        let aid_hex = "0".repeat(64);
        let card = StoredContactCard {
            agent_id_hex: aid_hex.clone(),
            display_name: "Peer".into(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: None,
            rendezvous_hints: Some(hints.clone()),
        };
        card.save(&layout).unwrap();

        let got = StoredContactCard::resolve_recipient_hints(&layout, &aid_hex)
            .unwrap()
            .expect("hints round-trip via disk");
        assert_eq!(got.relays, hints.relays);
    }

    /// Legacy v1 card has no hints slot — resolver returns None.
    /// The send-path fallback then synthesizes the local primary URL
    /// before calling `MultiHomeTransport`.
    #[tokio::test]
    async fn resolve_recipient_hints_legacy_v1_card_returns_none() {
        use crate::local_store::StoreLayout;
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let aid_hex = "1".repeat(64);
        let card = StoredContactCard {
            agent_id_hex: aid_hex.clone(),
            display_name: "LegacyPeer".into(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: None,
            rendezvous_hints: None,
        };
        card.save(&layout).unwrap();

        let got = StoredContactCard::resolve_recipient_hints(&layout, &aid_hex).unwrap();
        assert!(
            got.is_none(),
            "legacy v1 card resolves to None so caller can synthesize primary fallback",
        );
    }

    /// R-tail-5 fallback wrapper: legacy v1 card synthesises a
    /// `RendezvousHintsV1 { relays: [primary] }` so
    /// [`crate::transport::MultiHomeTransport`] always sees
    /// `Some(hints)` and can be strict-on-None at the wire boundary.
    #[tokio::test]
    async fn resolve_recipient_hints_or_fallback_synthesizes_primary_for_v1_card() {
        use crate::local_store::StoreLayout;
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let aid_hex = "2".repeat(64);
        let card = StoredContactCard {
            agent_id_hex: aid_hex.clone(),
            display_name: "LegacyPeer".into(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: None,
            rendezvous_hints: None,
        };
        card.save(&layout).unwrap();

        let primary = "wss://primary.test/v1/ws";
        let got =
            StoredContactCard::resolve_recipient_hints_or_fallback(&layout, &aid_hex, primary)
                .unwrap();
        assert_eq!(got.relays, vec![primary.to_owned()]);
    }

    /// `HintCapturingTransport`: records the hints handed to its
    /// `send` so the send-path tests can assert what the fanout
    /// loop computed per recipient.
    struct HintCapturingTransport {
        last_hints: Arc<StdMutex<Option<crate::card::RendezvousHintsV1>>>,
    }

    impl HintCapturingTransport {
        fn new() -> (
            Arc<Self>,
            Arc<StdMutex<Option<crate::card::RendezvousHintsV1>>>,
        ) {
            let captured = Arc::new(StdMutex::new(None));
            (
                Arc::new(Self {
                    last_hints: captured.clone(),
                }),
                captured,
            )
        }
    }

    #[async_trait]
    impl Transport for HintCapturingTransport {
        fn name(&self) -> &'static str {
            "hint-capture"
        }
        fn reachability(&self, _: &AgentId) -> Reachability {
            Reachability::Always
        }
        async fn send(
            &self,
            _: &AgentId,
            _: TransportOutbound,
            hints: Option<&crate::card::RendezvousHintsV1>,
        ) -> Result<SendReceipt> {
            *self.last_hints.lock().unwrap() = hints.cloned();
            Ok(SendReceipt {
                accepted_at_ms: 1,
                message_id: Some("captured".into()),
                transport_name: "hint-capture",
            })
        }
        fn take_inbound(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<InboundEnvelope>> {
            None
        }
    }

    /// R-tail-5: a private-group fanout to a peer whose stored card
    /// carries v2 hints forwards those hints verbatim to the Router.
    /// This is the load-bearing assertion that proves the multi-home
    /// routing reach is live: a contact card with v2 hints to
    /// `wss://A` causes the transport surface to see
    /// `Some(relays=[wss://A])` on send.
    #[tokio::test]
    async fn send_private_group_threads_v2_hints_to_router() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer_hex = "b".repeat(64);
        mount_encrypt_and_two_member_roster(&server, &local_hex, &peer_hex).await;

        // Peer's card advertises a v2 hint to wss://nyc.test/v1/ws —
        // this is what MultiHomeTransport will route by.
        let advertised = "wss://nyc.test/v1/ws";
        let peer_card = StoredContactCard {
            agent_id_hex: peer_hex.clone(),
            display_name: "Peer".into(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: None,
            rendezvous_hints: Some(crate::card::RendezvousHintsV1 {
                relays: vec![advertised.to_owned()],
            }),
        };
        peer_card.save(&rig.layout).unwrap();

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = HintCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let primary = "wss://primary.test/v1/ws";
        let endpoint = Endpoint::new_with_denylist(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
            None,
            Some(primary),
        );
        endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .expect("fanout succeeds");

        let got = captured.lock().unwrap().clone().expect("hints captured");
        assert_eq!(
            got.relays,
            vec![advertised.to_owned()],
            "v2 hints from peer's card must reach Router::send verbatim",
        );
    }

    /// R-tail-5 fallback: legacy v1 contact (no hints on card) →
    /// fanout synthesizes the local primary URL and passes that
    /// through as `Some(hints)`. Keeps the strict-on-None contract at
    /// the transport surface honest while preserving the legacy wire
    /// path.
    #[tokio::test]
    async fn send_private_group_falls_back_to_primary_when_recipient_card_lacks_v2_hints() {
        let server = MockServer::start().await;
        let rig = build_rig();
        let local_hex = rig.agent_hex().to_owned();
        let peer_hex = "c".repeat(64);
        mount_encrypt_and_two_member_roster(&server, &local_hex, &peer_hex).await;

        // Peer's card is legacy v1: no `rendezvous_hints`. The
        // send-path's fallback synthesis must kick in.
        let peer_card = StoredContactCard {
            agent_id_hex: peer_hex.clone(),
            display_name: "LegacyPeer".into(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: None,
            rendezvous_hints: None,
        };
        peer_card.save(&rig.layout).unwrap();

        let http = Http::new(server.uri(), "tok".to_owned()).unwrap();
        let (transport, captured) = HintCapturingTransport::new();
        let mut router = Router::new();
        router.add(transport);
        let signer_arc = rig.signer_arc();
        let primary = "wss://primary.test/v1/ws";
        let endpoint = Endpoint::new_with_denylist(
            &http,
            &router,
            Some(&rig.identity),
            Some(&rig.registry),
            Some(&signer_arc),
            Some(&rig.layout),
            [0u8; 32],
            None,
            None,
            Some(primary),
        );
        endpoint
            .send_private_group(TEST_GROUP_HEX, "hi", "A")
            .await
            .expect("fanout succeeds");

        let got = captured.lock().unwrap().clone().expect("hints captured");
        assert_eq!(
            got.relays,
            vec![primary.to_owned()],
            "v1 card + primary URL must synthesize fallback hints",
        );
    }
}
