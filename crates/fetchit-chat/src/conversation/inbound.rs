//! Inbound envelope dispatch: distinguish Welcome vs Message, decrypt,
//! and surface a typed result.

use super::registry::{ConversationRegistry, MutateAction, NonceCheckOutcome};
use super::types::{
    now_ms, Conversation, DeliveryReceiptPayload, MessagePayload, PriorKey, TrustState,
    WelcomePayload, PRIOR_KEY_WINDOW_MS,
};
use crate::chat_crypto::{
    aead_open, canonical_envelope_bytes, derive_aead_key, kem_decapsulate, message_aad,
    ml_dsa_verify, AEAD_KEY_LEN, KDF_INFO_WELCOME, SIGN_DOMAIN_ENVELOPE,
};
use crate::chat_identity::FetchitIdentity;
use crate::error::ChatError;
use crate::local_store::write_json_atomic;
use crate::messages::StoredContactCard;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_proto::{derive_agent_id, EnvelopeKind, TransitEnvelope};

/// Inbound dispatch result.
#[derive(Clone, Debug)]
pub enum InboundDispatch {
    /// Installed a new conversation from a welcome whose sender was
    /// already on file (Confirmed trust posture).
    Welcomed {
        /// The freshly installed conversation.
        conversation: Conversation,
    },
    /// Installed a new conversation from an unsolicited TOFU welcome.
    /// The sender's card was auto-installed from the self-attested
    /// pubkey in the payload. UI should prompt the user to accept the
    /// contact before the conversation becomes `Confirmed`.
    WelcomedPending {
        /// The freshly installed (Pending-trust) conversation.
        conversation: Conversation,
    },
    /// Stale or duplicate welcome — no state change.
    WelcomeIgnored,
    /// Updated an existing conversation (welcome carrying a higher epoch).
    Rekeyed {
        /// The updated conversation.
        conversation: Conversation,
    },
    /// Decrypted a chat message.
    Message {
        /// Hex group id.
        group_id_hex: String,
        /// Hex sender agent id.
        sender_agent_id_hex: String,
        /// Decoded payload.
        payload: MessagePayload,
    },
    /// Decrypted a delivery receipt for a previously-sent message.
    Receipt {
        /// Hex group id.
        group_id_hex: String,
        /// Hex sender agent id (the *receiver* of the original message
        /// — they are confirming decode).
        sender_agent_id_hex: String,
        /// Hex-encoded dedupe key of the original message envelope.
        message_id: String,
        /// Recipient-asserted decode timestamp, milliseconds since
        /// the Unix epoch.
        received_at_ms: u64,
    },
    /// Stale epoch — dropped.
    StaleEpoch {
        /// Hex group id.
        group_id_hex: String,
        /// The envelope epoch.
        epoch: u32,
    },
    /// KEM decap failed (likely encrypted to a different KEM key).
    KemDecapFailed,
    /// AEAD open failed (likely tampered or wrong key).
    AeadOpenFailed {
        /// Hex group id.
        group_id_hex: String,
        /// The envelope epoch.
        epoch: u32,
    },
    /// Replay detected — the `(sender, nonce)` pair is in the
    /// conversation's sliding window. Dropped without AEAD-open; no
    /// state change beyond the no-op window touch.
    ReplayDetected {
        /// Hex group id.
        group_id_hex: String,
        /// Hex sender agent id.
        sender_agent_id_hex: String,
    },
    /// Envelope dropped without decryption. `kind` is one of:
    /// `"no-card"` (sender's card isn't on file — message path only),
    /// `"no-pubkey"` (card exists but doesn't carry an ML-DSA pubkey —
    /// message path only),
    /// `"bad-signature"` (signature verification failed),
    /// `"rekey-from-non-member"` (signature was valid but the sender
    /// isn't a current member of the conversation they're trying to
    /// rekey),
    /// `"welcome-sender-not-member"` (welcome payload omits the
    /// envelope's `sender_agent_id` from `members`),
    /// `"welcome-missing-sender-pubkey"` (welcome's sender device
    /// record lacks the self-attested ML-DSA pubkey),
    /// `"welcome-pubkey-agent-mismatch"` (the welcome's claimed sender
    /// pubkey does not hash to the envelope's `sender_agent_id`).
    Dropped {
        /// Short reason tag.
        kind: String,
        /// Hex-encoded sender agent id from the envelope.
        sender: String,
    },
}

/// Whether a dispatch outcome is TERMINAL for the envelope that produced
/// it — its effects are durably applied (vault persisted), it is a
/// provable duplicate, or no future redelivery could ever process it
/// differently — so a transport-held stored copy may be reclaimed
/// ([`crate::transport::DeliveryAck::confirm`]).
///
/// Returns `false` for outcomes a later redelivery can genuinely
/// improve, which must leave the stored copy in place:
/// - [`InboundDispatch::StaleEpoch`] — the headline case: the frame
///   becomes decryptable after a re-key / epoch catch-up, and the
///   relay's redelivery is what fills the gap.
/// - [`InboundDispatch::KemDecapFailed`] — encrypted to a different KEM
///   key; a device/pair update can make a redelivery decryptable.
/// - [`InboundDispatch::Dropped`] with `"no-card"` / `"no-pubkey"` —
///   the sender's card can arrive or gain its pubkey before the TTL.
///
/// Everything else confirms: persisted messages/receipts/rekeys/welcomes,
/// duplicates, tampered frames (`AeadOpenFailed` — corrupt bytes never
/// improve), and signature/membership rejections (deterministic verdicts
/// on immutable bytes).
#[must_use]
pub fn confirms_delivery(dispatch: &InboundDispatch) -> bool {
    match dispatch {
        InboundDispatch::Welcomed { .. }
        | InboundDispatch::WelcomedPending { .. }
        | InboundDispatch::WelcomeIgnored
        | InboundDispatch::Rekeyed { .. }
        | InboundDispatch::Message { .. }
        | InboundDispatch::Receipt { .. }
        | InboundDispatch::AeadOpenFailed { .. }
        | InboundDispatch::ReplayDetected { .. } => true,
        InboundDispatch::StaleEpoch { .. } | InboundDispatch::KemDecapFailed => false,
        InboundDispatch::Dropped { kind, .. } => !matches!(kind.as_str(), "no-card" | "no-pubkey"),
    }
}

/// Outcome of the verify prelude: either an early `Dropped` result, or
/// a green light that the message-path dispatcher can proceed.
#[allow(clippy::large_enum_variant)] // InboundDispatch contains Conversation; boxing here would force every call site to dereference.
enum VerifyOutcome {
    Drop(InboundDispatch),
    Ok,
}

/// Look up the sender's stored card and verify the envelope's ML-DSA
/// signature against the agent's public key. Runs BEFORE the message
/// path's AEAD open so unauthenticated envelopes can't surface fake
/// messages. The welcome path runs its own pubkey-bound verification
/// from the self-attested payload pubkey instead.
fn verify_sender(
    envelope: &TransitEnvelope,
    registry: &ConversationRegistry,
) -> Result<VerifyOutcome, ChatError> {
    let sender_agent_hex = hex::encode(envelope.sender_agent_id.as_bytes());
    let card_path = registry.contact_path(&sender_agent_hex);
    if !card_path.exists() {
        return Ok(VerifyOutcome::Drop(InboundDispatch::Dropped {
            kind: "no-card".to_owned(),
            sender: sender_agent_hex,
        }));
    }
    let card_bytes = std::fs::read(&card_path)
        .map_err(|e| ChatError::Invalid(format!("read card {}: {e}", card_path.display())))?;
    let stored: crate::messages::StoredContactCard = serde_json::from_slice(&card_bytes)
        .map_err(|e| ChatError::Invalid(format!("stored card parse: {e}")))?;
    let Some(agent_pk_b64) = stored.agent_public_key_b64.as_deref() else {
        return Ok(VerifyOutcome::Drop(InboundDispatch::Dropped {
            kind: "no-pubkey".to_owned(),
            sender: sender_agent_hex,
        }));
    };
    let agent_pub = B64
        .decode(agent_pk_b64)
        .map_err(|e| ChatError::Invalid(format!("card agent_public_key_b64: {e}")))?;
    let canonical = canonical_envelope_bytes(envelope)?;
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
    sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
    sign_bytes.extend_from_slice(&canonical);
    if ml_dsa_verify(&agent_pub, &sign_bytes, &envelope.sender_signature).is_err() {
        return Ok(VerifyOutcome::Drop(InboundDispatch::Dropped {
            kind: "bad-signature".to_owned(),
            sender: sender_agent_hex,
        }));
    }
    Ok(VerifyOutcome::Ok)
}

/// Dispatch an inbound envelope: distinguish Welcome vs Message,
/// decrypt, and surface a typed result.
///
/// The Message path requires a `StoredContactCard` for the sender on
/// disk (the welcome is what installs it). The Welcome path decrypts
/// first using our own KEM secret key, then extracts the sender's
/// self-attested ML-DSA pubkey from the payload, binds it to the
/// envelope's `sender_agent_id` via the `AUTONOMI_PEER_ID_V2`
/// derivation, and only then verifies the envelope signature — closing
/// the chicken-and-egg first-contact gap.
///
/// # Errors
/// Hard errors (e.g. malformed envelope bytes). Soft errors (stale
/// epoch, decap fail) are returned as `InboundDispatch` variants.
/// 3-arg convenience entry: dispatch with no outbox wiring (a delivery
/// receipt is still verified + persisted to conversation history, but no
/// outbound bubble is flipped to Delivered). Kept for the test suite + the
/// chat-peer binary; the production dispatcher calls
/// [`dispatch_inbound_with_outbox`] so the sender's outbox reflects delivery.
pub async fn dispatch_inbound(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
) -> Result<InboundDispatch, ChatError> {
    dispatch_inbound_with_outbox(envelope, identity, registry, None, None).await
}

/// Inbound dispatch with optional outbox wiring. When `outbox` +
/// `outbox_events` are supplied and the envelope is a `DeliveryReceipt`, the
/// matching outbound bubble (by `message_id`) is marked Delivered and an
/// [`crate::outbox::OutboxEvent`] is broadcast -- engine-side so every shell
/// (desktop + Android) inherits Delivered without threading receipts through
/// the UI layer (see the outbox-lift design).
pub async fn dispatch_inbound_with_outbox(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
    outbox: Option<&std::sync::Arc<tokio::sync::Mutex<crate::outbox::store::OutboxStore>>>,
    outbox_events: Option<&tokio::sync::broadcast::Sender<crate::outbox::OutboxEvent>>,
) -> Result<InboundDispatch, ChatError> {
    let group_id_bytes = match &envelope.group_id {
        Some(g) => *g.as_bytes(),
        None => return Err(ChatError::Invalid("envelope has no group_id".into())),
    };
    let group_id_hex = hex::encode(group_id_bytes);

    match envelope.kind {
        EnvelopeKind::DeliveryReceipt => match verify_sender(&envelope, registry)? {
            VerifyOutcome::Drop(d) => Ok(d),
            VerifyOutcome::Ok => {
                dispatch_receipt(
                    envelope,
                    registry,
                    group_id_bytes,
                    group_id_hex,
                    outbox,
                    outbox_events,
                )
                .await
            }
        },
        _ => {
            if envelope.kem_ciphertext.is_empty() {
                match verify_sender(&envelope, registry)? {
                    VerifyOutcome::Drop(d) => Ok(d),
                    VerifyOutcome::Ok => {
                        dispatch_message(envelope, registry, group_id_bytes, group_id_hex).await
                    }
                }
            } else {
                dispatch_welcome(envelope, identity, registry, group_id_bytes, group_id_hex).await
            }
        }
    }
}

async fn dispatch_receipt(
    envelope: TransitEnvelope,
    registry: &ConversationRegistry,
    group_id_bytes: [u8; 32],
    group_id_hex: String,
    outbox: Option<&std::sync::Arc<tokio::sync::Mutex<crate::outbox::store::OutboxStore>>>,
    outbox_events: Option<&tokio::sync::broadcast::Sender<crate::outbox::OutboxEvent>>,
) -> Result<InboundDispatch, ChatError> {
    let Some(conv) = registry.get(&group_id_hex).await? else {
        return Ok(InboundDispatch::StaleEpoch {
            group_id_hex,
            epoch: envelope.epoch,
        });
    };
    let Some(key) = conv.key_for_epoch(envelope.epoch)? else {
        return Ok(InboundDispatch::StaleEpoch {
            group_id_hex,
            epoch: envelope.epoch,
        });
    };
    if envelope.nonce.len() != 12 {
        return Err(ChatError::Invalid("nonce length".into()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&envelope.nonce);
    let sender_hex = hex::encode(envelope.sender_agent_id.as_bytes());
    // Replay-protection (spec §7). The atomic registry.record_nonce
    // call holds the by-group_id mutex across the check + persist so
    // a concurrent inbound pump (relay + LAN run side-by-side) can't
    // race past an empty window. Recording before AEAD-open also
    // means a crafted-shape replay can't keep retrying the same
    // nonce; the relay TLS + KEM/AEAD end-to-end bound the DoS
    // surface that a wire observer could otherwise exploit by
    // burning legitimate nonces.
    match registry
        .record_nonce(&group_id_hex, &sender_hex, nonce)
        .await?
    {
        NonceCheckOutcome::Replay => {
            return Ok(InboundDispatch::ReplayDetected {
                group_id_hex,
                sender_agent_id_hex: sender_hex,
            });
        }
        NonceCheckOutcome::Recorded => {}
    }
    let aad = message_aad(&group_id_bytes, envelope.epoch);
    let Ok(plaintext) = aead_open(&key, &nonce, &envelope.ciphertext, &aad) else {
        return Ok(InboundDispatch::AeadOpenFailed {
            group_id_hex,
            epoch: envelope.epoch,
        });
    };
    let payload: DeliveryReceiptPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("receipt payload parse: {e}")))?;
    // Persist delivery-state into the conversation history so headless
    // readers and vault reloads see "delivered" without the caller
    // threading receipt events back. Bookkeeping, not security — a
    // persist failure must not eat the receipt event itself.
    if let Err(e) = registry
        .record_delivery(&group_id_hex, &payload.message_id, payload.received_at_ms)
        .await
    {
        log::warn!(
            "[chat] receipt delivery-state persist failed for {}: {e}",
            payload.message_id
        );
    }
    // Outbox lift (T5d): flip the matching outbound bubble to Delivered so
    // the SENDER's UI advances Sending -> Delivered, then broadcast it.
    // Engine-side so every shell (incl. Android via the default dispatcher)
    // inherits Delivered without threading receipts through the UI layer.
    // Match by message_id only -- the globally-unique relay dedupe hex --
    // exactly like desktop markDelivered. A LAN-direct send whose receipt
    // never carries a message_id stays Sending until the 24h sweep, the
    // same as desktop today.
    if let (Some(outbox), Some(events)) = (outbox, outbox_events) {
        if let Some(bubble) = outbox.lock().await.mark_delivered(&payload.message_id) {
            let _ = events.send(crate::outbox::OutboxEvent { bubble });
        }
    }
    Ok(InboundDispatch::Receipt {
        group_id_hex,
        sender_agent_id_hex: sender_hex,
        message_id: payload.message_id,
        received_at_ms: payload.received_at_ms,
    })
}

async fn dispatch_message(
    envelope: TransitEnvelope,
    registry: &ConversationRegistry,
    group_id_bytes: [u8; 32],
    group_id_hex: String,
) -> Result<InboundDispatch, ChatError> {
    let Some(conv) = registry.get(&group_id_hex).await? else {
        return Ok(InboundDispatch::StaleEpoch {
            group_id_hex,
            epoch: envelope.epoch,
        });
    };
    let Some(key) = conv.key_for_epoch(envelope.epoch)? else {
        return Ok(InboundDispatch::StaleEpoch {
            group_id_hex,
            epoch: envelope.epoch,
        });
    };
    if envelope.nonce.len() != 12 {
        return Err(ChatError::Invalid("nonce length".into()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&envelope.nonce);
    let sender_hex = hex::encode(envelope.sender_agent_id.as_bytes());
    // Replay-protection (spec §7) — see dispatch_receipt for the full
    // commentary on why the atomic record_nonce path matters and why
    // we record before AEAD-open.
    match registry
        .record_nonce(&group_id_hex, &sender_hex, nonce)
        .await?
    {
        NonceCheckOutcome::Replay => {
            return Ok(InboundDispatch::ReplayDetected {
                group_id_hex,
                sender_agent_id_hex: sender_hex,
            });
        }
        NonceCheckOutcome::Recorded => {}
    }
    let aad = message_aad(&group_id_bytes, envelope.epoch);
    let Ok(plaintext) = aead_open(&key, &nonce, &envelope.ciphertext, &aad) else {
        return Ok(InboundDispatch::AeadOpenFailed {
            group_id_hex,
            epoch: envelope.epoch,
        });
    };
    let mut payload: MessagePayload = serde_json::from_slice(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("message payload parse: {e}")))?;
    // Receive-side attachment validation (spec 2.4): a hostile peer could
    // craft a payload with an oversize, SVG, or corrupt-base64 attachment.
    // Validate here and strip on failure so the UI always sees either a
    // well-formed attachment or None — never a bad one. The message body
    // is surfaced intact regardless.
    if let Some(att) = payload.attachment.take() {
        match att.validate() {
            Ok(_) => payload.attachment = Some(att),
            Err(e) => {
                log::warn!("dropping invalid inbound attachment: {e}");
            }
        }
    }
    // In-band relay-hint refresh (Task 6). This runs AFTER the signature
    // verify (verify_sender called before dispatch_message) and AFTER the
    // AEAD open, so only authenticated + decrypted payloads can update the
    // contact card. The monotonic guard in apply_relay_hint rejects stale
    // or replayed hints so a compromised-key replay of an old payload
    // cannot downgrade the stored relay list.
    if let (Some(relays), Some(epoch)) = (payload.advertised_relays.clone(), payload.hint_epoch_ms)
    {
        let layout = registry.layout();
        if let Err(e) = StoredContactCard::apply_relay_hint(layout, &sender_hex, relays, epoch) {
            log::warn!(
                "[chat] relay-hint update failed for {}: {e}",
                &sender_hex[..8.min(sender_hex.len())]
            );
        }
    }
    // Persist the inbound entry so headless readers and vault reloads
    // see the transcript without replaying events. Bookkeeping — a
    // persist failure must not drop the message dispatch itself.
    let entry = super::types::HistoryEntry {
        sender_agent_id_hex: sender_hex.clone(),
        sender_name: payload.sender_name.clone(),
        body: payload.body.clone(),
        ts_ms: payload.ts_ms,
        message_id: payload.message_id.clone().unwrap_or_default(),
        attachment: payload.attachment.clone(),
        delivered_at_ms: None,
    };
    if let Err(e) = registry
        .mutate_in_place(&group_id_hex, |conv| {
            conv.push_history(entry);
            super::registry::MutateAction::Persist(())
        })
        .await
    {
        log::warn!("[chat] inbound history persist failed: {e}");
    }
    Ok(InboundDispatch::Message {
        group_id_hex,
        sender_agent_id_hex: sender_hex,
        payload,
    })
}

/// Successful welcome-path crypto preamble: AEAD opens, pubkey binds,
/// signature verifies. Carries everything the install/rekey step needs.
struct WelcomeVerified {
    payload: WelcomePayload,
    sender_agent_hex: String,
    sender_pk_b64: String,
    sender_kem_pub_b64: String,
}

async fn dispatch_welcome(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
    group_id_bytes: [u8; 32],
    group_id_hex: String,
) -> Result<InboundDispatch, ChatError> {
    let verified = match decrypt_and_verify_welcome(&envelope, identity, group_id_bytes)? {
        Ok(v) => v,
        Err(d) => return Ok(d),
    };

    let prior_card_exists = registry.contact_path(&verified.sender_agent_hex).exists();
    let trust_state = if prior_card_exists {
        TrustState::Confirmed
    } else {
        TrustState::Pending
    };

    // Stash the would-be card before install_or_rekey moves
    // `verified.sender_agent_hex` into the conversation record.
    let pending_card = (!prior_card_exists).then(|| StoredContactCard {
        agent_id_hex: verified.sender_agent_hex.clone(),
        display_name: String::new(),
        kem_public_key_b64: verified.sender_kem_pub_b64,
        agent_public_key_b64: Some(verified.sender_pk_b64),
        // TOFU welcomes don't carry the sender's advertised
        // rendezvous hints — that metadata lives on their share card,
        // which they paste-imported earlier. Pending-cards installed
        // via welcome stay v1-shaped here; the send path's primary
        // fallback keeps replies routable until the peer re-pastes
        // an updated card.
        rendezvous_hints: None,
        last_hint_epoch_ms: None,
        user_id_hex: None,
    });

    let result = install_or_rekey_conversation(
        envelope,
        verified.payload,
        verified.sender_agent_hex,
        registry,
        group_id_hex,
        trust_state,
    )
    .await?;

    if let (InboundDispatch::WelcomedPending { .. }, Some(card)) = (&result, pending_card) {
        write_json_atomic(&registry.contact_path(&card.agent_id_hex), &card)?;
    }

    Ok(result)
}

/// Run the welcome-path crypto preamble: KEM-decap, AEAD-open, decode
/// payload, locate sender device, bind self-attested pubkey to the
/// envelope's `sender_agent_id`, ML-DSA-verify the envelope signature.
fn decrypt_and_verify_welcome(
    envelope: &TransitEnvelope,
    identity: &FetchitIdentity,
    group_id_bytes: [u8; 32],
) -> Result<Result<WelcomeVerified, InboundDispatch>, ChatError> {
    let sender_agent_hex = hex::encode(envelope.sender_agent_id.as_bytes());
    let group_id_hex = hex::encode(group_id_bytes);

    // KEM-decap + AEAD-open. We can do this without any prior card on
    // file because the secret key is OURS.
    let Ok(ss) = kem_decapsulate(identity.kem_secret_key(), &envelope.kem_ciphertext) else {
        return Ok(Err(InboundDispatch::KemDecapFailed));
    };
    let aead_key = derive_aead_key(&ss[..], KDF_INFO_WELCOME);
    if envelope.nonce.len() != 12 {
        return Err(ChatError::Invalid("nonce length".into()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&envelope.nonce);
    let aad = message_aad(&group_id_bytes, envelope.epoch);
    let Ok(plaintext) = aead_open(&aead_key, &nonce, &envelope.ciphertext, &aad) else {
        return Ok(Err(InboundDispatch::AeadOpenFailed {
            group_id_hex,
            epoch: envelope.epoch,
        }));
    };
    let payload: WelcomePayload = serde_json::from_slice(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("welcome payload parse: {e}")))?;

    // Belt-and-suspenders against epoch downgrade: AEAD binds to
    // envelope.epoch in the AAD, but install_or_rekey installs
    // payload.epoch into conv.current_epoch. A mismatch indicates
    // tampering or a crafted payload — drop without state change.
    if payload.epoch != envelope.epoch {
        return Ok(Err(InboundDispatch::Dropped {
            kind: "welcome-epoch-mismatch".to_owned(),
            sender: sender_agent_hex,
        }));
    }

    // Validate the inner symmetric key is well-formed BEFORE any state
    // mutation. A peer that ships a non-AEAD_KEY_LEN key would otherwise
    // poison the local conversation: every AEAD-open afterwards fails
    // because the key length is wrong — a permanent local DoS from a
    // single signed welcome.
    match B64.decode(&payload.current_key_b64) {
        Ok(k) if k.len() == AEAD_KEY_LEN => {}
        _ => {
            return Ok(Err(InboundDispatch::Dropped {
                kind: "welcome-invalid-key-length".to_owned(),
                sender: sender_agent_hex,
            }));
        }
    }

    // Locate the sender's device in the payload member list and extract
    // the self-attested pubkey.
    let Some(sender_device) = payload
        .members
        .iter()
        .flat_map(|m| m.devices.iter())
        .find(|d| d.agent_id_hex == sender_agent_hex)
    else {
        return Ok(Err(InboundDispatch::Dropped {
            kind: "welcome-sender-not-member".to_owned(),
            sender: sender_agent_hex,
        }));
    };
    let Some(sender_pk_b64) = sender_device.agent_public_key_b64.clone() else {
        return Ok(Err(InboundDispatch::Dropped {
            kind: "welcome-missing-sender-pubkey".to_owned(),
            sender: sender_agent_hex,
        }));
    };
    let sender_pk = B64
        .decode(&sender_pk_b64)
        .map_err(|e| ChatError::Invalid(format!("welcome sender pk b64: {e}")))?;
    let sender_kem_pub_b64 = sender_device.kem_public_key_b64.clone();

    // Cryptographic safety net: derive_agent_id(claimed_pk) must match
    // the envelope's sender_agent_id. The relay's auth flow already
    // verifies the connection's agent_id matches the bearer-attached
    // pubkey, so a forged payload pubkey can't lie about the sender's
    // identity.
    let derived = derive_agent_id(&sender_pk);
    if derived != *envelope.sender_agent_id.as_bytes() {
        return Ok(Err(InboundDispatch::Dropped {
            kind: "welcome-pubkey-agent-mismatch".to_owned(),
            sender: sender_agent_hex,
        }));
    }

    // Verify the envelope signature against the bound pubkey.
    let canonical = canonical_envelope_bytes(envelope)?;
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
    sign_bytes.extend_from_slice(SIGN_DOMAIN_ENVELOPE);
    sign_bytes.extend_from_slice(&canonical);
    if ml_dsa_verify(&sender_pk, &sign_bytes, &envelope.sender_signature).is_err() {
        return Ok(Err(InboundDispatch::Dropped {
            kind: "bad-signature".to_owned(),
            sender: sender_agent_hex,
        }));
    }

    Ok(Ok(WelcomeVerified {
        payload,
        sender_agent_hex,
        sender_pk_b64,
        sender_kem_pub_b64,
    }))
}

/// What `install_or_rekey_conversation` decided inside the registry's
/// atomic `mutate_in_place` closure. Lifts the variant choice out of
/// the closure so the surrounding async fn can pick the right
/// `InboundDispatch` and own moved values like `sender_agent_hex`.
#[allow(clippy::large_enum_variant)] // Rekeyed carries an owned Conversation by design; the producer would otherwise reallocate.
enum RekeyResolution {
    /// Welcome's epoch is not strictly higher than the cached one —
    /// no state change.
    Ignored,
    /// The welcome's sender was not a member of the cached
    /// conversation, so we refused the rekey even though everything
    /// else verified.
    NotMember,
    /// Rekey applied. Carries the post-mutation clone so the caller
    /// can surface it in [`InboundDispatch::Rekeyed`].
    Rekeyed(Conversation),
}

/// Install the welcome's conversation on first contact, or fold a
/// higher-epoch welcome into an existing conversation as a rekey.
async fn install_or_rekey_conversation(
    envelope: TransitEnvelope,
    payload: WelcomePayload,
    sender_agent_hex: String,
    registry: &ConversationRegistry,
    group_id_hex: String,
    trust_state: TrustState,
) -> Result<InboundDispatch, ChatError> {
    let existing_epoch = registry.get(&group_id_hex).await?.map(|c| c.current_epoch);
    let Some(_) = existing_epoch else {
        // New install — no concurrent record_nonce can race a cache
        // entry that doesn't exist yet, so the existing `save` is
        // safe here.
        let conv = Conversation::from_welcome(payload, trust_state);
        registry.save(&conv).await?;
        return if trust_state == TrustState::Pending {
            Ok(InboundDispatch::WelcomedPending { conversation: conv })
        } else {
            Ok(InboundDispatch::Welcomed { conversation: conv })
        };
    };

    // Existing conversation — the rekey path runs through
    // `mutate_in_place` so we hold `by_group_id` across the entire
    // check + mutation + persist. The old shape (clone → mutate →
    // save) clobbered any concurrently-recorded `seen_nonces`
    // because save() replaces the cached entry wholesale with the
    // stale clone, undoing what a parallel record_nonce had
    // committed.
    //
    // Defence in depth: even a valid signature isn't enough to swap
    // the conversation key. The sender must already be a member of
    // the conversation they're rekeying — and the membership check
    // happens INSIDE the closure so a concurrent rekey between our
    // read and our write can't sneak in.
    let resolution = registry
        .mutate_in_place(&group_id_hex, |conv| {
            if envelope.epoch <= conv.current_epoch {
                return MutateAction::Skip(RekeyResolution::Ignored);
            }
            let sender_already_member = conv
                .members
                .iter()
                .flat_map(|m| m.devices.iter())
                .any(|d| d.agent_id_hex == sender_agent_hex);
            if !sender_already_member {
                return MutateAction::Skip(RekeyResolution::NotMember);
            }
            let now = now_ms();
            conv.prior_keys.push(PriorKey {
                epoch: conv.current_epoch,
                key_b64: conv.current_key_b64.clone(),
                expires_at_ms: now + PRIOR_KEY_WINDOW_MS,
            });
            conv.current_epoch = payload.epoch;
            conv.current_key_b64.clone_from(&payload.current_key_b64);
            conv.members.clone_from(&payload.members);
            conv.name.clone_from(&payload.name);
            conv.last_rekey_at_ms = now;
            conv.sweep_prior_keys();
            MutateAction::Persist(RekeyResolution::Rekeyed(conv.clone()))
        })
        .await?;

    match resolution {
        RekeyResolution::Ignored => Ok(InboundDispatch::WelcomeIgnored),
        RekeyResolution::NotMember => Ok(InboundDispatch::Dropped {
            kind: "rekey-from-non-member".to_owned(),
            sender: sender_agent_hex,
        }),
        RekeyResolution::Rekeyed(conv) => Ok(InboundDispatch::Rekeyed { conversation: conv }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::outbound::{
        build_message_outbox, build_receipt_outbox, build_welcome_outbox,
    };
    use super::super::types::{Member, MemberDevice, MemberDeviceStatus};
    use super::*;
    use crate::at_rest::{
        fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource, ARGON_SALT_LEN,
    };
    use crate::chat_crypto::random_symmetric_key;
    use crate::local_store::StoreLayout;

    #[test]
    fn confirms_delivery_holds_exactly_the_retriable_outcomes() {
        use super::confirms_delivery as c;
        use super::InboundDispatch as D;
        // Retriable: a later redelivery can genuinely improve these.
        assert!(!c(&D::StaleEpoch {
            group_id_hex: "g".into(),
            epoch: 2
        }));
        assert!(!c(&D::KemDecapFailed));
        assert!(!c(&D::Dropped {
            kind: "no-card".into(),
            sender: "s".into()
        }));
        assert!(!c(&D::Dropped {
            kind: "no-pubkey".into(),
            sender: "s".into()
        }));
        // Terminal: persisted, duplicate, or deterministic verdicts on
        // immutable bytes.
        assert!(c(&D::WelcomeIgnored));
        assert!(c(&D::ReplayDetected {
            group_id_hex: "g".into(),
            sender_agent_id_hex: "s".into(),
        }));
        assert!(c(&D::AeadOpenFailed {
            group_id_hex: "g".into(),
            epoch: 2
        }));
        assert!(c(&D::Dropped {
            kind: "bad-signature".into(),
            sender: "s".into()
        }));
        assert!(c(&D::Dropped {
            kind: "rekey-from-non-member".into(),
            sender: "s".into(),
        }));
    }

    use crate::messages::StoredContactCard;
    use base64::engine::general_purpose::STANDARD as B64;
    use fetchit_relay_client::{MlDsaSigner, Signer};
    use fetchit_relay_proto::{AgentId, EnvelopeKind, GroupId, MachineId, WIRE_VERSION};
    use rand::rngs::OsRng;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    fn install_card(
        layout: &StoreLayout,
        agent_id_hex: &str,
        signer: &MlDsaSigner,
        kem_pub: &[u8],
    ) {
        let card = StoredContactCard {
            agent_id_hex: agent_id_hex.to_owned(),
            display_name: "Peer".to_owned(),
            kem_public_key_b64: B64.encode(kem_pub),
            agent_public_key_b64: Some(B64.encode(signer.public_key())),
            rendezvous_hints: None,
            last_hint_epoch_ms: None,
            user_id_hex: None,
        };
        card.save(layout).unwrap();
    }

    fn local_member(agent_id_hex: &str, kem_pub_b64: &str) -> Member {
        Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: agent_id_hex.to_owned(),
                kem_public_key_b64: kem_pub_b64.to_owned(),
                agent_public_key_b64: None,
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        }
    }

    fn fixture_identity(
        tmp: &Path,
        agent_id_hex: &str,
    ) -> (FetchitIdentity, MasterKey, [u8; ARGON_SALT_LEN]) {
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("p".into())),
            Some(&salt),
        )
        .unwrap();
        let id = FetchitIdentity::load_or_create(
            tmp,
            &master,
            agent_id_hex,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        (id, master, salt)
    }

    /// Derive a fresh ML-DSA signer + identity whose agent-id is the
    /// pubkey-bound `AUTONOMI_PEER_ID_V2` hash. The welcome path
    /// requires this binding to verify; the helper keeps every test
    /// using a realistic identity / signer pair.
    fn fresh_signer_with_identity(
        tmp: &Path,
    ) -> (
        MlDsaSigner,
        FetchitIdentity,
        MasterKey,
        [u8; ARGON_SALT_LEN],
        String,
    ) {
        let signer = MlDsaSigner::generate().unwrap();
        let aid_hex = hex::encode(derive_agent_id(&signer.public_key()));
        let (id, master, salt) = fixture_identity(tmp, &aid_hex);
        (signer, id, master, salt, aid_hex)
    }

    #[tokio::test]
    async fn welcome_round_trip_between_two_identities() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        assert_eq!(outbox.len(), 1);

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Welcomed { conversation } => {
                assert_eq!(conversation.group_id_hex, conv.group_id_hex);
                assert_eq!(conversation.current_key_b64, conv.current_key_b64);
                assert_eq!(conversation.members.len(), 2);
                assert_eq!(conversation.trust_state, TrustState::Confirmed);
            }
            other => panic!("expected Welcomed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn receipt_round_trip_after_message() {
        // Alice and Bob set up a conversation. Bob receives a message,
        // builds a receipt back to Alice, and Alice's dispatch must
        // surface the matching `InboundDispatch::Receipt`.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        // Bob's side has Alice's card and the conversation installed.
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Alice's side has Bob's card and the conversation installed
        // so the receipt's verify-prelude passes.
        let tmp_a_store = tempdir().unwrap();
        let layout_a = StoreLayout::ensure(tmp_a_store.path().join("store")).unwrap();
        install_card(&layout_a, &aid_b, &bob_signer, bob_id.kem_public_key());
        let (_, master_a2, salt_a2) = fixture_identity(tmp_a_store.path(), &aid_a);
        let registry_a = ConversationRegistry::new(
            layout_a,
            Arc::new(master_a2),
            kdf_id_argon2(),
            Some(salt_a2),
        );
        // Seed Alice's history with the entry the receipt will echo so
        // the dispatch's delivery-state persistence has a row to mark.
        let mut conv_a = conv.clone();
        conv_a.push_history(crate::conversation::HistoryEntry {
            sender_agent_id_hex: aid_a.clone(),
            sender_name: None,
            body: "ping".into(),
            ts_ms: 1,
            message_id: "deadbeef".into(),
            attachment: None,
            delivered_at_ms: None,
        });
        registry_a.save(&conv_a).await.unwrap();

        let receipt_outbox = build_receipt_outbox(
            &conv,
            "deadbeef",
            1_700_000_000_001,
            &aid_a,
            &bob_id,
            [0u8; 32],
            &bob_signer,
        )
        .await
        .unwrap();
        assert_eq!(receipt_outbox.len(), 1);

        let result = dispatch_inbound(receipt_outbox[0].envelope.clone(), &alice_id, &registry_a)
            .await
            .unwrap();
        match result {
            InboundDispatch::Receipt {
                message_id,
                sender_agent_id_hex,
                received_at_ms,
                group_id_hex,
            } => {
                assert_eq!(message_id, "deadbeef");
                assert_eq!(sender_agent_id_hex, aid_b);
                assert_eq!(received_at_ms, 1_700_000_000_001);
                assert_eq!(group_id_hex, conv.group_id_hex);
            }
            other => panic!("expected Receipt, got {other:?}"),
        }
        // The dispatch must also have PERSISTED the delivered mark —
        // this is what headless readers and vault reloads consume.
        let stored = registry_a.get(&conv.group_id_hex).await.unwrap().unwrap();
        let entry = stored
            .history
            .iter()
            .find(|e| e.message_id == "deadbeef")
            .expect("seeded entry present");
        assert_eq!(entry.delivered_at_ms, Some(1_700_000_000_001));
    }

    #[tokio::test]
    async fn message_round_trip_after_welcome() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        let msg_outbox = build_message_outbox(
            &conv,
            "hello bob",
            "Alice",
            "msg-id-1",
            Some("parent-id-0"),
            None,
            &alice_id,
            [0u8; 32],
            &alice_signer,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(msg_outbox.len(), 1);
        let result = dispatch_inbound(msg_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Message { payload, .. } => {
                assert_eq!(payload.body, "hello bob");
                assert_eq!(payload.sender_name.as_deref(), Some("Alice"));
                assert_eq!(payload.reply_to_message_id.as_deref(), Some("parent-id-0"));
                assert_eq!(payload.attachment, None);
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stale_epoch_is_surfaced_not_panicked() {
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        // Install a synthetic card so the verify prelude passes; the
        // test still targets the Message-path StaleEpoch branch.
        let synthetic_signer = MlDsaSigner::generate().unwrap();
        let sender_hex = hex::encode([0xaa; 32]);
        let synthetic_card = StoredContactCard {
            agent_id_hex: sender_hex.clone(),
            display_name: "Synthetic".to_owned(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: Some(B64.encode(synthetic_signer.public_key())),
            rendezvous_hints: None,
            last_hint_epoch_ms: None,
            user_id_hex: None,
        };
        synthetic_card.save(&layout_b).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let mut env = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes([0xee; 32])),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([0xaa; 32]),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: 99,
            ciphertext: vec![0u8; 16],
            nonce: vec![0u8; 12],
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let canonical = crate::chat_crypto::canonical_envelope_bytes(&env).unwrap();
        let mut sign_bytes =
            Vec::with_capacity(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        env.sender_signature = synthetic_signer.sign(&sign_bytes).await.unwrap();
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(matches!(result, InboundDispatch::StaleEpoch { .. }));
    }

    #[tokio::test]
    async fn higher_epoch_welcome_rekeys_existing_conversation() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let mut conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));

        // Epoch-0 welcome installs the conversation on Bob.
        let outbox0 = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(outbox0[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Alice rotates the key and bumps the epoch (e.g. auto-rekey fired).
        let new_key = random_symmetric_key(&mut OsRng);
        conv.advance_epoch(new_key);
        assert_eq!(conv.current_epoch, 1, "advance_epoch should bump to 1");
        let expected_key_b64 = conv.current_key_b64.clone();

        // Alice resends a welcome carrying the new epoch + key.
        let outbox1 = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let result = dispatch_inbound(outbox1[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Rekeyed { conversation } => {
                assert_eq!(conversation.current_epoch, 1);
                assert_eq!(conversation.current_key_b64, expected_key_b64);
                assert_eq!(
                    conversation.prior_keys.len(),
                    1,
                    "old epoch-0 key should have been pushed into prior_keys"
                );
                assert_eq!(conversation.prior_keys[0].epoch, 0);
            }
            other => panic!("expected Rekeyed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn duplicate_welcome_returns_welcome_ignored() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        // First dispatch installs.
        let r1 = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(matches!(r1, InboundDispatch::Welcomed { .. }));

        // Second dispatch of the same envelope should be ignored.
        let r2 = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(matches!(r2, InboundDispatch::WelcomeIgnored));
    }

    #[tokio::test]
    async fn stale_welcome_does_not_install_contact_card() {
        // Replay-attack defence: a stale welcome (same envelope, second
        // delivery) installs the conversation on the first pass and is
        // rejected as WelcomeIgnored on the second. The TOFU card-install
        // MUST be gated on the install actually succeeding — if we wipe
        // the card and re-deliver the stale welcome, the contact store
        // must stay empty.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        // No card pre-installed for Alice on Bob's side — first delivery
        // is a TOFU path.

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let r1 = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(r1, InboundDispatch::WelcomedPending { .. }),
            "first delivery should TOFU-install Pending, got {r1:?}",
        );
        let card_path = registry_b.contact_path(&aid_a);
        assert!(
            card_path.exists(),
            "first delivery must have written Alice's card",
        );

        // Delete the card to simulate a clean-slate replay attack — an
        // attacker re-delivers the stale welcome hoping to reinstall
        // themselves into the contact store even though the install path
        // will reject the welcome as stale.
        std::fs::remove_file(&card_path).unwrap();
        assert!(!card_path.exists(), "card removal precondition");

        let r2 = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(r2, InboundDispatch::WelcomeIgnored),
            "stale-epoch replay must surface WelcomeIgnored, got {r2:?}",
        );
        assert!(
            !card_path.exists(),
            "WelcomeIgnored must NOT reinstall the contact card",
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_envelope_with_no_card() {
        // Welcome auto-installs cards on first contact, so this test
        // exercises the MESSAGE path (the only path where a missing
        // card is a hard drop).
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        // Intentionally NO card saved for the sender.
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let env = synthetic_message_envelope([0xaa; 32], [0xee; 32]);
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(result, InboundDispatch::Dropped { ref kind, .. } if kind == "no-card"),
            "expected Dropped(no-card), got {result:?}",
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_envelope_with_no_pubkey_card() {
        // Same as above: the no-pubkey case is also message-path-only.
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let sender_hex = hex::encode([0xaa; 32]);
        let no_pk_card = StoredContactCard {
            agent_id_hex: sender_hex,
            display_name: "Sender".to_owned(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: None,
            rendezvous_hints: None,
            last_hint_epoch_ms: None,
            user_id_hex: None,
        };
        no_pk_card.save(&layout_b).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let env = synthetic_message_envelope([0xaa; 32], [0xee; 32]);
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(result, InboundDispatch::Dropped { ref kind, .. } if kind == "no-pubkey"),
            "expected Dropped(no-pubkey), got {result:?}",
        );
    }

    /// Build a synthetic message-shaped envelope (no KEM ciphertext) with
    /// the supplied sender and group agent ids. Used by drop-path tests
    /// that don't actually need to decrypt anything — the verify prelude
    /// fires before any AEAD work.
    fn synthetic_message_envelope(
        sender_agent_id: [u8; 32],
        group_id: [u8; 32],
    ) -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(sender_agent_id),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![0u8; 16],
            nonce: vec![0u8; 12],
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        }
    }

    #[tokio::test]
    async fn dispatch_rejects_envelope_with_bad_signature() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let mut outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        if let Some(last) = outbox[0].envelope.sender_signature.last_mut() {
            *last ^= 0x01;
        }
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(result, InboundDispatch::Dropped { ref kind, .. } if kind == "bad-signature"),
            "expected Dropped(bad-signature), got {result:?}",
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_higher_epoch_welcome_from_non_member() {
        // Alice and Bob set up a normal DM. Carol — who is NOT a member —
        // gets her card installed on Bob's side and her ML-DSA key present.
        // She signs a higher-epoch welcome for the same group_id and tries
        // to rekey Bob's conversation. Even with a valid signature the
        // dispatch must drop it.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let tmp_c = tempdir().unwrap();
        let (carol_signer, carol_id, _master_c, _salt_c, aid_c) =
            fresh_signer_with_identity(tmp_c.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member.clone(), None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        install_card(&layout_b, &aid_c, &carol_signer, carol_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));

        // Bootstrap epoch-0 from Alice.
        let outbox0 = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(outbox0[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Carol forges a higher-epoch welcome carrying the SAME group_id
        // but with Carol + Bob in the member list. The KEM ciphertext is
        // encapsulated to Bob's KEM key (since Bob is in Carol's fanout)
        // so decap + AEAD open succeed; the prelude signature check passes
        // because Carol's card is installed. The defence below — sender
        // must already be a member of Bob's existing conversation — is
        // what catches her.
        let carol_member = local_member(&aid_c, &B64.encode(carol_id.kem_public_key()));
        let mut carol_conv = Conversation::new_dm(carol_member, bob_member, None).unwrap();
        carol_conv.group_id_hex = conv.group_id_hex.clone();
        carol_conv.current_epoch = 5;
        let outbox1 = build_welcome_outbox(&carol_conv, &carol_id, [0u8; 32], &carol_signer)
            .await
            .unwrap();
        let result = dispatch_inbound(outbox1[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "rekey-from-non-member"
            ),
            "expected Dropped(rekey-from-non-member), got {result:?}",
        );
    }

    #[tokio::test]
    async fn welcome_from_unknown_sender_installs_pending_conversation() {
        // First-contact TOFU: Bob has NO card on file for Alice, yet
        // her welcome decrypts, the self-attested pubkey binds to her
        // sender_agent_id, the signature verifies — and the dispatch
        // auto-installs both the card and a Pending conversation.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        // No card pre-installed for Alice on Bob's side.

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::WelcomedPending { conversation } => {
                assert_eq!(conversation.group_id_hex, conv.group_id_hex);
                assert_eq!(conversation.trust_state, TrustState::Pending);
            }
            other => panic!("expected WelcomedPending, got {other:?}"),
        }

        // Card was auto-installed.
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let stored = StoredContactCard::load(&layout_b, &aid_a)
            .unwrap()
            .expect("auto-install should have persisted Alice's card");
        assert_eq!(
            stored.agent_public_key_b64.as_deref(),
            Some(B64.encode(alice_signer.public_key())).as_deref(),
        );
    }

    #[tokio::test]
    async fn welcome_from_known_sender_returns_welcomed_confirmed() {
        // Returning trusted contact: Alice's card already on file from
        // an out-of-band QR scan. The welcome should install the
        // conversation as Confirmed and surface as Welcomed (not the
        // Pending variant).
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Welcomed { conversation } => {
                assert_eq!(conversation.trust_state, TrustState::Confirmed);
            }
            other => panic!("expected Welcomed (Confirmed), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn welcome_pubkey_agent_id_mismatch_drops() {
        // Security: even if an attacker controls the welcome payload,
        // they cannot lie about the sender's pubkey because the
        // AUTONOMI_PEER_ID_V2 derivation deterministically maps it back
        // to the relay-authenticated sender_agent_id. Splicing a
        // mismatched pubkey into the payload must drop.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        // Wrong pubkey: a different ML-DSA signer whose pubkey does NOT
        // hash to alice's sender_agent_id.
        let wrong_signer = MlDsaSigner::generate().unwrap();

        let mut alice_member_with_wrong_pk =
            local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        alice_member_with_wrong_pk.devices[0].agent_public_key_b64 =
            Some(B64.encode(wrong_signer.public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let payload = WelcomePayload {
            group_id_hex: "0".repeat(64),
            current_key_b64: B64.encode([7u8; 32]),
            epoch: 0,
            members: vec![alice_member_with_wrong_pk, bob_member],
            name: None,
        };
        let env =
            seal_welcome_envelope(&payload, &aid_a, bob_id.kem_public_key(), &alice_signer).await;

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "welcome-pubkey-agent-mismatch"
            ),
            "expected Dropped(welcome-pubkey-agent-mismatch), got {result:?}",
        );
    }

    #[tokio::test]
    async fn welcome_with_payload_epoch_mismatch_dropped() {
        // Belt-and-suspenders: AEAD binds envelope.epoch into the AAD,
        // but install_or_rekey installs payload.epoch into
        // conv.current_epoch. A crafted envelope where envelope.epoch
        // and payload.epoch disagree must drop without state change,
        // otherwise a payload.epoch=0 inside an envelope.epoch=N seal
        // would regress the victim's conversation epoch on install or
        // rekey.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let mut alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        alice_member.devices[0].agent_public_key_b64 = Some(B64.encode(alice_signer.public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        // Inner payload claims epoch 0 — what install_or_rekey would
        // write into conv.current_epoch if the cross-check were missing.
        let payload = WelcomePayload {
            group_id_hex: "0".repeat(64),
            current_key_b64: B64.encode([7u8; 32]),
            epoch: 0,
            members: vec![alice_member, bob_member],
            name: None,
        };
        // Envelope is sealed at epoch 5 — AEAD opens because the AAD
        // matches, but the cross-check on payload.epoch must fail.
        let env = seal_welcome_envelope_with_epoch(
            &payload,
            5,
            &aid_a,
            bob_id.kem_public_key(),
            &alice_signer,
        )
        .await;

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "welcome-epoch-mismatch"
            ),
            "expected Dropped(welcome-epoch-mismatch), got {result:?}",
        );
    }

    #[tokio::test]
    async fn welcome_with_short_key_dropped() {
        // A welcome whose inner current_key_b64 decodes to fewer than
        // AEAD_KEY_LEN (32) bytes would poison the conversation: every
        // subsequent AEAD-open would fail because the key length is
        // wrong. Drop before any state mutation.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let mut alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        alice_member.devices[0].agent_public_key_b64 = Some(B64.encode(alice_signer.public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let payload = WelcomePayload {
            group_id_hex: "0".repeat(64),
            current_key_b64: B64.encode([7u8; 16]),
            epoch: 0,
            members: vec![alice_member, bob_member],
            name: None,
        };
        let env =
            seal_welcome_envelope(&payload, &aid_a, bob_id.kem_public_key(), &alice_signer).await;

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "welcome-invalid-key-length"
            ),
            "expected Dropped(welcome-invalid-key-length), got {result:?}",
        );
    }

    #[tokio::test]
    async fn welcome_with_long_key_dropped() {
        // Symmetric to the short-key case: a payload key that decodes
        // to MORE than AEAD_KEY_LEN bytes is equally malformed.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let mut alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        alice_member.devices[0].agent_public_key_b64 = Some(B64.encode(alice_signer.public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let payload = WelcomePayload {
            group_id_hex: "0".repeat(64),
            current_key_b64: B64.encode([7u8; 48]),
            epoch: 0,
            members: vec![alice_member, bob_member],
            name: None,
        };
        let env =
            seal_welcome_envelope(&payload, &aid_a, bob_id.kem_public_key(), &alice_signer).await;

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "welcome-invalid-key-length"
            ),
            "expected Dropped(welcome-invalid-key-length), got {result:?}",
        );
    }

    #[tokio::test]
    async fn welcome_with_non_base64_key_dropped() {
        // A non-base64 current_key_b64 must drop the welcome before
        // any state mutation. The check fails closed on decode error
        // — no ChatError propagates.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let mut alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        alice_member.devices[0].agent_public_key_b64 = Some(B64.encode(alice_signer.public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let payload = WelcomePayload {
            group_id_hex: "0".repeat(64),
            current_key_b64: "not!!!base64!!!".to_owned(),
            epoch: 0,
            members: vec![alice_member, bob_member],
            name: None,
        };
        let env =
            seal_welcome_envelope(&payload, &aid_a, bob_id.kem_public_key(), &alice_signer).await;

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "welcome-invalid-key-length"
            ),
            "expected Dropped(welcome-invalid-key-length), got {result:?}",
        );
    }

    #[tokio::test]
    async fn welcome_missing_sender_member_drops() {
        // If the welcome payload omits the sender's agent_id from its
        // member list there's nothing to bind the pubkey to. Drop.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, _alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        // Payload member list does NOT include Alice (the sender).
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let payload = WelcomePayload {
            group_id_hex: "0".repeat(64),
            current_key_b64: B64.encode([7u8; 32]),
            epoch: 0,
            members: vec![bob_member],
            name: None,
        };
        let env =
            seal_welcome_envelope(&payload, &aid_a, bob_id.kem_public_key(), &alice_signer).await;

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(
                result,
                InboundDispatch::Dropped { ref kind, .. } if kind == "welcome-sender-not-member"
            ),
            "expected Dropped(welcome-sender-not-member), got {result:?}",
        );
    }

    #[tokio::test]
    async fn replay_message_returns_replay_detected() {
        // Spec §7: redelivering a previously-decrypted Message envelope
        // must surface ReplayDetected without re-running AEAD-open
        // against the conversation key.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        let msg_outbox = build_message_outbox(
            &conv,
            "hello bob",
            "Alice",
            "msg-id-1",
            None,
            None,
            &alice_id,
            [0u8; 32],
            &alice_signer,
            None,
            None,
        )
        .await
        .unwrap();
        let first = dispatch_inbound(msg_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(first, InboundDispatch::Message { .. }),
            "first delivery should decrypt as Message, got {first:?}",
        );

        let replay = dispatch_inbound(msg_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match replay {
            InboundDispatch::ReplayDetected {
                group_id_hex,
                sender_agent_id_hex,
            } => {
                assert_eq!(group_id_hex, conv.group_id_hex);
                assert_eq!(sender_agent_id_hex, aid_a);
            }
            other => panic!("expected ReplayDetected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbound_oversize_attachment_is_stripped_body_intact() {
        // Spec 2.4 receive path: a payload carrying an attachment whose
        // base64 decodes to MAX_ATTACHMENT_BYTES + 1 bytes must have the
        // attachment stripped to None on dispatch; the message body must
        // survive intact.
        use super::super::types::MessagePayload;
        use crate::attachment::{Attachment, MAX_ATTACHMENT_BYTES};
        use crate::chat_crypto::{aead_seal, canonical_envelope_bytes, message_aad, random_nonce};
        use base64::engine::general_purpose::STANDARD as B64e;
        use base64::Engine as _;
        use fetchit_relay_proto::{AgentId as ProtoAgentId, EnvelopeKind, GroupId, MachineId};
        use rand::rngs::OsRng;

        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Hand-craft an oversize attachment bypassing from_raw's guard —
        // identical technique as attachment.rs::validate_rejects_oversize_on_the_wire.
        let oversize_raw = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
        let forged_att = Attachment {
            mime: "image/png".to_owned(),
            width: 1,
            height: 1,
            bytes_b64: B64e.encode(&oversize_raw),
        };

        // Seal a MessagePayload containing the forged attachment directly,
        // bypassing build_message_outbox so the validation guard there
        // does not fire. This is the same hand-roll used by the welcome
        // drop-path tests in this module.
        let group_id_bytes = conv.group_id_bytes().unwrap();
        let key = conv.current_key().unwrap();
        let aad = message_aad(&group_id_bytes, conv.current_epoch);
        let payload = MessagePayload {
            sender_name: Some("Alice".into()),
            body: "body text".into(),
            ts_ms: 1,
            message_id: Some("forged-id".into()),
            reply_to_message_id: None,
            attachment: Some(forged_att),
            advertised_relays: None,
            hint_epoch_ms: None,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let nonce = random_nonce(&mut OsRng);
        let ciphertext = aead_seal(&key, &nonce, &payload_bytes, &aad).unwrap();
        let mut local_agent_bytes = [0u8; 32];
        hex::decode_to_slice(&aid_a, &mut local_agent_bytes).unwrap();
        let group_id_bytes_arr: [u8; 32] = group_id_bytes;
        let mut env = fetchit_relay_proto::TransitEnvelope {
            version: fetchit_relay_proto::WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes_arr)),
            tenant_id: None,
            sender_agent_id: ProtoAgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1,
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let canonical = canonical_envelope_bytes(&env).unwrap();
        let mut sign_bytes =
            Vec::with_capacity(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        env.sender_signature = alice_signer.sign(&sign_bytes).await.unwrap();

        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        match result {
            InboundDispatch::Message { payload, .. } => {
                assert_eq!(payload.body, "body text", "body must survive the strip");
                assert_eq!(
                    payload.attachment, None,
                    "oversize attachment must be stripped to None",
                );
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn replay_receipt_returns_replay_detected() {
        // Spec §7: the receipt path has the same window — replaying a
        // DeliveryReceipt envelope must surface ReplayDetected.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        // Bob installs the conversation via the welcome.
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Alice's side: install Bob's card and the conversation so the
        // receipt's verify prelude + dispatch find their fixtures.
        let tmp_a_store = tempdir().unwrap();
        let layout_a = StoreLayout::ensure(tmp_a_store.path().join("store")).unwrap();
        install_card(&layout_a, &aid_b, &bob_signer, bob_id.kem_public_key());
        let (_, master_a2, salt_a2) = fixture_identity(tmp_a_store.path(), &aid_a);
        let registry_a = ConversationRegistry::new(
            layout_a,
            Arc::new(master_a2),
            kdf_id_argon2(),
            Some(salt_a2),
        );
        registry_a.save(&conv).await.unwrap();

        let receipt_outbox = build_receipt_outbox(
            &conv,
            "deadbeef",
            1_700_000_000_001,
            &aid_a,
            &bob_id,
            [0u8; 32],
            &bob_signer,
        )
        .await
        .unwrap();
        let first = dispatch_inbound(receipt_outbox[0].envelope.clone(), &alice_id, &registry_a)
            .await
            .unwrap();
        assert!(
            matches!(first, InboundDispatch::Receipt { .. }),
            "first receipt delivery should decrypt, got {first:?}",
        );

        let replay = dispatch_inbound(receipt_outbox[0].envelope.clone(), &alice_id, &registry_a)
            .await
            .unwrap();
        match replay {
            InboundDispatch::ReplayDetected {
                group_id_hex,
                sender_agent_id_hex,
            } => {
                assert_eq!(group_id_hex, conv.group_id_hex);
                assert_eq!(sender_agent_id_hex, aid_b);
            }
            other => panic!("expected ReplayDetected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn receipt_marks_outbox_bubble_delivered_and_emits() {
        // Outbox lift (T5d): a verified DeliveryReceipt flips the matching
        // outbound bubble (by message_id) to Delivered and broadcasts the
        // change -- engine-side, so every shell inherits it.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        // Bob installs the conversation via the welcome.
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Alice's side: install Bob's card + the conversation.
        let tmp_a_store = tempdir().unwrap();
        let layout_a = StoreLayout::ensure(tmp_a_store.path().join("store")).unwrap();
        install_card(&layout_a, &aid_b, &bob_signer, bob_id.kem_public_key());
        let (_, master_a2, salt_a2) = fixture_identity(tmp_a_store.path(), &aid_a);
        let registry_a = ConversationRegistry::new(
            layout_a,
            Arc::new(master_a2),
            kdf_id_argon2(),
            Some(salt_a2),
        );
        registry_a.save(&conv).await.unwrap();

        // Bob acks message "deadbeef"; seed Alice's outbox with the bubble
        // that carries that relay message_id (still Sending).
        let receipt_outbox = build_receipt_outbox(
            &conv,
            "deadbeef",
            1_700_000_000_001,
            &aid_a,
            &bob_id,
            [0u8; 32],
            &bob_signer,
        )
        .await
        .unwrap();
        let outbox = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::outbox::store::OutboxStore::new(),
        ));
        outbox.lock().await.upsert(crate::outbox::OutboxBubble {
            id: "bubble-1".into(),
            peer: crate::identity::AgentId(aid_b.clone()),
            body: "hi".into(),
            status: crate::outbox::OutboxStatus::Sending,
            message_id: Some("deadbeef".into()),
            enqueued_at_ms: 1_700_000_000_000,
            last_error: None,
            group: None,
        });
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);

        let dispatched = dispatch_inbound_with_outbox(
            receipt_outbox[0].envelope.clone(),
            &alice_id,
            &registry_a,
            Some(&outbox),
            Some(&tx),
        )
        .await
        .unwrap();
        assert!(matches!(dispatched, InboundDispatch::Receipt { .. }));

        // The bubble flipped to Delivered, and the change was broadcast.
        assert_eq!(
            outbox.lock().await.get("bubble-1").unwrap().status,
            crate::outbox::OutboxStatus::Delivered,
        );
        let evt = rx.try_recv().expect("outbox event emitted");
        assert_eq!(evt.bubble.id, "bubble-1");
        assert_eq!(evt.bubble.status, crate::outbox::OutboxStatus::Delivered);
    }

    /// Hand-roll a welcome envelope around a caller-supplied
    /// `WelcomePayload`, signing with the supplied ML-DSA signer.
    /// Used by drop-path tests that need to manipulate the payload
    /// (e.g. splice a wrong pubkey, omit the sender member).
    async fn seal_welcome_envelope(
        payload: &WelcomePayload,
        sender_aid_hex: &str,
        recipient_kem_pub: &[u8],
        signer: &MlDsaSigner,
    ) -> TransitEnvelope {
        seal_welcome_envelope_with_epoch(
            payload,
            payload.epoch,
            sender_aid_hex,
            recipient_kem_pub,
            signer,
        )
        .await
    }

    /// Variant of `seal_welcome_envelope` that lets the caller set a
    /// distinct envelope.epoch (used in the AAD) from the inner
    /// `payload.epoch`. Exercises the cross-validation drop path.
    async fn seal_welcome_envelope_with_epoch(
        payload: &WelcomePayload,
        envelope_epoch: u32,
        sender_aid_hex: &str,
        recipient_kem_pub: &[u8],
        signer: &MlDsaSigner,
    ) -> TransitEnvelope {
        use crate::chat_crypto::{
            aead_seal, derive_aead_key, kem_encapsulate, message_aad, random_nonce,
            KDF_INFO_WELCOME,
        };
        let payload_bytes = serde_json::to_vec(payload).unwrap();
        let group_id_bytes: [u8; 32] = hex::decode(&payload.group_id_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let (kem_ct, ss) = kem_encapsulate(recipient_kem_pub).unwrap();
        let aead_key = derive_aead_key(&ss[..], KDF_INFO_WELCOME);
        let nonce = random_nonce(&mut OsRng);
        let aad = message_aad(&group_id_bytes, envelope_epoch);
        let ciphertext = aead_seal(&aead_key, &nonce, &payload_bytes, &aad).unwrap();
        let mut sender_bytes = [0u8; 32];
        hex::decode_to_slice(sender_aid_hex, &mut sender_bytes).unwrap();
        let mut env = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(sender_bytes),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: envelope_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct,
            sender_signature: Vec::new(),
        };
        let canonical = crate::chat_crypto::canonical_envelope_bytes(&env).unwrap();
        let mut sign_bytes =
            Vec::with_capacity(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len());
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        env.sender_signature = signer.sign(&sign_bytes).await.unwrap();
        env
    }

    // ── Task 6: in-band relay-hint refresh ───────────────────────────────────

    /// Build a real signed + encrypted Message envelope wrapping
    /// `payload`, sealed to `conv`'s current key and signed by
    /// `sender_signer`.
    async fn seal_message_envelope(
        conv: &Conversation,
        payload: &MessagePayload,
        sender_aid_hex: &str,
        sender_signer: &MlDsaSigner,
    ) -> TransitEnvelope {
        use crate::chat_crypto::{aead_seal, canonical_envelope_bytes, message_aad, random_nonce};
        let key = conv.current_key().unwrap();
        let group_id_bytes = conv.group_id_bytes().unwrap();
        let aad = message_aad(&group_id_bytes, conv.current_epoch);
        let payload_bytes = serde_json::to_vec(payload).unwrap();
        let nonce = random_nonce(&mut OsRng);
        let ciphertext = aead_seal(&key, &nonce, &payload_bytes, &aad).unwrap();
        let mut sender_bytes = [0u8; 32];
        hex::decode_to_slice(sender_aid_hex, &mut sender_bytes).unwrap();
        let mut env = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(sender_bytes),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
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

    #[tokio::test]
    async fn verified_inbound_with_newer_hint_epoch_updates_card_relays() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b = ConversationRegistry::new(
            layout_b.clone(),
            Arc::new(master_b),
            kdf_id_argon2(),
            Some(salt_b),
        );
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Alice sends a message carrying relay hints with epoch 1_000.
        let payload = MessagePayload {
            sender_name: Some("Alice".into()),
            body: "ping".into(),
            ts_ms: 1,
            message_id: Some("m1".into()),
            reply_to_message_id: None,
            attachment: None,
            advertised_relays: Some(vec!["wss://new-relay.example.com".to_owned()]),
            hint_epoch_ms: Some(1_000),
        };
        let env = seal_message_envelope(&conv, &payload, &aid_a, &alice_signer).await;
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(
            matches!(result, InboundDispatch::Message { .. }),
            "expected Message, got {result:?}",
        );

        // Alice's stored card on Bob's side must now carry the new relays.
        let card = StoredContactCard::load(&layout_b, &aid_a)
            .unwrap()
            .expect("card exists");
        assert_eq!(
            card.rendezvous_hints.as_ref().map(|h| &h.relays),
            Some(&vec!["wss://new-relay.example.com".to_owned()]),
            "relay slot must be updated by the verified inbound hint",
        );
        assert_eq!(
            card.last_hint_epoch_ms,
            Some(1_000),
            "hint epoch must be recorded",
        );
    }

    #[tokio::test]
    async fn verified_inbound_with_older_or_equal_hint_epoch_does_not_update_card() {
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b = ConversationRegistry::new(
            layout_b.clone(),
            Arc::new(master_b),
            kdf_id_argon2(),
            Some(salt_b),
        );
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Apply a fresh hint at epoch 5_000 to seed the stored watermark.
        let payload_fresh = MessagePayload {
            sender_name: Some("Alice".into()),
            body: "first".into(),
            ts_ms: 1,
            message_id: Some("m1".into()),
            reply_to_message_id: None,
            attachment: None,
            advertised_relays: Some(vec!["wss://current-relay.example.com".to_owned()]),
            hint_epoch_ms: Some(5_000),
        };
        let env_fresh = seal_message_envelope(&conv, &payload_fresh, &aid_a, &alice_signer).await;
        let _ = dispatch_inbound(env_fresh, &bob_id, &registry_b)
            .await
            .unwrap();

        // Simulate a stale/replayed hint at epoch 3_000 (strictly less).
        let payload_stale = MessagePayload {
            sender_name: Some("Alice".into()),
            body: "stale".into(),
            ts_ms: 2,
            message_id: Some("m2".into()),
            reply_to_message_id: None,
            attachment: None,
            advertised_relays: Some(vec!["wss://old-relay.example.com".to_owned()]),
            hint_epoch_ms: Some(3_000),
        };
        let env_stale = seal_message_envelope(&conv, &payload_stale, &aid_a, &alice_signer).await;
        let _ = dispatch_inbound(env_stale, &bob_id, &registry_b)
            .await
            .unwrap();

        // Card must still carry the original (higher-epoch) relay.
        let card = StoredContactCard::load(&layout_b, &aid_a)
            .unwrap()
            .expect("card exists");
        assert_eq!(
            card.rendezvous_hints.as_ref().map(|h| &h.relays),
            Some(&vec!["wss://current-relay.example.com".to_owned()]),
            "stale hint must not downgrade the stored relay list",
        );
        assert_eq!(
            card.last_hint_epoch_ms,
            Some(5_000),
            "epoch must stay at the higher value",
        );
    }

    #[tokio::test]
    async fn inbound_message_without_hint_fields_does_not_touch_card() {
        // Pre-Task-6 senders (no advertised_relays / hint_epoch_ms) must
        // leave the existing card untouched.
        let tmp_a = tempdir().unwrap();
        let (alice_signer, alice_id, _master_a, _salt_a, aid_a) =
            fresh_signer_with_identity(tmp_a.path());
        let tmp_b = tempdir().unwrap();
        let (_bob_signer, bob_id, master_b, salt_b, aid_b) =
            fresh_signer_with_identity(tmp_b.path());

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        install_card(&layout_b, &aid_a, &alice_signer, alice_id.kem_public_key());
        let registry_b = ConversationRegistry::new(
            layout_b.clone(),
            Arc::new(master_b),
            kdf_id_argon2(),
            Some(salt_b),
        );
        let welcome_outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        let payload_no_hint = MessagePayload {
            sender_name: Some("Alice".into()),
            body: "no hint".into(),
            ts_ms: 1,
            message_id: Some("m1".into()),
            reply_to_message_id: None,
            attachment: None,
            advertised_relays: None,
            hint_epoch_ms: None,
        };
        let env = seal_message_envelope(&conv, &payload_no_hint, &aid_a, &alice_signer).await;
        let _ = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();

        let card = StoredContactCard::load(&layout_b, &aid_a)
            .unwrap()
            .expect("card exists");
        assert_eq!(
            card.last_hint_epoch_ms, None,
            "no-hint message must leave last_hint_epoch_ms untouched",
        );
    }
}
