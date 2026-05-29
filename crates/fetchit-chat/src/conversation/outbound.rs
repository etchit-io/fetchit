//! Outbound envelope construction for Welcome, Message, and `DeliveryReceipt` payloads.

use super::types::{now_ms, Conversation, DeliveryReceiptPayload, MessagePayload, WelcomePayload};
use crate::chat_crypto::{
    aead_seal, canonical_envelope_bytes, derive_aead_key, kem_encapsulate, message_aad,
    random_nonce, KDF_INFO_WELCOME, KEM_PUBLIC_KEY_LEN, SIGN_DOMAIN_ENVELOPE,
};
use crate::chat_identity::FetchitIdentity;
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_proto::{AgentId, EnvelopeKind, GroupId, MachineId, TransitEnvelope};
use rand::rngs::OsRng;

/// Tuple convenience: an outbound envelope paired with its recipient.
#[derive(Clone, Debug)]
pub struct OutboundEnvelope {
    /// The recipient agent id (one entry per recipient device).
    pub recipient_agent_id: AgentId,
    /// The signed, sealed envelope.
    pub envelope: TransitEnvelope,
}

/// Build the set of Welcome envelopes Alice needs to send when starting
/// a new conversation. One envelope per recipient device.
///
/// The local device's `agent_public_key_b64` is populated from the
/// signer's public key before the payload is encoded, so first-contact
/// recipients can verify the envelope signature against the
/// self-attested pubkey (bound to `sender_agent_id` via the
/// `AUTONOMI_PEER_ID_V2` derivation).
///
/// # Errors
/// KEM / AEAD / signing errors.
pub async fn build_welcome_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let local_agent_hex = identity.agent_id_hex().to_owned();
    let signer_pk_b64 = B64.encode(signer.public_key());
    let mut members_for_payload = conv.members.clone();
    for member in &mut members_for_payload {
        for device in &mut member.devices {
            if device.agent_id_hex == local_agent_hex {
                device.agent_public_key_b64 = Some(signer_pk_b64.clone());
            }
        }
    }
    let payload = WelcomePayload {
        group_id_hex: conv.group_id_hex.clone(),
        current_key_b64: conv.current_key_b64.clone(),
        epoch: conv.current_epoch,
        members: members_for_payload,
        name: conv.name.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ChatError::Invalid(format!("welcome serialize: {e}")))?;

    let group_id_bytes = conv.group_id_bytes()?;
    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let mut out = Vec::new();

    for device in conv.fanout_devices(&local_agent_hex) {
        let kem_pub = B64
            .decode(&device.kem_public_key_b64)
            .map_err(|e| ChatError::Invalid(format!("device kem b64: {e}")))?;
        if kem_pub.len() != KEM_PUBLIC_KEY_LEN {
            return Err(ChatError::Invalid("device kem key length".into()));
        }
        let (kem_ct, ss) = kem_encapsulate(&kem_pub)?;
        let aead_key = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let nonce = random_nonce(&mut OsRng);
        let aad = message_aad(&group_id_bytes, conv.current_epoch);
        let ciphertext = aead_seal(&aead_key, &nonce, &payload_bytes, &aad)?;

        let mut recipient_agent = [0u8; 32];
        hex::decode_to_slice(&device.agent_id_hex, &mut recipient_agent)
            .map_err(|e| ChatError::Invalid(format!("recipient agent_id hex: {e}")))?;

        let mut env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes(local_machine_id),
            timestamp_ms: now_ms(),
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct,
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

        out.push(OutboundEnvelope {
            recipient_agent_id: AgentId::from_bytes(recipient_agent),
            envelope: env,
        });
    }
    Ok(out)
}

/// Build outbound Message envelopes for a chat message in `conv`.
///
/// `message_id` is the logical id assigned to *this* send — every
/// fanout envelope carries it, so a recipient's `DeliveryReceipt`
/// always echoes the same id regardless of which device decoded the
/// envelope.
///
/// # Errors
/// AEAD or signing errors.
pub async fn build_message_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    body: &str,
    sender_name: &str,
    message_id: &str,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let now = now_ms();
    let payload = MessagePayload {
        sender_name: Some(sender_name.to_owned()),
        body: body.to_owned(),
        ts_ms: now,
        message_id: Some(message_id.to_owned()),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ChatError::Invalid(format!("message serialize: {e}")))?;

    let key = conv.current_key()?;
    let group_id_bytes = conv.group_id_bytes()?;
    let aad = message_aad(&group_id_bytes, conv.current_epoch);

    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let local_agent_hex = identity.agent_id_hex().to_owned();
    let mut out = Vec::new();
    for device in conv.fanout_devices(&local_agent_hex) {
        let nonce = random_nonce(&mut OsRng);
        let ciphertext = aead_seal(&key, &nonce, &payload_bytes, &aad)?;
        let mut recipient_agent = [0u8; 32];
        hex::decode_to_slice(&device.agent_id_hex, &mut recipient_agent)
            .map_err(|e| ChatError::Invalid(format!("recipient hex: {e}")))?;

        let mut env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes(local_machine_id),
            timestamp_ms: now,
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
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

        out.push(OutboundEnvelope {
            recipient_agent_id: AgentId::from_bytes(recipient_agent),
            envelope: env,
        });
    }
    Ok(out)
}

/// Build a single delivery-receipt envelope addressed to
/// `recipient_agent_id_hex` (the original `Message`'s sender).
///
/// The receipt rides the conversation's current symmetric key with the
/// same AAD shape as a message — `EnvelopeKind::DeliveryReceipt`
/// distinguishes it on the wire so the inbound dispatcher routes it to
/// the receipt branch rather than the message branch.
///
/// # Errors
/// AEAD or signing errors.
pub async fn build_receipt_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    message_id: &str,
    received_at_ms: u64,
    recipient_agent_id_hex: &str,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let payload = DeliveryReceiptPayload {
        message_id: message_id.to_owned(),
        received_at_ms,
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ChatError::Invalid(format!("receipt serialize: {e}")))?;

    let key = conv.current_key()?;
    let group_id_bytes = conv.group_id_bytes()?;
    let aad = message_aad(&group_id_bytes, conv.current_epoch);

    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;
    let mut recipient_agent = [0u8; 32];
    hex::decode_to_slice(recipient_agent_id_hex, &mut recipient_agent)
        .map_err(|e| ChatError::Invalid(format!("recipient hex: {e}")))?;

    let nonce = random_nonce(&mut OsRng);
    let ciphertext = aead_seal(&key, &nonce, &payload_bytes, &aad)?;
    let mut env = TransitEnvelope {
        version: 2,
        kind: EnvelopeKind::DeliveryReceipt,
        group_id: Some(GroupId::from_bytes(group_id_bytes)),
        tenant_id: None,
        sender_agent_id: AgentId::from_bytes(local_agent_bytes),
        sender_machine_id: MachineId::from_bytes(local_machine_id),
        timestamp_ms: now_ms(),
        epoch: conv.current_epoch,
        ciphertext,
        nonce: nonce.to_vec(),
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

    Ok(vec![OutboundEnvelope {
        recipient_agent_id: AgentId::from_bytes(recipient_agent),
        envelope: env,
    }])
}
