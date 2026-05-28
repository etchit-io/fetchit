//! Inbound envelope dispatch: distinguish Welcome vs Message, decrypt,
//! and surface a typed result.

use super::registry::ConversationRegistry;
use super::types::{
    now_ms, Conversation, MessagePayload, PriorKey, WelcomePayload, PRIOR_KEY_WINDOW_MS,
};
use crate::chat_crypto::{
    aead_open, derive_aead_key, kem_decapsulate, message_aad, KDF_INFO_WELCOME,
};
use crate::chat_identity::FetchitIdentity;
use crate::error::ChatError;
use fetchit_relay_proto::TransitEnvelope;

/// Inbound dispatch result.
#[derive(Clone, Debug)]
pub enum InboundDispatch {
    /// Installed a new conversation (from a welcome).
    Welcomed {
        /// The freshly installed conversation.
        conversation: Conversation,
    },
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
}

/// Dispatch an inbound envelope: distinguish Welcome vs Message,
/// decrypt, and surface a typed result.
///
/// # Errors
/// Hard errors (e.g. malformed envelope bytes). Soft errors (stale
/// epoch, decap fail) are returned as `InboundDispatch` variants.
pub async fn dispatch_inbound(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
) -> Result<InboundDispatch, ChatError> {
    let group_id_bytes = match &envelope.group_id {
        Some(g) => *g.as_bytes(),
        None => return Err(ChatError::Invalid("envelope has no group_id".into())),
    };
    let group_id_hex = hex::encode(group_id_bytes);

    if envelope.kem_ciphertext.is_empty() {
        // Message path.
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
        let aad = message_aad(&group_id_bytes, envelope.epoch);
        let Ok(plaintext) = aead_open(&key, &nonce, &envelope.ciphertext, &aad) else {
            return Ok(InboundDispatch::AeadOpenFailed {
                group_id_hex,
                epoch: envelope.epoch,
            });
        };
        let payload: MessagePayload = serde_json::from_slice(&plaintext)
            .map_err(|e| ChatError::Invalid(format!("message payload parse: {e}")))?;
        Ok(InboundDispatch::Message {
            group_id_hex,
            sender_agent_id_hex: hex::encode(envelope.sender_agent_id.as_bytes()),
            payload,
        })
    } else {
        // Welcome path.
        let Ok(ss) = kem_decapsulate(identity.kem_secret_key(), &envelope.kem_ciphertext) else {
            return Ok(InboundDispatch::KemDecapFailed);
        };
        let aead_key = derive_aead_key(&ss, KDF_INFO_WELCOME);
        if envelope.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&envelope.nonce);
        let aad = message_aad(&group_id_bytes, envelope.epoch);
        let Ok(plaintext) = aead_open(&aead_key, &nonce, &envelope.ciphertext, &aad) else {
            return Ok(InboundDispatch::AeadOpenFailed {
                group_id_hex,
                epoch: envelope.epoch,
            });
        };
        let payload: WelcomePayload = serde_json::from_slice(&plaintext)
            .map_err(|e| ChatError::Invalid(format!("welcome payload parse: {e}")))?;
        let existing = registry.get(&group_id_hex).await?;
        match existing {
            Some(conv) if envelope.epoch <= conv.current_epoch => {
                // Stale or current — no-op.
                Ok(InboundDispatch::Welcomed { conversation: conv })
            }
            Some(mut conv) => {
                // Higher epoch — adopt new key and member list. Don't
                // advance_epoch(); we're not generating a fresh key here,
                // we're adopting the one carried in the welcome. We do
                // push the OLD key into prior_keys so in-flight messages
                // can still decrypt for up to PRIOR_KEY_WINDOW_MS.
                let now = now_ms();
                conv.prior_keys.push(PriorKey {
                    epoch: conv.current_epoch,
                    key_b64: conv.current_key_b64.clone(),
                    expires_at_ms: now + PRIOR_KEY_WINDOW_MS,
                });
                conv.current_epoch = payload.epoch;
                conv.current_key_b64 = payload.current_key_b64.clone();
                conv.members = payload.members.clone();
                conv.name = payload.name.clone();
                conv.last_rekey_at_ms = now;
                conv.sweep_prior_keys();
                registry.save(&conv).await?;
                Ok(InboundDispatch::Rekeyed { conversation: conv })
            }
            None => {
                let conv = Conversation::from_welcome(payload);
                registry.save(&conv).await?;
                Ok(InboundDispatch::Welcomed { conversation: conv })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::outbound::{build_message_outbox, build_welcome_outbox};
    use super::super::types::{Member, MemberDevice, MemberDeviceStatus};
    use super::*;
    use crate::at_rest::{
        fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource, ARGON_SALT_LEN,
    };
    use crate::local_store::StoreLayout;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use fetchit_relay_client::MlDsaSigner;
    use fetchit_relay_proto::{AgentId, EnvelopeKind, GroupId, MachineId};
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn local_member(agent_id_hex: &str, kem_pub_b64: &str) -> Member {
        Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: agent_id_hex.to_owned(),
                kem_public_key_b64: kem_pub_b64.to_owned(),
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
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
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

    #[tokio::test]
    async fn welcome_round_trip_between_two_identities() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);

        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let alice_signer = MlDsaSigner::generate().unwrap();

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        assert_eq!(outbox.len(), 1);

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
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
            }
            other => panic!("expected Welcomed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn message_round_trip_after_welcome() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let alice_signer = MlDsaSigner::generate().unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
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
            &alice_id,
            [0u8; 32],
            &alice_signer,
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
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let env = TransitEnvelope {
            version: 2,
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
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(matches!(result, InboundDispatch::StaleEpoch { .. }));
    }
}
