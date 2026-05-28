//! Inbound envelope dispatch: distinguish Welcome vs Message, decrypt,
//! and surface a typed result.

use super::registry::ConversationRegistry;
use super::types::{
    now_ms, Conversation, MessagePayload, PriorKey, WelcomePayload, PRIOR_KEY_WINDOW_MS,
};
use crate::chat_crypto::{
    aead_open, canonical_envelope_bytes, derive_aead_key, kem_decapsulate, message_aad,
    ml_dsa_verify, KDF_INFO_WELCOME, SIGN_DOMAIN_ENVELOPE,
};
use crate::chat_identity::FetchitIdentity;
use crate::error::ChatError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_proto::TransitEnvelope;

/// Inbound dispatch result.
#[derive(Clone, Debug)]
pub enum InboundDispatch {
    /// Installed a new conversation (from a welcome).
    Welcomed {
        /// The freshly installed conversation.
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
    /// Envelope dropped without decryption. `kind` is one of:
    /// `"no-card"` (sender's card isn't on file),
    /// `"no-pubkey"` (card exists but doesn't carry an ML-DSA pubkey),
    /// `"bad-signature"` (signature verification failed),
    /// `"rekey-from-non-member"` (signature was valid but the sender
    /// isn't a current member of the conversation they're trying to
    /// rekey).
    Dropped {
        /// Short reason tag.
        kind: String,
        /// Hex-encoded sender agent id from the envelope.
        sender: String,
    },
}

/// Outcome of the verify prelude: either an early `Dropped` result, or
/// the sender's hex agent id ready for the main dispatch path to reuse.
enum VerifyOutcome {
    Drop(InboundDispatch),
    Ok { sender_agent_hex: String },
}

/// Look up the sender's stored card and verify the envelope's ML-DSA
/// signature against the agent's public key. Runs BEFORE any KEM decap
/// or AEAD open so unauthenticated envelopes can't trigger the
/// key-substitution rekey path or surface fake messages.
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
    Ok(VerifyOutcome::Ok { sender_agent_hex })
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

    let sender_agent_hex = match verify_sender(&envelope, registry)? {
        VerifyOutcome::Drop(d) => return Ok(d),
        VerifyOutcome::Ok { sender_agent_hex } => sender_agent_hex,
    };

    if envelope.kem_ciphertext.is_empty() {
        dispatch_message(envelope, registry, group_id_bytes, group_id_hex).await
    } else {
        dispatch_welcome(
            envelope,
            identity,
            registry,
            group_id_bytes,
            group_id_hex,
            sender_agent_hex,
        )
        .await
    }
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
}

async fn dispatch_welcome(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
    group_id_bytes: [u8; 32],
    group_id_hex: String,
    sender_agent_hex: String,
) -> Result<InboundDispatch, ChatError> {
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
            // Drop `conv` explicitly — we read it just to check the epoch
            // comparison; no caller-visible payload is needed for an
            // ignored welcome.
            let _ = conv;
            Ok(InboundDispatch::WelcomeIgnored)
        }
        Some(mut conv) => {
            // Higher epoch — adopt new key and member list. Don't
            // advance_epoch(); we're not generating a fresh key here,
            // we're adopting the one carried in the welcome. We do
            // push the OLD key into prior_keys so in-flight messages
            // can still decrypt for up to PRIOR_KEY_WINDOW_MS.
            //
            // Defence in depth: even a valid signature isn't enough
            // to swap the conversation key. The sender must already
            // be a member of the conversation they're rekeying.
            let sender_already_member = conv
                .members
                .iter()
                .flat_map(|m| m.devices.iter())
                .any(|d| d.agent_id_hex == sender_agent_hex);
            if !sender_already_member {
                return Ok(InboundDispatch::Dropped {
                    kind: "rekey-from-non-member".to_owned(),
                    sender: sender_agent_hex,
                });
            }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::outbound::{build_message_outbox, build_welcome_outbox};
    use super::super::types::{Member, MemberDevice, MemberDeviceStatus};
    use super::*;
    use crate::at_rest::{
        fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource, ARGON_SALT_LEN,
    };
    use crate::chat_crypto::random_symmetric_key;
    use crate::local_store::StoreLayout;
    use crate::messages::StoredContactCard;
    use base64::engine::general_purpose::STANDARD as B64;
    use fetchit_relay_client::{MlDsaSigner, Signer};
    use fetchit_relay_proto::{AgentId, EnvelopeKind, GroupId, MachineId};
    use rand::rngs::OsRng;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::tempdir;

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
        };
        card.save(layout).unwrap();
    }

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
        // Install a synthetic card so the verify prelude passes; the
        // test still targets the Message-path StaleEpoch branch.
        let synthetic_signer = MlDsaSigner::generate().unwrap();
        let sender_hex = hex::encode([0xaa; 32]);
        let synthetic_card = StoredContactCard {
            agent_id_hex: sender_hex.clone(),
            display_name: "Synthetic".to_owned(),
            kem_public_key_b64: B64.encode(vec![0u8; 1184]),
            agent_public_key_b64: Some(B64.encode(synthetic_signer.public_key())),
        };
        synthetic_card.save(&layout_b).unwrap();
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let mut env = TransitEnvelope {
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
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let mut conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let alice_signer = MlDsaSigner::generate().unwrap();

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
    async fn dispatch_rejects_envelope_with_no_card() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let alice_signer = MlDsaSigner::generate().unwrap();
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        // Intentionally NO card saved for Alice on Bob's side.
        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(result, InboundDispatch::Dropped { ref kind, .. } if kind == "no-card"),
            "expected Dropped(no-card), got {result:?}",
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_envelope_with_no_pubkey_card() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let alice_signer = MlDsaSigner::generate().unwrap();
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();

        let alice_card_no_pk = StoredContactCard {
            agent_id_hex: aid_a.clone(),
            display_name: "Alice".to_owned(),
            kem_public_key_b64: B64.encode(alice_id.kem_public_key()),
            agent_public_key_b64: None,
        };
        alice_card_no_pk.save(&layout_b).unwrap();

        let registry_b =
            ConversationRegistry::new(layout_b, Arc::new(master_b), kdf_id_argon2(), Some(salt_b));
        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        assert!(
            matches!(result, InboundDispatch::Dropped { ref kind, .. } if kind == "no-pubkey"),
            "expected Dropped(no-pubkey), got {result:?}",
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_envelope_with_bad_signature() {
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let alice_signer = MlDsaSigner::generate().unwrap();
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
        let aid_a = "aa".repeat(32);
        let (alice_id, _master_a, _salt_a) = fixture_identity(tmp_a.path(), &aid_a);
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b);
        let tmp_c = tempdir().unwrap();
        let aid_c = "cc".repeat(32);
        let (carol_id, _master_c, _salt_c) = fixture_identity(tmp_c.path(), &aid_c);
        let alice_signer = MlDsaSigner::generate().unwrap();
        let carol_signer = MlDsaSigner::generate().unwrap();

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
}
