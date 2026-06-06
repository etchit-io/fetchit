//! Owner-side bridge dispatchers for group-metadata events.
//!
//! Each `dispatch_*_bridge` function builds the JSON event body, resolves
//! per-recipient KEM pubkeys from stored share-cards, seals one
//! [`crate::conversation::OutboundEnvelope`] per recipient, and routes
//! them through the [`crate::transport::Router`].
//!
//! Recipients whose share-card has not yet been imported are skipped
//! with a `WARN`-level tracing event. That matches the P1.A gate
//! upstream specifies for the bridge path.

use crate::conversation::OutboundEnvelope as ConvEnvelope;
use crate::error::{ChatError, Result};
use crate::groups::bridge::{dispatch_owner_broadcast, recipient_kem_key, OwnerBroadcastInputs};
use crate::groups::bridge_member_removed::{build_member_removed_event, MemberRemovedInputs};
use crate::groups::bridge_member_role_updated::{
    build_member_role_updated_event, MemberRoleUpdatedInputs,
};
use crate::identity::AgentId;
use crate::local_store::StoreLayout;
use crate::transport::{OutboundEnvelope, OutboundKind, Router};

/// Build sealed [`ConvEnvelope`]s for a `MemberRemoved` fan-out.
///
/// Filters `actor_agent_id` and `removed_agent_id` out of
/// `active_member_aids`. Recipients missing a share-card are skipped
/// (logged at `WARN`); any other error propagates.
///
/// This is the pure inner function; [`dispatch_member_removed_bridge`]
/// wraps it and routes via [`Router`].
///
/// # Errors
/// - [`ChatError::Invalid`] on share-card b64 decode failure.
/// - Any error surfaced by the KEM/AEAD/signing path in
///   [`dispatch_owner_broadcast`].
#[allow(clippy::too_many_arguments)]
pub async fn build_member_removed_envelopes<S>(
    signer: &S,
    layout: &StoreLayout,
    group_id: &str,
    metadata_topic: &str,
    revision: u64,
    actor_agent_id: [u8; 32],
    removed_agent_id: [u8; 32],
    treekem_commit_b64: Option<&str>,
    treekem_epoch: Option<u64>,
    commit_json: Option<serde_json::Value>,
    active_member_aids: &[[u8; 32]],
    local_machine_id: [u8; 32],
) -> Result<Vec<ConvEnvelope>>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    let actor_hex = hex::encode(actor_agent_id);
    let removed_hex = hex::encode(removed_agent_id);

    let event = build_member_removed_event(&MemberRemovedInputs {
        group_id,
        revision,
        actor: &actor_hex,
        agent_id: &removed_hex,
        treekem_commit_b64,
        treekem_epoch,
        commit_json,
    });

    let mut recipients: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(active_member_aids.len());
    for aid in active_member_aids {
        if aid == &actor_agent_id || aid == &removed_agent_id {
            continue;
        }
        let aid_hex = hex::encode(aid);
        match recipient_kem_key(layout, &aid_hex) {
            Ok(kem) => recipients.push((*aid, kem)),
            Err(ChatError::ShareCardMissing { .. }) => {
                log::warn!("MemberRemoved bridge: share-card missing for {aid_hex}; skipping");
            }
            Err(e) => return Err(e),
        }
    }

    dispatch_owner_broadcast(
        signer,
        &OwnerBroadcastInputs {
            topic: metadata_topic.to_owned(),
            event_json: event,
            recipients_kem: &recipients,
            local_agent_id: actor_agent_id,
            local_machine_id,
        },
    )
    .await
}

/// Fan out a `MemberRemoved` bridge envelope to every active member
/// except the actor and the removed peer.
///
/// Recipients whose share-card has not been imported are skipped with a
/// `WARN` log. Other errors (bad b64, KEM/AEAD failure, signer error)
/// propagate as hard failures.
///
/// # Errors
/// - [`ChatError::ShareCardMissing`] is swallowed (warn-logged); see
///   [`build_member_removed_envelopes`] for full error list.
/// - [`ChatError::NoTransportAvailable`] / relay errors forwarded from
///   [`Router::send`].
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_member_removed_bridge<S>(
    signer: &S,
    router: &Router,
    layout: &StoreLayout,
    group_id: &str,
    metadata_topic: &str,
    revision: u64,
    actor_agent_id: [u8; 32],
    removed_agent_id: [u8; 32],
    treekem_commit_b64: Option<&str>,
    treekem_epoch: Option<u64>,
    commit_json: Option<serde_json::Value>,
    active_member_aids: &[[u8; 32]],
    local_machine_id: [u8; 32],
) -> Result<()>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    let envelopes = build_member_removed_envelopes(
        signer,
        layout,
        group_id,
        metadata_topic,
        revision,
        actor_agent_id,
        removed_agent_id,
        treekem_commit_b64,
        treekem_epoch,
        commit_json,
        active_member_aids,
        local_machine_id,
    )
    .await?;

    for env in envelopes {
        let recipient = AgentId(hex::encode(env.recipient_agent_id.as_bytes()));
        let transport_out = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: Some(local_machine_id),
            payload: Vec::new(),
            timestamp_ms: env.envelope.timestamp_ms,
            transit: Some(env.envelope),
        };
        router.send(&recipient, transport_out).await?;
    }
    Ok(())
}

/// Build sealed [`ConvEnvelope`]s for a `MemberRoleUpdated` fan-out.
///
/// Filters only `actor_agent_id` from `active_member_aids`. The target
/// member whose role changed still receives the broadcast -- they need to
/// know their role has been updated. Recipients missing a share-card are
/// skipped (logged at `WARN`); any other error propagates.
///
/// This is the pure inner function; [`dispatch_member_role_updated_bridge`]
/// wraps it and routes via [`Router`].
///
/// # Errors
/// - [`ChatError::Invalid`] on share-card b64 decode failure.
/// - Any error surfaced by the KEM/AEAD/signing path in
///   [`dispatch_owner_broadcast`].
#[allow(clippy::too_many_arguments)]
pub async fn build_member_role_updated_envelopes<S>(
    signer: &S,
    layout: &StoreLayout,
    group_id: &str,
    metadata_topic: &str,
    revision: u64,
    actor_agent_id: [u8; 32],
    target_agent_id: [u8; 32],
    new_role: &str,
    commit_json: Option<serde_json::Value>,
    active_member_aids: &[[u8; 32]],
    local_machine_id: [u8; 32],
) -> Result<Vec<ConvEnvelope>>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    let actor_hex = hex::encode(actor_agent_id);
    let target_hex = hex::encode(target_agent_id);

    let event = build_member_role_updated_event(&MemberRoleUpdatedInputs {
        group_id,
        revision,
        actor: &actor_hex,
        agent_id: &target_hex,
        role: new_role,
        commit_json,
    });

    let mut recipients: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(active_member_aids.len());
    for aid in active_member_aids {
        // Only the actor is excluded; the target still receives the broadcast.
        if aid == &actor_agent_id {
            continue;
        }
        let aid_hex = hex::encode(aid);
        match recipient_kem_key(layout, &aid_hex) {
            Ok(kem) => recipients.push((*aid, kem)),
            Err(ChatError::ShareCardMissing { .. }) => {
                log::warn!("MemberRoleUpdated bridge: share-card missing for {aid_hex}; skipping");
            }
            Err(e) => return Err(e),
        }
    }

    dispatch_owner_broadcast(
        signer,
        &OwnerBroadcastInputs {
            topic: metadata_topic.to_owned(),
            event_json: event,
            recipients_kem: &recipients,
            local_agent_id: actor_agent_id,
            local_machine_id,
        },
    )
    .await
}

/// Fan out a `MemberRoleUpdated` bridge envelope to every active member
/// except the actor. The target member whose role changed is included.
///
/// Recipients whose share-card has not been imported are skipped with a
/// `WARN` log. Other errors (bad b64, KEM/AEAD failure, signer error)
/// propagate as hard failures.
///
/// # Errors
/// - [`ChatError::ShareCardMissing`] is swallowed (warn-logged); see
///   [`build_member_role_updated_envelopes`] for full error list.
/// - [`ChatError::NoTransportAvailable`] / relay errors forwarded from
///   [`Router::send`].
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_member_role_updated_bridge<S>(
    signer: &S,
    router: &Router,
    layout: &StoreLayout,
    group_id: &str,
    metadata_topic: &str,
    revision: u64,
    actor_agent_id: [u8; 32],
    target_agent_id: [u8; 32],
    new_role: &str,
    commit_json: Option<serde_json::Value>,
    active_member_aids: &[[u8; 32]],
    local_machine_id: [u8; 32],
) -> Result<()>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    let envelopes = build_member_role_updated_envelopes(
        signer,
        layout,
        group_id,
        metadata_topic,
        revision,
        actor_agent_id,
        target_agent_id,
        new_role,
        commit_json,
        active_member_aids,
        local_machine_id,
    )
    .await?;

    for env in envelopes {
        let recipient = AgentId(hex::encode(env.recipient_agent_id.as_bytes()));
        let transport_out = OutboundEnvelope {
            kind: OutboundKind::Dm,
            from_machine_id: Some(local_machine_id),
            payload: Vec::new(),
            timestamp_ms: env.envelope.timestamp_ms,
            transit: Some(env.envelope),
        };
        router.send(&recipient, transport_out).await?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chat_crypto::kem_keygen;
    use crate::messages::StoredContactCard;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use fetchit_relay_proto::EnvelopeKind;

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

    fn store_card(layout: &StoreLayout, aid: [u8; 32], kem_pub: &[u8]) {
        let card = StoredContactCard {
            agent_id_hex: hex::encode(aid),
            display_name: "peer".into(),
            kem_public_key_b64: B64.encode(kem_pub),
            agent_public_key_b64: None,
        };
        card.save(layout).unwrap();
    }

    /// Actor (aid-a) and removed peer (aid-b) are filtered out.
    /// Only aid-c receives an envelope. The sealed ciphertext unseals
    /// to a JSON event with `"event": "member_removed"`.
    #[tokio::test]
    async fn dispatch_member_removed_bridge_skips_actor_and_removed_member() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let aid_a = [0xaau8; 32];
        let aid_b = [0xbbu8; 32];
        let aid_c = [0xccu8; 32];

        let (pk_a, _) = kem_keygen().unwrap();
        let (pk_b, _) = kem_keygen().unwrap();
        let (pk_c, sk_c) = kem_keygen().unwrap();

        // Only store cards for the three peers; aid-a and aid-b will be
        // skipped by the filter before the card lookup runs.
        store_card(&layout, aid_a, &pk_a);
        store_card(&layout, aid_b, &pk_b);
        store_card(&layout, aid_c, &pk_c);

        let envelopes = build_member_removed_envelopes(
            &StubSigner,
            &layout,
            "group-1",
            "x0x.named_group/group-1/metadata",
            7,
            aid_a, // actor
            aid_b, // removed
            None,
            None,
            None,
            &[aid_a, aid_b, aid_c],
            [0x01u8; 32],
        )
        .await
        .unwrap();

        assert_eq!(envelopes.len(), 1, "exactly one envelope: aid-c only");

        let env = &envelopes[0];
        assert_eq!(
            env.envelope.kind,
            EnvelopeKind::X0xdGroupMetadataEvent,
            "kind must be X0xdGroupMetadataEvent"
        );
        assert_eq!(
            env.recipient_agent_id.as_bytes(),
            &aid_c,
            "sole recipient is aid-c"
        );

        // Unseal and verify the inner JSON carries "event": "member_removed".
        let wrapper = crate::groups::bridge::unseal_bridge_wrapper(
            &sk_c,
            &env.envelope.kem_ciphertext,
            &env.envelope.nonce,
            &env.envelope.ciphertext,
        )
        .unwrap();
        let payload_bytes = B64.decode(&wrapper.payload_b64).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(inner["event"], "member_removed", "inner event field");
        assert_eq!(inner["group_id"], "group-1");
        assert_eq!(inner["actor"], hex::encode(aid_a));
        assert_eq!(inner["agent_id"], hex::encode(aid_b));
        assert_eq!(inner["revision"], 7u64);
    }

    /// When the share-card for a non-excluded recipient is missing,
    /// that peer is silently skipped and no error is returned.
    #[tokio::test]
    async fn dispatch_member_removed_bridge_skips_missing_share_card() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let aid_a = [0x01u8; 32];
        let aid_b = [0x02u8; 32];
        let aid_c = [0x03u8; 32]; // no card stored

        let (pk_c, _) = kem_keygen().unwrap();
        // Only store a card for aid_c; aid_b has none.
        store_card(&layout, aid_c, &pk_c);

        // aid_a is actor, aid_b is removed; both filtered before lookup.
        // aid_c has a card but there's nothing else in active_member_aids,
        // so aid_c should produce an envelope.
        // Introduce aid_d with no card to exercise the skip path.
        let aid_d = [0x04u8; 32];
        let (pk_c2, _) = kem_keygen().unwrap();
        store_card(&layout, aid_c, &pk_c2);

        let envelopes = build_member_removed_envelopes(
            &StubSigner,
            &layout,
            "g",
            "topic",
            1,
            aid_a,
            aid_b,
            None,
            None,
            None,
            &[aid_a, aid_b, aid_c, aid_d],
            [0u8; 32],
        )
        .await
        .unwrap();

        // aid_a and aid_b skipped (filter); aid_d skipped (no card).
        // aid_c has a card: 1 envelope.
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].recipient_agent_id.as_bytes(), &aid_c);
    }

    /// Actor (aid-a) is filtered out. Target (aid-b) and aid-c both receive
    /// the role-change broadcast. Inner JSON must carry `"event":
    /// "member_role_updated"` and `"role": "admin"`.
    #[tokio::test]
    async fn dispatch_member_role_updated_bridge_skips_actor_includes_target() {
        let dir = tempfile::tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();

        let aid_a = [0xaau8; 32];
        let aid_b = [0xbbu8; 32];
        let aid_c = [0xccu8; 32];

        let (pk_a, _) = kem_keygen().unwrap();
        let (pk_b, sk_b) = kem_keygen().unwrap();
        let (pk_c, sk_c) = kem_keygen().unwrap();

        store_card(&layout, aid_a, &pk_a);
        store_card(&layout, aid_b, &pk_b);
        store_card(&layout, aid_c, &pk_c);

        let envelopes = build_member_role_updated_envelopes(
            &StubSigner,
            &layout,
            "group-1",
            "x0x.named_group/group-1/metadata",
            3,
            aid_a, // actor -- must be excluded
            aid_b, // target -- must be included
            "admin",
            None,
            &[aid_a, aid_b, aid_c],
            [0x01u8; 32],
        )
        .await
        .unwrap();

        assert_eq!(envelopes.len(), 2, "aid-b and aid-c receive the broadcast");

        let recipient_ids: Vec<[u8; 32]> = envelopes
            .iter()
            .map(|e| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(e.recipient_agent_id.as_bytes());
                arr
            })
            .collect();
        assert!(
            recipient_ids.contains(&aid_b),
            "aid-b (target) must receive"
        );
        assert!(recipient_ids.contains(&aid_c), "aid-c must receive");

        for env in &envelopes {
            assert_eq!(
                env.envelope.kind,
                EnvelopeKind::X0xdGroupMetadataEvent,
                "kind must be X0xdGroupMetadataEvent"
            );

            let aid_bytes: [u8; 32] = {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(env.recipient_agent_id.as_bytes());
                arr
            };
            let sk = if aid_bytes == aid_b { &sk_b } else { &sk_c };

            let wrapper = crate::groups::bridge::unseal_bridge_wrapper(
                sk,
                &env.envelope.kem_ciphertext,
                &env.envelope.nonce,
                &env.envelope.ciphertext,
            )
            .unwrap();
            let payload_bytes = B64.decode(&wrapper.payload_b64).unwrap();
            let inner: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
            assert_eq!(inner["event"], "member_role_updated");
            assert_eq!(inner["role"], "admin");
            assert_eq!(inner["group_id"], "group-1");
            assert_eq!(inner["actor"], hex::encode(aid_a));
            assert_eq!(inner["agent_id"], hex::encode(aid_b));
        }
    }
}
