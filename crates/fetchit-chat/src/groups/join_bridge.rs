//! Engine A joiner-emit core: capture THIS agent's own native
//! `member_joined` off the SSE stream after a `POST /groups/join`, so the
//! Client can bridge it (verbatim, byte-identical) to a NAT'd owner.
//!
//! The owner's x0xd verifies the event's signature against the joiner key
//! and consumes the single-use invite secret on apply, so the bridged
//! event MUST be x0xd's native joiner-signed bytes (not a reconstruction).
//! This module is the pure/testable half (capture + owner extraction);
//! the runtime seal + `Router::send` orchestration lives on `Client`.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use futures_util::{Stream, StreamExt};

use crate::card::RendezvousHintsV1;
use crate::error::{ChatError, Result};
use crate::events::Event;
use crate::groups::bridge::{seal_and_sign_bridge_wrapper, X0xdGroupMetadataEventWrapper};
use crate::groups::GroupId;
use crate::groups_reachability::is_self_member_joined_for_group;
use crate::identity::AgentId;
use crate::transport::{OutboundEnvelope, OutboundKind, Router};

/// Wall-clock to wait for x0xd to publish the joiner's own `member_joined`
/// after `POST /groups/join` before giving up the bridge. The event fires
/// almost immediately; the window only covers daemon/gossip scheduling.
pub const SELF_JOIN_CAPTURE_TIMEOUT: Duration = Duration::from_secs(15);

/// The captured native event to bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedSelfJoin {
    /// x0xd metadata topic the event was published on (-> wrapper topic).
    pub topic: String,
    /// Raw signed `member_joined` event bytes (-> base64 wrapper payload).
    pub payload: Vec<u8>,
}

/// Extract the inviter (group owner) agent-id hex from a captured
/// `member_joined` payload. Engine A's joiner-emit bridges the event to
/// this owner; the owner is the event's `inviter_agent_id`.
#[must_use]
pub fn inviter_agent_id_from_member_joined(payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    v.get("inviter_agent_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Extract the joined member (the joiner) agent-id hex from a captured
/// `member_joined` payload. The owner-side reply
/// (`Client::reply_to_bridged_join`) addresses the local x0xd
/// `join-result` lookup and the bridged-back `MemberAdded` to this
/// member.
#[must_use]
pub fn member_agent_id_from_member_joined(payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    v.get("member_agent_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Consume `stream` until this agent's own `member_joined` for
/// `target_group` arrives (per [`is_self_member_joined_for_group`]),
/// returning the captured event to bridge. One-shot: returns the FIRST
/// match -- x0xd replays the event 2-3x but we bridge once. Bounded by
/// `timeout` so a join that never publishes can't hang the caller.
///
/// # Errors
/// - [`ChatError::Invalid`] on timeout, or if the stream ends before a
///   self `member_joined` is seen.
/// - The stream's own error, propagated.
pub async fn capture_self_member_joined<S>(
    stream: &mut S,
    target_group: &GroupId,
    local_agent_hex: &str,
    timeout: Duration,
) -> Result<CapturedSelfJoin>
where
    S: Stream<Item = Result<Event>> + Unpin,
{
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => {
                return Err(ChatError::Invalid(format!(
                    "join-bridge: no self member_joined for group {} within {}s",
                    target_group.as_str(),
                    timeout.as_secs(),
                )));
            }
            next = stream.next() => {
                let Some(item) = next else {
                    return Err(ChatError::Invalid(
                        "join-bridge: event stream ended before self member_joined".to_owned(),
                    ));
                };
                let Event::GossipMessage { topic, payload, from } = item? else {
                    continue;
                };
                if is_self_member_joined_for_group(
                    &topic,
                    &payload,
                    from.as_ref(),
                    local_agent_hex,
                    target_group,
                ) {
                    return Ok(CapturedSelfJoin { topic, payload });
                }
            }
        }
    }
}

/// Seal + ML-DSA-65 sign the captured native `member_joined` and send it
/// to the group owner over the relay-routed transport, with the joiner's
/// own ML-KEM-768 public key attached as `joiner_kem_pubkey`.
///
/// The payload is bridged **byte-identical** -- the joiner-signed event
/// x0xd minted -- so the owner's `POST /publish` re-injects exactly what
/// x0xd validates on apply: the native ML-DSA signature and the
/// single-use `invite_secret`. The `joiner_kem_pubkey` hint lets the
/// owner seal its post-apply roster/commit reply back to a joiner whose
/// relay never appears in the native event (the reason a pair-record
/// lookup has nothing to target).
///
/// `owner_kem_pub` is the owner's ML-KEM-768 public key (resolve via
/// [`crate::groups::bridge::recipient_kem_key`]). `hints` are the
/// owner's rendezvous hints, or `None` to let the [`Router`] fall back
/// to the local primary relay.
///
/// # Errors
/// - [`ChatError::Invalid`] when `owner_agent_hex` is not 32-byte hex,
///   or the KEM/AEAD/sign path fails.
/// - Forwarded transport errors from [`Router::send`].
#[allow(clippy::too_many_arguments)]
pub async fn emit_self_join_bridge<S>(
    captured: &CapturedSelfJoin,
    owner_agent_hex: &str,
    owner_kem_pub: &[u8],
    joiner_kem_pub: &[u8],
    local_agent_id: &[u8; 32],
    local_machine_id: &[u8; 32],
    signer: &S,
    router: &Router,
    hints: Option<&RendezvousHintsV1>,
) -> Result<()>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    let owner_bytes = agent_hex_to_bytes(owner_agent_hex)?;
    let wrapper = X0xdGroupMetadataEventWrapper {
        topic: captured.topic.clone(),
        payload_b64: B64.encode(&captured.payload),
        joiner_kem_pubkey: Some(joiner_kem_pub.to_vec()),
    };
    let conv = seal_and_sign_bridge_wrapper(
        &owner_bytes,
        owner_kem_pub,
        &wrapper,
        local_agent_id,
        local_machine_id,
        signer,
    )
    .await?;
    let transport_out = OutboundEnvelope {
        kind: OutboundKind::Dm,
        from_machine_id: Some(*local_machine_id),
        payload: Vec::new(),
        timestamp_ms: conv.envelope.timestamp_ms,
        transit: Some(conv.envelope),
    };
    let recipient = AgentId(owner_agent_hex.to_owned());
    router.send(&recipient, transport_out, hints).await?;
    Ok(())
}

/// Decode a 64-char agent-id hex string to the 32-byte id the seal path
/// addresses.
fn agent_hex_to_bytes(agent_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(agent_hex)
        .map_err(|e| ChatError::Invalid(format!("join-bridge: owner agent_id hex decode: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ChatError::Invalid("join-bridge: owner agent_id is not 32 bytes".to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn gossip(topic: &str, payload: &[u8], from: &str) -> Event {
        Event::GossipMessage {
            topic: topic.to_owned(),
            payload: payload.to_vec(),
            from: Some(AgentId(from.to_owned())),
        }
    }

    fn member_joined(member: &str, inviter: &str) -> Vec<u8> {
        format!(
            r#"{{"event":"member_joined","member_agent_id":"{member}","inviter_agent_id":"{inviter}"}}"#
        )
        .into_bytes()
    }

    #[test]
    fn extracts_inviter() {
        assert_eq!(
            inviter_agent_id_from_member_joined(&member_joined("me", "owner-99")).as_deref(),
            Some("owner-99"),
        );
    }

    #[test]
    fn extracts_member_agent_id() {
        assert_eq!(
            member_agent_id_from_member_joined(&member_joined("joiner-7", "owner-1")).as_deref(),
            Some("joiner-7"),
        );
        assert_eq!(member_agent_id_from_member_joined(b"not json"), None);
    }

    #[test]
    fn inviter_none_on_missing_or_garbage() {
        assert_eq!(
            inviter_agent_id_from_member_joined(br#"{"event":"member_joined"}"#),
            None,
        );
        assert_eq!(inviter_agent_id_from_member_joined(b"not json"), None);
    }

    #[tokio::test]
    async fn captures_the_first_self_member_joined() {
        let mj = member_joined("me", "owner-1");
        let mut stream = futures_util::stream::iter(vec![
            // unrelated DM-shaped gossip: skipped (wrong topic)
            Ok(gossip("x0x.dm/whatever", b"{}", "me")),
            // someone else's member_joined: skipped (not self)
            Ok(gossip(
                "x0x.named_group/g1/metadata",
                &member_joined("other", "owner-1"),
                "other",
            )),
            // ours:
            Ok(gossip("x0x.named_group/g1/metadata", &mj, "me")),
        ]);
        let got = capture_self_member_joined(
            &mut stream,
            &GroupId::parse("g1").unwrap(),
            "me",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(got.topic, "x0x.named_group/g1/metadata");
        assert_eq!(got.payload, mj);
    }

    #[tokio::test]
    async fn times_out_when_no_self_event() {
        let mut stream = futures_util::stream::iter(vec![Ok(gossip(
            "x0x.named_group/g1/metadata",
            &member_joined("other", "owner-1"),
            "other",
        ))]);
        // Stream ends with no self event -> error (stream-ended branch).
        let err = capture_self_member_joined(
            &mut stream,
            &GroupId::parse("g1").unwrap(),
            "me",
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)));
    }

    /// Capturing transport that records every `(recipient, envelope)` so
    /// the emit test can unseal what was actually sent.
    struct CapturingTransport {
        sent: std::sync::Mutex<Vec<(AgentId, OutboundEnvelope)>>,
    }

    #[async_trait::async_trait]
    impl crate::transport::Transport for CapturingTransport {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn reachability(&self, _: &AgentId) -> crate::transport::Reachability {
            crate::transport::Reachability::Always
        }
        async fn send(
            &self,
            to: &AgentId,
            env: OutboundEnvelope,
            _: Option<&RendezvousHintsV1>,
        ) -> Result<crate::transport::SendReceipt> {
            self.sent.lock().unwrap().push((to.clone(), env));
            Ok(crate::transport::SendReceipt {
                accepted_at_ms: 1,
                message_id: None,
                transport_name: "capture",
            })
        }
        fn take_inbound(
            &self,
        ) -> Option<tokio::sync::mpsc::UnboundedReceiver<crate::transport::InboundEnvelope>>
        {
            None
        }
    }

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
    async fn emit_seals_native_event_to_owner_with_joiner_kem() {
        let (owner_kem_pub, owner_kem_secret) = crate::chat_crypto::kem_keygen().unwrap();
        let joiner_kem = vec![0x5au8; 1184]; // stand-in ML-KEM-768 pub bytes
        let owner_hex = hex::encode([0xcdu8; 32]);
        let captured = CapturedSelfJoin {
            topic: "x0x.named_group/g7/metadata".to_owned(),
            payload: member_joined("joiner-aid", &owner_hex),
        };

        let capture = std::sync::Arc::new(CapturingTransport {
            sent: std::sync::Mutex::new(Vec::new()),
        });
        let mut router = Router::new();
        router.add(capture.clone());

        emit_self_join_bridge(
            &captured,
            &owner_hex,
            &owner_kem_pub,
            &joiner_kem,
            &[0x11u8; 32],
            &[0x22u8; 32],
            &StubSigner,
            &router,
            None,
        )
        .await
        .unwrap();

        let sent = capture.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "exactly one bridge envelope to the owner");
        let (to, env) = &sent[0];
        assert_eq!(to.0, owner_hex, "addressed to the group owner");
        let transit = env
            .transit
            .as_ref()
            .expect("bridge rides a transit envelope");
        assert_eq!(
            transit.kind,
            fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent,
        );

        // Unseal with the owner's KEM secret: the joiner_kem hint and the
        // native payload survive verbatim.
        let wrapper = crate::groups::bridge::unseal_bridge_wrapper(
            &owner_kem_secret,
            &transit.kem_ciphertext,
            &transit.nonce,
            &transit.ciphertext,
        )
        .unwrap();
        assert_eq!(wrapper.topic, captured.topic);
        assert_eq!(B64.decode(&wrapper.payload_b64).unwrap(), captured.payload);
        assert_eq!(
            wrapper.joiner_kem_pubkey.as_deref(),
            Some(joiner_kem.as_slice()),
            "joiner ML-KEM hint conveyed so the owner can seal its reply",
        );
    }

    #[test]
    fn agent_hex_to_bytes_rejects_non_32_byte() {
        assert!(agent_hex_to_bytes("deadbeef").is_err());
        assert!(agent_hex_to_bytes("nothex").is_err());
        assert!(agent_hex_to_bytes(&hex::encode([0u8; 32])).is_ok());
    }
}
