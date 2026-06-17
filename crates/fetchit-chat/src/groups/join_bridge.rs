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

use futures_util::{Stream, StreamExt};

use crate::error::{ChatError, Result};
use crate::events::Event;
use crate::groups::GroupId;
use crate::groups_reachability::is_self_member_joined_for_group;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::AgentId;

    fn gossip(topic: &str, payload: &[u8], from: &str) -> Result<Event> {
        Ok(Event::GossipMessage {
            topic: topic.to_owned(),
            payload: payload.to_vec(),
            from: Some(AgentId(from.to_owned())),
        })
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
            gossip("x0x.dm/whatever", b"{}", "me"),
            // someone else's member_joined: skipped (not self)
            gossip(
                "x0x.named_group/g1/metadata",
                &member_joined("other", "owner-1"),
                "other",
            ),
            // ours:
            gossip("x0x.named_group/g1/metadata", &mj, "me"),
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
        let mut stream = futures_util::stream::iter(vec![gossip(
            "x0x.named_group/g1/metadata",
            &member_joined("other", "owner-1"),
            "other",
        )]);
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
}
