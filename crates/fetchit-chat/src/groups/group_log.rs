//! Producer side of the durable relay group-log (#297 Lane A).
//!
//! Builds the log-append intents for the owner's join-reply path: the
//! Welcome-bearing `MemberAdded` (or `MemberReKeyed`) addressed to the
//! joiner becomes a recipient-gated `JoinResult` record, and its
//! commit-only projection becomes a broadcast `Commit` record. The log is
//! the system of record for warm epoch-recovery: records are appended
//! BEFORE the live sends, so a member that misses the live frame recovers
//! from the log instead of desyncing permanently.
//!
//! Exposure note: record payloads are the signed membership events
//! (plaintext JSON shell; the Welcome's secrets stay KEM-sealed to the
//! joiner inside the event). The relay can read membership-change
//! metadata -- the same class it already learns from pair-records and
//! routing -- and never message content, which stays end-to-end sealed
//! and never enters the log. Sealing the log payloads is a Lane B
//! consideration (see `docs/SECURITY.md`).
//!
//! Lane B design constraint (cross-review P1-2): a member replaying its
//! OWN historical `JoinResult` (in-memory cursors restart at 0) gets a
//! daemon 403 once the expected-inviter entry has cleared; the applier
//! classifies deterministic 4xx as skip-and-advance, so this is benign,
//! but a durable cursor store would avoid the wasted replay entirely.

use fetchit_relay_proto::{AgentId, GroupId, LogRecordKind};

use crate::error::{ChatError, Result};
use crate::groups::bridge_member_added::commit_only_member_added;

/// One pending group-log append: the wire-level record a producer
/// deposits via `RelayTransport::log_append`.
pub(crate) struct GroupLogIntent {
    /// Log key: the MLS group id (the id `StaleEpoch` frames carry, and
    /// the id a recovering member fetches by).
    pub group_id: GroupId,
    /// Record kind (`Commit` broadcast / `JoinResult` recipient-gated).
    pub kind: LogRecordKind,
    /// `Some(joiner)` for a `JoinResult`; `None` for a `Commit`.
    pub recipient: Option<AgentId>,
    /// The signed event JSON bytes -- exactly what the warm applier hands
    /// to x0xd's verifying apply endpoints.
    pub payload: Vec<u8>,
}

/// Build the two log records for one owner join-reply: the full
/// Welcome-bearing event as a `JoinResult` addressed to `joiner`, and its
/// commit-only projection (Welcome stripped) as a broadcast `Commit`.
///
/// # Errors
/// [`ChatError::Invalid`] when `mls_group_id_hex` is not 64-hex or either
/// event fails to serialize.
pub(crate) fn join_reply_log_intents(
    mls_group_id_hex: &str,
    joiner: [u8; 32],
    welcome_event: &serde_json::Value,
) -> Result<Vec<GroupLogIntent>> {
    let mut gid_bytes = [0u8; 32];
    hex::decode_to_slice(mls_group_id_hex, &mut gid_bytes)
        .map_err(|e| ChatError::Invalid(format!("group-log: mls group id hex: {e}")))?;
    let group_id = GroupId::from_bytes(gid_bytes);

    let welcome_bytes = serde_json::to_vec(welcome_event)
        .map_err(|e| ChatError::Invalid(format!("group-log: welcome event encode: {e}")))?;
    let commit_only = commit_only_member_added(welcome_event);
    let commit_bytes = serde_json::to_vec(&commit_only)
        .map_err(|e| ChatError::Invalid(format!("group-log: commit event encode: {e}")))?;

    Ok(vec![
        GroupLogIntent {
            group_id,
            kind: LogRecordKind::JoinResult,
            recipient: Some(AgentId::from_bytes(joiner)),
            payload: welcome_bytes,
        },
        GroupLogIntent {
            group_id,
            kind: LogRecordKind::Commit,
            recipient: None,
            payload: commit_bytes,
        },
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn welcome_event() -> serde_json::Value {
        serde_json::json!({
            "event": "member_added",
            "group_id": "stable-id",
            "agent_id": "aa".repeat(32),
            "treekem_commit_b64": "COMMITB64",
            "treekem_welcome_b64": "WELCOMEB64",
            "welcome_ref": { "hash": "abc", "size": 42 },
        })
    }

    #[test]
    fn builds_join_result_then_commit_with_right_addressing() {
        let gid_hex = "cd".repeat(32);
        let joiner = [0x77u8; 32];
        let intents = join_reply_log_intents(&gid_hex, joiner, &welcome_event()).unwrap();

        assert_eq!(intents.len(), 2);
        let jr = &intents[0];
        assert_eq!(jr.kind, LogRecordKind::JoinResult);
        assert_eq!(jr.recipient, Some(AgentId::from_bytes(joiner)));
        assert_eq!(jr.group_id, GroupId::from_bytes([0xcd; 32]));

        let c = &intents[1];
        assert_eq!(c.kind, LogRecordKind::Commit);
        assert!(c.recipient.is_none(), "commit is broadcast, never gated");
        assert_eq!(c.group_id, jr.group_id, "both records share the log key");
    }

    #[test]
    fn commit_payload_strips_welcome_join_result_keeps_it() {
        let intents =
            join_reply_log_intents(&"cd".repeat(32), [1u8; 32], &welcome_event()).unwrap();
        let jr: serde_json::Value = serde_json::from_slice(&intents[0].payload).unwrap();
        let c: serde_json::Value = serde_json::from_slice(&intents[1].payload).unwrap();
        assert!(
            jr.get("treekem_welcome_b64").is_some() && jr.get("welcome_ref").is_some(),
            "join-result carries the sealed Welcome fields"
        );
        assert!(
            c.get("treekem_welcome_b64").is_none() && c.get("welcome_ref").is_none(),
            "broadcast commit must not carry the joiner's Welcome"
        );
        assert_eq!(
            c.get("treekem_commit_b64"),
            jr.get("treekem_commit_b64"),
            "commit material survives the projection"
        );
    }

    #[test]
    fn bad_group_hex_is_an_error() {
        assert!(join_reply_log_intents("nothex", [0u8; 32], &welcome_event()).is_err());
    }
}
