//! Pure mapping from relay group-log wire records to the recovery loop's
//! [`CommitRecord`], and the pure decision of which x0xd apply endpoint a
//! record routes to. No I/O, no crypto: the security-critical routing is
//! testable in isolation. The actual apply (which re-verifies daemon-side)
//! lives in `Client`'s warm applier.

use base64::Engine as _;
use fetchit_relay_proto::{LogRecordKind, LogRecordWire};

use super::{CommitRecord, CommitRecordKind};

/// Map a relay group-log wire record into the recovery loop's record shape:
/// base64-encode the raw payload and hex-encode the (routing-hint) author.
#[must_use]
pub fn commit_record_from_wire(w: &LogRecordWire) -> CommitRecord {
    let kind = match w.kind {
        LogRecordKind::Commit => CommitRecordKind::Commit,
        LogRecordKind::JoinResult => CommitRecordKind::JoinResult,
    };
    CommitRecord {
        seq: w.seq,
        kind,
        payload_b64: base64::engine::general_purpose::STANDARD.encode(&w.payload),
        author_agent_id_hex: w.author.map(|a| a.to_hex()),
    }
}

/// Which x0xd apply endpoint a fetched record routes to.
///
/// `author` is a routing hint only: the daemon endpoints re-verify the
/// ML-DSA `committed_by` inside the payload, so a spoofed author cannot
/// force an unauthorized apply, only a rejected one.
#[derive(Debug)]
pub enum ApplyPlan {
    /// Route to `apply_metadata_event` (a group commit).
    Metadata {
        /// Base64 signed metadata event.
        payload_b64: String,
        /// The author agent id (hex) passed as `sender_agent_id`.
        author_hex: String,
    },
    /// Route to `apply_join_result` (a Welcome addressed to this node).
    JoinResult {
        /// Stable group id parsed from the `MemberAdded` payload.
        stable_group_id: String,
        /// The joining member (this node) parsed from the payload.
        member: String,
        /// Base64 `MemberAdded` event.
        payload_b64: String,
        /// The owner/creator agent id (hex) = the record author.
        owner_hex: String,
    },
    /// Nothing to apply (malformed, missing author, or not addressed to us).
    Skip(&'static str),
}

/// Decide how to apply one fetched record.
///
/// Pure: decodes the payload to classify a `JoinResult`'s self-target, but
/// performs no network or crypto. The caller executes the returned plan
/// against x0xd's verifying apply endpoints.
#[must_use]
pub fn plan_apply(rec: &CommitRecord, my_agent_hex: &str) -> ApplyPlan {
    let Some(author_hex) = rec.author_agent_id_hex.clone() else {
        return ApplyPlan::Skip("record carries no author");
    };
    match rec.kind {
        CommitRecordKind::Commit => ApplyPlan::Metadata {
            payload_b64: rec.payload_b64.clone(),
            author_hex,
        },
        CommitRecordKind::JoinResult => {
            let Ok(bytes) =
                base64::engine::general_purpose::STANDARD.decode(rec.payload_b64.as_bytes())
            else {
                return ApplyPlan::Skip("join-result payload not base64");
            };
            match crate::groups::join_bridge::member_added_self_target(&bytes, my_agent_hex) {
                Some((stable_group_id, member)) => ApplyPlan::JoinResult {
                    stable_group_id,
                    member,
                    payload_b64: rec.payload_b64.clone(),
                    owner_hex: author_hex,
                },
                None => ApplyPlan::Skip("join-result not addressed to this node"),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_proto::identity::AgentId;
    use fetchit_relay_proto::{LogRecordKind, LogRecordWire};

    fn wire(kind: LogRecordKind, author: Option<[u8; 32]>) -> LogRecordWire {
        LogRecordWire {
            seq: 7,
            kind,
            recipient: None,
            payload: b"hello".to_vec(),
            author: author.map(AgentId::from_bytes),
            inserted_at_ms: 123,
        }
    }

    #[test]
    fn maps_commit_wire_to_record_base64_and_hex() {
        let w = wire(LogRecordKind::Commit, Some([0xab; 32]));
        let r = commit_record_from_wire(&w);
        assert_eq!(r.seq, 7);
        assert_eq!(r.kind, CommitRecordKind::Commit);
        assert_eq!(r.payload_b64, "aGVsbG8="); // base64("hello")
        assert_eq!(r.author_agent_id_hex.as_deref(), Some(&"ab".repeat(32)[..]));
    }

    #[test]
    fn maps_missing_author_to_none() {
        let w = wire(LogRecordKind::JoinResult, None);
        let r = commit_record_from_wire(&w);
        assert_eq!(r.kind, CommitRecordKind::JoinResult);
        assert!(r.author_agent_id_hex.is_none());
    }

    #[test]
    fn commit_plan_routes_to_metadata_with_author() {
        let r = CommitRecord {
            seq: 1,
            kind: CommitRecordKind::Commit,
            payload_b64: "cA==".into(),
            author_agent_id_hex: Some("cc".repeat(32)),
        };
        match plan_apply(&r, "me00") {
            ApplyPlan::Metadata {
                payload_b64,
                author_hex,
            } => {
                assert_eq!(payload_b64, "cA==");
                assert_eq!(author_hex, "cc".repeat(32));
            }
            other => panic!("expected Metadata, got {other:?}"),
        }
    }

    #[test]
    fn commit_without_author_is_skipped_not_applied() {
        let r = CommitRecord {
            seq: 1,
            kind: CommitRecordKind::Commit,
            payload_b64: "cA==".into(),
            author_agent_id_hex: None,
        };
        assert!(matches!(plan_apply(&r, "me00"), ApplyPlan::Skip(_)));
    }

    #[test]
    fn join_result_with_garbage_payload_is_skipped() {
        // A JoinResult whose payload is not a self-targeted MemberAdded must
        // not route to apply_join_result; it is skipped, and the loop
        // advances past it rather than stalling.
        let r = CommitRecord {
            seq: 2,
            kind: CommitRecordKind::JoinResult,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(b"not-json"),
            author_agent_id_hex: Some("dd".repeat(32)),
        };
        assert!(matches!(plan_apply(&r, "aa11"), ApplyPlan::Skip(_)));
    }

    #[test]
    fn join_result_self_targeted_routes_with_owner_as_author() {
        // A self-targeted MemberAdded routes to JoinResult: member parsed
        // from the payload, owner = the record author (the appender).
        let me = "aa11";
        let payload =
            br#"{"event":"member_added","group_id":"stableG","agent_id":"aa11","commit":"x"}"#;
        let r = CommitRecord {
            seq: 3,
            kind: CommitRecordKind::JoinResult,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
            author_agent_id_hex: Some("ee".repeat(32)),
        };
        match plan_apply(&r, me) {
            ApplyPlan::JoinResult {
                stable_group_id,
                member,
                owner_hex,
                ..
            } => {
                assert_eq!(stable_group_id, "stableG");
                assert_eq!(member, "aa11");
                assert_eq!(owner_hex, "ee".repeat(32));
            }
            other => panic!("expected JoinResult, got {other:?}"),
        }
    }
}
