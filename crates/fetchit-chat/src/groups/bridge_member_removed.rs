//! JSON event builders for member removal and other owner-side
//! group-metadata mutations on the M2.5 bridge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Inputs for a `MemberRemoved` event published to the group metadata
/// topic. Mirrors the JSON shape upstream x0xd expects when the M2.5
/// bridge ferries a member removal event across the gossip relay.
#[derive(Debug, Clone)]
pub struct MemberRemovedInputs<'a> {
    /// Group identifier (x0xd's local `group_id`).
    pub group_id: &'a str,
    /// Revision number of the group state at the time of removal.
    pub revision: u64,
    /// Hex agent id of the actor (group owner / admin) performing the removal.
    pub actor: &'a str,
    /// Hex agent id of the member being removed.
    pub agent_id: &'a str,
    /// Optional base64-encoded `TreeKEM` commit for the removal operation.
    pub treekem_commit_b64: Option<&'a str>,
    /// Optional `TreeKEM` epoch number after the removal.
    pub treekem_epoch: Option<u64>,
    /// Optional nested `GroupStateCommit` object with `state_hash` and `signature`.
    pub commit_json: Option<serde_json::Value>,
}

/// Build the JSON event body for a `member_removed` event published
/// to the group metadata topic. The returned object is encoded to bytes
/// and base64-wrapped for inclusion in the bridge relay wrapper.
#[must_use]
pub fn build_member_removed_event(inputs: &MemberRemovedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "member_removed",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "agent_id": inputs.agent_id,
        "treekem_commit_b64": inputs.treekem_commit_b64,
        "treekem_epoch": inputs.treekem_epoch,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_member_removed_event_matches_upstream_json_shape() {
        let inputs = MemberRemovedInputs {
            group_id: "abcd",
            revision: 3,
            actor: "owner-aid",
            agent_id: "member-aid",
            treekem_commit_b64: Some("commitb64"),
            treekem_epoch: Some(4),
            commit_json: Some(json!({ "state_hash": "h", "signature": "s" })),
        };
        let v = build_member_removed_event(&inputs);
        assert_eq!(v["event"], json!("member_removed"));
        assert_eq!(v["group_id"], json!("abcd"));
        assert_eq!(v["revision"], json!(3));
        assert_eq!(v["actor"], json!("owner-aid"));
        assert_eq!(v["agent_id"], json!("member-aid"));
        assert_eq!(v["treekem_commit_b64"], json!("commitb64"));
        assert_eq!(v["treekem_epoch"], json!(4));
        assert_eq!(v["commit"]["state_hash"], json!("h"));
    }

    #[test]
    fn build_member_removed_event_serializes_none_as_json_null() {
        let inputs = MemberRemovedInputs {
            group_id: "g",
            revision: 1,
            actor: "a",
            agent_id: "m",
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit_json: None,
        };
        let v = build_member_removed_event(&inputs);
        assert!(v["treekem_commit_b64"].is_null());
        assert!(v["treekem_epoch"].is_null());
        assert!(v["commit"].is_null());
    }
}
