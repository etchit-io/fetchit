//! JSON event builders for member role updates and other owner-side
//! group-metadata mutations on the M2.5 bridge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Inputs for a `MemberRoleUpdated` event published to the group metadata
/// topic. Mirrors the JSON shape upstream x0xd expects when the M2.5
/// bridge ferries a member role change event across the gossip relay.
#[derive(Debug, Clone)]
pub struct MemberRoleUpdatedInputs<'a> {
    /// Group identifier (x0xd's local `group_id`).
    pub group_id: &'a str,
    /// Revision number of the group state at the time of the role change.
    pub revision: u64,
    /// Hex agent id of the actor (group owner / admin) performing the change.
    pub actor: &'a str,
    /// Hex agent id of the member whose role is being changed.
    pub agent_id: &'a str,
    /// Upstream wire string: "owner", "admin", "member", "observer", etc.
    pub role: &'a str,
    /// Optional nested `GroupStateCommit` object with `state_hash` and `signature`.
    pub commit_json: Option<serde_json::Value>,
}

/// Build the JSON event body for a `member_role_updated` event published
/// to the group metadata topic. The returned object is encoded to bytes
/// and base64-wrapped for inclusion in the bridge relay wrapper.
#[must_use]
pub fn build_member_role_updated_event(inputs: &MemberRoleUpdatedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "member_role_updated",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "agent_id": inputs.agent_id,
        "role": inputs.role,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_member_role_updated_event_matches_upstream_json_shape() {
        let inputs = MemberRoleUpdatedInputs {
            group_id: "g",
            revision: 5,
            actor: "owner-aid",
            agent_id: "member-aid",
            role: "admin",
            commit_json: Some(json!({ "state_hash": "h" })),
        };
        let v = build_member_role_updated_event(&inputs);
        assert_eq!(v["event"], json!("member_role_updated"));
        assert_eq!(v["role"], json!("admin"));
        assert_eq!(v["commit"]["state_hash"], json!("h"));
    }

    #[test]
    fn build_member_role_updated_event_serializes_none_commit_as_json_null() {
        let inputs = MemberRoleUpdatedInputs {
            group_id: "g",
            revision: 1,
            actor: "a",
            agent_id: "m",
            role: "observer",
            commit_json: None,
        };
        let v = build_member_role_updated_event(&inputs);
        assert!(v["commit"].is_null());
        assert_eq!(v["role"], json!("observer"));
    }
}
