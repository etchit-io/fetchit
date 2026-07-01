//! JSON event builders for policy updates and other owner-side
//! group-metadata mutations on the M2.5 bridge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Inputs for a `PolicyUpdated` event published to the group metadata topic.
/// Mirrors the JSON shape upstream x0xd expects when the M2.5 bridge ferries
/// a policy change event across the gossip relay.
#[derive(Debug, Clone)]
pub struct PolicyUpdatedInputs<'a> {
    /// Group identifier (x0xd's local `group_id`).
    pub group_id: &'a str,
    /// Revision number of the group state at the time of the policy change.
    pub revision: u64,
    /// Hex agent id of the actor (group owner) performing the change.
    pub actor: &'a str,
    /// Upstream `GroupPolicy` already serialized to JSON (opaque to us).
    pub policy_json: serde_json::Value,
    /// Optional nested `GroupStateCommit` object with `state_hash` and `signature`.
    pub commit_json: Option<serde_json::Value>,
}

/// Build the JSON event body for a `policy_updated` event published to the
/// group metadata topic. The returned object is encoded to bytes and
/// base64-wrapped for inclusion in the bridge relay wrapper.
#[must_use]
pub fn build_policy_updated_event(inputs: &PolicyUpdatedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "policy_updated",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "policy": inputs.policy_json,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_policy_updated_event_passes_policy_through_opaque() {
        let inputs = PolicyUpdatedInputs {
            group_id: "g",
            revision: 2,
            actor: "owner",
            policy_json: json!({ "name": "strict", "max_members": 50 }),
            commit_json: None,
        };
        let v = build_policy_updated_event(&inputs);
        assert_eq!(v["event"], json!("policy_updated"));
        assert_eq!(v["policy"]["name"], json!("strict"));
        assert_eq!(v["policy"]["max_members"], json!(50));
    }
}
