//! JSON event builders for group deletion and other owner-side
//! group-metadata mutations on the M2.5 bridge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Inputs for group deleted event construction.
#[derive(Debug, Clone)]
pub struct GroupDeletedInputs<'a> {
    /// Group identifier.
    pub group_id: &'a str,
    /// Revision number.
    pub revision: u64,
    /// Actor who deleted the group.
    pub actor: &'a str,
    /// Optional commit metadata.
    pub commit_json: Option<serde_json::Value>,
}

/// Build a `group_deleted` JSON event from the given inputs.
#[must_use]
pub fn build_group_deleted_event(inputs: &GroupDeletedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "group_deleted",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_group_deleted_event_emits_event_tag() {
        let inputs = GroupDeletedInputs {
            group_id: "g",
            revision: 99,
            actor: "owner",
            commit_json: None,
        };
        let v = build_group_deleted_event(&inputs);
        assert_eq!(v["event"], json!("group_deleted"));
        assert_eq!(v["revision"], json!(99));
    }
}
