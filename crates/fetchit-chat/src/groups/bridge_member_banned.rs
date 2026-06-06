//! JSON event builders for member bans and other owner-side
//! group-metadata mutations on the M2.5 bridge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Inputs for member banned event construction.
#[derive(Debug, Clone)]
pub struct MemberBannedInputs<'a> {
    /// Group identifier.
    pub group_id: &'a str,
    /// Revision number.
    pub revision: u64,
    /// Actor who banned the member.
    pub actor: &'a str,
    /// Agent ID of the banned member.
    pub agent_id: &'a str,
    /// Optional reason for the ban.
    pub reason: Option<&'a str>,
    /// Optional commit metadata.
    pub commit_json: Option<serde_json::Value>,
}

/// Build a `member_banned` JSON event from the given inputs.
#[must_use]
pub fn build_member_banned_event(inputs: &MemberBannedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "member_banned",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "agent_id": inputs.agent_id,
        "reason": inputs.reason,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_member_banned_event_includes_reason_field() {
        let inputs = MemberBannedInputs {
            group_id: "g",
            revision: 7,
            actor: "owner",
            agent_id: "bad-aid",
            reason: Some("spam"),
            commit_json: None,
        };
        let v = build_member_banned_event(&inputs);
        assert_eq!(v["reason"], json!("spam"));
        assert_eq!(v["event"], json!("member_banned"));
    }
}
