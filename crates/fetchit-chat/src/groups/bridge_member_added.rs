//! JSON transform for the `member_added` relay-bridge fan-out to EXISTING
//! members (R3 — the "group only knows the first 2" fix).
//!
//! The owner's authoritative `MemberAdded` (staged at the x0xd join-result
//! endpoint) carries the new member's `TreeKEM` Welcome inlined
//! (`treekem_welcome_b64` / `welcome_ref`) for the joiner, plus the `TreeKEM`
//! Commit (`treekem_commit_b64` / `commit`) that EXISTING members apply to
//! advance epoch and learn the new leaf. The joiner receives the full event
//! via `reply_to_bridged_join`; the existing-member fan-out needs only the
//! commit, so the joiner-sealed welcome fields are stripped first.

/// Strip the joiner-only `TreeKEM` Welcome fields from an authoritative
/// `MemberAdded` event, leaving the commit-only form that EXISTING
/// members apply to advance their epoch and learn the new leaf.
///
/// The owner stages the full event (via the x0xd join-result endpoint)
/// with both the HPKE-sealed Welcome for the new joiner
/// (`treekem_welcome_b64` / `welcome_ref`) and the `TreeKEM` Commit for
/// the rest of the roster (`treekem_commit_b64` / `commit`). The joiner
/// receives the full event from `reply_to_bridged_join`; the
/// existing-member fan-out (R3) must carry only the commit, so the two
/// joiner-sealed welcome keys are removed and every other field is kept
/// verbatim.
///
/// Input that already lacks the welcome fields is returned unchanged
/// (the strip is idempotent).
#[must_use]
pub(crate) fn commit_only_member_added(event: &serde_json::Value) -> serde_json::Value {
    let mut out = event.clone();
    if let Some(obj) = out.as_object_mut() {
        // DENYLIST, not allowlist: any FUTURE joiner-sealed field the staged
        // event grows MUST be added here, or it fans out in the broadcast
        // Commit (including the durable relay group-log copy every group-id
        // holder can fetch).
        obj.remove("treekem_welcome_b64");
        obj.remove("welcome_ref");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn commit_only_member_added_strips_welcome_keeps_commit() {
        let full = json!({
            "event": "member_added",
            "group_id": "stableG",
            "revision": 2,
            "actor": "owneraid",
            "agent_id": "joineraid",
            "display_name": "Joiner",
            "treekem_commit_b64": "COMMITB64",
            "treekem_welcome_b64": "WELCOMEB64",
            "welcome_ref": { "hash": "abc", "size": 42 },
            "treekem_epoch": 5,
            "commit": { "state_hash": "h", "signature": "s" },
        });

        let stripped = commit_only_member_added(&full);

        // Joiner-only welcome fields are removed.
        assert!(stripped.get("treekem_welcome_b64").is_none());
        assert!(stripped.get("welcome_ref").is_none());
        // Commit + identity fields existing members need are retained.
        assert_eq!(stripped["event"], json!("member_added"));
        assert_eq!(stripped["group_id"], json!("stableG"));
        assert_eq!(stripped["agent_id"], json!("joineraid"));
        assert_eq!(stripped["treekem_commit_b64"], json!("COMMITB64"));
        assert_eq!(stripped["treekem_epoch"], json!(5));
        assert_eq!(stripped["commit"]["state_hash"], json!("h"));
    }

    #[test]
    fn commit_only_member_added_is_noop_when_already_commit_only() {
        let commit_only = json!({
            "event": "member_added",
            "group_id": "g",
            "agent_id": "m",
            "treekem_commit_b64": "C",
        });
        assert_eq!(commit_only_member_added(&commit_only), commit_only);
    }
}
