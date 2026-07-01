//! [`GroupMemberFfi`] -- a group member as surfaced to the Android shell.
//!
//! The uniffi-friendly mirror of [`fetchit_chat::groups::GroupMemberInfo`]: the
//! [`fetchit_chat::identity::AgentId`] newtype is flattened to a bare 64-hex
//! `String`, and the engine's free-text `role` is pre-reduced to the two
//! booleans the UI gates moderation controls on (`is_owner` / `is_admin`).
//!
//! These booleans are **cosmetic** -- they only hide controls that would 4xx.
//! x0xd is the sole authorization gate (admin+, refuses owner-target, drives
//! the TreeKEM re-key); a client that flips a bit here still cannot moderate.
//! The roster + moderation methods live on
//! [`crate::ChatClient`](crate::chat_ffi::ChatClient) (uniffi requires every
//! exported method to sit on the object's own `impl`).

/// A group member as surfaced to Android.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupMemberFfi {
    /// 64-hex agent id.
    pub agent_id_hex: String,
    /// Display name x0xd has for this member, if any.
    pub display_name: Option<String>,
    /// Raw role string as reported by x0xd (`owner` / `admin` / `member`).
    pub role: Option<String>,
    /// `true` when [`role`](Self::role) is `"owner"`. Cosmetic: hides the
    /// per-row moderation overflow on the owner, who x0xd refuses to target.
    pub is_owner: bool,
    /// `true` when [`role`](Self::role) is `"owner"` or `"admin"` -- i.e. the
    /// member can moderate. Cosmetic: the UI uses the *viewer's* value to show
    /// or hide the moderation affordances; x0xd is the real authority.
    pub is_admin: bool,
}

impl From<fetchit_chat::groups::GroupMemberInfo> for GroupMemberFfi {
    fn from(m: fetchit_chat::groups::GroupMemberInfo) -> Self {
        let is_owner = m.role.as_deref() == Some("owner");
        let is_admin = matches!(m.role.as_deref(), Some("owner" | "admin"));
        Self {
            agent_id_hex: m.agent_id.0,
            display_name: m.display_name,
            role: m.role,
            is_owner,
            is_admin,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_chat::groups::GroupMemberInfo;
    use fetchit_chat::identity::AgentId;

    fn member(role: Option<&str>) -> GroupMemberInfo {
        GroupMemberInfo {
            agent_id: AgentId("a".repeat(64)),
            display_name: Some("Ada".into()),
            role: role.map(str::to_owned),
            state: Some("active".into()),
        }
    }

    #[test]
    fn from_owner_sets_both_owner_and_admin() {
        let ffi = GroupMemberFfi::from(member(Some("owner")));
        assert_eq!(ffi.agent_id_hex, "a".repeat(64));
        assert_eq!(ffi.display_name.as_deref(), Some("Ada"));
        assert_eq!(ffi.role.as_deref(), Some("owner"));
        assert!(ffi.is_owner);
        assert!(ffi.is_admin);
    }

    #[test]
    fn from_admin_sets_admin_only() {
        let ffi = GroupMemberFfi::from(member(Some("admin")));
        assert!(!ffi.is_owner);
        assert!(ffi.is_admin);
    }

    #[test]
    fn from_member_sets_neither() {
        let ffi = GroupMemberFfi::from(member(Some("member")));
        assert!(!ffi.is_owner);
        assert!(!ffi.is_admin);
    }

    #[test]
    fn from_none_role_sets_neither() {
        let ffi = GroupMemberFfi::from(member(None));
        assert_eq!(ffi.role, None);
        assert!(!ffi.is_owner);
        assert!(!ffi.is_admin);
    }
}
