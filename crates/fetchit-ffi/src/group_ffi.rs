//! [`GroupFfi`] -- a group as surfaced to the Android shell.
//!
//! The uniffi-friendly mirror of [`fetchit_chat::groups::Group`]: the
//! [`fetchit_chat::groups::GroupId`] newtype is flattened to a bare 64-hex
//! `String`, `member_count` widens to `u64` (uniffi has no `usize`), and the
//! engine's [`fetchit_chat::groups::GroupKind`] collapses to an
//! `is_private: Option<bool>` the UI uses to draw the lock icon. The group
//! create/join/send/list/invite methods live on
//! [`crate::ChatClient`](crate::chat_ffi::ChatClient) (uniffi requires every
//! exported method to sit on the object's own `impl`).

/// A group as surfaced to Android.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupFfi {
    /// 64-hex group id.
    pub group_id: String,
    /// Optional human name.
    pub name: Option<String>,
    /// Local roster size.
    pub member_count: u64,
    /// Whether this agent created it.
    pub is_owner: bool,
    /// True for PQ-encrypted (private) groups -- drives the UI lock icon.
    /// `None` when unknown (e.g. from a bare list before kind resolves).
    pub is_private: Option<bool>,
}

impl From<fetchit_chat::groups::Group> for GroupFfi {
    fn from(g: fetchit_chat::groups::Group) -> Self {
        let is_private = g
            .kind
            .map(|k| matches!(k, fetchit_chat::groups::GroupKind::Private));
        Self {
            group_id: g.group_id.as_str().to_owned(),
            name: g.name,
            member_count: g.member_count as u64,
            is_owner: g.is_owner,
            is_private,
        }
    }
}

/// Outcome of a durable join, surfaced to Android
/// ([`crate::ChatClient::join_group_durable`]). `Converged` carries the live
/// group; `Pending` carries only the group id -- the join is a durable intent
/// the resume pump completes when the owner is next reachable, so the shell
/// draws "joining…" instead of a failure. Mirrors
/// [`fetchit_chat::groups::JoinOutcome`].
#[derive(Debug, Clone, uniffi::Enum)]
pub enum JoinOutcomeFfi {
    /// Fully joined and keyed -- usable immediately.
    Converged {
        /// The joined group.
        group: GroupFfi,
    },
    /// Join accepted but not yet converged; the resume pump
    /// ([`crate::ChatClient::drive_pending_joins_once`]) finishes it with no
    /// user action and no re-spent invite. Draw "joining…".
    Pending {
        /// 64-hex group id being joined.
        group_id: String,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_chat::groups::{Group, GroupId, GroupKind};

    fn gid() -> GroupId {
        GroupId::parse(&"a".repeat(64)).unwrap()
    }

    #[test]
    fn from_group_maps_private_kind_to_is_private_true() {
        let g = Group {
            group_id: gid(),
            name: Some("alpha".into()),
            member_count: 3,
            is_owner: true,
            kind: Some(GroupKind::Private),
        };
        let ffi = GroupFfi::from(g);
        assert_eq!(ffi.group_id, "a".repeat(64));
        assert_eq!(ffi.name.as_deref(), Some("alpha"));
        assert_eq!(ffi.member_count, 3);
        assert!(ffi.is_owner);
        assert_eq!(ffi.is_private, Some(true));
    }

    #[test]
    fn from_group_maps_public_kind_to_is_private_false() {
        let g = Group {
            group_id: gid(),
            name: None,
            member_count: 0,
            is_owner: false,
            kind: Some(GroupKind::Public),
        };
        let ffi = GroupFfi::from(g);
        assert_eq!(ffi.is_private, Some(false));
        assert_eq!(ffi.name, None);
        assert!(!ffi.is_owner);
    }

    #[test]
    fn from_group_maps_unknown_kind_to_is_private_none() {
        // A group deserialized from x0xd's bare list/join response omits
        // `policy`, so its kind is None -- that must surface as `None`,
        // never a defaulted bool.
        let g = Group {
            group_id: gid(),
            name: None,
            member_count: 1,
            is_owner: false,
            kind: None,
        };
        let ffi = GroupFfi::from(g);
        assert_eq!(ffi.is_private, None);
    }
}
