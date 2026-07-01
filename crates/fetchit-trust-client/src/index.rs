//! Per-kind in-memory denylist index with delta tracking on replace.

use std::collections::HashSet;

use fetchit_trust::EntryKind;

/// In-memory index of denylisted values, partitioned by [`EntryKind`].
///
/// Values are stored lowercase (matching the
/// [`fetchit_trust::TargetIdentity::value`] normalisation contract).
/// `is_blocked` lowercases its query for the same reason.
#[allow(dead_code)]
#[derive(Default, Debug)]
pub(crate) struct DenylistIndexes {
    xor_names: HashSet<String>,
    agent_ids: HashSet<String>,
    relay_urls: HashSet<String>,
    actor_urls: HashSet<String>,
}

/// Description of what changed when an [`EntryKind`] bucket was
/// replaced. Empty `added` + empty `removed` means the snapshot was
/// identical to the previous one.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Delta {
    pub(crate) kind: EntryKind,
    pub(crate) added: Vec<String>,
    pub(crate) removed: Vec<String>,
}

impl DenylistIndexes {
    /// Atomically replace the contents of one [`EntryKind`] bucket.
    /// Returns the diff (added / removed values) against the prior
    /// snapshot.
    #[allow(dead_code)]
    pub(crate) fn replace(&mut self, kind: EntryKind, values: Vec<String>) -> Delta {
        let new: HashSet<String> = values.into_iter().map(|v| v.to_ascii_lowercase()).collect();
        let target = self.bucket_mut(kind);
        let added: Vec<String> = new.difference(target).cloned().collect();
        let removed: Vec<String> = target.difference(&new).cloned().collect();
        *target = new;
        Delta {
            kind,
            added,
            removed,
        }
    }

    /// `true` when `value` (after ASCII-lowercase normalisation) is
    /// present in the index for `kind`.
    #[allow(dead_code)]
    pub(crate) fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        let normalised = value.to_ascii_lowercase();
        self.bucket(kind).contains(&normalised)
    }

    fn bucket(&self, kind: EntryKind) -> &HashSet<String> {
        match kind {
            EntryKind::XorName => &self.xor_names,
            EntryKind::AgentId => &self.agent_ids,
            EntryKind::RelayUrl => &self.relay_urls,
            EntryKind::ActorUrl => &self.actor_urls,
        }
    }

    fn bucket_mut(&mut self, kind: EntryKind) -> &mut HashSet<String> {
        match kind {
            EntryKind::XorName => &mut self.xor_names,
            EntryKind::AgentId => &mut self.agent_ids,
            EntryKind::RelayUrl => &mut self.relay_urls,
            EntryKind::ActorUrl => &mut self.actor_urls,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_trust::EntryKind;

    #[test]
    fn index_replace_swaps_kind_atomically() {
        let mut idx = DenylistIndexes::default();
        let _ = idx.replace(
            EntryKind::RelayUrl,
            vec!["wss://a".into(), "wss://b".into()],
        );
        assert!(idx.is_blocked(EntryKind::RelayUrl, "wss://a"));
        assert!(!idx.is_blocked(EntryKind::RelayUrl, "wss://c"));
        let _ = idx.replace(EntryKind::RelayUrl, vec!["wss://c".into()]);
        assert!(!idx.is_blocked(EntryKind::RelayUrl, "wss://a"));
        assert!(idx.is_blocked(EntryKind::RelayUrl, "wss://c"));
    }

    #[test]
    fn index_isolates_kinds() {
        let mut idx = DenylistIndexes::default();
        let _ = idx.replace(EntryKind::RelayUrl, vec!["wss://a".into()]);
        assert!(!idx.is_blocked(EntryKind::AgentId, "wss://a"));
    }

    #[test]
    fn replace_returns_delta_added_and_removed() {
        let mut idx = DenylistIndexes::default();
        let _ = idx.replace(
            EntryKind::AgentId,
            vec!["aaa".into(), "bbb".into(), "ccc".into()],
        );
        let delta = idx.replace(EntryKind::AgentId, vec!["bbb".into(), "ddd".into()]);
        let mut added = delta.added.clone();
        let mut removed = delta.removed.clone();
        added.sort();
        removed.sort();
        assert_eq!(added, vec!["ddd".to_string()]);
        assert_eq!(removed, vec!["aaa".to_string(), "ccc".to_string()]);
    }

    #[test]
    fn replace_idempotent_returns_empty_delta() {
        let mut idx = DenylistIndexes::default();
        let _ = idx.replace(EntryKind::RelayUrl, vec!["wss://a".into()]);
        let delta = idx.replace(EntryKind::RelayUrl, vec!["wss://a".into()]);
        assert!(delta.added.is_empty());
        assert!(delta.removed.is_empty());
    }

    #[test]
    fn is_blocked_lowercases_query_for_url_lookup() {
        let mut idx = DenylistIndexes::default();
        let _ = idx.replace(EntryKind::RelayUrl, vec!["wss://a.example/v1/ws".into()]);
        // Caller may pass mixed-case; we normalize at the lookup boundary.
        assert!(idx.is_blocked(EntryKind::RelayUrl, "WSS://A.Example/V1/WS"));
    }

    #[test]
    fn covers_all_four_entry_kinds() {
        let mut idx = DenylistIndexes::default();
        let _ = idx.replace(EntryKind::XorName, vec!["x".into()]);
        let _ = idx.replace(EntryKind::AgentId, vec!["a".into()]);
        let _ = idx.replace(EntryKind::RelayUrl, vec!["wss://r".into()]);
        let _ = idx.replace(EntryKind::ActorUrl, vec!["https://u".into()]);
        assert!(idx.is_blocked(EntryKind::XorName, "x"));
        assert!(idx.is_blocked(EntryKind::AgentId, "a"));
        assert!(idx.is_blocked(EntryKind::RelayUrl, "wss://r"));
        assert!(idx.is_blocked(EntryKind::ActorUrl, "https://u"));
    }
}
