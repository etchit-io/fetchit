//! Handle-to-agent continuity ledger (M5.1).
//!
//! Lookup is keyed by handle, but trust is keyed by agent id. This
//! small persisted map remembers which agent id each handle last
//! verifiably resolved to, so the actor card can surface "this handle
//! changed hands" instead of silently presenting a new identity under
//! a familiar name. Best-effort local state: a corrupt ledger resets
//! continuity (an attacker who can corrupt local disk already owns
//! stronger primitives), it never blocks a lookup.

use crate::error::ChatError;
use crate::local_store::StoreLayout;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Serializes ledger read-modify-write cycles (same pattern as
/// `messages::CARD_UPDATE_LOCK`).
static RESOLUTIONS_LOCK: Mutex<()> = Mutex::new(());

/// Outcome of recording a verified handle resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionChange {
    /// First time this handle resolved on this device.
    New,
    /// Same agent id as last time.
    Same,
    /// The handle now resolves to a DIFFERENT agent id; surface it.
    Changed {
        /// The agent id this handle previously resolved to.
        previous_agent_id_hex: String,
    },
}

/// Record that `canonical_handle` verifiably resolved to
/// `agent_id_hex`, returning how that compares to the last record.
/// `canonical_handle` is the `@local@instance` form built from
/// `fetchit_fedi::parse_mention` output (instance already lowercased).
///
/// # Errors
///
/// [`ChatError::Invalid`] when the ledger cannot be written.
pub fn note_resolution(
    layout: &StoreLayout,
    canonical_handle: &str,
    agent_id_hex: &str,
) -> Result<ResolutionChange, ChatError> {
    let _guard = RESOLUTIONS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = layout.fedi_resolutions_path();
    let mut map: BTreeMap<String, String> = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    };
    let change = match map.get(canonical_handle) {
        None => ResolutionChange::New,
        Some(prev) if prev == agent_id_hex => ResolutionChange::Same,
        Some(prev) => ResolutionChange::Changed {
            previous_agent_id_hex: prev.clone(),
        },
    };
    map.insert(canonical_handle.to_string(), agent_id_hex.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ChatError::Invalid(format!("fedi dir: {e}")))?;
    }
    let json = serde_json::to_vec_pretty(&map)
        .map_err(|e| ChatError::Invalid(format!("resolutions encode: {e}")))?;
    std::fs::write(&path, json)
        .map_err(|e| ChatError::Invalid(format!("resolutions write: {e}")))?;
    Ok(change)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_layout() -> (StoreLayout, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        (layout, dir)
    }

    #[test]
    fn first_resolution_is_new_then_same() {
        let (layout, _tmp) = test_layout();
        let a = "a".repeat(64);
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &a).unwrap(),
            ResolutionChange::New
        );
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &a).unwrap(),
            ResolutionChange::Same
        );
    }

    #[test]
    fn different_agent_id_reports_changed_with_previous() {
        let (layout, _tmp) = test_layout();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        note_resolution(&layout, "@josh@etchit.io", &a).unwrap();
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &b).unwrap(),
            ResolutionChange::Changed {
                previous_agent_id_hex: a
            }
        );
        // The ledger now stores the new binding.
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &b).unwrap(),
            ResolutionChange::Same
        );
    }

    #[test]
    fn handles_are_tracked_independently() {
        let (layout, _tmp) = test_layout();
        note_resolution(&layout, "@a@x.io", &"a".repeat(64)).unwrap();
        assert_eq!(
            note_resolution(&layout, "@b@x.io", &"b".repeat(64)).unwrap(),
            ResolutionChange::New
        );
        assert_eq!(
            note_resolution(&layout, "@a@x.io", &"a".repeat(64)).unwrap(),
            ResolutionChange::Same
        );
    }

    #[test]
    fn corrupt_ledger_resets_to_empty_rather_than_erroring() {
        let (layout, _tmp) = test_layout();
        std::fs::create_dir_all(layout.fedi_resolutions_path().parent().unwrap()).unwrap();
        std::fs::write(layout.fedi_resolutions_path(), b"not json").unwrap();
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &"a".repeat(64)).unwrap(),
            ResolutionChange::New
        );
    }
}
