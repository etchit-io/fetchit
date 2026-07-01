//! In-memory registry store: atomic FCFS + same-agent continuity +
//! strict hint-epoch monotonicity via a `DashMap` keyed by handle.

use crate::registry::{ActorRecord, ActorRegistryStore, RegistryStoreError};
use dashmap::DashMap;

/// `DashMap`-backed store. Per-key atomicity comes from the `entry`
/// API: the FCFS check and the insert happen under the same shard
/// guard, so two concurrent registrations of the same handle cannot
/// both win.
#[derive(Default)]
pub struct InMemoryActorStore {
    by_handle: DashMap<String, ActorRecord>,
}

impl InMemoryActorStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ActorRegistryStore for InMemoryActorStore {
    fn register(&self, record: ActorRecord) -> Result<(), RegistryStoreError> {
        use dashmap::mapref::entry::Entry;
        match self.by_handle.entry(record.handle.clone()) {
            Entry::Occupied(_) => Err(RegistryStoreError::HandleTaken),
            Entry::Vacant(v) => {
                v.insert(record);
                Ok(())
            }
        }
    }

    fn update(&self, record: ActorRecord) -> Result<(), RegistryStoreError> {
        use dashmap::mapref::entry::Entry;
        match self.by_handle.entry(record.handle.clone()) {
            Entry::Vacant(_) => Err(RegistryStoreError::UnknownHandle),
            Entry::Occupied(mut o) => {
                let current = o.get();
                if current.agent_id_hex != record.agent_id_hex {
                    return Err(RegistryStoreError::AgentMismatch);
                }
                if record.attestation.hint_epoch_ms <= current.attestation.hint_epoch_ms {
                    return Err(RegistryStoreError::StaleEpoch);
                }
                o.insert(record);
                Ok(())
            }
        }
    }

    fn get(&self, handle: &str) -> Option<ActorRecord> {
        self.by_handle.get(handle).map(|r| r.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::tests_support::record_with;

    #[test]
    fn first_registration_wins_and_second_is_taken() {
        let store = InMemoryActorStore::new();
        store
            .register(record_with("josh", "a".repeat(64), 10))
            .unwrap();
        let dup = store.register(record_with("josh", "b".repeat(64), 99));
        assert_eq!(dup, Err(RegistryStoreError::HandleTaken));
        // The original record is untouched.
        assert_eq!(store.get("josh").unwrap().agent_id_hex, "a".repeat(64));
    }

    #[test]
    fn update_requires_existing_handle() {
        let store = InMemoryActorStore::new();
        assert_eq!(
            store.update(record_with("ghost", "a".repeat(64), 5)),
            Err(RegistryStoreError::UnknownHandle)
        );
    }

    #[test]
    fn update_same_agent_newer_epoch_succeeds() {
        let store = InMemoryActorStore::new();
        let agent = "a".repeat(64);
        store
            .register(record_with("josh", agent.clone(), 10))
            .unwrap();
        store
            .update(record_with("josh", agent.clone(), 11))
            .unwrap();
        assert_eq!(store.get("josh").unwrap().attestation.hint_epoch_ms, 11);
    }

    #[test]
    fn update_rejects_different_agent() {
        let store = InMemoryActorStore::new();
        store
            .register(record_with("josh", "a".repeat(64), 10))
            .unwrap();
        assert_eq!(
            store.update(record_with("josh", "b".repeat(64), 11)),
            Err(RegistryStoreError::AgentMismatch)
        );
    }

    #[test]
    fn update_rejects_stale_or_equal_epoch() {
        let store = InMemoryActorStore::new();
        let agent = "a".repeat(64);
        store
            .register(record_with("josh", agent.clone(), 10))
            .unwrap();
        assert_eq!(
            store.update(record_with("josh", agent.clone(), 10)),
            Err(RegistryStoreError::StaleEpoch)
        );
        assert_eq!(
            store.update(record_with("josh", agent.clone(), 9)),
            Err(RegistryStoreError::StaleEpoch)
        );
    }
}
