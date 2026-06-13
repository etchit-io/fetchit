//! Durable, in-relay actor-registry ledger backed by `SQLite` (Task 13).
//!
//! `SQLite` is the SINGLE FCFS authority (Alice's design note): [`register`]
//! is an `INSERT .. ON CONFLICT(handle) DO NOTHING` whose committed
//! result IS the land-grab outcome, and the write commits BEFORE the
//! method returns, so a `201` survives a crash one second later
//! (durable-before-ack). [`update`] runs the same-agent + epoch CAS
//! inside one transaction. The DB file is the durable state, so
//! "load on boot" is just opening it; FCFS + epoch monotonicity survive
//! restart. The in-memory [`super::InMemoryActorStore`] stays for tests.
//!
//! [`register`]: SqliteActorStore::register
//! [`update`]: SqliteActorStore::update

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};

use crate::registry::{ActorRecord, ActorRegistryStore, RegistryStoreError};
use fetchit_fedi::attestation::ActorAttestationV2;

/// SQLite-backed registry store. The `Connection` is wrapped in a
/// `Mutex` because `rusqlite::Connection` is `Send` but not `Sync`;
/// registration volume is low, so a single serialized connection with
/// short critical sections is ample and gives serializable FCFS for free.
pub struct SqliteActorStore {
    conn: Mutex<Connection>,
}

/// Map a `rusqlite` error into the store's `Storage` variant (HTTP 500).
#[allow(clippy::needless_pass_by_value)]
fn storage(e: rusqlite::Error) -> RegistryStoreError {
    RegistryStoreError::Storage(e.to_string())
}

impl SqliteActorStore {
    /// Open (creating if absent) the registry DB at `path` and ensure the
    /// schema. Opening IS the boot-load: the table is the durable state.
    ///
    /// # Errors
    /// [`RegistryStoreError::Storage`] if the DB cannot be opened or the
    /// schema cannot be created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegistryStoreError> {
        Self::from_conn(Connection::open(path).map_err(storage)?)
    }

    fn from_conn(conn: Connection) -> Result<Self, RegistryStoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS actors (
                handle           TEXT PRIMARY KEY NOT NULL,
                actor_url        TEXT NOT NULL,
                agent_id_hex     TEXT NOT NULL,
                rsa_spki_der     BLOB NOT NULL,
                attestation_json TEXT NOT NULL,
                hint_epoch_ms    INTEGER NOT NULL,
                registered_at_ms INTEGER NOT NULL
            );",
        )
        .map_err(storage)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, RegistryStoreError> {
        self.conn
            .lock()
            .map_err(|_| RegistryStoreError::Storage("registry connection lock poisoned".into()))
    }
}

impl ActorRegistryStore for SqliteActorStore {
    fn register(&self, record: ActorRecord) -> Result<(), RegistryStoreError> {
        let attestation_json = serde_json::to_string(&record.attestation)
            .map_err(|e| RegistryStoreError::Storage(e.to_string()))?;
        let conn = self.lock()?;
        // ON CONFLICT DO NOTHING: the committed row-count IS the FCFS
        // verdict. Autocommit persists before this returns -> a later 201
        // survives a crash (durable-before-ack).
        let changed = conn
            .execute(
                "INSERT INTO actors
                   (handle, actor_url, agent_id_hex, rsa_spki_der,
                    attestation_json, hint_epoch_ms, registered_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(handle) DO NOTHING",
                rusqlite::params![
                    record.handle,
                    record.actor_url,
                    record.agent_id_hex,
                    record.rsa_spki_der,
                    attestation_json,
                    record.attestation.hint_epoch_ms,
                    record.registered_at_ms,
                ],
            )
            .map_err(storage)?;
        if changed == 0 {
            return Err(RegistryStoreError::HandleTaken);
        }
        Ok(())
    }

    fn update(&self, record: ActorRecord) -> Result<(), RegistryStoreError> {
        let attestation_json = serde_json::to_string(&record.attestation)
            .map_err(|e| RegistryStoreError::Storage(e.to_string()))?;
        let mut conn = self.lock()?;
        // One transaction over read-check-write; the Mutex serializes it,
        // so the same-agent + strictly-greater-epoch CAS is atomic.
        let tx = conn.transaction().map_err(storage)?;
        let current: Option<(String, u64)> = tx
            .query_row(
                "SELECT agent_id_hex, hint_epoch_ms FROM actors WHERE handle = ?1",
                rusqlite::params![record.handle],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let Some((cur_agent, cur_epoch)) = current else {
            return Err(RegistryStoreError::UnknownHandle);
        };
        if cur_agent != record.agent_id_hex {
            return Err(RegistryStoreError::AgentMismatch);
        }
        if record.attestation.hint_epoch_ms <= cur_epoch {
            return Err(RegistryStoreError::StaleEpoch);
        }
        tx.execute(
            "UPDATE actors
                SET actor_url = ?2, agent_id_hex = ?3, rsa_spki_der = ?4,
                    attestation_json = ?5, hint_epoch_ms = ?6, registered_at_ms = ?7
              WHERE handle = ?1",
            rusqlite::params![
                record.handle,
                record.actor_url,
                record.agent_id_hex,
                record.rsa_spki_der,
                attestation_json,
                record.attestation.hint_epoch_ms,
                record.registered_at_ms,
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(())
    }

    fn get(&self, handle: &str) -> Option<ActorRecord> {
        let conn = self.lock().ok()?;
        let row: Option<(String, String, String, Vec<u8>, String, i64)> = conn
            .query_row(
                "SELECT handle, actor_url, agent_id_hex, rsa_spki_der,
                        attestation_json, registered_at_ms
                   FROM actors WHERE handle = ?1",
                rusqlite::params![handle],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten();
        let (handle, actor_url, agent_id_hex, rsa_spki_der, attestation_json, reg) = row?;
        let attestation: ActorAttestationV2 = serde_json::from_str(&attestation_json).ok()?;
        Some(ActorRecord {
            handle,
            actor_url,
            agent_id_hex,
            rsa_spki_der,
            attestation,
            registered_at_ms: u64::try_from(reg).unwrap_or(0),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::tests_support::record_with;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// In-memory `SQLite`: same schema + code path as the on-disk store,
    /// minus cross-process durability.
    fn mem() -> SqliteActorStore {
        SqliteActorStore::from_conn(Connection::open_in_memory().unwrap()).unwrap()
    }

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    fn temp_db_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("fetchit-reg-test-{}-{n}.db", std::process::id()))
    }

    #[test]
    fn first_registration_wins_and_second_is_taken() {
        let store = mem();
        store
            .register(record_with("josh", "a".repeat(64), 10))
            .unwrap();
        assert_eq!(
            store.register(record_with("josh", "b".repeat(64), 99)),
            Err(RegistryStoreError::HandleTaken)
        );
        assert_eq!(store.get("josh").unwrap().agent_id_hex, "a".repeat(64));
    }

    #[test]
    fn update_continuity_and_epoch_rules_match_in_memory_store() {
        let store = mem();
        let agent = "a".repeat(64);
        assert_eq!(
            store.update(record_with("ghost", agent.clone(), 5)),
            Err(RegistryStoreError::UnknownHandle)
        );
        store
            .register(record_with("josh", agent.clone(), 10))
            .unwrap();
        store
            .update(record_with("josh", agent.clone(), 11))
            .unwrap();
        assert_eq!(store.get("josh").unwrap().attestation.hint_epoch_ms, 11);
        assert_eq!(
            store.update(record_with("josh", "b".repeat(64), 12)),
            Err(RegistryStoreError::AgentMismatch)
        );
        assert_eq!(
            store.update(record_with("josh", agent.clone(), 11)),
            Err(RegistryStoreError::StaleEpoch)
        );
    }

    #[test]
    fn get_round_trips_the_full_record_including_attestation() {
        let store = mem();
        let rec = record_with("josh", "a".repeat(64), 42);
        store.register(rec.clone()).unwrap();
        assert_eq!(store.get("josh"), Some(rec));
        assert_eq!(store.get("nobody"), None);
    }

    #[test]
    fn registration_survives_reopen() {
        let path = temp_db_path();
        {
            let store = SqliteActorStore::open(&path).unwrap();
            store
                .register(record_with("josh", "a".repeat(64), 10))
                .unwrap();
        } // store dropped -> connection closed
        {
            let store = SqliteActorStore::open(&path).unwrap();
            let got = store.get("josh").expect("registration survived restart");
            assert_eq!(got.handle, "josh");
            assert_eq!(got.agent_id_hex, "a".repeat(64));
            // FCFS still holds after reopen.
            assert_eq!(
                store.register(record_with("josh", "b".repeat(64), 99)),
                Err(RegistryStoreError::HandleTaken)
            );
        }
        let _ = std::fs::remove_file(&path);
    }
}
