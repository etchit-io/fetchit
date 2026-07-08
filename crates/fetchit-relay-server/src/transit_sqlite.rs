//! `SQLite`-backed durable transit store (`rusqlite`).
//!
//! Persists opaque `TransitEnvelope` ciphertext per recipient so
//! undelivered messages survive a relay restart and a multi-day offline
//! window. `SQLite` already backs the relay's registry store, so
//! durability is added with no new dependency. The relay never inspects
//! the payload (stays blind); disk-at-rest protection is operator
//! full-disk encryption (consistent with x0xd ADR-0015).

use crate::error::ServerError;
use crate::transit::{StoredEntry, TransitStore};
use fetchit_relay_proto::{AgentId, TransitEnvelope};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// Fixed-size overhead estimate per stored envelope, mirroring the RAM
/// buffer's accounting so the global byte cap behaves the same.
const FIXED_OVERHEAD: usize = 128;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

fn row_size(env: &TransitEnvelope) -> usize {
    FIXED_OVERHEAD
        .saturating_add(env.ciphertext.len())
        .saturating_add(env.nonce.len())
        .saturating_add(env.kem_ciphertext.len())
        .saturating_add(env.sender_signature.len())
}

/// Durable per-recipient transit store backed by a single `SQLite` file.
///
/// `rusqlite::Connection` is `!Sync`, so it is wrapped in a `Mutex`;
/// transit traffic is modest and `SQLite` serializes writes anyway.
pub struct SqliteTransitStore {
    conn: Mutex<Connection>,
    ttl_ms: u64,
    cap_per_recipient: usize,
    max_total_bytes: usize,
}

impl SqliteTransitStore {
    /// Open (or create) the durable store at `path`.
    ///
    /// # Errors
    /// [`ServerError::TransitStore`] if the database cannot be opened or
    /// its schema cannot be created.
    pub fn open(
        path: &Path,
        ttl: Duration,
        cap_per_recipient: usize,
        max_total_bytes: usize,
    ) -> Result<Self, ServerError> {
        let conn = Connection::open(path).map_err(|e| ServerError::TransitStore(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 recipient BLOB NOT NULL,
                 enqueued_at_ms INTEGER NOT NULL,
                 envelope BLOB NOT NULL
             )",
            [],
        )
        .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transit_recipient ON transit(recipient, id)",
            [],
        )
        .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            ttl_ms: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
            cap_per_recipient,
            max_total_bytes,
        })
    }
}

impl TransitStore for SqliteTransitStore {
    fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<u64, ServerError> {
        let bytes = postcard::to_allocvec(&envelope)
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        let size = row_size(&envelope);
        let rid: &[u8] = to.as_bytes();
        let conn = self
            .conn
            .lock()
            .map_err(|_| ServerError::TransitStore("transit mutex poisoned".to_owned()))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM transit WHERE recipient = ?1",
                params![rid],
                |r| r.get(0),
            )
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= self.cap_per_recipient {
            return Err(ServerError::TransitBufferFull);
        }
        let total: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(envelope)), 0) FROM transit",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        if usize::try_from(total)
            .unwrap_or(usize::MAX)
            .saturating_add(size)
            > self.max_total_bytes
        {
            return Err(ServerError::TransitBufferFull);
        }
        conn.execute(
            "INSERT INTO transit (recipient, enqueued_at_ms, envelope) VALUES (?1, ?2, ?3)",
            params![rid, i64::try_from(now_ms()).unwrap_or(i64::MAX), bytes],
        )
        .map_err(|e| ServerError::TransitStore(e.to_string()))?;
        Ok(u64::try_from(conn.last_insert_rowid()).unwrap_or(0))
    }

    fn read_all(&self, to: &AgentId) -> Vec<StoredEntry> {
        let rid: &[u8] = to.as_bytes();
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, enqueued_at_ms, envelope FROM transit WHERE recipient = ?1 ORDER BY id",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params![rid], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        }) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (id, at, env_bytes) in rows.flatten() {
            if let Ok(envelope) = postcard::from_bytes::<TransitEnvelope>(&env_bytes) {
                out.push(StoredEntry {
                    id: u64::try_from(id).unwrap_or(0),
                    envelope,
                    enqueued_at_ms: u64::try_from(at).unwrap_or(0),
                });
            }
        }
        out
    }

    fn delete(&self, to: &AgentId, ids: &[u64]) {
        let rid: &[u8] = to.as_bytes();
        let Ok(conn) = self.conn.lock() else {
            return;
        };
        for id in ids {
            let _ = conn.execute(
                "DELETE FROM transit WHERE recipient = ?1 AND id = ?2",
                params![rid, i64::try_from(*id).unwrap_or(i64::MAX)],
            );
        }
    }

    fn sweep_expired(&self) -> usize {
        let cutoff = now_ms().saturating_sub(self.ttl_ms);
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.execute(
            "DELETE FROM transit WHERE enqueued_at_ms <= ?1",
            params![i64::try_from(cutoff).unwrap_or(i64::MAX)],
        )
        .unwrap_or(0)
    }

    fn len(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.query_row("SELECT COUNT(*) FROM transit", [], |r| r.get::<_, i64>(0))
            .map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX))
    }

    fn total_bytes(&self) -> usize {
        let count = self.len();
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        let raw: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(envelope)), 0) FROM transit",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        usize::try_from(raw)
            .unwrap_or(0)
            .saturating_add(count.saturating_mul(FIXED_OVERHEAD))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::transit::TransitStore;
    use fetchit_relay_proto::{EnvelopeKind, MachineId, WIRE_VERSION};

    fn env() -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1; 32]),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![7u8; 32],
            nonce: vec![],
            kem_ciphertext: vec![],
            sender_signature: vec![],
        }
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.db");
        let to = AgentId::from_bytes([9u8; 32]);
        let id = {
            let s =
                SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
            let id = s.enqueue(to, env()).unwrap();
            assert_eq!(s.read_all(&to).len(), 1);
            id
        }; // store dropped == process restart
        let reopened =
            SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
        let after = reopened.read_all(&to);
        assert_eq!(after.len(), 1, "entry survived reopen");
        assert_eq!(after[0].id, id);
        assert_eq!(
            after[0].envelope.ciphertext,
            vec![7u8; 32],
            "ciphertext intact across reopen"
        );
    }

    #[test]
    fn delete_then_reopen_stays_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let to = AgentId::from_bytes([4u8; 32]);
        let s = SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
        let id = s.enqueue(to, env()).unwrap();
        s.delete(&to, &[id]);
        drop(s);
        let s2 = SqliteTransitStore::open(&path, Duration::from_secs(3600), 256, 1 << 30).unwrap();
        assert!(s2.read_all(&to).is_empty());
    }

    #[test]
    fn ttl_sweep_removes_old() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let to = AgentId::from_bytes([5u8; 32]);
        // ttl 0 => everything is already expired.
        let s = SqliteTransitStore::open(&path, Duration::from_millis(0), 256, 1 << 30).unwrap();
        s.enqueue(to, env()).unwrap();
        assert_eq!(s.sweep_expired(), 1);
        assert!(s.read_all(&to).is_empty());
    }

    #[test]
    fn per_recipient_cap_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let to = AgentId::from_bytes([6u8; 32]);
        let s = SqliteTransitStore::open(&path, Duration::from_secs(3600), 2, 1 << 30).unwrap();
        s.enqueue(to, env()).unwrap();
        s.enqueue(to, env()).unwrap();
        let err = s.enqueue(to, env()).unwrap_err();
        assert!(matches!(err, ServerError::TransitBufferFull));
    }
}
