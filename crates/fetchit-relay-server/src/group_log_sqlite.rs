//! `SQLite`-backed durable group log (`rusqlite`).
//!
//! Persists opaque per-group log records so epoch catch-up, join-result
//! re-staging, and cold group reconstruction survive a relay restart.
//! Shares the one durable database file with
//! [`crate::transit_sqlite::SqliteTransitStore`] (separate tables,
//! separate WAL-mode connections). The relay never inspects the payload
//! (stays blind); disk-at-rest protection is operator full-disk
//! encryption, consistent with the transit store.

use crate::error::ServerError;
use crate::group_log::{GroupLogStore, StoredLogRecord};
use fetchit_relay_proto::{AgentId, GroupId, LogRecordKind};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// Fixed-size overhead estimate per stored record, mirroring the RAM
/// log's accounting so the global byte cap behaves the same.
const FIXED_OVERHEAD: usize = 64;

fn kind_to_i64(kind: LogRecordKind) -> i64 {
    match kind {
        LogRecordKind::Commit => 0,
        LogRecordKind::JoinResult => 1,
    }
}

fn kind_from_i64(value: i64) -> Option<LogRecordKind> {
    match value {
        0 => Some(LogRecordKind::Commit),
        1 => Some(LogRecordKind::JoinResult),
        _ => None,
    }
}

/// Durable per-group append-only log backed by a single `SQLite` file.
///
/// `rusqlite::Connection` is `!Sync`, so it is wrapped in a `Mutex`;
/// log traffic is modest and `SQLite` serializes writes anyway. The
/// per-group sequence watermark lives in its own `group_log_seq` table,
/// updated in the same transaction as each insert, so an assigned seq
/// is never reused even after a full sweep of the group or a restart.
pub struct SqliteGroupLog {
    conn: Mutex<Connection>,
    window_ms: u64,
    per_group_cap: usize,
    max_total_bytes: usize,
}

impl SqliteGroupLog {
    /// Open (or create) the durable log at `path`. The path may be the
    /// same file the `SQLite` transit store uses — both schemas are
    /// `CREATE TABLE IF NOT EXISTS` and WAL mode supports the two
    /// connections.
    ///
    /// # Errors
    /// [`ServerError::GroupLog`] if the database cannot be opened or
    /// its schema cannot be created.
    pub fn open(
        path: &Path,
        window: Duration,
        per_group_cap: usize,
        max_total_bytes: usize,
    ) -> Result<Self, ServerError> {
        let conn = Connection::open(path).map_err(|e| ServerError::GroupLog(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_log (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 group_id BLOB NOT NULL,
                 seq INTEGER NOT NULL,
                 kind INTEGER NOT NULL,
                 recipient BLOB,
                 payload BLOB NOT NULL,
                 inserted_at_ms INTEGER NOT NULL
             )",
            [],
        )
        .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_group_log_group_seq ON group_log(group_id, seq)",
            [],
        )
        .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_log_seq (
                 group_id BLOB PRIMARY KEY,
                 next_seq INTEGER NOT NULL
             )",
            [],
        )
        .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            per_group_cap,
            max_total_bytes,
        })
    }
}

impl GroupLogStore for SqliteGroupLog {
    fn append(
        &self,
        group: GroupId,
        kind: LogRecordKind,
        recipient: Option<AgentId>,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<u64, ServerError> {
        let size = FIXED_OVERHEAD.saturating_add(payload.len());
        let gid: &[u8] = group.as_bytes();
        let rcpt: Option<Vec<u8>> = recipient.map(|a| a.as_bytes().to_vec());
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| ServerError::GroupLog("group-log mutex poisoned".to_owned()))?;
        let tx = conn
            .transaction()
            .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        let total: i64 = tx
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM group_log",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        if usize::try_from(total)
            .unwrap_or(usize::MAX)
            .saturating_add(size)
            > self.max_total_bytes
        {
            return Err(ServerError::GroupLogFull);
        }
        // Per-group cap: evict the group's oldest record(s) to admit
        // the new one — the newest records are the ones members need.
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM group_log WHERE group_id = ?1",
                params![gid],
                |r| r.get(0),
            )
            .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count >= self.per_group_cap {
            let excess =
                i64::try_from(count.saturating_sub(self.per_group_cap) + 1).unwrap_or(i64::MAX);
            tx.execute(
                "DELETE FROM group_log WHERE group_id = ?1 AND seq IN (
                     SELECT seq FROM group_log WHERE group_id = ?1
                     ORDER BY seq ASC LIMIT ?2
                 )",
                params![gid, excess],
            )
            .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        }
        // Watermark, not MAX(seq)+1: the counter must survive rows
        // being swept or evicted so a seq is never reused.
        let seq: u64 = tx
            .query_row(
                "SELECT next_seq FROM group_log_seq WHERE group_id = ?1",
                params![gid],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| ServerError::GroupLog(e.to_string()))?
            .map_or(1, |v| u64::try_from(v).unwrap_or(u64::MAX));
        tx.execute(
            "INSERT INTO group_log (group_id, seq, kind, recipient, payload, inserted_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                gid,
                i64::try_from(seq).unwrap_or(i64::MAX),
                kind_to_i64(kind),
                rcpt,
                payload,
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        tx.execute(
            "INSERT INTO group_log_seq (group_id, next_seq) VALUES (?1, ?2)
             ON CONFLICT(group_id) DO UPDATE SET next_seq = excluded.next_seq",
            params![
                gid,
                i64::try_from(seq.saturating_add(1)).unwrap_or(i64::MAX)
            ],
        )
        .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        tx.commit()
            .map_err(|e| ServerError::GroupLog(e.to_string()))?;
        Ok(seq)
    }

    fn fetch_since(&self, group: &GroupId, since_seq: u64) -> Vec<StoredLogRecord> {
        let gid: &[u8] = group.as_bytes();
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT seq, kind, recipient, payload, inserted_at_ms FROM group_log
             WHERE group_id = ?1 AND seq > ?2 ORDER BY seq",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(
            params![gid, i64::try_from(since_seq).unwrap_or(i64::MAX)],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        ) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (seq, kind_raw, rcpt, payload, at) in rows.flatten() {
            let Some(kind) = kind_from_i64(kind_raw) else {
                continue;
            };
            let recipient = match rcpt {
                None => None,
                Some(bytes) => match <[u8; 32]>::try_from(bytes) {
                    Ok(b) => Some(AgentId::from_bytes(b)),
                    Err(_) => continue,
                },
            };
            out.push(StoredLogRecord {
                seq: u64::try_from(seq).unwrap_or(0),
                kind,
                recipient,
                payload,
                inserted_at_ms: u64::try_from(at).unwrap_or(0),
            });
        }
        out
    }

    fn sweep_expired(&self, now_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.execute(
            "DELETE FROM group_log WHERE inserted_at_ms <= ?1",
            params![i64::try_from(cutoff).unwrap_or(i64::MAX)],
        )
        .unwrap_or(0)
    }

    fn len(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.query_row("SELECT COUNT(*) FROM group_log", [], |r| r.get::<_, i64>(0))
            .map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX))
    }

    fn total_bytes(&self) -> usize {
        let count = self.len();
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        let raw: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM group_log",
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
    use crate::group_log::GroupLogStore;
    use fetchit_relay_proto::{AgentId, GroupId, LogRecordKind};
    use std::time::Duration;

    const WINDOW: Duration = Duration::from_secs(3600);

    fn gid(tag: u8) -> GroupId {
        GroupId::from_bytes([tag; 32])
    }

    fn aid(tag: u8) -> AgentId {
        AgentId::from_bytes([tag; 32])
    }

    fn open(path: &std::path::Path) -> SqliteGroupLog {
        SqliteGroupLog::open(path, WINDOW, 16, 1 << 30).unwrap()
    }

    fn append_commit(log: &SqliteGroupLog, group: GroupId, payload: &[u8], at: u64) -> u64 {
        log.append(group, LogRecordKind::Commit, None, payload.to_vec(), at)
            .unwrap()
    }

    #[test]
    fn survives_reopen_and_per_group_seq_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.db");
        {
            let s = open(&path);
            assert_eq!(append_commit(&s, gid(1), b"one", 10), 1);
            assert_eq!(append_commit(&s, gid(1), b"two", 20), 2);
            assert_eq!(append_commit(&s, gid(2), b"other", 30), 1);
        } // store dropped == process restart

        let reopened = open(&path);
        let got = reopened.fetch_since(&gid(1), 0);
        assert_eq!(got.len(), 2, "records survived reopen");
        assert_eq!(got[0].seq, 1);
        assert_eq!(got[0].payload, b"one");
        assert_eq!(got[1].seq, 2);
        assert_eq!(
            append_commit(&reopened, gid(1), b"three", 40),
            3,
            "per-group seq resumes after reopen"
        );
        assert_eq!(
            append_commit(&reopened, gid(2), b"again", 50),
            2,
            "independent per-group seq also resumes"
        );
    }

    #[test]
    fn seq_not_reused_after_full_sweep_even_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.db");
        {
            let s = open(&path);
            assert_eq!(append_commit(&s, gid(1), b"a", 0), 1);
            assert_eq!(append_commit(&s, gid(1), b"b", 10), 2);
            assert_eq!(s.sweep_expired(u64::from(u32::MAX)), 2);
            assert!(s.fetch_since(&gid(1), 0).is_empty());
            assert_eq!(
                append_commit(&s, gid(1), b"c", 20), // still old, swept next
                3,
                "seq continues past swept records"
            );
            assert_eq!(s.sweep_expired(u64::from(u32::MAX)), 1);
        }
        let reopened = open(&path);
        assert_eq!(
            append_commit(&reopened, gid(1), b"d", 30),
            4,
            "watermark survives sweep + reopen — a seq is never reused"
        );
    }

    #[test]
    fn fetch_since_orders_ascending_with_strict_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(&dir.path().join("log.db"));
        append_commit(&s, gid(3), b"one", 10);
        append_commit(&s, gid(3), b"two", 20);
        append_commit(&s, gid(3), b"three", 30);

        let all = s.fetch_since(&gid(3), 0);
        assert_eq!(all.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        let tail = s.fetch_since(&gid(3), 2);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].seq, 3);
        assert!(s.fetch_since(&gid(3), 3).is_empty(), "head boundary empty");
        assert!(s.fetch_since(&gid(9), 0).is_empty(), "unknown group empty");
    }

    #[test]
    fn join_result_recipient_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(&dir.path().join("log.db"));
        s.append(
            gid(4),
            LogRecordKind::JoinResult,
            Some(aid(0x42)),
            b"welcome".to_vec(),
            10,
        )
        .unwrap();
        let got = s.fetch_since(&gid(4), 0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, LogRecordKind::JoinResult);
        assert_eq!(got[0].recipient, Some(aid(0x42)));
        assert_eq!(got[0].inserted_at_ms, 10);
    }

    #[test]
    fn per_group_cap_evicts_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteGroupLog::open(&dir.path().join("log.db"), WINDOW, 2, 1 << 30).unwrap();
        append_commit(&s, gid(1), b"aa", 10);
        append_commit(&s, gid(1), b"bb", 20);
        assert_eq!(append_commit(&s, gid(1), b"cc", 30), 3);
        let got = s.fetch_since(&gid(1), 0);
        assert_eq!(
            got.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![2, 3],
            "oldest record evicted, newest retained"
        );
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn global_byte_cap_rejects_with_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let payload = 100usize;
        let s = SqliteGroupLog::open(&dir.path().join("log.db"), WINDOW, 16, payload + 64).unwrap();
        s.append(gid(1), LogRecordKind::Commit, None, vec![0u8; payload], 10)
            .expect("first record fits");
        let err = s
            .append(gid(2), LogRecordKind::Commit, None, vec![0u8; payload], 20)
            .expect_err("second record must trip the global cap");
        assert!(matches!(err, crate::error::ServerError::GroupLogFull));
    }

    #[test]
    fn sweep_evicts_by_age() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteGroupLog::open(
            &dir.path().join("log.db"),
            Duration::from_millis(100),
            16,
            1 << 30,
        )
        .unwrap();
        append_commit(&s, gid(1), b"old", 0);
        append_commit(&s, gid(1), b"fresh", 950);
        assert_eq!(s.sweep_expired(1_000), 1);
        let left = s.fetch_since(&gid(1), 0);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].payload, b"fresh");
    }

    #[test]
    fn shares_one_db_file_with_the_transit_store() {
        use crate::transit::TransitStore;
        use fetchit_relay_proto::{EnvelopeKind, MachineId, TransitEnvelope, WIRE_VERSION};

        // The daemon opens BOTH durable stores on the one
        // FETCHIT_RELAY_TRANSIT_DB path — two tables, two WAL-mode
        // connections, one file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let transit = crate::transit_sqlite::SqliteTransitStore::open(
            &path,
            Duration::from_secs(3600),
            256,
            1 << 30,
        )
        .unwrap();
        let log = open(&path);

        let to = aid(9);
        transit
            .enqueue(
                to,
                TransitEnvelope {
                    version: WIRE_VERSION,
                    kind: EnvelopeKind::Dm,
                    group_id: None,
                    tenant_id: None,
                    sender_agent_id: aid(1),
                    sender_machine_id: MachineId::from_bytes([0u8; 32]),
                    timestamp_ms: 1,
                    epoch: 0,
                    ciphertext: vec![7u8; 8],
                    nonce: vec![],
                    kem_ciphertext: vec![],
                    sender_signature: vec![],
                },
            )
            .unwrap();
        assert_eq!(append_commit(&log, gid(1), b"coexists", 10), 1);

        assert_eq!(transit.read_all(&to).len(), 1);
        assert_eq!(log.fetch_since(&gid(1), 0).len(), 1);
    }
}
