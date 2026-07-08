//! Per-group append-only record log.
//!
//! [`GroupLogStore`] is the seam. [`RamGroupLog`] is the in-RAM
//! implementation used in tests and as the no-path fallback; the
//! production daemon uses the `SQLite`-backed
//! [`crate::group_log_sqlite::SqliteGroupLog`] so log records survive a
//! relay restart.
//!
//! The log serves three consumers — epoch catch-up, durable join-result
//! re-staging, and cold group reconstruction — so retention is
//! serve-to-many, NOT delete-on-ack: fetches never remove records, only
//! retention expiry (the time-window sweep), the per-group record cap
//! (evict-oldest-in-group), or the global byte cap (append rejected)
//! bound the store. Implementations hold only opaque ciphertext
//! payloads and never inspect them — the relay stays blind.

use crate::error::ServerError;
use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, GroupId, LogRecordKind};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Fixed-size overhead estimate per record (scalars plus length
/// prefixes), mirroring the transit store's accounting so the global
/// byte cap behaves the same way. Conservative — over-counts by a few
/// bytes vs the true wire size, the safe direction for a cap.
const RECORD_FIXED_OVERHEAD: usize = 64;

fn record_size(payload_len: usize) -> usize {
    RECORD_FIXED_OVERHEAD.saturating_add(payload_len)
}

/// One stored group-log record.
#[derive(Clone, Debug)]
pub struct StoredLogRecord {
    /// Relay-assigned per-group sequence number. Starts at 1 (`0` is
    /// the "from the beginning" fetch sentinel) and is never reused
    /// within a group.
    pub seq: u64,
    /// Record kind.
    pub kind: LogRecordKind,
    /// `None` for a [`LogRecordKind::Commit`]; `Some(joiner)` for a
    /// [`LogRecordKind::JoinResult`].
    pub recipient: Option<AgentId>,
    /// Opaque ciphertext payload — never inspected by the relay.
    pub payload: Vec<u8>,
    /// Server-side append time (ms since the Unix epoch).
    pub inserted_at_ms: u64,
}

/// A per-group, append-only, blind record log.
///
/// Implementations MUST persist only opaque ciphertext payloads and
/// never inspect them.
pub trait GroupLogStore: Send + Sync {
    /// Append one record to `group`'s log, returning the assigned
    /// per-group sequence number (monotonic, starts at 1, never
    /// reused).
    ///
    /// When the per-group record cap is hit, the OLDEST record in the
    /// group is evicted to admit the new one — the newest records are
    /// the ones members need to catch up, so old ones yield first.
    ///
    /// # Errors
    /// [`ServerError::GroupLogFull`] when admitting the record would
    /// exceed the global byte cap; [`ServerError::GroupLog`] on a
    /// backend failure.
    fn append(
        &self,
        group: GroupId,
        kind: LogRecordKind,
        recipient: Option<AgentId>,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<u64, ServerError>;

    /// Every record in `group` with `seq > since_seq`, ascending.
    /// Non-destructive: records stay stored until retention expiry
    /// regardless of how many times they are fetched.
    fn fetch_since(&self, group: &GroupId, since_seq: u64) -> Vec<StoredLogRecord>;

    /// Evict every record older than the retention window relative to
    /// `now_ms`; returns the count evicted.
    fn sweep_expired(&self, now_ms: u64) -> usize;

    /// Total records currently stored across all groups.
    fn len(&self) -> usize;

    /// True if nothing is stored.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total accounted bytes across all groups.
    fn total_bytes(&self) -> usize;
}

/// One group's slice of the in-RAM log.
struct GroupSlot {
    /// Next sequence number to assign. Persists even when every record
    /// in the group has been evicted, so a seq is never reused.
    next_seq: u64,
    /// Records in ascending `seq` order.
    records: VecDeque<StoredLogRecord>,
}

/// In-RAM per-group append-only log with window eviction. The
/// test/fallback [`GroupLogStore`]; production uses the `SQLite`
/// backend.
///
/// Group slots persist after their records are swept so the per-group
/// sequence counter keeps climbing — a slot is two words plus the map
/// entry, negligible against reused sequence numbers confusing every
/// log consumer.
pub struct RamGroupLog {
    groups: DashMap<GroupId, GroupSlot>,
    window_ms: u64,
    per_group_cap: usize,
    max_total_bytes: usize,
    total_bytes: AtomicUsize,
}

impl RamGroupLog {
    /// Create an empty log with the given retention window, per-group
    /// record cap, and global byte cap.
    #[must_use]
    pub fn new(window: Duration, per_group_cap: usize, max_total_bytes: usize) -> Self {
        Self {
            groups: DashMap::new(),
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            per_group_cap,
            max_total_bytes,
            total_bytes: AtomicUsize::new(0),
        }
    }

    fn reserve_bytes(&self, size: usize) -> Result<(), ServerError> {
        let mut current = self.total_bytes.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(size);
            if next > self.max_total_bytes {
                return Err(ServerError::GroupLogFull);
            }
            match self.total_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }
}

impl GroupLogStore for RamGroupLog {
    fn append(
        &self,
        group: GroupId,
        kind: LogRecordKind,
        recipient: Option<AgentId>,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<u64, ServerError> {
        let size = record_size(payload.len());
        self.reserve_bytes(size)?;
        let mut slot = self.groups.entry(group).or_insert_with(|| GroupSlot {
            next_seq: 1,
            records: VecDeque::new(),
        });
        // Per-group cap: evict the group's oldest record(s) to admit
        // the new one, releasing their byte budget.
        while slot.records.len() >= self.per_group_cap {
            let Some(old) = slot.records.pop_front() else {
                break;
            };
            self.total_bytes
                .fetch_sub(record_size(old.payload.len()), Ordering::Relaxed);
        }
        let seq = slot.next_seq;
        slot.next_seq = slot.next_seq.saturating_add(1);
        slot.records.push_back(StoredLogRecord {
            seq,
            kind,
            recipient,
            payload,
            inserted_at_ms: now_ms,
        });
        Ok(seq)
    }

    fn fetch_since(&self, group: &GroupId, since_seq: u64) -> Vec<StoredLogRecord> {
        self.groups
            .get(group)
            .map(|slot| {
                slot.records
                    .iter()
                    .filter(|r| r.seq > since_seq)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn sweep_expired(&self, now_ms: u64) -> usize {
        let mut evicted = 0usize;
        let mut freed = 0usize;
        // Slots are kept (returning true) even when emptied: `next_seq`
        // must survive so a later append never reuses a sequence number.
        self.groups.retain(|_, slot| {
            let before = slot.records.len();
            slot.records.retain(|r| {
                let alive = now_ms.saturating_sub(r.inserted_at_ms) < self.window_ms;
                if !alive {
                    freed = freed.saturating_add(record_size(r.payload.len()));
                }
                alive
            });
            evicted = evicted.saturating_add(before - slot.records.len());
            true
        });
        self.total_bytes.fetch_sub(freed, Ordering::Relaxed);
        evicted
    }

    fn len(&self) -> usize {
        self.groups.iter().map(|slot| slot.records.len()).sum()
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(3600);

    fn log() -> RamGroupLog {
        RamGroupLog::new(WINDOW, 16, usize::MAX)
    }

    fn gid(tag: u8) -> GroupId {
        GroupId::from_bytes([tag; 32])
    }

    fn aid(tag: u8) -> AgentId {
        AgentId::from_bytes([tag; 32])
    }

    fn append_commit(log: &RamGroupLog, group: GroupId, payload: &[u8], at: u64) -> u64 {
        log.append(group, LogRecordKind::Commit, None, payload.to_vec(), at)
            .unwrap()
    }

    #[test]
    fn seq_starts_at_1_and_is_monotonic_per_group() {
        let l = log();
        assert_eq!(append_commit(&l, gid(1), b"a", 10), 1);
        assert_eq!(append_commit(&l, gid(1), b"b", 20), 2);
        assert_eq!(append_commit(&l, gid(1), b"c", 30), 3);
    }

    #[test]
    fn seq_counters_are_independent_across_groups() {
        let l = log();
        assert_eq!(append_commit(&l, gid(1), b"a", 10), 1);
        assert_eq!(append_commit(&l, gid(1), b"b", 20), 2);
        assert_eq!(append_commit(&l, gid(2), b"x", 30), 1);
        assert_eq!(append_commit(&l, gid(2), b"y", 40), 1 + 1);
        assert_eq!(append_commit(&l, gid(1), b"c", 50), 3);
    }

    #[test]
    fn fetch_since_returns_newer_records_ascending() {
        let l = log();
        append_commit(&l, gid(7), b"one", 10);
        append_commit(&l, gid(7), b"two", 20);
        append_commit(&l, gid(7), b"three", 30);

        let all = l.fetch_since(&gid(7), 0);
        assert_eq!(all.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(all[0].payload, b"one");
        assert_eq!(all[2].payload, b"three");

        let tail = l.fetch_since(&gid(7), 2);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].seq, 3);
    }

    #[test]
    fn fetch_since_head_returns_empty() {
        let l = log();
        append_commit(&l, gid(7), b"one", 10);
        append_commit(&l, gid(7), b"two", 20);
        assert!(l.fetch_since(&gid(7), 2).is_empty());
    }

    #[test]
    fn fetch_since_unknown_group_returns_empty() {
        let l = log();
        assert!(l.fetch_since(&gid(9), 0).is_empty());
    }

    #[test]
    fn fetch_is_non_destructive() {
        let l = log();
        append_commit(&l, gid(3), b"stay", 10);
        assert_eq!(l.fetch_since(&gid(3), 0).len(), 1);
        assert_eq!(l.fetch_since(&gid(3), 0).len(), 1, "serve-to-many");
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn join_result_recipient_round_trips_through_store() {
        let l = log();
        l.append(
            gid(4),
            LogRecordKind::JoinResult,
            Some(aid(0x42)),
            b"welcome".to_vec(),
            10,
        )
        .unwrap();
        let got = l.fetch_since(&gid(4), 0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, LogRecordKind::JoinResult);
        assert_eq!(got[0].recipient, Some(aid(0x42)));
    }

    #[test]
    fn per_group_cap_evicts_oldest_and_releases_bytes() {
        let l = RamGroupLog::new(WINDOW, 2, usize::MAX);
        append_commit(&l, gid(1), b"aa", 10);
        append_commit(&l, gid(1), b"bb", 20);
        let bytes_at_cap = l.total_bytes();
        assert_eq!(append_commit(&l, gid(1), b"cc", 30), 3);

        let got = l.fetch_since(&gid(1), 0);
        assert_eq!(
            got.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![2, 3],
            "oldest record evicted, newest retained"
        );
        assert_eq!(
            l.total_bytes(),
            bytes_at_cap,
            "evicted record's bytes released"
        );
    }

    #[test]
    fn global_byte_cap_rejects_with_typed_error_and_no_leak() {
        // Cap sized to fit exactly one 100-byte payload. The second
        // append to a DIFFERENT group must be rejected — the cap is
        // global, not per-group.
        let payload = 100usize;
        let cap = RECORD_FIXED_OVERHEAD + payload;
        let l = RamGroupLog::new(WINDOW, 16, cap);
        l.append(gid(1), LogRecordKind::Commit, None, vec![0u8; payload], 10)
            .expect("first record fits");
        let err = l
            .append(gid(2), LogRecordKind::Commit, None, vec![0u8; payload], 20)
            .expect_err("second record must trip the global cap");
        assert!(matches!(err, ServerError::GroupLogFull));
        assert_eq!(
            l.total_bytes(),
            cap,
            "rejected append must not leak reserved bytes"
        );
    }

    #[test]
    fn sweep_evicts_by_age_and_releases_bytes() {
        let l = RamGroupLog::new(Duration::from_millis(100), 16, usize::MAX);
        append_commit(&l, gid(1), b"old", 0);
        append_commit(&l, gid(1), b"fresh", 950);
        let evicted = l.sweep_expired(1_000);
        assert_eq!(evicted, 1);
        let left = l.fetch_since(&gid(1), 0);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].payload, b"fresh");

        // Sweep everything and confirm the byte budget fully returns.
        assert_eq!(l.sweep_expired(5_000), 1);
        assert_eq!(l.total_bytes(), 0, "sweep must free evicted bytes");
        assert!(l.is_empty());
    }

    #[test]
    fn seq_is_not_reused_after_a_full_sweep() {
        let l = RamGroupLog::new(Duration::from_millis(100), 16, usize::MAX);
        assert_eq!(append_commit(&l, gid(1), b"a", 0), 1);
        assert_eq!(append_commit(&l, gid(1), b"b", 10), 2);
        assert_eq!(l.sweep_expired(10_000), 2, "everything expired");
        assert_eq!(
            append_commit(&l, gid(1), b"c", 10_001),
            3,
            "seq continues past swept records — never reused"
        );
    }
}
