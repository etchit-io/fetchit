//! Durable pending-join driver: re-drives a saved join to convergence.
//!
//! The driver's dependency set contains **no** `join_post` — it can only
//! re-bridge the already-captured event and probe membership. That is the
//! structural guarantee that a retry never spends a second invite (G1). It
//! runs on client startup and on a capped backoff while the client lives,
//! turning "owner offline" into an auto-completing pending state (G3). See
//! `docs/superpowers/specs/2026-07-04-durable-join-design.md`.

use std::future::Future;

use crate::error::ChatError;
use crate::groups::pending_join::{PendingJoin, PendingJoinState, PendingJoinStore};

/// Where the joiner stands relative to the group roster + its own keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStatus {
    /// Not in the roster yet — the owner has not applied our join.
    Absent,
    /// In the roster AND we hold the group key — fully joined.
    ActiveKeyed,
    /// In the roster but we hold no group key (Welcome lost); recoverable
    /// by re-requesting the staged join-result, never a new invite.
    ListedButUnkeyed,
}

/// Re-sends the saved captured `member_joined` to the owner over the relay.
/// Implementations MUST NOT call `join_post`.
pub trait JoinBridge {
    /// Re-bridge the saved event so the owner (re-)applies our join.
    fn rebridge(&self, record: &PendingJoin) -> impl Future<Output = Result<(), ChatError>> + Send;
    /// Re-request the staged join-result (Welcome) for the unkeyed case.
    fn request_join_result(
        &self,
        record: &PendingJoin,
    ) -> impl Future<Output = Result<(), ChatError>> + Send;
}

/// Probes whether the joiner has converged into the group.
pub trait MembershipProbe {
    /// Current membership status of the joiner in `group_id`.
    fn status(
        &self,
        group_id: &str,
    ) -> impl Future<Output = Result<MembershipStatus, ChatError>> + Send;
}

/// Monotonic clock (injectable for tests).
pub trait Clock {
    /// Milliseconds since an arbitrary fixed epoch (monotonic within a run).
    fn now_ms(&self) -> u64;
}

/// Result of driving one record one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveOutcome {
    /// Fully joined; the record has been removed.
    Converged,
    /// Still working; record persisted with bumped attempt state.
    Pending,
    /// Terminally failed; the record has been removed.
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
}

/// Exponential backoff (capped) for the spawn loop's re-bridge cadence.
/// N1 (Bob's PR #7 review): `drive_once` re-bridges on every Absent tick, so
/// the LOOP must gate the tick — a record is due only once
/// `last_attempt_ms + backoff_ms(attempts)` has passed. Pure + unit-tested.
#[must_use]
pub fn backoff_ms(attempts: u32) -> u64 {
    const BASE_MS: u64 = 2_000;
    const CAP_MS: u64 = 5 * 60 * 1_000; // 5 min
                                        // First attempt (attempts==0) is immediate; then 2s,4s,8s,… capped.
    if attempts == 0 {
        return 0;
    }
    BASE_MS.saturating_mul(1u64 << attempts.min(20)).min(CAP_MS)
}

/// True when `record` is due for another drive tick at `now_ms`. Jitter is
/// applied by the caller (the spawn loop) via its own sleep, not here, so
/// this stays deterministic for tests.
#[must_use]
pub fn is_due(record: &PendingJoin, now_ms: u64) -> bool {
    now_ms
        >= record
            .last_attempt_ms
            .saturating_add(backoff_ms(record.attempts))
}

/// Whether an engine-A join-result apply may retire the durable
/// pending-join record. An apply that answered Ok is NOT sufficient
/// proof of keying: a version-skewed daemon has been observed live
/// (2026-07-31, an x0x 0.27 daemon applying a 0.34-tail join-result)
/// answering Ok while installing no `TreeKEM` state — and retiring the
/// record on that lie strands a keyless roster member with no safety
/// net, the exact split-brain the durable record exists to prevent.
/// Only a CONFIRMED keyed probe (`Some(true)`) retires; an unkeyed
/// probe or a probe failure keeps the record for the resume driver.
#[must_use]
pub fn apply_ok_retires_record(probe_keyed: Option<bool>) -> bool {
    probe_keyed == Some(true)
}

/// Wall-clock ms since the epoch (saturating), for the production driver.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

/// Production [`Clock`] over the wall clock via [`now_ms`]. The unit type is
/// `Sync`, so the driver satisfies its `C: Clock + Sync` bound with a borrow
/// of the live client for the bridge/probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        now_ms()
    }
}

/// Drives durable pending joins to completion.
pub struct PendingJoinDriver<B, P, C> {
    store: PendingJoinStore,
    bridge: B,
    probe: P,
    clock: C,
}

impl<B: JoinBridge + Sync, P: MembershipProbe + Sync, C: Clock + Sync> PendingJoinDriver<B, P, C> {
    /// Construct a driver over a store + injected bridge/probe/clock.
    #[must_use]
    pub fn new(store: PendingJoinStore, bridge: B, probe: P, clock: C) -> Self {
        Self {
            store,
            bridge,
            probe,
            clock,
        }
    }

    /// Drive a single record one step. Terminal outcomes remove the record.
    ///
    /// # Errors
    /// Propagates a store I/O error. A bridge/probe *network* error is not
    /// fatal — it leaves the record `Pending` for the next tick.
    pub async fn drive_once(&self, mut record: PendingJoin) -> Result<DriveOutcome, ChatError> {
        if record.is_terminal() {
            return Ok(DriveOutcome::Failed {
                reason: match record.state {
                    PendingJoinState::Failed { reason } => reason,
                    _ => String::new(),
                },
            });
        }

        match self.probe.status(&record.group_id).await {
            Ok(MembershipStatus::ActiveKeyed) => {
                self.store.remove(&record.group_id)?;
                Ok(DriveOutcome::Converged)
            }
            Ok(MembershipStatus::ListedButUnkeyed) => {
                record.state = PendingJoinState::KeyedButUnverified;
                record.last_attempt_ms = self.clock.now_ms();
                record.attempts = record.attempts.saturating_add(1);
                self.store.upsert(&record)?;
                // Re-request the Welcome; a failure just retries next tick.
                let _ = self.bridge.request_join_result(&record).await;
                Ok(DriveOutcome::Pending)
            }
            Ok(MembershipStatus::Absent) => {
                record.state = PendingJoinState::Bridged;
                record.last_attempt_ms = self.clock.now_ms();
                record.attempts = record.attempts.saturating_add(1);
                self.store.upsert(&record)?;
                // Re-bridge the SAVED event — never a join_post. A network
                // error is non-fatal; the record stays Pending.
                let _ = self.bridge.rebridge(&record).await;
                Ok(DriveOutcome::Pending)
            }
            // A probe network error is not terminal — try again next tick.
            Err(_) => Ok(DriveOutcome::Pending),
        }
    }

    /// Drive every non-terminal record one step. Returns per-group outcomes.
    ///
    /// # Errors
    /// Propagates a store listing error.
    pub async fn drive_all(&self) -> Result<Vec<(String, DriveOutcome)>, ChatError> {
        let mut out = Vec::new();
        for record in self.store.list()? {
            let gid = record.group_id.clone();
            let outcome = self.drive_once(record).await?;
            out.push((gid, outcome));
        }
        Ok(out)
    }

    /// Mark a record terminally failed and remove it (malformed/consumed
    /// invite). Exposed so the submit path can retire a doomed intent.
    ///
    /// # Errors
    /// Propagates a store removal error.
    pub fn fail(&self, group_id: &str) -> Result<(), ChatError> {
        self.store.remove(group_id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    fn record(group: &str) -> PendingJoin {
        PendingJoin::new(
            group.into(),
            "Y2FwdHVyZWQ=".into(),
            "x0x.group.test.metadata".into(),
            "invitehash".into(),
            "aa".repeat(32),
            "b3duZXJrZW0=".into(),
            vec!["https://relay.example".to_owned()],
            "am9pbmVya2Vt".into(),
            100,
        )
    }

    fn store() -> (PendingJoinStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = PendingJoinStore::open(dir.path().join("pj")).unwrap();
        (s, dir)
    }

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    /// Owner that is Absent for the first `flip_at` probes, then `ActiveKeyed`.
    struct FlipProbe {
        flip_at: u32,
        calls: AtomicU32,
    }
    impl MembershipProbe for FlipProbe {
        fn status(
            &self,
            _g: &str,
        ) -> impl Future<Output = Result<MembershipStatus, ChatError>> + Send {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok(if n < self.flip_at {
                    MembershipStatus::Absent
                } else {
                    MembershipStatus::ActiveKeyed
                })
            }
        }
    }

    struct FixedProbe(MembershipStatus);
    impl MembershipProbe for FixedProbe {
        fn status(
            &self,
            _g: &str,
        ) -> impl Future<Output = Result<MembershipStatus, ChatError>> + Send {
            let s = self.0;
            async move { Ok(s) }
        }
    }

    /// Counts rebridge + join-result calls. There is NO `join_post` here or
    /// anywhere in the driver's reachable surface.
    #[derive(Clone, Default)]
    struct CountingBridge {
        rebridges: Arc<AtomicUsize>,
        join_results: Arc<AtomicUsize>,
    }
    impl JoinBridge for CountingBridge {
        fn rebridge(&self, _r: &PendingJoin) -> impl Future<Output = Result<(), ChatError>> + Send {
            self.rebridges.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        }
        fn request_join_result(
            &self,
            _r: &PendingJoin,
        ) -> impl Future<Output = Result<(), ChatError>> + Send {
            self.join_results.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        }
    }

    #[tokio::test]
    async fn offline_owner_stays_pending_then_auto_converges() {
        // G3: Absent for 2 ticks, then the owner applies -> ActiveKeyed.
        let (s, _d) = store();
        let r = record(&"11".repeat(32));
        s.upsert(&r).unwrap();
        let bridge = CountingBridge::default();
        let driver = PendingJoinDriver::new(
            s,
            bridge.clone(),
            FlipProbe {
                flip_at: 2,
                calls: AtomicU32::new(0),
            },
            FixedClock(500),
        );

        assert_eq!(
            driver.drive_once(r.clone()).await.unwrap(),
            DriveOutcome::Pending
        );
        assert_eq!(
            driver.drive_once(r.clone()).await.unwrap(),
            DriveOutcome::Pending
        );
        assert_eq!(
            driver.drive_once(r.clone()).await.unwrap(),
            DriveOutcome::Converged
        );

        // G1: re-bridged exactly on the two Absent ticks; never on convergence.
        assert_eq!(bridge.rebridges.load(Ordering::SeqCst), 2);
        // record removed on convergence.
        assert!(driver.store.get(&r.group_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn converged_record_is_removed() {
        let (s, _d) = store();
        let r = record(&"22".repeat(32));
        s.upsert(&r).unwrap();
        let driver = PendingJoinDriver::new(
            s,
            CountingBridge::default(),
            FixedProbe(MembershipStatus::ActiveKeyed),
            FixedClock(1),
        );
        assert_eq!(
            driver.drive_once(r.clone()).await.unwrap(),
            DriveOutcome::Converged
        );
        assert!(driver.store.get(&r.group_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn absent_bumps_attempts_and_rebridges_the_saved_event() {
        let (s, _d) = store();
        let r = record(&"33".repeat(32));
        s.upsert(&r).unwrap();
        let bridge = CountingBridge::default();
        let driver = PendingJoinDriver::new(
            s,
            bridge.clone(),
            FixedProbe(MembershipStatus::Absent),
            FixedClock(777),
        );
        assert_eq!(
            driver.drive_once(r.clone()).await.unwrap(),
            DriveOutcome::Pending
        );
        let saved = driver.store.get(&r.group_id).unwrap().unwrap();
        assert_eq!(saved.attempts, 1);
        assert_eq!(saved.last_attempt_ms, 777);
        assert_eq!(saved.state, PendingJoinState::Bridged);
        assert_eq!(bridge.rebridges.load(Ordering::SeqCst), 1);
        // the captured event is unchanged — we re-send the SAME bytes.
        assert_eq!(saved.captured_event_b64, r.captured_event_b64);
    }

    #[tokio::test]
    async fn unkeyed_requests_join_result_not_a_new_invite() {
        // Split-brain: listed but no key -> re-request Welcome, no rebridge-as-join.
        let (s, _d) = store();
        let r = record(&"44".repeat(32));
        s.upsert(&r).unwrap();
        let bridge = CountingBridge::default();
        let driver = PendingJoinDriver::new(
            s,
            bridge.clone(),
            FixedProbe(MembershipStatus::ListedButUnkeyed),
            FixedClock(9),
        );
        assert_eq!(
            driver.drive_once(r.clone()).await.unwrap(),
            DriveOutcome::Pending
        );
        assert_eq!(bridge.join_results.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.store.get(&r.group_id).unwrap().unwrap().state,
            PendingJoinState::KeyedButUnverified
        );
    }

    #[tokio::test]
    async fn terminal_record_reports_failed_without_touching_network() {
        let (s, _d) = store();
        let mut r = record(&"55".repeat(32));
        r.state = PendingJoinState::Failed {
            reason: "invite already used".into(),
        };
        s.upsert(&r).unwrap();
        let bridge = CountingBridge::default();
        let driver = PendingJoinDriver::new(
            s,
            bridge.clone(),
            FixedProbe(MembershipStatus::Absent),
            FixedClock(1),
        );
        assert_eq!(
            driver.drive_once(r).await.unwrap(),
            DriveOutcome::Failed {
                reason: "invite already used".into()
            }
        );
        assert_eq!(bridge.rebridges.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn apply_ok_retires_only_on_confirmed_keyed_probe() {
        // 2026-07-31 live failure: a version-skewed daemon answered the
        // join-result apply with Ok while installing nothing; the record
        // was retired and the joiner stranded keyless with no safety net.
        // An apply-Ok is not proof — only a keyed probe confirmation is.
        assert!(apply_ok_retires_record(Some(true)));
        assert!(
            !apply_ok_retires_record(Some(false)),
            "unkeyed keeps the record"
        );
        assert!(
            !apply_ok_retires_record(None),
            "probe failure keeps the record"
        );
    }

    #[test]
    fn backoff_is_immediate_then_exponential_then_capped() {
        assert_eq!(backoff_ms(0), 0, "first attempt is immediate");
        assert_eq!(backoff_ms(1), 4_000);
        assert_eq!(backoff_ms(2), 8_000);
        assert!(backoff_ms(30) <= 5 * 60 * 1_000, "capped at 5 min");
        assert_eq!(backoff_ms(30), 5 * 60 * 1_000);
    }

    #[test]
    fn is_due_gates_ticks_by_backoff() {
        let mut r = record(&"ab".repeat(32));
        // fresh (attempts 0): due immediately.
        assert!(is_due(&r, 0));
        // after one attempt at t=1000, next due at 1000+4000.
        r.attempts = 1;
        r.last_attempt_ms = 1_000;
        assert!(!is_due(&r, 4_000), "not yet due");
        assert!(is_due(&r, 5_000), "due at last+backoff");
    }

    #[tokio::test]
    async fn drive_all_walks_every_record() {
        let (s, _d) = store();
        s.upsert(&record(&"66".repeat(32))).unwrap();
        s.upsert(&record(&"77".repeat(32))).unwrap();
        let driver = PendingJoinDriver::new(
            s,
            CountingBridge::default(),
            FixedProbe(MembershipStatus::Absent),
            FixedClock(1),
        );
        let outcomes = driver.drive_all().await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|(_, o)| *o == DriveOutcome::Pending));
    }
}
