//! The recovery driver: the ONE code path the cold, warm, and wedge
//! triggers funnel through.
//!
//! `recover_once` probes the live group state and dispatches:
//! - keyed and caught up to the target epoch -> [`RecoverOutcome::Converged`]
//!   (status cleared to `Live`);
//! - keyed but behind -> the WARM path: fetch group-log records since our
//!   cursor, apply each in order + idempotently via the normal MLS
//!   validation path ([`super::apply_records_in_order`]), advance the
//!   cursor, and re-probe until keyed at the target (or records run out /
//!   a gap stops the pass);
//! - not keyed / not in roster -> the COLD path: hand off to the existing
//!   durable pending-join resume ([`ColdRecover`]) — never a parallel
//!   loop.
//!
//! The wedge trigger calls the same entry with `target_epoch: None`
//! ("drain whatever commits exist and re-check keyed").

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::groups::pending_join_driver::MembershipStatus;

use super::{apply_records_in_order, CommitApplier, CommitSource, GroupStateProbe, GroupStatusMap};

/// Safety bound on catch-up passes within a single `recover_once` so a
/// misbehaving source can never spin forever. Each productive pass strictly
/// advances the cursor, so real catch-up terminates well under this.
const MAX_PASSES: usize = 64;

/// Drives the cold (not-yet-keyed) recovery one step — the existing
/// durable pending-join resume. The seam keeps the driver from
/// re-implementing the cold loop: the production impl calls
/// [`crate::Client::drive_pending_joins_once`].
pub trait ColdRecover {
    /// Kick the cold recovery for `group_id`. Returns whether a cold
    /// record existed and was driven. A network error is `Err`.
    fn recover_cold(&self, group_id: &str) -> impl Future<Output = Result<bool>> + Send;
}

/// Terminal outcome of one `recover_once` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverOutcome {
    /// Keyed at (or above) the target epoch — or, for a wedge sweep with
    /// no target, the log is drained and we are keyed. Status is `Live`.
    Converged,
    /// Still catching up: commits are pending, a gap blocked the pass, or
    /// the target epoch is not yet reachable. Status stays `Reconnecting`;
    /// the caller retries on the next tick.
    Reconnecting,
    /// Not keyed / not in roster — handed to the cold pending-join resume.
    /// Convergence arrives asynchronously via the inbound-apply path;
    /// status stays `Reconnecting`.
    ColdPending {
        /// Whether a cold record was found and driven this pass.
        drove: bool,
    },
}

/// Drives a single group to epoch-convergence over injected seams.
pub struct EpochRecoveryDriver<S, A, P, R> {
    source: S,
    applier: A,
    probe: P,
    cold: R,
    status: GroupStatusMap,
    /// Last-applied group-log seq per group. Shared (`Arc`) so it survives
    /// the driver being rebuilt on each `recover_group_once` call — the
    /// caller holds the store and threads it in via [`Self::new_with_cursors`],
    /// so warm catch-up resumes from the cursor instead of re-fetching from 0
    /// every tick. Not durable across a process restart; the applier's
    /// idempotent 409 handling covers a cold start (re-fetch from 0, skip
    /// already-applied commits).
    cursors: Arc<Mutex<HashMap<String, u64>>>,
}

impl<S, A, P, R> EpochRecoveryDriver<S, A, P, R>
where
    S: CommitSource + Sync,
    A: CommitApplier + Sync,
    P: GroupStateProbe + Sync,
    R: ColdRecover + Sync,
{
    /// Build a driver over its seams + the shared status map, with a fresh
    /// per-driver cursor store (each process starts at 0). Use
    /// [`Self::new_with_cursors`] to share the cursor across driver rebuilds.
    pub fn new(source: S, applier: A, probe: P, cold: R, status: GroupStatusMap) -> Self {
        Self::new_with_cursors(
            source,
            applier,
            probe,
            cold,
            status,
            Arc::new(Mutex::new(HashMap::new())),
        )
    }

    /// Build a driver over an EXTERNALLY-owned cursor store. The caller
    /// (the client) holds the `Arc` for its lifetime and passes the same one
    /// each time it rebuilds the driver, so the last-applied cursor persists
    /// across `recover_group_once` calls instead of resetting to 0 (which
    /// would re-fetch the whole log every tick once a warm source is wired).
    pub fn new_with_cursors(
        source: S,
        applier: A,
        probe: P,
        cold: R,
        status: GroupStatusMap,
        cursors: Arc<Mutex<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            source,
            applier,
            probe,
            cold,
            status,
            cursors,
        }
    }

    fn cursor(&self, group_id: &str) -> u64 {
        self.cursors
            .lock()
            .ok()
            .and_then(|m| m.get(group_id).copied())
            .unwrap_or(0)
    }

    fn set_cursor(&self, group_id: &str, seq: u64) {
        if let Ok(mut m) = self.cursors.lock() {
            m.insert(group_id.to_owned(), seq);
        }
    }

    /// Recover one group one step. `target_epoch` is the epoch we must
    /// reach to be caught up — the inbound frame's `secret_epoch` for the
    /// `EpochBehind` + warm triggers, or `None` for a wedge sweep (drain the
    /// available log and re-check keyed).
    ///
    /// # Errors
    /// Propagates a probe / apply error, leaving the cursor at the last
    /// success and the status `Reconnecting`.
    pub async fn recover_once(
        &self,
        group_id: &str,
        target_epoch: Option<u64>,
    ) -> Result<RecoverOutcome> {
        // First probe is cheap and avoids flashing Reconnecting on a group
        // that is already fine.
        let state = self.probe.probe(group_id).await?;
        if state.membership() == MembershipStatus::ActiveKeyed {
            if let Some(t) = target_epoch {
                if state.epoch >= t {
                    self.status.set_live(group_id);
                    return Ok(RecoverOutcome::Converged);
                }
            }
        } else {
            // Not keyed: cold path. Do not touch the commit loop.
            self.status.set_reconnecting(group_id);
            let drove = self.cold.recover_cold(group_id).await?;
            return Ok(RecoverOutcome::ColdPending { drove });
        }

        // Warm catch-up: keyed but behind (or a wedge sweep). We are about
        // to do real work, so surface Reconnecting now.
        self.status.set_reconnecting(group_id);
        for _ in 0..MAX_PASSES {
            let cursor = self.cursor(group_id);
            let records = self.source.fetch_since(group_id, cursor).await?;
            if records.is_empty() {
                // Nothing more to apply. Re-probe to decide convergence.
                let state = self.probe.probe(group_id).await?;
                let caught_up = match target_epoch {
                    // Wedge sweep: keyed + drained log == converged.
                    None => state.membership() == MembershipStatus::ActiveKeyed,
                    // Known target: only converged once the epoch reaches it.
                    Some(t) => {
                        state.membership() == MembershipStatus::ActiveKeyed && state.epoch >= t
                    }
                };
                if caught_up {
                    self.status.set_live(group_id);
                    return Ok(RecoverOutcome::Converged);
                }
                // Keyed but waiting on commits we cannot fetch yet.
                return Ok(RecoverOutcome::Reconnecting);
            }
            let res = apply_records_in_order(&self.applier, group_id, cursor, &records).await?;
            self.set_cursor(group_id, res.cursor);
            if res.stopped_on_gap {
                // A hole we cannot fill this pass; retry on the next tick.
                return Ok(RecoverOutcome::Reconnecting);
            }
            // Re-probe: applying commits should have advanced our epoch.
            let state = self.probe.probe(group_id).await?;
            if let Some(t) = target_epoch {
                if state.membership() == MembershipStatus::ActiveKeyed && state.epoch >= t {
                    self.status.set_live(group_id);
                    return Ok(RecoverOutcome::Converged);
                }
            }
            // Loop: fetch the next contiguous batch from the advanced cursor.
        }
        // Ran out of passes without converging — stay Reconnecting.
        Ok(RecoverOutcome::Reconnecting)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::error::ChatError;
    use crate::groups::epoch_recovery::status::GroupRecoveryStatus;
    use crate::groups::epoch_recovery::{ApplyOutcome, CommitRecord, CommitRecordKind, GroupState};

    /// Probe that returns a scripted sequence of states, repeating the last.
    struct ScriptProbe {
        states: Mutex<VecDeque<GroupState>>,
        last: Mutex<GroupState>,
    }
    impl ScriptProbe {
        fn new(states: Vec<GroupState>) -> Self {
            let last = *states.last().expect("at least one state");
            Self {
                states: Mutex::new(states.into()),
                last: Mutex::new(last),
            }
        }
    }
    impl GroupStateProbe for ScriptProbe {
        fn probe(&self, _g: &str) -> impl Future<Output = Result<GroupState>> + Send {
            let next = {
                let mut q = self.states.lock().unwrap();
                q.pop_front()
            };
            if let Some(s) = next {
                *self.last.lock().unwrap() = s;
            }
            let s = *self.last.lock().unwrap();
            async move { Ok(s) }
        }
    }

    /// Source that serves one scripted batch per call, repeating empty.
    struct ScriptSource {
        batches: Mutex<VecDeque<Vec<CommitRecord>>>,
    }
    impl ScriptSource {
        fn new(batches: Vec<Vec<CommitRecord>>) -> Self {
            Self {
                batches: Mutex::new(batches.into()),
            }
        }
    }
    impl CommitSource for ScriptSource {
        fn fetch_since(
            &self,
            _g: &str,
            _since: u64,
        ) -> impl Future<Output = Result<Vec<CommitRecord>>> + Send {
            let batch = self.batches.lock().unwrap().pop_front().unwrap_or_default();
            async move { Ok(batch) }
        }
    }

    #[derive(Default)]
    struct OkApplier {
        applied: AtomicUsize,
    }
    impl CommitApplier for OkApplier {
        fn apply(
            &self,
            _g: &str,
            _r: &CommitRecord,
        ) -> impl Future<Output = Result<ApplyOutcome>> + Send {
            self.applied.fetch_add(1, Ordering::SeqCst);
            async { Ok(ApplyOutcome::Applied) }
        }
    }

    #[derive(Clone, Default)]
    struct CountingCold {
        calls: Arc<AtomicUsize>,
        found: bool,
    }
    impl ColdRecover for CountingCold {
        fn recover_cold(&self, _g: &str) -> impl Future<Output = Result<bool>> + Send {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let found = self.found;
            async move { Ok(found) }
        }
    }

    fn keyed(epoch: u64) -> GroupState {
        GroupState {
            keyed: true,
            in_roster: true,
            epoch,
        }
    }

    fn rec(seq: u64) -> CommitRecord {
        CommitRecord {
            seq,
            kind: CommitRecordKind::Commit,
            payload_b64: "ZXY".into(),
            author_agent_id_hex: Some("aa".repeat(32)),
        }
    }

    /// Source that records the `since_seq` it is asked to fetch from, so a
    /// test can assert the driver read the shared cursor rather than 0.
    struct CapturingSource {
        seen: Arc<Mutex<Vec<u64>>>,
    }
    impl CommitSource for CapturingSource {
        fn fetch_since(
            &self,
            _g: &str,
            since: u64,
        ) -> impl Future<Output = Result<Vec<CommitRecord>>> + Send {
            self.seen.lock().unwrap().push(since);
            async { Ok(Vec::new()) }
        }
    }

    #[tokio::test]
    async fn shared_cursor_store_survives_driver_rebuild() {
        // recover_group_once rebuilds the driver on every call; the cursor
        // must live in the shared store the caller threads in, so warm
        // catch-up resumes from it instead of re-fetching from seq 0. Seed the
        // store as if a prior driver applied through seq 3, then a fresh driver
        // over the SAME store must fetch since 3.
        let cursors = Arc::new(Mutex::new(HashMap::new()));
        cursors.lock().unwrap().insert("g".to_string(), 3u64);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let status = GroupStatusMap::new();

        let d = EpochRecoveryDriver::new_with_cursors(
            CapturingSource { seen: seen.clone() },
            OkApplier::default(),
            // keyed but behind target 9 -> warm loop -> fetch_since(cursor).
            ScriptProbe::new(vec![keyed(0)]),
            CountingCold::default(),
            status,
            cursors.clone(),
        );
        let _ = d.recover_once("g", Some(9)).await.unwrap();

        assert_eq!(
            seen.lock().unwrap().first().copied(),
            Some(3),
            "driver fetched since the shared cursor (3), proving the store is external"
        );
    }

    #[tokio::test]
    async fn already_live_at_target_is_converged_without_reconnecting_flash() {
        let status = GroupStatusMap::new();
        let mut rx = status.subscribe();
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![]),
            OkApplier::default(),
            ScriptProbe::new(vec![keyed(5)]),
            CountingCold::default(),
            status.clone(),
        );
        let out = d.recover_once("g", Some(5)).await.unwrap();
        assert_eq!(out, RecoverOutcome::Converged);
        assert_eq!(status.get("g"), GroupRecoveryStatus::Live);
        // Already-live group must not have flashed Reconnecting.
        assert!(
            rx.try_recv().is_err(),
            "no status event on an already-live group"
        );
    }

    #[tokio::test]
    async fn warm_catch_up_applies_commits_and_converges() {
        // Behind at epoch 2; after applying two commit batches the daemon
        // reports keyed at epoch 4 == target. Status ends Live.
        let status = GroupStatusMap::new();
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![vec![rec(1), rec(2)], vec![rec(3), rec(4)], vec![]]),
            OkApplier::default(),
            // probe: initial (behind@2), after batch1 (@3), after batch2 (@4).
            ScriptProbe::new(vec![keyed(2), keyed(3), keyed(4)]),
            CountingCold::default(),
            status.clone(),
        );
        let out = d.recover_once("g", Some(4)).await.unwrap();
        assert_eq!(out, RecoverOutcome::Converged);
        assert_eq!(status.get("g"), GroupRecoveryStatus::Live);
    }

    #[tokio::test]
    async fn warm_gap_stays_reconnecting() {
        // Cursor 0, first batch is seq 2,3 (seq 1 missing) -> gap, nothing
        // applied, stays Reconnecting.
        let status = GroupStatusMap::new();
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![vec![rec(2), rec(3)]]),
            OkApplier::default(),
            ScriptProbe::new(vec![keyed(1)]),
            CountingCold::default(),
            status.clone(),
        );
        let out = d.recover_once("g", Some(9)).await.unwrap();
        assert_eq!(out, RecoverOutcome::Reconnecting);
        assert_eq!(status.get("g"), GroupRecoveryStatus::Reconnecting);
    }

    #[tokio::test]
    async fn wedge_sweep_with_empty_log_converges_when_keyed() {
        // No target; keyed and the log is drained -> Converged.
        let status = GroupStatusMap::new();
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![vec![]]),
            OkApplier::default(),
            ScriptProbe::new(vec![keyed(3), keyed(3)]),
            CountingCold::default(),
            status.clone(),
        );
        let out = d.recover_once("g", None).await.unwrap();
        assert_eq!(out, RecoverOutcome::Converged);
        assert_eq!(status.get("g"), GroupRecoveryStatus::Live);
    }

    #[tokio::test]
    async fn warm_target_unreachable_stays_reconnecting() {
        // Keyed@3, target 9, but no commits available yet -> Reconnecting.
        let status = GroupStatusMap::new();
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![vec![]]),
            OkApplier::default(),
            ScriptProbe::new(vec![keyed(3), keyed(3)]),
            CountingCold::default(),
            status.clone(),
        );
        let out = d.recover_once("g", Some(9)).await.unwrap();
        assert_eq!(out, RecoverOutcome::Reconnecting);
        assert_eq!(status.get("g"), GroupRecoveryStatus::Reconnecting);
    }

    #[tokio::test]
    async fn absent_member_delegates_to_cold_and_stays_reconnecting() {
        let status = GroupStatusMap::new();
        let cold = CountingCold {
            calls: Arc::new(AtomicUsize::new(0)),
            found: true,
        };
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![]),
            OkApplier::default(),
            ScriptProbe::new(vec![GroupState {
                keyed: false,
                in_roster: false,
                epoch: 0,
            }]),
            cold.clone(),
            status.clone(),
        );
        let out = d.recover_once("g", Some(1)).await.unwrap();
        assert_eq!(out, RecoverOutcome::ColdPending { drove: true });
        assert_eq!(cold.calls.load(Ordering::SeqCst), 1);
        assert_eq!(status.get("g"), GroupRecoveryStatus::Reconnecting);
    }

    #[tokio::test]
    async fn listed_but_unkeyed_delegates_to_cold() {
        let status = GroupStatusMap::new();
        let cold = CountingCold {
            calls: Arc::new(AtomicUsize::new(0)),
            found: false,
        };
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![]),
            OkApplier::default(),
            ScriptProbe::new(vec![GroupState {
                keyed: false,
                in_roster: true,
                epoch: 2,
            }]),
            cold.clone(),
            status.clone(),
        );
        let out = d.recover_once("g", Some(3)).await.unwrap();
        assert_eq!(out, RecoverOutcome::ColdPending { drove: false });
        assert_eq!(cold.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn probe_error_propagates() {
        struct ErrProbe;
        impl GroupStateProbe for ErrProbe {
            async fn probe(&self, _g: &str) -> Result<GroupState> {
                Err(ChatError::Invalid("probe down".into()))
            }
        }
        let status = GroupStatusMap::new();
        let d = EpochRecoveryDriver::new(
            ScriptSource::new(vec![]),
            OkApplier::default(),
            ErrProbe,
            CountingCold::default(),
            status,
        );
        assert!(d.recover_once("g", Some(1)).await.is_err());
    }
}
