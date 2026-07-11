//! Task #297 (chat resilience): automatic MLS-epoch recovery.
//!
//! A group member that falls behind the group's MLS epoch must recover
//! WITHOUT the user ever re-pairing or hearing "`StaleEpoch`". This module
//! is the engine slice that makes that happen. It has four parts, each a
//! pure, unit-tested core with the network/crypto behind a small seam:
//!
//! - [`detect`] — [`detect::epoch_relation`]: is an inbound frame's
//!   `secret_epoch` ahead of (behind, from our view), equal to, or
//!   behind our local group epoch (from
//!   [`x0xd_client::secure::GroupSelfStatus`]).
//! - the recovery driver ([`EpochRecoveryDriver`]) — the one code path
//!   the cold ([`crate::groups::pending_join_driver`]), warm
//!   (commits-since-N), and wedge triggers all funnel through. It fetches
//!   group-log records since our last-applied seq, applies each IN ORDER
//!   and IDEMPOTENTLY via the normal MLS validation path, advances our
//!   cursor, and re-probes until we are keyed at the current epoch.
//! - [`watchdog`] — [`watchdog::wedge_should_trip`]: detect a wedged
//!   group (receipts still flowing but no epoch progress) and trip the
//!   driver.
//! - [`status`] — [`status::GroupRecoveryStatus`] + [`status::GroupStatusMap`]:
//!   the engine-side status a shell renders as "reconnecting to group…"
//!   instead of a silent drop.
//!
//! # The `CommitSource` / `CommitApplier` seams
//!
//! The fetch side is a trait ([`CommitSource`]) so Alice's durable
//! per-group Commit-log (#297 Lane A) plugs in unchanged. Today the relay
//! `LogFetch`/`LogRecords` frames exist
//! ([`fetchit_relay_proto::LogFetch`]) but the relay-client supervisor
//! never *issues* a `LogFetch` — so there is no production `CommitSource`
//! that serves warm commits yet. See [`DeferredCommitSource`] and the
//! `TODO(#297-laneA)` markers: the pure recovery loop is fully built and
//! tested against fake sources; the live warm path lights up when the
//! durable Commit-log serves records.

use std::future::Future;

use crate::error::Result;
use crate::groups::pending_join_driver::MembershipStatus;

pub mod detect;
pub mod driver;
pub mod status;
pub mod watchdog;
pub mod wire_map;

pub use detect::{epoch_relation, frame_is_behind, EpochRelation};
pub use driver::{ColdRecover, EpochRecoveryDriver, RecoverOutcome};
pub use status::{GroupRecoveryStatus, GroupStatusEvent, GroupStatusMap};
pub use watchdog::{groups_to_recover, wedge_should_trip, WedgeSignals, WEDGE_THRESHOLD_MS};
pub use wire_map::{commit_record_from_wire, plan_apply, ApplyPlan};

/// What kind of append-only group-log record this is. Mirrors
/// [`fetchit_relay_proto::LogRecordKind`] so a record fetched over the
/// relay maps across without a second enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitRecordKind {
    /// A group commit — served to every fetcher of the group. Applying
    /// it advances the local MLS epoch.
    Commit,
    /// A join-result addressed to exactly one joining agent (a Welcome).
    JoinResult,
}

/// One group-log record the recovery loop applies, in the minimal shape
/// the loop needs. Kept independent of the relay wire type so a fake
/// source drives the unit tests and Alice's durable Commit-log maps its
/// own record type in at the [`CommitSource`] boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRecord {
    /// Relay-assigned per-group sequence number (starts at 1, strictly
    /// increasing, never reused within a group).
    pub seq: u64,
    /// Record kind.
    pub kind: CommitRecordKind,
    /// Base64 opaque payload — the signed MLS event the applier hands to
    /// x0xd's normal validation path.
    pub payload_b64: String,
    /// The event author's agent id (hex), when the record carries it.
    /// Required by the x0xd apply endpoints, which re-verify the author
    /// signature.
    pub author_agent_id_hex: Option<String>,
}

/// The live group state the recovery loop re-probes. Mirrors
/// [`x0xd_client::secure::GroupSelfStatus`]; a production probe is a thin
/// wrapper over `group_self_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupState {
    /// True when this daemon holds the group's live crypto state (keyed).
    pub keyed: bool,
    /// True when this agent is an active member in the roster.
    pub in_roster: bool,
    /// The group's current secret epoch (local view).
    pub epoch: u64,
}

impl GroupState {
    /// Collapse the raw state into the cold-path
    /// [`MembershipStatus`] the [`crate::groups::pending_join_driver`]
    /// already reasons about — the point of convergence with the cold
    /// recovery machinery, so warm and cold share one classification.
    #[must_use]
    pub fn membership(&self) -> MembershipStatus {
        if self.keyed {
            MembershipStatus::ActiveKeyed
        } else if self.in_roster {
            MembershipStatus::ListedButUnkeyed
        } else {
            MembershipStatus::Absent
        }
    }
}

/// Fetch source for group-log records with `seq > since_seq`, ascending.
///
/// The seam that lets Alice's durable per-group Commit-log (#297 Lane A)
/// back the warm recovery path. Implementations MUST return records in
/// ascending `seq` order and MUST NOT skip a `seq` they can serve (the
/// loop stops cleanly on a gap rather than applying out of order).
pub trait CommitSource {
    /// Records with `seq` strictly greater than `since_seq`, ascending.
    fn fetch_since(
        &self,
        group_id: &str,
        since_seq: u64,
    ) -> impl Future<Output = Result<Vec<CommitRecord>>> + Send;
}

/// Outcome of applying one record through the normal MLS validation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The daemon applied the record and advanced state.
    Applied,
    /// The daemon reported the record was already applied (a 409 /
    /// already-a-member / already-at-epoch no-op). Idempotent: the cursor
    /// still advances, but nothing was double-applied.
    AlreadyApplied,
}

/// Applies one group-log record through x0xd's normal, signature-verifying
/// MLS path (`apply_metadata_event` / `apply_join_result`). NEVER a
/// verification bypass — the daemon re-runs full membership authority.
///
/// A network/transport error is returned as `Err`; the loop treats that
/// as "stop this pass, stay Reconnecting", never a double-apply.
pub trait CommitApplier {
    /// Apply one record to the local group state, idempotently.
    fn apply(
        &self,
        group_id: &str,
        record: &CommitRecord,
    ) -> impl Future<Output = Result<ApplyOutcome>> + Send;
}

/// Probes the live group state (keyed / in-roster / epoch).
pub trait GroupStateProbe {
    /// Current [`GroupState`] for `group_id`.
    fn probe(&self, group_id: &str) -> impl Future<Output = Result<GroupState>> + Send;
}

/// Result of the ordered, idempotent apply loop over a batch of records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyLoopResult {
    /// Highest contiguous `seq` applied (or skipped-as-already-applied).
    /// The new cursor.
    pub cursor: u64,
    /// Count of records the applier actually applied (fresh).
    pub applied: usize,
    /// Count of records skipped as already-applied / older than cursor.
    pub skipped: usize,
    /// True when the loop stopped because the next record's `seq` was not
    /// contiguous with the cursor — it did NOT apply out of order.
    pub stopped_on_gap: bool,
}

/// Apply `records` (ascending `seq`) starting from `start_seq`, in order
/// and idempotently. This is the pure core of the recovery driver: no
/// network, no crypto — the [`CommitApplier`] is the only side effect and
/// is injected.
///
/// Contract:
/// - A record with `seq <= cursor` is skipped (already applied / old):
///   never re-applied, never an error.
/// - The next contiguous record (`seq == cursor + 1`) is applied; both
///   [`ApplyOutcome::Applied`] and [`ApplyOutcome::AlreadyApplied`]
///   advance the cursor — a 409 never double-applies and never stalls.
/// - A gap (`seq > cursor + 1`) stops the loop cleanly WITHOUT applying
///   the out-of-order record.
/// - An applier error stops the loop with the cursor at the last success
///   (the caller stays Reconnecting and retries next pass).
///
/// # Errors
/// Propagates the first [`CommitApplier::apply`] error, with `cursor`
/// left at the last successfully-advanced position.
pub async fn apply_records_in_order<A: CommitApplier + Sync>(
    applier: &A,
    group_id: &str,
    start_seq: u64,
    records: &[CommitRecord],
) -> Result<ApplyLoopResult> {
    let mut cursor = start_seq;
    let mut applied_count = 0usize;
    let mut skipped_count = 0usize;
    let mut stopped_on_gap = false;
    for record in records {
        if record.seq <= cursor {
            // Already applied / older than our cursor — idempotent skip.
            skipped_count += 1;
            continue;
        }
        if record.seq > cursor + 1 {
            // Non-contiguous: a hole we can't fill from this batch. Stop
            // cleanly; never apply out of order.
            stopped_on_gap = true;
            break;
        }
        match applier.apply(group_id, record).await? {
            ApplyOutcome::Applied => applied_count += 1,
            ApplyOutcome::AlreadyApplied => {}
        }
        cursor = record.seq;
    }
    Ok(ApplyLoopResult {
        cursor,
        applied: applied_count,
        skipped: skipped_count,
        stopped_on_gap,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod apply_loop_tests {
    use std::sync::Mutex;

    use super::*;

    /// Records the seqs handed to `apply`, and can be told which seqs to
    /// answer `AlreadyApplied` for. No network, no crypto.
    #[derive(Default)]
    struct FakeApplier {
        applied_seqs: Mutex<Vec<u64>>,
        already: Vec<u64>,
        fail_at: Option<u64>,
    }
    impl CommitApplier for FakeApplier {
        fn apply(
            &self,
            _group_id: &str,
            record: &CommitRecord,
        ) -> impl Future<Output = Result<ApplyOutcome>> + Send {
            let seq = record.seq;
            let already = self.already.contains(&seq);
            let fail = self.fail_at == Some(seq);
            self.applied_seqs.lock().unwrap().push(seq);
            async move {
                if fail {
                    return Err(crate::error::ChatError::Invalid("boom".into()));
                }
                Ok(if already {
                    ApplyOutcome::AlreadyApplied
                } else {
                    ApplyOutcome::Applied
                })
            }
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

    #[tokio::test]
    async fn ordered_records_converge() {
        let applier = FakeApplier::default();
        let recs = [rec(1), rec(2), rec(3)];
        let out = apply_records_in_order(&applier, "g", 0, &recs)
            .await
            .unwrap();
        assert_eq!(out.cursor, 3);
        assert_eq!(out.applied, 3);
        assert_eq!(out.skipped, 0);
        assert!(!out.stopped_on_gap);
        assert_eq!(*applier.applied_seqs.lock().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn duplicate_and_old_records_skip_idempotently() {
        // Cursor already at 2: records 1 and 2 are old, only 3 applies.
        let applier = FakeApplier::default();
        let recs = [rec(1), rec(2), rec(3)];
        let out = apply_records_in_order(&applier, "g", 2, &recs)
            .await
            .unwrap();
        assert_eq!(out.cursor, 3);
        assert_eq!(out.applied, 1);
        assert_eq!(out.skipped, 2);
        assert!(!out.stopped_on_gap);
        // Only seq 3 ever reached the applier — 1 and 2 never re-applied.
        assert_eq!(*applier.applied_seqs.lock().unwrap(), vec![3]);
    }

    #[tokio::test]
    async fn gap_stops_cleanly_without_applying_out_of_order() {
        // 1 applies; 3 is non-contiguous (2 missing) -> stop, 3 not applied.
        let applier = FakeApplier::default();
        let recs = [rec(1), rec(3)];
        let out = apply_records_in_order(&applier, "g", 0, &recs)
            .await
            .unwrap();
        assert_eq!(out.cursor, 1);
        assert_eq!(out.applied, 1);
        assert!(out.stopped_on_gap);
        assert_eq!(*applier.applied_seqs.lock().unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn already_applied_outcome_advances_cursor_never_double_applies() {
        // The daemon says seq 2 was already applied (409): cursor still
        // advances to 3, and nothing is applied twice.
        let applier = FakeApplier {
            already: vec![2],
            ..Default::default()
        };
        let recs = [rec(1), rec(2), rec(3)];
        let out = apply_records_in_order(&applier, "g", 0, &recs)
            .await
            .unwrap();
        assert_eq!(out.cursor, 3);
        assert_eq!(out.applied, 2, "seq 1 and 3 applied; seq 2 was a 409 no-op");
        assert_eq!(*applier.applied_seqs.lock().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        let applier = FakeApplier::default();
        let out = apply_records_in_order(&applier, "g", 5, &[]).await.unwrap();
        assert_eq!(out.cursor, 5);
        assert_eq!(out.applied, 0);
        assert_eq!(out.skipped, 0);
        assert!(!out.stopped_on_gap);
        assert!(applier.applied_seqs.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn applier_error_stops_at_last_success() {
        // seq 2 errors: cursor stays at 1 (last success), error propagates.
        let applier = FakeApplier {
            fail_at: Some(2),
            ..Default::default()
        };
        let recs = [rec(1), rec(2), rec(3)];
        let err = apply_records_in_order(&applier, "g", 0, &recs).await;
        assert!(err.is_err());
        // seq 3 never reached the applier (loop broke on the seq-2 error).
        assert_eq!(*applier.applied_seqs.lock().unwrap(), vec![1, 2]);
    }
}
