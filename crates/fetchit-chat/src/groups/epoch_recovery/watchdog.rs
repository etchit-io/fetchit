//! Wedge-watchdog: spot a group that is silently stuck.
//!
//! The failure this catches is the "`StaleEpoch` loop" (see MEMORY): chat is
//! dead but `DeliveryReceipts` keep flowing — the transport is fine, MLS
//! state is desynced, and nothing advances. A healthy quiet group looks
//! nothing like this (no receipt traffic either), so the watchdog only
//! trips when receipts prove the peer is live AND we have made no decrypt /
//! epoch progress for a threshold.
//!
//! [`wedge_should_trip`] is a pure decision function; the periodic wiring
//! (a spawned task that calls it per active group and trips the recovery
//! driver) is kept thin and lives at the engine surface.

/// Default wedge threshold: receipts flowing but zero progress for this
/// long trips recovery. Chosen to sit well above normal message-gap jitter
/// so an ordinary lull never trips it.
pub const WEDGE_THRESHOLD_MS: u64 = 60_000;

/// The inputs the watchdog reasons about for one group at one tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WedgeSignals {
    /// Unix-ms of the last observed *progress* — a successful inbound
    /// decrypt or a local epoch advance.
    pub last_progress_ms: u64,
    /// True when delivery receipts have arrived recently (the peer is
    /// demonstrably live on the transport).
    pub recent_receipt_activity: bool,
    /// Our current local group epoch.
    pub current_epoch: u64,
    /// The epoch we last saw at the previous progress point. Equal to
    /// `current_epoch` means the epoch has not advanced since.
    pub last_seen_epoch: u64,
}

/// Decide whether a group is wedged and recovery should be tripped.
///
/// Trips iff ALL hold:
/// - receipts are flowing (`recent_receipt_activity`) — the peer is live,
///   so silence is not just an idle group;
/// - no progress for at least `threshold_ms` (`now_ms - last_progress_ms`);
/// - the epoch has not advanced (`current_epoch <= last_seen_epoch`) — an
///   advance would itself be progress.
///
/// Never trips on a healthy or merely-idle group: no receipt activity, or
/// recent progress, or an advanced epoch each veto.
#[must_use]
pub fn wedge_should_trip(signals: &WedgeSignals, now_ms: u64, threshold_ms: u64) -> bool {
    if !signals.recent_receipt_activity {
        return false;
    }
    if signals.current_epoch > signals.last_seen_epoch {
        // The epoch advanced since the last progress mark — that IS
        // progress; not wedged.
        return false;
    }
    let stalled_for = now_ms.saturating_sub(signals.last_progress_ms);
    stalled_for >= threshold_ms
}

/// Pure per-tick decision: given each active group's signals, return the
/// group ids that should be handed to the recovery driver this tick. The
/// spawned watchdog task is a thin wrapper — sample signals, call this,
/// drive [`crate::Client::recover_group_once`] for each returned id — so
/// the tripping logic stays testable without a runtime.
#[must_use]
pub fn groups_to_recover(
    now_ms: u64,
    threshold_ms: u64,
    groups: &[(String, WedgeSignals)],
) -> Vec<String> {
    groups
        .iter()
        .filter(|(_, s)| wedge_should_trip(s, now_ms, threshold_ms))
        .map(|(g, _)| g.clone())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn signals() -> WedgeSignals {
        WedgeSignals {
            last_progress_ms: 1_000,
            recent_receipt_activity: true,
            current_epoch: 4,
            last_seen_epoch: 4,
        }
    }

    #[test]
    fn trips_on_receipts_flowing_no_progress_no_epoch_advance() {
        // 60s+ since progress, receipts live, epoch flat -> the StaleEpoch loop.
        let s = signals();
        assert!(wedge_should_trip(
            &s,
            1_000 + WEDGE_THRESHOLD_MS,
            WEDGE_THRESHOLD_MS
        ));
    }

    #[test]
    fn does_not_trip_when_no_receipt_activity() {
        // Idle-but-fine: nobody's talking, so silence is expected.
        let s = WedgeSignals {
            recent_receipt_activity: false,
            ..signals()
        };
        assert!(!wedge_should_trip(
            &s,
            1_000 + 10 * WEDGE_THRESHOLD_MS,
            WEDGE_THRESHOLD_MS
        ));
    }

    #[test]
    fn does_not_trip_when_progress_is_recent() {
        // Receipts flowing but we decrypted something 1s ago — healthy.
        let s = signals();
        assert!(!wedge_should_trip(&s, 1_000 + 1_000, WEDGE_THRESHOLD_MS));
    }

    #[test]
    fn does_not_trip_when_epoch_advanced() {
        // Even past the threshold, an epoch advance is progress.
        let s = WedgeSignals {
            current_epoch: 5,
            last_seen_epoch: 4,
            ..signals()
        };
        assert!(!wedge_should_trip(
            &s,
            1_000 + 5 * WEDGE_THRESHOLD_MS,
            WEDGE_THRESHOLD_MS
        ));
    }

    #[test]
    fn trips_exactly_at_threshold_boundary() {
        let s = signals();
        // one ms short: no trip; exactly at threshold: trip.
        assert!(!wedge_should_trip(
            &s,
            1_000 + WEDGE_THRESHOLD_MS - 1,
            WEDGE_THRESHOLD_MS
        ));
        assert!(wedge_should_trip(
            &s,
            1_000 + WEDGE_THRESHOLD_MS,
            WEDGE_THRESHOLD_MS
        ));
    }

    #[test]
    fn groups_to_recover_selects_only_wedged_groups() {
        let wedged = signals(); // receipts flowing, flat epoch
        let healthy = WedgeSignals {
            recent_receipt_activity: false,
            ..signals()
        };
        let advancing = WedgeSignals {
            current_epoch: 6,
            last_seen_epoch: 4,
            ..signals()
        };
        let groups = vec![
            ("wedged".to_owned(), wedged),
            ("healthy".to_owned(), healthy),
            ("advancing".to_owned(), advancing),
        ];
        let out = groups_to_recover(1_000 + WEDGE_THRESHOLD_MS, WEDGE_THRESHOLD_MS, &groups);
        assert_eq!(out, vec!["wedged".to_owned()]);
    }
}
