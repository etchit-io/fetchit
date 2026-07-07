//! Per-sender sequence tracking for missed-message detection.
//!
//! Senders seal a monotonic per-group counter (`GroupBodyV1::seq`)
//! inside the encrypted frame; this module is the receive-side ledger
//! that turns those counters into gap observations. A hole in a
//! sender's sequence means a message this device never received —
//! the detection half of chat resilience. Recovery (re-fetching the
//! missing messages) is a separate concern layered on top.
//!
//! Failure-direction contract: this tracker must never report a gap
//! that is not one. Duplicate and backward counters (sender counter
//! reset after an identity restore, a lost counter-bump persist on
//! the sender, or the optimistic-allocation race between two
//! concurrent sends) are absorbed as no-ops; the cost is missed
//! detection in those rare cases, never a false alarm.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Cap on remembered holes per sender. A gap larger than this keeps
/// only the newest holes (closest to the live conversation, the ones
/// recovery is most likely to fetch); older ones are dropped rather
/// than growing the vault without bound.
pub const MISSING_CAP: usize = 128;

/// Receive-side sequence ledger for one sender within one conversation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderSeqState {
    /// Highest counter observed from this sender.
    pub high_water: u64,
    /// Missing counters (holes) mapped to the Unix-ms time the hole
    /// was detected, bounded at [`MISSING_CAP`].
    pub missing: BTreeMap<u64, u64>,
}

/// Outcome of recording one observed counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeqObservation {
    /// First counted message from this sender. The counter becomes the
    /// high-water mark with no holes: earlier messages may predate our
    /// membership, so losses before the first observation are
    /// undetectable by design.
    First,
    /// Exactly the next expected counter.
    Consecutive,
    /// The counter jumped past the high-water mark: the skipped values
    /// (bounded by [`MISSING_CAP`]) are newly recorded holes.
    Gap {
        /// Newly recorded missing counters, ascending.
        missing: Vec<u64>,
    },
    /// The counter filled a previously recorded hole.
    FilledHole,
    /// At or below the high-water mark and not a known hole. Absorbed
    /// as a no-op per the module's failure-direction contract.
    Duplicate,
}

impl SenderSeqState {
    /// Record one observed counter and classify it.
    ///
    /// `now_ms` stamps newly detected holes so [`Self::stale_missing`]
    /// can apply a reorder grace window before anything is surfaced.
    pub fn record(&mut self, seq: u64, now_ms: u64) -> SeqObservation {
        if seq == 0 {
            // Counters start at 1; zero is malformed. Absorb it.
            return SeqObservation::Duplicate;
        }
        if self.high_water == 0 {
            self.high_water = seq;
            return SeqObservation::First;
        }
        if seq == self.high_water + 1 {
            self.high_water = seq;
            return SeqObservation::Consecutive;
        }
        if seq > self.high_water {
            // Record the skipped range, newest holes first when the
            // range exceeds the cap.
            let first_missing = (self.high_water + 1).max(seq.saturating_sub(MISSING_CAP as u64));
            let newly: Vec<u64> = (first_missing..seq).collect();
            for m in &newly {
                self.missing.insert(*m, now_ms);
            }
            self.high_water = seq;
            // Evict oldest holes beyond the cap.
            while self.missing.len() > MISSING_CAP {
                if let Some((&oldest, _)) = self.missing.iter().next() {
                    self.missing.remove(&oldest);
                }
            }
            return SeqObservation::Gap { missing: newly };
        }
        if self.missing.remove(&seq).is_some() {
            return SeqObservation::FilledHole;
        }
        SeqObservation::Duplicate
    }

    /// Holes detected at least `grace_ms` ago, ascending. The grace
    /// window absorbs in-flight reordering (relay replay, concurrent
    /// transports) so a late-but-arriving message is not surfaced as
    /// missing.
    #[must_use]
    pub fn stale_missing(&self, now_ms: u64, grace_ms: u64) -> Vec<u64> {
        self.missing
            .iter()
            .filter(|(_, &detected_at)| now_ms.saturating_sub(detected_at) >= grace_ms)
            .map(|(&seq, _)| seq)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_sets_high_water_without_holes() {
        let mut s = SenderSeqState::default();
        assert_eq!(s.record(500, 10), SeqObservation::First);
        assert_eq!(s.high_water, 500);
        assert!(s.missing.is_empty());
    }

    #[test]
    fn consecutive_advances_high_water() {
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        assert_eq!(s.record(2, 11), SeqObservation::Consecutive);
        assert_eq!(s.record(3, 12), SeqObservation::Consecutive);
        assert_eq!(s.high_water, 3);
        assert!(s.missing.is_empty());
    }

    #[test]
    fn jump_records_the_skipped_range_as_holes() {
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        let obs = s.record(5, 20);
        assert_eq!(
            obs,
            SeqObservation::Gap {
                missing: vec![2, 3, 4]
            }
        );
        assert_eq!(s.high_water, 5);
        assert_eq!(s.missing.keys().copied().collect::<Vec<_>>(), vec![2, 3, 4]);
    }

    #[test]
    fn late_arrival_fills_the_hole() {
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        s.record(4, 20);
        assert_eq!(s.record(3, 21), SeqObservation::FilledHole);
        assert_eq!(s.missing.keys().copied().collect::<Vec<_>>(), vec![2]);
        assert_eq!(s.record(2, 22), SeqObservation::FilledHole);
        assert!(s.missing.is_empty());
    }

    #[test]
    fn duplicate_and_backward_counters_are_noops() {
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        s.record(2, 11);
        // Exact duplicate (optimistic-allocation race / lost counter
        // bump on the sender).
        assert_eq!(s.record(2, 12), SeqObservation::Duplicate);
        // Backward counter (sender restored from phrase, counter
        // restarted): never a gap, never mutates state.
        assert_eq!(s.record(1, 13), SeqObservation::Duplicate);
        assert_eq!(s.high_water, 2);
        assert!(s.missing.is_empty());
    }

    #[test]
    fn zero_seq_is_absorbed() {
        let mut s = SenderSeqState::default();
        assert_eq!(s.record(0, 10), SeqObservation::Duplicate);
        assert_eq!(s.high_water, 0);
    }

    #[test]
    fn oversized_gap_keeps_only_the_newest_holes() {
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        let obs = s.record(10_000, 20);
        let SeqObservation::Gap { missing } = obs else {
            panic!("expected Gap");
        };
        assert_eq!(missing.len(), MISSING_CAP);
        assert_eq!(*missing.first().unwrap(), 10_000 - MISSING_CAP as u64);
        assert_eq!(*missing.last().unwrap(), 9_999);
        assert_eq!(s.missing.len(), MISSING_CAP);
    }

    #[test]
    fn repeated_gaps_evict_oldest_beyond_cap() {
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        s.record(100, 20); // holes 2..=99
        s.record(200, 30); // holes 101..=199 -> total 197, capped to 128
        assert_eq!(s.missing.len(), MISSING_CAP);
        // Oldest holes were evicted; the newest survive.
        assert!(!s.missing.contains_key(&2));
        assert!(s.missing.contains_key(&199));
    }

    #[test]
    fn stale_missing_applies_the_grace_window() {
        let mut s = SenderSeqState::default();
        s.record(1, 1_000);
        s.record(4, 2_000); // holes 2, 3 detected at 2_000
        s.record(6, 9_000); // hole 5 detected at 9_000
                            // At 10_000 with 5s grace only the older holes qualify.
        assert_eq!(s.stale_missing(10_000, 5_000), vec![2, 3]);
        // Filling one removes it from the stale set.
        s.record(2, 10_500);
        assert_eq!(s.stale_missing(11_000, 5_000), vec![3]);
    }

    #[test]
    fn state_round_trips_through_serde_json() {
        // The vault seals conversations as JSON; u64 map keys must
        // survive the trip.
        let mut s = SenderSeqState::default();
        s.record(1, 10);
        s.record(5, 20);
        let json = serde_json::to_string(&s).unwrap();
        let back: SenderSeqState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
