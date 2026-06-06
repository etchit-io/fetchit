#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::time::{Duration, Instant};

/// Sliding-window crash counter. Returns true when the supervisor
/// must give up and stop respawning.
#[derive(Debug, Default)]
pub struct CrashLoopDetector {
    crashes: Vec<Instant>,
    window: Duration,
    threshold: usize,
}

impl CrashLoopDetector {
    #[must_use]
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            crashes: Vec::new(),
            window,
            threshold,
        }
    }

    /// Record a crash; returns true when the threshold within the
    /// rolling window has been exceeded.
    pub fn record(&mut self, now: Instant) -> bool {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        self.crashes.retain(|t| *t >= cutoff);
        self.crashes.push(now);
        self.crashes.len() >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_at_three_crashes_in_thirty_seconds() {
        let mut d = CrashLoopDetector::new(Duration::from_secs(30), 3);
        let t0 = Instant::now();
        assert!(!d.record(t0));
        assert!(!d.record(t0 + Duration::from_secs(5)));
        assert!(d.record(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn does_not_trip_when_crashes_span_more_than_window() {
        let mut d = CrashLoopDetector::new(Duration::from_secs(30), 3);
        let t0 = Instant::now();
        assert!(!d.record(t0));
        assert!(!d.record(t0 + Duration::from_secs(40)));
        assert!(!d.record(t0 + Duration::from_secs(50)));
    }
}
