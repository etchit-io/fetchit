//! Sliding-window replay cache for the fediverse inbox.
//!
//! Stage 3.1b gate 3. Caches `(Content-Digest, Date)` pairs for the
//! last [`REPLAY_WINDOW`] seconds (default 5 minutes per the M4
//! plan). [`ReplayWindow::record_and_check_now`] returns `false` if the same
//! pair has already been recorded inside the window — i.e. a
//! replay.
//!
//! Bounded memory: the inner map is capped at [`REPLAY_CAP`] entries.
//! When the cap is reached, the oldest entry is evicted before
//! insert (LRU-by-insertion-time, since `Instant` strictly
//! increases). 100k entries × ~80 bytes/entry ≈ 8 MB worst case,
//! well below the relay-server's existing memory ceilings.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default sliding window for the replay cache (RFC 9421 freshness
/// window).
pub const REPLAY_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Hard ceiling on tracked replay entries — bounded memory.
pub const REPLAY_CAP: usize = 100_000;

/// Sliding-window cache of `(digest, date_unix)` pairs.
#[derive(Debug)]
pub struct ReplayWindow {
    inner: Mutex<HashMap<(String, i64), Instant>>,
    window: Duration,
    cap: usize,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(REPLAY_WINDOW, REPLAY_CAP)
    }
}

impl ReplayWindow {
    /// New window with explicit `window` duration and `cap` capacity.
    /// Production callers should use [`Self::default`] for the
    /// 5-minute / 100k defaults.
    #[must_use]
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            cap,
        }
    }

    /// Record `(digest, date_unix)` if not already present in the
    /// window. Returns `true` if NEW (request allowed through), or
    /// `false` if it duplicates a prior entry within
    /// `Self::window` (replay — drop the request).
    ///
    /// `now` is injected so unit tests can wind the clock without
    /// `tokio::time::pause()`. Production callers use
    /// [`Self::record_and_check_now`].
    #[must_use]
    pub fn record_and_check(&self, key: (String, i64), now: Instant) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return true;
        };

        // Sweep expired entries before insert. Cheap O(n) for now;
        // if 3.2 metrics show this becomes a bottleneck, swap in a
        // priority queue.
        guard.retain(|_, t| now.duration_since(*t) < self.window);

        if guard.contains_key(&key) {
            return false;
        }

        // Memory-bounded insert: if at cap, evict the oldest entry
        // BEFORE insert so we never exceed the cap mid-call.
        if guard.len() >= self.cap {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_key);
            }
        }

        guard.insert(key, now);
        true
    }

    /// Production-shaped variant of [`Self::record_and_check`] that
    /// calls `Instant::now()` itself.
    #[must_use]
    pub fn record_and_check_now(&self, key: (String, i64)) -> bool {
        self.record_and_check(key, Instant::now())
    }

    /// Live entry count. For ops metrics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.len())
    }

    /// `true` when no entries are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn k(digest: &str, date: i64) -> (String, i64) {
        (digest.into(), date)
    }

    #[test]
    fn new_pair_is_allowed() {
        let w = ReplayWindow::default();
        let t0 = Instant::now();
        assert!(w.record_and_check(k("AAA", 1), t0));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn duplicate_pair_is_rejected() {
        let w = ReplayWindow::default();
        let t0 = Instant::now();
        assert!(w.record_and_check(k("AAA", 1), t0));
        assert!(
            !w.record_and_check(k("AAA", 1), t0 + Duration::from_secs(1)),
            "same digest+date in window must be rejected as replay"
        );
    }

    #[test]
    fn distinct_pairs_dont_collide() {
        let w = ReplayWindow::default();
        let t0 = Instant::now();
        assert!(w.record_and_check(k("AAA", 1), t0));
        assert!(w.record_and_check(k("BBB", 1), t0));
        assert!(w.record_and_check(k("AAA", 2), t0));
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn entry_evicted_after_window() {
        let w = ReplayWindow::new(Duration::from_secs(60), REPLAY_CAP);
        let t0 = Instant::now();
        assert!(w.record_and_check(k("AAA", 1), t0));
        // Just past the window — entry should sweep + the same key
        // becomes a fresh insert.
        let later = t0 + Duration::from_secs(61);
        assert!(w.record_and_check(k("AAA", 1), later));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn cap_evicts_oldest_on_insert() {
        let w = ReplayWindow::new(Duration::from_secs(3600), 3);
        let t0 = Instant::now();
        assert!(w.record_and_check(k("A", 1), t0));
        assert!(w.record_and_check(k("B", 1), t0 + Duration::from_secs(1)));
        assert!(w.record_and_check(k("C", 1), t0 + Duration::from_secs(2)));
        // Cap = 3, insert 4th: oldest (k=A) evicted.
        assert!(w.record_and_check(k("D", 1), t0 + Duration::from_secs(3)));
        assert_eq!(w.len(), 3);
        // 'A' is gone — re-inserting it is allowed.
        assert!(w.record_and_check(k("A", 1), t0 + Duration::from_secs(4)));
    }

    #[test]
    fn default_is_5_minutes_100k() {
        assert_eq!(REPLAY_WINDOW, Duration::from_secs(300));
        assert_eq!(REPLAY_CAP, 100_000);
    }
}
