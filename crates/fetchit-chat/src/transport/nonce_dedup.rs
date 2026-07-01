//! Bounded LRU dedup for `MultiHomeTransport`'s inbound fan-in.
//!
//! When the same envelope arrives over multiple relay sessions (the
//! sender broadcast it to several of our advertised relays), the
//! dispatch layer should see it exactly once. `NonceDedup` provides
//! that gate: the first observation of a `(sender, nonce)` pair is
//! recorded + returned `true` (pass to dispatch); subsequent
//! observations within the LRU window return `false` (drop).
//!
//! Backed by `lru::LruCache` with TTL eviction on each observe call.

use std::time::{Duration, Instant};

use lru::LruCache;

/// First-seen-wins dedup gate keyed on `(sender_agent_id, nonce)`.
pub struct NonceDedup {
    seen: LruCache<(String, [u8; 12]), Instant>,
    ttl: Duration,
}

impl NonceDedup {
    /// Create a fresh dedup gate with at most `capacity` entries and
    /// a per-entry TTL of `ttl`.
    ///
    /// # Panics
    /// Panics when `capacity` is zero.
    #[must_use]
    #[allow(clippy::expect_used)] // documented panic per #[Panics]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = std::num::NonZeroUsize::new(capacity).expect("capacity must be non-zero");
        Self {
            seen: LruCache::new(cap),
            ttl,
        }
    }

    /// Record an observation of `(sender, nonce)` at time `now`.
    /// Returns `true` when this is the first time we've seen it (pass
    /// to dispatch); `false` when we already have it within the TTL
    /// window (drop).
    pub fn observe(&mut self, key: (String, [u8; 12]), now: Instant) -> bool {
        if let Some(&seen_at) = self.seen.get(&key) {
            if now.duration_since(seen_at) < self.ttl {
                return false;
            }
            // Stale; treat as first-seen + refresh.
        }
        self.seen.put(key, now);
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn dedup_first_seen_wins_duplicate_dropped() {
        let mut d = NonceDedup::new(8, Duration::from_secs(300));
        let k = ("alice".to_string(), [1u8; 12]);
        let now = Instant::now();
        assert!(d.observe(k.clone(), now));
        assert!(!d.observe(k.clone(), now));
    }

    #[test]
    fn dedup_distinct_nonces_preserved() {
        let mut d = NonceDedup::new(8, Duration::from_secs(300));
        let now = Instant::now();
        assert!(d.observe(("a".into(), [1u8; 12]), now));
        assert!(d.observe(("a".into(), [2u8; 12]), now));
        assert!(d.observe(("b".into(), [1u8; 12]), now));
    }

    #[test]
    fn dedup_evicts_oldest_at_capacity() {
        let mut d = NonceDedup::new(2, Duration::from_secs(300));
        let now = Instant::now();
        d.observe(("a".into(), [1u8; 12]), now);
        d.observe(("a".into(), [2u8; 12]), now + Duration::from_millis(1));
        d.observe(("a".into(), [3u8; 12]), now + Duration::from_millis(2));
        // [1u8;12] should have evicted; re-observing returns true (first-seen again).
        assert!(d.observe(("a".into(), [1u8; 12]), now + Duration::from_millis(3)));
    }

    #[test]
    fn dedup_ttl_expiry_treats_stale_as_first_seen() {
        let mut d = NonceDedup::new(8, Duration::from_millis(100));
        let now = Instant::now();
        let k = ("a".to_string(), [1u8; 12]);
        assert!(d.observe(k.clone(), now));
        // Within TTL: drop.
        assert!(!d.observe(k.clone(), now + Duration::from_millis(50)));
        // Past TTL: first-seen again.
        assert!(d.observe(k.clone(), now + Duration::from_millis(200)));
    }
}
