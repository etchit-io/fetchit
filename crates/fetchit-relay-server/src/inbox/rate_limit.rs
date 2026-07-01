//! Per-source-instance token-bucket rate limiter for the fediverse
//! inbox.
//!
//! Stage 3.1b gate 1. Keyed by the **remote instance hostname**
//! (parsed out of the signing actor URL's `keyId`), not the
//! per-actor surface — so a hostile instance burns rate-limit budget
//! once for all its actors. Mirrors the shape of
//! [`crate::ratelimit::RateLimiter`] (R-002) but uses `String` keys
//! and per-instance state rather than per-`AgentId`.
//!
//! The cap is constructor-fixed for 3.1b. R-002's cap-change-on-the-fly
//! semantics aren't needed here yet because the fediverse-inbox is
//! a single binary-restart setting; bring the dynamic cap reshape
//! over if 3.2 adds per-instance overrides.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Token bucket state for a single source instance.
#[derive(Clone, Debug)]
struct Bucket {
    /// Current token count (float so partial-refill works precisely).
    tokens: f64,
    /// Maximum tokens this bucket holds (burst size).
    capacity: f64,
    /// Tokens added per second of wall-clock time.
    refill_per_sec: f64,
    /// Last refill timestamp — drives the time-since-then-refill math.
    last_refill: Instant,
}

/// Per-source-instance token-bucket limiter.
///
/// Use [`Self::allow`] before forwarding an inbox POST further into
/// the pipeline. Returns `true` if the request consumed a token,
/// `false` if the instance is over budget.
#[derive(Debug)]
pub struct InboxRateLimit {
    per_instance: DashMap<String, Bucket>,
    rate_per_min: u32,
}

impl InboxRateLimit {
    /// New limiter with `rate_per_min` requests per source instance
    /// per 60 seconds. Burst capacity equals the rate (1-minute
    /// budget held in reserve when idle).
    #[must_use]
    pub fn new(rate_per_min: u32) -> Self {
        Self {
            per_instance: DashMap::new(),
            rate_per_min,
        }
    }

    /// Number of source instances currently tracked. Useful for
    /// ops counters; not part of the gate semantics.
    #[must_use]
    pub fn tracked_instances(&self) -> usize {
        self.per_instance.len()
    }

    /// Default cap for this limiter (requests/minute/instance).
    #[must_use]
    pub fn rate_per_min(&self) -> u32 {
        self.rate_per_min
    }

    /// Attempt to consume one request's worth of budget for the
    /// source instance keyed by `instance` (hostname or
    /// host:port). `true` ⇒ accepted; `false` ⇒ over budget.
    #[must_use]
    pub fn allow(&self, instance: &str) -> bool {
        self.allow_at(instance, Instant::now())
    }

    /// Test-shaped variant of [`Self::allow`] that takes an explicit
    /// `now`. Production callers use [`Self::allow`] which calls
    /// `Instant::now()` itself.
    #[must_use]
    pub fn allow_at(&self, instance: &str, now: Instant) -> bool {
        let cap = f64::from(self.rate_per_min);
        let refill = cap / 60.0;
        let mut bucket = self
            .per_instance
            .entry(instance.to_string())
            .or_insert(Bucket {
                tokens: cap,
                capacity: cap,
                refill_per_sec: refill,
                last_refill: now,
            });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.last_refill = now;
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_per_sec).min(bucket.capacity);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets unused for at least `idle`. Run periodically by
    /// the relay-server's existing sweeper if memory becomes an
    /// issue; not on the hot path of [`Self::allow`].
    pub fn sweep_idle(&self, idle: Duration) {
        let now = Instant::now();
        self.per_instance
            .retain(|_, b| now.duration_since(b.last_refill) < idle);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn allow_consumes_one_token_per_call() {
        let lim = InboxRateLimit::new(60);
        // Cap = 60 tokens; first 60 calls must succeed.
        let t0 = Instant::now();
        for _ in 0..60 {
            assert!(lim.allow_at("mastodon.example", t0));
        }
        // 61st must fail (no time elapsed -> no refill).
        assert!(!lim.allow_at("mastodon.example", t0));
    }

    #[test]
    fn refill_restores_budget_over_time() {
        let lim = InboxRateLimit::new(60); // 1 token/second steady state
        let t0 = Instant::now();
        // Drain the bucket.
        for _ in 0..60 {
            assert!(lim.allow_at("a.example", t0));
        }
        assert!(!lim.allow_at("a.example", t0));
        // After 30s, ~30 tokens have refilled.
        let t30 = t0 + Duration::from_secs(30);
        for _ in 0..30 {
            assert!(lim.allow_at("a.example", t30), "expected refilled token");
        }
        assert!(!lim.allow_at("a.example", t30));
    }

    #[test]
    fn distinct_instances_dont_share_budget() {
        let lim = InboxRateLimit::new(2);
        let t0 = Instant::now();
        assert!(lim.allow_at("a.example", t0));
        assert!(lim.allow_at("a.example", t0));
        assert!(!lim.allow_at("a.example", t0));
        // b.example has its own bucket — full at first call.
        assert!(lim.allow_at("b.example", t0));
        assert!(lim.allow_at("b.example", t0));
        assert!(!lim.allow_at("b.example", t0));
    }

    #[test]
    fn sweep_idle_drops_unused_buckets() {
        let lim = InboxRateLimit::new(60);
        let t0 = Instant::now();
        let _ = lim.allow_at("a.example", t0);
        let _ = lim.allow_at("b.example", t0);
        assert_eq!(lim.tracked_instances(), 2);
        // sweep at t0 + 1ns of idle threshold — both buckets still
        // young, neither dropped.
        lim.sweep_idle(Duration::from_secs(3600));
        assert_eq!(lim.tracked_instances(), 2);
    }
}
