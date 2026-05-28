//! Per-agent token-bucket rate limiter.

use dashmap::DashMap;
use fetchit_relay_proto::AgentId;
use std::time::{Duration, Instant};

/// Token bucket parameterised per call by `max_per_min`.
#[derive(Clone, Debug)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

/// Per-agent rate limiter. Drops idle agents after a sweep.
#[derive(Default)]
pub struct RateLimiter {
    per_agent: DashMap<AgentId, Bucket>,
}

impl RateLimiter {
    /// Construct an empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to consume one envelope's worth of budget for `agent`.
    /// Returns `true` if accepted, `false` if the bucket is empty.
    #[must_use]
    pub fn allow(&self, agent: &AgentId, max_per_min: u32) -> bool {
        let now = Instant::now();
        let cap = f64::from(max_per_min);
        let refill = cap / 60.0;
        let mut bucket = self.per_agent.entry(*agent).or_insert(Bucket {
            tokens: cap,
            capacity: cap,
            refill_per_sec: refill,
            last_refill: now,
        });
        bucket.capacity = cap;
        bucket.refill_per_sec = refill;
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

    /// Drop buckets unused for at least `idle` seconds.
    pub fn sweep_idle(&self, idle: Duration) {
        let now = Instant::now();
        self.per_agent
            .retain(|_, b| now.duration_since(b.last_refill) < idle);
    }

    /// Number of agents currently tracked.
    #[must_use]
    pub fn tracked_agents(&self) -> usize {
        self.per_agent.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fresh_bucket_admits_up_to_capacity() {
        let rl = RateLimiter::new();
        let a = AgentId::from_bytes([1u8; 32]);
        for _ in 0..10 {
            assert!(rl.allow(&a, 10));
        }
        assert!(!rl.allow(&a, 10));
    }

    #[tokio::test]
    async fn bucket_refills_over_time() {
        let rl = RateLimiter::new();
        let a = AgentId::from_bytes([1u8; 32]);
        // max_per_min=60 ⇒ 1 token / second of refill.
        for _ in 0..60 {
            assert!(rl.allow(&a, 60));
        }
        assert!(!rl.allow(&a, 60));
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(rl.allow(&a, 60));
    }

    #[tokio::test]
    async fn idle_buckets_get_swept() {
        let rl = RateLimiter::new();
        let a = AgentId::from_bytes([1u8; 32]);
        assert!(rl.allow(&a, 10));
        std::thread::sleep(Duration::from_millis(50));
        rl.sweep_idle(Duration::from_millis(20));
        assert_eq!(rl.tracked_agents(), 0);
    }
}
