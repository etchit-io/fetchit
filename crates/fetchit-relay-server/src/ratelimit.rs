//! Per-agent token-bucket rate limiter.

use dashmap::DashMap;
use fetchit_relay_proto::AgentId;
use std::time::{Duration, Instant};

/// Token bucket parameterised per call by `max_per_min`.
///
/// `max_per_min` is recorded so a cap change between two `allow()`
/// calls adopts the new cap without granting a fresh full burst.
/// Tokens are clamped to the new capacity when shrinking and left
/// alone when growing — a cap change never adds budget. The bucket
/// keeps refilling at the new rate from the existing token count.
#[derive(Clone, Debug)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
    max_per_min: u32,
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
            max_per_min,
        });
        if bucket.max_per_min != max_per_min {
            // Cap changed — adopt the new cap but DON'T grant a fresh
            // burst. A previously-drained bucket stays drained at the
            // new cap; a fuller bucket gets clamped to the new max.
            // This closes the reconnect-oscillation amplification (an
            // agent flipping a capability token on and off otherwise
            // harvests a fresh bucket per cycle since the entry
            // outlives any WS disconnect).
            bucket.tokens = bucket.tokens.min(cap);
            bucket.capacity = cap;
            bucket.refill_per_sec = refill;
            bucket.max_per_min = max_per_min;
        }
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

    #[test]
    fn pooled_sessions_for_one_agent_share_a_single_bucket() {
        // Reachability V1 / TB3 — pooled-deposit auth parity. The limiter
        // is keyed by `AgentId`, and the WS send path passes the
        // connection's *authenticated* `auth.agent_id`
        // (`ws.rs`: `ratelimit.allow(&auth.agent_id, …)`). So N pooled
        // connections for one agent all index the SAME bucket — opening a
        // second connection cannot multiply an agent's send budget.
        let rl = RateLimiter::new();
        let agent = AgentId::from_bytes([0x33; 32]);
        // First "connection" spends the only token at cap=1…
        assert!(rl.allow(&agent, 1));
        // …the second same-agent "connection" finds it already drained.
        assert!(!rl.allow(&agent, 1));
        // A different agent has an independent bucket.
        let other = AgentId::from_bytes([0x44; 32]);
        assert!(rl.allow(&other, 1));
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

    #[test]
    fn raising_cap_mid_session_does_not_grant_fresh_burst() {
        // Drain the bucket at max_per_min=10. Raising to 20 must NOT
        // hand out a fresh full bucket — an agent who just exhausted
        // their old budget should not get 20 new admits for free.
        // Without this contract, an authenticated agent can oscillate
        // a capability token on/off to harvest a full bucket per
        // reconnect because the bucket entry outlives WS disconnect.
        let rl = RateLimiter::new();
        let a = AgentId::from_bytes([2u8; 32]);
        for _ in 0..10 {
            assert!(rl.allow(&a, 10));
        }
        assert!(!rl.allow(&a, 10), "bucket should be empty at the old cap");
        assert!(
            !rl.allow(&a, 20),
            "raising cap immediately after exhausting the old one must not refill",
        );
    }

    #[test]
    fn lowering_cap_mid_session_clamps_tokens_to_new_capacity() {
        // The symmetric case — a downgrade must clamp the token
        // count to the new (smaller) cap so the agent can't drain
        // the larger budget after the cap has shrunk.
        let rl = RateLimiter::new();
        let a = AgentId::from_bytes([3u8; 32]);
        for _ in 0..3 {
            assert!(rl.allow(&a, 20));
        }
        // Bucket has ~17 tokens at cap=20. Lower to cap=5: clamp to 5.
        for i in 0..5 {
            assert!(
                rl.allow(&a, 5),
                "lowered-cap call {i} admits from the clamped bucket",
            );
        }
        assert!(
            !rl.allow(&a, 5),
            "after exhausting the clamped capacity the bucket is empty",
        );
    }

    #[test]
    fn oscillating_cap_does_not_amplify_admits() {
        // The DoS-amplification scenario: an authenticated agent
        // flips a capability token on and off across reconnects to
        // try and harvest a fresh full bucket each cycle. With clamp
        // semantics the total admits stay bounded by the refill
        // rate, not by the cap-switch frequency.
        let rl = RateLimiter::new();
        let a = AgentId::from_bytes([4u8; 32]);
        for _ in 0..10 {
            assert!(rl.allow(&a, 10));
        }
        // Drained at cap=10. Switch to cap=20 → no fresh burst (clamp).
        assert!(!rl.allow(&a, 20), "cap up does not refill");
        // Switch back to cap=10 → still drained.
        assert!(!rl.allow(&a, 10), "cap down does not refill");
        // Switch up again → still drained.
        assert!(!rl.allow(&a, 20), "second oscillation does not refill");
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
