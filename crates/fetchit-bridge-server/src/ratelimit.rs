//! Per-IP token-bucket rate limiting for the registration endpoint, with
//! secure-by-default client-IP resolution behind a trusted reverse proxy.
//!
//! `POST /actors` is open in the sense that anyone can mint a valid `ML-DSA`
//! attestation, so a flood of distinct attested documents could still
//! exhaust the store. A per-IP token bucket caps the registration rate with
//! no shared cross-request state beyond a single bounded in-memory map.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Instant;

use axum::http::HeaderMap;

/// How many tracked buckets to sample when evicting at capacity. A bounded
/// sample keeps eviction O(1) instead of an O(n) full min-scan per insert
/// (which a spray-many-IPs attack would otherwise amplify).
const EVICT_SAMPLE: usize = 8;

/// One client's refilling token bucket.
struct Bucket {
    /// Tokens currently available (fractional to allow sub-token refill).
    tokens: f64,
    /// When the bucket was last refilled.
    last: Instant,
}

/// A fixed-capacity, per-IP token-bucket rate limiter.
///
/// Each distinct IP gets `capacity` tokens that refill at `refill_per_sec`
/// tokens per second; a request consumes one token, and an empty bucket is
/// rejected. The tracked-IP map is bounded at `max_tracked` entries
/// (evicting the oldest of a bounded sample) so a spray-many-source-IPs attack
/// cannot grow it without bound.
pub struct RateLimiter {
    /// Burst size and refill ceiling. A value `< 1.0` disables the limiter.
    capacity: f64,
    /// Sustained refill rate in tokens per second.
    refill_per_sec: f64,
    /// Hard cap on distinct tracked IPs (bounds memory).
    max_tracked: usize,
    /// Per-IP buckets. A plain `Mutex` suffices: the critical section is a
    /// few map operations and is never held across an `await`.
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Build a limiter allowing bursts of `capacity` requests, refilling at
    /// `refill_per_sec` tokens/second, tracking at most `max_tracked`
    /// distinct IPs. A `capacity` of `0` disables limiting entirely (every
    /// request allowed) -- used by tests and as an operator escape hatch.
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: f64, max_tracked: usize) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_per_sec,
            max_tracked: max_tracked.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Whether limiting is active. A disabled limiter allows everything.
    fn enabled(&self) -> bool {
        self.capacity >= 1.0
    }

    /// Returns `true` if a request from `ip` is allowed (consuming one token)
    /// and `false` if the bucket is empty. `now` is injected so refill
    /// behaviour is deterministically testable.
    #[must_use]
    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled() {
            return true;
        }
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !buckets.contains_key(&ip) && buckets.len() >= self.max_tracked {
            // Evict the oldest of a bounded sample -- a full min-scan would be
            // O(n) per insert, which a spray-many-IPs attack could amplify.
            if let Some(victim) = buckets
                .iter()
                .take(EVICT_SAMPLE)
                .min_by_key(|(_, b)| b.last)
                .map(|(k, _)| *k)
            {
                buckets.remove(&victim);
            }
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of distinct IPs currently tracked. Used in tests to assert the
    /// `max_tracked` bound holds.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        match self.buckets.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

/// Parse one `X-Forwarded-For` entry into an IP, tolerating a trailing
/// `:port` that some proxies emit. A bare IPv4/IPv6 address parses directly;
/// `1.2.3.4:5678` and `[2001:db8::1]:443` parse as a socket address and the
/// IP is taken -- mirroring the socket-peer side, which already strips the
/// port via `SocketAddr::ip`.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    entry.parse::<SocketAddr>().ok().map(|sa| sa.ip())
}

/// Resolve the client IP to rate-limit on.
///
/// Secure-by-default: with `trusted_hops == 0` the socket `peer` is used and
/// any `X-Forwarded-For` header is ignored, so a directly-connected client
/// cannot spoof its key. With `trusted_hops == n > 0` the IP is taken from
/// the n-th `X-Forwarded-For` entry counted from the right -- the address the
/// n-th trusted proxy in front observed. Client-supplied entries are always
/// to the *left* of the proxy-appended ones, so they are never selected as
/// long as `trusted_hops` matches the real proxy count. A missing, too-short,
/// or unparseable header falls back to `peer` (fail safe -- a short chain is
/// never trusted).
#[must_use]
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_hops: usize) -> IpAddr {
    if trusted_hops == 0 {
        return peer;
    }
    let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer;
    };
    let entries: Vec<&str> = xff
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.len() < trusted_hops {
        return peer;
    }
    let idx = entries.len() - trusted_hops;
    entries
        .get(idx)
        .copied()
        .and_then(parse_forwarded_ip)
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use axum::http::{HeaderMap, HeaderValue};

    use super::{client_ip, RateLimiter};

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    #[test]
    fn allows_burst_then_blocks() {
        let rl = RateLimiter::new(2, 0.0, 1024);
        let now = Instant::now();
        let a = ip(1);
        assert!(rl.check(a, now));
        assert!(rl.check(a, now));
        assert!(!rl.check(a, now)); // burst exhausted, no refill
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1, 1.0, 1024); // 1 token/sec
        let t0 = Instant::now();
        let a = ip(1);
        assert!(rl.check(a, t0));
        assert!(!rl.check(a, t0)); // empty
        let t1 = t0 + Duration::from_secs(1);
        assert!(rl.check(a, t1)); // refilled one token
    }

    #[test]
    fn distinct_ips_are_independent() {
        let rl = RateLimiter::new(1, 0.0, 1024);
        let now = Instant::now();
        assert!(rl.check(ip(1), now));
        assert!(rl.check(ip(2), now)); // different IP, own bucket
        assert!(!rl.check(ip(1), now)); // first IP still empty
    }

    #[test]
    fn capacity_zero_disables() {
        let rl = RateLimiter::new(0, 0.0, 1024);
        let now = Instant::now();
        for _ in 0..100 {
            assert!(rl.check(ip(1), now));
        }
    }

    #[test]
    fn tracked_map_is_bounded() {
        let rl = RateLimiter::new(5, 0.0, 2); // track at most 2 IPs
        let now = Instant::now();
        let _ = rl.check(ip(1), now);
        let _ = rl.check(ip(2), now);
        let _ = rl.check(ip(3), now); // forces eviction of the oldest
        assert!(rl.tracked() <= 2, "tracked={}", rl.tracked());
    }

    #[test]
    fn hops_zero_uses_peer_and_ignores_xff() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert_eq!(client_ip(ip(9), &h, 0), ip(9));
    }

    #[test]
    fn one_hop_takes_rightmost_xff() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert_eq!(
            client_ip(ip(9), &h, 1),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn spoofed_left_entries_are_ignored() {
        // Attacker prepends a fake entry; the proxy appends the real client
        // on the right. One trusted hop -> rightmost wins.
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("9.9.9.9, 1.2.3.4"),
        );
        assert_eq!(
            client_ip(ip(9), &h, 1),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn two_hops_takes_second_from_right() {
        // client, then CDN egress appended by the inner proxy.
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        assert_eq!(
            client_ip(ip(9), &h, 2),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn short_chain_falls_back_to_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert_eq!(client_ip(ip(9), &h, 2), ip(9)); // only 1 entry, need 2
    }

    #[test]
    fn missing_header_falls_back_to_peer() {
        let h = HeaderMap::new();
        assert_eq!(client_ip(ip(9), &h, 1), ip(9));
    }

    #[test]
    fn garbage_entry_falls_back_to_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip(ip(9), &h, 1), ip(9));
    }

    #[test]
    fn xff_entry_with_ipv4_port_is_stripped() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4:5678"));
        assert_eq!(
            client_ip(ip(9), &h, 1),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn xff_bracketed_ipv6_port_is_stripped() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("[2001:db8::1]:443"),
        );
        let want: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(client_ip(ip(9), &h, 1), want);
    }
}
