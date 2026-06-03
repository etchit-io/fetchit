//! RAM-only transit buffer.
//!
//! Holds undelivered envelopes per recipient with a hard TTL and a
//! per-recipient cap. Sweeps eviction off a background tick. Never
//! writes to disk.

use crate::error::ServerError;
use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, TransitEnvelope};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Fixed-size overhead estimate per envelope (postcard-encoded scalars
/// plus per-`Vec` length prefixes). Conservative — over-counts by a few
/// bytes vs the true wire size, which is the safe direction for a cap.
const ENVELOPE_FIXED_OVERHEAD: usize = 128;

fn envelope_size(env: &TransitEnvelope) -> usize {
    ENVELOPE_FIXED_OVERHEAD
        .saturating_add(env.ciphertext.len())
        .saturating_add(env.nonce.len())
        .saturating_add(env.kem_ciphertext.len())
        .saturating_add(env.sender_signature.len())
}

/// One buffered envelope plus the instant it was enqueued.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The envelope.
    pub envelope: TransitEnvelope,
    /// Server-side enqueue time, monotonic.
    pub enqueued_at: Instant,
}

/// Per-recipient FIFO with TTL eviction.
pub struct TransitBuffer {
    by_recipient: DashMap<AgentId, VecDeque<Entry>>,
    ttl: Duration,
    cap_per_recipient: usize,
    max_total_bytes: usize,
    total_bytes: AtomicUsize,
}

impl TransitBuffer {
    /// Create an empty buffer with the given TTL, per-recipient
    /// envelope cap, and global byte cap.
    #[must_use]
    pub fn new(ttl: Duration, cap_per_recipient: usize, max_total_bytes: usize) -> Self {
        Self {
            by_recipient: DashMap::new(),
            ttl,
            cap_per_recipient,
            max_total_bytes,
            total_bytes: AtomicUsize::new(0),
        }
    }

    /// Enqueue an envelope for `to`.
    ///
    /// # Errors
    /// Returns [`ServerError::TransitBufferFull`] when either (a) the
    /// recipient's per-agent queue is at capacity or (b) admitting
    /// this envelope would push global buffered bytes above
    /// `max_total_bytes`.
    pub fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<(), ServerError> {
        let size = envelope_size(&envelope);
        self.reserve_bytes(size)?;
        let mut entry = self.by_recipient.entry(to).or_default();
        if entry.len() >= self.cap_per_recipient {
            self.total_bytes.fetch_sub(size, Ordering::Relaxed);
            return Err(ServerError::TransitBufferFull);
        }
        entry.push_back(Entry {
            envelope,
            enqueued_at: Instant::now(),
        });
        Ok(())
    }

    /// Remove and return every envelope currently buffered for `to`.
    #[must_use]
    pub fn drain(&self, to: &AgentId) -> Vec<Entry> {
        let Some((_, q)) = self.by_recipient.remove(to) else {
            return Vec::new();
        };
        let mut freed = 0usize;
        let out: Vec<Entry> = q.into_iter().collect();
        for entry in &out {
            freed = freed.saturating_add(envelope_size(&entry.envelope));
        }
        self.total_bytes.fetch_sub(freed, Ordering::Relaxed);
        out
    }

    /// Evict every entry older than `ttl`. Returns the count evicted.
    #[must_use]
    pub fn sweep_expired(&self) -> usize {
        let now = Instant::now();
        let mut evicted = 0usize;
        let mut freed = 0usize;
        self.by_recipient.retain(|_, q| {
            let before = q.len();
            q.retain(|e| {
                let alive = now.duration_since(e.enqueued_at) < self.ttl;
                if !alive {
                    freed = freed.saturating_add(envelope_size(&e.envelope));
                }
                alive
            });
            evicted = evicted.saturating_add(before - q.len());
            !q.is_empty()
        });
        self.total_bytes.fetch_sub(freed, Ordering::Relaxed);
        evicted
    }

    /// Current total bytes accounted across all recipients.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }

    fn reserve_bytes(&self, size: usize) -> Result<(), ServerError> {
        let mut current = self.total_bytes.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(size);
            if next > self.max_total_bytes {
                return Err(ServerError::TransitBufferFull);
            }
            match self.total_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    /// Total envelopes currently buffered across all recipients.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_recipient.iter().map(|r| r.len()).sum()
    }

    /// True if no envelopes are currently buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_proto::{EnvelopeKind, MachineId, WIRE_VERSION};

    fn env_for(sender: u8) -> TransitEnvelope {
        TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([sender; 32]),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![],
            nonce: vec![],
            kem_ciphertext: vec![],
            sender_signature: vec![],
        }
    }

    #[test]
    fn enqueue_then_drain_returns_in_fifo_order() {
        let b = TransitBuffer::new(Duration::from_secs(60), 10, usize::MAX);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        b.enqueue(to, env_for(2)).unwrap();
        let drained = b.drain(&to);
        assert_eq!(drained.len(), 2);
        assert_eq!(
            drained[0].envelope.sender_agent_id,
            AgentId::from_bytes([1; 32])
        );
        assert_eq!(
            drained[1].envelope.sender_agent_id,
            AgentId::from_bytes([2; 32])
        );
    }

    #[test]
    fn drain_clears_the_buffer() {
        let b = TransitBuffer::new(Duration::from_secs(60), 10, usize::MAX);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        let _ = b.drain(&to);
        assert!(b.drain(&to).is_empty());
        assert!(b.is_empty());
    }

    #[test]
    fn enqueue_rejects_when_full() {
        let b = TransitBuffer::new(Duration::from_secs(60), 2, usize::MAX);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        b.enqueue(to, env_for(2)).unwrap();
        let err = b.enqueue(to, env_for(3)).unwrap_err();
        assert!(matches!(err, ServerError::TransitBufferFull));
    }

    fn env_with_bytes(sender: u8, payload_bytes: usize) -> TransitEnvelope {
        let mut e = env_for(sender);
        e.ciphertext = vec![0u8; payload_bytes];
        e
    }

    #[test]
    fn global_byte_cap_rejects_when_admitting_would_exceed() {
        // Cap sized to fit exactly one 600-byte payload (plus header
        // overhead). The second enqueue to a *different* recipient
        // must be rejected — proving the cap is global rather than
        // per-recipient.
        let payload = 600usize;
        let cap = ENVELOPE_FIXED_OVERHEAD + payload;
        let b = TransitBuffer::new(Duration::from_secs(60), 10, cap);
        let to_a = AgentId::from_bytes([0xaa; 32]);
        let to_b = AgentId::from_bytes([0xbb; 32]);

        b.enqueue(to_a, env_with_bytes(1, payload))
            .expect("first envelope fits");
        let err = b
            .enqueue(to_b, env_with_bytes(2, payload))
            .expect_err("second envelope must trip the global cap");
        assert!(matches!(err, ServerError::TransitBufferFull));
        assert_eq!(
            b.total_bytes(),
            cap,
            "rejected enqueue must not leak reserved bytes",
        );
    }

    #[test]
    fn drain_releases_byte_budget_so_new_enqueue_fits() {
        let payload = 600usize;
        let cap = ENVELOPE_FIXED_OVERHEAD + payload;
        let b = TransitBuffer::new(Duration::from_secs(60), 10, cap);
        let to = AgentId::from_bytes([7u8; 32]);

        b.enqueue(to, env_with_bytes(1, payload)).unwrap();
        let _ = b.drain(&to);
        assert_eq!(b.total_bytes(), 0, "drain must free its bytes");
        b.enqueue(to, env_with_bytes(2, payload))
            .expect("budget recovered after drain");
    }

    #[tokio::test]
    async fn sweep_releases_byte_budget_for_evicted_entries() {
        let payload = 600usize;
        let cap = ENVELOPE_FIXED_OVERHEAD + payload;
        let b = TransitBuffer::new(Duration::from_millis(20), 10, cap);
        let to = AgentId::from_bytes([8u8; 32]);

        b.enqueue(to, env_with_bytes(1, payload)).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let evicted = b.sweep_expired();
        assert_eq!(evicted, 1);
        assert_eq!(b.total_bytes(), 0, "sweep must free evicted bytes");
        b.enqueue(to, env_with_bytes(2, payload))
            .expect("budget recovered after sweep");
    }

    #[test]
    fn per_recipient_cap_rejection_does_not_leak_bytes() {
        let b = TransitBuffer::new(Duration::from_secs(60), 1, 1 << 20);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        let bytes_after_first = b.total_bytes();
        let err = b.enqueue(to, env_for(2)).unwrap_err();
        assert!(matches!(err, ServerError::TransitBufferFull));
        assert_eq!(
            b.total_bytes(),
            bytes_after_first,
            "per-recipient cap path must roll back its byte reservation",
        );
    }

    #[tokio::test]
    async fn sweep_expired_evicts_old_entries() {
        let b = TransitBuffer::new(Duration::from_millis(50), 10, usize::MAX);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let evicted = b.sweep_expired();
        assert_eq!(evicted, 1);
        assert!(b.is_empty());
    }
}
