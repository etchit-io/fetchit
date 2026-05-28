//! RAM-only transit buffer.
//!
//! Holds undelivered envelopes per recipient with a hard TTL and a
//! per-recipient cap. Sweeps eviction off a background tick. Never
//! writes to disk.

use crate::error::ServerError;
use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, TransitEnvelope};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

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
}

impl TransitBuffer {
    /// Create an empty buffer with the given TTL + per-recipient cap.
    #[must_use]
    pub fn new(ttl: Duration, cap_per_recipient: usize) -> Self {
        Self {
            by_recipient: DashMap::new(),
            ttl,
            cap_per_recipient,
        }
    }

    /// Enqueue an envelope for `to`.
    ///
    /// # Errors
    /// Returns [`ServerError::TransitBufferFull`] when the recipient's
    /// queue is already at capacity.
    pub fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<(), ServerError> {
        let mut entry = self.by_recipient.entry(to).or_default();
        if entry.len() >= self.cap_per_recipient {
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
        self.by_recipient
            .remove(to)
            .map(|(_, q)| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Evict every entry older than `ttl`. Returns the count evicted.
    #[must_use]
    pub fn sweep_expired(&self) -> usize {
        let now = Instant::now();
        let mut evicted = 0usize;
        self.by_recipient.retain(|_, q| {
            let before = q.len();
            q.retain(|e| now.duration_since(e.enqueued_at) < self.ttl);
            evicted = evicted.saturating_add(before - q.len());
            !q.is_empty()
        });
        evicted
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
    use fetchit_relay_proto::{EnvelopeKind, MachineId};

    fn env_for(sender: u8) -> TransitEnvelope {
        TransitEnvelope {
            version: 1,
            kind: EnvelopeKind::Dm,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([sender; 32]),
            sender_machine_id: MachineId::from_bytes([0u8; 32]),
            timestamp_ms: 1,
            ciphertext: vec![],
            nonce: vec![],
            kem_ciphertext: vec![],
            sender_signature: vec![],
        }
    }

    #[test]
    fn enqueue_then_drain_returns_in_fifo_order() {
        let b = TransitBuffer::new(Duration::from_secs(60), 10);
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
        let b = TransitBuffer::new(Duration::from_secs(60), 10);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        let _ = b.drain(&to);
        assert!(b.drain(&to).is_empty());
        assert!(b.is_empty());
    }

    #[test]
    fn enqueue_rejects_when_full() {
        let b = TransitBuffer::new(Duration::from_secs(60), 2);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        b.enqueue(to, env_for(2)).unwrap();
        let err = b.enqueue(to, env_for(3)).unwrap_err();
        assert!(matches!(err, ServerError::TransitBufferFull));
    }

    #[tokio::test]
    async fn sweep_expired_evicts_old_entries() {
        let b = TransitBuffer::new(Duration::from_millis(50), 10);
        let to = AgentId::from_bytes([9u8; 32]);
        b.enqueue(to, env_for(1)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let evicted = b.sweep_expired();
        assert_eq!(evicted, 1);
        assert!(b.is_empty());
    }
}
