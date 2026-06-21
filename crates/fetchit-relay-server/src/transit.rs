//! Transit store for undelivered envelopes.
//!
//! [`TransitStore`] is the seam. [`TransitBuffer`] is the in-RAM
//! implementation used in tests and as the no-path fallback; the
//! production daemon uses the `SQLite`-backed
//! [`crate::transit_sqlite::SqliteTransitStore`] so undelivered
//! ciphertext survives a relay restart and a multi-day offline window.
//!
//! Implementations hold only the opaque `TransitEnvelope` ciphertext and
//! never inspect its payload — the relay stays blind. Delivery is
//! confirmed out of band (a client delivery-ack drives
//! [`TransitStore::delete`]); reads are non-destructive so a mid-delivery
//! disconnect or restart cannot lose a message.

use crate::error::ServerError;
use dashmap::DashMap;
use fetchit_relay_proto::{AgentId, TransitEnvelope};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Milliseconds since the Unix epoch, saturating on the rare clock error.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

/// One buffered envelope plus the wall-clock time it was enqueued.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The envelope.
    pub envelope: TransitEnvelope,
    /// Server-side enqueue time (ms since the Unix epoch). Wall-clock so
    /// it survives serialization in the durable backend.
    pub enqueued_at_ms: u64,
}

/// A stored entry plus its store-stable id, returned by
/// [`TransitStore::read_all`]. The id is echoed by the client's
/// delivery-ack to drive [`TransitStore::delete`].
#[derive(Clone, Debug)]
pub struct StoredEntry {
    /// Store-stable id (never reused).
    pub id: u64,
    /// The envelope.
    pub envelope: TransitEnvelope,
    /// Server-side enqueue time (ms since the Unix epoch).
    pub enqueued_at_ms: u64,
}

/// A per-recipient store of undelivered, opaque transit envelopes.
///
/// Implementations MUST persist only the ciphertext `TransitEnvelope`
/// and never inspect its payload.
pub trait TransitStore: Send + Sync {
    /// Enqueue `envelope` for `to`, returning a store-stable id used
    /// later by [`TransitStore::delete`]. Ids are never reused.
    ///
    /// # Errors
    /// [`ServerError::TransitBufferFull`] on a per-recipient or global
    /// cap breach; [`ServerError::TransitStore`] on a backend failure.
    fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<u64, ServerError>;

    /// Read every currently-stored entry for `to` WITHOUT removing it
    /// (delivery is confirmed separately via [`TransitStore::delete`]).
    fn read_all(&self, to: &AgentId) -> Vec<StoredEntry>;

    /// Delete the listed ids for `to` (called on a client delivery-ack).
    /// Unknown ids are ignored.
    fn delete(&self, to: &AgentId, ids: &[u64]);

    /// Evict every entry older than the configured TTL; returns the
    /// count evicted.
    fn sweep_expired(&self) -> usize;

    /// Total envelopes currently stored across all recipients.
    fn len(&self) -> usize;

    /// True if nothing is stored.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total accounted bytes across all recipients.
    fn total_bytes(&self) -> usize;
}

/// In-RAM per-recipient FIFO with TTL eviction. The test/fallback
/// [`TransitStore`]; production uses the `SQLite` backend.
pub struct TransitBuffer {
    by_recipient: DashMap<AgentId, VecDeque<(u64, Entry)>>,
    ttl_ms: u64,
    cap_per_recipient: usize,
    max_total_bytes: usize,
    total_bytes: AtomicUsize,
    next_id: AtomicU64,
}

impl TransitBuffer {
    /// Create an empty buffer with the given TTL, per-recipient
    /// envelope cap, and global byte cap.
    #[must_use]
    pub fn new(ttl: Duration, cap_per_recipient: usize, max_total_bytes: usize) -> Self {
        Self {
            by_recipient: DashMap::new(),
            ttl_ms: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
            cap_per_recipient,
            max_total_bytes,
            total_bytes: AtomicUsize::new(0),
            // Start at 1; `0` is reserved for "direct / non-durable" on
            // the wire (`Deliver::transit_seq == 0` needs no ack).
            next_id: AtomicU64::new(1),
        }
    }

    /// Remove and return every envelope currently buffered for `to`
    /// (destructive).
    ///
    /// Retained for the legacy reconnect-drain path; superseded by
    /// [`TransitStore::read_all`] + [`TransitStore::delete`], which do
    /// not lose messages on a mid-delivery disconnect.
    #[must_use]
    pub fn drain(&self, to: &AgentId) -> Vec<Entry> {
        let Some((_, q)) = self.by_recipient.remove(to) else {
            return Vec::new();
        };
        let out: Vec<Entry> = q.into_iter().map(|(_, e)| e).collect();
        let mut freed = 0usize;
        for entry in &out {
            freed = freed.saturating_add(envelope_size(&entry.envelope));
        }
        self.total_bytes.fetch_sub(freed, Ordering::Relaxed);
        out
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
}

impl TransitStore for TransitBuffer {
    fn enqueue(&self, to: AgentId, envelope: TransitEnvelope) -> Result<u64, ServerError> {
        let size = envelope_size(&envelope);
        self.reserve_bytes(size)?;
        let mut entry = self.by_recipient.entry(to).or_default();
        if entry.len() >= self.cap_per_recipient {
            self.total_bytes.fetch_sub(size, Ordering::Relaxed);
            return Err(ServerError::TransitBufferFull);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        entry.push_back((
            id,
            Entry {
                envelope,
                enqueued_at_ms: now_ms(),
            },
        ));
        Ok(id)
    }

    fn read_all(&self, to: &AgentId) -> Vec<StoredEntry> {
        self.by_recipient
            .get(to)
            .map(|q| {
                q.iter()
                    .map(|item| {
                        let (id, e) = item;
                        StoredEntry {
                            id: *id,
                            envelope: e.envelope.clone(),
                            enqueued_at_ms: e.enqueued_at_ms,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn delete(&self, to: &AgentId, ids: &[u64]) {
        if let Some(mut q) = self.by_recipient.get_mut(to) {
            let mut freed = 0usize;
            q.retain(|item| {
                let (id, e) = item;
                let keep = !ids.contains(id);
                if !keep {
                    freed = freed.saturating_add(envelope_size(&e.envelope));
                }
                keep
            });
            self.total_bytes.fetch_sub(freed, Ordering::Relaxed);
        }
    }

    fn sweep_expired(&self) -> usize {
        let now = now_ms();
        let mut evicted = 0usize;
        let mut freed = 0usize;
        self.by_recipient.retain(|_, q| {
            let before = q.len();
            q.retain(|item| {
                let (_, e) = item;
                let alive = now.saturating_sub(e.enqueued_at_ms) < self.ttl_ms;
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

    fn len(&self) -> usize {
        self.by_recipient.iter().map(|r| r.len()).sum()
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
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
    fn read_all_is_non_destructive_and_delete_removes_by_id() {
        let b = TransitBuffer::new(Duration::from_secs(60), 10, usize::MAX);
        let to = AgentId::from_bytes([9u8; 32]);
        let id1 = b.enqueue(to, env_for(1)).unwrap();
        let id2 = b.enqueue(to, env_for(2)).unwrap();
        assert_ne!(id1, id2, "ids are unique");

        let first = b.read_all(&to);
        assert_eq!(first.len(), 2);
        let second = b.read_all(&to);
        assert_eq!(second.len(), 2, "read_all is non-destructive");

        b.delete(&to, &[id1]);
        let after = b.read_all(&to);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, id2);
    }

    #[test]
    fn read_all_empty_for_unknown_recipient() {
        let b = TransitBuffer::new(Duration::from_secs(60), 10, usize::MAX);
        assert!(b.read_all(&AgentId::from_bytes([3u8; 32])).is_empty());
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
    fn delete_releases_byte_budget_so_new_enqueue_fits() {
        let payload = 600usize;
        let cap = ENVELOPE_FIXED_OVERHEAD + payload;
        let b = TransitBuffer::new(Duration::from_secs(60), 10, cap);
        let to = AgentId::from_bytes([7u8; 32]);

        let id = b.enqueue(to, env_with_bytes(1, payload)).unwrap();
        b.delete(&to, &[id]);
        assert_eq!(b.total_bytes(), 0, "delete must free its bytes");
        b.enqueue(to, env_with_bytes(2, payload))
            .expect("budget recovered after delete");
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
