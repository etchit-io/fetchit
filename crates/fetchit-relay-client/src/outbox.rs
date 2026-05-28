//! Tracks pending sends until the matching `Ack` arrives.

use dashmap::DashMap;
use fetchit_relay_proto::DedupeKey;
use std::time::Instant;
use tokio::sync::oneshot;

/// Pending-send record awaiting an `Ack` from the relay.
pub struct PendingSend {
    /// One-shot the caller awaits.
    pub completion: oneshot::Sender<Receipt>,
    /// When the send was dispatched.
    pub sent_at: Instant,
}

/// What the caller of `Client::send` resolves with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Server-reported acceptance time, milliseconds since the Unix epoch.
    pub accepted_at_ms: u64,
}

/// Concurrent map of outbound dedupe keys → pending send records.
#[derive(Default)]
pub struct Outbox {
    by_dedupe: DashMap<DedupeKey, PendingSend>,
}

impl Outbox {
    /// Construct an empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh pending send; returns the `Receipt` future.
    #[must_use]
    pub fn track(&self, key: DedupeKey) -> oneshot::Receiver<Receipt> {
        let (tx, rx) = oneshot::channel();
        self.by_dedupe.insert(
            key,
            PendingSend {
                completion: tx,
                sent_at: Instant::now(),
            },
        );
        rx
    }

    /// Resolve a pending send with the relay's acceptance time.
    /// Returns `true` if a matching record was found.
    #[must_use]
    pub fn ack(&self, key: &DedupeKey, accepted_at_ms: u64) -> bool {
        let Some((_, pending)) = self.by_dedupe.remove(key) else {
            return false;
        };
        let _ = pending.completion.send(Receipt { accepted_at_ms });
        true
    }

    /// Number of sends currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.by_dedupe.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn track_then_ack_resolves_receipt() {
        let ob = Outbox::new();
        let key = DedupeKey::from_bytes([1u8; 16]);
        let rx = ob.track(key);
        assert!(ob.ack(&key, 1_700_000_000_000));
        let receipt = rx.await.unwrap();
        assert_eq!(receipt.accepted_at_ms, 1_700_000_000_000);
        assert_eq!(ob.in_flight(), 0);
    }

    #[tokio::test]
    async fn ack_for_unknown_key_returns_false() {
        let ob = Outbox::new();
        assert!(!ob.ack(&DedupeKey::from_bytes([2u8; 16]), 0));
    }
}
