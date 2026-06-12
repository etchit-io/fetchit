//! Tracks pending sends until the matching `Ack` arrives.
//!
//! The same struct doubles as the per-connection store of last-known
//! `Pong` receipt time so the keepalive task can detect a half-open
//! socket without sharing a separate state object.

use dashmap::DashMap;
use fetchit_relay_proto::DedupeKey;
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::oneshot;

/// Pending-send record awaiting an `Ack` (or `Moved`) from the relay.
pub struct PendingSend {
    /// One-shot the caller awaits.
    pub completion: oneshot::Sender<SendResolution>,
    /// When the send was dispatched.
    pub sent_at: Instant,
}

/// What the caller of `Client::send` resolves with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Server-reported acceptance time, milliseconds since the Unix epoch.
    pub accepted_at_ms: u64,
}

/// How the relay resolved a pending send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendResolution {
    /// The relay accepted the envelope into its routing buffer.
    Acked(Receipt),
    /// The relay answered `Moved`: the recipient migrated away and the
    /// relay holds a live signed forwarding record for them. The sender
    /// must re-resolve the recipient's relays via that signed record and
    /// retry the deposit at the new relay.
    RecipientMoved,
}

/// Concurrent map of outbound dedupe keys → pending send records.
pub struct Outbox {
    by_dedupe: DashMap<DedupeKey, PendingSend>,
    last_pong: Mutex<Instant>,
    last_pong_nonce: Mutex<Option<u64>>,
}

impl Default for Outbox {
    fn default() -> Self {
        Self {
            by_dedupe: DashMap::new(),
            last_pong: Mutex::new(Instant::now()),
            last_pong_nonce: Mutex::new(None),
        }
    }
}

impl Outbox {
    /// Construct an empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh pending send; returns the resolution future.
    #[must_use]
    pub fn track(&self, key: DedupeKey) -> oneshot::Receiver<SendResolution> {
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
        let _ = pending
            .completion
            .send(SendResolution::Acked(Receipt { accepted_at_ms }));
        true
    }

    /// Resolve a pending send as `Moved`: the relay reports the
    /// recipient migrated away (it holds a live signed forwarding record
    /// for them). Returns `true` if a matching record was found.
    #[must_use]
    pub fn moved(&self, key: &DedupeKey) -> bool {
        let Some((_, pending)) = self.by_dedupe.remove(key) else {
            return false;
        };
        let _ = pending.completion.send(SendResolution::RecipientMoved);
        true
    }

    /// Number of sends currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.by_dedupe.len()
    }

    /// Refresh the recorded `last_pong` to `Instant::now`. Called when
    /// the supervisor installs a new connection so the keepalive task
    /// doesn't immediately judge it dead.
    pub fn touch_pong(&self) {
        if let Ok(mut g) = self.last_pong.lock() {
            *g = Instant::now();
        }
    }

    /// Record that a `Pong` was received from the relay.
    pub fn record_pong(&self, nonce: u64) {
        if let Ok(mut g) = self.last_pong.lock() {
            *g = Instant::now();
        }
        if let Ok(mut g) = self.last_pong_nonce.lock() {
            *g = Some(nonce);
        }
    }

    /// Instant the most recent `Pong` was received (or the outbox was
    /// constructed / touched, whichever is later).
    #[must_use]
    pub fn last_pong(&self) -> Instant {
        self.last_pong
            .lock()
            .map_or_else(|_| Instant::now(), |g| *g)
    }

    /// Nonce from the most recently observed `Pong`, useful for tests
    /// and diagnostics.
    #[must_use]
    pub fn last_pong_nonce(&self) -> Option<u64> {
        self.last_pong_nonce.lock().ok().and_then(|g| *g)
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
        let resolution = rx.await.unwrap();
        assert_eq!(
            resolution,
            SendResolution::Acked(Receipt {
                accepted_at_ms: 1_700_000_000_000
            })
        );
        assert_eq!(ob.in_flight(), 0);
    }

    #[tokio::test]
    async fn track_then_moved_resolves_recipient_moved() {
        let ob = Outbox::new();
        let key = DedupeKey::from_bytes([3u8; 16]);
        let rx = ob.track(key);
        assert!(ob.moved(&key));
        assert_eq!(rx.await.unwrap(), SendResolution::RecipientMoved);
        assert_eq!(ob.in_flight(), 0);
    }

    #[tokio::test]
    async fn moved_for_unknown_key_returns_false() {
        let ob = Outbox::new();
        assert!(!ob.moved(&DedupeKey::from_bytes([4u8; 16])));
    }

    #[tokio::test]
    async fn ack_for_unknown_key_returns_false() {
        let ob = Outbox::new();
        assert!(!ob.ack(&DedupeKey::from_bytes([2u8; 16]), 0));
    }

    #[tokio::test]
    async fn record_pong_updates_last_pong_and_nonce() {
        let ob = Outbox::new();
        let before = ob.last_pong();
        // Sleep at least one OS tick so the clock visibly advances.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        ob.record_pong(0xfeed_face_dead_beef);
        let after = ob.last_pong();
        assert!(after > before);
        assert_eq!(ob.last_pong_nonce(), Some(0xfeed_face_dead_beef));
    }

    #[tokio::test]
    async fn touch_pong_resets_clock_to_now() {
        let ob = Outbox::new();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let before = ob.last_pong();
        ob.touch_pong();
        let after = ob.last_pong();
        assert!(after > before);
    }
}
