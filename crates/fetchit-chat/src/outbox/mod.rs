//! Engine-owned outbound-DM outbox: pending bubbles, the retry policy, and
//! a presence-driven retry loop. Lifts the resend/durability semantics out
//! of desktop's `outboxDriver.ts` so desktop and Android share one
//! implementation.
//!
//! - [`OutboxBubble`] + [`OutboxStatus`]: per-send state.
//! - [`is_retryable`]: the pure retry-eligibility rule.
//! - `store::OutboxStore`: vault-persisted bubble map.
//! - `driver::OutboxDriver`: the presence-driven retry loop.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};

pub mod driver;
pub mod store;

/// Delivery state of a single outbound DM bubble.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboxStatus {
    /// Send attempted, not yet confirmed delivered.
    Sending,
    /// Recipient acknowledged delivery.
    Delivered,
    /// The attempt errored or timed out; eligible for retry.
    Failed,
}

/// Group-send context attached to a bubble that carries one fan-out copy of
/// an MLS-sealed private-group message.
///
/// A bubble's `group` is `None` for a DM (whose plaintext `body` is
/// re-encrypted on every send) and `Some` for a per-member group fan-out
/// copy. The already-sealed `envelope` is re-sent **verbatim** on retry:
/// x0xd's `TreeKEM` seal ratchets, so re-sealing the same plaintext would mint
/// a distinct frame -- a duplicate at the receiver and a wasted epoch step.
/// Storing the sealed bytes is what lets a group send survive the sender
/// being offline and flush intact on reconnect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupOutbound {
    /// Daemon-side group id, hex-encoded (the receiver's conversation key).
    pub group_id: String,
    /// The sealed transit envelope, postcard-encoded, re-sent byte-for-byte
    /// on every retry.
    ///
    /// Stored as postcard bytes -- the wire format -- rather than a typed
    /// `TransitEnvelope` because the vault seals bubbles with `serde_json`,
    /// and `EnvelopeKind`'s serde impl is postcard-only (it serializes the
    /// variant index, which `serde_json` cannot round-trip). A `Vec<u8>`
    /// round-trips through any format; the transport decodes it back with
    /// `postcard::from_bytes` just before the send.
    pub envelope: Vec<u8>,
}

/// One outbound message, tracked from enqueue through delivery.
///
/// `message_id` carries the relay's dedupe-key hex once the initial send
/// is acked (`Some`); a `Sending` bubble with `None` is still in flight
/// and must not be re-fired (double-send guard -- see [`is_retryable`]).
/// A DM leaves `group` `None` and re-encrypts `body` per send; a private
/// group fan-out copy sets `group` and re-sends its sealed frame verbatim
/// (see [`GroupOutbound`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxBubble {
    /// Client-assigned bubble id (stable across retries).
    pub id: String,
    /// Recipient agent (for a group bubble, the single fan-out member).
    pub peer: AgentId,
    /// Plaintext body (the UI echo; the wire payload for a group bubble is
    /// the sealed `group.envelope`, not this).
    pub body: String,
    /// Delivery state.
    pub status: OutboxStatus,
    /// Relay dedupe-key hex, set once the first send is acked.
    pub message_id: Option<String>,
    /// Unix epoch ms when first enqueued.
    pub enqueued_at_ms: u64,
    /// Last send error, populated on [`OutboxStatus::Failed`].
    pub last_error: Option<String>,
    /// Private-group fan-out context; `None` for a DM. Additive so vaults
    /// sealed before group durability landed load with `None`.
    #[serde(default)]
    pub group: Option<GroupOutbound>,
}

/// A single outbox change broadcast to shells (upsert by `bubble.id`).
#[derive(Clone, Debug)]
pub struct OutboxEvent {
    /// The bubble's current state.
    pub bubble: OutboxBubble,
}

/// Whether `bubble` is eligible for an automatic resend.
///
/// Eligible when the previous attempt `Failed`, or it is still `Sending`
/// but the relay already assigned a `message_id` (the initial ACK landed,
/// so re-firing is safe). A `Sending` bubble with no `message_id` is still
/// in flight -- re-firing would double-send.
#[must_use]
pub fn is_retryable(bubble: &OutboxBubble) -> bool {
    matches!(bubble.status, OutboxStatus::Failed)
        || (matches!(bubble.status, OutboxStatus::Sending) && bubble.message_id.is_some())
}

/// A fresh client-assigned bubble id: 128 bits of randomness, hex-encoded.
/// Stable across retries and distinct from the relay's `message_id` (which
/// is only known once the first send is acked). Mirrors
/// `messages::random_message_id`.
pub(crate) fn new_bubble_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn bubble(status: OutboxStatus, message_id: Option<&str>) -> OutboxBubble {
        OutboxBubble {
            id: "b1".into(),
            peer: AgentId("aa".repeat(32)),
            body: "hi".into(),
            status,
            message_id: message_id.map(Into::into),
            enqueued_at_ms: 1_000,
            last_error: None,
            group: None,
        }
    }

    #[test]
    fn bubble_serde_round_trips() {
        let b = bubble(OutboxStatus::Sending, Some("m1"));
        let j = serde_json::to_vec(&b).unwrap();
        assert_eq!(serde_json::from_slice::<OutboxBubble>(&j).unwrap(), b);
    }

    #[test]
    fn is_retryable_matrix() {
        assert!(is_retryable(&bubble(OutboxStatus::Failed, None)));
        assert!(is_retryable(&bubble(OutboxStatus::Sending, Some("m"))));
        assert!(!is_retryable(&bubble(OutboxStatus::Sending, None)));
        assert!(!is_retryable(&bubble(OutboxStatus::Delivered, Some("m"))));
    }
}
