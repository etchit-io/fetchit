//! Engine-owned outbound-DM outbox: pending bubbles, the retry policy, and
//! a presence-driven retry loop. Lifts the resend/durability semantics out
//! of desktop's `outboxDriver.ts` so desktop and Android share one
//! implementation.
//!
//! - [`OutboxBubble`]: one outbound message copy, carrying the
//!   [`SendState`] the user is shown.
//! - [`is_retryable`]: the pure retry-eligibility rule.
//! - `store::OutboxStore`: vault-persisted bubble map.
//! - `driver::OutboxDriver`: the presence-driven retry loop.
//! - `overlay::overlay_history_send_state`: folds live bubble state onto a
//!   persisted transcript so a listing never over-reports a send.

use crate::identity::AgentId;
pub use crate::send_state::SendState;
use serde::{Deserialize, Serialize};

pub mod driver;
pub mod overlay;
pub mod store;

/// Unix-ms now, saturating rather than panicking on a broken clock.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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
    /// The sender's own client message id (the UI bubble anchor minted by
    /// `send_private_group`, NOT the relay dedupe key). Carried so the shell
    /// can correlate this per-member bubble reaching `Delivered` back to the
    /// ONE group message it belongs to, and flip that message's delivery tick
    /// from "queued" to "sent". Every fan-out copy of the same message shares
    /// this id.
    #[serde(default)]
    pub client_message_id: String,
}

/// One outbound message, tracked from enqueue through delivery.
///
/// `message_id` carries the logical message id the send was accepted
/// under, set once a relay acks (`Some` from [`SendState::Sent`] on);
/// delivery receipts echo it back. A DM leaves `group` `None` and
/// re-encrypts `body` per send; a private group fan-out copy sets `group`
/// and re-sends its sealed frame verbatim (see [`GroupOutbound`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxBubble {
    /// Client-assigned bubble id (stable across retries).
    pub id: String,
    /// Recipient agent (for a group bubble, the single fan-out member).
    pub peer: AgentId,
    /// Plaintext body (the UI echo; the wire payload for a group bubble is
    /// the sealed `group.envelope`, not this).
    pub body: String,
    /// What the sender actually knows about this copy.
    pub status: SendState,
    /// Logical message id of the most recent accepted send, set once a
    /// relay acks. Delivery receipts are matched against it (and against
    /// [`Self::prior_message_ids`]).
    pub message_id: Option<String>,
    /// Unix epoch ms when first enqueued.
    pub enqueued_at_ms: u64,
    /// Unix-ms of the last [`SendState`] transition -- the age a shell
    /// reads to distinguish "sending" from "still sending". Zero on
    /// bubbles restored from a vault sealed before send-state truth
    /// (`#[serde(default)]`), which the store's load migration re-stamps.
    #[serde(default)]
    pub state_changed_at_ms: u64,
    /// Logical message ids earlier accepted sends of THIS bubble used,
    /// newest last, capped at [`PRIOR_MESSAGE_ID_CAP`].
    ///
    /// A DM resend re-encrypts the body and mints a fresh logical message
    /// id, so without this a receipt for an earlier copy would match
    /// nothing and a delivered message would sit on `Sent` forever.
    #[serde(default)]
    pub prior_message_ids: Vec<String>,
    /// Last send error, whatever the current state: populated on a
    /// terminal [`SendState::Failed`] AND on a retryable failure that
    /// left the bubble [`SendState::Queued`], where it is diagnostics
    /// rather than a verdict.
    pub last_error: Option<String>,
    /// Private-group fan-out context; `None` for a DM. Additive so vaults
    /// sealed before group durability landed load with `None`.
    #[serde(default)]
    pub group: Option<GroupOutbound>,
}

/// How many superseded logical message ids a bubble remembers for receipt
/// matching. Bounds vault growth on a peer that never acks; eight covers
/// far more resends than a live peer needs.
pub const PRIOR_MESSAGE_ID_CAP: usize = 8;

impl OutboxBubble {
    /// A fresh [`SendState::Queued`] bubble for `peer`, enqueued at
    /// `now_ms`. The one constructor every send path uses so a bubble can
    /// never start life claiming more than "queued".
    #[must_use]
    pub fn queued(id: String, peer: AgentId, body: String, now_ms: u64) -> Self {
        Self {
            id,
            peer,
            body,
            status: SendState::Queued,
            message_id: None,
            enqueued_at_ms: now_ms,
            state_changed_at_ms: now_ms,
            prior_message_ids: Vec::new(),
            last_error: None,
            group: None,
        }
    }

    /// Attach private-group fan-out context (builder form of
    /// [`Self::group`]).
    #[must_use]
    pub fn with_group(mut self, group: GroupOutbound) -> Self {
        self.group = Some(group);
        self
    }

    /// Does a delivery receipt for `message_id` belong to this bubble?
    /// Matches the current id and every superseded one, so a receipt for
    /// a copy an earlier attempt sent still lands.
    #[must_use]
    pub fn matches_receipt(&self, message_id: &str) -> bool {
        self.message_id.as_deref() == Some(message_id)
            || self.prior_message_ids.iter().any(|id| id == message_id)
    }
}

/// A single outbox change broadcast to shells (upsert by `bubble.id`).
#[derive(Clone, Debug)]
pub struct OutboxEvent {
    /// The bubble's current state.
    pub bubble: OutboxBubble,
}

/// Whether `bubble` is eligible for an automatic resend.
///
/// - [`SendState::Queued`]: always. No relay ever took custody, so the
///   only way the message arrives is another attempt. The in-flight claim
///   (`OutboxStore::try_mark_inflight`), not the state, is what stops a
///   send in progress from being fired twice.
/// - [`SendState::Sent`]: a DM keeps retrying until its delivery receipt
///   lands -- relay acceptance is not receipt, and a wedged peer that
///   never decrypts is exactly the case this exists for. A private-group
///   fan-out copy does NOT: it re-sends one sealed `TreeKEM` frame that
///   the receiver would show twice, and no per-member receipt exists to
///   ever close it.
/// - [`SendState::Delivered`] / [`SendState::Failed`]: terminal.
#[must_use]
pub fn is_retryable(bubble: &OutboxBubble) -> bool {
    match bubble.status {
        SendState::Queued => true,
        SendState::Sent => bubble.group.is_none(),
        SendState::Delivered | SendState::Failed => false,
    }
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

    fn bubble(status: SendState, message_id: Option<&str>) -> OutboxBubble {
        OutboxBubble {
            status,
            message_id: message_id.map(Into::into),
            ..OutboxBubble::queued("b1".into(), AgentId("aa".repeat(32)), "hi".into(), 1_000)
        }
    }

    fn group_bubble(status: SendState) -> OutboxBubble {
        bubble(status, Some("m")).with_group(GroupOutbound {
            group_id: "aa".repeat(32),
            envelope: vec![1, 2, 3],
            client_message_id: "cm-1".into(),
        })
    }

    #[test]
    fn bubble_serde_round_trips() {
        let mut b = bubble(SendState::Sent, Some("m1"));
        b.prior_message_ids = vec!["m0".into()];
        let j = serde_json::to_vec(&b).unwrap();
        assert_eq!(serde_json::from_slice::<OutboxBubble>(&j).unwrap(), b);
    }

    #[test]
    fn legacy_bubble_json_loads_without_the_new_fields() {
        // A vault sealed before send-state truth: "Sending" status, no
        // state stamp, no prior ids. It must load (a parse failure would
        // drop every pending send) as Queued.
        let legacy = serde_json::json!({
            "id": "b1",
            "peer": "aa".repeat(32),
            "body": "hi",
            "status": "Sending",
            "message_id": null,
            "enqueued_at_ms": 1_000,
            "last_error": null,
        });
        let b: OutboxBubble = serde_json::from_value(legacy).unwrap();
        assert_eq!(b.status, SendState::Queued);
        assert_eq!(b.state_changed_at_ms, 0);
        assert!(b.prior_message_ids.is_empty());
    }

    #[test]
    fn queued_constructor_starts_at_queued() {
        let b = OutboxBubble::queued("b1".into(), AgentId("aa".repeat(32)), "hi".into(), 42);
        assert_eq!(b.status, SendState::Queued);
        assert_eq!(b.state_changed_at_ms, 42);
        assert!(b.message_id.is_none());
    }

    #[test]
    fn is_retryable_matrix() {
        // Queued retries whether or not an id was ever assigned.
        assert!(is_retryable(&bubble(SendState::Queued, None)));
        assert!(is_retryable(&bubble(SendState::Queued, Some("m"))));
        // A relay-accepted DM keeps retrying until its receipt lands.
        assert!(is_retryable(&bubble(SendState::Sent, Some("m"))));
        // A relay-accepted group copy never re-fires (it would duplicate).
        assert!(!is_retryable(&group_bubble(SendState::Sent)));
        assert!(is_retryable(&group_bubble(SendState::Queued)));
        // Terminal states never retry.
        assert!(!is_retryable(&bubble(SendState::Delivered, Some("m"))));
        assert!(!is_retryable(&bubble(SendState::Failed, None)));
    }

    #[test]
    fn matches_receipt_covers_superseded_ids() {
        let mut b = bubble(SendState::Sent, Some("m2"));
        b.prior_message_ids = vec!["m0".into(), "m1".into()];
        assert!(b.matches_receipt("m2"));
        // A receipt for the copy the FIRST attempt sent still lands: the
        // resend minted a new id, the message still arrived.
        assert!(b.matches_receipt("m0"));
        assert!(!b.matches_receipt("nope"));
    }
}
