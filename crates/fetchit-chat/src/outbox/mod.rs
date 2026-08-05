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
    /// Inline image this DM carries, retained so a resend delivers the
    /// SAME message the user composed instead of a text-only degradation
    /// (for a caption-less photo, an empty one).
    ///
    /// `None` on a text-only DM, on a group fan-out copy (the wire payload
    /// there is the sealed `group.envelope`), on a bubble restored from a
    /// vault sealed before full-fidelity retry, and on a bubble whose
    /// bytes were released at a terminal state -- see
    /// [`Self::attachment_dropped`] and [`ATTACHMENT_BUBBLE_CAP`].
    ///
    /// While the bubble is [`SendState::Queued`] this is the ONLY durable
    /// copy of the image: a send that never succeeded persists no
    /// transcript entry, so nothing else on disk holds the bytes.
    #[serde(default)]
    pub attachment: Option<crate::attachment::Attachment>,
    /// Logical message id this DM is a reply to, retained for the same
    /// reason as [`Self::attachment`]: a resend that dropped it would
    /// deliver an unthreaded copy of a threaded message. `None` on a
    /// non-reply and on a group fan-out copy.
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    /// `true` when this bubble carried an attachment whose bytes the
    /// outbox has since released AND no transcript entry is known to hold
    /// them -- i.e. the message failed terminally, so it was never sent
    /// and never persisted. A shell renders it as an explicit "image not
    /// kept" affordance; the alternative is an empty bubble that silently
    /// lies about what the user sent.
    ///
    /// Deliberately NOT set when the bytes are released at
    /// [`SendState::Delivered`]: that message reached the recipient, so
    /// the send persisted a transcript entry carrying the image and the
    /// user loses nothing.
    #[serde(default)]
    pub attachment_dropped: bool,
}

/// How many superseded logical message ids a bubble remembers for receipt
/// matching. Bounds vault growth on a peer that never acks; eight covers
/// far more resends than a live peer needs.
pub const PRIOR_MESSAGE_ID_CAP: usize = 8;

/// How many attachment-bearing bubbles the outbox will retain at once.
///
/// The retention policy, in full. The outbox has no garbage collector: a
/// bubble lives until its peer's device is revoked, so anything stored on
/// one is stored forever. Attachments are up to
/// [`crate::attachment::MAX_ATTACHMENT_BYTES`] (256 `KiB`) raw each, so
/// retaining them unconditionally would turn a phone's chat vault into an
/// image store. Three rules keep it bounded, and none of them loses
/// content the user is not told about:
///
/// 1. **Bytes are released the moment they can no longer do work.** A
///    bubble that reaches [`SendState::Delivered`] is terminal and never
///    re-sent, and the send that earned the receipt persisted a transcript
///    entry carrying the image -- so its copy is dead weight and goes,
///    silently and safely. A bubble that reaches [`SendState::Failed`] is
///    also terminal (nothing ever retries it), but it never sent and so
///    never persisted a transcript entry -- its bytes go too, with
///    [`OutboxBubble::attachment_dropped`] set so the shell can say so.
/// 2. **What remains is capped.** Only [`SendState::Queued`] and
///    [`SendState::Sent`] bubbles hold bytes, at most this many. Because
///    each attachment is independently capped, the retained set is bounded
///    at `ATTACHMENT_BUBBLE_CAP * MAX_ATTACHMENT_BYTES` -- 4 `MiB` raw,
///    about 5.5 `MiB` as the base64 the vault seals.
/// 3. **The cap refuses, it never degrades.** Enqueueing an image past the
///    cap returns [`crate::ChatError::OutboxAttachmentsFull`] rather than
///    quietly sending the message without its picture. Rule 1 guarantees
///    the cap cannot wedge: every bubble that stops being sendable gives
///    its slot back.
///
/// Sixteen is far past any realistic backlog -- it takes sixteen photos
/// that have not yet been confirmed delivered to reach it -- while staying
/// a few megabytes rather than a few hundred.
pub const ATTACHMENT_BUBBLE_CAP: usize = 16;

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
            attachment: None,
            reply_to_message_id: None,
            attachment_dropped: false,
        }
    }

    /// Attach private-group fan-out context (builder form of
    /// [`Self::group`]).
    #[must_use]
    pub fn with_group(mut self, group: GroupOutbound) -> Self {
        self.group = Some(group);
        self
    }

    /// Attach the DM payload a retry must reproduce: the inline image and
    /// the reply anchor. Builder form of [`Self::attachment`] +
    /// [`Self::reply_to_message_id`], taken together because the one send
    /// path that supplies either supplies both.
    #[must_use]
    pub fn with_dm_payload(
        mut self,
        attachment: Option<crate::attachment::Attachment>,
        reply_to_message_id: Option<String>,
    ) -> Self {
        self.attachment = attachment;
        self.reply_to_message_id = reply_to_message_id;
        self
    }

    /// Release the retained attachment bytes, flagging the loss when this
    /// bubble may have been their last holder.
    ///
    /// Called only on a transition into a terminal state (see
    /// [`ATTACHMENT_BUBBLE_CAP`] rule 1). `last_holder` distinguishes the
    /// two terminal arms: a [`SendState::Failed`] bubble never sent, so
    /// nothing persisted its image and the shell must be told; a
    /// [`SendState::Delivered`] one did, so its transcript entry holds the
    /// image and there is nothing to announce.
    ///
    /// Idempotent, and a no-op on a bubble that never carried an image --
    /// so a text message can never be flagged as having lost a picture.
    pub(crate) fn release_attachment(&mut self, last_holder: bool) {
        if self.attachment.take().is_some() && last_holder {
            self.attachment_dropped = true;
        }
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

    fn image() -> crate::attachment::Attachment {
        crate::attachment::Attachment::from_raw("image/png", 32, 24, &[0xABu8; 1024]).unwrap()
    }

    #[test]
    fn a_bubble_round_trips_its_whole_dm_payload() {
        // The regression this guards: the durable record used to hold the
        // body alone, so everything else about the message evaporated the
        // moment the first attempt ended.
        let b =
            bubble(SendState::Queued, None).with_dm_payload(Some(image()), Some("m-parent".into()));
        let j = serde_json::to_vec(&b).unwrap();
        let back: OutboxBubble = serde_json::from_slice(&j).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.attachment.as_ref().unwrap().mime, "image/png");
        assert_eq!(
            back.attachment.unwrap().validate().unwrap(),
            vec![0xABu8; 1024],
            "the image bytes survive the vault round trip intact"
        );
        assert_eq!(back.reply_to_message_id.as_deref(), Some("m-parent"));
    }

    #[test]
    fn a_bubble_written_before_full_fidelity_retry_still_loads() {
        // Back-compat: a vault sealed by the shipping build has none of
        // the payload fields. It must load as a plain text bubble and stay
        // sendable -- a parse failure would drop every pending message.
        let legacy = serde_json::json!({
            "id": "b1",
            "peer": "aa".repeat(32),
            "body": "hi",
            "status": "Queued",
            "message_id": null,
            "enqueued_at_ms": 1_000,
            "state_changed_at_ms": 1_000,
            "prior_message_ids": [],
            "last_error": null,
        });
        let b: OutboxBubble = serde_json::from_value(legacy).unwrap();
        assert_eq!(b.body, "hi");
        assert!(b.attachment.is_none());
        assert!(b.reply_to_message_id.is_none());
        assert!(!b.attachment_dropped);
        assert!(is_retryable(&b), "a legacy bubble still sends");
    }

    #[test]
    fn release_attachment_flags_only_when_it_was_the_last_copy() {
        // Delivered: the send persisted a transcript entry holding the
        // image, so releasing the bytes loses nothing and says nothing.
        let mut delivered =
            bubble(SendState::Delivered, Some("m")).with_dm_payload(Some(image()), None);
        delivered.release_attachment(false);
        assert!(delivered.attachment.is_none());
        assert!(!delivered.attachment_dropped);

        // Failed: never sent, so nothing else holds the image and the
        // shell has to be able to say so.
        let mut failed = bubble(SendState::Failed, None).with_dm_payload(Some(image()), None);
        failed.release_attachment(true);
        assert!(failed.attachment.is_none());
        assert!(failed.attachment_dropped);

        // Idempotent, and a text message is never flagged as having lost
        // a picture it never had.
        let mut text = bubble(SendState::Failed, None);
        text.release_attachment(true);
        assert!(!text.attachment_dropped);
        failed.release_attachment(true);
        assert!(failed.attachment_dropped);
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
