//! Fold live outbox state onto a persisted transcript.
//!
//! A conversation's [`HistoryEntry`](crate::conversation::HistoryEntry)
//! records what was true when the entry was written; the outbox records
//! what is true now for every copy still in flight. A listing that showed
//! only the former would keep claiming "sent" for a group message whose
//! copies are back in the queue after a relay outage.
//!
//! [`overlay_history_send_state`] reconciles the two the only honest way:
//! a message is as far along as its LEAST advanced copy.

use super::{OutboxBubble, SendState};
use crate::conversation::HistoryEntry;
use std::collections::HashMap;

/// Reconcile each entry's persisted send state with every outbox bubble
/// that belongs to it.
///
/// A bubble belongs to an entry when it carries the entry's `message_id`
/// -- as the DM bubble's own id (current or superseded) or as a group
/// fan-out copy's `client_message_id`. Entries with no live bubble are
/// left exactly as persisted, so an inbound entry (which has no send
/// state at all) is never given one.
///
/// Two rules, in order:
/// 1. A delivery receipt is proof of arrival. If either view says
///    [`SendState::Delivered`], the message was delivered -- and since a
///    group fan-out copy never gets a receipt, only a DM can reach here.
/// 2. Otherwise the message is as far along as its LEAST advanced copy,
///    so one group copy back in the queue pulls the whole message back to
///    [`SendState::Queued`].
///
/// The transition timestamp moves with the state: an entry pulled back to
/// `Queued` reports the moment its copy re-entered the queue, which is
/// what a "still sending" affordance measures.
pub fn overlay_history_send_state(entries: &mut [HistoryEntry], bubbles: &[OutboxBubble]) {
    if bubbles.is_empty() {
        return;
    }
    // message_id -> (least advanced live copy, receipt time if any copy
    // was delivered).
    let mut live: HashMap<&str, ((SendState, u64), Option<u64>)> = HashMap::new();
    for bubble in bubbles {
        let anchors = bubble
            .group
            .as_ref()
            .map(|g| g.client_message_id.as_str())
            .into_iter()
            .chain(bubble.message_id.as_deref())
            .chain(bubble.prior_message_ids.iter().map(String::as_str));
        let candidate = (bubble.status, bubble.state_changed_at_ms);
        let delivered_at =
            (bubble.status == SendState::Delivered).then_some(bubble.state_changed_at_ms);
        for anchor in anchors {
            if anchor.is_empty() {
                continue;
            }
            let slot = live.entry(anchor).or_insert((candidate, delivered_at));
            if candidate.0 < slot.0 .0 {
                slot.0 = candidate;
            }
            slot.1 = slot.1.or(delivered_at);
        }
    }
    for entry in entries {
        let Some((lowest, delivered_at)) = live.get(entry.message_id.as_str()) else {
            continue;
        };
        let persisted = entry.send_progress();
        let (state, changed_at_ms) = if persisted.state == SendState::Delivered {
            (persisted.state, persisted.changed_at_ms)
        } else if let Some(at) = *delivered_at {
            (SendState::Delivered, at)
        } else if lowest.0 < persisted.state {
            *lowest
        } else {
            // Keep the persisted verdict, but make it explicit so a
            // listing never has to re-derive it from `delivered_at_ms`.
            (persisted.state, persisted.changed_at_ms)
        };
        entry.send_state = Some(state);
        entry.state_changed_at_ms = changed_at_ms;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::AgentId;
    use crate::outbox::GroupOutbound;

    fn entry(message_id: &str, state: Option<SendState>, at_ms: u64) -> HistoryEntry {
        HistoryEntry {
            sender_agent_id_hex: "aa".repeat(32),
            sender_name: None,
            body: "hi".into(),
            ts_ms: 1,
            message_id: message_id.into(),
            attachment: None,
            delivered_at_ms: None,
            send_state: state,
            state_changed_at_ms: at_ms,
        }
    }

    fn bubble(id: &str, message_id: Option<&str>, state: SendState, at_ms: u64) -> OutboxBubble {
        OutboxBubble {
            status: state,
            message_id: message_id.map(Into::into),
            state_changed_at_ms: at_ms,
            ..OutboxBubble::queued(id.into(), AgentId("bb".repeat(32)), "hi".into(), 0)
        }
    }

    fn group_copy(id: &str, anchor: &str, state: SendState, at_ms: u64) -> OutboxBubble {
        bubble(id, None, state, at_ms).with_group(GroupOutbound {
            group_id: "cc".repeat(32),
            envelope: vec![1],
            client_message_id: anchor.into(),
        })
    }

    #[test]
    fn a_requeued_copy_pulls_the_message_back_to_queued() {
        // The persisted entry says Sent; one group copy is back in the
        // queue after a relay outage. The message has NOT fully made it.
        let mut entries = [entry("m1", Some(SendState::Sent), 10)];
        let bubbles = [
            group_copy("g1", "m1", SendState::Sent, 20),
            group_copy("g2", "m1", SendState::Queued, 30),
        ];
        overlay_history_send_state(&mut entries, &bubbles);
        assert_eq!(entries[0].send_state, Some(SendState::Queued));
        assert_eq!(entries[0].state_changed_at_ms, 30);
    }

    #[test]
    fn a_receipt_is_proof_of_arrival_from_either_view() {
        // Persisted Delivered, bubble left behind at Sent: the receipt
        // wins, the message arrived.
        let mut entries = [entry("m1", Some(SendState::Delivered), 10)];
        overlay_history_send_state(
            &mut entries,
            &[bubble("b1", Some("m1"), SendState::Sent, 4)],
        );
        assert_eq!(entries[0].send_state, Some(SendState::Delivered));
        assert_eq!(entries[0].state_changed_at_ms, 10);
        // And the other way round: the bubble caught the receipt, the
        // persisted entry did not.
        let mut entries = [entry("m1", Some(SendState::Sent), 10)];
        overlay_history_send_state(
            &mut entries,
            &[bubble("b1", Some("m1"), SendState::Delivered, 88)],
        );
        assert_eq!(entries[0].send_state, Some(SendState::Delivered));
        assert_eq!(entries[0].state_changed_at_ms, 88);
    }

    #[test]
    fn a_terminal_failure_surfaces_on_the_message() {
        let mut entries = [entry("m1", Some(SendState::Sent), 10)];
        let bubbles = [bubble("b1", Some("m1"), SendState::Failed, 55)];
        overlay_history_send_state(&mut entries, &bubbles);
        assert_eq!(entries[0].send_state, Some(SendState::Failed));
        assert_eq!(entries[0].state_changed_at_ms, 55);
    }

    #[test]
    fn a_superseded_id_still_matches_its_message() {
        let mut entries = [entry("m1", Some(SendState::Sent), 10)];
        let mut b = bubble("b1", Some("m2"), SendState::Queued, 60);
        b.prior_message_ids = vec!["m1".into()];
        overlay_history_send_state(&mut entries, &[b]);
        assert_eq!(entries[0].send_state, Some(SendState::Queued));
    }

    #[test]
    fn entries_with_no_live_bubble_are_untouched() {
        // Including inbound entries, which carry no send state at all and
        // must never be given one.
        let mut entries = [
            entry("inbound", None, 0),
            entry("m1", Some(SendState::Sent), 9),
        ];
        overlay_history_send_state(
            &mut entries,
            &[bubble("b1", Some("other"), SendState::Queued, 1)],
        );
        assert_eq!(entries[0].send_state, None);
        assert_eq!(entries[1].send_state, Some(SendState::Sent));
    }

    #[test]
    fn no_bubbles_is_a_no_op() {
        let mut entries = [entry("m1", None, 0)];
        overlay_history_send_state(&mut entries, &[]);
        assert_eq!(entries[0].send_state, None);
    }

    #[test]
    fn a_legacy_entry_gets_its_derived_state_made_explicit() {
        // Pre-send-state-truth entries carry no state; the derived reading
        // (a receipt landed => Delivered) is written through so a listing
        // never has to re-derive it.
        let mut e = entry("m1", None, 0);
        e.delivered_at_ms = Some(77);
        let mut entries = [e];
        overlay_history_send_state(
            &mut entries,
            &[bubble("b1", Some("m1"), SendState::Sent, 5)],
        );
        assert_eq!(entries[0].send_state, Some(SendState::Delivered));
        assert_eq!(entries[0].state_changed_at_ms, 77);
        // A legacy entry with no receipt derives Sent (it was only ever
        // persisted after acceptance), and a queued copy pulls it back.
        let mut entries = [entry("m2", None, 0)];
        overlay_history_send_state(
            &mut entries,
            &[bubble("b2", Some("m2"), SendState::Queued, 6)],
        );
        assert_eq!(entries[0].send_state, Some(SendState::Queued));
    }
}
