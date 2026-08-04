//! What the sender actually knows about one outbound message.
//!
//! The rule this module exists to enforce: the user is never told a
//! message made it when it did not, and never told it failed when it is
//! still being retried. Every outbound message carries a [`SendState`]
//! plus the Unix-ms it last changed ([`SendProgress`]), persisted so the
//! answer survives a restart.
//!
//! Only two things move a message forward: a relay acking acceptance
//! (`Queued` -> `Sent`) and a delivery receipt (`-> Delivered`).
//! [`SendState::Failed`] is reserved for outcomes no retry can improve,
//! classified by [`SendFailure::classify`].

use crate::error::ChatError;
use serde::{Deserialize, Serialize};

/// How far one outbound message actually got.
///
/// Variant order is load-bearing: [`Ord`] reads as "how far it got", so a
/// message fanned out as several copies is only as far along as its LEAST
/// advanced copy (`min`) -- including a terminally failed one, because a
/// message that reached some recipients and can never reach another has
/// not made it.
///
/// # At rest
///
/// Serializes under these exact variant names; vaults sealed before the
/// send-state machine landed carry `"Sending"`, which loads as
/// [`SendState::Queued`] (the honest reading: no relay ack was recorded).
/// A legacy `"Failed"` also means "retry me", so the outbox re-queues it
/// on load -- see `outbox::store::OutboxStore::load`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SendState {
    /// Terminal. The send can never succeed, so retrying is pointless and
    /// the user must be told. Only [`SendFailure::terminal`] outcomes
    /// reach this state; anything a later attempt could fix stays
    /// [`SendState::Queued`].
    Failed,
    /// In the durable outbox, not yet accepted by any relay. Retried
    /// indefinitely by the outbox driver. A dropped socket, a lost ack, a
    /// dead relay -- all of them leave a message here, never in
    /// [`SendState::Failed`].
    #[serde(alias = "Sending")]
    Queued,
    /// A relay acked acceptance, so the message is in durable transit.
    /// The ONLY transition into this state is that ack.
    Sent,
    /// A delivery receipt attributed receipt to the recipient.
    Delivered,
}

impl SendState {
    /// Has a relay taken durable custody of this message?
    #[must_use]
    pub const fn reached_relay(self) -> bool {
        matches!(self, Self::Sent | Self::Delivered)
    }

    /// Is this state terminal (no further transition is possible)?
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Failed)
    }
}

/// A [`SendState`] plus the Unix-ms at which it was entered.
///
/// Shells render the pair: the state picks the tick, and the age of
/// `changed_at_ms` is what lets a UI distinguish "sending" from "still
/// sending after ten minutes" without the engine inventing a threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendProgress {
    /// How far the message got.
    pub state: SendState,
    /// Unix-ms of the last transition into `state`.
    pub changed_at_ms: u64,
}

/// A failed send attempt, classified for the state machine.
///
/// `terminal` is the whole point: it decides whether the bubble may be
/// declared [`SendState::Failed`] or must stay [`SendState::Queued`] and
/// keep retrying. When in doubt the classifier keeps retrying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendFailure {
    /// Human-readable reason, surfaced as the bubble's `last_error`.
    pub reason: String,
    /// `true` only when no future attempt could ever succeed.
    pub terminal: bool,
}

impl SendFailure {
    /// Classify a typed send error.
    ///
    /// Terminal outcomes, exhaustively:
    /// - [`ChatError::Denied`] / [`ChatError::DeniedActor`] -- the engine
    ///   refuses to address a denylisted recipient; the verdict is local
    ///   policy, identical on every retry.
    /// - [`ChatError::SealedRequired`] -- a caller handed the transport an
    ///   unsealed envelope; a programming error, not a network condition.
    ///
    /// Everything else -- no transport, all relays unreachable, transport
    /// and websocket errors, a missing contact card, a daemon hiccup --
    /// is retryable: a later attempt can genuinely succeed, so the message
    /// stays queued rather than lying about failure.
    #[must_use]
    pub fn classify(error: &ChatError) -> Self {
        Self {
            reason: error.to_string(),
            terminal: matches!(
                error,
                ChatError::Denied { .. }
                    | ChatError::DeniedActor { .. }
                    | ChatError::SealedRequired { .. }
            ),
        }
    }

    /// A non-terminal failure from a bare reason string, for callers with
    /// no typed error to classify.
    #[must_use]
    pub fn retryable(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            terminal: false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn order_reads_as_how_far_the_message_got() {
        assert!(SendState::Failed < SendState::Queued);
        assert!(SendState::Queued < SendState::Sent);
        assert!(SendState::Sent < SendState::Delivered);
        // A fan-out is only as far along as its least advanced copy.
        assert_eq!(
            [SendState::Delivered, SendState::Queued, SendState::Sent]
                .into_iter()
                .min(),
            Some(SendState::Queued)
        );
    }

    #[test]
    fn legacy_sending_loads_as_queued() {
        // Vaults sealed before send-state truth carry "Sending"; it must
        // come back as Queued (no relay ack was ever recorded) rather than
        // failing the whole outbox parse.
        assert_eq!(
            serde_json::from_str::<SendState>("\"Sending\"").unwrap(),
            SendState::Queued
        );
        // And the new names round-trip verbatim.
        for state in [
            SendState::Queued,
            SendState::Sent,
            SendState::Delivered,
            SendState::Failed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(serde_json::from_str::<SendState>(&json).unwrap(), state);
        }
    }

    #[test]
    fn only_denial_and_sealed_required_are_terminal() {
        let terminal = [
            ChatError::Denied {
                agent_id_hex: "aa".repeat(32),
            },
            ChatError::DeniedActor {
                actor_url: "https://example.test/actor".into(),
            },
            ChatError::SealedRequired {
                caller: "RelayTransport::send",
            },
        ];
        for e in &terminal {
            assert!(SendFailure::classify(e).terminal, "{e} must be terminal");
        }
        let retryable = [
            ChatError::NoTransportAvailable,
            ChatError::AllRelaysUnreachable {
                recipient: "bb".repeat(32),
            },
            ChatError::MessageTransport("relay send: socket closed".into()),
            ChatError::WebSocket("connection reset".into()),
            ChatError::Invalid("no stored card for recipient".into()),
        ];
        for e in &retryable {
            assert!(
                !SendFailure::classify(e).terminal,
                "{e} must keep retrying, not be declared failed"
            );
        }
    }

    #[test]
    fn classify_keeps_the_reason_and_retryable_is_never_terminal() {
        let e = ChatError::MessageTransport("relay send: eof".into());
        let f = SendFailure::classify(&e);
        assert_eq!(f.reason, e.to_string());
        assert!(!SendFailure::retryable("socket dropped").terminal);
    }

    #[test]
    fn reached_relay_and_is_terminal_matrix() {
        assert!(!SendState::Queued.reached_relay());
        assert!(SendState::Sent.reached_relay());
        assert!(SendState::Delivered.reached_relay());
        assert!(!SendState::Failed.reached_relay());
        assert!(!SendState::Queued.is_terminal());
        assert!(!SendState::Sent.is_terminal());
        assert!(SendState::Delivered.is_terminal());
        assert!(SendState::Failed.is_terminal());
    }
}
