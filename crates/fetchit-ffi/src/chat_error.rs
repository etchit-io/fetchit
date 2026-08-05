//! Coarse, stable error surface for the FFI chat client. Mirrors the
//! shape of [`crate::error::FetchitError`]: few variants, a `reason`
//! string (named to avoid colliding with Kotlin's `Throwable.message`),
//! no nested causes.

/// Errors surfaced to Kotlin/Swift by the chat FFI.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ChatFfiError {
    /// Malformed input: bad URL, bad agent id, bad pair URI.
    #[error("invalid: {reason}")]
    Invalid {
        /// Human-readable cause.
        reason: String,
    },
    /// Relay or network failure (connect, publish, resolve, send).
    #[error("network: {reason}")]
    Network {
        /// Human-readable cause.
        reason: String,
    },
}

impl From<fetchit_chat::ChatError> for ChatFfiError {
    fn from(e: fetchit_chat::ChatError) -> Self {
        match e {
            fetchit_chat::ChatError::Invalid(reason) => Self::Invalid { reason },
            // A local refusal, not a network problem: the outbox is
            // already holding its cap of undelivered images. Mapping it to
            // Network would send the shell chasing connectivity for
            // something only the user can clear.
            other @ fetchit_chat::ChatError::OutboxAttachmentsFull { .. } => Self::Invalid {
                reason: other.to_string(),
            },
            other => Self::Network {
                reason: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn invalid_maps_to_invalid() {
        let err = ChatFfiError::from(fetchit_chat::ChatError::Invalid("bad input".into()));
        assert!(matches!(err, ChatFfiError::Invalid { reason } if reason == "bad input"));
    }

    #[test]
    fn transport_ish_maps_to_network() {
        let err = ChatFfiError::from(fetchit_chat::ChatError::NoTransportAvailable);
        assert!(
            matches!(err, ChatFfiError::Network { .. }),
            "expected Network variant"
        );
    }

    #[test]
    fn a_full_attachment_outbox_maps_to_invalid_not_network() {
        let err = ChatFfiError::from(fetchit_chat::ChatError::OutboxAttachmentsFull {
            retained: 16,
            cap: 16,
        });
        assert!(
            matches!(&err, ChatFfiError::Invalid { reason } if reason.contains("image slots")),
            "a local cap refusal must not read as a network failure: {err:?}",
        );
    }

    #[test]
    fn message_transport_maps_to_network() {
        let err = ChatFfiError::from(fetchit_chat::ChatError::MessageTransport(
            "dial failed".into(),
        ));
        assert!(matches!(err, ChatFfiError::Network { reason } if reason.contains("dial failed")));
    }
}
