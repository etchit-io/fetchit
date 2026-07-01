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
    fn message_transport_maps_to_network() {
        let err = ChatFfiError::from(fetchit_chat::ChatError::MessageTransport(
            "dial failed".into(),
        ));
        assert!(matches!(err, ChatFfiError::Network { reason } if reason.contains("dial failed")));
    }
}
