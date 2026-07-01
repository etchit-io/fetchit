//! Client error type.

use thiserror::Error;

/// Errors surfaced by the relay client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// HTTP failure during auth handshake.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// URL was malformed.
    #[error("url: {0}")]
    Url(#[from] url::ParseError),

    /// IO failure on the underlying socket.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// WebSocket error.
    #[error("ws: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Proto encode / decode failure.
    #[error("proto: {0}")]
    Proto(#[from] fetchit_relay_proto::ProtoError),

    /// Relay rejected the auth verify call.
    #[error("auth rejected: {0}")]
    AuthRejected(String),

    /// The relay closed the WS unexpectedly.
    #[error("relay closed connection: {0}")]
    RelayClosed(String),

    /// Inbox channel was closed.
    #[error("inbox channel closed")]
    InboxClosed,

    /// A `send` was attempted while the supervisor had no live WS.
    /// Callers may wait for `Client::connection_state` to report
    /// `Connected` before retrying.
    #[error("client is disconnected: {0}")]
    Disconnected(String),

    /// A non-binary message was received where binary was expected.
    #[error("unexpected non-binary message")]
    UnexpectedMessage,

    /// The relay answered `Moved` instead of `Ack`: the deposit's
    /// recipient migrated away and the relay holds a live signed
    /// forwarding record for them. The caller should re-resolve the
    /// recipient's relays via that signed forwarding record and retry
    /// the deposit at the new relay.
    #[error("recipient moved away from this relay")]
    RecipientMoved,

    /// A `send` attempt exceeded its WS-write or ack timeout. Returned
    /// when the underlying TCP send buffer is wedged (write never
    /// completed) or when the relay accepted the bytes but never
    /// emitted an `Ack` frame within the timeout. Callers should
    /// treat this as "definitively did not send" so the UI can flip
    /// the bubble to a clear `failed` state.
    #[error("send timed out after {0:?}")]
    SendTimeout(std::time::Duration),
}

impl From<x0xd_client::X0xdError> for ClientError {
    fn from(e: x0xd_client::X0xdError) -> Self {
        match e {
            x0xd_client::X0xdError::Http(e) => Self::Http(e),
            x0xd_client::X0xdError::Url(e) => Self::Url(e),
            x0xd_client::X0xdError::Rejected(s) | x0xd_client::X0xdError::Invalid(s) => {
                // Caller-side validation failures and daemon refusals
                // share the AuthRejected surface here — relay-client
                // doesn't yet distinguish them and adding a new variant
                // would ripple into every consumer.
                Self::AuthRejected(s)
            }
        }
    }
}
