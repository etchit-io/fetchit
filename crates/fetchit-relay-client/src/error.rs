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
}
