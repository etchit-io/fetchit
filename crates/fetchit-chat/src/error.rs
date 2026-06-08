//! Typed error surface for chat-client operations.

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ChatError>;

/// All failure modes the client can surface.
#[derive(Debug, Error)]
pub enum ChatError {
    /// The daemon's data directory or auth token was not discoverable.
    #[error("x0xd not discoverable: {0}")]
    NotDiscoverable(String),

    /// HTTP transport / connection error.
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// WebSocket connection or framing error.
    #[error("websocket: {0}")]
    WebSocket(String),

    /// The daemon returned a non-success status with a body.
    #[error("daemon returned {status}: {body}")]
    Daemon {
        /// HTTP status code.
        status: u16,
        /// Response body, truncated for log safety.
        body: String,
    },

    /// JSON serialization / deserialization mismatch.
    #[error("decode: {0}")]
    Decode(#[from] serde_json::Error),

    /// Malformed input (bad agent id, malformed card, etc.).
    #[error("invalid input: {0}")]
    Invalid(String),

    /// I/O error reading discovery files.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// No message transport could reach the recipient.
    #[error("no transport available for recipient")]
    NoTransportAvailable,

    /// A message-transport operation failed.
    #[error("message transport: {0}")]
    MessageTransport(String),

    /// The local chat identity vault is missing or hasn't been
    /// bootstrapped. Call `Client::ensure_identity` or pass the right
    /// passphrase.
    #[error("chat identity not initialised at {path}")]
    IdentityNotInitialised {
        /// Where the identity vault was looked up.
        path: String,
    },

    /// Caller invoked a transport's `send` without supplying a
    /// prebuilt sealed envelope. After M2, the v1 fabricated path is
    /// gone — every send must go through the conversation/group
    /// layer that produces a sealed `TransitEnvelope`. The `caller`
    /// field names the specific transport surface that refused the
    /// unsealed envelope so a misbehaving caller can be pinpointed
    /// from a log line.
    #[error("sealed envelope required: {caller} did not supply a prebuilt sealed envelope")]
    SealedRequired {
        /// Descriptive name of the transport surface that rejected
        /// the unsealed envelope, e.g. `"RelayTransport::send"`.
        caller: &'static str,
    },

    /// The M2.5 bridge needs a stored share-card for the recipient so
    /// it can pull their ML-KEM-768 public key for the seal. When the
    /// card hasn't been imported (peer has never been DM-paired with
    /// this device), surface this typed error so the desktop UI can
    /// route to "Import their contact card first" instead of a
    /// generic invalid-input toast.
    #[error("no stored share-card for {agent_id_short} — exchange contact cards before adding them to a private group")]
    ShareCardMissing {
        /// Short prefix of the recipient's agent id (hex) for the
        /// user-visible message. Truncated to keep log lines tractable.
        agent_id_short: String,
    },

    /// The M2.5 bridge needs per-group consent (default-OFF per Q4)
    /// before it will relay-mediate a metadata event, and the user has
    /// never been asked for this group. The desktop UI catches this and
    /// surfaces the consent modal; on opt-in the call is re-issued.
    #[error("bridge consent not yet requested for group {group_id} — desktop UI surfaces the consent modal")]
    BridgeNeedsConsent {
        /// Group id whose consent hasn't been resolved.
        group_id: String,
    },

    /// The user previously declined bridging for this group. Drop the
    /// event and surface "group unreachable" in the chat UI.
    #[error("bridge declined for group {group_id} — metadata event dropped, peer unreachable via direct gossip")]
    BridgeDeclined {
        /// Group id whose consent is `DeclinedOptOut`.
        group_id: String,
    },

    /// M3 federation core: the addressed recipient is on the
    /// community-maintained denylist. The chat layer refuses outbound
    /// DM sends to blocked peers — UI surfaces "this contact is on
    /// the community denylist" so the user understands why the send
    /// was rejected. Inbound from blocked peers is silently dropped
    /// at the dispatcher, not surfaced as this error.
    #[error("recipient {agent_id_hex} is on the community denylist — send refused")]
    Denied {
        /// 64-hex agent id of the blocked recipient.
        agent_id_hex: String,
    },

    /// M4 Stage 5.1-chat: the targeted fediverse actor is on the
    /// community-maintained denylist. Sibling of [`Self::Denied`] for
    /// `EntryKind::ActorUrl` rather than `EntryKind::AgentId`. Raised
    /// by [`crate::public::check_actor_url_denylist`] and
    /// [`crate::public::check_publish_denylist`] before any outbound
    /// HTTPS POST fires.
    ///
    /// `actor_url` is the canonical-form value matched against the
    /// denylist (lowercased, no userinfo/fragment/query, single
    /// trailing-slash strip) — what the UI should display verbatim.
    #[error("actor {actor_url} is on the community denylist — publish refused")]
    DeniedActor {
        /// Canonical-form actor URL of the blocked recipient.
        actor_url: String,
    },

    /// `Client::groups::join` returned 200 from x0xd but the joiner's
    /// local x0xd never applied `MemberAdded` to the state slice that
    /// `/secure/decrypt` reads against. Inbound owner-gossiped messages
    /// land before convergence and 403 with "not a member"; this error
    /// surfaces that race instead of papering over it.
    ///
    /// Empirically observed under x0xd v0.21.3 on degraded-NAT joiners
    /// (gossip-into-joiner saturation window, typically ~20s on cross-NAT
    /// pairs). The launch surface ([desktop UI, Android UI]) renders this
    /// as "Joining the group is still in progress" and exposes a retry.
    #[error("joiner did not converge into /groups/{group_id}/members within {waited_ms}ms")]
    JoinerNotConverged {
        /// Group id whose /members the joiner never appeared in active.
        group_id: String,
        /// Wall-clock the joiner was given before this error surfaced.
        waited_ms: u128,
    },
}

impl From<x0xd_client::DiscoveryError> for ChatError {
    fn from(e: x0xd_client::DiscoveryError) -> Self {
        match e {
            x0xd_client::DiscoveryError::Io(io) => Self::Io(io),
            other => Self::NotDiscoverable(other.to_string()),
        }
    }
}

impl From<x0xd_client::X0xdError> for ChatError {
    fn from(e: x0xd_client::X0xdError) -> Self {
        match e {
            x0xd_client::X0xdError::Http(re) => Self::Transport(re),
            x0xd_client::X0xdError::Url(u) => Self::Invalid(format!("x0xd url: {u}")),
            x0xd_client::X0xdError::Rejected(s) => Self::MessageTransport(s),
            x0xd_client::X0xdError::Invalid(s) => Self::Invalid(s),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sealed_required_displays_descriptive_message_with_caller_context() {
        let e: ChatError = ChatError::SealedRequired {
            caller: "RelayTransport::send",
        };
        let msg = e.to_string();
        assert!(msg.contains("sealed envelope required"));
        assert!(
            msg.contains("RelayTransport::send"),
            "caller context must surface in Display: {msg}",
        );
    }
}
