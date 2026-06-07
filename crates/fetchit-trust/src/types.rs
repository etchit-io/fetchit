//! Wire schemas for the trust service.

use serde::{Deserialize, Serialize};

/// What kind of entity is being targeted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// 64-hex Autonomi address (`XorName`).
    XorName,
    /// 64-hex agent id (chat identity).
    AgentId,
    /// Relay endpoint URL (e.g. `wss://relay.example.com/v1/ws`),
    /// consumed by federated relays via the M3 denylist surface.
    RelayUrl,
    /// Fediverse actor URL (e.g. `https://mastodon.example/users/eve`),
    /// consumed by the M4 Stage 4 `MastodonBlocklistConsumer`.
    ActorUrl,
}

/// Identifies the thing being reported or denylisted.
///
/// `value` carries a 64-character lowercase hex string for
/// [`EntryKind::XorName`] / [`EntryKind::AgentId`], and a normalised
/// lowercase URL for [`EntryKind::RelayUrl`] / [`EntryKind::ActorUrl`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetIdentity {
    /// What family of identifier this is.
    pub kind: EntryKind,
    /// Identifier value, normalised to lowercase ASCII at construction.
    pub value: String,
}

impl TargetIdentity {
    /// Build a new `TargetIdentity`, lowercasing the value at the
    /// ASCII boundary. Hex values become lowercase hex; URL values
    /// become lowercase URLs (scheme, host, path, etc.).
    #[must_use]
    pub fn new(kind: EntryKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into().to_ascii_lowercase(),
        }
    }
}

/// Classification chosen by the reporter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    /// CSAM — top-priority queue.
    Csam,
    /// Threats of violence.
    ViolenceThreat,
    /// Targeted harassment.
    Harassment,
    /// Unsolicited bulk content.
    Spam,
    /// Doxxing / privacy violation.
    Doxxing,
    /// Generic abusive content.
    AbusiveContent,
    /// Anything not covered above.
    Other,
}

/// One report submitted to `/v1/report`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Reporter's agent id (hex), present when the report came from an authenticated client.
    pub reporter_agent_id_hex: Option<String>,
    /// What is being reported.
    pub target: TargetIdentity,
    /// Reporter-chosen classification.
    pub kind: ReportKind,
    /// Free-text reason / context the reporter included.
    pub reason: String,
    /// Optional plaintext excerpt the reporter chose to disclose.
    pub attached_excerpt: Option<String>,
    /// Reporter wall-clock time, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
}

/// One entry in the published denylist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenylistEntry {
    /// What's blocked.
    pub target: TargetIdentity,
    /// Server wall-clock time when this entry was promoted to the denylist.
    pub added_at_ms: u64,
    /// Reviewer-chosen reason category (mirrors [`ReportKind`]).
    pub reason: ReportKind,
}

/// Signed denylist response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenylistResponse {
    /// Cache validator — opaque, monotonic across publishes.
    pub etag: String,
    /// Server wall-clock time of this snapshot, milliseconds since the Unix epoch.
    pub generated_at_ms: u64,
    /// Entries restricted to the requested family.
    pub kind: EntryKind,
    /// Denylist entries in stable order.
    pub entries: Vec<DenylistEntry>,
    /// Hex-encoded ML-DSA-65 signature of the postcard-encoded
    /// `{etag, generated_at_ms, kind, entries}` tuple under the
    /// issuer key (looked up by `issuer_key_id`).
    pub issuer_signature_hex: String,
    /// Identifier of the issuer key that signed this payload.
    pub issuer_key_id: String,
}

/// Canonical signing payload for [`DenylistResponse`].
///
/// Both the server-side signer and the consumer-side verifier
/// construct this from the same field set + postcard-encode it.
/// Borrowing keeps the server's hot path zero-copy; consumers
/// reconstruct it from a deserialized [`DenylistResponse`].
#[derive(Serialize)]
pub struct DenylistToSign<'a> {
    /// Mirrors [`DenylistResponse::etag`].
    pub etag: &'a str,
    /// Mirrors [`DenylistResponse::generated_at_ms`].
    pub generated_at_ms: u64,
    /// Mirrors [`DenylistResponse::kind`].
    pub kind: EntryKind,
    /// Mirrors [`DenylistResponse::entries`].
    pub entries: &'a [DenylistEntry],
}

/// Health endpoint payload.
#[derive(Debug, Serialize)]
pub struct Health {
    /// Always `true` while serving.
    pub ok: bool,
    /// Service build identifier.
    pub version: String,
    /// Number of reports currently in the queue.
    pub queued_reports: usize,
    /// Number of denylisted Autonomi addresses.
    pub denylisted_xornames: usize,
    /// Number of denylisted agent ids.
    pub denylisted_agents: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn relay_url_entry_kind_lowercases_value() {
        let t = TargetIdentity::new(EntryKind::RelayUrl, "WSS://Relay.Example.com/V1/WS");
        assert_eq!(t.kind, EntryKind::RelayUrl);
        assert_eq!(t.value, "wss://relay.example.com/v1/ws");
    }

    #[test]
    fn actor_url_entry_kind_lowercases_value() {
        let t = TargetIdentity::new(EntryKind::ActorUrl, "HTTPS://Mastodon.example/Users/Eve");
        assert_eq!(t.value, "https://mastodon.example/users/eve");
    }
}
