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
}

/// Identifies the thing being reported or denylisted.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetIdentity {
    /// What family of identifier this is.
    pub kind: EntryKind,
    /// 64-character lowercase hex.
    pub value_hex: String,
}

impl TargetIdentity {
    /// Build a new `TargetIdentity`, lowercasing the hex.
    #[must_use]
    pub fn new(kind: EntryKind, value_hex: impl Into<String>) -> Self {
        Self {
            kind,
            value_hex: value_hex.into().to_ascii_lowercase(),
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
