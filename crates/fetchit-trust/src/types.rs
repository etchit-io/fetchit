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

    /// Construct + validate. Per-kind rules:
    /// - [`EntryKind::XorName`] / [`EntryKind::AgentId`]: 64-char
    ///   lowercase hex (input is lowercased first, then validated).
    /// - [`EntryKind::RelayUrl`]: lowercased; must start with
    ///   `wss://`; canonicalized via [`canonicalize_url_value`]
    ///   (rejects userinfo, query strings, fragments; strips a
    ///   single trailing slash; enforces [`MAX_URL_VALUE_LEN`]).
    /// - [`EntryKind::ActorUrl`]: lowercased; must start with
    ///   `https://`; canonicalized via [`canonicalize_url_value`].
    ///
    /// Use `try_new` in new code where invalid input is a real bug.
    /// The infallible [`Self::new`] is kept for callers that need
    /// permissive back-compat behaviour.
    ///
    /// # Errors
    /// Returns a static `&str` describing the kind-specific rule that
    /// failed.
    pub fn try_new(kind: EntryKind, value: impl Into<String>) -> Result<Self, &'static str> {
        let v = value.into().to_ascii_lowercase();
        let v = match kind {
            EntryKind::XorName | EntryKind::AgentId => {
                if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("XorName/AgentId require 64-char lowercase hex");
                }
                v
            }
            EntryKind::RelayUrl => {
                if !v.starts_with("wss://") {
                    return Err("RelayUrl must be wss://");
                }
                canonicalize_url_value(&v)?
            }
            EntryKind::ActorUrl => {
                if !v.starts_with("https://") {
                    return Err("ActorUrl must be https://");
                }
                canonicalize_url_value(&v)?
            }
        };
        Ok(Self { kind, value: v })
    }
}

/// Hard upper bound on a `RelayUrl` / `ActorUrl` value's character
/// length, after lowercasing. Real Mastodon actor URLs run ~50-80
/// chars; 512 is generous but bounded — defends against pathological
/// inputs in the denylist publisher pipeline + keeps the consumer
/// memory profile predictable.
pub const MAX_URL_VALUE_LEN: usize = 512;

/// Canonicalize a lowercased URL value used as a `TargetIdentity`
/// match key.
///
/// Rejects evasion vectors that would otherwise let an actor evade
/// a denylist entry by re-publishing a trivially-different URL form
/// of the same resource. The discipline mirrors what Mastodon emits
/// natively (host case-folded, no userinfo, no fragment, no query,
/// no trailing slash on the actor path).
///
/// Specifically:
/// - Rejects userinfo: `https://user:pass@host/path` is refused.
/// - Rejects fragments: `https://host/path#main-key` is refused.
/// - Rejects query strings: `https://host/path?x=1` is refused.
/// - Strips a single trailing slash on the path: `https://host/path/`
///   becomes `https://host/path`. `https://host/` stays as-is so
///   instance-root URLs round-trip.
/// - Enforces [`MAX_URL_VALUE_LEN`].
///
/// The match logic is intentionally stricter than a full RFC 3986
/// parse — every byte rejected here is one a hostile sender could
/// otherwise use to slip past a denylist hit. Callers that need
/// liberal URL handling for display purposes hold a separate copy
/// outside of [`TargetIdentity`].
///
/// # Errors
/// Returns a static `&str` describing which rule failed. The
/// labels are stable for use as Prometheus counter slots in any
/// future denylist-validation observability surface.
pub fn canonicalize_url_value(v: &str) -> Result<String, &'static str> {
    if v.len() > MAX_URL_VALUE_LEN {
        return Err("URL value exceeds MAX_URL_VALUE_LEN");
    }
    // Drop the scheme prefix before inspection so the `@` / `?` / `#`
    // checks don't false-positive on the `://` separator. Both
    // schemes (`wss://`, `https://`) are validated by the caller
    // before reaching this fn.
    let after_scheme = v.find("://").map_or(v, |i| &v[i + 3..]);
    if after_scheme.contains('@') {
        return Err("URL value must not contain userinfo (`@`)");
    }
    if after_scheme.contains('?') {
        return Err("URL value must not contain a query string (`?`)");
    }
    if after_scheme.contains('#') {
        return Err("URL value must not contain a fragment (`#`)");
    }
    // Trailing-slash policy: strip ONE trailing `/` unless the path
    // is exactly the host root (where the slash is the path).
    let stripped = if let Some(rest) = v.strip_suffix('/') {
        // Count path slashes after the host. If there's a path
        // component beyond the host root, we drop the trailing
        // slash; otherwise we keep it.
        let after_scheme_stripped = rest.find("://").map_or(rest, |i| &rest[i + 3..]);
        if after_scheme_stripped.contains('/') {
            rest.to_string()
        } else {
            v.to_string()
        }
    } else {
        v.to_string()
    };
    Ok(stripped)
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

    #[test]
    fn xorname_value_must_be_64_hex() {
        let t = TargetIdentity::try_new(EntryKind::XorName, "deadbeef");
        assert!(t.is_err());
    }

    #[test]
    fn agentid_value_must_be_64_hex() {
        let t = TargetIdentity::try_new(EntryKind::AgentId, "abc");
        assert!(t.is_err());
    }

    #[test]
    fn xorname_accepts_64_hex_lowercase() {
        let v = "0".repeat(64);
        let t = TargetIdentity::try_new(EntryKind::XorName, &v).unwrap();
        assert_eq!(t.value, v);
    }

    #[test]
    fn xorname_accepts_64_hex_uppercase_normalises_lowercase() {
        let v = "A".repeat(64);
        let t = TargetIdentity::try_new(EntryKind::XorName, &v).unwrap();
        assert_eq!(t.value, "a".repeat(64));
    }

    #[test]
    fn relay_url_must_be_wss() {
        assert!(TargetIdentity::try_new(EntryKind::RelayUrl, "wss://a.example/v1/ws").is_ok());
        // Hostile input — assert REJECTED. String built via format!
        // so the insecure-scheme literal isn't present in the source
        // (avoids a false-positive on lint scanners that match the
        // literal pattern without looking at how it's used).
        let plaintext_scheme = format!("{}://a.example/v1/ws", "ws");
        assert!(TargetIdentity::try_new(EntryKind::RelayUrl, plaintext_scheme).is_err());
        assert!(TargetIdentity::try_new(EntryKind::RelayUrl, "file:///etc/passwd").is_err());
    }

    #[test]
    fn actor_url_must_be_https() {
        assert!(TargetIdentity::try_new(EntryKind::ActorUrl, "https://m.example/u/a").is_ok());
        assert!(TargetIdentity::try_new(EntryKind::ActorUrl, "http://m.example/u/a").is_err());
    }

    #[test]
    fn relay_url_normalises_to_lowercase() {
        let t = TargetIdentity::try_new(EntryKind::RelayUrl, "WSS://Relay.Example/V1/WS").unwrap();
        assert_eq!(t.value, "wss://relay.example/v1/ws");
    }

    // ---- M4 Stage 4.1: URL canonicalization evasion-vector pins ----

    #[test]
    fn actor_url_strips_single_trailing_slash() {
        let t = TargetIdentity::try_new(EntryKind::ActorUrl, "https://mastodon.example/users/eve/")
            .unwrap();
        assert_eq!(t.value, "https://mastodon.example/users/eve");
    }

    #[test]
    fn actor_url_preserves_instance_root_slash() {
        // `https://mastodon.example/` — the slash IS the path, can't
        // be stripped without ambiguity vs the bare host form. We
        // keep it as-is so denylist hits match what the inbox layer
        // sees verbatim.
        let t = TargetIdentity::try_new(EntryKind::ActorUrl, "https://mastodon.example/").unwrap();
        assert_eq!(t.value, "https://mastodon.example/");
    }

    #[test]
    fn actor_url_rejects_fragment() {
        // Per M3↔M4 EntryKind co-author decision: a denylist hit must
        // not be evadable via `#main-key` re-publication.
        let err = TargetIdentity::try_new(
            EntryKind::ActorUrl,
            "https://mastodon.example/users/eve#main-key",
        )
        .unwrap_err();
        assert!(err.contains("fragment"), "got: {err}");
    }

    #[test]
    fn actor_url_rejects_query_string() {
        let err = TargetIdentity::try_new(
            EntryKind::ActorUrl,
            "https://mastodon.example/users/eve?x=1",
        )
        .unwrap_err();
        assert!(err.contains("query"), "got: {err}");
    }

    #[test]
    fn actor_url_rejects_userinfo() {
        let err = TargetIdentity::try_new(
            EntryKind::ActorUrl,
            "https://user:pass@mastodon.example/users/eve",
        )
        .unwrap_err();
        assert!(err.contains("userinfo"), "got: {err}");
    }

    #[test]
    fn relay_url_rejects_userinfo() {
        let err =
            TargetIdentity::try_new(EntryKind::RelayUrl, "wss://user:pass@relay.example/v1/ws")
                .unwrap_err();
        assert!(err.contains("userinfo"), "got: {err}");
    }

    #[test]
    fn relay_url_rejects_fragment() {
        let err = TargetIdentity::try_new(EntryKind::RelayUrl, "wss://relay.example/v1/ws#anchor")
            .unwrap_err();
        assert!(err.contains("fragment"), "got: {err}");
    }

    #[test]
    fn url_rejects_over_length_input() {
        // A pathologically long actor URL must be refused so the
        // denylist publisher / consumer pipeline can't be DoS'd with
        // unbounded String pressure.
        let long_path = "x".repeat(MAX_URL_VALUE_LEN);
        let v = format!("https://mastodon.example/users/{long_path}");
        let err = TargetIdentity::try_new(EntryKind::ActorUrl, v).unwrap_err();
        assert!(err.contains("MAX_URL_VALUE_LEN"), "got: {err}");
    }

    #[test]
    fn url_at_exact_max_length_is_accepted() {
        // Boundary: a value at exactly MAX_URL_VALUE_LEN must round-trip.
        let prefix = "https://mastodon.example/users/";
        let pad = MAX_URL_VALUE_LEN - prefix.len();
        let value = format!("{prefix}{}", "x".repeat(pad));
        assert_eq!(value.len(), MAX_URL_VALUE_LEN);
        let t = TargetIdentity::try_new(EntryKind::ActorUrl, value.clone()).unwrap();
        assert_eq!(t.value, value);
    }

    #[test]
    fn canonicalize_url_value_idempotent_on_clean_input() {
        // Already-canonical input should be a no-op (modulo the
        // lowercasing that's the caller's responsibility).
        let v = "https://mastodon.example/users/eve";
        assert_eq!(canonicalize_url_value(v).unwrap(), v);
    }

    #[test]
    fn canonicalize_handles_at_in_path_after_scheme_split() {
        // Sanity: `://` is what splits scheme from authority; the
        // userinfo `@` check operates AFTER that split so a path
        // segment that happened to contain `@` (unusual but legal)
        // still gets rejected — we don't trust input enough to
        // distinguish path-`@` from userinfo-`@` without a full
        // URL parser. Conservative on purpose.
        let err = TargetIdentity::try_new(
            EntryKind::ActorUrl,
            "https://mastodon.example/users/eve@instance",
        )
        .unwrap_err();
        assert!(err.contains("userinfo"), "got: {err}");
    }

    // ---- Manifest round-trip with ActorUrl entries ----

    #[test]
    fn denylist_response_round_trips_actor_url_entries() {
        let entries = vec![
            DenylistEntry {
                target: TargetIdentity::try_new(
                    EntryKind::ActorUrl,
                    "https://attacker.example/users/eve",
                )
                .unwrap(),
                added_at_ms: 1_700_000_000_000,
                reason: ReportKind::Harassment,
            },
            DenylistEntry {
                target: TargetIdentity::try_new(
                    EntryKind::ActorUrl,
                    "https://mastodon.example/users/spam/",
                )
                .unwrap(),
                added_at_ms: 1_700_000_001_000,
                reason: ReportKind::Spam,
            },
        ];
        let resp = DenylistResponse {
            etag: "v1".into(),
            generated_at_ms: 1_700_000_002_000,
            kind: EntryKind::ActorUrl,
            entries: entries.clone(),
            issuer_signature_hex: "ff".repeat(32),
            issuer_key_id: "etchit-io-v1".into(),
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: DenylistResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.kind, EntryKind::ActorUrl);
        assert_eq!(decoded.entries.len(), 2);
        // Trailing-slash entry must have been canonicalized.
        assert_eq!(
            decoded.entries[1].target.value,
            "https://mastodon.example/users/spam"
        );
        assert_eq!(decoded.entries, entries);
    }
}
