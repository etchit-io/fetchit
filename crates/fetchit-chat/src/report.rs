//! User-facing abuse reporting — the client half of the trust
//! service's `POST /v1/report`.
//!
//! The trust service has carried a report queue since M3, but nothing
//! ever called it: moderation was an operator-only path (shell access to
//! the trust host, `POST /admin/deny`). This module is the reporting
//! on-ramp a social product owes its users — a person who sees abuse can
//! hand it to the moderators from inside the app, and the moderator
//! decides whether it becomes a signed denylist entry.
//!
//! Reporting is deliberately NOT blocking: a report is a request for
//! review, nothing more. Blocking an account is separate, local, and
//! instant (the shells' block stores); the denylist is the community
//! answer and only a reviewer promotes an entry onto it.
//!
//! # What leaves the device
//!
//! Exactly the [`fetchit_trust_types::Report`] fields: the reporter's own
//! agent id, the [`TargetIdentity`] being reported, the chosen
//! [`ReportKind`], the free-text comment the user typed, and a
//! timestamp. No message bodies, no conversation state, no contact list.
//! The `attached_excerpt` slot exists on the wire type for a future
//! "include this message" affordance and is always `None` here — an
//! excerpt is plaintext disclosure and must be an explicit, separate
//! user choice.

use std::time::Duration;

use fetchit_trust_types::{EntryKind, Report, ReportKind, TargetIdentity};

use crate::client::Client;
use crate::error::{ChatError, Result};

/// Compiled-in default trust-service base (the live NY-Trust node) —
/// the same service the M3 denylist consumer polls, so a report and the
/// list it may end up on never diverge.
pub const DEFAULT_TRUST_URL: &str = "https://trust.etchit.io/v1";

/// Env override for the trust-service base, shared with the denylist
/// consumer wiring in the shells. A test or a staging deploy points both
/// at one stub by setting this alone.
pub const TRUST_URL_ENV: &str = "FETCHIT_DENYLIST_URL";

/// Wall-clock ceiling on the report POST. A report is user-initiated
/// and the UI is waiting on it, so it fails honestly rather than
/// hanging.
const REPORT_TIMEOUT: Duration = Duration::from_secs(15);

/// Longest comment accepted from a caller. A report is a pointer for a
/// human reviewer, not a document; the cap bounds what an automated
/// caller could push into the moderation queue.
pub const MAX_COMMENT_LEN: usize = 2000;

/// Resolve the trust-service base URL: a non-empty [`TRUST_URL_ENV`]
/// wins, else [`DEFAULT_TRUST_URL`]. Mirrors the denylist resolver in
/// the FFI + desktop shells so one env var moves both.
#[must_use]
pub fn resolve_trust_url() -> String {
    std::env::var(TRUST_URL_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_TRUST_URL.to_owned())
}

/// Parse a wire-form report-kind discriminant (the `snake_case`
/// [`ReportKind`] serde names) into the typed enum.
///
/// Shells hand the user's radio choice across an FFI boundary as a
/// string; this is the single place that mapping lives, so a new kind is
/// added once.
///
/// # Errors
/// [`ChatError::Invalid`] naming the unknown discriminant.
pub fn parse_report_kind(kind: &str) -> Result<ReportKind> {
    match kind {
        "csam" => Ok(ReportKind::Csam),
        "violence_threat" => Ok(ReportKind::ViolenceThreat),
        "harassment" => Ok(ReportKind::Harassment),
        "spam" => Ok(ReportKind::Spam),
        "doxxing" => Ok(ReportKind::Doxxing),
        "abusive_content" => Ok(ReportKind::AbusiveContent),
        "other" => Ok(ReportKind::Other),
        unknown => Err(ChatError::Invalid(format!(
            "unknown report kind {unknown:?}"
        ))),
    }
}

/// Build a validated [`Report`] ready to POST.
///
/// `value` is canonicalized + validated by
/// [`TargetIdentity::try_new`] — for [`EntryKind::ActorUrl`] that means
/// lowercased, `https://` required, no userinfo / query / fragment, and
/// a single trailing slash stripped. Reporting a URL that fails those
/// rules is a caller bug (the value came from an actor document we
/// already parsed), so it surfaces as an error rather than being
/// silently normalised into something the reviewer cannot act on.
///
/// # Errors
/// [`ChatError::Invalid`] when the target fails validation or the
/// comment exceeds [`MAX_COMMENT_LEN`].
pub fn build_report(
    reporter_agent_id_hex: Option<String>,
    kind: EntryKind,
    value: &str,
    report_kind: ReportKind,
    comment: &str,
    now_ms: u64,
) -> Result<Report> {
    // Characters, not bytes: a 2000-character comment in a non-Latin
    // script would otherwise be refused for being 4000 bytes long.
    if comment.chars().count() > MAX_COMMENT_LEN {
        return Err(ChatError::Invalid(format!(
            "report comment exceeds {MAX_COMMENT_LEN} characters"
        )));
    }
    let target = TargetIdentity::try_new(kind, value)
        .map_err(|e| ChatError::Invalid(format!("report target: {e}")))?;
    Ok(Report {
        reporter_agent_id_hex,
        target,
        kind: report_kind,
        reason: comment.trim().to_owned(),
        // Never auto-attached: disclosing plaintext is its own decision.
        attached_excerpt: None,
        timestamp_ms: now_ms,
    })
}

/// POST `report` to `<base>/report` on the trust service.
///
/// Split from [`Client::report_target`] so the wire half is exercisable
/// against a stub server without a `Client`.
///
/// # Errors
/// - [`ChatError::Invalid`] when the request cannot be sent (DNS, TLS,
///   timeout) or the service answers non-2xx; the status and a truncated
///   body ride in the message so the UI can say something true.
pub async fn post_report(base_url: &str, report: &Report) -> Result<()> {
    let url = format!("{}/report", base_url.trim_end_matches('/'));
    let http = crate::relay_http::guarded_client();
    let resp = http
        .post(&url)
        .timeout(REPORT_TIMEOUT)
        .json(report)
        .send()
        .await
        .map_err(|e| ChatError::Invalid(format!("report POST: {e}")))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    // Truncate: the body is remote-controlled and only ever a diagnostic.
    let body = resp.text().await.unwrap_or_default();
    let short: String = body.chars().take(200).collect();
    Err(ChatError::Invalid(format!(
        "report rejected: HTTP {} {short}",
        status.as_u16()
    )))
}

impl Client {
    /// Report a target to the community trust service for moderator
    /// review.
    ///
    /// The reporter is this device's own agent id when chat state is
    /// wired, `None` otherwise (a REST-only client can still file an
    /// anonymous report — the service accepts one, and refusing would
    /// mean the least-privileged shell cannot report abuse at all).
    ///
    /// Reporting does NOT block or mute: the shells' local block is the
    /// instant remedy, this is the request for community review.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] when the target or comment fails
    /// validation, or when the service is unreachable / answers non-2xx.
    pub async fn report_target(
        &self,
        kind: EntryKind,
        value: &str,
        report_kind: ReportKind,
        comment: &str,
    ) -> Result<()> {
        let report = build_report(
            self.local_agent_id_hex(),
            kind,
            value,
            report_kind,
            comment,
            now_ms(),
        )?;
        post_report(&resolve_trust_url(), &report).await
    }

    /// String-typed entrance to [`Self::report_target`] for a fediverse
    /// actor URL — what every shell's "Report" affordance calls.
    ///
    /// `reason` is a `snake_case` [`ReportKind`] discriminant (see
    /// [`parse_report_kind`]); keeping the mapping engine-side means the
    /// FFI needs no trust-types dependency and every shell offers the
    /// same vocabulary.
    ///
    /// # Errors
    /// [`ChatError::Invalid`] for an unknown `reason`, an actor URL that
    /// fails canonicalization, an over-long comment, or a service
    /// failure.
    pub async fn report_actor_url(
        &self,
        actor_url: &str,
        reason: &str,
        comment: &str,
    ) -> Result<()> {
        let report_kind = parse_report_kind(reason)?;
        self.report_target(EntryKind::ActorUrl, actor_url, report_kind, comment)
            .await
    }
}

/// Milliseconds since the Unix epoch; `0` if the clock is before it.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ACTOR: &str = "https://attacker.example/users/eve";

    #[test]
    fn every_report_kind_round_trips_through_its_wire_name() {
        // The shells send these strings; a rename on either side that
        // is not mirrored here silently degrades every report to an
        // error, so the mapping is pinned both ways.
        for (wire, kind) in [
            ("csam", ReportKind::Csam),
            ("violence_threat", ReportKind::ViolenceThreat),
            ("harassment", ReportKind::Harassment),
            ("spam", ReportKind::Spam),
            ("doxxing", ReportKind::Doxxing),
            ("abusive_content", ReportKind::AbusiveContent),
            ("other", ReportKind::Other),
        ] {
            assert_eq!(parse_report_kind(wire).unwrap(), kind);
            // The parser's vocabulary IS the serde vocabulary.
            assert_eq!(serde_json::to_value(kind).unwrap(), wire);
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected_not_defaulted() {
        let err = parse_report_kind("definitely-not-a-kind").unwrap_err();
        assert!(
            matches!(err, ChatError::Invalid(ref m) if m.contains("unknown report kind")),
            "got {err:?}",
        );
    }

    #[test]
    fn build_report_canonicalizes_the_actor_url() {
        // Trailing slash + uppercase host: the reviewer must see the
        // same canonical form the denylist would carry, or a promoted
        // entry would not match the gate.
        let r = build_report(
            Some("a".repeat(64)),
            EntryKind::ActorUrl,
            "https://Attacker.Example/users/Eve/",
            ReportKind::Harassment,
            "  they keep messaging me  ",
            42,
        )
        .unwrap();
        assert_eq!(r.target.kind, EntryKind::ActorUrl);
        assert_eq!(r.target.value, "https://attacker.example/users/eve");
        assert_eq!(r.reason, "they keep messaging me");
        assert_eq!(r.timestamp_ms, 42);
        assert_eq!(r.reporter_agent_id_hex, Some("a".repeat(64)));
        assert!(
            r.attached_excerpt.is_none(),
            "an excerpt is never attached without an explicit user choice",
        );
    }

    #[test]
    fn degenerate_targets_are_refused_before_any_post() {
        for bad in [
            "http://attacker.example/users/eve", // not https
            "https://attacker.example/users/eve?x=1",
            "https://attacker.example/users/eve#frag",
            "https://user@attacker.example/users/eve",
            "not a url at all",
        ] {
            assert!(
                build_report(None, EntryKind::ActorUrl, bad, ReportKind::Spam, "", 0).is_err(),
                "{bad} must not produce a report",
            );
        }
    }

    #[test]
    fn an_over_long_comment_is_refused() {
        let comment = "x".repeat(MAX_COMMENT_LEN + 1);
        assert!(build_report(
            None,
            EntryKind::ActorUrl,
            ACTOR,
            ReportKind::Spam,
            &comment,
            0
        )
        .is_err());
        let ok = "x".repeat(MAX_COMMENT_LEN);
        assert!(
            build_report(None, EntryKind::ActorUrl, ACTOR, ReportKind::Spam, &ok, 0).is_ok(),
            "the cap itself is accepted",
        );
    }

    #[test]
    fn an_agent_id_target_is_validated_as_hex() {
        assert!(build_report(
            None,
            EntryKind::AgentId,
            &"a".repeat(64),
            ReportKind::Spam,
            "",
            0
        )
        .is_ok());
        assert!(
            build_report(None, EntryKind::AgentId, "abc", ReportKind::Spam, "", 0).is_err(),
            "a short agent id is not a reportable target",
        );
    }

    #[test]
    fn the_default_trust_base_matches_the_denylist_service() {
        assert_eq!(DEFAULT_TRUST_URL, "https://trust.etchit.io/v1");
    }

    #[tokio::test]
    async fn post_report_sends_the_wire_shape_and_accepts_202() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/report"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let report = build_report(
            Some("b".repeat(64)),
            EntryKind::ActorUrl,
            ACTOR,
            ReportKind::Csam,
            "see the linked post",
            7,
        )
        .unwrap();
        post_report(&format!("{}/v1", server.uri()), &report)
            .await
            .unwrap();

        let received = &server.received_requests().await.unwrap()[0];
        let sent: serde_json::Value = serde_json::from_slice(&received.body).unwrap();
        assert_eq!(sent["kind"], "csam");
        assert_eq!(sent["target"]["kind"], "actor_url");
        assert_eq!(sent["target"]["value"], ACTOR);
        assert_eq!(sent["reason"], "see the linked post");
        assert_eq!(sent["reporter_agent_id_hex"], "b".repeat(64));
        assert_eq!(sent["timestamp_ms"], 7);
        assert!(sent["attached_excerpt"].is_null());
    }

    #[tokio::test]
    async fn a_trailing_slash_on_the_base_does_not_double_up_the_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/report"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
        let report =
            build_report(None, EntryKind::ActorUrl, ACTOR, ReportKind::Spam, "", 0).unwrap();
        post_report(&format!("{}/v1/", server.uri()), &report)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_service_rejection_surfaces_the_status_honestly() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/report"))
            .respond_with(ResponseTemplate::new(500).set_body_string("storage down"))
            .mount(&server)
            .await;
        let report =
            build_report(None, EntryKind::ActorUrl, ACTOR, ReportKind::Spam, "", 0).unwrap();
        let err = post_report(&format!("{}/v1", server.uri()), &report)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("500"), "got {msg}");
        assert!(msg.contains("storage down"), "got {msg}");
    }

    #[tokio::test]
    async fn an_unreachable_service_is_an_honest_error_not_a_silent_success() {
        let report =
            build_report(None, EntryKind::ActorUrl, ACTOR, ReportKind::Spam, "", 0).unwrap();
        let err = post_report("http://127.0.0.1:1/v1", &report)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("report POST"), "got {err}");
    }
}
