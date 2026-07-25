//! Production [`CommitApplier`] that applies fetched group-log records
//! through x0xd's signature-verifying MLS endpoints.
//!
//! The routing decision (which endpoint, what params) is the pure
//! [`super::plan_apply`]; this module only executes the returned plan
//! against `apply_metadata_event` / `apply_join_result`. NEVER a bypass:
//! the daemon re-runs full membership authority (ML-DSA `committed_by` +
//! single-use invite-secret + inviter-gate) on the payload, so the
//! relay-stamped author is only a routing hint and a forged record fails
//! verification daemon-side rather than being applied.

use super::{plan_apply, ApplyOutcome, ApplyPlan, CommitApplier, CommitRecord};
use crate::error::{ChatError, Result};

/// A [`CommitApplier`] over a local x0xd `SecureGroupsEndpoint`. Holds the
/// daemon base URL + token so it builds the endpoint per call (matching the
/// client's own `secure_groups`), plus this node's agent id (hex) to
/// classify a self-addressed join-result.
pub struct X0xdCommitApplier {
    base_url: String,
    token: String,
    my_agent_hex: String,
    /// Shared engine-A capability latch (see `Client::engine_a_supported`).
    /// A route-level 404 from either apply endpoint means the daemon is
    /// stock and has no engine-A at all — that must flip this latch and
    /// surface as an environment error, never be skipped as a poison
    /// record (skipping would silently drain the whole log unapplied).
    engine_a: std::sync::Arc<std::sync::OnceLock<bool>>,
}

impl X0xdCommitApplier {
    /// Build an applier targeting the daemon at `base_url` with `token`.
    /// `engine_a` is the client's shared capability latch.
    #[must_use]
    pub fn new(
        base_url: String,
        token: String,
        my_agent_hex: String,
        engine_a: std::sync::Arc<std::sync::OnceLock<bool>>,
    ) -> Self {
        Self {
            base_url,
            token,
            my_agent_hex,
            engine_a,
        }
    }

    fn secure(&self) -> Result<x0xd_client::SecureGroupsEndpoint> {
        let base = url::Url::parse(&self.base_url)
            .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
        x0xd_client::SecureGroupsEndpoint::new(base, self.token.clone()).map_err(ChatError::from)
    }
}

/// Classify an apply-endpoint error for the recovery loop by fault
/// domain. A RECORD-fault -- any deterministic 4xx the daemon answers
/// for this specific record's content (400 malformed, 403 disallowed,
/// 404 unknown, 405/413/422/...) -- can NEVER succeed on a later retry,
/// so the loop must skip it and advance its cursor; otherwise one
/// poison or stale record (the log is not membership-gated on append)
/// wedges warm recovery permanently. An ENVIRONMENT-fault stays an
/// error and retries with the cursor before the record, because it is
/// constant across records and skipping would silently drain the whole
/// log unapplied: 401/407 (auth), 431 (headers -- ours never vary per
/// record), 408 (timeout), 429 (throttle). The failure asymmetry picks
/// the sides: a wrong Err is a visible, retriggered wedge; a wrong skip
/// is silent unapplied loss. For the same reason everything OUTSIDE
/// 4xx (5xx, and any 3xx a non-following client would surface) falls
/// through to Err -- the safe, visible side -- never to skip.
fn classify_apply_error(
    e: x0xd_client::X0xdError,
    seq: u64,
    group_id: &str,
    engine_a: &std::sync::OnceLock<bool>,
) -> Result<ApplyOutcome> {
    // Endpoint-level 404 (bare router body, no daemon JSON error shape):
    // the daemon is stock and has no engine-A apply routes AT ALL. That is
    // an environment condition, not a property of this record — latch it
    // and error out so the driver's next pass skips the warm lane entirely.
    // Treating it as a record fault would "skip" every record and silently
    // drain the whole log unapplied while looking successful.
    if crate::groups::engine_a::route_miss_404(&e) {
        if engine_a.set(false).is_ok() {
            log::warn!(
                "[chat] warm recovery: daemon has no engine-A apply endpoints \
                 (stock x0xd); warm lane disabled, cold resume owns recovery"
            );
        }
        return Err(ChatError::from(e));
    }
    match e {
        x0xd_client::X0xdError::ApplyRejected { status, detail }
            if (400..500).contains(&status) && !matches!(status, 401 | 407 | 408 | 429 | 431) =>
        {
            log::warn!(
                "[chat] warm recovery: daemon rejected log record seq={seq} \
                 group={group_id} with {status} ({detail}); skipping past the \
                 dead record"
            );
            Ok(ApplyOutcome::AlreadyApplied)
        }
        other => Err(ChatError::from(other)),
    }
}

impl CommitApplier for X0xdCommitApplier {
    async fn apply(&self, group_id: &str, record: &CommitRecord) -> Result<ApplyOutcome> {
        let applied = match plan_apply(record, &self.my_agent_hex) {
            ApplyPlan::Metadata {
                payload_b64,
                author_hex,
            } => match self
                .secure()?
                .apply_metadata_event(group_id, &payload_b64, &author_hex)
                .await
            {
                Ok(applied) => applied,
                Err(e) => return classify_apply_error(e, record.seq, group_id, &self.engine_a),
            },
            ApplyPlan::JoinResult {
                stable_group_id,
                member,
                payload_b64,
                owner_hex,
            } => match self
                .secure()?
                .apply_join_result(&stable_group_id, &member, &payload_b64, &owner_hex)
                .await
            {
                Ok(applied) => applied,
                Err(e) => return classify_apply_error(e, record.seq, group_id, &self.engine_a),
            },
            // Nothing to apply (malformed, no author, or a join-result not
            // addressed to us). Traced, then treated as already-satisfied so
            // the loop advances its cursor past the record, never stalls.
            ApplyPlan::Skip(reason) => {
                log::warn!(
                    "[chat] warm recovery: skipping log record seq={} group={group_id}: {reason}",
                    record.seq
                );
                return Ok(ApplyOutcome::AlreadyApplied);
            }
        };
        Ok(if applied {
            ApplyOutcome::Applied
        } else {
            ApplyOutcome::AlreadyApplied
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::groups::epoch_recovery::CommitRecordKind;
    use base64::Engine as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn commit_record(payload: &[u8], author_hex: Option<String>) -> CommitRecord {
        CommitRecord {
            seq: 1,
            kind: CommitRecordKind::Commit,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
            author_agent_id_hex: author_hex,
        }
    }

    fn latch() -> std::sync::Arc<std::sync::OnceLock<bool>> {
        std::sync::Arc::new(std::sync::OnceLock::new())
    }

    #[tokio::test]
    async fn commit_routes_to_apply_metadata_event_and_reports_applied() {
        let gid = "aa".repeat(32); // 64-hex, passes validate_group_id_hex
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/groups/{gid}/apply-metadata-event")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applied": true
            })))
            .mount(&server)
            .await;

        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32), latch());
        let rec = commit_record(b"signed-event", Some("cc".repeat(32)));
        let outcome = applier.apply(&gid, &rec).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied);
    }

    #[tokio::test]
    async fn commit_409_reports_already_applied_not_error() {
        let gid = "dd".repeat(32);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/groups/{gid}/apply-metadata-event")))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "applied": false
            })))
            .mount(&server)
            .await;

        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32), latch());
        let rec = commit_record(b"already-have-it", Some("cc".repeat(32)));
        let outcome = applier.apply(&gid, &rec).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::AlreadyApplied);
    }

    #[tokio::test]
    async fn commit_without_author_skips_without_calling_daemon() {
        // No author -> plan_apply Skip -> AlreadyApplied, and crucially NO
        // HTTP call (an unmounted server would 404 any request; none is made).
        let server = MockServer::start().await;
        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32), latch());
        let rec = commit_record(b"no-author", None);
        let outcome = applier.apply(&"ee".repeat(32), &rec).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::AlreadyApplied);
        // The mock server received zero requests: the Skip short-circuited
        // before any apply call.
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Deterministic record-fault rejects (400 malformed, 403
    /// disallowed, 404 unknown, 405/413/422 protocol/size/semantic)
    /// mean the record can NEVER become valid: the applier must
    /// skip-and-advance (`AlreadyApplied`) so one poison or stale
    /// record cannot wedge warm recovery forever. Nothing is applied --
    /// the daemon already refused it. The bodies carry the daemon's
    /// JSON error shape -- the 404 case is a HANDLER "group not found"
    /// (a record fault), distinguished from a bare route-level 404
    /// (engine-A missing entirely; covered separately below).
    #[tokio::test]
    async fn deterministic_daemon_reject_skips_and_advances() {
        for status in [400u16, 403, 404, 405, 411, 413, 415, 422] {
            let gid = "ff".repeat(32);
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("/groups/{gid}/apply-metadata-event")))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_string(r#"{"error":"refused","ok":false}"#),
                )
                .mount(&server)
                .await;

            let applier =
                X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32), latch());
            let rec = commit_record(b"refused-event", Some("cc".repeat(32)));
            let outcome = applier
                .apply(&gid, &rec)
                .await
                .unwrap_or_else(|e| panic!("status {status} must skip-and-advance, got Err: {e}"));
            assert_eq!(
                outcome,
                ApplyOutcome::AlreadyApplied,
                "status {status} must advance the cursor past the dead record"
            );
        }
    }

    /// A route-level 404 (bare body, no daemon JSON error shape) means
    /// the daemon is STOCK -- it has no engine-A apply endpoints at all.
    /// That is an environment condition: the applier must error out (so
    /// the cursor holds and nothing is "skipped") and flip the shared
    /// capability latch so the driver stops choosing the warm lane.
    /// Classifying it as a record fault would skip EVERY record and
    /// silently drain the whole log unapplied while looking successful.
    #[tokio::test]
    async fn route_level_404_errors_and_latches_engine_a_off() {
        let gid = "ab".repeat(32);
        let server = MockServer::start().await;
        // No mounted route: wiremock answers unknown paths with a bare
        // 404 and an empty body -- exactly the stock-router shape.
        let shared = latch();
        let applier =
            X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32), shared.clone());
        let rec = commit_record(b"engine-a-event", Some("cc".repeat(32)));
        assert!(
            applier.apply(&gid, &rec).await.is_err(),
            "a missing route must NOT advance the cursor"
        );
        assert_eq!(
            shared.get(),
            Some(&false),
            "the shared latch must record that engine-A is unsupported"
        );
    }

    /// Environment-faults stay errors -- the cursor holds BEFORE the
    /// record and the next trigger retries it. 401 is the load-bearing
    /// case: a broken bearer token 401s EVERY record, and classifying it
    /// as skip would silently drain the whole log unapplied; 407/431 are
    /// the same shape (auth/headers, constant across records). 408/429
    /// are transient by definition; 5xx is the daemon's problem, not the
    /// record's; a surfaced 3xx falls to the same safe side.
    #[tokio::test]
    async fn environment_fault_stays_an_error() {
        for status in [301u16, 401, 407, 408, 429, 431, 500, 503] {
            let gid = "ee".repeat(32);
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("/groups/{gid}/apply-metadata-event")))
                .respond_with(ResponseTemplate::new(status).set_body_string("not-the-record"))
                .mount(&server)
                .await;

            let applier =
                X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32), latch());
            let rec = commit_record(b"retry-me", Some("cc".repeat(32)));
            assert!(
                applier.apply(&gid, &rec).await.is_err(),
                "status {status} must NOT advance the cursor; the record is retried next pass"
            );
        }
    }
}
