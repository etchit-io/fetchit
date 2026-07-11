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
}

impl X0xdCommitApplier {
    /// Build an applier targeting the daemon at `base_url` with `token`.
    #[must_use]
    pub fn new(base_url: String, token: String, my_agent_hex: String) -> Self {
        Self {
            base_url,
            token,
            my_agent_hex,
        }
    }

    fn secure(&self) -> Result<x0xd_client::SecureGroupsEndpoint> {
        let base = url::Url::parse(&self.base_url)
            .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?;
        x0xd_client::SecureGroupsEndpoint::new(base, self.token.clone()).map_err(ChatError::from)
    }
}

impl CommitApplier for X0xdCommitApplier {
    async fn apply(&self, group_id: &str, record: &CommitRecord) -> Result<ApplyOutcome> {
        let applied = match plan_apply(record, &self.my_agent_hex) {
            ApplyPlan::Metadata {
                payload_b64,
                author_hex,
            } => self
                .secure()?
                .apply_metadata_event(group_id, &payload_b64, &author_hex)
                .await
                .map_err(ChatError::from)?,
            ApplyPlan::JoinResult {
                stable_group_id,
                member,
                payload_b64,
                owner_hex,
            } => self
                .secure()?
                .apply_join_result(&stable_group_id, &member, &payload_b64, &owner_hex)
                .await
                .map_err(ChatError::from)?,
            // Nothing to apply (malformed, no author, or a join-result not
            // addressed to us). Treat as already-satisfied so the loop
            // advances its cursor past the record rather than stalling.
            ApplyPlan::Skip(_reason) => return Ok(ApplyOutcome::AlreadyApplied),
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

        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32));
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

        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32));
        let rec = commit_record(b"already-have-it", Some("cc".repeat(32)));
        let outcome = applier.apply(&gid, &rec).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::AlreadyApplied);
    }

    #[tokio::test]
    async fn commit_without_author_skips_without_calling_daemon() {
        // No author -> plan_apply Skip -> AlreadyApplied, and crucially NO
        // HTTP call (an unmounted server would 404 any request; none is made).
        let server = MockServer::start().await;
        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32));
        let rec = commit_record(b"no-author", None);
        let outcome = applier.apply(&"ee".repeat(32), &rec).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::AlreadyApplied);
        // The mock server received zero requests: the Skip short-circuited
        // before any apply call.
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn daemon_reject_surfaces_as_error() {
        let gid = "ff".repeat(32);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/groups/{gid}/apply-metadata-event")))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad event"))
            .mount(&server)
            .await;

        let applier = X0xdCommitApplier::new(server.uri(), "tok".into(), "bb".repeat(32));
        let rec = commit_record(b"forged", Some("cc".repeat(32)));
        // A 400 (member / sender / event reject) surfaces as Err, never a
        // silent apply.
        assert!(applier.apply(&gid, &rec).await.is_err());
    }
}
