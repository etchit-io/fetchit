//! Typed wrapper over x0xd's `/announce` endpoint.
//!
//! Background: x0xd's MLS `MemberJoined` event applier verifies the
//! joiner's signature against the network-published `agent_id ->
//! public_key` binding (the identity announcement). Without a prior
//! `POST /announce` the inviter's signature-verify fails before the
//! `TreeKEM` `add_member` runs even when gossip is fully connected,
//! so private-group invites silently 404 at the receiver.
//! Long-running chat clients (chat-peer, desktop app) must announce
//! once at startup so any subsequent `groups::create_private`
//! user-flow can complete end-to-end.

use crate::error::X0xdError;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// Endpoint wrapper around x0xd's `POST /announce`. Owns its own
/// HTTP client + bearer auth, same shape as
/// [`crate::SecureGroupsEndpoint`]. Construct via
/// [`IdentityEndpoint::new`].
pub struct IdentityEndpoint {
    base_url: Url,
    api_token: String,
    http: HttpClient,
}

impl std::fmt::Debug for IdentityEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityEndpoint")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AnnounceRequest {
    include_user_identity: bool,
    human_consent: bool,
}

#[derive(Deserialize)]
struct AnnounceResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

impl IdentityEndpoint {
    /// Build a new endpoint against an x0xd daemon at `base_url`,
    /// authenticated with `api_token`.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] if the underlying reqwest client
    /// fails to build (timeout/TLS configuration error).
    pub fn new(base_url: Url, api_token: impl Into<String>) -> Result<Self, X0xdError> {
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base_url,
            api_token: api_token.into(),
            http,
        })
    }

    /// Publish this agent's `agent_id -> public_key` binding to the
    /// gossip identity store. Idempotent: x0xd republishes its own
    /// announcement on every call, so chat clients can safely invoke
    /// once per startup without coordinating with prior runs.
    ///
    /// `include_user_identity` controls whether the user-level
    /// identity is announced alongside the agent identity. Default
    /// `false` for v1.0 chat clients — only the agent identity is
    /// required for the MLS `MemberJoined` signature-verify path.
    /// `human_consent` is x0xd's audit flag for human-attested
    /// announcements; chat clients pass `false` because the
    /// announcement is a routine startup step, not a user action.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] on transport failure,
    /// [`X0xdError::Url`] if the base URL fails to join, or
    /// [`X0xdError::Rejected`] if x0xd returns a non-2xx body or
    /// `{ok: false}`.
    pub async fn announce(
        &self,
        include_user_identity: bool,
        human_consent: bool,
    ) -> Result<(), X0xdError> {
        let url = self.base_url.join("announce").map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&AnnounceRequest {
                include_user_identity,
                human_consent,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /announce returned {status}: {body}"
            )));
        }
        let resp: AnnounceResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd /announce returned ok=false without error message".into()
            })));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn announce_posts_request_body_and_parses_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/announce"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(serde_json::json!({
                "include_user_identity": false,
                "human_consent": false,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "include_user_identity": false,
            })))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = IdentityEndpoint::new(base, "tok").unwrap();
        endpoint.announce(false, false).await.expect("announce ok");
    }

    #[tokio::test]
    async fn announce_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/announce"))
            .respond_with(ResponseTemplate::new(400).set_body_string("daemon-not-ready"))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = IdentityEndpoint::new(base, "tok").unwrap();
        let err = endpoint
            .announce(false, false)
            .await
            .expect_err("expected announce to fail");
        assert!(matches!(err, X0xdError::Rejected(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("400"), "msg: {msg}");
        assert!(msg.contains("daemon-not-ready"), "msg: {msg}");
    }

    #[tokio::test]
    async fn announce_surfaces_ok_false_body_as_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/announce"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": false,
                "error": "gossip not ready",
            })))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = IdentityEndpoint::new(base, "tok").unwrap();
        let err = endpoint
            .announce(false, false)
            .await
            .expect_err("expected announce to fail");
        match err {
            X0xdError::Rejected(msg) => assert!(msg.contains("gossip not ready"), "msg: {msg}"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
