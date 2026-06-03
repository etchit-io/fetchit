//! Typed wrappers over x0xd's MLS HTTP+SSE surface (TreeKEM-backed since
//! x0xd v0.20.1). Consumed by the fetchit-chat groups module for the
//! encrypted group send/receive path; the daemon owns the MLS ratchet.

use crate::error::X0xdError;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// One encrypted application-data frame returned by `/secure/encrypt`
/// and accepted by `/secure/decrypt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFrame {
    /// Base64 `ChaCha20-Poly1305` ciphertext.
    pub ciphertext_b64: String,
    /// Base64 12-byte nonce.
    pub nonce_b64: String,
    /// MLS epoch (`secret_epoch` on the wire).
    pub secret_epoch: u32,
}

/// Response shape from `POST /groups` for a private-secure group.
#[derive(Clone, Debug, Deserialize)]
pub struct CreatedGroup {
    /// Hex group id assigned by x0xd.
    pub group_id: String,
    /// Gossip topic the group's encrypted frames publish on. Captured
    /// here for callers that opt into x0xd's `/publish` + `/subscribe`
    /// (the M2 chat path uses `RelayTransport` instead per
    /// `private/m2-decisions.md` Decision 1).
    pub chat_topic: String,
}

#[derive(Deserialize)]
struct CreatedGroupResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    chat_topic: Option<String>,
}

/// Endpoint wrapper around the x0xd `/groups` + `/secure/*` surface.
/// Owns its own HTTP client + bearer auth — same pattern as
/// [`crate::X0xdSigner`]. Construct via [`SecureGroupsEndpoint::new`].
pub struct SecureGroupsEndpoint {
    base_url: Url,
    api_token: String,
    http: HttpClient,
}

impl std::fmt::Debug for SecureGroupsEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureGroupsEndpoint")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct CreatePrivateSecureRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    preset: &'static str,
    discoverability: &'static str,
}

impl SecureGroupsEndpoint {
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

    /// Create a private MLS group with `TreeKEM` activation
    /// (`preset=private_secure` + `discoverability=Hidden`). Returns
    /// the assigned group id and the gossip chat topic.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] on transport failure,
    /// [`X0xdError::Url`] if the base URL fails to join, or
    /// [`X0xdError::Rejected`] if x0xd returns a non-2xx body or a
    /// body that fails the schema (missing `group_id` / `chat_topic`).
    pub async fn create_private_secure(
        &self,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<CreatedGroup, X0xdError> {
        let url = self.base_url.join("groups").map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&CreatePrivateSecureRequest {
                name,
                display_name,
                preset: "private_secure",
                discoverability: "Hidden",
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /groups returned {status}: {body}"
            )));
        }
        let resp: CreatedGroupResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        let group_id = resp
            .group_id
            .ok_or_else(|| X0xdError::Rejected("x0xd response missing group_id".into()))?;
        let chat_topic = resp
            .chat_topic
            .ok_or_else(|| X0xdError::Rejected("x0xd response missing chat_topic".into()))?;
        Ok(CreatedGroup {
            group_id,
            chat_topic,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn encrypted_frame_round_trips_via_serde_json() {
        let f = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 7,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EncryptedFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn encrypted_frame_rejects_missing_epoch() {
        let bad = r#"{"ciphertext_b64":"Y3Q=","nonce_b64":"bm9uY2U="}"#;
        assert!(serde_json::from_str::<EncryptedFrame>(bad).is_err());
    }

    #[tokio::test]
    async fn create_private_secure_sends_correct_preset_and_discoverability() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .and(body_partial_json(serde_json::json!({
                "name": "alpha",
                "preset": "private_secure",
                "discoverability": "Hidden",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": "abc",
                "chat_topic": "x0x.group.abc.chat/general",
            })))
            .mount(&server)
            .await;

        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let g = endpoint.create_private_secure("alpha", None).await.unwrap();
        assert_eq!(g.group_id, "abc");
        assert_eq!(g.chat_topic, "x0x.group.abc.chat/general");
    }

    #[tokio::test]
    async fn create_private_secure_includes_display_name_when_supplied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .and(body_partial_json(serde_json::json!({
                "name": "alpha",
                "display_name": "Alice",
                "preset": "private_secure",
                "discoverability": "Hidden",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": "abc",
                "chat_topic": "x0x.group.abc.chat/general",
            })))
            .mount(&server)
            .await;

        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        endpoint
            .create_private_secure("alpha", Some("Alice"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_private_secure_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_string(r#"{"ok":false,"error":"name already taken"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint
            .create_private_secure("dup", None)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("422"), "status code not in error: {msg}");
                assert!(
                    msg.contains("name already taken"),
                    "body not in error: {msg}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
