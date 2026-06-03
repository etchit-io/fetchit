//! Typed wrappers over x0xd's MLS HTTP+SSE surface (TreeKEM-backed since
//! x0xd v0.20.1). Consumed by the fetchit-chat groups module for the
//! encrypted group send/receive path; the daemon owns the MLS ratchet.

use crate::error::X0xdError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// Validate that `group_id` is the 64-hex shape every x0xd
/// `/groups/{group_id}/secure/*` endpoint expects, BEFORE the value
/// is interpolated into a URL path. Without this, an external caller
/// could pass `../` or other path-traversal sequences and target
/// arbitrary x0xd HTTP endpoints from this process — fetchit-chat's
/// `messages::send_private_group` already filters upstream, but
/// etch>it / future tooling consuming `SecureGroupsEndpoint` doesn't.
///
/// Returns the validated `&str` so callsites can chain straight into
/// `format!`. Ascii-hex characters only; any non-hex byte rejects.
fn validate_group_id_hex(s: &str) -> Result<&str, X0xdError> {
    if s.len() != 64 {
        return Err(X0xdError::Invalid(format!(
            "group_id must be 64 hex chars, got {}",
            s.len()
        )));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(X0xdError::Invalid("group_id must be ASCII hex".into()));
    }
    Ok(s)
}

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

#[derive(Serialize)]
struct EncryptRequest<'a> {
    payload_b64: &'a str,
}

#[derive(Deserialize)]
struct EncryptResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    ciphertext_b64: Option<String>,
    #[serde(default)]
    nonce_b64: Option<String>,
    #[serde(default)]
    secret_epoch: Option<u32>,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext_b64: &'a str,
    nonce_b64: &'a str,
    secret_epoch: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_agent_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    payload_b64: Option<String>,
}

#[derive(Serialize)]
struct PublishRequest<'a> {
    topic: &'a str,
    payload: &'a str,
}

#[derive(Deserialize)]
struct PublishResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
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

    /// Encrypt one application frame under the group's current MLS
    /// epoch. Returns ciphertext + nonce + epoch the recipient needs
    /// to feed to [`Self::decrypt`].
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] on transport
    /// failure or URL join failure, [`X0xdError::Rejected`] if x0xd
    /// returns non-2xx, `ok=false`, or omits one of the response
    /// fields needed to construct an [`EncryptedFrame`].
    pub async fn encrypt(
        &self,
        group_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedFrame, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let payload_b64 = B64.encode(plaintext);
        let path = format!("groups/{group_id}/secure/encrypt");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&EncryptRequest {
                payload_b64: &payload_b64,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /secure/encrypt returned {status}: {body}"
            )));
        }
        let resp: EncryptResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        let ciphertext_b64 = resp
            .ciphertext_b64
            .ok_or_else(|| X0xdError::Rejected("encrypt response missing ciphertext_b64".into()))?;
        let nonce_b64 = resp
            .nonce_b64
            .ok_or_else(|| X0xdError::Rejected("encrypt response missing nonce_b64".into()))?;
        let secret_epoch = resp
            .secret_epoch
            .ok_or_else(|| X0xdError::Rejected("encrypt response missing secret_epoch".into()))?;
        Ok(EncryptedFrame {
            ciphertext_b64,
            nonce_b64,
            secret_epoch,
        })
    }

    /// Decrypt one application frame. `sender_agent_id` is optional;
    /// when supplied x0xd checks the membership / identity binding.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] on transport
    /// failure, [`X0xdError::Rejected`] if x0xd returns non-2xx,
    /// `ok=false`, or omits `payload_b64`, or if the base64 payload
    /// is malformed.
    pub async fn decrypt(
        &self,
        group_id: &str,
        frame: &EncryptedFrame,
        sender_agent_id: Option<&str>,
    ) -> Result<Vec<u8>, X0xdError> {
        let group_id = validate_group_id_hex(group_id)?;
        let path = format!("groups/{group_id}/secure/decrypt");
        let url = self.base_url.join(&path).map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&DecryptRequest {
                ciphertext_b64: &frame.ciphertext_b64,
                nonce_b64: &frame.nonce_b64,
                secret_epoch: frame.secret_epoch,
                sender_agent_id,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /secure/decrypt returned {status}: {body}"
            )));
        }
        let resp: DecryptResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        let payload_b64 = resp
            .payload_b64
            .ok_or_else(|| X0xdError::Rejected("decrypt response missing payload_b64".into()))?;
        B64.decode(&payload_b64)
            .map_err(|e| X0xdError::Rejected(format!("decrypt payload base64: {e}")))
    }

    /// Publish a base64-encoded payload onto an x0xd gossip topic.
    ///
    /// The v1.0 fetchit-chat group path does NOT use this (chat
    /// messages tunnel through `RelayTransport` instead per
    /// `private/m2-decisions.md` Decision 1). Kept available so etch>it
    /// and future tooling can address the gossip plane directly.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] on transport
    /// failure, [`X0xdError::Rejected`] if x0xd returns non-2xx or
    /// `ok=false`.
    pub async fn publish(&self, topic: &str, payload_b64: &str) -> Result<(), X0xdError> {
        let url = self.base_url.join("publish").map_err(X0xdError::Url)?;
        let raw = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&PublishRequest {
                topic,
                payload: payload_b64,
            })
            .send()
            .await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /publish returned {status}: {body}"
            )));
        }
        let resp: PublishResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd returned ok=false without error message".into()
            })));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 64-hex group id matching the wire shape x0xd's `POST /groups`
    /// returns. Doubles as a stable URL-path component for the
    /// wiremock matchers below.
    const TEST_GROUP_HEX: &str = "4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e";

    #[tokio::test]
    async fn encrypt_rejects_empty_group_id_before_http() {
        // P2 from Bob's review: path-traversal via free-form group_id
        // would otherwise let an external caller target arbitrary
        // x0xd HTTP endpoints from this process. `validate_group_id_hex`
        // rejects locally — no HTTP traffic on a malformed id.
        let server = MockServer::start().await;
        // Mount nothing — any attempted HTTP call would surface as a
        // wiremock-side 404, which is a different X0xdError shape.
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint.encrypt("", b"hi").await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(
                    msg.contains("64 hex chars"),
                    "expected length message, got: {msg}",
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt_rejects_wrong_length_group_id() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        // 63 chars — one short of the expected 64.
        let almost = "a".repeat(63);
        let err = endpoint.encrypt(&almost, b"hi").await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("64 hex chars"), "got: {msg}");
                assert!(msg.contains("63"), "should report observed length: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypt_rejects_non_hex_group_id_including_path_traversal() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        // Length 64 but containing `../` — the exact path-traversal
        // shape the validator is here to refuse.
        let traversal = format!("../{}", "a".repeat(61));
        assert_eq!(traversal.len(), 64);
        let err = endpoint.encrypt(&traversal, b"hi").await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("ASCII hex"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_wrong_length_group_id() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        let err = endpoint.decrypt("short", &frame, None).await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("64 hex chars"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_non_hex_group_id() {
        let server = MockServer::start().await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        // 64 chars but contains a Z (non-hex).
        let mut bad = "a".repeat(63);
        bad.push('Z');
        let err = endpoint.decrypt(&bad, &frame, None).await.unwrap_err();
        match err {
            X0xdError::Invalid(msg) => {
                assert!(msg.contains("ASCII hex"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

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

    #[tokio::test]
    async fn encrypt_posts_payload_b64_and_parses_frame() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/encrypt"))
            .and(body_partial_json(serde_json::json!({
                "payload_b64": "aGk=",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let f = endpoint.encrypt(TEST_GROUP_HEX, b"hi").await.unwrap();
        assert_eq!(f.secret_epoch, 3);
        assert_eq!(f.ciphertext_b64, "Y3Q=");
        assert_eq!(f.nonce_b64, "bm9uY2U=");
    }

    #[tokio::test]
    async fn encrypt_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/encrypt"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string(r#"{"ok":false,"error":"not a member"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint.encrypt(TEST_GROUP_HEX, b"hi").await.unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("403"));
                assert!(msg.contains("not a member"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_posts_full_frame_and_returns_plaintext_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        let plaintext = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap();
        assert_eq!(plaintext, b"hi");
    }

    #[tokio::test]
    async fn decrypt_passes_sender_agent_id_when_supplied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "sender_agent_id": "abcd1234",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        endpoint
            .decrypt(TEST_GROUP_HEX, &frame, Some("abcd1234"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decrypt_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"ok":false,"error":"stale epoch"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        let err = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("403"), "status code missing: {msg}");
                assert!(msg.contains("stale epoch"), "body missing: {msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_returns_rejected_when_response_payload_b64_is_malformed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/4d216f18809c131d001294c38a90e91d36c765882c6e18ad320e64f55df9492e/secure/decrypt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "!!!not-valid-base64!!!",
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        let err = endpoint
            .decrypt(TEST_GROUP_HEX, &frame, None)
            .await
            .unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(
                    msg.contains("decrypt payload base64"),
                    "expected base64 context in message: {msg}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sends_topic_and_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publish"))
            .and(body_partial_json(serde_json::json!({
                "topic": "x0x.group.G.chat/general",
                "payload": "aGk=",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        endpoint
            .publish("x0x.group.G.chat/general", "aGk=")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn publish_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publish"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_string(r#"{"ok":false,"error":"rate limited"}"#),
            )
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let endpoint = SecureGroupsEndpoint::new(base, "test-token").unwrap();
        let err = endpoint.publish("t", "x").await.unwrap_err();
        match err {
            X0xdError::Rejected(msg) => {
                assert!(msg.contains("429"));
                assert!(msg.contains("rate limited"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
