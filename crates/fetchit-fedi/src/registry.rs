//! Self-serve actor-registry client (M5.1, Component D).
//!
//! The JSON shapes here are a frozen wire contract shared with
//! `fetchit-bridge-server`; tests pin them against
//! `tests/fixtures/registry-v1/`. See the fixture README for the
//! server-side verification obligations (attestation verify,
//! first-come-first-served handles, same-agent-id continuity,
//! hint-epoch monotonicity).

use crate::attestation::{b64, ActorAttestationV2};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Per-call timeout for registry requests.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Registration / update request body. One shape for both verbs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterActorRequest {
    /// Local handle, client-validated `[A-Za-z0-9_-]{1,64}`.
    pub handle: String,
    /// RSA `SubjectPublicKeyInfo` DER, base64 on the wire.
    #[serde(with = "b64")]
    pub rsa_spki_der: Vec<u8>,
    /// The signed v2 binding the bridge must verify before serving.
    pub attestation_v2: ActorAttestationV2,
}

/// Success body for both verbs.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisterActorResponse {
    /// Canonical actor URL the directory now serves.
    pub actor_url: String,
}

/// Typed failure surface so the UI can render per-cause copy.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// 409: the handle is registered (to this or another agent).
    #[error("handle already registered")]
    HandleTaken,
    /// 422: the bridge rejected the attestation; reason text attached.
    #[error("registry rejected the attestation: {0}")]
    AttestationRejected(String),
    /// 429: per-source rate limit.
    #[error("registry rate limit hit; retry later")]
    RateLimited,
    /// Connection / DNS / TLS / body-read failure.
    #[error("transport: {0}")]
    Transport(String),
    /// Any other non-success status.
    #[error("registry returned HTTP {status}: {body}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// First 256 chars of the response body.
        body: String,
    },
}

/// `POST {base}v1/actors`: first-time registration.
///
/// # Errors
///
/// A [`RegistryError`] per the contract README's response table.
pub async fn register_actor(
    base: &url::Url,
    req: &RegisterActorRequest,
    http: &reqwest::Client,
) -> Result<RegisterActorResponse, RegistryError> {
    let url = base
        .join("v1/actors")
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .post(url)
        .json(req)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    decode_response(resp).await
}

/// `PUT {base}v1/actors/<handle>`: update an existing registration
/// (new hint epoch, new profile address, RSA key rotation). The handle
/// in the path comes from `req.handle` and is path-safe by the crate's
/// handle alphabet; the bridge re-validates.
///
/// # Errors
///
/// A [`RegistryError`] per the contract README's response table.
pub async fn update_actor(
    base: &url::Url,
    req: &RegisterActorRequest,
    http: &reqwest::Client,
) -> Result<RegisterActorResponse, RegistryError> {
    let url = base
        .join(&format!("v1/actors/{}", req.handle))
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .put(url)
        .json(req)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    decode_response(resp).await
}

async fn decode_response(resp: reqwest::Response) -> Result<RegisterActorResponse, RegistryError> {
    let status = resp.status().as_u16();
    match status {
        200 | 201 => resp
            .json()
            .await
            .map_err(|e| RegistryError::Transport(format!("response decode: {e}"))),
        409 => Err(RegistryError::HandleTaken),
        422 => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::AttestationRejected(
                body.chars().take(256).collect(),
            ))
        }
        429 => Err(RegistryError::RateLimited),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::Status {
                status,
                body: body.chars().take(256).collect(),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn contract_request() -> RegisterActorRequest {
        RegisterActorRequest {
            handle: "josh".into(),
            rsa_spki_der: vec![0xDE, 0xAD, 0xBE, 0xEF],
            attestation_v2: ActorAttestationV2 {
                version: 2,
                profile_addr: "a".repeat(64),
                relay_hint: "https://relay.example:8088/".into(),
                hint_epoch_ms: 1_750_000_000_000,
                ml_dsa_pubkey: vec![0x42; 4],
                signature: vec![0x41; 4],
            },
        }
    }

    #[test]
    fn register_request_matches_contract_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/registry-v1/register-request.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(contract_request()).unwrap(), fixture);
    }

    #[test]
    fn register_request_round_trips_through_json() {
        let req = contract_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: RegisterActorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[tokio::test]
    async fn register_posts_to_v1_actors_and_decodes_created() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/actors"))
            .and(body_json(serde_json::to_value(contract_request()).unwrap()))
            .respond_with(ResponseTemplate::new(201).set_body_string(include_str!(
                "../tests/fixtures/registry-v1/register-response.json"
            )))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        let resp = register_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap();
        assert_eq!(resp.actor_url, "https://etchit.io/actors/josh");
    }

    #[tokio::test]
    async fn update_puts_to_handle_path() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/actors/josh"))
            .respond_with(ResponseTemplate::new(200).set_body_string(include_str!(
                "../tests/fixtures/registry-v1/register-response.json"
            )))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        update_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_codes_map_to_typed_errors() {
        for (status, expect) in [(409_u16, "taken"), (429, "rate"), (500, "status")] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/actors"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let base: url::Url = server.uri().parse().unwrap();
            let err = register_actor(&base, &contract_request(), &reqwest::Client::new())
                .await
                .unwrap_err();
            match expect {
                "taken" => assert!(matches!(err, RegistryError::HandleTaken), "got {err:?}"),
                "rate" => assert!(matches!(err, RegistryError::RateLimited), "got {err:?}"),
                _ => assert!(
                    matches!(err, RegistryError::Status { status: 500, .. }),
                    "got {err:?}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn unprocessable_carries_reason_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/actors"))
            .respond_with(ResponseTemplate::new(422).set_body_string("bad attestation"))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        let err = register_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::AttestationRejected(ref r) if r == "bad attestation"),
            "got {err:?}"
        );
    }
}
