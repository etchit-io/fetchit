//! [`Signer`] trait + the [`X0xdSigner`] implementation that delegates
//! signing to a running `x0xd` daemon.
//!
//! `MlDsaSigner` (local ML-DSA-65 keypair via `saorsa-pqc`) and
//! `StaticKeySigner` (test fixture) live in `fetchit-relay-client`
//! because they pull the heavy PQ key-material dep tree. Anything
//! that only ever talks to a live x0xd — including publishers like
//! etch>it — can depend on this crate alone.

use crate::error::X0xdError;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_proto::derive_agent_id;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::time::Duration;
use url::Url;

/// Anything that can produce an ML-DSA-65 signature for a challenge.
///
/// Implementations: [`X0xdSigner`] in this crate; `MlDsaSigner` and
/// `StaticKeySigner` re-exported from `fetchit-relay-client`.
#[async_trait]
pub trait Signer: Send + Sync {
    /// The signer's agent id, encoded as raw 32 bytes.
    fn agent_id(&self) -> [u8; 32];

    /// The signer's ML-DSA-65 public key, raw bytes.
    fn public_key(&self) -> Vec<u8>;

    /// Produce a signature over `message` using the signer's private key.
    ///
    /// # Errors
    /// Returns a static-error string when the underlying signing
    /// service is unreachable or rejects the message.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// Signer that delegates ML-DSA-65 operations to a local `x0xd`
/// daemon's `POST /agent/sign` endpoint, so callers use the user's
/// existing x0x identity (same agent id everywhere in the ecosystem).
///
/// Calls `/agent/sign` once at construction to warm up the cached
/// public key + agent id, then forwards every subsequent `sign` to
/// the same endpoint. The local x0xd holds the private key throughout
/// — this crate never sees it.
pub struct X0xdSigner {
    base_url: Url,
    api_token: String,
    http: HttpClient,
    agent_id: [u8; 32],
    public_key: Vec<u8>,
}

impl std::fmt::Debug for X0xdSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X0xdSigner")
            .field("base_url", &self.base_url)
            .field("agent_id", &hex::encode(&self.agent_id[..4]))
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

/// Domain-separation tag used on the warmup signature so it cannot be
/// mistaken for an auth signature.
const X0XD_WARMUP_DOMAIN: &[u8] = b"fetchit-relay/v1/x0xd-signer-warmup\0";

/// Payload signed during warmup just to retrieve the agent's public key
/// from `/agent/sign`'s response. The signature itself is discarded.
const X0XD_WARMUP_PAYLOAD: &[u8] = b"warmup";

#[derive(Debug, Deserialize)]
struct AgentSignResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    public_key_b64: Option<String>,
    #[serde(default)]
    signature_b64: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
}

impl X0xdSigner {
    /// Connect to `x0xd` at `base_url` and cache its identity.
    ///
    /// `base_url` is the daemon's HTTP root (e.g. `http://127.0.0.1:6464`).
    /// `api_token` is the bearer token x0xd issued for local API access.
    ///
    /// # Errors
    /// Returns [`X0xdError::Rejected`] if x0xd rejects the bearer
    /// token, returns a non-OK body, or omits the agent identity fields.
    /// Returns [`X0xdError::Http`] / [`X0xdError::Url`] for transport
    /// failures.
    pub async fn connect(base_url: Url, api_token: impl Into<String>) -> Result<Self, X0xdError> {
        let api_token = api_token.into();
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let mut signer = Self {
            base_url,
            api_token,
            http,
            agent_id: [0u8; 32],
            public_key: Vec::new(),
        };
        let warmup = build_warmup_payload();
        let resp = signer.post_sign(&warmup).await?;
        let public_key = decode_public_key(&resp)?;
        let agent_id = decode_agent_id(&resp)?;

        let derived = derive_agent_id(&public_key);
        if derived != agent_id {
            return Err(X0xdError::Rejected(format!(
                "x0xd agent_id ({}) does not match derive_agent_id(public_key) ({})",
                hex::encode(agent_id),
                hex::encode(derived),
            )));
        }

        signer.agent_id = agent_id;
        signer.public_key = public_key;
        Ok(signer)
    }

    /// Borrow the base URL we're talking to. Useful for logging.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    async fn post_sign(&self, payload: &[u8]) -> Result<AgentSignResponse, X0xdError> {
        let body = serde_json::json!({
            "payload_b64": B64.encode(payload),
        });
        let resp = self
            .http
            .post(self.base_url.join("agent/sign")?)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(X0xdError::Rejected(format!(
                "x0xd /agent/sign returned {}",
                resp.status()
            )));
        }
        let parsed: AgentSignResponse = resp.json().await?;
        if !parsed.ok {
            return Err(X0xdError::Rejected(format!(
                "x0xd /agent/sign error: {}",
                parsed.error.as_deref().unwrap_or("unknown")
            )));
        }
        Ok(parsed)
    }
}

fn build_warmup_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(X0XD_WARMUP_DOMAIN.len() + X0XD_WARMUP_PAYLOAD.len());
    v.extend_from_slice(X0XD_WARMUP_DOMAIN);
    v.extend_from_slice(X0XD_WARMUP_PAYLOAD);
    v
}

fn decode_public_key(resp: &AgentSignResponse) -> Result<Vec<u8>, X0xdError> {
    let Some(b64) = resp.public_key_b64.as_deref() else {
        return Err(X0xdError::Rejected(
            "x0xd /agent/sign response missing public_key_b64".into(),
        ));
    };
    B64.decode(b64)
        .map_err(|e| X0xdError::Rejected(format!("public_key_b64 decode: {e}")))
}

fn decode_agent_id(resp: &AgentSignResponse) -> Result<[u8; 32], X0xdError> {
    let Some(hex_str) = resp.agent_id.as_deref() else {
        return Err(X0xdError::Rejected(
            "x0xd /agent/sign response missing agent_id".into(),
        ));
    };
    let raw = hex::decode(hex_str)
        .map_err(|e| X0xdError::Rejected(format!("agent_id hex decode: {e}")))?;
    raw.try_into().map_err(|v: Vec<u8>| {
        X0xdError::Rejected(format!("agent_id expected 32 bytes, got {}", v.len()))
    })
}

#[async_trait]
impl Signer for X0xdSigner {
    fn agent_id(&self) -> [u8; 32] {
        self.agent_id
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self.post_sign(message).await.map_err(|e| e.to_string())?;
        let Some(sig_b64) = resp.signature_b64.as_deref() else {
            return Err("x0xd /agent/sign response missing signature_b64".into());
        };
        if resp.algorithm.as_deref() != Some("x0x.agent-sign.v1.ml-dsa-65") {
            return Err(format!("unexpected algorithm tag {:?}", resp.algorithm));
        }
        B64.decode(sig_b64).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fake_response_body(
        agent_id_hex: &str,
        pubkey_b64: &str,
        sig_b64: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "agent_id": agent_id_hex,
            "public_key_b64": pubkey_b64,
            "signature_b64": sig_b64,
            "algorithm": "x0x.agent-sign.v1.ml-dsa-65",
        })
    }

    #[tokio::test]
    async fn connect_rejects_when_derive_agent_id_mismatch() {
        let server = MockServer::start().await;
        let pubkey = b"not-a-real-key".to_vec();
        let wrong_agent_id = hex::encode([0u8; 32]);
        Mock::given(method("POST"))
            .and(path("/agent/sign"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fake_response_body(
                &wrong_agent_id,
                &B64.encode(&pubkey),
                &B64.encode([0u8; 8]),
            )))
            .mount(&server)
            .await;

        let url = Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = X0xdSigner::connect(url, "tok").await.unwrap_err();
        assert!(matches!(err, X0xdError::Rejected(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn connect_rejects_on_non_ok_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/agent/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": false,
                "error": "boom",
            })))
            .mount(&server)
            .await;

        let url = Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = X0xdSigner::connect(url, "tok").await.unwrap_err();
        assert!(matches!(err, X0xdError::Rejected(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn connect_rejects_on_401() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/agent/sign"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let url = Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = X0xdSigner::connect(url, "wrong-token").await.unwrap_err();
        assert!(matches!(err, X0xdError::Rejected(_)), "got {err:?}");
    }
}
