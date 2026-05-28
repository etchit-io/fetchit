//! Pluggable signer abstraction.
//!
//! Three implementations ship:
//!
//! - [`MlDsaSigner`] — local ML-DSA-65 keypair via `saorsa-pqc`. Use
//!   when there is no x0xd around.
//! - [`X0xdSigner`] — bridge to a running `x0xd` daemon's `/agent/sign`
//!   endpoint, so the relay session uses the user's existing x0x
//!   identity. Preferred path for the desktop / mobile clients.
//! - [`StaticKeySigner`] — deterministic fixture for tests that pair
//!   the client with the server's `AcceptAllVerifier`.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_proto::derive_agent_id;
use reqwest::Client as HttpClient;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaVariant};
use serde::Deserialize;
use std::time::Duration;
use url::Url;

use crate::error::ClientError;

/// Anything that can produce an ML-DSA-65 signature for a challenge.
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

/// Test signer with deterministic outputs.
///
/// Use only in tests or controlled local-dev; pairs with the server's
/// `AcceptAllVerifier`.
pub struct StaticKeySigner {
    agent_id: [u8; 32],
    public_key: Vec<u8>,
    fixed_signature: Vec<u8>,
}

impl StaticKeySigner {
    /// Build a signer from a public key — agent id is derived using
    /// the shared [`derive_agent_id`] convention.
    #[must_use]
    pub fn from_public_key(public_key: Vec<u8>) -> Self {
        let agent_id = derive_agent_id(&public_key);
        Self {
            agent_id,
            public_key,
            fixed_signature: vec![0u8; 64],
        }
    }
}

#[async_trait]
impl Signer for StaticKeySigner {
    fn agent_id(&self) -> [u8; 32] {
        self.agent_id
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.fixed_signature.clone())
    }
}

/// Production signer backed by a real ML-DSA-65 keypair.
pub struct MlDsaSigner {
    dsa: MlDsa,
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
    public_key_bytes: Vec<u8>,
    agent_id: [u8; 32],
}

impl MlDsaSigner {
    /// Generate a fresh ML-DSA-65 keypair.
    ///
    /// # Errors
    /// Returns a string error if `saorsa-pqc` keygen fails.
    pub fn generate() -> Result<Self, String> {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (public_key, secret_key) = dsa.generate_keypair().map_err(|e| e.to_string())?;
        let public_key_bytes = public_key.to_bytes();
        let agent_id = derive_agent_id(&public_key_bytes);
        Ok(Self {
            dsa,
            public_key,
            secret_key,
            public_key_bytes,
            agent_id,
        })
    }

    /// Reconstruct from previously-serialised raw keypair bytes.
    ///
    /// # Errors
    /// Returns a string error when either byte string is malformed.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, String> {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let public_key = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, public_key)
            .map_err(|e| e.to_string())?;
        let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, secret_key)
            .map_err(|e| e.to_string())?;
        let public_key_bytes = public_key.to_bytes();
        let agent_id = derive_agent_id(&public_key_bytes);
        Ok(Self {
            dsa,
            public_key,
            secret_key,
            public_key_bytes,
            agent_id,
        })
    }

    /// The signer's secret-key bytes (caller is responsible for safe storage).
    #[must_use]
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes()
    }

    /// Borrow the signer's public key value.
    #[must_use]
    pub fn public_key_value(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
}

#[async_trait]
impl Signer for MlDsaSigner {
    fn agent_id(&self) -> [u8; 32] {
        self.agent_id
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.dsa
            .sign(&self.secret_key, message)
            .map(|sig| sig.to_bytes())
            .map_err(|e| e.to_string())
    }
}

/// Signer that delegates ML-DSA-65 operations to a local `x0xd`
/// daemon's `POST /agent/sign` endpoint, so the relay session uses the
/// user's existing x0x identity (same agent id everywhere in the
/// ecosystem).
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
    /// Returns [`ClientError::AuthRejected`] if x0xd rejects the bearer
    /// token, returns a non-OK body, or omits the agent identity fields.
    /// Returns [`ClientError::Http`] / [`ClientError::Url`] for transport
    /// failures.
    pub async fn connect(base_url: Url, api_token: impl Into<String>) -> Result<Self, ClientError> {
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
            return Err(ClientError::AuthRejected(format!(
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

    async fn post_sign(&self, payload: &[u8]) -> Result<AgentSignResponse, ClientError> {
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
            return Err(ClientError::AuthRejected(format!(
                "x0xd /agent/sign returned {}",
                resp.status()
            )));
        }
        let parsed: AgentSignResponse = resp.json().await?;
        if !parsed.ok {
            return Err(ClientError::AuthRejected(format!(
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

fn decode_public_key(resp: &AgentSignResponse) -> Result<Vec<u8>, ClientError> {
    let Some(b64) = resp.public_key_b64.as_deref() else {
        return Err(ClientError::AuthRejected(
            "x0xd /agent/sign response missing public_key_b64".into(),
        ));
    };
    B64.decode(b64)
        .map_err(|e| ClientError::AuthRejected(format!("public_key_b64 decode: {e}")))
}

fn decode_agent_id(resp: &AgentSignResponse) -> Result<[u8; 32], ClientError> {
    let Some(hex_str) = resp.agent_id.as_deref() else {
        return Err(ClientError::AuthRejected(
            "x0xd /agent/sign response missing agent_id".into(),
        ));
    };
    let raw = hex::decode(hex_str)
        .map_err(|e| ClientError::AuthRejected(format!("agent_id hex decode: {e}")))?;
    raw.try_into().map_err(|v: Vec<u8>| {
        ClientError::AuthRejected(format!("agent_id expected 32 bytes, got {}", v.len()))
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_signer_signs_and_self_verifies() {
        let signer = MlDsaSigner::generate().unwrap();
        let msg = b"verify me";
        let sig = signer.sign(msg).await.unwrap();

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(signer.public_key_value(), msg, &sig_value)
            .unwrap());
    }

    #[tokio::test]
    async fn from_bytes_round_trips() {
        let original = MlDsaSigner::generate().unwrap();
        let pk = original.public_key();
        let sk = original.secret_key_bytes();
        let restored = MlDsaSigner::from_bytes(&pk, &sk).unwrap();
        assert_eq!(restored.agent_id(), original.agent_id());
        assert_eq!(restored.public_key(), original.public_key());

        let msg = b"after restore";
        let sig = restored.sign(msg).await.unwrap();
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa
            .verify(restored.public_key_value(), msg, &sig_value)
            .unwrap());
    }
}
