//! [`Signer`] trait + the [`X0xdSigner`] implementation that delegates
//! signing to a running `x0xd` daemon.
//!
//! `MlDsaSigner` (local ML-DSA-65 keypair via `saorsa-pqc`) and
//! `StaticKeySigner` (test fixture) live in `fetchit-relay-client`
//! because they pull the heavy PQ key-material dep tree. Anything
//! that only ever talks to a live x0xd — including publishers like
//! etch>it — can depend on this crate alone.

use crate::discovery::base_url_from_api_port_line;
use crate::error::X0xdError;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_proto::{derive_agent_id, AGENT_SIGN_CONTEXT, AGENT_SIGN_SCHEME_ID};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
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
///
/// # x0xd port self-healing
///
/// When constructed via [`Self::connect_with_port_file`], the signer
/// holds a reference to the daemon's `api.port` discovery file. On a
/// `reqwest::Error::is_connect()` failure during signing (i.e. the
/// daemon has restarted on a new port and the cached `base_url` is
/// stale), the signer re-reads `api.port`, swaps the URL in-place
/// (under `RwLock`), and retries the request **once** before
/// surfacing the error. This turns a daemon restart into a one-RTT
/// hiccup instead of a hard outage for every long-running consumer.
/// The default [`Self::connect`] constructor keeps the previous
/// no-self-heal semantics for tests and unit consumers.
pub struct X0xdSigner {
    base_url: Arc<RwLock<Url>>,
    port_file: Option<PathBuf>,
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
        Self::connect_inner(base_url, api_token.into(), None).await
    }

    /// Like [`Self::connect`] but caches the path to x0xd's `api.port`
    /// discovery file and self-heals the cached base URL on transport-
    /// level connection failures. Use this for long-lived consumers
    /// (chat-peer, desktop app, fetch>it agent bridges) that should
    /// survive a daemon restart without exiting.
    ///
    /// `port_file` is the path x0xd writes its bound HTTP port to (the
    /// default systemd rig writes `~/.local/share/x0x/api.port`). The
    /// initial `base_url` is read from this file at construction time.
    pub async fn connect_with_port_file(
        port_file: PathBuf,
        api_token: impl Into<String>,
    ) -> Result<Self, X0xdError> {
        let url = read_port_file(&port_file)?;
        Self::connect_inner(url, api_token.into(), Some(port_file)).await
    }

    async fn connect_inner(
        base_url: Url,
        api_token: String,
        port_file: Option<PathBuf>,
    ) -> Result<Self, X0xdError> {
        // no_proxy: loopback-only daemon; never route 127.0.0.1 through
        // an ambient corporate proxy. See version.rs for the rationale.
        let http = HttpClient::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()?;
        let mut signer = Self {
            base_url: Arc::new(RwLock::new(base_url)),
            port_file,
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

    /// Clone the cached base URL we're talking to. Useful for logging.
    /// When self-healing is enabled, the returned value reflects the
    /// most recently resolved port — successive calls may differ if
    /// x0xd has restarted.
    ///
    /// On a poisoned lock (i.e. another task panicked mid-update,
    /// which is itself unrecoverable), this falls back to the inner
    /// value via `into_inner`-style read so the surfaceable error is
    /// the upstream transport one rather than a re-raised lock panic.
    #[must_use]
    pub fn base_url(&self) -> Url {
        match self.base_url.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    async fn post_sign(&self, payload: &[u8]) -> Result<AgentSignResponse, X0xdError> {
        match self.post_sign_once(payload).await {
            Err(X0xdError::Http(e)) if e.is_connect() && self.port_file.is_some() => {
                // x0xd is unreachable at the cached port. Re-read the
                // discovery file; if the port has drifted, swap the URL
                // and retry once. Any failure to re-resolve falls back
                // to surfacing the original connect error.
                if self.try_re_resolve_port() {
                    self.post_sign_once(payload).await
                } else {
                    Err(X0xdError::Http(e))
                }
            }
            other => other,
        }
    }

    async fn post_sign_once(&self, payload: &[u8]) -> Result<AgentSignResponse, X0xdError> {
        // x0x >= 0.29 mandates a `context` on `/agent/sign`: the daemon signs
        // `assemble_agent_sign_buffer(context, payload)`, never the raw payload.
        // Sending the shared `AGENT_SIGN_CONTEXT` makes an x0xd-signed payload
        // reproduce byte-for-byte what the daemonless `MlDsaSigner` produces, so
        // the two signing paths cross-verify. The warmup call rides the same
        // context (its signature is discarded).
        let body = serde_json::json!({
            "context": AGENT_SIGN_CONTEXT,
            "payload_b64": B64.encode(payload),
        });
        let url = self.base_url().join("agent/sign")?;
        let resp = self
            .http
            .post(url)
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

    /// Re-read the cached `api.port` discovery file and swap the
    /// base URL in-place when the port has drifted. Returns `true` on
    /// a successful swap (caller should retry), `false` otherwise (the
    /// file is missing, unparseable, or the port hasn't changed —
    /// retrying won't help).
    fn try_re_resolve_port(&self) -> bool {
        let Some(path) = self.port_file.as_ref() else {
            return false;
        };
        let new_url = match read_port_file(path) {
            Ok(u) => u,
            Err(e) => {
                eprintln!(
                    "[x0xd-signer] port self-heal: re-read {} failed: {e}",
                    path.display(),
                );
                return false;
            }
        };
        let Ok(mut guard) = self.base_url.write() else {
            return false;
        };
        if *guard == new_url {
            // Same port — re-resolving wouldn't change anything, so
            // there's no point retrying.
            return false;
        }
        eprintln!(
            "[x0xd-signer] port self-heal: re-resolved {} -> {}",
            *guard, new_url,
        );
        *guard = new_url;
        true
    }
}

/// Read the x0xd `api.port` discovery file and return the corresponding
/// HTTP base URL. Shared between [`X0xdSigner::connect_with_port_file`]
/// and the self-healing path so the parsing logic is in one place.
fn read_port_file(path: &std::path::Path) -> Result<Url, X0xdError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| X0xdError::Invalid(format!("read {}: {e}", path.display())))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(X0xdError::Invalid(format!(
            "empty api.port at {}",
            path.display()
        )));
    }
    let base = base_url_from_api_port_line(trimmed);
    Url::parse(&base).map_err(|e| X0xdError::Invalid(format!("parse api.port url: {e}")))
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
        if resp.algorithm.as_deref() != Some(AGENT_SIGN_SCHEME_ID) {
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
            "algorithm": AGENT_SIGN_SCHEME_ID,
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
    async fn connect_with_port_file_reads_initial_url() {
        // A wiremock server stands in for x0xd; write its base URL into
        // a temp api.port file in the canonical `127.0.0.1:<port>` shape
        // and assert the signer connects against it.
        let server = MockServer::start().await;
        let host_port = server.uri().trim_start_matches("http://").to_owned();

        let pubkey = vec![0u8; 32];
        let derived = derive_agent_id(&pubkey);
        let agent_id_hex = hex::encode(derived);

        Mock::given(method("POST"))
            .and(path("/agent/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fake_response_body(
                &agent_id_hex,
                &B64.encode(&pubkey),
                &B64.encode([0u8; 8]),
            )))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let port_file = tmp.path().join("api.port");
        std::fs::write(&port_file, &host_port).unwrap();

        let signer = X0xdSigner::connect_with_port_file(port_file.clone(), "tok")
            .await
            .expect("connect via port file");
        assert!(signer.base_url().as_str().contains(&host_port));
        assert_eq!(signer.agent_id(), derived);
    }

    #[tokio::test]
    async fn self_heal_swaps_url_on_connect_failure_and_retries() {
        // Stand up the "live" server, point api.port at a clearly-dead
        // port first so the cached base URL is stale. The first
        // `sign` attempt will fail with connect-refused, the self-heal
        // path will re-read api.port, swap to the live URL, and the
        // retry will succeed.
        let server = MockServer::start().await;
        let host_port = server.uri().trim_start_matches("http://").to_owned();

        let pubkey = vec![0u8; 32];
        let derived = derive_agent_id(&pubkey);
        let agent_id_hex = hex::encode(derived);

        Mock::given(method("POST"))
            .and(path("/agent/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fake_response_body(
                &agent_id_hex,
                &B64.encode(&pubkey),
                &B64.encode([0u8; 8]),
            )))
            .mount(&server)
            .await;

        // First make the file point at the LIVE server so connect() in
        // the constructor succeeds (the warmup round-trip exercises
        // post_sign). Then rewrite the file to point at the live server
        // (no-op) and seed the signer's cached base URL at a dead port
        // by direct write — this simulates x0xd having restarted on a
        // new port AFTER the signer was constructed.
        let tmp = tempfile::tempdir().unwrap();
        let port_file = tmp.path().join("api.port");
        std::fs::write(&port_file, &host_port).unwrap();
        let signer = X0xdSigner::connect_with_port_file(port_file.clone(), "tok")
            .await
            .expect("initial connect");

        // Force the cached URL to point at a port that will refuse
        // connections; api.port still has the live URL so self-heal
        // recovers on the next call.
        {
            let mut g = signer.base_url.write().unwrap();
            *g = Url::parse("http://127.0.0.1:1/").expect("dead url parses");
        }

        let sig = signer
            .sign(b"replay-after-port-drift")
            .await
            .expect("sign retries");
        assert!(!sig.is_empty());
        // After self-heal, the cached URL is back to the live server.
        assert!(signer.base_url().as_str().contains(&host_port));
    }

    #[tokio::test]
    async fn self_heal_disabled_without_port_file() {
        // The plain `connect` constructor does NOT enable self-heal.
        // A connect failure on a subsequent `sign` should propagate as
        // an Http error rather than triggering a re-resolve attempt.
        let server = MockServer::start().await;
        let host_port = server.uri().trim_start_matches("http://").to_owned();

        let pubkey = vec![0u8; 32];
        let derived = derive_agent_id(&pubkey);
        let agent_id_hex = hex::encode(derived);

        Mock::given(method("POST"))
            .and(path("/agent/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fake_response_body(
                &agent_id_hex,
                &B64.encode(&pubkey),
                &B64.encode([0u8; 8]),
            )))
            .mount(&server)
            .await;

        let url = Url::parse(&format!("http://{host_port}/")).unwrap();
        let signer = X0xdSigner::connect(url, "tok").await.expect("connect");

        // Same forced-stale state as the self-heal test — but this
        // signer has no port_file, so the sign should fail outright.
        {
            let mut g = signer.base_url.write().unwrap();
            *g = Url::parse("http://127.0.0.1:1/").expect("dead url parses");
        }
        let err = signer.sign(b"no-self-heal").await.unwrap_err();
        assert!(
            err.contains("connect") || err.contains("error") || err.contains("connection"),
            "expected transport error, got {err}",
        );
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
