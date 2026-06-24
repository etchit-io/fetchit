//! Internal HTTP client shared by the typed x0xd endpoint modules.
//!
//! Wraps `reqwest` to add the bearer auth header on every request and
//! normalize daemon error responses into [`ChatError::Daemon`].
//!
//! Naming: this used to be `transport.rs`. It was renamed to free up
//! the `transport` name for the message-routing trait that selects
//! between relay / LAN-direct / future P2P paths. This file is the
//! HTTP-to-x0xd seam only.
//!
//! # x0xd port self-healing
//!
//! When constructed via [`Http::new_with_port_file`], the wrapper holds
//! a reference to the daemon's `api.port` discovery file. On a
//! transport-level connect failure (cached port stale because x0xd
//! restarted on a new port), it re-reads `api.port`, swaps the cached
//! base URL in-place under `RwLock`, and retries the request once
//! before surfacing the original error. The plain [`Http::new`]
//! constructor keeps the previous no-self-heal semantics for tests
//! and unit consumers. Mirrors the
//! [`x0xd_client::X0xdSigner`] self-heal pattern so long-running
//! chat-side consumers survive a daemon restart in-process instead of
//! burning a systemd `Restart=` cycle.

use crate::error::{ChatError, Result};
use reqwest::{Method, RequestBuilder, Response};
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use x0xd_client::base_url_from_api_port_line;

/// Lightweight bearer-authenticated HTTP transport.
///
/// Holds two clients: a short-timeout one for normal request/response
/// endpoints, and a no-timeout one for SSE streams whose bodies stay
/// open indefinitely.
#[derive(Debug, Clone)]
pub(crate) struct Http {
    inner: reqwest::Client,
    streaming: reqwest::Client,
    base_url: Arc<RwLock<String>>,
    port_file: Option<PathBuf>,
    token: String,
}

impl Http {
    pub(crate) fn new(base_url: String, token: String) -> Result<Self> {
        Self::new_inner(base_url, token, None)
    }

    /// Like [`Self::new`] but caches the path to x0xd's `api.port`
    /// discovery file and self-heals the cached base URL on transport-
    /// level connect failures. Use for long-running consumers
    /// (chat-peer, desktop app) that should survive a daemon restart
    /// without a process bounce.
    pub(crate) fn new_with_port_file(port_file: PathBuf, token: String) -> Result<Self> {
        let initial = read_port_file(&port_file)?;
        Self::new_inner(initial, token, Some(port_file))
    }

    fn new_inner(base_url: String, token: String, port_file: Option<PathBuf>) -> Result<Self> {
        let inner = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        let streaming = reqwest::Client::builder().pool_idle_timeout(None).build()?;
        Ok(Self {
            inner,
            streaming,
            base_url: Arc::new(RwLock::new(base_url)),
            port_file,
            token,
        })
    }

    /// Base URL the wrapper dials (e.g. `http://127.0.0.1:12700`).
    /// Returned by value because self-healing may have swapped it; a
    /// `&str` slice would alias the lock guard and force callers to
    /// hold it for the duration of the borrow.
    ///
    /// On a poisoned lock (another task panicked mid-update) this
    /// falls back to the inner value via `into_inner` so the
    /// surfaced error is the upstream transport one rather than a
    /// re-raised lock panic.
    pub(crate) fn base_url(&self) -> String {
        match self.base_url.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Bearer token forwarded on every `Http` request. Same use as
    /// [`Self::base_url`] — letting sibling x0xd-client endpoints
    /// share the auth without re-deriving it.
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) async fn get_json<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        self.with_retry(|| self.request_json_once(Method::GET, path, None::<&()>))
            .await
    }

    pub(crate) async fn post_json<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R> {
        self.with_retry(|| self.request_json_once(Method::POST, path, Some(body)))
            .await
    }

    pub(crate) async fn patch_json<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R> {
        self.with_retry(|| self.request_json_once(Method::PATCH, path, Some(body)))
            .await
    }

    pub(crate) async fn delete(&self, path: &str) -> Result<()> {
        self.with_retry(|| self.delete_once(path)).await
    }

    /// GET a long-lived response (SSE) without imposing the standard
    /// timeout. Callers consume `resp.bytes_stream()` directly. The
    /// retry layer covers the initial connect only — once the stream
    /// body is in flight, subsequent loss is the caller's concern.
    pub(crate) async fn stream_get(&self, path: &str) -> Result<Response> {
        self.with_retry(|| self.stream_get_once(path)).await
    }

    async fn request_json_once<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<R> {
        let mut req = self.authed(method, path);
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(daemon_error(resp).await);
        }
        Ok(resp.json::<R>().await?)
    }

    async fn delete_once(&self, path: &str) -> Result<()> {
        let req = self.authed(Method::DELETE, path);
        let resp = req.send().await?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(daemon_error(resp).await)
    }

    async fn stream_get_once(&self, path: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url(), path);
        let resp = self
            .streaming
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(daemon_error(resp).await);
        }
        Ok(resp)
    }

    fn authed(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url(), path);
        self.inner.request(method, url).bearer_auth(&self.token)
    }

    /// Run `op`; on a `reqwest::Error::is_connect()` failure with a
    /// known `api.port` discovery file, re-resolve the cached base URL
    /// and retry once. Other errors and successes fall through
    /// unchanged. Mirrors `X0xdSigner::post_sign`'s retry shape.
    async fn with_retry<F, Fut, T>(&self, op: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        match op().await {
            Err(ChatError::Transport(e)) if e.is_connect() && self.port_file.is_some() => {
                if self.try_re_resolve_port() {
                    op().await
                } else {
                    Err(ChatError::Transport(e))
                }
            }
            other => other,
        }
    }

    /// Re-read the cached `api.port` discovery file and swap the base
    /// URL in-place when the port has drifted. Returns `true` on a
    /// successful swap (caller should retry), `false` otherwise (file
    /// missing, unparseable, or port unchanged — retrying won't help).
    fn try_re_resolve_port(&self) -> bool {
        let Some(path) = self.port_file.as_ref() else {
            return false;
        };
        let new_url = match read_port_file(path) {
            Ok(u) => u,
            Err(e) => {
                eprintln!(
                    "[fetchit-chat::http] port self-heal: re-read {} failed: {e}",
                    path.display(),
                );
                return false;
            }
        };
        let Ok(mut guard) = self.base_url.write() else {
            return false;
        };
        if *guard == new_url {
            return false;
        }
        eprintln!(
            "[fetchit-chat::http] port self-heal: re-resolved {} -> {}",
            *guard, new_url,
        );
        *guard = new_url;
        true
    }
}

fn read_port_file(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ChatError::Invalid(format!(
            "empty api.port at {}",
            path.display()
        )));
    }
    Ok(base_url_from_api_port_line(trimmed))
}

async fn daemon_error(resp: reqwest::Response) -> ChatError {
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .unwrap_or_else(|e| format!("<body read failed: {e}>"));
    ChatError::Daemon {
        status,
        body: truncate(&body, 512),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Debug, Deserialize)]
    struct Ok {
        ok: bool,
    }

    fn host_port(server: &MockServer) -> String {
        server.uri().trim_start_matches("http://").to_owned()
    }

    #[tokio::test]
    async fn new_with_port_file_reads_initial_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let port_file = tmp.path().join("api.port");
        std::fs::write(&port_file, host_port(&server)).unwrap();

        let http = Http::new_with_port_file(port_file.clone(), "tok".to_owned())
            .expect("new_with_port_file");
        assert!(http.base_url().contains(&host_port(&server)));

        let body: Ok = http.get_json("/health").await.expect("get_json");
        assert!(body.ok);
    }

    #[tokio::test]
    async fn self_heal_swaps_url_on_connect_failure_and_retries() {
        // Stand up the live mock, point api.port at it so the initial
        // construction succeeds, then forcibly stale the cached base
        // URL by writing in a dead port directly under the lock. The
        // next request hits connect-refused, the self-heal path
        // re-reads api.port, swaps to the live URL, and the retry
        // succeeds. Mirrors `X0xdSigner::self_heal_swaps_url_on_connect_failure_and_retries`.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let port_file = tmp.path().join("api.port");
        std::fs::write(&port_file, host_port(&server)).unwrap();

        let http =
            Http::new_with_port_file(port_file.clone(), "tok".to_owned()).expect("initial new");

        {
            let mut g = http.base_url.write().unwrap();
            *g = "http://127.0.0.1:1".to_owned();
        }

        let body: Ok = http
            .get_json("/health")
            .await
            .expect("get_json retries through self-heal");
        assert!(body.ok);
        assert!(http.base_url().contains(&host_port(&server)));
    }

    #[tokio::test]
    async fn self_heal_disabled_without_port_file() {
        // The plain `new` constructor does NOT enable self-heal. A
        // connect-refused on a subsequent request must propagate
        // rather than triggering a re-resolve attempt — mirrors
        // `X0xdSigner::self_heal_disabled_without_port_file`.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let http = Http::new(server.uri(), "tok".to_owned()).expect("plain new");

        {
            let mut g = http.base_url.write().unwrap();
            *g = "http://127.0.0.1:1".to_owned();
        }

        let err = http
            .get_json::<Ok>("/health")
            .await
            .expect_err("expected connect error without self-heal");
        assert!(
            matches!(err, ChatError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }
}
