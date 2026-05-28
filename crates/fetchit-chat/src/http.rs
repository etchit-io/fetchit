//! Internal HTTP transport shared by the typed endpoint modules.
//!
//! Wraps `reqwest` to add the bearer auth header on every request and
//! normalize daemon error responses into [`ChatError::Daemon`].

use crate::error::{ChatError, Result};
use reqwest::{Method, RequestBuilder, Response};
use serde::{Serialize, de::DeserializeOwned};

/// Lightweight bearer-authenticated HTTP transport.
///
/// Holds two clients: a short-timeout one for normal request/response
/// endpoints, and a no-timeout one for SSE streams whose bodies stay
/// open indefinitely.
#[derive(Debug, Clone)]
pub(crate) struct Http {
    inner: reqwest::Client,
    streaming: reqwest::Client,
    base_url: String,
    token: String,
}

impl Http {
    pub(crate) fn new(base_url: String, token: String) -> Result<Self> {
        let inner = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        let streaming = reqwest::Client::builder()
            .pool_idle_timeout(None)
            .build()?;
        Ok(Self { inner, streaming, base_url, token })
    }

    pub(crate) async fn get_json<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        self.request_json(Method::GET, path, None::<&()>).await
    }

    pub(crate) async fn post_json<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R> {
        self.request_json(Method::POST, path, Some(body)).await
    }

    pub(crate) async fn delete(&self, path: &str) -> Result<()> {
        let req = self.authed(Method::DELETE, path);
        let resp = req.send().await?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(daemon_error(resp).await)
    }

    /// GET a long-lived response (SSE) without imposing the standard
    /// timeout. Callers consume `resp.bytes_stream()` directly.
    pub(crate) async fn stream_get(&self, path: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
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

    async fn request_json<B: Serialize, R: DeserializeOwned>(
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

    fn authed(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        self.inner
            .request(method, url)
            .bearer_auth(&self.token)
    }
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
