//! HTTP transport abstraction. The [`HttpClient`] trait is the seam
//! between the denylist consumer and the network: production code
//! wires in [`ReqwestClient`] behind the `reqwest` Cargo feature,
//! tests provide their own stubs.

use crate::consumer::TrustError;
use async_trait::async_trait;

/// HTTP client interface used by the denylist consumer.
///
/// Implementations: a feature-gated `reqwest::Client` wrapper in
/// production, hand-rolled stubs in tests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// GET `url`, return the response body bytes on 2xx, error
    /// otherwise.
    async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError>;
}

/// Production HTTP client wrapping `reqwest::Client`. Enabled by
/// the `reqwest` Cargo feature.
#[cfg(feature = "reqwest")]
pub struct ReqwestClient(pub reqwest::Client);

#[cfg(feature = "reqwest")]
impl ReqwestClient {
    /// Build with a default `reqwest::Client` (30s timeout, default
    /// user-agent).
    ///
    /// # Errors
    /// Returns [`TrustError::Http`] if the default client builder
    /// fails (e.g. no usable TLS backend).
    pub fn new() -> Result<Self, TrustError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("fetchit-trust-client/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| TrustError::Http(format!("reqwest builder: {e}")))?;
        Ok(Self(http))
    }
}

#[cfg(feature = "reqwest")]
#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError> {
        let resp = self
            .0
            .get(url)
            .send()
            .await
            .map_err(|e| TrustError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TrustError::Http(format!("status {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TrustError::Http(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_http_client_returns_bytes() {
        struct Stub(Vec<u8>);
        #[async_trait::async_trait]
        impl HttpClient for Stub {
            async fn get(&self, _: &str) -> Result<Vec<u8>, TrustError> {
                Ok(self.0.clone())
            }
        }
        let c = Stub(b"hello".to_vec());
        assert_eq!(c.get("ignored").await.unwrap(), b"hello");
    }
}
