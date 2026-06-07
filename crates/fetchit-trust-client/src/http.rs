//! HTTP transport abstraction. Stub for C1; the `HttpClient` trait
//! definition lands in C2.

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
