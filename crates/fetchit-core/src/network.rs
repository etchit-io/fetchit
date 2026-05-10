//! The [`NetworkClient`] trait — the seam between `fetchit-core` and
//! whatever actually talks to the Autonomi network.
//!
//! The trait keeps the core stateless and testable: production builds
//! plug in an `ant-core`-backed implementation; unit tests use the
//! [`MockClient`] in this module.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use bytes::Bytes;

use crate::{Address, Error, Result};

/// Anything that can resolve an [`Address`] into bytes.
///
/// Implementations are expected to handle hierarchical data-maps
/// transparently — callers receive the concatenated payload, not the
/// inner data-map chunk. The real `ant-core`-backed client (added in
/// a follow-up commit) does this via
/// `self_encryption::get_root_data_map_parallel`; the [`MockClient`]
/// returns whatever bytes the test inserted.
#[async_trait]
pub trait NetworkClient: Send + Sync {
    /// Fetch the bytes addressed by `addr`.
    async fn fetch(&self, addr: &Address) -> Result<Bytes>;
}

/// In-memory [`NetworkClient`] used by tests and the CLI's offline
/// demo mode.
///
/// Insert addresses with [`MockClient::insert`]; `fetch` returns the
/// stored bytes or [`Error::Network`] if the address is unknown.
#[derive(Debug, Default)]
pub struct MockClient {
    store: Mutex<HashMap<Address, Bytes>>,
}

impl MockClient {
    /// Construct an empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `bytes` against `addr`.
    pub fn insert(&self, addr: Address, bytes: Bytes) {
        lock_or_recover(&self.store).insert(addr, bytes);
    }
}

/// Recover from mutex poisoning by accepting the inner data. The mock
/// is only ever poisoned by a panic in another test — the data itself
/// is not corrupted, so falling through is preferable to a cascade.
fn lock_or_recover(m: &Mutex<HashMap<Address, Bytes>>) -> MutexGuard<'_, HashMap<Address, Bytes>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[async_trait]
impl NetworkClient for MockClient {
    async fn fetch(&self, addr: &Address) -> Result<Bytes> {
        lock_or_recover(&self.store)
            .get(addr)
            .cloned()
            .ok_or_else(|| Error::Network(format!("address not in mock store: {addr}")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const ZERO_ADDR: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[tokio::test]
    async fn returns_inserted_bytes() {
        let client = MockClient::new();
        let addr: Address = ZERO_ADDR.parse().expect("valid");
        client.insert(addr, Bytes::from_static(b"hello"));
        let got = client.fetch(&addr).await.expect("fetch");
        assert_eq!(got.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn missing_address_errors() {
        let client = MockClient::new();
        let addr: Address = ZERO_ADDR.parse().expect("valid");
        let err = client.fetch(&addr).await.expect_err("should error");
        assert!(matches!(err, Error::Network(_)));
    }
}
