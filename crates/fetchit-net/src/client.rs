//! [`AutonomiClient`] — the production [`NetworkClient`] implementation.
//!
//! Wraps `ant-core`'s `Client`, adds the bootstrap-warmup pattern, and
//! handles hierarchical data-maps so callers always receive the full
//! payload regardless of the on-network chunking topology.

use std::path::Path;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use ant_core::data::{
    Client as CoreClient, ClientConfig, CoreNodeConfig, MultiAddr, NodeMode, P2PNode,
    MAX_WIRE_MESSAGE_SIZE,
};

use fetchit_core::{Address, Error as CoreError, NetworkClient, Result as CoreResult};

use crate::normalize_multiaddr;

/// Production network backend. Cheap to clone — wraps an `Arc`-shared
/// `ant-core` client.
#[derive(Clone)]
pub struct AutonomiClient {
    inner: Arc<CoreClient>,
}

impl AutonomiClient {
    /// Connect to the network using the supplied bootstrap peers.
    ///
    /// `peers` accepts both full multiaddrs and `ip:port` shorthand —
    /// each entry is run through [`normalize_multiaddr`].
    ///
    /// On platforms where `HOME` may be unset (notably Android),
    /// callers must invoke [`set_data_home`] before this
    /// constructor — `ant-core`'s internal `data_dir()` resolution
    /// will panic with `HomeDirNotFound` otherwise. On desktop where
    /// the shell sets `HOME`, no setup is needed.
    ///
    /// # Errors
    ///
    /// Returns [`fetchit_core::Error::Network`] if the bootstrap-peer
    /// strings fail to parse or the underlying P2P node cannot be
    /// constructed.
    pub async fn connect(peers: &[String]) -> CoreResult<Self> {
        let mut builder = CoreNodeConfig::builder()
            .mode(NodeMode::Client)
            .port(0)
            .ipv6(false)
            .max_message_size(MAX_WIRE_MESSAGE_SIZE);

        for raw in peers {
            let normalised = normalize_multiaddr(raw);
            let addr: MultiAddr = normalised
                .parse()
                .map_err(|e| net_err(format!("invalid peer address {raw}: {e}")))?;
            builder = builder.bootstrap_peer(addr);
        }

        let config = builder
            .build()
            .map_err(|e| net_err(format!("config build failed: {e}")))?;

        let node = P2PNode::new(config)
            .await
            .map_err(|e| net_err(format!("P2P node init failed: {e}")))?;

        let node = Arc::new(node);
        start_node_with_warmup(node.clone()).await?;

        let inner = Arc::new(CoreClient::from_node(node, cli_style_client_config()));
        Ok(Self { inner })
    }

    /// Number of currently-connected peers. Useful for UI status
    /// indicators.
    pub async fn peer_count(&self) -> usize {
        self.inner.network().connected_peers().await.len()
    }
}

#[async_trait]
impl NetworkClient for AutonomiClient {
    async fn fetch(&self, addr: &Address) -> CoreResult<Bytes> {
        let key = *addr.as_bytes();
        let data_map = self
            .inner
            .data_map_fetch(&key)
            .await
            .map_err(|e| net_err(format!("data_map_fetch: {e}")))?;
        let root_map = resolve_data_map(&self.inner, data_map)?;
        let content = self
            .inner
            .data_download(&root_map)
            .await
            .map_err(|e| net_err(format!("data_download: {e}")))?;
        Ok(content)
    }
}

/// Resolve a hierarchical (shrunk) `DataMap` to its root form.
///
/// `ant-core`'s `data_download` does not walk hierarchical maps — for
/// content large enough that `self_encryption` shrinks the data map
/// (anything past the chunk-of-pointers threshold), the top-level
/// addresses are intermediate child-map pointers, not content. Without
/// this resolution step, downloads of large content silently return
/// garbage. Mirrors etchit's FFI helper, which is the production-tested
/// path against the same `ant-core` revision.
///
/// Pure pass-through for flat maps (`is_child() == false`).
fn resolve_data_map(
    inner: &CoreClient,
    data_map: ant_core::data::DataMap,
) -> CoreResult<ant_core::data::DataMap> {
    if !data_map.is_child() {
        return Ok(data_map);
    }
    let handle = tokio::runtime::Handle::current();
    let resolved = tokio::task::block_in_place(|| {
        let fetch = |batch: &[(usize, xor_name::XorName)]| -> std::result::Result<
            Vec<(usize, bytes::Bytes)>,
            self_encryption::Error,
        > {
            let owned = batch.to_vec();
            handle.block_on(async {
                let mut out = Vec::with_capacity(owned.len());
                for (idx, hash) in owned {
                    let chunk = inner
                        .chunk_get(&hash.0)
                        .await
                        .map_err(|e| {
                            self_encryption::Error::Generic(format!(
                                "data-map resolution chunk_get failed: {e}"
                            ))
                        })?
                        .ok_or_else(|| {
                            self_encryption::Error::Generic(format!(
                                "data-map chunk not found: {}",
                                hex::encode(hash.0)
                            ))
                        })?;
                    out.push((idx, chunk.content));
                }
                Ok(out)
            })
        };
        self_encryption::get_root_data_map_parallel(data_map, &fetch)
    })
    .map_err(|e| net_err(format!("data-map resolution: {e}")))?;
    Ok(resolved)
}

/// `ClientConfig` matching what `ant-cli` uses at default settings:
/// 60-second per-peer chunk timeout. `ClientConfig::default()` ships
/// 10 seconds, which is too aggressive on mobile or any path that
/// crosses NAT traversal — etchit hit this in production and
/// `ant-cli` itself overrides it. Everything else stays at stock.
fn cli_style_client_config() -> ClientConfig {
    ClientConfig {
        store_timeout_secs: 60,
        ..ClientConfig::default()
    }
}

/// Spawn `node.start()` in the background and return as soon as we
/// either see at least one connected peer **or** hit a short deadline.
///
/// `P2PNode::start()` performs a full DHT bootstrap which takes 30+
/// seconds on a cold connection. Blocking the caller for that long is
/// unworkable for an interactive viewer, so we let the bootstrap finish
/// in the background while returning a usable `Client` early.
async fn start_node_with_warmup(node: Arc<P2PNode>) -> CoreResult<()> {
    const START_DEADLINE: Duration = Duration::from_secs(10);
    const WARMUP_POLL: Duration = Duration::from_millis(250);

    let start_task = {
        let node = node.clone();
        tokio::spawn(async move { node.start().await })
    };

    let deadline = tokio::time::Instant::now() + START_DEADLINE;
    loop {
        if !node.connected_peers().await.is_empty() {
            log::info!("fetchit-net: bootstrap warmup saw a peer, returning early");
            return Ok(());
        }
        if start_task.is_finished() {
            return match start_task.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(net_err(format!("node.start: {e}"))),
                Err(e) => Err(net_err(format!("node.start task panicked: {e}"))),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            log::warn!(
                "fetchit-net: bootstrap warmup hit {}s deadline with no peers, returning anyway",
                START_DEADLINE.as_secs()
            );
            return Ok(());
        }
        tokio::time::sleep(WARMUP_POLL).await;
    }
}

fn net_err(reason: String) -> CoreError {
    CoreError::Network(reason)
}

static SET_DATA_HOME_ONCE: Once = Once::new();

/// Set `HOME` and `XDG_DATA_HOME` to `path` if they are unset.
///
/// `ant-core`'s internal `data_dir()` resolution calls
/// `home_dir().unwrap()` on Linux when `XDG_DATA_HOME` is missing —
/// this panics with `HomeDirNotFound` on platforms that don't set
/// `HOME` (notably Android). Call this once early in the process
/// lifetime — before any thread reads the environment, before
/// [`AutonomiClient::connect`] — to avoid the panic.
///
/// Idempotent: only the first call has effect. Calls from desktop
/// processes where `HOME` is already set are a no-op.
///
/// # Safety / threading
///
/// `std::env::set_var` is not safe to call concurrently with reads of
/// the same variable. This function uses [`std::sync::Once`] so
/// repeated calls are harmless, but the *first* call still races with
/// any background thread already started — which is why it must run
/// before `connect`.
pub fn set_data_home(path: &Path) {
    SET_DATA_HOME_ONCE.call_once(|| {
        if std::env::var_os("HOME").is_none() {
            std::env::set_var("HOME", path);
        }
        if std::env::var_os("XDG_DATA_HOME").is_none() {
            std::env::set_var("XDG_DATA_HOME", path);
        }
    });
}
