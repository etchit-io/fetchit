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
    Client as CoreClient, ClientConfig, CoreNodeConfig, DownloadEvent, IPDiversityConfig, NodeMode,
    P2PNode, MAX_WIRE_MESSAGE_SIZE,
};

use fetchit_core::{Address, Error as CoreError, NetworkClient, Result as CoreResult};

use crate::parse_bootstrap_peer;

/// Bound on the `ant-core` progress-event channel. `ant-core` emits with
/// `try_send`, so a full channel drops events — harmless for a coarse bar.
const PROGRESS_CHANNEL: usize = 64;

/// A coarse, UI-ready download-progress update.
///
/// Same shape as the etchit upload-progress struct: a `phase` plus a
/// `done` / `total` chunk count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadProgress {
    /// `"resolving"` while walking the data map, then `"fetching"` for
    /// the content chunks.
    pub phase: &'static str,
    /// Chunks completed in the current phase.
    pub done: u64,
    /// Total chunks in the current phase; `0` until `ant-core` knows it.
    pub total: u64,
}

/// Maps an `ant-core` [`DownloadEvent`] to a coarse [`DownloadProgress`].
/// The resolve phase has no firm chunk total until it completes, so its
/// three events all report the indeterminate `resolving` state; only
/// `ChunksFetched` carries a real `done` / `total`.
fn download_progress(ev: &DownloadEvent) -> DownloadProgress {
    match ev {
        DownloadEvent::ResolvingDataMap { .. }
        | DownloadEvent::MapChunkFetched { .. }
        | DownloadEvent::DataMapResolved { .. } => DownloadProgress {
            phase: "resolving",
            done: 0,
            total: 0,
        },
        DownloadEvent::ChunksFetched { fetched, total } => DownloadProgress {
            phase: "fetching",
            done: *fetched as u64,
            total: *total as u64,
        },
    }
}

/// Production network backend. Cheap to clone — wraps an `Arc`-shared
/// `ant-core` client.
#[derive(Clone)]
pub struct AutonomiClient {
    inner: Arc<CoreClient>,
}

impl AutonomiClient {
    /// Connect to the production network using the supplied bootstrap
    /// peers.
    ///
    /// `peers` accepts both full multiaddrs and `ip:port` shorthand —
    /// each entry is parsed via [`parse_bootstrap_peer`].
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
        Self::connect_with(peers, false).await
    }

    /// Connect with loopback peering enabled — for local-devnet testing
    /// only.
    ///
    /// An `ant-core` `LocalDevnet` runs entirely on `127.0.0.1`. A
    /// production client filters loopback addresses out of its routing
    /// table, so it cannot peer with a devnet at all; this enables the
    /// node's `local` mode — the toggle `ant-cli` exposes as
    /// `--allow-loopback`. Production callers use [`connect`]: real
    /// bootstrap peers are never loopback.
    ///
    /// # Errors
    ///
    /// As [`connect`].
    pub async fn connect_local(peers: &[String]) -> CoreResult<Self> {
        Self::connect_with(peers, true).await
    }

    /// Shared connect path. `local` enables loopback peering — `false`
    /// for the production network, `true` for a `LocalDevnet`.
    async fn connect_with(peers: &[String], local: bool) -> CoreResult<Self> {
        let mut builder = CoreNodeConfig::builder()
            .mode(NodeMode::Client)
            .port(0)
            .ipv6(false)
            .local(local)
            .max_message_size(MAX_WIRE_MESSAGE_SIZE);

        for raw in peers {
            let addr = parse_bootstrap_peer(raw).map_err(net_err)?;
            builder = builder.bootstrap_peer(addr);
        }

        let mut config = builder
            .build()
            .map_err(|e| net_err(format!("config build failed: {e}")))?;

        // Clients don't host data — the routing table only exists to
        // find peers, not to be defended against Sybil clustering.
        // Relax the per-IP / per-subnet diversity caps so legitimate
        // bootstrap peers that share an IP or /24 (several of ours do)
        // aren't silently dropped. Mirrors `ant-cli`'s client setup.
        config.diversity_config = Some(IPDiversityConfig::permissive());

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

    /// Fetch the content at `addr`, streaming it to the file at `output`
    /// and reporting coarse [`DownloadProgress`] through `on_progress`.
    ///
    /// `ant-core`'s only progress-instrumented download path is file-
    /// based, so this streams to disk rather than holding the payload in
    /// memory like [`NetworkClient::fetch`]. The desktop shell calls it
    /// only when the user has enabled the on-disk cache, with `output`
    /// pointing at the cache slot — so no fetched content reaches disk
    /// that the cache would not have written anyway. With the cache off,
    /// callers stay on the in-memory `fetch`.
    ///
    /// # Errors
    ///
    /// [`fetchit_core::Error::Network`] if the data-map fetch or the
    /// download fails.
    pub async fn fetch_with_progress(
        &self,
        addr: &Address,
        output: &Path,
        on_progress: impl Fn(DownloadProgress) + Send + 'static,
    ) -> CoreResult<()> {
        let key = *addr.as_bytes();
        let data_map = self
            .inner
            .data_map_fetch(&key)
            .await
            .map_err(|e| net_err(format!("data_map_fetch: {e}")))?;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<DownloadEvent>(PROGRESS_CHANNEL);
        let forward = tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                on_progress(download_progress(&ev));
            }
        });

        let result = self
            .inner
            .file_download_with_progress(&data_map, output, Some(tx))
            .await
            .map_err(|e| net_err(format!("file_download: {e}")));
        // `file_download_with_progress` owns `tx` and drops it on return,
        // closing the channel so the forward task drains and exits.
        let _ = forward.await;
        result.map(|_| ())
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
/// garbage.
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

/// `ClientConfig` matching what `ant-cli` runs at default settings: a
/// 60-second per-peer chunk timeout. (`ant-cli`'s `--store-timeout-secs`
/// flag defaults to 60; `ClientConfig::default()` ships 10.)
///
/// Despite the field name, `store_timeout_secs` also governs chunk
/// *retrieve* — `ant-core`'s `chunk_get_from_peer` uses it as the
/// per-peer GET timeout (and `ant-cli`'s own flag doc reads "chunk
/// store / retrieve operations") — so it is the right knob for a
/// read-only client like fetch>it. The 10-second default is too
/// aggressive on mobile or NAT-traversed paths, where a multi-MB
/// chunk transfer plus QUIC slow-start runs well past it. Everything
/// else stays at stock.
fn cli_style_client_config() -> ClientConfig {
    ClientConfig {
        store_timeout_secs: 60,
        ..ClientConfig::default()
    }
}

/// Spawn `node.start()` in the background and return as soon as we
/// either see at least one connected peer **or** hit a short deadline.
///
/// `P2PNode::start()` performs a full DHT bootstrap; on a cold
/// connection that can take tens of seconds (it depends on how quickly
/// bootstrap peers respond, NAT traversal, etc.). Blocking an
/// interactive viewer for that is unworkable, so we let it finish in
/// the background and return a usable `Client` as soon as we see one
/// connected peer, or after the `START_DEADLINE` warmup window —
/// whichever comes first.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn resolve_events_report_indeterminate_resolving() {
        for ev in [
            DownloadEvent::ResolvingDataMap {
                total_map_chunks: 3,
            },
            DownloadEvent::MapChunkFetched { fetched: 2 },
            DownloadEvent::DataMapResolved { total_chunks: 128 },
        ] {
            assert_eq!(
                download_progress(&ev),
                DownloadProgress {
                    phase: "resolving",
                    done: 0,
                    total: 0
                },
            );
        }
    }

    #[test]
    fn chunks_fetched_reports_determinate_fetching() {
        assert_eq!(
            download_progress(&DownloadEvent::ChunksFetched {
                fetched: 64,
                total: 128
            }),
            DownloadProgress {
                phase: "fetching",
                done: 64,
                total: 128
            },
        );
    }
}
