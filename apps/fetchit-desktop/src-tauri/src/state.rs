//! Process-scoped state for the Tauri app: the lazily-built Autonomi client,
//! the in-memory bytes cache, and the (opt-in) on-disk bytes cache.

use crate::cache::BytesCache;
use crate::disk_cache::DiskCache;
use crate::settings::Settings;
use bytes::Bytes;
use fetchit_core::Address;
use fetchit_net::{AutonomiClient, DEFAULT_PEERS};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct AppState {
    pub client: Arc<Mutex<Option<AutonomiClient>>>,
    pub cache: Arc<BytesCache>,
    pub disk_cache: Arc<DiskCache>,
    /// In-memory copy of settings.json; serialise all read-modify-write
    /// operations through the std mutex (critical sections never `.await`).
    pub settings: Arc<StdMutex<Settings>>,
    pub settings_path: Arc<PathBuf>,
    /// Cancellation tokens for in-flight fetches, keyed by tab id and
    /// tagged with a registration generation. Closing a tab fires the
    /// matching token; re-registering the same tab cancels the prior
    /// token atomically so the superseded Rust task stops making
    /// progress instead of running to completion against a UI that no
    /// longer cares. The generation lets a superseded fetch finish late
    /// without evicting its replacement's token.
    pub fetches: Arc<StdMutex<HashMap<String, (u64, CancellationToken)>>>,
    /// Monotonic source for fetch registration generations.
    fetch_generation: Arc<AtomicU64>,
    /// Reader-side community-denylist gate. Built at boot from the same
    /// signed NY-Trust endpoint the chat client uses, but independent of
    /// the chat feature flag: the reader must short-circuit a denylisted
    /// `XorName` to [`fetchit_core::Rendition::Blocked`] before any
    /// handler runs, even when chat ships cold. `None` when no denylist
    /// URL resolves (offline / self-host without a trust service).
    pub reader_denylist: Option<Arc<dyn fetchit_trust_types::DenylistQuery>>,
    /// Active progressive downloads, keyed by address. At most one feeder
    /// task runs per address; concurrent requests share the same entry.
    /// The media HTTP server resolves its stream from this registry via
    /// `get_or_start_stream`.
    pub streams: Arc<StdMutex<HashMap<Address, Arc<crate::streaming_media::StreamingMedia>>>>,
}

impl AppState {
    pub fn new(disk_cache: Arc<DiskCache>, settings: Settings, settings_path: PathBuf) -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
            cache: Arc::new(BytesCache::default()),
            disk_cache,
            settings: Arc::new(StdMutex::new(settings)),
            settings_path: Arc::new(settings_path),
            fetches: Arc::new(StdMutex::new(HashMap::new())),
            fetch_generation: Arc::new(AtomicU64::new(0)),
            reader_denylist: None,
            streams: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Install the reader-side denylist gate (boot-time builder). The
    /// backing consumer polls the signed trust endpoint independently of
    /// the chat client; `None` leaves the reader ungated.
    #[must_use]
    pub fn with_reader_denylist(
        mut self,
        denylist: Option<Arc<dyn fetchit_trust_types::DenylistQuery>>,
    ) -> Self {
        self.reader_denylist = denylist;
        self
    }

    /// Build the [`fetchit_core::RenderingContext`] for rendering
    /// `addr_hex` (the canonical lowercase 64-hex `XorName`). Carries the
    /// reader denylist so
    /// [`fetchit_core::HandlerRegistry::render_with_context`]
    /// short-circuits a denylisted address to
    /// [`fetchit_core::Rendition::Blocked`] before any handler runs. With
    /// no denylist installed the context is inert and rendering is
    /// unchanged.
    #[must_use]
    pub fn rendering_context(&self, addr_hex: String) -> fetchit_core::RenderingContext {
        fetchit_core::RenderingContext {
            denylist: self.reader_denylist.clone(),
            addr_hex: Some(addr_hex),
        }
    }

    /// Register a cancellation token for `tab_id`'s in-flight fetch.
    /// Any prior fetch still registered for the same tab is cancelled
    /// here, under the registry lock, so callers never race a separate
    /// cancel against the new registration. Returns the token to
    /// `tokio::select!` against plus the generation tag to pass back to
    /// [`Self::finish_fetch`].
    pub fn register_fetch(&self, tab_id: String) -> (CancellationToken, u64) {
        let token = CancellationToken::new();
        let generation = self.fetch_generation.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.fetches.lock() {
            if let Some((_, superseded)) = map.insert(tab_id, (generation, token.clone())) {
                superseded.cancel();
            }
        }
        (token, generation)
    }

    /// Remove the entry for `tab_id` once the fetch finishes (success,
    /// error, or cancellation) — but only while it still belongs to
    /// this registration. A superseded fetch finishing late must not
    /// evict its replacement's token, or the replacement becomes
    /// uncancellable. Idempotent.
    pub fn finish_fetch(&self, tab_id: &str, generation: u64) {
        if let Ok(mut map) = self.fetches.lock() {
            if map.get(tab_id).is_some_and(|(g, _)| *g == generation) {
                map.remove(tab_id);
            }
        }
    }

    /// Cancel any in-flight fetch registered for `tab_id`. No-op if
    /// no fetch is registered.
    pub fn cancel_fetch(&self, tab_id: &str) {
        if let Ok(map) = self.fetches.lock() {
            if let Some((_, token)) = map.get(tab_id) {
                token.cancel();
            }
        }
    }

    /// Insert a pre-built stream for testing. Guards the map and places `sm`
    /// under `addr` so unit tests can prime the registry without going to the
    /// network.
    #[cfg(test)]
    pub fn insert_stream_for_test(
        &self,
        addr: Address,
        sm: Arc<crate::streaming_media::StreamingMedia>,
    ) {
        if let Ok(mut map) = self.streams.lock() {
            map.insert(addr, sm);
        }
    }

    /// Return the existing stream for `addr` (or start a new one), along with
    /// an [`crate::streaming_media::InterestGuard`] that keeps the feeder
    /// alive for the caller's lifetime.
    ///
    /// Interest is registered before the feeder task is allowed to run,
    /// closing the window where `should_abort` could see zero interest and
    /// cancel an in-progress download that a caller is about to consume.
    pub async fn get_or_start_stream(
        &self,
        addr: Address,
    ) -> Result<
        (
            Arc<crate::streaming_media::StreamingMedia>,
            crate::streaming_media::InterestGuard,
        ),
        String,
    > {
        // Fast path: attach to an existing stream.
        if let Some(sm) = self
            .streams
            .lock()
            .map_err(|e| e.to_string())?
            .get(&addr)
            .cloned()
        {
            let guard = sm.add_interest();
            return Ok((sm, guard));
        }
        let client = crate::state::ensure_client(self, &self.effective_peers()).await?;
        let total = client.content_size(&addr).await.map_err(|e| e.to_string())?;
        #[cfg(not(feature = "e2e"))]
        let backing = if self.disk_cache.policy().enabled {
            // Remove any stale partial left by a previous crash before starting
            // to append; without this the feeder appends to the old data and
            // commit_stream promotes a silently corrupt file to a cache entry.
            let _ = std::fs::remove_file(self.disk_cache.stream_path(&addr));
            crate::streaming_media::StreamBacking::File(self.disk_cache.stream_path(&addr))
        } else {
            crate::streaming_media::StreamBacking::Memory(StdMutex::new(Vec::new()))
        };
        #[cfg(feature = "e2e")]
        let backing = crate::streaming_media::StreamBacking::Memory(StdMutex::new(Vec::new()));
        let sm = Arc::new(crate::streaming_media::StreamingMedia::new(total, backing));
        let guard = {
            let mut map = self.streams.lock().map_err(|e| e.to_string())?;
            if let Some(existing) = map.get(&addr).cloned() {
                // Lost the insert race: attach to the winner's stream.
                let g = existing.add_interest();
                return Ok((existing, g));
            }
            map.insert(addr, sm.clone());
            // Register interest under the map lock so the feeder cannot
            // observe interest == 0 between insert and spawn.
            sm.add_interest()
        };
        let client = Arc::new(client);
        let streams = self.streams.clone();
        let disk_cache = self.disk_cache.clone();
        #[cfg(not(feature = "e2e"))]
        let cache_on = self.disk_cache.policy().enabled;
        let sm_feeder = sm.clone();
        tokio::spawn(async move {
            crate::streaming_media::feed(sm_feeder.clone(), client, addr).await;
            // Commit a complete stream to cache; discard a partial one.
            // Both commit_stream and discard_stream are cfg(not(e2e)).
            #[cfg(not(feature = "e2e"))]
            {
                let ok = matches!(sm_feeder.subscribe().borrow().terminal, Some(Ok(())));
                if cache_on {
                    if ok {
                        disk_cache.commit_stream(&addr);
                    } else {
                        disk_cache.discard_stream(&addr);
                    }
                }
            }
            // Remove from registry so a subsequent view re-resolves
            // (cache hit if committed, new download if discarded/absent).
            if let Ok(mut map) = streams.lock() {
                map.remove(&addr);
            }
        });
        Ok((sm, guard))
    }

    /// Layered cache lookup: memory hit first; on miss, consult disk and
    /// hydrate the memory layer for subsequent hits in this session.
    pub fn cached_bytes(&self, addr: &Address) -> Option<Bytes> {
        if let Some(b) = self.cache.get(addr) {
            return Some(b);
        }
        let b = self.disk_cache.get(addr)?;
        self.cache.put(*addr, b.clone());
        Some(b)
    }

    /// Write-through: every fresh fetch lands in both layers.
    /// `disk_cache.put` is a no-op when the policy is disabled.
    pub fn cache_bytes(&self, addr: &Address, bytes: Bytes) {
        self.cache.put(*addr, bytes.clone());
        self.disk_cache.put(addr, &bytes);
    }
}

pub async fn ensure_client(state: &AppState, peers: &[String]) -> Result<AutonomiClient, String> {
    let mut guard = state.client.lock().await;
    if let Some(c) = guard.as_ref() {
        return Ok(c.clone());
    }
    let c = AutonomiClient::connect(peers)
        .await
        .map_err(|e| e.to_string())?;
    *guard = Some(c.clone());
    Ok(c)
}

pub fn default_peers() -> Vec<String> {
    DEFAULT_PEERS.iter().map(|s| (*s).to_owned()).collect()
}

impl AppState {
    /// Bootstrap peers to use for the next connection: the user override
    /// from settings if any non-empty entries exist, otherwise the bundled
    /// production defaults.
    pub fn effective_peers(&self) -> Vec<String> {
        let override_list = self
            .settings
            .lock()
            .map(|s| s.peers.clone())
            .unwrap_or_default();
        let cleaned: Vec<String> = override_list
            .into_iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if cleaned.is_empty() {
            default_peers()
        } else {
            cleaned
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::disk_cache::Policy;
    use fetchit_core::handlers::default_registry;
    use fetchit_core::{Hint, RenderContext, Rendition};
    use fetchit_trust_types::{DenylistQuery, EntryKind};

    const HEX_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    /// Denylist stub that blocks exactly one `XorName` value.
    struct StubBlock(String);
    impl DenylistQuery for StubBlock {
        fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
            kind == EntryKind::XorName && value == self.0
        }
    }

    fn make_state(tmp: &std::path::Path) -> AppState {
        let disk = Arc::new(DiskCache::new(tmp.join("disk"), Policy::default()));
        AppState::new(disk, Settings::default(), tmp.join("settings.json"))
    }

    #[test]
    fn cached_bytes_returns_in_memory_hit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let addr: Address = HEX_ONE.parse().expect("valid hex");
        state.cache.put(addr, Bytes::from_static(b"in-memory"));
        assert_eq!(
            state.cached_bytes(&addr),
            Some(Bytes::from_static(b"in-memory")),
        );
    }

    #[test]
    fn clearing_only_disk_leaves_in_memory_layer_populated() {
        // Documents the invariant the `clear_cache` Tauri command must
        // honor: BOTH layers have to be wiped, otherwise the next fetch
        // for an address from this session returns the previously-cached
        // bytes from RAM and never goes near the network or disk.
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let addr: Address = HEX_ONE.parse().expect("valid hex");
        state.cache.put(addr, Bytes::from_static(b"hello"));
        state.disk_cache.clear();
        assert!(
            state.cached_bytes(&addr).is_some(),
            "in-memory cache must survive a disk-only wipe",
        );
    }

    #[test]
    fn clearing_both_layers_fully_empties_the_lookup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let addr: Address = HEX_ONE.parse().expect("valid hex");
        state.cache.put(addr, Bytes::from_static(b"hello"));
        state.cache.clear();
        state.disk_cache.clear();
        assert!(state.cached_bytes(&addr).is_none());
    }

    #[test]
    fn cancel_fetch_flips_the_registered_token() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let (token, _) = state.register_fetch("tab-1".into());
        assert!(!token.is_cancelled());
        state.cancel_fetch("tab-1");
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancel_fetch_is_a_noop_for_unknown_tab_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        // Just shouldn't panic; the registry simply has no entry to fire.
        state.cancel_fetch("never-registered");
    }

    #[test]
    fn finish_fetch_removes_the_entry_so_later_cancels_are_noops() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let (token, generation) = state.register_fetch("tab-1".into());
        state.finish_fetch("tab-1", generation);
        state.cancel_fetch("tab-1");
        // The token we held a reference to never fires after finish.
        assert!(!token.is_cancelled());
    }

    #[test]
    fn register_fetch_cancels_the_superseded_token() {
        // Re-registration is what happens when the user refetches the
        // same tab (refresh, retry, back-nav). Cancelling the prior
        // token here, under the registry lock, means no caller has to
        // race a separate cancel against the new registration.
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let (first, _) = state.register_fetch("tab-1".into());
        let (second, _) = state.register_fetch("tab-1".into());
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        state.cancel_fetch("tab-1");
        assert!(second.is_cancelled());
    }

    #[test]
    fn finish_fetch_from_a_superseded_fetch_leaves_the_replacement_registered() {
        // The superseded task observes its cancellation and calls
        // finish_fetch AFTER the replacement registered. A generation-
        // blind finish would evict the replacement's token, making it
        // uncancellable for the rest of its run.
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let (_, first_generation) = state.register_fetch("tab-1".into());
        let (second, _) = state.register_fetch("tab-1".into());
        state.finish_fetch("tab-1", first_generation);
        state.cancel_fetch("tab-1");
        assert!(second.is_cancelled());
    }

    /// M3 #342: a reader denylist that blocks a `XorName` makes
    /// `rendering_context` produce a context that short-circuits the
    /// render to `Rendition::Blocked` before any handler runs. Without
    /// the denylist threaded in, the same bytes render as normal content
    /// — this is the wiring the reader path was missing.
    #[test]
    fn rendering_context_blocks_a_denylisted_xorname() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let blocked = "ab".repeat(32);
        let state =
            make_state(tmp.path()).with_reader_denylist(Some(Arc::new(StubBlock(blocked.clone()))));
        let rctx = state.rendering_context(blocked);
        let r = default_registry()
            .render_with_context(
                Bytes::from_static(b"plain readable text"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx,
            )
            .expect("blocked short-circuit returns Ok(Blocked)");
        assert!(
            matches!(r, Rendition::Blocked { .. }),
            "expected Blocked, got {r:?}"
        );
    }

    /// M3 #342: with a denylist installed but the address NOT on it, the
    /// reader renders normally (the common happy path).
    #[test]
    fn rendering_context_allows_an_unblocked_addr() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state =
            make_state(tmp.path()).with_reader_denylist(Some(Arc::new(StubBlock("ff".repeat(32)))));
        let rctx = state.rendering_context("ab".repeat(32));
        let r = default_registry()
            .render_with_context(
                Bytes::from_static(b"plain readable text"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx,
            )
            .expect("unblocked addr renders normally");
        assert!(
            !matches!(r, Rendition::Blocked { .. }),
            "unblocked addr must not be Blocked"
        );
    }

    #[test]
    fn get_or_start_returns_the_same_stream_for_one_address() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let addr: Address = "ab".repeat(32).parse().unwrap();
        let sm = std::sync::Arc::new(crate::streaming_media::StreamingMedia::new(
            4,
            crate::streaming_media::StreamBacking::Memory(std::sync::Mutex::new(Vec::new())),
        ));
        state.insert_stream_for_test(addr, sm.clone());
        let again = state.streams.lock().unwrap().get(&addr).cloned().unwrap();
        assert!(std::sync::Arc::ptr_eq(&sm, &again));
    }

    /// M3 #342: with no denylist installed (offline / self-host), the
    /// context is inert and the reader renders unchanged.
    #[test]
    fn rendering_context_without_denylist_passes_through() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        assert!(state.reader_denylist.is_none());
        let rctx = state.rendering_context("ab".repeat(32));
        let r = default_registry()
            .render_with_context(
                Bytes::from_static(b"plain readable text"),
                &Hint::default(),
                &RenderContext::default(),
                &rctx,
            )
            .expect("inert gate renders normally");
        assert!(!matches!(r, Rendition::Blocked { .. }));
    }
}
