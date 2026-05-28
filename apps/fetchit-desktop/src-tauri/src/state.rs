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
    /// Cancellation tokens for in-flight fetches, keyed by tab id.
    /// Closing a tab or refetching the same tab fires the matching
    /// token so the Rust task stops making progress instead of running
    /// to completion against a UI that no longer cares.
    pub fetches: Arc<StdMutex<HashMap<String, CancellationToken>>>,
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
        }
    }

    /// Register a cancellation token for `tab_id`'s in-flight fetch,
    /// replacing any prior one. Returns the freshly-registered token
    /// the caller should `tokio::select!` against.
    pub fn register_fetch(&self, tab_id: String) -> CancellationToken {
        let token = CancellationToken::new();
        if let Ok(mut map) = self.fetches.lock() {
            // Drop any prior token without cancelling — the caller is
            // the one starting a new fetch on the same tab, so the
            // previous one's cancellation is its own concern (or
            // already happened via `cancel_fetch`).
            map.insert(tab_id, token.clone());
        }
        token
    }

    /// Remove the entry for `tab_id` once the fetch finishes (success,
    /// error, or cancellation). Idempotent.
    pub fn finish_fetch(&self, tab_id: &str) {
        if let Ok(mut map) = self.fetches.lock() {
            map.remove(tab_id);
        }
    }

    /// Cancel any in-flight fetch registered for `tab_id`. No-op if
    /// no fetch is registered.
    pub fn cancel_fetch(&self, tab_id: &str) {
        if let Ok(map) = self.fetches.lock() {
            if let Some(token) = map.get(tab_id) {
                token.cancel();
            }
        }
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

    const HEX_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";

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
        let token = state.register_fetch("tab-1".into());
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
        let token = state.register_fetch("tab-1".into());
        state.finish_fetch("tab-1");
        state.cancel_fetch("tab-1");
        // The token we held a reference to never fires after finish.
        assert!(!token.is_cancelled());
    }

    #[test]
    fn register_fetch_replaces_a_prior_token_without_cancelling_it() {
        // Re-registration is what happens when the user refetches the
        // same tab: the controller cancels the prior token explicitly
        // before registering the new one. `register_fetch` itself
        // doesn't fire the previous token — that's the controller's
        // contract.
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_state(tmp.path());
        let first = state.register_fetch("tab-1".into());
        let second = state.register_fetch("tab-1".into());
        state.cancel_fetch("tab-1");
        assert!(!first.is_cancelled());
        assert!(second.is_cancelled());
    }
}
