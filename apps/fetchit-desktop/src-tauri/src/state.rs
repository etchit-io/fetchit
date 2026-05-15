//! Process-scoped state for the Tauri app: the lazily-built Autonomi client,
//! the in-memory bytes cache, and the (opt-in) on-disk bytes cache.

use crate::cache::BytesCache;
use crate::disk_cache::DiskCache;
use crate::settings::Settings;
use bytes::Bytes;
use fetchit_core::Address;
use fetchit_net::{AutonomiClient, DEFAULT_PEERS};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub client: Arc<Mutex<Option<AutonomiClient>>>,
    pub cache: Arc<BytesCache>,
    pub disk_cache: Arc<DiskCache>,
    /// In-memory copy of settings.json; serialise all read-modify-write
    /// operations through the std mutex (critical sections never `.await`).
    pub settings: Arc<StdMutex<Settings>>,
    pub settings_path: Arc<PathBuf>,
}

impl AppState {
    pub fn new(disk_cache: Arc<DiskCache>, settings: Settings, settings_path: PathBuf) -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
            cache: Arc::new(BytesCache::default()),
            disk_cache,
            settings: Arc::new(StdMutex::new(settings)),
            settings_path: Arc::new(settings_path),
        }
    }

    /// Layered cache lookup: memory hit first; on miss, consult disk and
    /// hydrate the memory layer for subsequent hits in this session.
    pub fn cached_bytes(&self, addr: &Address) -> Option<Bytes> {
        if let Some(b) = self.cache.get(addr) {
            return Some(b);
        }
        let b = self.disk_cache.get(addr)?;
        self.cache.put(addr.clone(), b.clone());
        Some(b)
    }

    /// Write-through: every fresh fetch lands in both layers.
    /// `disk_cache.put` is a no-op when the policy is disabled.
    pub fn cache_bytes(&self, addr: &Address, bytes: Bytes) {
        self.cache.put(addr.clone(), bytes.clone());
        self.disk_cache.put(addr, &bytes);
    }
}

pub async fn ensure_client(state: &AppState, peers: &[String]) -> Result<AutonomiClient, String> {
    let mut guard = state.client.lock().await;
    if let Some(c) = guard.as_ref() {
        return Ok(c.clone());
    }
    let c = AutonomiClient::connect(peers).await.map_err(|e| e.to_string())?;
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
