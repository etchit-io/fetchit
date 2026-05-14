//! Process-scoped state for the Tauri app: the lazily-built Autonomi client
//! and the bytes cache backing the `fetchit://` protocol handler.

use crate::cache::BytesCache;
use fetchit_net::{AutonomiClient, DEFAULT_PEERS};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default, Clone)]
pub struct AppState {
    pub client: Arc<Mutex<Option<AutonomiClient>>>,
    pub cache: Arc<BytesCache>,
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
