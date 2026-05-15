//! Tauri backend for fetch>it desktop — a thin shell over `fetchit-core`
//! (the handler engine) and `fetchit-net` (the Autonomi client).

mod cache;
mod disk_cache;
mod protocol;
mod rendition;
mod server;
mod settings;
mod state;

use std::sync::{Arc, OnceLock};

use fetchit_core::handlers::default_registry;
use fetchit_core::{Address, Hint, NetworkClient, RenderContext};

use disk_cache::{ClearMode, DiskCache, Policy};
use rendition::RenditionDto;
use serde::Serialize;
use settings::{Bookmark, IdlePolicy, Settings};
use state::{default_peers as peer_list, ensure_client, AppState};

/// Wall-clock seconds — cheap, durable, no time crate dep.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Filled in by `run`'s setup callback once the local media server is bound.
/// JS reads it via [`media_url_base`].
static MEDIA_URL_BASE: OnceLock<String> = OnceLock::new();

#[tauri::command]
fn default_peers() -> Vec<String> {
    peer_list()
}

/// JS-side diagnostic forwarding: anything the frontend wants to land in the
/// dev daemon log calls this so we can tail everything in one place. No-op in
/// release builds — the JS side gates calls behind `import.meta.env.DEV` too,
/// so the IPC isn't even fired.
#[tauri::command]
fn log(_line: String) {
    #[cfg(debug_assertions)]
    eprintln!("{_line}");
}

/// Open the WebView devtools window. The `devtools` feature on tauri makes
/// this available in release builds too — the desktop app is read-only, so
/// letting power users inspect what's being rendered is fine.
#[tauri::command]
fn open_devtools(window: tauri::WebviewWindow) {
    window.open_devtools();
}

/// Base URL of the local media server (e.g. `http://127.0.0.1:54321`).
/// Renderers append `/<addr>` and set the resulting URL on `<audio>` /
/// `<video>` elements. WebKit's media pipeline accepts plain `http://`
/// where it rejects our `fetchit://` / `autonomi://` schemes.
#[tauri::command]
fn media_url_base() -> Result<String, String> {
    MEDIA_URL_BASE
        .get()
        .cloned()
        .ok_or_else(|| "media server not ready".to_string())
}

#[tauri::command]
async fn connect(state: tauri::State<'_, AppState>, peers: Vec<String>) -> Result<(), String> {
    let peers = if peers.is_empty() { peer_list() } else { peers };
    ensure_client(&state, &peers).await.map(|_| ())
}

#[tauri::command]
async fn peer_count(state: tauri::State<'_, AppState>) -> Result<u64, String> {
    match state.client.lock().await.as_ref() {
        Some(c) => Ok(c.peer_count().await as u64),
        None => Ok(0),
    }
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state.client.lock().await = None;
    state.cache.clear();
    Ok(())
}

/// Snapshot of the on-disk cache: policy + footprint. Wired to the settings
/// panel so the user can see "currently using N MB across M files".
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheStats {
    policy: Policy,
    size_bytes: u64,
    file_count: usize,
    path: String,
}

#[tauri::command]
fn cache_stats(state: tauri::State<'_, AppState>) -> CacheStats {
    CacheStats {
        policy: state.disk_cache.policy(),
        size_bytes: state.disk_cache.size_on_disk(),
        file_count: state.disk_cache.file_count(),
        path: state.disk_cache.root().to_string_lossy().into_owned(),
    }
}

#[tauri::command]
fn set_cache_policy(state: tauri::State<'_, AppState>, policy: Policy) {
    state.disk_cache.set_policy(policy);
    // Persist through so the choice survives a relaunch. Failure here doesn't
    // affect the in-memory policy — the user sees the new behaviour
    // immediately, even if the save couldn't land (read-only home dir, etc).
    if let Ok(mut s) = state.settings.lock() {
        s.cache = policy;
        let _ = s.save(&state.settings_path);
    }
}

#[tauri::command]
fn clear_cache(state: tauri::State<'_, AppState>) {
    state.disk_cache.clear();
}

#[tauri::command]
fn list_bookmarks(state: tauri::State<'_, AppState>) -> Vec<Bookmark> {
    state
        .settings
        .lock()
        .map(|s| s.bookmarks.clone())
        .unwrap_or_default()
}

#[tauri::command]
fn is_bookmarked(state: tauri::State<'_, AppState>, address: String) -> bool {
    state
        .settings
        .lock()
        .map(|s| s.bookmarks.iter().any(|b| b.address == address))
        .unwrap_or(false)
}

/// Add or rename a bookmark. Dedupes by address — re-bookmarking the same
/// address updates the label (and leaves the original `createdAt` so the
/// stable ordering survives renames).
#[tauri::command]
fn add_bookmark(state: tauri::State<'_, AppState>, address: String, label: String) {
    let Ok(mut s) = state.settings.lock() else { return };
    if let Some(existing) = s.bookmarks.iter_mut().find(|b| b.address == address) {
        existing.label = label;
    } else {
        s.bookmarks.push(Bookmark {
            address,
            label,
            created_at: now_secs(),
        });
    }
    let _ = s.save(&state.settings_path);
}

#[tauri::command]
fn remove_bookmark(state: tauri::State<'_, AppState>, address: String) {
    let Ok(mut s) = state.settings.lock() else { return };
    s.bookmarks.retain(|b| b.address != address);
    let _ = s.save(&state.settings_path);
}

#[tauri::command]
fn idle_policy(state: tauri::State<'_, AppState>) -> IdlePolicy {
    state
        .settings
        .lock()
        .map(|s| s.idle)
        .unwrap_or_default()
}

#[tauri::command]
fn set_idle_policy(state: tauri::State<'_, AppState>, policy: IdlePolicy) {
    let Ok(mut s) = state.settings.lock() else { return };
    s.idle = policy;
    let _ = s.save(&state.settings_path);
}

/// Run when the JS-side idle timer expires. Drops the Autonomi client
/// connection, wipes the in-memory cache, and — if the disk-cache policy
/// is `OnIdle` — wipes the on-disk cache too. Always safe to invoke
/// (no-ops cleanly if nothing was open).
#[tauri::command]
async fn idle_disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state.client.lock().await = None;
    state.cache.clear();
    let mode = state.disk_cache.policy().mode;
    if mode == ClearMode::OnIdle {
        state.disk_cache.clear();
    }
    Ok(())
}

#[tauri::command]
async fn fetch_and_render(
    state: tauri::State<'_, AppState>,
    addr: String,
) -> Result<RenditionDto, String> {
    let parsed: Address = addr.parse().map_err(|e: fetchit_core::Error| e.to_string())?;
    let bytes = match state.cached_bytes(&parsed) {
        Some(b) => b,
        None => {
            let client = ensure_client(&state, &peer_list()).await?;
            let b = client.fetch(&parsed).await.map_err(|e| e.to_string())?;
            state.cache_bytes(&parsed, b.clone());
            b
        }
    };
    let rendition = default_registry()
        .render(bytes, &Hint::default(), &RenderContext::default())
        .map_err(|e| e.to_string())?;
    Ok(rendition.into())
}

/// Build and run the Tauri application: wires the URI scheme protocols,
/// loads persisted settings, manages app state, and starts the local
/// media server.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Two scheme aliases for the same protocol handler. The localhost HTTP
    // server is the third path WebKit's `<video>` will accept (it ignores
    // custom URI schemes for media), spawned in `setup` below.
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .register_asynchronous_uri_scheme_protocol("fetchit", protocol::handle)
        .register_asynchronous_uri_scheme_protocol("autonomi", protocol::handle)
        .setup(move |app| {
            use tauri::Manager;

            // Deep-link: register `autonomi://` and `fetchit://` with the OS
            // on Linux + Windows. macOS reads the schemes from Info.plist via
            // the bundle config and registers automatically. In dev, Linux
            // needs this runtime call so the desktop file gets installed.
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let _ = app.deep_link().register_all();
            }

            // Resolve the app-local data dir once; everything user-persisted
            // lives under it (settings.json + the on-disk byte cache).
            let app_data = app
                .path()
                .app_local_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir().join("fetchit"));
            let settings_path = app_data.join("settings.json");
            let cache_root = app_data.join("bytes_cache");

            // Load persisted settings (defaults if missing/malformed) and seed
            // the on-disk cache with the user's saved policy.
            let loaded = Settings::load(&settings_path);
            let disk_cache = Arc::new(DiskCache::new(cache_root, loaded.cache));

            let state = AppState::new(disk_cache, loaded, settings_path);
            let server_state = state.clone();
            app.manage(state);

            tauri::async_runtime::spawn(async move {
                match server::spawn(server_state).await {
                    Ok(port) => {
                        let _ = MEDIA_URL_BASE.set(format!("http://127.0.0.1:{port}"));
                    }
                    Err(e) => eprintln!("[fetchit] media server failed to bind: {e}"),
                }
            });
            // Devtools is available via F12 / Ctrl-Shift-I / right-click in every
            // build; auto-opening it on launch was noisy.
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            default_peers,
            connect,
            peer_count,
            disconnect,
            fetch_and_render,
            log,
            open_devtools,
            media_url_base,
            cache_stats,
            set_cache_policy,
            clear_cache,
            list_bookmarks,
            is_bookmarked,
            add_bookmark,
            remove_bookmark,
            idle_policy,
            set_idle_policy,
            idle_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
