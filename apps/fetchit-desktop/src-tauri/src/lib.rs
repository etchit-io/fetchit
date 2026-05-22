//! Tauri backend for fetch>it desktop — a thin shell over `fetchit-core`
//! (the handler engine) and `fetchit-net` (the Autonomi client).

mod archive_extract;
mod cache;
mod disk_cache;
#[cfg(feature = "e2e")]
mod e2e;
mod protocol;
mod rendition;
mod server;
mod settings;
mod state;

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use fetchit_core::handlers::default_registry;
use fetchit_core::{Address, Hint, RenderContext};
// Brings `.fetch()` into scope — unused once the e2e build stubs fetching.
#[cfg(not(feature = "e2e"))]
use fetchit_core::NetworkClient;

use disk_cache::{ClearMode, DiskCache, Policy};
use rendition::RenditionDto;
use serde::Serialize;
use settings::{Bookmark, IdlePolicy, Settings};
use state::{default_peers as bundled_peers, ensure_client, AppState};

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

/// The bundled default peer list (production network). The frontend
/// pre-fills the editor with this when the user hasn't saved an override.
#[tauri::command]
fn default_peers() -> Vec<String> {
    bundled_peers()
}

/// User's current bootstrap-peer override, or empty if they're on the
/// bundled defaults. Stored in `settings.json`.
#[tauri::command]
fn peers_override(state: tauri::State<'_, AppState>) -> Vec<String> {
    state
        .settings
        .lock()
        .map(|s| s.peers.clone())
        .unwrap_or_default()
}

/// Save a user-supplied peer list (one entry per element). Each entry
/// must parse via `parse_bootstrap_peer` — either an `ip:port`
/// shorthand or a full multiaddr. Returns the cleaned list that was
/// persisted (empty entries dropped, whitespace trimmed). Drops any
/// active client so the next fetch reconnects with the new list.
#[tauri::command]
async fn set_peers_override(
    state: tauri::State<'_, AppState>,
    peers: Vec<String>,
) -> Result<Vec<String>, String> {
    let cleaned: Vec<String> = peers
        .into_iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    for p in &cleaned {
        fetchit_net::parse_bootstrap_peer(p)?;
    }
    if let Ok(mut s) = state.settings.lock() {
        s.peers.clone_from(&cleaned);
        let _ = s.save(&state.settings_path);
    }
    *state.client.lock().await = None;
    Ok(cleaned)
}

/// Clear any saved peer override; next fetch will reconnect using the
/// bundled defaults. Drops any active client.
#[tauri::command]
async fn reset_peers_override(state: tauri::State<'_, AppState>) -> Result<(), String> {
    if let Ok(mut s) = state.settings.lock() {
        s.peers.clear();
        let _ = s.save(&state.settings_path);
    }
    *state.client.lock().await = None;
    Ok(())
}

/// Outcome of [`refresh_peers_from_upstream`]: the list now active +
/// whether it changed from what was previously effective.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResult {
    peers: Vec<String>,
    updated: bool,
}

const UPSTREAM_PEERS_URL: &str =
    "https://raw.githubusercontent.com/WithAutonomi/ant-node/main/config/bootstrap_peers.toml";

/// Fetch WithAutonomi's canonical `bootstrap_peers.toml`, parse it
/// tolerantly (any string leaf that passes `parse_bootstrap_peer`
/// counts), and replace the user override + cached client if it
/// differs from the currently-effective list. Always writes fresh on
/// every call — no diff-and-skip, no soft-merge.
#[tauri::command]
async fn refresh_peers_from_upstream(
    state: tauri::State<'_, AppState>,
) -> Result<RefreshResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("http client build: {e}"))?;
    let body = client
        .get(UPSTREAM_PEERS_URL)
        .send()
        .await
        .map_err(|e| format!("GET {UPSTREAM_PEERS_URL} failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("upstream HTTP error: {e}"))?
        .text()
        .await
        .map_err(|e| format!("read upstream body: {e}"))?;

    let value: toml::Value = body
        .parse()
        .map_err(|e| format!("upstream is not valid TOML: {e}"))?;
    let mut found: Vec<String> = Vec::new();
    collect_toml_strings(&value, &mut found);
    let upstream: Vec<String> = found
        .into_iter()
        .filter(|s| fetchit_net::parse_bootstrap_peer(s).is_ok())
        .collect();
    if upstream.is_empty() {
        return Err("upstream TOML had no recognisable peer entries".into());
    }

    let current = state.effective_peers();
    if upstream == current {
        return Ok(RefreshResult { peers: current, updated: false });
    }

    if let Ok(mut s) = state.settings.lock() {
        s.peers.clone_from(&upstream);
        let _ = s.save(&state.settings_path);
    }
    *state.client.lock().await = None;
    Ok(RefreshResult { peers: upstream, updated: true })
}

fn collect_toml_strings(value: &toml::Value, out: &mut Vec<String>) {
    match value {
        toml::Value::String(s) => out.push(s.clone()),
        toml::Value::Array(arr) => {
            for v in arr {
                collect_toml_strings(v, out);
            }
        }
        toml::Value::Table(t) => {
            for (_, v) in t {
                collect_toml_strings(v, out);
            }
        }
        _ => {}
    }
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

/// Write bytes to a user-chosen file. The JS side picks the path via
/// `plugin-dialog`'s `save`; we just write what they hand us. Used by
/// the archive viewer's per-entry / whole-archive Save buttons, where
/// the browser-native `<a download>` trick fails inside the WebView.
#[tauri::command]
fn save_bytes_to_path(path: String, data: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, &data).map_err(|e| format!("couldn't write {path}: {e}"))
}

/// Decode a PNG and write it to the OS clipboard as an image, in a single
/// backend hop. The QR share modal calls this instead of the JS-side
/// `Image.fromBytes(..)` → `writeImage(img)` chain because that chain
/// crosses the IPC boundary twice carrying an `Image` resource handle in
/// between, and on webkit2gtk that resource sometimes never makes it
/// back across the second invoke (the handle is reaped before the
/// clipboard write resolves). Doing the decode + clipboard write in one
/// Rust frame sidesteps the cross-IPC resource lifecycle entirely. The
/// clipboard plugin takes RGBA bytes, not encoded PNG, so we decode
/// here using the `png` crate.
#[tauri::command]
fn copy_png_to_clipboard(app: tauri::AppHandle, data: Vec<u8>) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    let decoder = png::Decoder::new(std::io::Cursor::new(&data));
    let mut reader = decoder.read_info().map_err(|e| format!("png header: {e}"))?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).map_err(|e| format!("png frame: {e}"))?;
    buf.truncate(info.buffer_size());
    // Canvas.toBlob("image/png") emits RGBA8. Defend against the off
    // chance a future renderer emits something else by widening here
    // rather than silently writing a malformed buffer to the clipboard.
    let rgba = match info.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => {
            let mut out = Vec::with_capacity(buf.len() / 3 * 4);
            for px in buf.chunks_exact(3) {
                out.extend_from_slice(&[px[0], px[1], px[2], 0xff]);
            }
            out
        }
        other => return Err(format!("unsupported png color type: {other:?}")),
    };
    let img = tauri::image::Image::new_owned(rgba, info.width, info.height);
    app.clipboard()
        .write_image(&img)
        .map_err(|e| format!("clipboard write: {e}"))
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
    let peers = if peers.is_empty() { state.effective_peers() } else { peers };
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

/// Acquire the raw bytes for an address. Normal builds fetch from the
/// Autonomi network; an `e2e` build serves in-process fixtures so the
/// desktop E2E suite is deterministic and offline.
#[cfg(not(feature = "e2e"))]
async fn fetch_bytes(state: &AppState, addr: &Address) -> Result<Bytes, String> {
    let client = ensure_client(state, &state.effective_peers()).await?;
    client.fetch(addr).await.map_err(|e| e.to_string())
}

#[cfg(feature = "e2e")]
async fn fetch_bytes(_state: &AppState, addr: &Address) -> Result<Bytes, String> {
    e2e::fixture_bytes(addr)
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
            let b = fetch_bytes(&state, &parsed).await?;
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
        // single-instance MUST be first per plugin docs — it short-
        // circuits the secondary process before any other plugin
        // initialises. The `deep-link` feature on the dep wires
        // forwarded argv URLs straight into the same on_open_url
        // listeners the first instance already registered, so the
        // controller's deep-link handler fires unchanged.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
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
            peers_override,
            set_peers_override,
            reset_peers_override,
            refresh_peers_from_upstream,
            connect,
            peer_count,
            disconnect,
            fetch_and_render,
            archive_extract::extract_archive_entry,
            save_bytes_to_path,
            copy_png_to_clipboard,
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
