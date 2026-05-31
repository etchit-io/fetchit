//! Tauri backend for fetch>it desktop — a thin shell over `fetchit-core`
//! (the handler engine) and `fetchit-net` (the Autonomi client).

mod archive_extract;
mod cache;
mod chat;
mod disk_cache;
#[cfg(feature = "e2e")]
mod e2e;
mod linux_deep_link;
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
// `.emit()` for download-progress events — same e2e gating.
#[cfg(not(feature = "e2e"))]
use tauri::Emitter;

use disk_cache::{ClearMode, DiskCache, Policy};
use rendition::RenditionDto;
use serde::Serialize;
use settings::{Bookmark, IdlePolicy, Settings};
use state::{default_peers as bundled_peers, ensure_client, AppState};

/// Wall-clock seconds — cheap, durable, no time crate dep.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

/// Fetch `WithAutonomi`'s canonical `bootstrap_peers.toml`, parse it
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
        return Ok(RefreshResult {
            peers: current,
            updated: false,
        });
    }

    if let Ok(mut s) = state.settings.lock() {
        s.peers.clone_from(&upstream);
        let _ = s.save(&state.settings_path);
    }
    *state.client.lock().await = None;
    Ok(RefreshResult {
        peers: upstream,
        updated: true,
    })
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
fn log(line: String) {
    #[cfg(debug_assertions)]
    eprintln!("{line}");
    #[cfg(not(debug_assertions))]
    let _ = line;
}

/// Write bytes to a user-chosen file. The JS side picks the path via
/// `plugin-dialog`'s `save`; we just write what they hand us. Used by
/// the archive viewer's per-entry / whole-archive Save buttons, where
/// the browser-native `<a download>` trick fails inside the `WebView`.
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
    let mut reader = decoder
        .read_info()
        .map_err(|e| format!("png header: {e}"))?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|e| format!("png frame: {e}"))?;
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

/// Open the `WebView` devtools window. The `devtools` feature on tauri
/// makes this available in release builds too — the app is read-only,
/// so exposing devtools cannot enable writes.
#[tauri::command]
fn open_devtools(window: tauri::WebviewWindow) {
    window.open_devtools();
}

/// Base URL of the local media server (e.g. `http://127.0.0.1:54321`).
/// Renderers append `/<addr>` and set the resulting URL on `<audio>` /
/// `<video>` elements. `WebKit`'s media pipeline accepts plain `http://`
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
    let peers = if peers.is_empty() {
        state.effective_peers()
    } else {
        peers
    };
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

/// Snapshot of the on-disk cache: policy + footprint, surfaced by the
/// settings panel.
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
    // Persist through so the policy survives a relaunch. Failure here
    // doesn't affect the in-memory policy — runtime behaviour updates
    // immediately even if the save fails (read-only home dir, etc).
    if let Ok(mut s) = state.settings.lock() {
        s.cache = policy;
        let _ = s.save(&state.settings_path);
    }
}

#[tauri::command]
fn clear_cache(state: tauri::State<'_, AppState>) {
    // Both layers must be wiped — `cached_bytes` reads in-memory first
    // and would otherwise keep serving fetched bytes from the current
    // session even after the user explicitly cleared the cache.
    state.cache.clear();
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
        .is_ok_and(|s| s.bookmarks.iter().any(|b| b.address == address))
}

/// Add or rename a bookmark. Dedupes by address — re-bookmarking the same
/// address updates the label (and leaves the original `createdAt` so the
/// stable ordering survives renames).
#[tauri::command]
fn add_bookmark(state: tauri::State<'_, AppState>, address: String, label: String) {
    let Ok(mut s) = state.settings.lock() else {
        return;
    };
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
    let Ok(mut s) = state.settings.lock() else {
        return;
    };
    s.bookmarks.retain(|b| b.address != address);
    let _ = s.save(&state.settings_path);
}

#[tauri::command]
fn idle_policy(state: tauri::State<'_, AppState>) -> IdlePolicy {
    state.settings.lock().map(|s| s.idle).unwrap_or_default()
}

/// Read the persisted display name. Empty string = unset.
#[tauri::command]
fn display_name(state: tauri::State<'_, AppState>) -> String {
    state
        .settings
        .lock()
        .map(|s| s.display_name.clone())
        .unwrap_or_default()
}

/// Persist a user-chosen display name. Trims whitespace; an empty
/// string clears the value and reverts to auto-derived placeholders.
#[tauri::command]
fn set_display_name(state: tauri::State<'_, AppState>, name: String) {
    let Ok(mut s) = state.settings.lock() else {
        return;
    };
    s.display_name = name.trim().to_string();
    let _ = s.save(&state.settings_path);
}

/// Read the persisted LAN-direct opt-in flag.
#[tauri::command]
fn lan_direct_enabled(state: tauri::State<'_, AppState>) -> bool {
    state.settings.lock().is_ok_and(|s| s.lan_direct_enabled)
}

/// Flip the LAN-direct opt-in flag. Persists to disk and invalidates
/// the chat client so the next operation rebuilds with the new
/// transport set. No restart required.
#[tauri::command]
async fn set_lan_direct_enabled(
    settings_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, chat::ChatState>,
    enabled: bool,
) -> Result<(), String> {
    if let Ok(mut s) = settings_state.settings.lock() {
        s.lan_direct_enabled = enabled;
        let _ = s.save(&settings_state.settings_path);
    }
    chat_state.set_lan_direct_enabled(enabled).await;
    Ok(())
}

#[tauri::command]
fn set_idle_policy(state: tauri::State<'_, AppState>, policy: IdlePolicy) {
    let Ok(mut s) = state.settings.lock() else {
        return;
    };
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

/// Progress update for an in-flight download, forwarded to the frontend
/// as a `download-progress` event. Emitted only when the on-disk cache
/// is enabled — that is the one path that streams (see [`fetch_bytes`]).
#[cfg(not(feature = "e2e"))]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadProgressDto {
    address: String,
    phase: String,
    done: u64,
    total: u64,
}

/// Acquire the raw bytes for an address and populate the in-memory cache.
///
/// With the on-disk cache enabled the download streams into the cache
/// slot, emitting `download-progress` events; with it disabled (the
/// default) the fetch stays in memory and nothing touches disk. An `e2e`
/// build serves in-process fixtures so the desktop E2E suite is offline.
#[cfg(not(feature = "e2e"))]
async fn fetch_bytes(
    app: &tauri::AppHandle,
    state: &AppState,
    addr: &Address,
) -> Result<Bytes, String> {
    let client = ensure_client(state, &state.effective_peers()).await?;
    let bytes = if state.disk_cache.policy().enabled {
        // Cache on: stream into the cache slot, reporting progress. The
        // bytes land where the cache would have written them anyway.
        let dest = state.disk_cache.stream_path(addr);
        let app = app.clone();
        let hex = addr.to_hex();
        match client
            .fetch_with_progress(addr, &dest, move |p| {
                let _ = app.emit(
                    "download-progress",
                    DownloadProgressDto {
                        address: hex.clone(),
                        phase: p.phase.to_owned(),
                        done: p.done,
                        total: p.total,
                    },
                );
            })
            .await
        {
            Ok(()) => {
                state.disk_cache.commit_stream(addr);
                state
                    .disk_cache
                    .get(addr)
                    .ok_or_else(|| "download finished but the cache slot was empty".to_string())?
            }
            Err(e) => {
                state.disk_cache.discard_stream(addr);
                return Err(e.to_string());
            }
        }
    } else {
        // Cache off: in-memory fetch, no on-disk trace.
        client.fetch(addr).await.map_err(|e| e.to_string())?
    };
    state.cache.put(*addr, bytes.clone());
    Ok(bytes)
}

#[cfg(feature = "e2e")]
async fn fetch_bytes(
    _app: &tauri::AppHandle,
    state: &AppState,
    addr: &Address,
) -> Result<Bytes, String> {
    let bytes = e2e::fixture_bytes(addr)?;
    state.cache.put(*addr, bytes.clone());
    Ok(bytes)
}

#[tauri::command]
async fn fetch_and_render(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    addr: String,
    tab_id: String,
) -> Result<RenditionDto, String> {
    let parsed: Address = addr
        .parse()
        .map_err(|e: fetchit_core::Error| e.to_string())?;
    let token = state.register_fetch(tab_id.clone());
    let work = async {
        let bytes = match state.cached_bytes(&parsed) {
            Some(b) => b,
            None => fetch_bytes(&app, &state, &parsed).await?,
        };
        default_registry()
            .render(bytes, &Hint::default(), &RenderContext::default())
            .map(RenditionDto::from)
            .map_err(|e| e.to_string())
    };
    let result = tokio::select! {
        r = work => r,
        () = token.cancelled() => Err("fetch cancelled".to_string()),
    };
    state.finish_fetch(&tab_id);
    result
}

/// Cancel any in-flight fetch registered for `tab_id`. Fire-and-forget
/// from the frontend: no error if nothing is pending. The Rust task
/// stops at its next `.await` after the token flips, so cancellation
/// is "soon" but not instantaneous.
#[tauri::command]
fn cancel_fetch(state: tauri::State<'_, AppState>, tab_id: String) {
    state.cancel_fetch(&tab_id);
}

/// Build the chat state from a relay URL, falling back to the default
/// URL when the user-supplied one is malformed.
///
/// # Panics
/// Cannot panic in practice — `settings::DEFAULT_RELAY_URL` is a
/// compile-time constant known to parse as a valid URL. The `expect`
/// guards a programming error in the fallback constant.
#[allow(clippy::expect_used)]
fn build_chat_state(
    relay_url: &str,
    data_dir: std::path::PathBuf,
    lan_direct_enabled: bool,
) -> chat::ChatState {
    match chat::ChatState::new(relay_url, data_dir.clone(), None, lan_direct_enabled) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[fetchit][chat] invalid relay_url ({relay_url}): {e}; falling back to default"
            );
            chat::ChatState::new(
                settings::DEFAULT_RELAY_URL,
                data_dir,
                None,
                lan_direct_enabled,
            )
            .expect("default relay url is always valid")
        }
    }
}

/// Build and run the Tauri application: wires the URI scheme protocols,
/// loads persisted settings, manages app state, and starts the local
/// media server.
///
/// # Panics
///
/// Panics if the Tauri runtime fails to start — an unrecoverable startup
/// error with nothing to fall back to.
#[allow(clippy::expect_used)] // entry point: a failed startup is unrecoverable
#[allow(clippy::too_many_lines)] // dominated by the invoke-handler list
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
        .plugin(tauri_plugin_notification::init())
        .register_asynchronous_uri_scheme_protocol("fetchit", protocol::handle)
        .register_asynchronous_uri_scheme_protocol("autonomi", protocol::handle)
        .setup(move |app| {
            use tauri::Manager;

            // Deep-link: register `autonomi://` and `fetchit://` with the OS
            // on Linux + Windows. macOS reads the schemes from Info.plist via
            // the bundle config and registers automatically. Linux additionally
            // skips runtime registration when a bundle install (.deb / .rpm)
            // already claims the schemes — prevents duplicate "fetchit" entries
            // in "Open With" dialogs on machines that have both an installed
            // bundle and a dev/AppImage run on disk.
            #[cfg(target_os = "windows")]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let _ = app.deep_link().register_all();
            }
            #[cfg(target_os = "linux")]
            crate::linux_deep_link::register_or_cleanup(app.handle());

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
            let relay_url = loaded.relay_url.clone();
            let lan_direct_enabled = loaded.lan_direct_enabled;

            let state = AppState::new(disk_cache, loaded, settings_path);
            let server_state = state.clone();
            app.manage(state);

            let chat_state =
                build_chat_state(&relay_url, app_data.join("chat"), lan_direct_enabled);
            app.manage(chat_state.clone());
            chat::spawn_event_pump(app.handle().clone(), chat_state);

            tauri::async_runtime::spawn(async move {
                match server::spawn(server_state).await {
                    Ok(port) => {
                        let _ = MEDIA_URL_BASE.set(format!("http://127.0.0.1:{port}"));
                    }
                    Err(e) => eprintln!("[fetchit] media server failed to bind: {e}"),
                }
            });
            // Devtools is reachable via F12 / Ctrl-Shift-I / right-click
            // in every build.
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
            cancel_fetch,
            list_bookmarks,
            is_bookmarked,
            add_bookmark,
            remove_bookmark,
            idle_policy,
            set_idle_policy,
            idle_disconnect,
            display_name,
            set_display_name,
            lan_direct_enabled,
            set_lan_direct_enabled,
            chat::chat_health,
            chat::chat_list_nearby,
            chat::chat_identity,
            chat::chat_card,
            chat::chat_import_card,
            chat::chat_pair_accept,
            chat::chat_pair_share,
            chat::chat_contacts,
            chat::chat_set_trust,
            chat::chat_remove_contact,
            chat::chat_send_dm,
            chat::chat_dm_connect,
            chat::chat_presence_online,
            chat::chat_groups_list,
            chat::chat_group_create,
            chat::chat_group_invite,
            chat::chat_group_join,
            chat::chat_group_send,
            chat::chat_group_messages,
            chat::chat_group_leave,
            chat::chat_set_passphrase,
            chat::chat_confirm_contact,
            chat::chat_watch_presence,
            chat::chat_unwatch_presence,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
