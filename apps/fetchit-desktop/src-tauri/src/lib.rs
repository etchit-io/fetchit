//! Tauri backend for fetch>it desktop — a thin shell over `fetchit-core`
//! (the handler engine) and `fetchit-net` (the Autonomi client).

mod archive_extract;
mod cache;
mod chat;
mod disk_cache;
#[cfg(feature = "e2e")]
mod e2e;
mod etchit_handoff;
mod fediverse;
mod fediverse_lookup;
mod linux_deep_link;
mod profile;
mod protocol;
mod rendition;
mod server;
mod settings;
mod state;
mod x0xd_supervisor;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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

/// Set to `true` when `boot_x0xd_supervisor_blocking` picks the bundled
/// binary and starts the respawn task. `spawn_x0xd_supervisor` in chat.rs
/// checks this to avoid racing over the same x0xd process.
static BUNDLED_SUPERVISOR_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Holds the bundled-x0xd [`SupervisorTask`] for the lifetime of the app.
/// Populated once by `boot_x0xd_supervisor_blocking`; dropped when the
/// process exits.
static SUPERVISOR_TASK: OnceLock<Mutex<Option<x0xd_supervisor::SupervisorTask>>> = OnceLock::new();

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

/// Read the first-run onboarding marker.
#[tauri::command]
fn onboarding_done(state: tauri::State<'_, AppState>) -> bool {
    state.settings.lock().is_ok_and(|s| s.onboarding_done)
}

/// Mark first-run onboarding as completed (or skipped). One-way.
#[tauri::command]
fn set_onboarding_done(state: tauri::State<'_, AppState>) {
    let Ok(mut s) = state.settings.lock() else {
        return;
    };
    s.onboarding_done = true;
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

/// Flip the chat feature flag at runtime. Persists the setting, then
/// returns the RESOLVED flag (the `FETCHIT_CHAT_ENABLED` env override
/// still wins) so the frontend reflects reality. When the resolved
/// flag is on, starts the chat event pump if not already running.
#[tauri::command]
fn set_chat_enabled(
    app: tauri::AppHandle,
    settings_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, chat::ChatState>,
    enabled: bool,
) -> bool {
    if let Ok(mut s) = settings_state.settings.lock() {
        s.chat_enabled = enabled;
        let _ = s.save(&settings_state.settings_path);
    }
    let resolved = settings_state.settings.lock().map_or_else(
        |_| cfg!(debug_assertions),
        |s| settings::resolve_chat_enabled(&s),
    );
    if resolved {
        chat::ensure_event_pump(app, chat_state.inner().clone());
    }
    resolved
}

/// Snapshot the fetchit-operated relay nodes the desktop knows about.
/// The frontend reads this once and renders a region dropdown; entries
/// are added by appending to [`settings::KNOWN_RELAYS`] without a JS
/// update.
#[tauri::command]
fn relay_regions() -> Vec<settings::KnownRelay> {
    settings::KNOWN_RELAYS.to_vec()
}

/// Read the persisted relay URL the chat client points at.
#[tauri::command]
fn relay_url(state: tauri::State<'_, AppState>) -> String {
    state.settings.lock().map_or_else(
        |_| settings::DEFAULT_RELAY_URL.to_owned(),
        |s| s.relay_url.clone(),
    )
}

/// Switch to a new relay URL (either a `KNOWN_RELAYS` entry or a custom
/// URL the user typed in). Persists to disk and invalidates the chat
/// client so the next chat op reconnects against the new relay. No
/// restart required.
#[tauri::command]
async fn set_relay_url(
    settings_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, chat::ChatState>,
    url: String,
) -> Result<(), String> {
    chat_state.set_relay_url(&url).await?;
    if let Ok(mut s) = settings_state.settings.lock() {
        s.relay_url = url;
        let _ = s.save(&settings_state.settings_path);
    }
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

/// Fetch raw bytes for a 64-hex Autonomi address via the `AppState`
/// client, rejecting a blob larger than `cap` (a sanity bound: the
/// caller knows the expected size class). Used by the profile commands.
///
/// # Errors
/// Returns a user-facing string when the address is malformed, the
/// fetch fails, or the blob exceeds `cap`.
pub(crate) async fn fetch_autonomi_bytes(
    app_state: &tauri::State<'_, AppState>,
    addr_hex: &str,
    cap: usize,
) -> Result<Vec<u8>, String> {
    use fetchit_core::NetworkClient as _;
    let addr: Address = addr_hex
        .parse()
        .map_err(|e: fetchit_core::Error| e.to_string())?;
    let client = ensure_client(app_state, &app_state.effective_peers()).await?;
    let bytes = client.fetch(&addr).await.map_err(|e| e.to_string())?;
    if bytes.len() > cap {
        return Err(format!(
            "blob is larger than expected ({} > {cap} bytes)",
            bytes.len()
        ));
    }
    Ok(bytes.to_vec())
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
    let (token, generation) = state.register_fetch(tab_id.clone());
    let work = async {
        let bytes = match state.cached_bytes(&parsed) {
            Some(b) => b,
            None => fetch_bytes(&app, &state, &parsed).await?,
        };
        default_registry()
            .render_with_context(
                bytes,
                &Hint::default(),
                &RenderContext::default(),
                &state.rendering_context(parsed.to_hex()),
            )
            .map(RenditionDto::from)
            .map_err(|e| e.to_string())
    };
    let result = tokio::select! {
        r = work => r,
        () = token.cancelled() => Err("fetch cancelled".to_string()),
    };
    state.finish_fetch(&tab_id, generation);
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

/// Read-only Tauri command surfacing the resolved chat feature flag
/// to the frontend so the chat panel + toolbar toggle can hide
/// themselves when chat is off. Frontend queries this once at
/// startup. Resolver lives in [`settings::resolve_chat_enabled`].
#[tauri::command]
fn chat_feature_enabled(state: tauri::State<'_, AppState>) -> bool {
    state.settings.lock().map_or_else(
        |_| cfg!(debug_assertions),
        |s| settings::resolve_chat_enabled(&s),
    )
}

/// Resource path for the bundled x0xd binary shipped inside the app bundle.
///
/// Reads the `FETCHIT_BUNDLED_X0XD_PATH_REL` env var stamped by `build.rs`
/// when the binary is staged under `resources/`. At runtime, tries two
/// resolution bases in order: CWD (for `cargo run` from `src-tauri/`) then
/// next to the executable (for installed bundles). Returns `None` when the
/// env var is unset (default dev build) or neither candidate exists, so the
/// supervisor falls through to `discover_installed_x0xd()`.
fn bundled_x0xd_binary_path() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let rel = option_env!("FETCHIT_BUNDLED_X0XD_PATH_REL")?;
    let rel_path = PathBuf::from(rel);
    let candidates = [
        std::env::current_dir().ok().map(|c| c.join(&rel_path)),
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|d| d.join(&rel_path))),
    ];
    candidates.into_iter().flatten().find(|p| p.exists())
}

/// Config-dir path for the x0xd TOML used when spawning the bundled binary.
///
/// On first run, copies `resources/x0xd.toml.tpl` into the OS config dir
/// (`$XDG_CONFIG_HOME/fetchit/x0xd.toml` on Linux,
/// `%APPDATA%\fetchit\x0xd.toml` on Windows,
/// `~/Library/Application Support/fetchit/x0xd.toml` on macOS),
/// substituting any `FETCHIT_*_RELAY_AGENT_ID` env vars set at build/release
/// time plus the app-managed `identity_dir` (the directory fetch>it seeds
/// from the chat vault so the daemon boots as the unified agent).
/// Subsequent runs reuse the existing file so user edits persist —
/// except `identity_dir`, which is appended when missing so installs
/// that predate identity unification pick it up.
fn bundled_x0xd_toml_path(identity_dir: &std::path::Path) -> std::path::PathBuf {
    let cfg_base = dirs::config_dir().unwrap_or_else(std::env::temp_dir);
    let app_cfg = cfg_base.join("fetchit");
    let _ = std::fs::create_dir_all(&app_cfg);
    let dst = app_cfg.join("x0xd.toml");
    // TOML basic strings treat backslash as an escape; forward slashes
    // work on every OS the daemon runs on.
    let id_dir_toml = identity_dir.display().to_string().replace('\\', "/");
    if dst.exists() {
        // Existing install: user edits persist, but identity unification
        // needs the daemon reading the seeded directory. Append the key
        // only when absent so a hand-edited value wins.
        if let Ok(body) = std::fs::read_to_string(&dst) {
            let has_identity_dir = body
                .lines()
                .any(|l| l.trim_start().starts_with("identity_dir"));
            if !has_identity_dir {
                let _ = std::fs::write(
                    &dst,
                    format!("{body}\nidentity_dir = \"{id_dir_toml}\"\n"),
                );
            }
        }
    } else {
        let tpl = include_str!("../resources/x0xd.toml.tpl");
        let mut filled = tpl.to_owned();
        filled = filled.replace("PLACEHOLDER_IDENTITY_DIR", &id_dir_toml);
        if let Ok(ny) = std::env::var("FETCHIT_NY_RELAY_AGENT_ID") {
            filled = filled.replace("PLACEHOLDER_NY_RELAY_AGENT_ID_HEX", &ny);
        }
        if let Ok(fra) = std::env::var("FETCHIT_FRA_RELAY_AGENT_ID") {
            filled = filled.replace("PLACEHOLDER_FRA_RELAY_AGENT_ID_HEX", &fra);
        }
        let _ = std::fs::write(&dst, filled);
    }
    dst
}

#[cfg(all(test, target_os = "linux"))]
mod e2_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::bundled_x0xd_toml_path;
    use std::sync::Mutex;

    // Serialises all tests that mutate env vars in this module so that
    // concurrent test threads do not observe each other's env mutations.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn first_run_copies_tpl_and_substitutes_placeholders() {
        let _guard = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let temp = tempfile::tempdir().unwrap();
        // Point XDG_CONFIG_HOME at the temp dir so dirs::config_dir()
        // returns a predictable, isolated path.
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        let aid = "deadbeef".repeat(8); // 64-hex
        std::env::set_var("FETCHIT_NY_RELAY_AGENT_ID", &aid);
        let id_dir = temp.path().join("x0xd-identity");

        let path = bundled_x0xd_toml_path(&id_dir);
        let body = std::fs::read_to_string(&path).expect("template must be copied on first run");

        assert!(body.contains(&aid), "NY placeholder must be substituted");
        assert!(
            !body.contains("PLACEHOLDER_NY_RELAY_AGENT_ID_HEX"),
            "NY placeholder must be removed"
        );
        assert!(
            body.contains(&format!("identity_dir = \"{}\"", id_dir.display())),
            "identity_dir must be substituted so the daemon boots as the seeded agent"
        );
        assert!(!body.contains("PLACEHOLDER_IDENTITY_DIR"));

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("FETCHIT_NY_RELAY_AGENT_ID");
    }

    #[test]
    fn existing_toml_gains_identity_dir_but_keeps_user_edits() {
        let _guard = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        // Simulate an install that predates identity unification: a
        // user-edited TOML with no identity_dir.
        let cfg_dir = temp.path().join("fetchit");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(cfg_dir.join("x0xd.toml"), "# my precious edits\n").unwrap();
        let id_dir = temp.path().join("x0xd-identity");

        let path = bundled_x0xd_toml_path(&id_dir);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("# my precious edits"), "user edits persist");
        assert!(
            body.contains(&format!("identity_dir = \"{}\"", id_dir.display())),
            "identity_dir appended for pre-unification installs"
        );

        // A hand-set identity_dir wins: calling again must not stack a
        // second entry.
        let again = bundled_x0xd_toml_path(&temp.path().join("other"));
        let body2 = std::fs::read_to_string(&again).unwrap();
        assert_eq!(
            body2.matches("identity_dir").count(),
            1,
            "existing identity_dir must not be duplicated or overridden"
        );

        std::env::remove_var("XDG_CONFIG_HOME");
    }
}

/// Boot the x0xd supervisor synchronously, blocking the caller (the Tauri
/// `setup` hook, on the main thread, before the webview shows content).
///
/// `identity_dir` is the app-managed directory the chat vault seeded with
/// the unified `agent.key`; it is substituted into (or appended to) the
/// bundled TOML so the daemon boots as that agent.
///
/// Builds a [`x0xd_supervisor::SupervisorConfig`], blocks on
/// [`x0xd_supervisor::boot_supervisor`] using a fresh Tokio runtime, and
/// returns the x0xd base URL to thread into the chat client:
/// - Bundled binary chosen: `Some("http://127.0.0.1:<managed-port>")`.
/// - Installed binary chosen (or no binary available): `None`; the chat
///   client falls back to `discover_local()` on first use.
fn boot_x0xd_supervisor_blocking(identity_dir: &std::path::Path) -> Option<String> {
    use std::time::Duration;
    use x0xd_supervisor::{BinaryChoice, SupervisorConfig};

    let bundled_version = option_env!("FETCHIT_BUNDLED_X0XD_VERSION")
        .unwrap_or("0.23.1")
        .parse::<semver::Version>()
        .ok();

    let cfg = SupervisorConfig {
        bundled_binary: bundled_x0xd_binary_path(),
        bundled_version,
        bundled_toml: bundled_x0xd_toml_path(identity_dir),
        port_range: (45_000, 45_100),
        crash_window: Duration::from_secs(30),
        crash_threshold: 3,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(rt) = rt else {
        // Fires before `run()` wires `tauri-plugin-log`, so no tracing
        // subscriber would catch a `tracing::warn!` here. Stay on stderr
        // so dev terminals still see the failure.
        eprintln!("[fetchit][supervisor] failed to build runtime for boot; chat uses discovery");
        return None;
    };

    let boot_result = rt.block_on(x0xd_supervisor::boot_supervisor(cfg.clone()));
    match boot_result {
        Ok(handle) => match handle.choice {
            BinaryChoice::Bundled { ref binary, .. } if handle.port != 0 => {
                let binary = binary.clone();
                let disabled = handle.disabled.clone();
                let port = handle.port;
                // Spawn the respawn loop on the Tauri async runtime, which
                // outlives this boot helper. The local `rt` is dropped after
                // this function returns; tasks spawned on it would be aborted.
                // `spawn_supervisor_task` calls `tokio::spawn` internally, so
                // we enter the Tauri runtime's context before calling it.
                let _enter = tauri::async_runtime::handle().inner().enter();
                let task = x0xd_supervisor::spawn_supervisor_task(cfg, binary, disabled);
                let cell = SUPERVISOR_TASK.get_or_init(|| Mutex::new(None));
                if let Ok(mut g) = cell.lock() {
                    *g = Some(task);
                }
                BUNDLED_SUPERVISOR_ACTIVE.store(true, Ordering::Release);
                Some(format!("http://127.0.0.1:{port}"))
            }
            _ => None,
        },
        Err(e) => {
            // Same pre-init lifetime as the runtime-build branch above.
            eprintln!("[fetchit][supervisor] boot_supervisor: {e}; chat uses discovery");
            None
        }
    }
}

/// Build the chat state from a relay URL, falling back to the default
/// URL when the user-supplied one is malformed. `x0xd_base_url` pins
/// the daemon URL when the supervisor manages a bundled x0xd; `None`
/// lets the chat client fall through to `discover_local()`.
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
    x0xd_base_url: Option<String>,
    name_provider: Arc<dyn Fn() -> String + Send + Sync>,
) -> chat::ChatState {
    match chat::ChatState::new(
        relay_url,
        data_dir.clone(),
        None,
        lan_direct_enabled,
        x0xd_base_url.clone(),
        name_provider.clone(),
    ) {
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
                x0xd_base_url,
                name_provider,
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
    // rustls 0.23 refuses to auto-select a crypto provider when both
    // `ring` and `aws-lc-rs` are linked (a transitive dep pulls aws-lc-rs
    // in alongside ring), panicking on the first TLS handshake, which
    // breaks every chat/relay/x0xd HTTPS call. Install aws-lc-rs (NOT
    // ring): it backs ant-quic's post-quantum crypto as well as the relay
    // TLS, so ring would silently drop PQC on the QUIC path. Matches the
    // FFI (chat_ffi.rs). Install before anything touches the network;
    // ignore the error: a second call just means a provider is already set.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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
        .plugin(
            // Info floor: saorsa_transport instruments every packet drive/recv
            // with tracing spans (mirrored to the log facade), which flood at
            // the plugin's default Trace. Warn/Error from all crates still show.
            tauri_plugin_log::Builder::default()
                .level(tauri_plugin_log::log::LevelFilter::Info)
                .build(),
        )
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
            // Resolve the chat feature flag once at boot. Env var
            // override is rechecked here so a settings.json default-off
            // doesn't fight a `FETCHIT_CHAT_ENABLED=1` invocation.
            let chat_enabled_at_boot = settings::resolve_chat_enabled(&loaded);

            // M3 reader-side denylist (#342): gate denylisted XorNames in
            // the reader even when chat ships cold. Built from the same
            // signed NY-Trust endpoint + baked issuer key as the chat
            // consumer, but independent of the chat feature flag. `None`
            // when no URL resolves (offline / self-host).
            let reader_denylist = chat::resolve_denylist_url(
                std::env::var("FETCHIT_DENYLIST_URL").ok(),
                chat::DEFAULT_DENYLIST_URL,
            )
            .map(|url| {
                let consumer = Arc::new(fetchit_trust_client::DenylistConsumer::new(
                    fetchit_trust_client::etchitio_pubkey(),
                    url,
                    Some(app_data.join("denylist")),
                ));
                consumer.load_cache_blocking();
                consumer
            });

            let state = AppState::new(disk_cache, loaded, settings_path).with_reader_denylist(
                reader_denylist
                    .clone()
                    .map(|c| c as Arc<dyn fetchit_trust_types::DenylistQuery>),
            );
            let server_state = state.clone();
            app.manage(state);

            // Identity unification (bundled daemon): seed x0xd's agent.key
            // from the chat vault BEFORE the supervisor spawns it, so the
            // daemon boots as the SAME agent the chat client pairs and
            // publishes under — and the identity the 24-word recovery
            // phrase backs up IS the identity groups are keyed to.
            // `None` = keychain custody, matching build_chat_state below.
            // Non-fatal: a passphrase-mode vault can't unlock here (no
            // passphrase at boot), so the daemon keeps its previous
            // identity and chat behaves exactly as before this feature.
            let x0xd_identity_dir = app_data.join("x0xd-identity");
            match fetchit_chat::seed_x0xd_agent_key(
                &app_data.join("chat"),
                None,
                &x0xd_identity_dir,
            ) {
                Ok(id) => eprintln!("[fetchit][supervisor] x0xd identity unified as {id}"),
                Err(e) => eprintln!(
                    "[fetchit][supervisor] identity seed skipped ({e}); daemon keeps its own key"
                ),
            }

            // Boot the x0xd supervisor (blocking; the webview shows no
            // content until setup returns, so this is still "before the
            // app is up" from the user's perspective).
            let x0xd_base_url = boot_x0xd_supervisor_blocking(&x0xd_identity_dir);

            // Drive the reader denylist's signed-manifest refresh loop
            // (needs a runtime context; the loop outlives this task via its
            // own Arc clone). A failed HTTP-client build leaves the reader
            // gated by the on-disk cache snapshot only.
            if let Some(consumer) = reader_denylist {
                match fetchit_trust_client::ReqwestClient::new() {
                    Ok(http) => {
                        let http: Arc<
                            dyn fetchit_trust_client::HttpClient + Send + Sync + 'static,
                        > = Arc::new(http);
                        tauri::async_runtime::spawn(async move {
                            // JoinHandle dropped on purpose: the loop runs
                            // detached for the life of the consumer Arc.
                            let _handle = consumer.spawn_poll_loop(http);
                        });
                    }
                    Err(e) => eprintln!(
                        "[fetchit][denylist] reader consumer http init failed: {e}; \
                         reader gated by cache snapshot only"
                    ),
                }
            }

            // Build + manage the chat client even when the feature is
            // off, so dev builds that flip the env var post-launch can
            // see the panel without restart. The expensive bit —
            // spawn_event_pump — is gated: it pulls x0xd, opens a WS
            // to the relay, and starts background tasks. Skip when
            // chat is off so the v1 release ships cold.
            // Sender display name for the engine outbox driver: read the
            // persisted setting at send/retry time so a resend stamps the
            // same name the initial send used. Falls back to "fetchit" when
            // unset, matching chat_send_dm's own default.
            let name_settings = server_state.settings.clone();
            let name_provider: Arc<dyn Fn() -> String + Send + Sync> = Arc::new(move || {
                name_settings
                    .lock()
                    .ok()
                    .map(|s| s.display_name.trim().to_string())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "fetchit".to_string())
            });
            let chat_state = build_chat_state(
                &relay_url,
                app_data.join("chat"),
                lan_direct_enabled,
                x0xd_base_url.clone(),
                name_provider,
            );
            app.manage(chat_state.clone());
            if chat_enabled_at_boot {
                chat::ensure_event_pump(app.handle().clone(), chat_state);
            } else {
                eprintln!(
                    "[fetchit][chat] feature gated off (set {}=1 or Settings → \
                     Advanced → chatEnabled=true to enable)",
                    settings::CHAT_ENABLED_ENV,
                );
            }

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
            onboarding_done,
            set_onboarding_done,
            set_chat_enabled,
            lan_direct_enabled,
            set_lan_direct_enabled,
            chat_feature_enabled,
            relay_regions,
            relay_url,
            set_relay_url,
            chat::chat_health,
            chat::chat_list_nearby,
            chat::chat_identity,
            chat::chat_card,
            chat::chat_regenerate_card_with_relays,
            chat::chat_import_card,
            chat::chat_pair_accept,
            chat::chat_pair_share,
            chat::chat_pair_share_uri,
            chat::chat_import_pair_uri,
            profile::chat_fetch_profile,
            profile::chat_fetch_avatar,
            chat::chat_contacts,
            chat::chat_set_trust,
            chat::chat_remove_contact,
            chat::chat_send_dm,
            chat::chat_dm_connect,
            chat::chat_retry_outbox,
            chat::chat_outbox_snapshot,
            chat::chat_presence_online,
            chat::chat_groups_list,
            chat::chat_group_create,
            chat::chat_group_invite,
            chat::chat_group_join,
            chat::chat_group_send,
            chat::chat_group_messages,
            chat::chat_group_leave,
            chat::chat_group_members,
            chat::chat_group_remove_member,
            chat::chat_group_rename,
            chat::chat_group_ban_member,
            chat::chat_set_passphrase,
            chat::chat_custody_status,
            chat::chat_rekey_vault,
            chat::chat_confirm_contact,
            chat::chat_watch_presence,
            chat::chat_unwatch_presence,
            fediverse::fediverse_actor_status,
            fediverse::fediverse_ensure_v2,
            fediverse::fediverse_mint,
            fediverse::fediverse_publish,
            fediverse_lookup::fediverse_lookup,
            etchit_handoff::etchit_handoff,
            etchit_handoff::etchit_open_profile,
        ])
        .on_window_event(|win, event| {
            // ClearMode::OnClose: wipe the on-disk cache when the user
            // closes the window. Counterpart to the OnIdle branch in
            // `idle_disconnect`. Tolerant of missing state — partial
            // shutdowns (e.g. setup hadn't finished) must not panic.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                use tauri::Manager;
                if let Some(state) = win.try_state::<AppState>() {
                    if state.disk_cache.policy().mode == ClearMode::OnClose {
                        state.disk_cache.clear();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
