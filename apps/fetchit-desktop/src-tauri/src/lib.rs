//! Tauri backend for fetch>it desktop — a thin shell over `fetchit-core`
//! (the handler engine) and `fetchit-net` (the Autonomi client).

mod cache;
mod protocol;
mod rendition;
mod server;
mod state;

use std::sync::OnceLock;

use fetchit_core::handlers::default_registry;
use fetchit_core::{Address, Hint, NetworkClient, RenderContext};

use rendition::RenditionDto;
use state::{default_peers as peer_list, ensure_client, AppState};

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

#[tauri::command]
async fn fetch_and_render(
    state: tauri::State<'_, AppState>,
    addr: String,
) -> Result<RenditionDto, String> {
    let parsed: Address = addr.parse().map_err(|e: fetchit_core::Error| e.to_string())?;
    let bytes = match state.cache.get(&parsed) {
        Some(b) => b,
        None => {
            let client = ensure_client(&state, &peer_list()).await?;
            let b = client.fetch(&parsed).await.map_err(|e| e.to_string())?;
            state.cache.put(parsed, b.clone());
            b
        }
    };
    let rendition = default_registry()
        .render(bytes, &Hint::default(), &RenderContext::default())
        .map_err(|e| e.to_string())?;
    Ok(rendition.into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::default();
    let server_state = state.clone();

    // Two scheme aliases for the same protocol handler. The localhost HTTP
    // server is the third path WebKit's `<video>` will accept (it ignores
    // custom URI schemes for media), spawned in `setup` below.
    tauri::Builder::default()
        .manage(state)
        .register_asynchronous_uri_scheme_protocol("fetchit", protocol::handle)
        .register_asynchronous_uri_scheme_protocol("autonomi", protocol::handle)
        .setup(move |app| {
            let server_state = server_state.clone();
            tauri::async_runtime::spawn(async move {
                match server::spawn(server_state).await {
                    Ok(port) => {
                        let _ = MEDIA_URL_BASE.set(format!("http://127.0.0.1:{port}"));
                    }
                    Err(e) => eprintln!("[fetchit] media server failed to bind: {e}"),
                }
            });

            #[cfg(debug_assertions)]
            {
                use tauri::Manager;
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
