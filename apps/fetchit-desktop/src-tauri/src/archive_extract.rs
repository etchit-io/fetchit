//! Inner-entry extraction for archive addresses.
//!
//! `fetchit-core`'s `ZipHandler` parses the central directory and
//! returns an index (names + sizes), then deliberately stops there:
//!
//! > UI shells render the listing; extraction (when added) belongs in
//! > the surface, not the engine.
//!
//! This module is that surface. Given a `(addr, entry_path)` pair, it
//! resolves the archive bytes through the same layered cache the
//! `fetchit://` protocol handler uses, opens the zip, and returns the
//! named entry's bytes. The frontend renders them inline (image /
//! text / audio / video / pdf via blob URLs) or offers Save As… for
//! unknown types.
//!
//! Two-layer fetch: in-memory + on-disk cache (hot path), Autonomi
//! network on miss. Same as the protocol handler, so an archive the
//! user is already viewing is essentially free to extract from.

use bytes::Bytes;
use fetchit_core::{handlers::extract_entry, Address, NetworkClient};

use crate::state::{ensure_client, AppState};

/// Read a named entry from the archive at `addr`. Returns the bytes
/// inside (post-decompression for Deflate entries; for Stored entries
/// they're identical to what was put in).
#[tauri::command]
pub async fn extract_archive_entry(
    state: tauri::State<'_, AppState>,
    addr: String,
    entry_path: String,
) -> Result<Vec<u8>, String> {
    let parsed: Address = addr
        .parse()
        .map_err(|e: fetchit_core::Error| e.to_string())?;
    let bytes = resolve_bytes(&state, &parsed).await?;
    extract_entry(bytes, &entry_path).map_err(|e| e.to_string())
}

async fn resolve_bytes(state: &AppState, addr: &Address) -> Result<Bytes, String> {
    if let Some(b) = state.cached_bytes(addr) {
        return Ok(b);
    }
    let client = ensure_client(state, &state.effective_peers()).await?;
    let bytes = client.fetch(addr).await.map_err(|e| e.to_string())?;
    state.cache_bytes(addr, bytes.clone());
    Ok(bytes)
}

// Extraction unit-tests live with the implementation in
// `fetchit-core::handlers::zip` — this file's `extract_archive_entry`
// is the Tauri-command adapter that adds network resolution.
