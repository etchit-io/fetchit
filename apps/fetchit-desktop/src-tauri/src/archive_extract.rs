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

use std::io::{Cursor, Read};

use bytes::Bytes;
use fetchit_core::{Address, NetworkClient};

use crate::state::{default_peers, ensure_client, AppState};

/// Read a named entry from the archive at `addr`. Returns the bytes
/// inside (post-decompression for Deflate entries; for Stored entries
/// they're identical to what was put in).
#[tauri::command]
pub async fn extract_archive_entry(
    state: tauri::State<'_, AppState>,
    addr: String,
    entry_path: String,
) -> Result<Vec<u8>, String> {
    let parsed: Address = addr.parse().map_err(|e: fetchit_core::Error| e.to_string())?;
    let bytes = resolve_bytes(&state, &parsed).await?;
    extract_from_zip(&bytes, &entry_path)
}

async fn resolve_bytes(state: &AppState, addr: &Address) -> Result<Bytes, String> {
    if let Some(b) = state.cached_bytes(addr) {
        return Ok(b);
    }
    let client = ensure_client(state, &default_peers()).await?;
    let bytes = client.fetch(addr).await.map_err(|e| e.to_string())?;
    state.cache_bytes(addr, bytes.clone());
    Ok(bytes)
}

fn extract_from_zip(zip_bytes: &Bytes, entry_path: &str) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(zip_bytes.clone());
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| format!("zip parse failed: {e}"))?;
    let mut file = archive
        .by_name(entry_path)
        .map_err(|e| format!("entry {entry_path:?}: {e}"))?;
    let mut out = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut out)
        .map_err(|e| format!("entry read failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::{FileOptions, ZipWriter};
    use zip::CompressionMethod;

    fn build_zip(entries: &[(&str, &[u8])]) -> Bytes {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zw = ZipWriter::new(&mut buf);
            let opts: FileOptions<()> =
                FileOptions::default().compression_method(CompressionMethod::Stored);
            for (name, body) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(body).unwrap();
            }
            zw.finish().unwrap();
        }
        Bytes::from(buf.into_inner())
    }

    #[test]
    fn extracts_stored_entry_byte_for_byte() {
        let zip = build_zip(&[("hello.txt", b"world")]);
        assert_eq!(extract_from_zip(&zip, "hello.txt").unwrap(), b"world");
    }

    #[test]
    fn extracts_nested_path_entry() {
        let zip = build_zip(&[("dir/sub/asset.bin", &[1u8, 2, 3, 255])]);
        assert_eq!(
            extract_from_zip(&zip, "dir/sub/asset.bin").unwrap(),
            vec![1u8, 2, 3, 255]
        );
    }

    #[test]
    fn errors_on_missing_entry() {
        let zip = build_zip(&[("only.txt", b"x")]);
        let err = extract_from_zip(&zip, "absent.bin").unwrap_err();
        assert!(err.contains("absent.bin"));
    }

    #[test]
    fn errors_on_garbage_input() {
        let not_zip = Bytes::from_static(b"definitely not a zip");
        assert!(extract_from_zip(&not_zip, "foo").is_err());
    }
}
