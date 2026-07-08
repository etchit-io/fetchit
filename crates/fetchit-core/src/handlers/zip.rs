//! ZIP archive handler. Parses the central directory and emits
//! [`Rendition::Archive`] with one [`ArchiveEntry`] per stored file.
//! No decompression — just an index. UI shells render the listing;
//! extraction (when added) belongs in the surface, not the engine.

use std::io::Cursor;

use bytes::Bytes;

use crate::handler::{ArchiveEntry, Confidence, ContentHandler, Hint, RenderContext, Rendition};
use crate::{Error, Result};

/// Recognises ZIP archives.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZipHandler;

const KIND: &str = "application/zip";
const LFH_MAGIC: &[u8] = &[0x50, 0x4B, 0x03, 0x04]; // "PK\x03\x04" — local file header
const EOCD_MAGIC: &[u8] = &[0x50, 0x4B, 0x05, 0x06]; // "PK\x05\x06" — end-of-central-directory

/// Hard cap on a single extracted entry's decompressed size (256 MiB).
///
/// A ZIP entry's compressed size can be tiny while its decompressed size
/// is many GiB (a "zip bomb"). Extraction buffers the whole entry into
/// memory, so an unbounded read is an out-of-memory vector for untrusted
/// archives — acute now that unattended MCP agents call this. Entries
/// that decompress past this cap are rejected. Generous enough for real
/// archived media.
pub const MAX_EXTRACT_BYTES: u64 = 256 * 1024 * 1024;

/// Read one named entry's decompressed bytes out of a ZIP archive.
///
/// Pure extraction — given the archive bytes and an entry path (as
/// reported by [`ZipHandler::render`]'s [`ArchiveEntry::path`]), returns
/// the decompressed bytes for that entry. Supports Stored and Deflate
/// entries; the surface decides what to do with the bytes (render
/// inline, save to disk, hand off to another app).
///
/// Entries decompressing past [`MAX_EXTRACT_BYTES`] are rejected rather
/// than buffered, and the decompressed-size header is never trusted for
/// pre-allocation (a forged value would abort on allocation before a
/// byte is read).
///
/// # Errors
///
/// Returns [`Error::Render`] when the archive bytes don't parse, when
/// the named entry is missing, when decompression fails, or when the
/// entry exceeds [`MAX_EXTRACT_BYTES`].
pub fn extract_entry(archive_bytes: Bytes, entry_path: &str) -> Result<Vec<u8>> {
    extract_entry_capped(archive_bytes, entry_path, MAX_EXTRACT_BYTES)
}

/// [`extract_entry`] with an explicit decompressed-size cap (in bytes).
/// The public entry point pins `max` to [`MAX_EXTRACT_BYTES`]; the seam
/// exists so the cap is exercisable in tests without a multi-GiB fixture.
fn extract_entry_capped(archive_bytes: Bytes, entry_path: &str, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let cursor = Cursor::new(archive_bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| Error::Render {
        kind: KIND,
        reason: format!("zip parse failed: {e}"),
    })?;
    let file = archive.by_name(entry_path).map_err(|e| Error::Render {
        kind: KIND,
        reason: format!("entry {entry_path:?}: {e}"),
    })?;
    // Start empty — NEVER pre-allocate from `file.size()`, the
    // attacker-controlled uncompressed-size header. Bound the read to
    // `max + 1` so a deflate bomb can't inflate past the cap into
    // memory; if it produces more than `max`, reject.
    let mut out = Vec::new();
    let mut limited = file.take(max + 1);
    limited.read_to_end(&mut out).map_err(|e| Error::Render {
        kind: KIND,
        reason: format!("entry read failed: {e}"),
    })?;
    if out.len() as u64 > max {
        return Err(Error::Render {
            kind: KIND,
            reason: format!("entry {entry_path:?} exceeds the {max}-byte extract cap"),
        });
    }
    Ok(out)
}

impl ContentHandler for ZipHandler {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn can_handle(&self, head: &[u8], _hint: &Hint) -> Confidence {
        // A normal ZIP starts with a local file header. An empty ZIP
        // starts with the EOCD magic. Either is unambiguous enough to
        // claim Definite.
        if head.starts_with(LFH_MAGIC) || head.starts_with(EOCD_MAGIC) {
            Confidence::Definite
        } else {
            Confidence::None
        }
    }

    fn render(&self, bytes: Bytes, _ctx: &RenderContext) -> Result<Rendition> {
        let cursor = Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(cursor).map_err(|e| Error::Render {
            kind: KIND,
            reason: format!("zip parse failed: {e}"),
        })?;
        let mut entries = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let file = archive.by_index(i).map_err(|e| Error::Render {
                kind: KIND,
                reason: format!("zip entry {i}: {e}"),
            })?;
            entries.push(ArchiveEntry {
                path: file.name().to_owned(),
                size: Some(file.size()),
            });
        }
        Ok(Rendition::Archive { entries })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::Write;

    fn confidence(bytes: &[u8]) -> Confidence {
        ZipHandler.can_handle(bytes, &Hint::default())
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<'static, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(body).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn claims_local_file_header_magic() {
        assert_eq!(confidence(LFH_MAGIC), Confidence::Definite);
    }

    #[test]
    fn claims_eocd_magic_for_empty_archive() {
        assert_eq!(confidence(EOCD_MAGIC), Confidence::Definite);
    }

    #[test]
    fn rejects_text() {
        assert_eq!(confidence(b"hello world"), Confidence::None);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(confidence(b""), Confidence::None);
    }

    #[test]
    fn parses_two_entry_archive() {
        let bytes = build_zip(&[
            ("hello.txt", b"world"),
            ("nested/path.txt", b"deeply nested content"),
        ]);
        let r = ZipHandler
            .render(Bytes::from(bytes), &RenderContext::default())
            .expect("render");
        match r {
            Rendition::Archive { entries } => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].path, "hello.txt");
                assert_eq!(entries[0].size, Some(5));
                assert_eq!(entries[1].path, "nested/path.txt");
            }
            other => panic!("expected Archive, got {other:?}"),
        }
    }

    #[test]
    fn extract_entry_returns_stored_bytes() {
        let zip = build_zip(&[("hello.txt", b"world")]);
        let out = extract_entry(Bytes::from(zip), "hello.txt").expect("extract");
        assert_eq!(out, b"world");
    }

    #[test]
    fn extract_entry_rejects_an_entry_past_the_cap() {
        // An entry whose decompressed size exceeds the cap is rejected,
        // not buffered — the zip-bomb guard. Drive the seam with a tiny
        // cap so no multi-GiB fixture is needed.
        let zip = build_zip(&[("big.bin", &[0u8; 4096])]);
        let err = extract_entry_capped(Bytes::from(zip), "big.bin", 100)
            .expect_err("entry over the cap must be rejected");
        match err {
            Error::Render { reason, .. } => assert!(
                reason.contains("exceeds"),
                "expected a cap error, got {reason:?}"
            ),
            other => panic!("expected Error::Render, got {other:?}"),
        }
    }

    #[test]
    fn extract_entry_accepts_an_entry_at_the_cap() {
        // Exactly at the cap still extracts (the +1 take headroom means
        // the boundary is inclusive of `max`).
        let payload = [0u8; 100];
        let zip = build_zip(&[("edge.bin", &payload)]);
        let out = extract_entry_capped(Bytes::from(zip), "edge.bin", 100).expect("at-cap extract");
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn extract_entry_handles_nested_paths() {
        let zip = build_zip(&[("dir/sub/asset.bin", &[1u8, 2, 3, 4, 5])]);
        let out = extract_entry(Bytes::from(zip), "dir/sub/asset.bin").expect("extract");
        assert_eq!(out, vec![1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn extract_entry_reports_missing_entry() {
        let zip = build_zip(&[("present.txt", b"x")]);
        let err = extract_entry(Bytes::from(zip), "absent.bin").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("absent.bin"), "got: {msg}");
    }

    #[test]
    fn extract_entry_rejects_non_zip_bytes() {
        let not_zip = Bytes::from_static(b"not a zip file");
        assert!(extract_entry(not_zip, "anything").is_err());
    }
}
