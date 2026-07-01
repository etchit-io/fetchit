//! Disk cache for the last good `DenylistResponse` per `EntryKind`.
//!
//! Storage layout: one file per kind under `<cache_path>/<kind>.json`:
//!   - `xor_name.json`
//!   - `agent_id.json`
//!   - `relay_url.json`
//!   - `actor_url.json`
//!
//! Each file holds the JSON-encoded `DenylistResponse` bytes verbatim
//! as fetched from the issuer. Boot-time reload re-verifies the
//! signature before hydrating the in-memory index, so a poisoned
//! cache file cannot bypass trust.

use std::fs;
use std::io;
use std::path::Path;

use fetchit_trust::EntryKind;

/// Convert an [`EntryKind`] to its cache-file basename.
pub(crate) fn cache_file_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::XorName => "xor_name.json",
        EntryKind::AgentId => "agent_id.json",
        EntryKind::RelayUrl => "relay_url.json",
        EntryKind::ActorUrl => "actor_url.json",
    }
}

/// Write `bytes` to `cache_dir/<kind>.json`. Creates the directory if
/// it doesn't exist. Uses tempfile + rename for atomic write so a
/// crash mid-write cannot leave a half-written file.
pub(crate) fn write_kind(cache_dir: &Path, kind: EntryKind, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    let dest = cache_dir.join(cache_file_name(kind));
    let tmp = cache_dir.join(format!("{}.tmp", cache_file_name(kind)));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, &dest)?;
    Ok(())
}

/// Read `cache_dir/<kind>.json`. Returns `Ok(None)` when the file
/// doesn't exist (clean first boot); `Err` on I/O failure.
pub(crate) fn read_kind(cache_dir: &Path, kind: EntryKind) -> io::Result<Option<Vec<u8>>> {
    let path = cache_dir.join(cache_file_name(kind));
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
