//! On-disk bytes cache, keyed by [`Address`]. **Opt-in** — disabled by default
//! so a fresh install leaves no on-disk trace of fetched content; users enable
//! it explicitly in settings and pick one of three clear semantics.
//!
//! Sits a layer below the in-memory cache: on cache miss, callers consult disk
//! before going to the network. Writes are write-through (in-memory + disk).
//! LRU eviction by file mtime (touched on read).

use bytes::Bytes;
use fetchit_core::Address;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClearMode {
    /// Cache persists across app sessions.
    Persist,
    /// Cache contents are wiped when the app closes.
    OnClose,
    /// Cache contents are wiped when the idle-disconnect fires.
    OnIdle,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub enabled: bool,
    pub mode: ClearMode,
    pub max_bytes: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ClearMode::Persist,
            max_bytes: 500 * 1024 * 1024,
        }
    }
}

pub struct DiskCache {
    root: PathBuf,
    policy: Mutex<Policy>,
}

impl DiskCache {
    /// Build a cache rooted at `root`. The directory is created if missing.
    pub fn new(root: PathBuf, policy: Policy) -> Self {
        let _ = fs::create_dir_all(&root);
        Self {
            root,
            policy: Mutex::new(policy),
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy.lock().map(|p| *p).unwrap_or_default()
    }

    pub fn set_policy(&self, p: Policy) {
        if let Ok(mut g) = self.policy.lock() {
            *g = p;
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, addr: &Address) -> PathBuf {
        self.root.join(format!("{}.bin", addr.to_hex()))
    }

    /// Read the bytes for `addr` from disk. Touches mtime so LRU sees the
    /// access. Returns `None` if the cache is disabled or the file is missing.
    pub fn get(&self, addr: &Address) -> Option<Bytes> {
        if !self.policy().enabled {
            return None;
        }
        let p = self.path_for(addr);
        let bytes = fs::read(&p).ok()?;
        let _ = filetime::set_file_mtime(&p, filetime::FileTime::now());
        Some(Bytes::from(bytes))
    }

    /// Write `bytes` for `addr`. No-op when disabled. After a successful
    /// write, evicts oldest files until total size is under the policy cap.
    pub fn put(&self, addr: &Address, bytes: &[u8]) {
        let policy = self.policy();
        if !policy.enabled {
            return;
        }
        let p = self.path_for(addr);
        if fs::write(&p, bytes).is_err() {
            return;
        }
        self.evict_to(policy.max_bytes);
    }

    /// Path a streaming download writes to before it is committed. Lives
    /// in the cache directory so a completed stream becomes a cache entry
    /// with a single rename, no extra copy.
    #[cfg(not(feature = "e2e"))]
    pub fn stream_path(&self, addr: &Address) -> PathBuf {
        self.root.join(format!("{}.partial", addr.to_hex()))
    }

    /// Promote a completed streaming download to a cache entry: rename the
    /// partial file onto the address slot, then evict to the policy cap.
    #[cfg(not(feature = "e2e"))]
    pub fn commit_stream(&self, addr: &Address) {
        if fs::rename(self.stream_path(addr), self.path_for(addr)).is_ok() {
            self.evict_to(self.policy().max_bytes);
        }
    }

    /// Delete an aborted streaming download's partial file.
    #[cfg(not(feature = "e2e"))]
    pub fn discard_stream(&self, addr: &Address) {
        let _ = fs::remove_file(self.stream_path(addr));
    }

    /// Wipe every file in the cache directory. Always available, regardless
    /// of policy (so a user can clear even after disabling the cache).
    pub fn clear(&self) {
        if let Ok(entries) = fs::read_dir(&self.root) {
            for e in entries.flatten() {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    /// Total size of files in the cache directory.
    pub fn size_on_disk(&self) -> u64 {
        let mut total = 0u64;
        if let Ok(entries) = fs::read_dir(&self.root) {
            for e in entries.flatten() {
                if let Ok(m) = e.metadata() {
                    total += m.len();
                }
            }
        }
        total
    }

    /// Number of cached files (one per address).
    pub fn file_count(&self) -> usize {
        fs::read_dir(&self.root)
            .map(|it| it.flatten().count())
            .unwrap_or(0)
    }

    /// Drop oldest-mtime files until total size is at or below `cap`.
    fn evict_to(&self, cap: u64) {
        let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.root) {
            for e in entries.flatten() {
                let path = e.path();
                // In-flight streaming downloads must not be evicted.
                if path.extension().is_some_and(|x| x == "partial") {
                    continue;
                }
                if let Ok(m) = e.metadata() {
                    let mtime = m.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    files.push((path, m.len(), mtime));
                }
            }
        }
        let total: u64 = files.iter().map(|(_, s, _)| s).sum();
        if total <= cap {
            return;
        }
        files.sort_by_key(|(_, _, mtime)| *mtime);
        let mut remaining = total;
        for (path, size, _) in files {
            if remaining <= cap {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                remaining = remaining.saturating_sub(size);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;
    use tempfile::tempdir;

    const A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const B: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const C: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    fn addr(hex: &str) -> Address {
        hex.parse().expect("valid 64-hex test fixture")
    }

    fn enabled(max: u64) -> Policy {
        Policy {
            enabled: true,
            mode: ClearMode::Persist,
            max_bytes: max,
        }
    }

    #[test]
    fn put_then_get_round_trip_when_enabled() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        c.put(&addr(A), b"hello");
        assert_eq!(c.get(&addr(A)).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn disabled_policy_writes_nothing_and_reads_none() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), Policy::default());
        c.put(&addr(A), b"hello");
        assert!(c.get(&addr(A)).is_none());
        assert_eq!(c.file_count(), 0);
    }

    #[test]
    fn flipping_policy_to_disabled_stops_writes_but_keeps_files() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        c.put(&addr(A), b"hello");
        c.set_policy(Policy::default());
        // Existing file still on disk, but get() refuses to serve it.
        assert!(c.get(&addr(A)).is_none());
        // Re-enable — the bytes are still there.
        c.set_policy(enabled(1024));
        assert_eq!(c.get(&addr(A)).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn clear_always_works_even_when_disabled() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        c.put(&addr(A), b"x");
        c.put(&addr(B), b"y");
        assert_eq!(c.file_count(), 2);
        c.set_policy(Policy::default());
        c.clear();
        assert_eq!(c.file_count(), 0);
    }

    #[test]
    fn size_on_disk_reports_total() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        c.put(&addr(A), b"hello"); // 5
        c.put(&addr(B), b"worlds!"); // 7
        assert_eq!(c.size_on_disk(), 12);
    }

    #[test]
    fn evicts_oldest_when_cap_exceeded() {
        let dir = tempdir().unwrap();
        // Tiny cap: 6 bytes — third 4-byte file should evict the oldest.
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(6));
        c.put(&addr(A), b"aaaa");
        sleep(Duration::from_millis(15));
        c.put(&addr(B), b"bbbb");
        sleep(Duration::from_millis(15));
        c.put(&addr(C), b"cccc");

        // A is oldest, evicted; B was put before cap was breached but its
        // mtime is more recent than A's; C is the freshest write.
        assert!(c.get(&addr(A)).is_none(), "oldest should be evicted");
        assert!(c.get(&addr(B)).is_some() || c.get(&addr(C)).is_some());
    }

    #[test]
    fn get_touches_mtime_so_recently_read_files_survive_eviction() {
        let dir = tempdir().unwrap();
        // Cap = 8 so two 4-byte files fit; the third write triggers a single
        // eviction. Without get()'s touch on A, A is the oldest and would
        // evict; the touch makes B the oldest instead.
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(8));
        c.put(&addr(A), b"aaaa");
        sleep(Duration::from_millis(15));
        c.put(&addr(B), b"bbbb");
        sleep(Duration::from_millis(15));
        let _ = c.get(&addr(A));
        sleep(Duration::from_millis(15));
        c.put(&addr(C), b"cccc");
        assert!(
            c.get(&addr(A)).is_some(),
            "recently-touched A should survive"
        );
        assert!(c.get(&addr(B)).is_none(), "B should be the eviction victim");
        assert!(c.get(&addr(C)).is_some(), "fresh write C should remain");
    }

    #[test]
    fn file_count_matches_entries() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        assert_eq!(c.file_count(), 0);
        c.put(&addr(A), b"x");
        c.put(&addr(B), b"y");
        assert_eq!(c.file_count(), 2);
        c.clear();
        assert_eq!(c.file_count(), 0);
    }

    #[test]
    fn default_policy_disables_cache() {
        let p = Policy::default();
        assert!(!p.enabled);
        assert_eq!(p.mode, ClearMode::Persist);
        assert_eq!(p.max_bytes, 500 * 1024 * 1024);
    }

    #[cfg(not(feature = "e2e"))]
    #[test]
    fn stream_path_is_a_partial_sibling_of_the_slot() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        let p = c.stream_path(&addr(A));
        assert_eq!(p.extension().unwrap(), "partial");
        assert!(p.starts_with(dir.path()));
    }

    #[cfg(not(feature = "e2e"))]
    #[test]
    fn commit_stream_promotes_a_partial_to_a_cache_entry() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        fs::write(c.stream_path(&addr(A)), b"streamed").unwrap();
        c.commit_stream(&addr(A));
        assert_eq!(c.get(&addr(A)).as_deref(), Some(&b"streamed"[..]));
    }

    #[cfg(not(feature = "e2e"))]
    #[test]
    fn discard_stream_removes_the_partial() {
        let dir = tempdir().unwrap();
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(1024));
        let partial = c.stream_path(&addr(A));
        fs::write(&partial, b"scratch").unwrap();
        c.discard_stream(&addr(A));
        assert!(!partial.exists());
    }

    #[cfg(not(feature = "e2e"))]
    #[test]
    fn eviction_never_drops_an_in_flight_partial() {
        let dir = tempdir().unwrap();
        // Cap = 4: the committed file alone fills it, so eviction runs.
        let c = DiskCache::new(dir.path().to_path_buf(), enabled(4));
        fs::write(c.stream_path(&addr(B)), b"downloading").unwrap();
        c.put(&addr(A), b"aaaa");
        assert!(
            c.stream_path(&addr(B)).exists(),
            "partial must survive eviction",
        );
    }
}
