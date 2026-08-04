//! Bounded on-disk cache for fediverse correspondents' avatars.
//!
//! Layout under the store root, one pair of files per correspondent:
//!
//! ```text
//! <root>/fedi/avatars/<sha256(canonical label)>.img    raw image bytes
//! <root>/fedi/avatars/<sha256(canonical label)>.json   [`AvatarMeta`]
//! ```
//!
//! Plaintext, 0600: a profile picture served from a public URL is
//! public directory data, the same class as the handle-resolution
//! ledger. The hashed filename keeps a correspondent's handle out of
//! `ls` output and sidesteps path-separator / case-folding hazards from
//! a remote-supplied label.
//!
//! Three properties this module exists to guarantee:
//!
//! 1. **No hot retry loops.** A success is not re-fetched for
//!    [`AVATAR_REFRESH_MS`]; a failure is not re-attempted for
//!    [`AVATAR_FAILURE_BACKOFF_MS`]. This codebase has already paid for
//!    retry storms once.
//! 2. **Bounded footprint.** [`enforce_cache_bounds`] evicts oldest-first
//!    past [`AVATAR_CACHE_MAX_ENTRIES`] entries or
//!    [`AVATAR_CACHE_MAX_BYTES`] total.
//! 3. **Never load-bearing.** Every function here is best-effort. A
//!    missing, stale, corrupt, or unfetchable avatar changes nothing
//!    about follow, DM, or feed behaviour.
//!
//! The bytes are stored exactly as served and never decoded here — see
//! [`fetchit_fedi::avatar`] for why decoding stays in the shells.

use crate::error::ChatError;
use crate::fedi_thread::canonical_thread_label;
use crate::local_store::{write_bytes_atomic, write_json_atomic, StoreLayout};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Minimum gap between successful avatar refreshes for one
/// correspondent (24h).
pub const AVATAR_REFRESH_MS: i64 = 24 * 60 * 60 * 1000;

/// Minimum gap after a failed fetch before trying again (1h). Long
/// enough that a dead CDN or a deleted account costs one request an
/// hour, not one per screen paint.
pub const AVATAR_FAILURE_BACKOFF_MS: i64 = 60 * 60 * 1000;

/// Maximum cached avatars retained. Oldest-fetched are evicted first.
pub const AVATAR_CACHE_MAX_ENTRIES: usize = 32;

/// Maximum total bytes of cached avatar images (8 MiB).
pub const AVATAR_CACHE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Stable cache key for a correspondent: `sha256` hex of the canonical
/// `user@host` label, so the on-disk name is fixed-length hex and can
/// never carry a path separator out of a remote-supplied handle.
#[must_use]
pub fn avatar_cache_key(label: &str) -> String {
    let mut h = Sha256::new();
    h.update(canonical_thread_label(label).as_bytes());
    hex::encode(h.finalize())
}

/// Sidecar metadata beside a cached avatar image.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvatarMeta {
    /// The `icon` URL this entry was (or will be) fetched from, exactly
    /// as the actor document served it. Empty when the actor has been
    /// seen but published no usable icon.
    #[serde(default)]
    pub source_url: String,
    /// Epoch-ms stamp of the last fetch **attempt** — the axis both the
    /// refresh cadence and the failure backoff measure from, and the
    /// eviction order.
    #[serde(default)]
    pub fetched_at_ms: i64,
    /// `ETag` as served on the last successful fetch.
    #[serde(default)]
    pub etag: Option<String>,
    /// Normalised content type of the stored bytes.
    #[serde(default)]
    pub content_type: String,
    /// The last attempt failed. Any stored `.img` from an earlier
    /// success is deliberately kept — a transient CDN outage should not
    /// blank an avatar that already renders.
    #[serde(default)]
    pub failed: bool,
}

/// Read the sidecar for `label`. A missing or unparsable sidecar reads
/// as `None`, which makes the entry due for a fetch.
#[must_use]
pub fn load_meta(layout: &StoreLayout, label: &str) -> Option<AvatarMeta> {
    let bytes = std::fs::read(layout.fedi_avatar_meta_path(label)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Cached avatar bytes for `label`, or `None` when nothing is cached.
///
/// Deliberately independent of [`AvatarMeta::failed`]: a stale-but-good
/// image beats a blank row while a refresh keeps failing.
#[must_use]
pub fn cached_bytes(layout: &StoreLayout, label: &str) -> Option<Vec<u8>> {
    let bytes = std::fs::read(layout.fedi_avatar_path(label)).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(bytes)
}

/// Whether a fetch attempt is allowed right now.
///
/// A clock that jumped backwards yields a negative age, which reads as
/// "not due" — a stalled avatar is strictly better than a retry storm.
#[must_use]
pub fn due_for_refresh(meta: Option<&AvatarMeta>, now_ms: i64) -> bool {
    let Some(meta) = meta else {
        return true;
    };
    // `fetched_at_ms == 0` is the never-attempted sentinel: a sidecar
    // that only records an icon URL (from [`note_icon_url`]) has no
    // window to wait out.
    if meta.fetched_at_ms == 0 {
        return true;
    }
    let age = now_ms.saturating_sub(meta.fetched_at_ms);
    if meta.failed {
        age >= AVATAR_FAILURE_BACKOFF_MS
    } else {
        age >= AVATAR_REFRESH_MS
    }
}

/// Record the `icon` URL seen for `label` in an actor document that was
/// fetched for some other reason. Cheap and network-free.
///
/// A URL that differs from the recorded one arms an immediate refresh
/// (the correspondent changed their picture) and clears any failure
/// marker. An unchanged URL leaves the cadence alone.
///
/// # Errors
/// [`ChatError`] when the sidecar cannot be written.
pub fn note_icon_url(layout: &StoreLayout, label: &str, icon_url: &str) -> Result<bool, ChatError> {
    let existing = load_meta(layout, label);
    if existing.as_ref().is_some_and(|m| m.source_url == icon_url) {
        return Ok(false);
    }
    let meta = AvatarMeta {
        source_url: icon_url.to_owned(),
        // Zero, not `now`: a changed picture should be picked up on the
        // next lazy read rather than waiting out the refresh window.
        fetched_at_ms: 0,
        etag: None,
        content_type: existing.map(|m| m.content_type).unwrap_or_default(),
        failed: false,
    };
    write_json_atomic(&layout.fedi_avatar_meta_path(label), &meta)?;
    Ok(true)
}

/// Persist freshly fetched avatar bytes plus their sidecar.
///
/// # Errors
/// [`ChatError`] when either file cannot be written.
pub fn store_success(
    layout: &StoreLayout,
    label: &str,
    source_url: &str,
    fetched: &fetchit_fedi::avatar::FetchedAvatar,
    now_ms: i64,
) -> Result<(), ChatError> {
    write_bytes_atomic(&layout.fedi_avatar_path(label), &fetched.bytes)?;
    let meta = AvatarMeta {
        source_url: source_url.to_owned(),
        fetched_at_ms: now_ms,
        etag: fetched.etag.clone(),
        content_type: fetched.content_type.clone(),
        failed: false,
    };
    write_json_atomic(&layout.fedi_avatar_meta_path(label), &meta)
}

/// Record a failed attempt so the backoff window starts. Any previously
/// stored image is left in place.
///
/// # Errors
/// [`ChatError`] when the sidecar cannot be written.
pub fn store_failure(
    layout: &StoreLayout,
    label: &str,
    source_url: &str,
    now_ms: i64,
) -> Result<(), ChatError> {
    let previous = load_meta(layout, label);
    let meta = AvatarMeta {
        source_url: source_url.to_owned(),
        fetched_at_ms: now_ms,
        etag: previous.as_ref().and_then(|m| m.etag.clone()),
        content_type: previous.map(|m| m.content_type).unwrap_or_default(),
        failed: true,
    };
    write_json_atomic(&layout.fedi_avatar_meta_path(label), &meta)
}

/// One cache entry as seen by the evictor.
struct Entry {
    key: String,
    fetched_at_ms: i64,
    bytes: u64,
}

fn scan_entries(layout: &StoreLayout) -> Vec<Entry> {
    let dir = layout.fedi_avatar_dir();
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(key) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let fetched_at_ms = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<AvatarMeta>(&b).ok())
            .map_or(0, |m| m.fetched_at_ms);
        let img: PathBuf = dir.join(format!("{key}.img"));
        let bytes = std::fs::metadata(&img).map_or(0, |m| m.len());
        out.push(Entry {
            key: key.to_owned(),
            fetched_at_ms,
            bytes,
        });
    }
    out
}

/// Evict oldest-fetched entries until the cache is within both the
/// entry-count and total-byte bounds. Returns how many were evicted.
///
/// # Errors
/// [`ChatError`] when an eviction delete fails for a reason other than
/// the file already being gone.
pub fn enforce_cache_bounds(layout: &StoreLayout) -> Result<usize, ChatError> {
    let mut entries = scan_entries(layout);
    // Oldest first; the key breaks ties so eviction is deterministic.
    entries.sort_by(|a, b| {
        a.fetched_at_ms
            .cmp(&b.fetched_at_ms)
            .then_with(|| a.key.cmp(&b.key))
    });
    let mut total: u64 = entries.iter().map(|e| e.bytes).sum();
    let mut count = entries.len();
    let dir = layout.fedi_avatar_dir();
    let mut evicted = 0usize;
    for e in &entries {
        if count <= AVATAR_CACHE_MAX_ENTRIES && total <= AVATAR_CACHE_MAX_BYTES {
            break;
        }
        for path in [
            dir.join(format!("{}.img", e.key)),
            dir.join(format!("{}.json", e.key)),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(ChatError::Invalid(format!(
                        "avatar cache evict {}: {err}",
                        path.display()
                    )))
                }
            }
        }
        total = total.saturating_sub(e.bytes);
        count -= 1;
        evicted += 1;
    }
    Ok(evicted)
}

/// Re-apply the cache bounds, logging rather than propagating.
///
/// Called after EVERY write that can add an entry, not just after a
/// successful image fetch. A sidecar written for a correspondent who
/// publishes no icon, or whose avatar host is unreachable, is still a
/// cache entry — eviction that ran on success alone would let those
/// grow without limit on a device that mostly meets picture-less
/// accounts.
fn apply_cache_bounds(layout: &StoreLayout) {
    match enforce_cache_bounds(layout) {
        Ok(n) if n > 0 => log::debug!("[fedi] avatar cache evicted {n} entries"),
        Ok(_) => {}
        Err(e) => log::debug!("[fedi] avatar cache eviction failed: {e}"),
    }
}

impl crate::client::Client {
    /// Cached avatar bytes for a fediverse correspondent, or `None`.
    /// Pure disk read: never blocks on the network.
    ///
    /// No side effects at all — no fetch, no spawn, no refresh cadence
    /// touched. That is what makes this the only avatar call a private
    /// (LIT) surface may make: a linked contact's row reuses the
    /// fediverse face, and fetch timing must never correlate with LIT
    /// activity. Refreshing stays with the fediverse surfaces, where a
    /// request is already expected.
    #[must_use]
    pub fn fedi_avatar_cached(&self, label: &str) -> Option<Vec<u8>> {
        cached_bytes(self.layout()?, label)
    }

    /// Record the `icon` URL from an actor document that was fetched for
    /// some other reason (follow, DM, feed pull, lookup). Best-effort and
    /// infallible by construction: an avatar must never fail a real flow.
    pub fn note_fedi_avatar_source(&self, label: &str, icon_url: Option<&str>) {
        let (Some(layout), Some(url)) = (self.layout(), icon_url) else {
            return;
        };
        if url.is_empty() {
            return;
        }
        match note_icon_url(layout, label, url) {
            // A new sidecar is a new cache entry; re-bound immediately.
            Ok(true) => apply_cache_bounds(layout),
            Ok(false) => {}
            Err(e) => log::debug!("[fedi] avatar source note failed for {label}: {e}"),
        }
    }

    /// Fetch `label`'s avatar if one is due, storing it in the bounded
    /// cache. Returns `true` when fresh bytes were stored.
    ///
    /// Resolves the icon URL from the sidecar when a prior actor fetch
    /// already recorded one; otherwise resolves the handle to its actor
    /// document first. Every failure is cached with a backoff rather
    /// than surfaced.
    ///
    /// # Errors
    /// [`ChatError`] only when the cache itself cannot be written — a
    /// network, SSRF, or decode-shaped failure is recorded, not returned.
    pub async fn refresh_fedi_avatar(&self, label: &str, now_ms: i64) -> Result<bool, ChatError> {
        let Some(layout) = self.layout() else {
            return Ok(false);
        };
        let meta = load_meta(layout, label);
        if !due_for_refresh(meta.as_ref(), now_ms) {
            return Ok(false);
        }
        let recorded = meta
            .as_ref()
            .map(|m| m.source_url.clone())
            .filter(|s| !s.is_empty());
        let source = if let Some(s) = recorded {
            s
        } else if let Some(s) = self.resolve_fedi_icon_url(label).await {
            s
        } else {
            // Unresolvable, or resolvable but publishing no icon. Both
            // get the failure backoff so a picture-less correspondent
            // costs one resolve an hour, not one per screen paint.
            store_failure(layout, label, "", now_ms)?;
            apply_cache_bounds(layout);
            return Ok(false);
        };
        let Ok(url) = source.parse::<url::Url>() else {
            store_failure(layout, label, &source, now_ms)?;
            apply_cache_bounds(layout);
            return Ok(false);
        };
        let stored = match fetchit_fedi::avatar::fetch_avatar(&url).await {
            Ok(fetched) => {
                store_success(layout, label, &source, &fetched, now_ms)?;
                true
            }
            Err(e) => {
                log::debug!("[fedi] avatar fetch for {label} rejected: {e}");
                store_failure(layout, label, &source, now_ms)?;
                false
            }
        };
        apply_cache_bounds(layout);
        Ok(stored)
    }

    /// `WebFinger` + actor fetch purely to learn a correspondent's icon
    /// URL. Only reached when no prior actor fetch recorded one.
    async fn resolve_fedi_icon_url(&self, label: &str) -> Option<String> {
        let mention = format!("@{}", canonical_thread_label(label));
        let actor_url = self.resolve_and_gate_mention(&mention).await.ok()?;
        let actor = fetchit_fedi::lookup::fetch_remote_actor(&actor_url)
            .await
            .ok()?;
        actor.icon_url
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_fedi::avatar::FetchedAvatar;
    use tempfile::{tempdir, TempDir};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn layout() -> (StoreLayout, TempDir) {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        (layout, dir)
    }

    fn png(len: usize) -> FetchedAvatar {
        FetchedAvatar {
            bytes: vec![0x89; len],
            content_type: "image/png".into(),
            etag: Some("\"abc\"".into()),
        }
    }

    #[test]
    fn cache_key_is_canonical_and_path_safe() {
        // Same three transforms as the thread label: trim, drop one
        // leading @, lowercase -- so a row and its avatar always agree.
        assert_eq!(
            avatar_cache_key(" @HappyBorg@Fosstodon.org "),
            avatar_cache_key("happyborg@fosstodon.org")
        );
        let key = avatar_cache_key("../../etc/passwd");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn avatar_paths_live_under_fedi_avatars_and_never_shadow_a_handle() {
        let (layout, _t) = layout();
        let img = layout.fedi_avatar_path("happyborg@fosstodon.org");
        let meta = layout.fedi_avatar_meta_path("happyborg@fosstodon.org");
        assert!(img.starts_with(layout.fedi_avatar_dir()));
        assert!(meta.starts_with(layout.fedi_avatar_dir()));
        assert!(img.to_string_lossy().ends_with(".img"));
        assert!(meta.to_string_lossy().ends_with(".json"));
        // fedi_vault scans fedi/*.json.enc for minted handles; the cache
        // sits one level down and uses a different suffix entirely.
        assert!(crate::fedi_vault::list_actor_handles(&layout).is_empty());
    }

    #[test]
    fn store_then_read_round_trips_bytes_and_meta() {
        let (layout, _t) = layout();
        store_success(&layout, "a@h", "https://cdn.example/a.png", &png(64), 1_000).unwrap();
        assert_eq!(cached_bytes(&layout, "a@h").unwrap(), vec![0x89; 64]);
        let meta = load_meta(&layout, "a@h").unwrap();
        assert_eq!(meta.source_url, "https://cdn.example/a.png");
        assert_eq!(meta.fetched_at_ms, 1_000);
        assert_eq!(meta.content_type, "image/png");
        assert!(!meta.failed);
        // Canonicalisation is applied on read too.
        assert!(cached_bytes(&layout, "@A@H").is_some());
    }

    #[test]
    fn missing_entry_reads_as_none() {
        let (layout, _t) = layout();
        assert!(cached_bytes(&layout, "nobody@nowhere").is_none());
        assert!(load_meta(&layout, "nobody@nowhere").is_none());
    }

    #[test]
    fn corrupt_sidecar_reads_as_none_rather_than_erroring() {
        let (layout, _t) = layout();
        let path = layout.fedi_avatar_meta_path("a@h");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_meta(&layout, "a@h").is_none());
        assert!(due_for_refresh(None, 0), "an unreadable entry is due");
    }

    // ----- refresh cadence + failure backoff -----

    #[test]
    fn a_fresh_success_is_not_refetched_inside_the_window() {
        let meta = AvatarMeta {
            fetched_at_ms: 1_000,
            ..AvatarMeta::default()
        };
        assert!(!due_for_refresh(Some(&meta), 1_000 + AVATAR_REFRESH_MS - 1));
        assert!(due_for_refresh(Some(&meta), 1_000 + AVATAR_REFRESH_MS));
    }

    #[test]
    fn a_failure_backs_off_for_an_hour_not_a_day() {
        let meta = AvatarMeta {
            fetched_at_ms: 1_000,
            failed: true,
            ..AvatarMeta::default()
        };
        assert!(
            !due_for_refresh(Some(&meta), 1_000 + AVATAR_FAILURE_BACKOFF_MS - 1),
            "no hot retry loop",
        );
        assert!(due_for_refresh(
            Some(&meta),
            1_000 + AVATAR_FAILURE_BACKOFF_MS
        ));
        const {
            assert!(
                AVATAR_FAILURE_BACKOFF_MS < AVATAR_REFRESH_MS,
                "a failure must retry sooner than a success refreshes",
            );
        }
    }

    #[test]
    fn a_never_attempted_entry_is_always_due() {
        let meta = AvatarMeta {
            source_url: "https://cdn.example/a.png".into(),
            ..AvatarMeta::default()
        };
        assert!(due_for_refresh(Some(&meta), 0));
        assert!(due_for_refresh(Some(&meta), 1));
    }

    #[test]
    fn a_backwards_clock_does_not_arm_a_retry_storm() {
        let meta = AvatarMeta {
            fetched_at_ms: 10_000_000,
            failed: true,
            ..AvatarMeta::default()
        };
        assert!(!due_for_refresh(Some(&meta), 1));
    }

    #[test]
    fn a_failure_keeps_the_previously_stored_image() {
        let (layout, _t) = layout();
        store_success(&layout, "a@h", "https://cdn.example/a.png", &png(32), 1).unwrap();
        store_failure(&layout, "a@h", "https://cdn.example/a.png", 2).unwrap();
        assert_eq!(
            cached_bytes(&layout, "a@h").unwrap().len(),
            32,
            "a transient outage must not blank a rendering avatar",
        );
        assert!(load_meta(&layout, "a@h").unwrap().failed);
    }

    // ----- icon-URL recording -----

    #[test]
    fn a_changed_icon_url_arms_an_immediate_refresh() {
        let (layout, _t) = layout();
        store_success(
            &layout,
            "a@h",
            "https://cdn.example/old.png",
            &png(8),
            5_000,
        )
        .unwrap();
        assert!(!due_for_refresh(load_meta(&layout, "a@h").as_ref(), 5_001));

        assert!(note_icon_url(&layout, "a@h", "https://cdn.example/new.png").unwrap());
        let meta = load_meta(&layout, "a@h").unwrap();
        assert_eq!(meta.source_url, "https://cdn.example/new.png");
        assert!(due_for_refresh(Some(&meta), 5_001));
    }

    #[test]
    fn an_unchanged_icon_url_leaves_the_cadence_alone() {
        let (layout, _t) = layout();
        store_success(&layout, "a@h", "https://cdn.example/a.png", &png(8), 5_000).unwrap();
        assert!(!note_icon_url(&layout, "a@h", "https://cdn.example/a.png").unwrap());
        assert_eq!(load_meta(&layout, "a@h").unwrap().fetched_at_ms, 5_000);
    }

    #[test]
    fn noting_a_url_clears_a_stale_failure_marker() {
        let (layout, _t) = layout();
        store_failure(&layout, "a@h", "https://cdn.example/gone.png", 1).unwrap();
        note_icon_url(&layout, "a@h", "https://cdn.example/back.png").unwrap();
        assert!(!load_meta(&layout, "a@h").unwrap().failed);
    }

    // ----- eviction bounds -----

    /// [`AVATAR_CACHE_MAX_ENTRIES`] as the `i64` the fetch stamps use.
    fn max_entries() -> i64 {
        i64::try_from(AVATAR_CACHE_MAX_ENTRIES).unwrap()
    }

    #[test]
    fn entry_count_bound_evicts_oldest_first() {
        let (layout, _t) = layout();
        let n = max_entries();
        for i in 1..=(n + 5) {
            store_success(
                &layout,
                &format!("user{i}@host"),
                "https://cdn.example/a.png",
                &png(16),
                i,
            )
            .unwrap();
        }
        let evicted = enforce_cache_bounds(&layout).unwrap();
        assert_eq!(evicted, 5);
        assert_eq!(scan_entries(&layout).len(), AVATAR_CACHE_MAX_ENTRIES);
        // The five oldest are gone, the newest survive.
        for i in 1..=5 {
            assert!(cached_bytes(&layout, &format!("user{i}@host")).is_none());
        }
        for i in 6..=(n + 5) {
            assert!(cached_bytes(&layout, &format!("user{i}@host")).is_some());
        }
    }

    #[test]
    fn byte_bound_evicts_even_when_the_entry_count_is_legal() {
        let (layout, _t) = layout();
        // 8 entries of 2 MiB = 16 MiB: well under 32 entries, twice the
        // byte bound. Eviction must be driven by size, not just count.
        let big = 2 * 1024 * 1024;
        for i in 1..=8i64 {
            store_success(
                &layout,
                &format!("user{i}@host"),
                "https://cdn.example/a.png",
                &png(big),
                i,
            )
            .unwrap();
        }
        assert!(enforce_cache_bounds(&layout).unwrap() >= 4);
        let total: u64 = scan_entries(&layout).iter().map(|e| e.bytes).sum();
        assert!(
            total <= AVATAR_CACHE_MAX_BYTES,
            "cache must fit the byte bound; got {total}",
        );
    }

    #[test]
    fn byteless_sidecars_count_toward_the_entry_bound() {
        // note_icon_url / store_failure write a sidecar with no image.
        // Those are real cache entries: a device that mostly meets
        // picture-less or unreachable accounts must still be bounded,
        // which is why every write re-applies the bounds, not just a
        // successful fetch.
        let (layout, _t) = layout();
        let n = max_entries();
        for i in 1..=(n + 4) {
            note_icon_url(
                &layout,
                &format!("user{i}@host"),
                &format!("https://cdn.example/{i}.png"),
            )
            .unwrap();
        }
        assert_eq!(scan_entries(&layout).len(), AVATAR_CACHE_MAX_ENTRIES + 4);
        assert_eq!(enforce_cache_bounds(&layout).unwrap(), 4);
        assert_eq!(scan_entries(&layout).len(), AVATAR_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn a_fetched_avatar_outlives_a_never_fetched_sidecar() {
        // Sidecars carry fetched_at_ms == 0, so they sort oldest and are
        // dropped first — eviction never trades a rendering avatar for a
        // placeholder that has no bytes.
        let (layout, _t) = layout();
        let n = max_entries();
        store_success(
            &layout,
            "real@host",
            "https://cdn.example/a.png",
            &png(16),
            1,
        )
        .unwrap();
        for i in 1..=n {
            note_icon_url(
                &layout,
                &format!("pending{i}@host"),
                "https://cdn.example/p.png",
            )
            .unwrap();
        }
        // n + 1 entries: exactly one goes, and it must be a sidecar.
        assert_eq!(enforce_cache_bounds(&layout).unwrap(), 1);
        assert!(cached_bytes(&layout, "real@host").is_some());
        let surviving_sidecars = (1..=n)
            .filter(|i| load_meta(&layout, &format!("pending{i}@host")).is_some())
            .count();
        assert_eq!(i64::try_from(surviving_sidecars).unwrap(), n - 1);
    }

    #[test]
    fn eviction_is_a_no_op_under_both_bounds() {
        let (layout, _t) = layout();
        store_success(&layout, "a@h", "https://cdn.example/a.png", &png(16), 1).unwrap();
        assert_eq!(enforce_cache_bounds(&layout).unwrap(), 0);
        assert!(cached_bytes(&layout, "a@h").is_some());
    }

    #[test]
    fn eviction_on_an_empty_cache_is_a_no_op() {
        let (layout, _t) = layout();
        assert_eq!(enforce_cache_bounds(&layout).unwrap(), 0);
    }

    // ----- the cache-only read path -----

    #[tokio::test]
    async fn the_cached_read_path_issues_no_request_even_when_a_refresh_is_due() {
        // [`cached_bytes`] is what [`crate::client::Client::fedi_avatar_cached`]
        // and, above it, the shells' LIT contact rows read through. A LIT row
        // must never cause an observable request to a fediverse server:
        // receiving a private message would otherwise show up as fetch timing
        // on someone else's access log. Assert the property, not the intent.
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .set_body_bytes(vec![0x89; 16]),
            )
            .mount(&server)
            .await;

        let (layout, _t) = layout();
        let source = format!("{}/avatar.png", server.uri());
        // The adversarial fixture: an entry a fetch-capable path WOULD
        // refresh right now, whose icon URL is a live server. Without this
        // the zero below could be zero for the wrong reason.
        store_success(&layout, "linked@host", &source, &png(48), 1).unwrap();
        let now = 1 + AVATAR_REFRESH_MS;
        assert!(
            due_for_refresh(load_meta(&layout, "linked@host").as_ref(), now),
            "fixture must be due for refresh or the assertion below is vacuous",
        );

        assert_eq!(cached_bytes(&layout, "linked@host").unwrap().len(), 48);
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a cache-only avatar read must issue zero requests",
        );
        // Nor may it leave state behind that arms one later: the sidecar is
        // untouched, so no "due" stamp moved and no failure backoff started.
        let meta = load_meta(&layout, "linked@host").unwrap();
        assert_eq!(meta.fetched_at_ms, 1);
        assert_eq!(meta.source_url, source);
        assert!(!meta.failed);

        // Control: the server does record requests, so the emptiness above
        // is a property of the read path and not of the harness.
        reqwest::get(&source).await.expect("control request");
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            1,
            "the mock server counts requests; the cached read simply made none",
        );
    }

    #[test]
    fn eviction_removes_both_the_image_and_its_sidecar() {
        let (layout, _t) = layout();
        for i in 1..=(max_entries() + 1) {
            store_success(
                &layout,
                &format!("user{i}@host"),
                "https://cdn.example/a.png",
                &png(16),
                i,
            )
            .unwrap();
        }
        enforce_cache_bounds(&layout).unwrap();
        assert!(load_meta(&layout, "user1@host").is_none());
        assert!(cached_bytes(&layout, "user1@host").is_none());
    }
}
