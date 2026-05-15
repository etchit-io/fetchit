//! User-facing settings, persisted to `settings.json` in the app-local data
//! dir. Loaded once at startup; written through whenever the user changes a
//! value from the settings panel. JSON because it's human-inspectable and the
//! file is tiny — no schema migration tooling needed.

use crate::disk_cache::Policy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bookmark {
    /// 64-hex Autonomi address.
    pub address: String,
    /// Display label — either user-renamed or auto-derived (HTML <title>, an
    /// etchit-envelope title, or a truncated address).
    pub label: String,
    /// Unix-epoch seconds when first bookmarked. Used for stable ordering.
    pub created_at: u64,
}

/// User-configurable idle behaviour. `timeout_minutes == 0` means "never
/// auto-disconnect". Idle = no fetch activity for this many minutes. The
/// timer is driven by the JS side; this is just the persisted policy.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdlePolicy {
    pub timeout_minutes: u32,
}

impl Default for IdlePolicy {
    fn default() -> Self {
        Self { timeout_minutes: 30 }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub cache: Policy,
    pub bookmarks: Vec<Bookmark>,
    pub idle: IdlePolicy,
    /// User-supplied bootstrap peer list. Empty = fall back to the
    /// bundled `DEFAULT_PEERS` (see `fetchit-net::peers`). Each entry is
    /// either an `ip:port` shorthand or a full multiaddr — both parse
    /// through `parse_bootstrap_peer`.
    pub peers: Vec<String>,
}

impl Settings {
    /// Read the settings file at `path`. Missing or malformed files yield
    /// defaults — explicit, no surprises, and lets users always recover by
    /// deleting the file.
    pub fn load(path: &Path) -> Self {
        let Ok(text) = fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// Write the settings file atomically-ish: create the parent dir if it's
    /// missing, then overwrite the target. Real atomic-rename would need a
    /// tempfile; the file is small enough that a torn write is unlikely to
    /// be both partial and parseable.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text =
            serde_json::to_string_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, text)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::disk_cache::ClearMode;
    use tempfile::tempdir;

    #[test]
    fn load_missing_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let s = Settings::load(&p);
        assert!(!s.cache.enabled);
        assert_eq!(s.cache.mode, ClearMode::Persist);
    }

    #[test]
    fn load_malformed_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(&p, "{not valid json").unwrap();
        let s = Settings::load(&p);
        assert!(!s.cache.enabled);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        s.cache.enabled = true;
        s.cache.mode = ClearMode::OnClose;
        s.cache.max_bytes = 123_456;
        s.save(&p).unwrap();

        let loaded = Settings::load(&p);
        assert!(loaded.cache.enabled);
        assert_eq!(loaded.cache.mode, ClearMode::OnClose);
        assert_eq!(loaded.cache.max_bytes, 123_456);
    }

    #[test]
    fn save_creates_missing_parent_dirs() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("nested").join("deep").join("settings.json");
        let s = Settings::default();
        s.save(&p).unwrap();
        assert!(p.exists());
    }

    #[test]
    fn unknown_fields_in_file_are_ignored() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(
            &p,
            r#"{"cache":{"enabled":true,"mode":"persist","maxBytes":100},"future_setting":"x"}"#,
        )
        .unwrap();
        let s = Settings::load(&p);
        assert!(s.cache.enabled);
        assert_eq!(s.cache.max_bytes, 100);
    }

    #[test]
    fn bookmarks_default_to_empty_and_round_trip() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        assert!(s.bookmarks.is_empty());
        s.bookmarks.push(Bookmark {
            address: "0".repeat(64),
            label: "Test page".into(),
            created_at: 1_700_000_000,
        });
        s.save(&p).unwrap();

        let loaded = Settings::load(&p);
        assert_eq!(loaded.bookmarks.len(), 1);
        assert_eq!(loaded.bookmarks[0].label, "Test page");
        assert_eq!(loaded.bookmarks[0].created_at, 1_700_000_000);
    }

    #[test]
    fn missing_bookmarks_field_in_file_defaults_to_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        // A file written by an older build without the bookmarks field.
        fs::write(&p, r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#).unwrap();
        let s = Settings::load(&p);
        assert!(s.bookmarks.is_empty());
    }

    #[test]
    fn idle_policy_defaults_to_30_minutes() {
        let s = Settings::default();
        assert_eq!(s.idle.timeout_minutes, 30);
    }

    #[test]
    fn idle_policy_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        s.idle.timeout_minutes = 240;
        s.save(&p).unwrap();
        let loaded = Settings::load(&p);
        assert_eq!(loaded.idle.timeout_minutes, 240);
    }

    #[test]
    fn missing_idle_field_in_file_defaults_to_30() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(&p, r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#).unwrap();
        let s = Settings::load(&p);
        assert_eq!(s.idle.timeout_minutes, 30);
    }

    #[test]
    fn peers_default_to_empty_and_round_trip() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        assert!(s.peers.is_empty());
        s.peers = vec!["127.0.0.1:10000".into(), "203.0.113.4:10000".into()];
        s.save(&p).unwrap();
        let loaded = Settings::load(&p);
        assert_eq!(loaded.peers, vec!["127.0.0.1:10000", "203.0.113.4:10000"]);
    }

    #[test]
    fn missing_peers_field_in_file_defaults_to_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(&p, r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#).unwrap();
        let s = Settings::load(&p);
        assert!(s.peers.is_empty());
    }
}
