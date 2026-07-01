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
        Self {
            timeout_minutes: 30,
        }
    }
}

/// One fetchit-operated relay node, advertised in Settings → Network
/// as a region option. Custom URLs go through the same UI but skip
/// this table.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownRelay {
    /// Wire tag (matches `fetchit_relay_proto::Region::tag()`).
    pub tag: &'static str,
    /// Human-facing label rendered in the Settings dropdown.
    pub label: &'static str,
    /// Base URL the desktop client connects to.
    pub url: &'static str,
}

/// Fetchit-operated relay nodes. The first entry is the shipped default.
/// Add a new row when a region comes online — the frontend reads this
/// table verbatim so no separate JS update is needed.
///
/// `url` uses the `https` scheme; the relay client upgrades it to `wss`
/// for the WebSocket connection (see `fetchit_relay_client::build_ws_url`).
pub const KNOWN_RELAYS: &[KnownRelay] = &[
    KnownRelay {
        tag: "nyc",
        label: "NYC (US East)",
        url: "https://nyc-relay.etchit.io",
    },
    KnownRelay {
        tag: "fra",
        label: "Frankfurt (EU)",
        url: "https://fra-relay.etchit.io",
    },
];

/// Default fetchit-operated relay URL. First entry of [`KNOWN_RELAYS`].
pub const DEFAULT_RELAY_URL: &str = KNOWN_RELAYS[0].url;

fn default_relay_url() -> String {
    DEFAULT_RELAY_URL.to_owned()
}

/// One-time relay-URL migrations for the #114 TLS cutover. An install whose
/// persisted `relay_url` still names a retired bare-IP origin is moved to the
/// matching `https` host on load, so it follows the cutover instead of
/// dropping when that origin's plaintext port is closed. Old to new pairs;
/// historical, so the table does not track [`KNOWN_RELAYS`].
const RELAY_URL_MIGRATIONS: &[(&str, &str)] = &[
    ("http://67.207.94.66:8088", "https://nyc-relay.etchit.io"),
    ("http://159.89.11.217:8088", "https://fra-relay.etchit.io"),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// Chat relay URL. Chat sends route through this relay; receivers
    /// connect for inbound delivery. Default points at the fetchit-
    /// operated NYC node; advanced users can change it.
    #[serde(default = "default_relay_url")]
    pub relay_url: String,
    /// User-chosen display name. Embedded in share cards and outbound
    /// DMs so recipients see a friendly label instead of the raw
    /// `agent_id`. Empty = fall back to the auto-derived
    /// `agent-<6-hex>` placeholder.
    #[serde(default)]
    pub display_name: String,
    /// Opt-in: wire a LAN-direct transport into the chat Router. When
    /// `true`, sends to peers reachable on the same network skip the
    /// relay and travel over a local Noise XX channel. Default off
    /// until the host has tested two-laptop bring-up.
    #[serde(default)]
    pub lan_direct_enabled: bool,
    /// Master feature gate for the LIT Chat surface. M0 ships this
    /// default OFF in release builds so the fetch>it v1 release does
    /// not leak chat scope to non-testers; debug builds default ON so
    /// `npm run tauri dev` keeps the chat panel visible for active
    /// development. The `FETCHIT_CHAT_ENABLED` env var overrides
    /// either default at startup. M1 announcement flips the release
    /// default to ON.
    #[serde(default = "default_chat_enabled")]
    pub chat_enabled: bool,
    /// Active minted fediverse handle (bare, no `@`). Empty = the user
    /// has not opted in to public posting. The per-handle key material
    /// lives in the chat vault; this only records which handle is
    /// active.
    #[serde(default)]
    pub fediverse_handle: String,
    /// First-run onboarding marker. False until the welcome overlay
    /// completes or is skipped once; the frontend gates the overlay
    /// on this so it never re-prompts.
    #[serde(default)]
    pub onboarding_done: bool,
}

/// Build-flavor-dependent default for the chat feature flag.
/// Release builds: false (M0 ship discipline — no chat scope leak).
/// Debug builds: true (devs keep the chat panel visible by default).
fn default_chat_enabled() -> bool {
    cfg!(debug_assertions)
}

/// Env var that forces the chat feature on or off at startup,
/// bypassing the persisted setting. Values: `0/false/no/off` → off,
/// `1/true/yes/on` → on, anything else → fall through to the setting.
///
/// M0 contract: the v1 fetch>it release ships with chat hidden by
/// default. Testers flip via env or Settings → Advanced.
pub const CHAT_ENABLED_ENV: &str = "FETCHIT_CHAT_ENABLED";

/// Resolve the effective chat-enabled flag from (env override,
/// persisted setting). Env wins when set to a recognised value;
/// otherwise the setting wins. Settings' own default is
/// `cfg!(debug_assertions)`, so an unconfigured release build
/// returns `false` here.
#[must_use]
pub fn resolve_chat_enabled(settings: &Settings) -> bool {
    if let Ok(raw) = std::env::var(CHAT_ENABLED_ENV) {
        match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => return true,
            "0" | "false" | "no" | "off" => return false,
            _ => {} // unrecognised — fall through to the persisted setting
        }
    }
    settings.chat_enabled
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cache: Policy::default(),
            bookmarks: Vec::new(),
            idle: IdlePolicy::default(),
            peers: Vec::new(),
            relay_url: default_relay_url(),
            display_name: String::new(),
            lan_direct_enabled: false,
            chat_enabled: default_chat_enabled(),
            fediverse_handle: String::new(),
            onboarding_done: false,
        }
    }
}

impl Settings {
    /// Read the settings file at `path`. Missing or malformed files
    /// yield defaults; deleting the file is a valid recovery path.
    pub fn load(path: &Path) -> Self {
        let Ok(text) = fs::read_to_string(path) else {
            return Self::default();
        };
        let mut settings: Self = serde_json::from_str(&text).unwrap_or_default();
        settings.migrate_relay_url();
        settings
    }

    /// Apply [`RELAY_URL_MIGRATIONS`] to the persisted `relay_url` so an
    /// install on a retired bare-IP origin follows the #114 TLS cutover.
    /// Idempotent: a url already on the https host, or any custom value, is
    /// left unchanged.
    fn migrate_relay_url(&mut self) {
        for (old, new) in RELAY_URL_MIGRATIONS {
            if self.relay_url == *old {
                (*new).clone_into(&mut self.relay_url);
                return;
            }
        }
    }

    /// Write the settings file atomically-ish: create the parent dir if it's
    /// missing, then overwrite the target. Real atomic-rename would need a
    /// tempfile; the file is small enough that a torn write is unlikely to
    /// be both partial and parseable.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
    fn load_migrates_retired_bare_ip_relay_to_https() {
        // An install persisted on the pre-#114 bare-IP origin must follow the
        // TLS cutover on load, or it drops when D4 closes the plaintext port.
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        for (old, want) in [
            ("http://67.207.94.66:8088", "https://nyc-relay.etchit.io"),
            ("http://159.89.11.217:8088", "https://fra-relay.etchit.io"),
        ] {
            let s = Settings {
                relay_url: old.into(),
                ..Default::default()
            };
            s.save(&p).unwrap();
            assert_eq!(Settings::load(&p).relay_url, want);
        }
    }

    #[test]
    fn load_leaves_custom_or_already_migrated_relay_untouched() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        for url in [
            "https://nyc-relay.etchit.io",
            "https://my.custom.relay:9000",
        ] {
            let s = Settings {
                relay_url: url.into(),
                ..Default::default()
            };
            s.save(&p).unwrap();
            assert_eq!(Settings::load(&p).relay_url, url);
        }
    }

    #[test]
    fn fediverse_handle_defaults_empty_and_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        assert!(s.fediverse_handle.is_empty());
        s.fediverse_handle = "josh".into();
        s.save(&p).unwrap();
        assert_eq!(Settings::load(&p).fediverse_handle, "josh");
    }

    #[test]
    fn onboarding_done_defaults_false_and_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        assert!(!s.onboarding_done);
        s.onboarding_done = true;
        s.save(&p).unwrap();
        assert!(Settings::load(&p).onboarding_done);
    }

    #[test]
    fn missing_onboarding_done_field_in_file_defaults_false() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
        assert!(!Settings::load(&p).onboarding_done);
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
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
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
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
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
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
        let s = Settings::load(&p);
        assert!(s.peers.is_empty());
    }

    #[test]
    fn display_name_defaults_to_empty_and_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        assert_eq!(s.display_name, "");
        s.display_name = "Alice 👋".into();
        s.save(&p).unwrap();
        let loaded = Settings::load(&p);
        assert_eq!(loaded.display_name, "Alice 👋");
    }

    #[test]
    fn missing_display_name_field_in_file_defaults_to_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
        let s = Settings::load(&p);
        assert_eq!(s.display_name, "");
    }

    // The chat-flag resolver reads a process-global env var, so the
    // tests serialise via a mutex to keep parallel runs deterministic.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_chat_env<F: FnOnce() -> R, R>(set_to: Option<&str>, f: F) -> R {
        let _guard = ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var_os(CHAT_ENABLED_ENV);
        match set_to {
            Some(v) => std::env::set_var(CHAT_ENABLED_ENV, v),
            None => std::env::remove_var(CHAT_ENABLED_ENV),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(CHAT_ENABLED_ENV, v),
            None => std::env::remove_var(CHAT_ENABLED_ENV),
        }
        out
    }

    #[test]
    fn chat_enabled_default_follows_build_flavor() {
        // The default field initialiser matches the build-flavor
        // helper. In debug builds the test runs with
        // `debug_assertions` on, so this fires `true`. A future
        // release-test mode would invert; the assertion stays
        // honest because both sides resolve via the same helper.
        let s = Settings::default();
        assert_eq!(s.chat_enabled, default_chat_enabled());
    }

    #[test]
    fn resolve_env_unset_returns_setting() {
        with_chat_env(None, || {
            let s = Settings {
                chat_enabled: true,
                ..Settings::default()
            };
            assert!(resolve_chat_enabled(&s));
            let s = Settings {
                chat_enabled: false,
                ..Settings::default()
            };
            assert!(!resolve_chat_enabled(&s));
        });
    }

    #[test]
    fn resolve_env_overrides_setting_to_true() {
        with_chat_env(Some("1"), || {
            let s = Settings {
                chat_enabled: false,
                ..Settings::default()
            };
            assert!(resolve_chat_enabled(&s));
        });
        with_chat_env(Some("true"), || {
            let s = Settings {
                chat_enabled: false,
                ..Settings::default()
            };
            assert!(resolve_chat_enabled(&s));
        });
        with_chat_env(Some("ON"), || {
            // Case-insensitive.
            let s = Settings {
                chat_enabled: false,
                ..Settings::default()
            };
            assert!(resolve_chat_enabled(&s));
        });
    }

    #[test]
    fn resolve_env_overrides_setting_to_false() {
        with_chat_env(Some("0"), || {
            let s = Settings {
                chat_enabled: true,
                ..Settings::default()
            };
            assert!(!resolve_chat_enabled(&s));
        });
        with_chat_env(Some("FALSE"), || {
            let s = Settings {
                chat_enabled: true,
                ..Settings::default()
            };
            assert!(!resolve_chat_enabled(&s));
        });
        with_chat_env(Some("off"), || {
            let s = Settings {
                chat_enabled: true,
                ..Settings::default()
            };
            assert!(!resolve_chat_enabled(&s));
        });
    }

    #[test]
    fn resolve_unrecognised_env_falls_through_to_setting() {
        // "maybe" isn't on the recognised list, so the setting wins.
        with_chat_env(Some("maybe"), || {
            let s = Settings {
                chat_enabled: true,
                ..Settings::default()
            };
            assert!(resolve_chat_enabled(&s));
            let s = Settings {
                chat_enabled: false,
                ..Settings::default()
            };
            assert!(!resolve_chat_enabled(&s));
        });
    }

    #[test]
    fn chat_enabled_round_trips_through_settings_json() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let s = Settings {
            chat_enabled: !default_chat_enabled(),
            ..Settings::default()
        };
        s.save(&p).unwrap();
        let loaded = Settings::load(&p);
        assert_eq!(loaded.chat_enabled, !default_chat_enabled());
    }

    #[test]
    fn missing_chat_enabled_field_in_file_defaults_to_build_flavor() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        // settings.json from before the field landed.
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
        let s = Settings::load(&p);
        assert_eq!(s.chat_enabled, default_chat_enabled());
    }

    #[test]
    fn lan_direct_enabled_defaults_false_and_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let mut s = Settings::default();
        assert!(!s.lan_direct_enabled);
        s.lan_direct_enabled = true;
        s.save(&p).unwrap();
        let loaded = Settings::load(&p);
        assert!(loaded.lan_direct_enabled);
    }

    #[test]
    fn missing_lan_direct_enabled_field_in_file_defaults_false() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("settings.json");
        fs::write(
            &p,
            r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
        )
        .unwrap();
        let s = Settings::load(&p);
        assert!(!s.lan_direct_enabled);
    }
}
