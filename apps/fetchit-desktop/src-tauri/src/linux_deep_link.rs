//! Linux-specific deep-link handler reconciliation.
//!
//! `tauri-plugin-deep-link::register_all()` writes a runtime
//! `.desktop` file (under `~/.local/share/applications/`) that claims
//! the `autonomi://` and `fetchit://` URI schemes. That works for
//! `AppImage` and `cargo run` builds, but on machines that *also*
//! have a `.deb` / `.rpm` of fetch>it installed it ends up
//! registering the schemes twice — GNOME's "Open With" dialog then
//! shows two `fetchit` entries (one with the bundle's icon, one with
//! the generic fallback).
//!
//! This module sniffs the standard `.desktop` directories for an
//! existing system-installed handler. If one is found, runtime
//! registration is skipped and any stale runtime handler left over
//! from a previous run is removed.

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use tauri::{AppHandle, Manager, Runtime};

/// Standard system directories the bundled `.deb` / `.rpm` installer
/// writes their `.desktop` file into.
#[cfg(target_os = "linux")]
const SYSTEM_DESKTOP_DIRS: &[&str] = &["/usr/share/applications", "/usr/local/share/applications"];

/// Decide whether to register `autonomi://` + `fetchit://` schemes at
/// runtime, or step aside for an already-installed bundle handler.
///
/// If a bundle-installed `.desktop` file is found, the stale runtime
/// handler (if any) is removed so the OS settles on a single source
/// of truth.
#[cfg(target_os = "linux")]
pub(crate) fn register_or_cleanup<R: Runtime>(app: &AppHandle<R>) {
    use tauri_plugin_deep_link::DeepLinkExt;

    let runtime_handler_name = our_runtime_handler_name();
    let user_apps_dir = app.path().data_dir().ok().map(|p| p.join("applications"));

    let dirs = handler_search_dirs(user_apps_dir.as_deref());

    if bundle_handler_present(&dirs, &runtime_handler_name) {
        if let Some(user_dir) = user_apps_dir.as_deref() {
            let stale = user_dir.join(&runtime_handler_name);
            let _ = fs::remove_file(&stale);
        }
        return;
    }

    let _ = app.deep_link().register_all();
}

/// `<basename(current_exe)>-handler.desktop` — matches what
/// `tauri-plugin-deep-link` writes at runtime, so we can recognise
/// our own file and not mistake it for an installed bundle.
#[cfg(target_os = "linux")]
fn our_runtime_handler_name() -> String {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .map(|n| format!("{}-handler.desktop", n.to_string_lossy()))
        .unwrap_or_default()
}

/// Search list: the user's data dir's `applications/` plus the
/// standard system dirs. Order doesn't matter — we only need to find
/// any *non-runtime* `.desktop` registering our schemes.
#[cfg(target_os = "linux")]
fn handler_search_dirs(user_apps_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = SYSTEM_DESKTOP_DIRS.iter().map(PathBuf::from).collect();
    if let Some(d) = user_apps_dir {
        dirs.push(d.to_path_buf());
    }
    dirs
}

/// True if any `.desktop` file in `dirs` (other than our own runtime
/// handler) claims `x-scheme-handler/autonomi` or
/// `x-scheme-handler/fetchit`.
#[cfg(target_os = "linux")]
fn bundle_handler_present(dirs: &[PathBuf], runtime_handler_name: &str) -> bool {
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".desktop") {
                continue;
            }
            if name == runtime_handler_name {
                continue;
            }
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            if contents.contains("x-scheme-handler/autonomi")
                || contents.contains("x-scheme-handler/fetchit")
            {
                return true;
            }
        }
    }
    false
}

/// No-op shim on non-Linux targets so the call site can stay
/// platform-agnostic.
#[cfg(not(target_os = "linux"))]
pub(crate) fn register_or_cleanup<R: tauri::Runtime>(_app: &tauri::AppHandle<R>) {}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_desktop(dir: &Path, name: &str, mime: Option<&str>) {
        let path = dir.join(name);
        let body = match mime {
            Some(m) => {
                format!("[Desktop Entry]\nType=Application\nName=test\nExec=/x\nMimeType={m}\n")
            }
            None => "[Desktop Entry]\nType=Application\nName=test\nExec=/x\n".to_string(),
        };
        fs::write(&path, body).unwrap();
    }

    #[test]
    fn empty_dirs_means_no_bundle() {
        let d = tempdir().unwrap();
        let dirs = vec![d.path().to_path_buf()];
        assert!(!bundle_handler_present(
            &dirs,
            "fetchit-desktop-handler.desktop"
        ));
    }

    #[test]
    fn finds_bundle_via_autonomi_scheme() {
        let d = tempdir().unwrap();
        write_desktop(
            d.path(),
            "io.etchit.fetchit.desktop",
            Some("x-scheme-handler/autonomi"),
        );
        let dirs = vec![d.path().to_path_buf()];
        assert!(bundle_handler_present(
            &dirs,
            "fetchit-desktop-handler.desktop"
        ));
    }

    #[test]
    fn finds_bundle_via_fetchit_scheme() {
        let d = tempdir().unwrap();
        write_desktop(
            d.path(),
            "io.etchit.fetchit.desktop",
            Some("x-scheme-handler/fetchit"),
        );
        let dirs = vec![d.path().to_path_buf()];
        assert!(bundle_handler_present(
            &dirs,
            "fetchit-desktop-handler.desktop"
        ));
    }

    #[test]
    fn ignores_our_own_runtime_handler() {
        let d = tempdir().unwrap();
        write_desktop(
            d.path(),
            "fetchit-desktop-handler.desktop",
            Some("x-scheme-handler/autonomi"),
        );
        let dirs = vec![d.path().to_path_buf()];
        assert!(!bundle_handler_present(
            &dirs,
            "fetchit-desktop-handler.desktop"
        ));
    }

    #[test]
    fn ignores_unrelated_desktop_files() {
        let d = tempdir().unwrap();
        write_desktop(d.path(), "firefox.desktop", Some("x-scheme-handler/http"));
        write_desktop(d.path(), "vlc.desktop", None);
        let dirs = vec![d.path().to_path_buf()];
        assert!(!bundle_handler_present(
            &dirs,
            "fetchit-desktop-handler.desktop"
        ));
    }

    #[test]
    fn missing_dirs_are_silently_skipped() {
        let d = tempdir().unwrap();
        let dirs = vec![
            PathBuf::from("/nonexistent/path/one"),
            d.path().to_path_buf(),
        ];
        write_desktop(
            d.path(),
            "io.etchit.fetchit.desktop",
            Some("x-scheme-handler/autonomi"),
        );
        assert!(bundle_handler_present(
            &dirs,
            "fetchit-desktop-handler.desktop"
        ));
    }
}
