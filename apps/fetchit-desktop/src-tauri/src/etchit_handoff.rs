//! etch/it creation handoff. fetch>it never writes; it points the user
//! at etch>it (the publisher) to create or edit their Autonomi profile.

use serde::Serialize;

/// Result of probing for an installed etch/it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffProbe {
    /// Whether an etch/it binary was found on PATH.
    pub installed: bool,
}

/// True if any known etch/it binary name resolves via the injected
/// path lookup. Pure so the probe is testable without a real PATH.
fn etchit_installed(on_path: impl Fn(&str) -> bool) -> bool {
    ["etchit", "etch-it", "etchit-desktop"]
        .iter()
        .any(|n| on_path(n))
}

fn on_path(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let p = dir.join(name);
        p.is_file() || p.with_extension("exe").is_file()
    })
}

/// Probe for an installed etch/it (PATH lookup). Non-fatal: the UI
/// always offers a "Get etch/it" fallback regardless of the result.
#[tauri::command]
#[must_use]
pub fn etchit_handoff() -> HandoffProbe {
    HandoffProbe {
        installed: etchit_installed(on_path),
    }
}

/// Open etch/it's profile editor via its registered URI scheme. Fixed
/// target, no user input near the opener.
///
/// Uses the OS-native URI launcher (`xdg-open` on Linux, `open` on
/// macOS, `cmd /c start` on Windows) because this app does not
/// bundle `tauri-plugin-opener`.
///
/// # Errors
/// Returns a user-facing string if the OS launcher fails to spawn.
#[tauri::command]
pub fn etchit_open_profile(_app: tauri::AppHandle) -> Result<(), String> {
    const TARGET: &str = "etchit://profile";
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(TARGET)
            .spawn()
            .map_err(|e| format!("couldn't open etch/it ({e})"))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(TARGET)
            .spawn()
            .map_err(|e| format!("couldn't open etch/it ({e})"))?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", TARGET])
            .spawn()
            .map_err(|e| format!("couldn't open etch/it ({e})"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn detects_installed_by_any_known_name() {
        assert!(etchit_installed(|n| n == "etch-it"));
        assert!(!etchit_installed(|_| false));
    }
}
