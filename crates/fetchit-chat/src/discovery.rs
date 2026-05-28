//! Locate a running `x0xd` daemon on the local machine.
//!
//! `x0xd` writes its API port to `api.port` and bearer token to
//! `api-token` inside a platform-specific data directory. The default
//! data directory layout — confirmed against the x0x README — is:
//!
//! | platform | path                                            |
//! |----------|-------------------------------------------------|
//! | Linux    | `$HOME/.local/share/x0x`                        |
//! | macOS    | `$HOME/Library/Application Support/x0x`         |
//! | Windows  | `%APPDATA%\x0x`                                 |
//!
//! Named instances (`x0x start --name alice`) get a sibling directory
//! under the same parent.

use crate::error::{ChatError, Result};
use std::path::{Path, PathBuf};

/// Resolved location of a running x0xd daemon.
#[derive(Debug, Clone)]
pub struct DaemonEndpoint {
    /// Base URL, e.g. `http://127.0.0.1:12700`.
    pub base_url: String,
    /// Bearer token to send in `Authorization: Bearer …`.
    pub token: String,
    /// Data directory the values came from.
    pub data_dir: PathBuf,
}

/// Discover the default x0xd instance for the current user.
///
/// Returns [`ChatError::NotDiscoverable`] if the daemon's data files
/// can't be read — usually because the daemon isn't running.
pub async fn discover_local() -> Result<DaemonEndpoint> {
    let dir =
        default_data_dir().ok_or_else(|| ChatError::NotDiscoverable("no home directory".into()))?;
    discover_in(&dir).await
}

/// Discover an x0xd instance in a specific data directory — useful for
/// named instances (`--name alice`) or test fixtures.
pub async fn discover_in(dir: &Path) -> Result<DaemonEndpoint> {
    let raw = read_trimmed(&dir.join("api.port")).await.map_err(|_| {
        ChatError::NotDiscoverable(format!("api.port missing in {}", dir.display()))
    })?;
    let token = read_trimmed(&dir.join("api-token")).await.map_err(|_| {
        ChatError::NotDiscoverable(format!("api-token missing in {}", dir.display()))
    })?;
    let base_url = build_base_url(&raw);
    Ok(DaemonEndpoint {
        base_url,
        token,
        data_dir: dir.to_path_buf(),
    })
}

/// The `api.port` file is sometimes a bare port (e.g. `12700`) and
/// sometimes a full `host:port` authority (e.g. `127.0.0.1:12700`).
/// Normalise both to a usable HTTP base URL.
fn build_base_url(raw: &str) -> String {
    if raw.contains(':') {
        format!("http://{raw}")
    } else {
        format!("http://127.0.0.1:{raw}")
    }
}

fn default_data_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    #[cfg(target_os = "linux")]
    {
        home.map(|h| h.join(".local/share/x0x"))
    }
    #[cfg(target_os = "macos")]
    {
        home.map(|h| h.join("Library/Application Support/x0x"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("x0x"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        home.map(|h| h.join(".x0x"))
    }
}

async fn read_trimmed(path: &Path) -> Result<String> {
    let raw = tokio::fs::read_to_string(path).await?;
    Ok(raw.trim().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn discovers_from_explicit_dir() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("api.port"), "12700\n")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("api-token"), "deadbeef\n")
            .await
            .unwrap();
        let ep = discover_in(dir.path()).await.unwrap();
        assert_eq!(ep.base_url, "http://127.0.0.1:12700");
        assert_eq!(ep.token, "deadbeef");
    }

    #[tokio::test]
    async fn missing_files_are_reported() {
        let dir = tempdir().unwrap();
        let err = discover_in(dir.path()).await.unwrap_err();
        assert!(matches!(err, ChatError::NotDiscoverable(_)));
    }

    #[tokio::test]
    async fn token_and_port_are_trimmed() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("api.port"), "  12701  \n\n")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("api-token"), "tok\n")
            .await
            .unwrap();
        let ep = discover_in(dir.path()).await.unwrap();
        assert_eq!(ep.base_url, "http://127.0.0.1:12701");
        assert_eq!(ep.token, "tok");
    }

    #[tokio::test]
    async fn full_authority_in_port_file_is_accepted() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("api.port"), "127.0.0.1:12700")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("api-token"), "tok")
            .await
            .unwrap();
        let ep = discover_in(dir.path()).await.unwrap();
        assert_eq!(ep.base_url, "http://127.0.0.1:12700");
    }
}
