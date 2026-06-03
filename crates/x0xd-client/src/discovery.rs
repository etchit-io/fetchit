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

use crate::error::DiscoveryError;
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
/// # Errors
/// Returns [`DiscoveryError::NotInstalled`] when no data directory can
/// be located, [`DiscoveryError::NotRunning`] when the daemon's
/// `api.port` / `api-token` are absent, [`DiscoveryError::Malformed`]
/// when those files exist but are empty / not UTF-8, or
/// [`DiscoveryError::PermissionDenied`] / [`DiscoveryError::Io`] for
/// filesystem-level failures.
pub async fn discover_local() -> Result<DaemonEndpoint, DiscoveryError> {
    let dir = default_data_dir()?;
    discover_in(&dir).await
}

/// Discover an x0xd instance in a specific data directory — useful for
/// named instances (`--name alice`) or test fixtures.
///
/// # Errors
/// Same variants as [`discover_local`].
pub async fn discover_in(dir: &Path) -> Result<DaemonEndpoint, DiscoveryError> {
    if !tokio::fs::try_exists(dir).await.unwrap_or(false) {
        return Err(DiscoveryError::NotInstalled(dir.to_path_buf()));
    }
    let raw = read_field(dir, "api.port").await?;
    let token = read_field(dir, "api-token").await?;
    if raw.is_empty() {
        return Err(DiscoveryError::Malformed(format!(
            "api.port at {} is empty",
            dir.display()
        )));
    }
    if token.is_empty() {
        return Err(DiscoveryError::Malformed(format!(
            "api-token at {} is empty",
            dir.display()
        )));
    }
    let base_url = base_url_from_api_port_line(&raw);
    Ok(DaemonEndpoint {
        base_url,
        token,
        data_dir: dir.to_path_buf(),
    })
}

async fn read_field(dir: &Path, name: &'static str) -> Result<String, DiscoveryError> {
    let path = dir.join(name);
    match tokio::fs::read_to_string(&path).await {
        Ok(raw) => Ok(raw.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(DiscoveryError::NotRunning(name)),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(DiscoveryError::PermissionDenied { path, source: e })
        }
        Err(e) => Err(e.into()),
    }
}

/// Normalise the contents of x0xd's `api.port` file into an HTTP base
/// URL (`http://<host>:<port>`).
///
/// `api.port` is sometimes a bare port (e.g. `12700`, the legacy
/// shape) and sometimes a full `host:port` authority (e.g.
/// `127.0.0.1:12700`, the systemd-rig shape). Both must be handled
/// uniformly: bare ports default to loopback (`127.0.0.1`),
/// host:port values pass through verbatim, and IPv6 authorities
/// (`[::1]:12700`) survive intact because the rule is "presence of a
/// colon means the whole line is already an authority."
///
/// This is the SINGLE point of normalization for the file format.
/// Downstream callers — `discover_in`, the test scaffold at
/// `crates/fetchit-chat/tests/m2_live.rs`, the publish-path probe at
/// `crates/fetchit-chat/examples/m2_publish_path_probe.rs` — all
/// route through here so a future rig change to the file shape only
/// has to update one place.
///
/// The input MUST already have been `str::trim`med; this function
/// does not strip whitespace.
#[must_use]
pub fn base_url_from_api_port_line(raw: &str) -> String {
    if raw.contains(':') {
        format!("http://{raw}")
    } else {
        format!("http://127.0.0.1:{raw}")
    }
}

fn default_data_dir() -> Result<PathBuf, DiscoveryError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    #[cfg(target_os = "linux")]
    {
        home.map(|h| h.join(".local/share/x0x"))
            .ok_or_else(|| DiscoveryError::NotInstalled(PathBuf::from("$HOME/.local/share/x0x")))
    }
    #[cfg(target_os = "macos")]
    {
        home.map(|h| h.join("Library/Application Support/x0x"))
            .ok_or_else(|| {
                DiscoveryError::NotInstalled(PathBuf::from("$HOME/Library/Application Support/x0x"))
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(|d| PathBuf::from(d).join("x0x"))
            .ok_or_else(|| DiscoveryError::NotInstalled(PathBuf::from("%APPDATA%\\x0x")))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        home.map(|h| h.join(".x0x"))
            .ok_or_else(|| DiscoveryError::NotInstalled(PathBuf::from("$HOME/.x0x")))
    }
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
    async fn missing_dir_is_not_installed() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("never-existed");
        let err = discover_in(&absent).await.unwrap_err();
        assert!(
            matches!(err, DiscoveryError::NotInstalled(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn empty_dir_is_not_running() {
        let dir = tempdir().unwrap();
        let err = discover_in(dir.path()).await.unwrap_err();
        assert!(
            matches!(err, DiscoveryError::NotRunning("api.port")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_token_is_not_running() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("api.port"), "12700")
            .await
            .unwrap();
        let err = discover_in(dir.path()).await.unwrap_err();
        assert!(
            matches!(err, DiscoveryError::NotRunning("api-token")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn empty_port_is_malformed() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("api.port"), "\n\n")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("api-token"), "tok")
            .await
            .unwrap();
        let err = discover_in(dir.path()).await.unwrap_err();
        assert!(matches!(err, DiscoveryError::Malformed(_)), "got {err:?}");
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

    #[test]
    fn base_url_from_api_port_line_bare_port_defaults_to_loopback() {
        assert_eq!(
            base_url_from_api_port_line("12700"),
            "http://127.0.0.1:12700",
        );
    }

    #[test]
    fn base_url_from_api_port_line_host_port_passes_through() {
        assert_eq!(
            base_url_from_api_port_line("127.0.0.1:8080"),
            "http://127.0.0.1:8080",
        );
        assert_eq!(
            base_url_from_api_port_line("192.168.1.5:45031"),
            "http://192.168.1.5:45031",
        );
    }

    #[test]
    fn base_url_from_api_port_line_ipv6_authority_survives() {
        // Cross-review note: the prior `split(':').nth(1)` parser
        // returned the empty segment between `::` for an IPv6 like
        // `[::1]:12700`. The colon-presence rule preserves the whole
        // authority because any string with a `:` is taken to
        // already be a full host:port (or [v6]:port).
        assert_eq!(
            base_url_from_api_port_line("[::1]:12700"),
            "http://[::1]:12700",
        );
        assert_eq!(
            base_url_from_api_port_line("[fe80::1]:8080"),
            "http://[fe80::1]:8080",
        );
    }
}
