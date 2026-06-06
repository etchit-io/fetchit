#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::{pick_binary, BinaryChoice};

/// Configuration for the x0xd supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Path to the bundled x0xd binary, if shipped with this build.
    pub bundled_binary: Option<PathBuf>,
    /// Version of the bundled binary.
    pub bundled_version: Option<semver::Version>,
    /// Path to the TOML config to pass when spawning the bundled binary.
    pub bundled_toml: PathBuf,
    /// `[start, end)` port range scanned for a free port.
    pub port_range: (u16, u16),
    /// Sliding window length for crash-loop detection.
    pub crash_window: Duration,
    /// Number of crashes in `crash_window` that trips the circuit breaker.
    pub crash_threshold: usize,
}

/// Live handle returned by [`boot_supervisor`].
#[derive(Debug, Clone)]
pub struct SupervisorHandle {
    /// Which binary was selected.
    pub choice: BinaryChoice,
    /// Port the bundled x0xd was bound to, or `0` for an installed binary
    /// (which binds its own port via its own TOML; caller resolves URL via
    /// x0xd-client discovery).
    pub port: u16,
    /// Set to `true` when the supervisor enters crash-loop disable.
    pub disabled: Arc<Mutex<bool>>,
}

/// Boot the supervisor: pick binary, spawn if bundled, return handle.
///
/// # Errors
/// - `"no x0xd binary available"` when both installed and bundled are missing.
/// - Propagates spawn / port errors from [`super::spawn::spawn_bundled`].
pub async fn boot_supervisor(cfg: SupervisorConfig) -> Result<SupervisorHandle, String> {
    let installed = x0xd_client::discover_installed_x0xd();
    let bundled = match (cfg.bundled_binary.clone(), cfg.bundled_version.clone()) {
        (Some(p), Some(v)) => Some((p, v)),
        _ => None,
    };
    let choice = pick_binary(installed.as_ref(), bundled)
        .ok_or_else(|| "no x0xd binary available (neither installed nor bundled)".to_owned())?;

    let port = match &choice {
        BinaryChoice::Installed { .. } => {
            // Installed x0xd binds its own port via its own TOML.
            // Return 0 as the sentinel; caller resolves URL via
            // existing x0xd-client discovery.
            0
        }
        BinaryChoice::Bundled { binary, .. } => {
            let (_child, port) =
                super::spawn::spawn_bundled(binary, &cfg.bundled_toml, cfg.port_range)
                    .map_err(|e| format!("spawn bundled x0xd: {e}"))?;
            // _child intentionally dropped here; the OS reaps on app exit.
            // Task D5 wires a JoinHandle + respawn loop + clean SIGTERM on
            // app shutdown.
            port
        }
    };

    Ok(SupervisorHandle {
        choice,
        port,
        disabled: Arc::new(Mutex::new(false)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_config_clone_round_trips() {
        let cfg = SupervisorConfig {
            bundled_binary: Some(PathBuf::from("/x")),
            bundled_version: Some(semver::Version::new(0, 21, 3)),
            bundled_toml: PathBuf::from("/y.toml"),
            port_range: (45_000, 45_010),
            crash_window: Duration::from_secs(30),
            crash_threshold: 3,
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.bundled_binary, cfg.bundled_binary);
        assert_eq!(cloned.bundled_version, cfg.bundled_version);
        assert_eq!(cloned.port_range, cfg.port_range);
    }

    #[tokio::test]
    async fn boot_supervisor_errors_when_no_binary_anywhere() {
        // This test is environment-sensitive: it only meaningfully asserts
        // when there is NO x0xd on PATH. Even if x0xd IS on PATH, the test
        // still compiles + runs without panicking; it just asserts on the
        // outcome path that applies. We don't override PATH because env
        // mutations would race with other tests in this binary.
        let cfg = SupervisorConfig {
            bundled_binary: None,
            bundled_version: None,
            bundled_toml: PathBuf::from("/dev/null"),
            port_range: (50_000, 50_010),
            crash_window: Duration::from_secs(30),
            crash_threshold: 3,
        };
        let result = boot_supervisor(cfg).await;
        if x0xd_client::discover_installed_x0xd().is_none() {
            // No installed binary and no bundled => Err.
            assert!(result.is_err(), "expected err when no binary available");
        } else {
            // Installed x0xd present and chosen => Ok with port=0 sentinel.
            assert!(result.is_ok(), "installed binary picked => Ok");
        }
    }
}
