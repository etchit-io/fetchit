#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

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

/// Background task that watches the bundled x0xd subprocess, respawns on
/// exit unless the crash-loop detector trips, and stops cleanly on signal.
pub struct SupervisorTask {
    handle: JoinHandle<()>,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl SupervisorTask {
    /// Send the shutdown signal and await the supervisor task. The inner
    /// `Child` handle is dropped on supervisor exit; for v1.0 we rely on the
    /// OS reaping the subprocess after the parent app exits. A future task
    /// wires explicit SIGTERM with grace + SIGKILL.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.handle.await;
    }
}

/// Spawn a background task that watches the bundled x0xd subprocess,
/// respawns on exit unless the crash-loop detector trips, and shuts
/// down cleanly on signal.
pub fn spawn_supervisor_task(
    cfg: SupervisorConfig,
    binary: PathBuf,
    disabled: Arc<Mutex<bool>>,
) -> SupervisorTask {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let mut detector = super::CrashLoopDetector::new(cfg.crash_window, cfg.crash_threshold);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    // Clean shutdown requested. Child is dropped when the
                    // task exits; OS reaps the subprocess. Explicit SIGTERM
                    // grace is a future task.
                    return;
                }
                spawn_res = tokio::task::spawn_blocking({
                    let binary = binary.clone();
                    let toml = cfg.bundled_toml.clone();
                    let range = cfg.port_range;
                    move || super::spawn::spawn_bundled(&binary, &toml, range)
                }) => {
                    match spawn_res {
                        Ok(Ok((mut child, _port))) => {
                            let exit =
                                tokio::task::spawn_blocking(move || child.wait()).await;
                            let crashed = matches!(exit, Ok(Ok(ref s)) if !s.success())
                                || matches!(exit, Ok(Err(_)) | Err(_));
                            if crashed && detector.record(std::time::Instant::now()) {
                                *disabled.lock().await = true;
                                eprintln!(
                                    "[fetchit][supervisor] x0xd crash-loop tripped; \
                                     disabling bundled binary for this session"
                                );
                                return;
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!(
                                "[fetchit][supervisor] x0xd spawn failed: {e}"
                            );
                            if detector.record(std::time::Instant::now()) {
                                *disabled.lock().await = true;
                                return;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[fetchit][supervisor] supervisor task panic: {e}"
                            );
                            return;
                        }
                    }
                }
            }
        }
    });
    SupervisorTask {
        handle,
        shutdown_tx,
    }
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

    #[cfg(unix)]
    #[tokio::test]
    async fn supervisor_respawns_until_crash_loop_disables() {
        // Use `/usr/bin/false` as the fake x0xd. The supervisor spawns it,
        // watches it exit non-zero, records a crash, repeats, and eventually
        // disables after 3 crashes within the window.
        let fake = PathBuf::from("/usr/bin/false");
        if !fake.exists() {
            // Environment without /usr/bin/false; skip silently.
            return;
        }
        let cfg = SupervisorConfig {
            bundled_binary: Some(fake.clone()),
            bundled_version: Some(semver::Version::parse("0.21.3").unwrap()),
            bundled_toml: PathBuf::from("/dev/null"),
            port_range: (51_000, 51_050),
            crash_window: Duration::from_secs(30),
            crash_threshold: 3,
        };
        let disabled = Arc::new(Mutex::new(false));
        let task = spawn_supervisor_task(cfg, fake, disabled.clone());

        // Wait up to 5s for the disable flag to flip.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if *disabled.lock().await {
                break;
            }
            assert!(
                tokio::time::Instant::now() <= deadline,
                "supervisor never disabled; check respawn loop"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        task.shutdown().await;
    }
}
