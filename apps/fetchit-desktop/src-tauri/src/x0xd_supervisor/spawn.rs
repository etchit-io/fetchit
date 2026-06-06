#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command};

/// Bind the next free port in `[start, end)` and return it.
/// Returns Err when no port in the range is free.
pub fn pick_free_port(start: u16, end: u16) -> Result<u16, String> {
    for port in start..end {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(format!("no free port in range {start}..{end}"))
}

/// Spawn the bundled x0xd on a managed port. The caller is
/// responsible for poll-detecting readiness on `127.0.0.1:<port>/version`
/// before threading the port into x0xd-client.
///
/// # Errors
/// - "no free port" when the port range is exhausted.
/// - `io::Error` when the subprocess fails to spawn.
#[allow(dead_code)]
pub fn spawn_bundled(
    binary: &Path,
    toml_path: &Path,
    port_range: (u16, u16),
) -> Result<(Child, u16), String> {
    let port = pick_free_port(port_range.0, port_range.1)?;
    let child = Command::new(binary)
        .arg("--config")
        .arg(toml_path)
        .arg("--http-bind")
        .arg(format!("127.0.0.1:{port}"))
        .spawn()
        .map_err(|e| format!("spawn bundled x0xd: {e}"))?;
    Ok((child, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_free_port_finds_a_port_in_a_wide_range() {
        let port = pick_free_port(45_000, 46_000).unwrap();
        assert!((45_000..46_000).contains(&port));
    }

    #[test]
    fn pick_free_port_errors_on_exhausted_range() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = listener.local_addr().unwrap().port();
        let err = pick_free_port(busy_port, busy_port + 1).unwrap_err();
        assert!(err.contains("no free port"));
    }
}
