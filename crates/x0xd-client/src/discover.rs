//! Probe for `x0xd` binaries installed on the system.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

/// Location and version of an `x0xd` binary found on the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledX0xd {
    /// Absolute path to the `x0xd` executable.
    pub binary: PathBuf,
    /// Parsed version from `x0xd --version`.
    pub version: semver::Version,
}

/// Probe `$PATH` for an installed `x0xd` binary. Returns Some when
/// the executable is found AND `x0xd --version` parses as semver.
#[must_use]
pub fn discover_installed_x0xd() -> Option<InstalledX0xd> {
    let binary = which::which("x0xd").ok()?;
    let output = std::process::Command::new(&binary)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_str = stdout
        .lines()
        .next()?
        .split_whitespace()
        .last()?
        .trim_start_matches('v');
    let version = semver::Version::parse(version_str).ok()?;
    Some(InstalledX0xd { binary, version })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_returns_none_when_no_x0xd_on_path() {
        if std::env::var("FETCHIT_TEST_ASSERT_NO_X0XD").is_ok() {
            assert!(discover_installed_x0xd().is_none());
        }
    }

    #[test]
    fn parses_v_prefix_version() {
        let stdout = "x0xd v0.21.2\n";
        let line = stdout.lines().next().unwrap();
        let word = line
            .split_whitespace()
            .last()
            .unwrap()
            .trim_start_matches('v');
        let v = semver::Version::parse(word).unwrap();
        assert_eq!(v, semver::Version::parse("0.21.2").unwrap());
    }

    #[test]
    fn parses_no_prefix_version() {
        let stdout = "x0xd 0.21.2\n";
        let line = stdout.lines().next().unwrap();
        let word = line
            .split_whitespace()
            .last()
            .unwrap()
            .trim_start_matches('v');
        let v = semver::Version::parse(word).unwrap();
        assert_eq!(v, semver::Version::parse("0.21.2").unwrap());
    }
}
