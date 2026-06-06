#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::path::PathBuf;
use x0xd_client::InstalledX0xd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryChoice {
    /// Use the user's installed x0xd at this path / version.
    Installed {
        binary: PathBuf,
        version: semver::Version,
    },
    /// Spawn the fetch>it bundled x0xd at this path / version.
    Bundled {
        binary: PathBuf,
        version: semver::Version,
    },
}

/// Pick which binary the supervisor should spawn / point at.
///
/// Rule: prefer a system-wide install when it is at-or-above the
/// bundled version. Otherwise use bundled. If both are missing,
/// return None so the caller can surface the `X0xdVersionMismatch`
/// error from spec section 6.
#[must_use]
pub fn pick_binary(
    installed: Option<&InstalledX0xd>,
    bundled: Option<(PathBuf, semver::Version)>,
) -> Option<BinaryChoice> {
    match (installed, bundled) {
        (Some(i), Some((b_path, b_ver))) => {
            if i.version >= b_ver {
                Some(BinaryChoice::Installed {
                    binary: i.binary.clone(),
                    version: i.version.clone(),
                })
            } else {
                Some(BinaryChoice::Bundled {
                    binary: b_path,
                    version: b_ver,
                })
            }
        }
        (Some(i), None) => Some(BinaryChoice::Installed {
            binary: i.binary.clone(),
            version: i.version.clone(),
        }),
        (None, Some((b_path, b_ver))) => Some(BinaryChoice::Bundled {
            binary: b_path,
            version: b_ver,
        }),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    fn installed(path: &str, ver: &str) -> InstalledX0xd {
        InstalledX0xd {
            binary: PathBuf::from(path),
            version: v(ver),
        }
    }

    #[test]
    fn installed_preferred_when_at_or_above_bundled() {
        let i = installed("/usr/local/bin/x0xd", "0.21.3");
        let b = (PathBuf::from("/bundle/x0xd"), v("0.21.3"));
        assert_eq!(
            pick_binary(Some(&i), Some(b)),
            Some(BinaryChoice::Installed {
                binary: PathBuf::from("/usr/local/bin/x0xd"),
                version: v("0.21.3")
            }),
        );
    }

    #[test]
    fn bundled_chosen_when_installed_too_old() {
        let i = installed("/usr/local/bin/x0xd", "0.20.0");
        let b = (PathBuf::from("/bundle/x0xd"), v("0.21.3"));
        assert_eq!(
            pick_binary(Some(&i), Some(b)),
            Some(BinaryChoice::Bundled {
                binary: PathBuf::from("/bundle/x0xd"),
                version: v("0.21.3")
            }),
        );
    }

    #[test]
    fn bundled_chosen_when_installed_missing() {
        let b = (PathBuf::from("/bundle/x0xd"), v("0.21.3"));
        assert_eq!(
            pick_binary(None, Some(b)),
            Some(BinaryChoice::Bundled {
                binary: PathBuf::from("/bundle/x0xd"),
                version: v("0.21.3")
            }),
        );
    }

    #[test]
    fn installed_chosen_when_bundled_missing() {
        let i = installed("/usr/local/bin/x0xd", "0.21.2");
        assert_eq!(
            pick_binary(Some(&i), None),
            Some(BinaryChoice::Installed {
                binary: PathBuf::from("/usr/local/bin/x0xd"),
                version: v("0.21.2")
            }),
        );
    }

    #[test]
    fn none_when_both_missing() {
        assert_eq!(pick_binary(None, None), None);
    }
}
