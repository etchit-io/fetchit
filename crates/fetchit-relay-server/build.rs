//! Bake the current git short SHA into the binary as
//! `FETCHIT_RELAY_GIT_SHORT`, so the relay's metrics `version` label can
//! be a deploy-unique `fetchit-relay-server/<semver>-<git-short>` string.
//!
//! Falls back to `unknown` when the build environment is not a git
//! checkout (release tarballs, vendored builds, sandboxed CI).

use std::process::Command;

fn main() {
    let short = git_short_sha().unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=FETCHIT_RELAY_GIT_SHORT={short}");

    if let Some(git_dir) = git_dir() {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        if let Some(ref_path) = active_ref_path(&git_dir) {
            println!("cargo:rerun-if-changed={ref_path}");
        }
    }
}

fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn git_dir() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn active_ref_path(git_dir: &str) -> Option<String> {
    let head = std::fs::read_to_string(format!("{git_dir}/HEAD")).ok()?;
    let head = head.trim();
    head.strip_prefix("ref: ").map(|r| format!("{git_dir}/{r}"))
}
