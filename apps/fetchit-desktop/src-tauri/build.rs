//! Tauri build script: stages the bundled x0xd binary and emits Tauri assets.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Pinned x0xd version we bundle. v0.34.3 is the post-defork base: stock
/// upstream x0x 0.34.3 (which absorbed the 0.29-era fork tail — re-key,
/// actor-authz `committed_by`, `GET /secure/self`) plus the short engine-A
/// tail on the `engine-a-34` branch: relay-delivered group-join apply
/// endpoints for gossip-isolated peers and the TreeKEM join-retry
/// convergence fixes. The bundled daemon and the Android embed (fetchit-ffi
/// `x0x` git pin) move together on this rev.
const X0XD_PIN_VERSION: &str = "0.34.3";

/// Pinned commit on josh-clsn/x0x `engine-a-34`: upstream v0.34.3 plus the
/// engine-A tail (apply endpoints + join-result store, join-retry
/// convergence, parity-test defer, engine-A CLI subcommands) and the
/// leaf-mode tail (config flag + vendored saorsa-gossip-pubsub patch:
/// leaves stop relaying pass-through gossip — default OFF, so this
/// desktop bundle behaves byte-identically to stock; only the Android
/// embed opts in). Bump in lockstep with the workflow pins and the
/// fetchit-ffi `x0x` rev.
#[allow(dead_code)]
const X0XD_PIN_SHA: &str = "55b88459b95f120f5902a27bdf8a3268cda414e7";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FETCHIT_BUNDLED_X0XD_PATH");
    println!("cargo:rerun-if-env-changed=FETCHIT_BUNDLED_X0XD_VERSION");
    println!("cargo:rerun-if-env-changed=FETCHIT_X0X_REPO");

    stage_bundled_x0xd();

    tauri_build::build();
}

fn stage_bundled_x0xd() {
    let resources_dir = PathBuf::from("resources").join("x0xd");
    fs::create_dir_all(&resources_dir).expect("create resources/x0xd dir");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_dir = resources_dir.join(format!("{target_os}-{target_arch}"));
    fs::create_dir_all(&target_dir).expect("create per-target dir");
    let binary_name = if target_os == "windows" {
        "x0xd.exe"
    } else {
        "x0xd"
    };
    let binary_path = target_dir.join(binary_name);

    let src = if let Ok(path) = std::env::var("FETCHIT_BUNDLED_X0XD_PATH") {
        PathBuf::from(path)
    } else {
        build_locally_or_skip()
    };

    if !src.exists() {
        // Skip silently if no bundled binary is available; the runtime
        // supervisor falls through to discover_installed_x0xd.
        println!("cargo:warning=fetchit: no bundled x0xd available; skipping resource stage");
        let version = std::env::var("FETCHIT_BUNDLED_X0XD_VERSION")
            .unwrap_or_else(|_| X0XD_PIN_VERSION.to_owned());
        println!("cargo:rustc-env=FETCHIT_BUNDLED_X0XD_VERSION={version}");
        return;
    }

    fs::copy(&src, &binary_path).expect("copy bundled x0xd binary");

    let version = std::env::var("FETCHIT_BUNDLED_X0XD_VERSION")
        .unwrap_or_else(|_| X0XD_PIN_VERSION.to_owned());
    println!("cargo:rustc-env=FETCHIT_BUNDLED_X0XD_VERSION={version}");
    println!(
        "cargo:rustc-env=FETCHIT_BUNDLED_X0XD_PATH_REL=resources/x0xd/{target_os}-{target_arch}/{binary_name}"
    );
}

fn build_locally_or_skip() -> PathBuf {
    let Ok(x0x_repo) = std::env::var("FETCHIT_X0X_REPO") else {
        return PathBuf::new(); // empty path => doesn't exist
    };
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--release").arg("--bin").arg("x0xd");
    // jemalloc fixes glibc malloc arena/RSS amplification; enable it only on
    // glibc-Linux hosts (not musl/macOS/Windows/Android, where it is unneeded
    // or where jemalloc-sys does not build).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        cmd.arg("--features").arg("jemalloc");
    }
    let status = cmd.current_dir(&x0x_repo).status();
    let Ok(status) = status else {
        return PathBuf::new();
    };
    if !status.success() {
        return PathBuf::new();
    }
    PathBuf::from(&x0x_repo)
        .join("target")
        .join("release")
        .join("x0xd")
}
