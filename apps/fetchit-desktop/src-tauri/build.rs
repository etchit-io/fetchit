//! Tauri build script: stages the bundled x0xd binary and emits Tauri assets.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Pinned x0xd version we bundle. v0.27.0 carries ADR-0016 flat
/// Admin/Member group authority (retiring the creator-owner role), the
/// embeddable in-process serve entrypoint, and the `send_replace`
/// DM-capability fix. We bundle it via the `mobile-0.27` fork, which
/// layers the fetch>it tail onto that release: the gossip-isolated
/// group-join apply endpoints, the peer-relay DM fallback, and the
/// returning-member re-key fix (whose upstream bail is still present in
/// 0.27.0). Cross-NAT DM + 2-party group verified on 0.27, both legs.
const X0XD_PIN_VERSION: &str = "0.27.0";

/// Pinned commit: the `mobile-0.27` fork tip on josh-clsn/x0x (upstream
/// `v0.27.0` release lineage plus the fetch>it fork tail, now including the
/// read-only `GET /groups/:id/secure/self` keyed-epoch probe).
#[allow(dead_code)]
const X0XD_PIN_SHA: &str = "b19f8c171831c535f44b31d28e0f19b61469b813";

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
    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--bin")
        .arg("x0xd")
        .current_dir(&x0x_repo)
        .status();
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
