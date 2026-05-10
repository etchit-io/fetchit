//! Smoke tests for the `fetchit` CLI binary. Each test writes a small
//! fixture to a temp file and asserts the headline output. The point
//! is to lock in the user-facing contract — exit codes, the `kind:`
//! header, the rendition selection — not to reproduce handler-level
//! coverage (which lives in `fetchit-core`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::NamedTempFile;

fn fixture(bytes: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp file");
    f.write_all(bytes).expect("write fixture");
    f
}

#[test]
fn detects_etchit_envelope() {
    let f = fixture(br#"{"v":1,"meta":{"title":"hi","lang":""},"content":"hello"}"#);
    Command::cargo_bin("fetchit")
        .expect("binary built")
        .args(["detect", f.path().to_str().expect("path")])
        .assert()
        .success()
        .stdout(contains("kind: etchit/envelope-v1"))
        .stdout(contains("title: hi"));
}

#[test]
fn detects_png_image() {
    let mut data: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    data.extend_from_slice(b"...not-a-real-png-but-magic-is-enough...");
    let f = fixture(&data);
    Command::cargo_bin("fetchit")
        .expect("binary built")
        .args(["detect", f.path().to_str().expect("path")])
        .assert()
        .success()
        .stdout(contains("kind: image/png"));
}

#[test]
fn detects_plain_text() {
    let f = fixture(b"hello, world\n");
    Command::cargo_bin("fetchit")
        .expect("binary built")
        .args(["detect", f.path().to_str().expect("path")])
        .assert()
        .success()
        .stdout(contains("kind: text/plain"))
        .stdout(contains("hello, world"));
}

#[test]
fn get_with_invalid_addr_errors_before_network() {
    // Address parsing runs before any network setup, so bad addresses
    // fail fast without waiting on bootstrap.
    Command::cargo_bin("fetchit")
        .expect("binary built")
        .args(["get", "not-an-address"])
        .assert()
        .code(1)
        .stderr(contains("invalid Autonomi address"));
}

#[test]
fn get_with_unparseable_peer_fails_at_connect() {
    // Bogus --peer entries are rejected by ant-core's MultiAddr parser
    // at connect time, so this exercises the connect error path
    // without making a real network attempt.
    let addr = "0".repeat(64);
    Command::cargo_bin("fetchit")
        .expect("binary built")
        .args(["get", &addr, "--peer", "definitely-not-a-multiaddr"])
        .assert()
        .code(1)
        .stderr(contains("connect failed"));
}

#[test]
fn detect_missing_file_errors() {
    Command::cargo_bin("fetchit")
        .expect("binary built")
        .args(["detect", "/no/such/file/anywhere"])
        .assert()
        .code(1);
}
