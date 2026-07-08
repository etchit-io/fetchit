#!/usr/bin/env bash
# Verify Cargo.lock + Cargo.toml + settings.rs match PINS.md.
# Used by CI; safe to run locally.
#
# Exit codes:
#   0 — all pins match
#   1 — drift detected; PINS.md is the source of truth

set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
    echo "PINS DRIFT: $1" >&2
    exit 1
}

ok() {
    echo "  ok: $1"
}

echo "checking pinned deps against PINS.md..."

# ant-core: rev = "95a23be"
grep -q 'ant-core.*rev = "95a23be"' Cargo.toml \
    || fail "Cargo.toml ant-core rev != 95a23be"
grep -q 'github.com/WithAutonomi/ant-client?rev=95a23be' Cargo.lock \
    || fail "Cargo.lock ant-core rev != 95a23be"
ok "ant-core rev=95a23be"

# ant-core in the workspace-EXCLUDED fetchit-ffi crate: it keeps its OWN
# Cargo.lock, which a root `cargo update` does NOT touch, so a root ant-core
# bump can silently leave the APK linking a stale ant-core. Assert it here too.
grep -q 'github.com/WithAutonomi/ant-client?rev=95a23be' crates/fetchit-ffi/Cargo.lock \
    || fail "crates/fetchit-ffi/Cargo.lock ant-core rev != 95a23be (excluded-crate lock drift)"
ok "ant-core rev=95a23be (fetchit-ffi excluded lock)"

# self_encryption: =0.36.0
grep -q 'self_encryption = "=0.36.0"' Cargo.toml \
    || fail "Cargo.toml self_encryption != =0.36.0"
ok "self_encryption =0.36.0"

# xor_name: =5.0.0
grep -q 'xor_name = "=5.0.0"' Cargo.toml \
    || fail "Cargo.toml xor_name != =5.0.0"
ok "xor_name =5.0.0"

# saorsa-pqc: workspace pin is "0.5"; lock should resolve to 0.5.x
grep -q 'saorsa-pqc = "0.5"' Cargo.toml \
    || fail "Cargo.toml saorsa-pqc != 0.5"
grep -A1 '^name = "saorsa-pqc"$' Cargo.lock | grep -q 'version = "0.5' \
    || fail "Cargo.lock saorsa-pqc not 0.5.x"
ok "saorsa-pqc 0.5.x"

# uniffi (workspace-excluded crates/fetchit-ffi): =0.29.5
grep -q 'uniffi = { version = "=0.29.5"' crates/fetchit-ffi/Cargo.toml \
    || fail "crates/fetchit-ffi/Cargo.toml uniffi != =0.29.5"
ok "uniffi =0.29.5 (fetchit-ffi)"

# four-word-networking: =2.7.0 (word rendering must match x0x tooling)
grep -q 'four-word-networking = "=2.7.0"' Cargo.toml \
    || fail "Cargo.toml four-word-networking != =2.7.0"
ok "four-word-networking =2.7.0"

# Relay region defaults
SETTINGS=apps/fetchit-desktop/src-tauri/src/settings.rs
grep -q '67.207.94.66:8088' "$SETTINGS" \
    || fail "$SETTINGS missing NYC default 67.207.94.66:8088"
grep -q '159.89.11.217:8088' "$SETTINGS" \
    || fail "$SETTINGS missing FRA default 159.89.11.217:8088"
ok "KNOWN_RELAYS NYC + FRA defaults"

echo "all pins green."
