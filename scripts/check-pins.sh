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

# ant-core: rev = "bcab72ae7"
grep -q 'ant-core.*rev = "bcab72ae7"' Cargo.toml \
    || fail "Cargo.toml ant-core rev != bcab72ae7"
grep -q 'github.com/WithAutonomi/ant-client?rev=bcab72ae7' Cargo.lock \
    || fail "Cargo.lock ant-core rev != bcab72ae7"
ok "ant-core rev=bcab72ae7"

# ant-core in the workspace-EXCLUDED fetchit-ffi crate: it keeps its OWN
# Cargo.lock, which a root `cargo update` does NOT touch, so a root ant-core
# bump can silently leave the APK linking a stale ant-core. Assert it here too.
grep -q 'github.com/WithAutonomi/ant-client?rev=bcab72ae7' crates/fetchit-ffi/Cargo.lock \
    || fail "crates/fetchit-ffi/Cargo.lock ant-core rev != bcab72ae7 (excluded-crate lock drift)"
ok "ant-core rev=bcab72ae7 (fetchit-ffi excluded lock)"

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

# Relay region defaults: NYC is the sole live region (FRA decommissioned
# 2026-07). The retired bare-IP rows must survive ONLY in the frozen
# migration/healing tables, never re-enter the live KNOWN_RELAYS directory.
SETTINGS=apps/fetchit-desktop/src-tauri/src/settings.rs
grep -q 'nyc-relay.etchit.io' "$SETTINGS" \
    || fail "$SETTINGS missing NYC default nyc-relay.etchit.io"
grep -q '67.207.94.66:8088' "$SETTINGS" \
    || fail "$SETTINGS lost the NYC bare-IP healing entry (RELAY_URL_MIGRATIONS)"
grep -q '159.89.11.217:8088' "$SETTINGS" \
    || fail "$SETTINGS lost the FRA bare-IP healing entry (RELAY_URL_MIGRATIONS)"
if grep -q 'tag: "fra"' "$SETTINGS"; then
    fail "$SETTINGS re-lists retired FRA in KNOWN_RELAYS"
fi
ok "relay defaults (NYC live; FRA heal-only)"

# Bundled-x0xd pin lockstep: build.rs is the source of truth; both
# workflow files must carry the identical sha and version (a drift here
# ships a mislabeled daemon inside released bundles).
BUILD_RS=apps/fetchit-desktop/src-tauri/build.rs
X0XD_SHA=$(grep -oE 'X0XD_PIN_SHA: &str = "[0-9a-f]{40}"' "$BUILD_RS" | grep -oE '[0-9a-f]{40}')
[ -n "$X0XD_SHA" ] || fail "$BUILD_RS X0XD_PIN_SHA const not found"
grep -q "X0XD_PIN_SHA: \"$X0XD_SHA\"" .github/workflows/release.yml \
    || fail "release.yml X0XD_PIN_SHA != build.rs ($X0XD_SHA)"
grep -q "X0XD_PIN_SHA: \"$X0XD_SHA\"" .github/workflows/bundled-x0xd.yml \
    || fail "bundled-x0xd.yml X0XD_PIN_SHA != build.rs ($X0XD_SHA)"
X0XD_VER=$(grep -oE 'X0XD_PIN_VERSION: &str = "[^"]+"' "$BUILD_RS" | cut -d'"' -f2)
[ -n "$X0XD_VER" ] || fail "$BUILD_RS X0XD_PIN_VERSION const not found"
grep -q "X0XD_PIN_VERSION: \"$X0XD_VER\"" .github/workflows/release.yml \
    || fail "release.yml X0XD_PIN_VERSION != build.rs ($X0XD_VER)"
grep -q "FETCHIT_BUNDLED_X0XD_VERSION: \"$X0XD_VER\"" .github/workflows/bundled-x0xd.yml \
    || fail "bundled-x0xd.yml FETCHIT_BUNDLED_X0XD_VERSION != build.rs ($X0XD_VER)"
ok "x0xd pin lockstep (build.rs == workflows @ ${X0XD_SHA:0:7} / $X0XD_VER)"

# PINS.md x0xd row must match build.rs too. This was the one leg the
# lockstep above missed: build.rs and the workflows were locked to each
# other while PINS.md said v0.27.0 for weeks after the 0.29.0 flip —
# exactly the silent doc drift this script exists to prevent.
grep -q "| \`x0xd\`.*\`$X0XD_VER\`" PINS.md \
    || fail "PINS.md x0xd version != build.rs ($X0XD_VER)"
grep -q "| \`x0xd\`.*$X0XD_SHA" PINS.md \
    || fail "PINS.md x0xd fork sha != build.rs ($X0XD_SHA)"
ok "x0xd PINS.md row matches build.rs ($X0XD_VER @ ${X0XD_SHA:0:7})"

echo "all pins green."
