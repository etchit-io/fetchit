#!/usr/bin/env bash
# Build fetchit-ffi for the Android ABIs the app supports, stage the
# resulting .so libraries where the Gradle build expects them, AND
# regenerate the matching uniffi Kotlin bindings.
#
# The .so embeds uniffi API checksums; the generated `fetchit_ffi.kt`
# verifies them at startup (`uniffiCheckApiChecksums`). If you rebuild
# one without the other they go out of sync and the app crashes on
# launch with "UniFFI API checksum mismatch". This script does both so
# they can't drift.
#
# Used by:
#   - local development (run once after editing fetchit-ffi)
#   - .github/workflows/release.yml before gradle assembleRelease
#
# Requires:
#   - rustup toolchain (rust-toolchain.toml at the workspace root pins
#     the version)
#   - cargo-ndk: `cargo install cargo-ndk`
#   - uniffi-bindgen, matching `uniffi` in crates/fetchit-ffi/Cargo.toml:
#     `cargo install uniffi-bindgen-cli --git https://github.com/mozilla/uniffi-rs --tag v0.29.4`
#   - Android NDK r27 (matches `ndkVersion` in app/build.gradle.kts).
#     Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT to its install path.

set -euo pipefail

# ── locate the workspace root from this script's location ────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"

JNI_DIR="$WORKSPACE/apps/fetchit-android/app/src/main/jniLibs"
FFI_CRATE_DIR="$WORKSPACE/crates/fetchit-ffi"
# uniffi writes <out-dir>/uniffi/fetchit_ffi/fetchit_ffi.kt under here:
KOTLIN_SRC_DIR="$WORKSPACE/apps/fetchit-android/app/src/main/java"

# Rust target triples → Android ABI directory names.
# arm64 only — abiFilters in app/build.gradle.kts matches. x86_64 is
# for emulators and would roughly double the APK size for no real-
# device benefit.
declare -a TARGETS=(aarch64-linux-android)
declare -a ABIS=(arm64-v8a)

# Ensure Rust targets are installed.
for t in "${TARGETS[@]}"; do
  rustup target add "$t" >/dev/null
done

echo "Building fetchit-ffi (release) for ${ABIS[*]}…"
(
  cd "$FFI_CRATE_DIR"
  cargo ndk -t arm64-v8a -o "$JNI_DIR" build --release
)

echo
echo "Staged libraries:"
for abi in "${ABIS[@]}"; do
  so="$JNI_DIR/$abi/libfetchit_ffi.so"
  if [[ -f "$so" ]]; then
    size=$(du -h "$so" | cut -f1)
    printf "  %-12s %s  (%s)\n" "$abi" "$so" "$size"
  else
    echo "  $abi  MISSING ($so)" >&2
    exit 1
  fi
done

# ── regenerate the matching uniffi Kotlin bindings ───────────────────
# Library mode: bindgen reads the uniffi metadata embedded in the .so
# (cross-target is fine — it parses the object, doesn't execute it), so
# the generated `fetchit_ffi.kt` carries exactly the checksums this .so
# expects. This sidesteps the multi-crate-workspace metadata-lookup bug
# that bites bindgen's source-tree mode.
if ! command -v uniffi-bindgen >/dev/null 2>&1; then
  echo "error: uniffi-bindgen not found." >&2
  echo "       install it (version must match \`uniffi\` in crates/fetchit-ffi/Cargo.toml):" >&2
  echo "         cargo install uniffi-bindgen-cli --git https://github.com/mozilla/uniffi-rs --tag v0.29.4" >&2
  exit 1
fi
echo
echo "Regenerating uniffi Kotlin bindings…"
uniffi-bindgen generate \
  --library "$JNI_DIR/arm64-v8a/libfetchit_ffi.so" \
  --language kotlin \
  --out-dir "$KOTLIN_SRC_DIR" \
  --no-format
echo "  -> $KOTLIN_SRC_DIR/uniffi/fetchit_ffi/fetchit_ffi.kt"
