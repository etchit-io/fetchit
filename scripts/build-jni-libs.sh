#!/usr/bin/env bash
# Build fetchit-ffi for the Android ABIs the app supports and stage the
# resulting .so libraries where the Android Gradle build expects them.
#
# Used by:
#   - local development (run once after editing fetchit-ffi)
#   - .github/workflows/release.yml before gradle assembleRelease
#
# Requires:
#   - rustup toolchain (rust-toolchain.toml at the workspace root pins
#     the version)
#   - cargo-ndk: `cargo install cargo-ndk`
#   - Android NDK r27 (matches `ndkVersion` in app/build.gradle.kts).
#     Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT to its install path.

set -euo pipefail

# ── locate the workspace root from this script's location ────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"

JNI_DIR="$WORKSPACE/apps/fetchit-android/app/src/main/jniLibs"
FFI_CRATE_DIR="$WORKSPACE/crates/fetchit-ffi"

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
