# Testing fetch>it

fetch>it gates every push and pull request on `cargo fmt`, `cargo
clippy`, and `cargo test` — green on Linux, macOS, and Windows — plus
the per-app suites below. This is the full picture: what to run, and
what each suite needs.

## Prerequisites

Always needed:

- **Rust** (stable, via rustup) — the engine, the CLI, and their tests.
- **Node 20+ and npm** — the desktop app and the web extension.

Per-app, only if you touch that app:

- **JDK 17, the Android SDK, and NDK r27** — the Android app and the FFI.
- **`cargo-ndk`** and **`uniffi-bindgen-cli`** (its version must match
  `uniffi` in `crates/fetchit-ffi/Cargo.toml`) — the Android native build.

Optional, for the heavier test tiers:

- **`tauri-driver`** (`cargo install tauri-driver --version 2.0.6 --locked`), **`WebKitWebDriver`**
  (apt package `webkit2gtk-driver`), and an **X server** (`xvfb` when
  headless) — the desktop end-to-end suite.
- **`anvil`** (Foundry) and **`ant`** (the WithAutonomi CLI) — the
  local-devnet integration test.

## The Rust engine — from the repo root

Covers all 12 workspace crates (`fetchit-core`, `fetchit-net`, `fetchit-cli`, `fetchit-chat`, `fetchit-fedi`, `fetchit-relay-proto`, `fetchit-relay-server`, `fetchit-relay-client`, `fetchit-trust`, `fetchit-trust-types`, `fetchit-trust-client`, `x0xd-client`):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p fetchit-core <name>      # one test by name substring
```

`crates/fetchit-ffi` and `apps/fetchit-desktop/src-tauri` are `exclude`d
from the workspace — a root `cargo test` does not touch them. Each is
tested from its own directory (below).

## The desktop app — `apps/fetchit-desktop`

```bash
npm install
npm run test:run                 # vitest — the TS/Vite frontend
npm run test:run -- <name>       # one frontend test file
(cd src-tauri && cargo test)     # the Tauri (Rust) backend
```

End-to-end, driving the built app through `tauri-driver`:

```bash
npm run e2e
```

The E2E suite needs `tauri-driver`, `WebKitWebDriver`, and a display
(`xvfb-run npm run e2e` when headless). Linux/Windows only — `tauri-driver`
has no macOS support. `wdio.conf.mjs`'s `onPrepare` hook builds the debug
binary with the `e2e` Cargo feature, which serves fixture content instead
of fetching from the network, so the suite is deterministic and offline.

## The Android app — `apps/fetchit-android`

```bash
./gradlew :app:testDebugUnitTest                       # JUnit + Robolectric
./gradlew :app:testDebugUnitTest --tests "*SomeTest*"  # one test class
./gradlew :app:assembleDebug                           # the debug APK
```

The unit suite — pure-logic tests plus Robolectric Activity tests —
needs no device or emulator. The native `fetchit_ffi` library is built
separately: `scripts/build-jni-libs.sh` runs cargo-ndk and regenerates
the Kotlin binding (the two must stay in lockstep or the app crashes at
launch).

## The FFI crate — `crates/fetchit-ffi`

```bash
cargo test --manifest-path crates/fetchit-ffi/Cargo.toml
```

Workspace-`exclude`d, so the root `cargo test` skips it. The full
Android `.so` + Kotlin-binding build is `scripts/build-jni-libs.sh`.

## The web extension — `apps/fetchit-web`

```bash
node --test apps/fetchit-web/test/addr.test.mjs
```

No dependencies. The extension's address parser must stay byte-for-byte
compatible with the desktop app's; this is what catches drift.

## Network-test tiers

The fetch path is tested at three levels:

1. **Mock** — `MockClient` in `fetchit-core`. Free and instant; part of
   `cargo test --workspace`.
2. **Local devnet** — an in-process Autonomi network. The `ant` CLI
   publishes a fixture; fetch>it fetches and renders it. Gated behind a
   feature and `#[ignore]`d:

   ```bash
   cargo test -p fetchit-net --test devnet --features devnet-tests \
     -- --ignored --nocapture
   ```

   Needs `anvil` and `ant` on `PATH`.
3. **Live network** — a smoke check against a real address:

   ```bash
   FETCHIT_LIVE_ADDR=<64-hex> cargo test -p fetchit-net --test live \
     -- --ignored --nocapture
   ```

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request: `fmt`, `clippy`, and `cargo test` (Linux + macOS + Windows);
the desktop suites (vitest + src-tauri) and the desktop E2E; the
web-extension parser tests; and the Android job (unit tests + a
debug-APK build + the FFI host tests). The local-devnet and live tiers
are not in CI — run them locally before a release.
