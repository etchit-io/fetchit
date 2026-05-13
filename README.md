# fetch>it

> *etch it. **fetch it.** chain it.*

A read-only viewer for content stored on the [Autonomi](https://autonomi.com)
network. Paste a 64-hex address, see what is there — text, image, audio,
video, PDF, archive, code with syntax highlighting, JSON, CSV, full HTML
SPAs — without installing a wallet, signing a message, or running a node.

fetch>it ships as a small Rust engine (`fetchit-core`), a CLI (`fetchit
get <addr>`), a uniffi FFI surface (`fetchit-ffi`), and a native Android
shell that gives the engine a touch UI.

For end-user instructions — every gesture, address-bar format, supported
content type, the `autonomi://` URL scheme, and honest limitations — see
[`docs/USING.md`](docs/USING.md). For the Autonomi-native web protocol
(loading SPAs straight off the network, the synthetic-origin trick that
makes the full Fetch API work over content-addressed URLs), see
[`docs/AUTONOMI-WEB.md`](docs/AUTONOMI-WEB.md).

## Status

`0.2.0`. The Android shell builds and runs end-to-end against the live
Autonomi network — the [`docs/USING.md`](docs/USING.md) guide describes
what it currently does. CLI compiles.

## Layout

```
fetchit/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── fetchit-core/                # handler trait, registry, decoders
│   ├── fetchit-net/                 # Autonomi-backed NetworkClient
│   ├── fetchit-cli/                 # `fetchit get <addr>` binary
│   └── fetchit-ffi/                 # uniffi 0.29 bindings (workspace-excluded)
├── apps/
│   └── fetchit-android/             # Material3 shell, sandboxed WebView, Media3
├── docs/
│   ├── USING.md                     # end-user guide
│   ├── AUTONOMI-WEB.md              # autonomi:// scheme + SPA platform
│   └── HANDLER-AUTHORS.md           # how to add a content handler
├── scripts/
│   └── build-jni-libs.sh            # cargo ndk → jniLibs/ for the Android build
├── .github/workflows/               # CI (fmt/clippy/test) + release (signed APK)
├── CONTRIBUTING.md                  # DCO, quality bar
├── RELEASING.md                     # one-time keystore setup + per-release flow
└── LICENSE                          # GPL-3.0-only
```

`fetchit-ffi` lives outside the main Cargo workspace by deliberate choice
— `uniffi-bindgen` walks transitive deps and fails the metadata lookup
silently inside multi-crate workspaces.

## Building

The Rust workspace is the boring case:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The Android app needs the FFI library compiled for the device's ABI
first:

```bash
./scripts/build-jni-libs.sh                         # cargo ndk → jniLibs/
cd apps/fetchit-android
./gradlew :app:assembleDebug                        # debug-signed APK
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

For signed release builds, see [`RELEASING.md`](RELEASING.md).

## License

[`GPL-3.0-only`](LICENSE) across the workspace. fetch>it ships as
free software with strong copyleft. Embedding into closed-source
applications via direct linking is not supported — use the CLI, the
Android intent surface, or (when it lands) the WASM build via process-
boundary integration.

## Family

fetch>it is the **reader** half of a pair: [etch/it](https://etchit.io)
publishes content to Autonomi, fetch>it renders it. Same palette,
same fonts, same panel grammar. Anyone with the bytes can read; only
etch/it (or any compatible publisher) can write.
