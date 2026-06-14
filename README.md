# fetch>it

> *etch it. **fetch it.** chain it.*

A read-only viewer for content stored on the [Autonomi](https://autonomi.com)
network. Paste a 64-hex address, see what is there -- text, image, audio,
video, PDF, archive, code with syntax highlighting, JSON, CSV, full HTML
SPAs -- without installing a wallet, signing a message, or running a node.

fetch>it ships as a Rust engine (`fetchit-core`), a CLI, a uniffi FFI
surface (`fetchit-ffi`), chat/relay/fediverse/trust crates, and two
GUI shells over the engine: a native Android app and a Tauri 2 desktop
app. A thin browser extension routes `autonomi://` links into the
desktop app.

For end-user instructions -- every gesture, address-bar format, supported
content type, the `autonomi://` URL scheme, and honest limitations -- see
[`docs/USING.md`](docs/USING.md). For the Autonomi-native web protocol
(loading SPAs straight off the network, the synthetic-origin trick that
makes the full Fetch API work over content-addressed URLs), see
[`docs/AUTONOMI-WEB.md`](docs/AUTONOMI-WEB.md).

## Status

**Beta.** The Rust engine, the CLI, the Android shell, and the Tauri 2
desktop shell all build and run end-to-end against the live Autonomi
network. [`docs/USING.md`](docs/USING.md) is the end-user guide for the
Android app.

**Dual-licensed.** Open-source under [`AGPL-3.0-only`](LICENSE);
a commercial license is available for closed-source / proprietary use
(see [`COMMERCIAL.md`](COMMERCIAL.md)). Provided *as-is*, no warranty,
no liability -- see sections 15 & 16 of the AGPL.

## Layout

```
fetchit/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── fetchit-core/                # handler trait, registry, decoders
│   ├── fetchit-net/                 # Autonomi-backed NetworkClient
│   ├── fetchit-cli/                 # `fetchit get <addr>` binary
│   ├── fetchit-chat/                # chat protocol layer
│   ├── fetchit-fedi/                # fediverse bridge protocol
│   ├── fetchit-relay-proto/         # relay wire protocol
│   ├── fetchit-relay-server/        # relay server
│   ├── fetchit-relay-client/        # relay client
│   ├── fetchit-trust/               # trust service core
│   ├── fetchit-trust-types/         # trust type definitions
│   ├── fetchit-trust-client/        # trust service client
│   ├── x0xd-client/                 # x0xd discovery + signer
│   └── fetchit-ffi/                 # uniffi 0.29 bindings (workspace-excluded)
├── apps/
│   ├── fetchit-android/             # Material3 shell, sandboxed WebView, Media3
│   ├── fetchit-desktop/             # Tauri 2 shell -- TS/Vite frontend, Rust backend
│   ├── fetchit-web/                 # browser extension -- routes autonomi:// links
│   └── fetchit-bridge-worker/       # fediverse bridge Cloudflare Worker
├── docs/
│   ├── USING.md                     # end-user guide (Android)
│   ├── AUTONOMI-WEB.md              # autonomi:// scheme + SPA platform
│   ├── HANDLER-AUTHORS.md           # how to add a content handler
│   ├── SECURITY.md                  # threat model + sandbox architecture
│   ├── BRAND.md                     # design tokens shared with etch/it
│   └── QR-SHARE.md                  # QR address-sharing design spec
├── scripts/
│   └── build-jni-libs.sh            # cargo ndk → jniLibs/ for the Android build
├── .github/workflows/               # CI (fmt/clippy/test) + release (signed bundles)
├── CONTRIBUTING.md                  # DCO, quality bar
├── RELEASING.md                     # one-time keystore setup + per-release flow
└── LICENSE                          # AGPL-3.0-only (+ commercial -- see COMMERCIAL.md)
```

`fetchit-ffi` lives outside the main Cargo workspace by deliberate choice
-- `uniffi-bindgen` walks transitive deps and fails the metadata lookup
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

The desktop app (Tauri 2) builds straight from a workspace checkout:

```bash
cd apps/fetchit-desktop
npm install
npm run tauri dev                                   # dev shell
npm run tauri build                                 # platform bundle
```

For signed release builds, see [`RELEASING.md`](RELEASING.md).

## Security

Threat model, sandbox architecture, per-vector defenses, and pointers
to what's worth reading if you want to verify any of it yourself live
in [`docs/SECURITY.md`](docs/SECURITY.md). Vulnerabilities should be
reported privately via GitHub security advisories (see that doc for
the link), not as public issues.

## License

fetch>it is **dual-licensed**:

- [`AGPL-3.0-only`](LICENSE) for open-source / community use. Strong
  copyleft including the "network use" trigger -- if you run a modified
  version as a network service, the source must be available to its
  users.
- A separate **commercial license** for closed-source / proprietary
  embedding. See [`COMMERCIAL.md`](COMMERCIAL.md) for the option and
  contact path.

Either license stands alone -- you do not need both. Choose whichever
fits your use. Contributions are accepted under terms that allow the
project to offer both tracks; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Family

fetch>it is the **reader** half of a pair: [etch/it](https://etchit.io)
publishes content to Autonomi, fetch>it renders it. Same palette,
same fonts, same panel grammar. Anyone with the bytes can read; only
etch/it (or any compatible publisher) can write.
