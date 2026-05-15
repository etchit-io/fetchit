# Third-Party Licenses

fetch>it is dual-licensed under AGPL-3.0-only and a separate commercial
license (see `COMMERCIAL.md`). It builds on, and ships, the following
open-source work. This lists the significant components; the full transitive
dependency set and exact license texts are in `Cargo.lock` (Rust) and
the resolved Gradle dependency tree (Android), and in each project's own
LICENSE.

## Autonomi network stack
- **ant-core / ant-client** — GPL-3.0 — https://github.com/WithAutonomi/ant-client — fetch>it's networking is built directly on this (`crates/fetchit-net`).
- **ant-node**, **evmlib**, and the rest of the Autonomi crates — GPL-3.0 — https://github.com/WithAutonomi — pulled in transitively via ant-client.
- **saorsa-core** — AGPL-3.0 — https://github.com/saorsa-labs/saorsa-core — transitive via the Autonomi node stack; not a direct dependency.
- **self_encryption** — MaidSafe — https://github.com/maidsafe/self_encryption — Autonomi's content-addressed chunk encryption (see the crate's LICENSE for terms).

## Rust ecosystem (direct deps)
- **uniffi** — MPL-2.0 — Mozilla — the Rust↔Kotlin FFI layer (`crates/fetchit-ffi`).
- **tokio**, **bytes**, **async-trait**, **thiserror**, **anyhow**, **serde_json**, **hex**, **log** — MIT (or MIT/Apache-2.0 dual) — the usual Rust building blocks.
- **clap** — MIT/Apache-2.0 — the CLI viewer's argument parsing.
- **android_logger** — MIT/Apache-2.0 — routes Rust `log` to Android logcat.

## Android app
- **Android WebView / Chromium** — BSD-3-Clause (and others) — the system component fetch>it uses to render HTML pages fetched from Autonomi. Part of the platform; not bundled.
- **AndroidX** — appcompat, core-ktx, activity-ktx, fragment-ktx, lifecycle (runtime + process), constraintlayout, recyclerview, swiperefreshlayout — Apache-2.0 — https://developer.android.com/jetpack
- **AndroidX Media3 / ExoPlayer** — media3-exoplayer, media3-ui, media3-datasource — Apache-2.0 — audio/video playback.
- **Material Components for Android** — Apache-2.0.
- **Kotlin Coroutines** (`kotlinx-coroutines-android`) — Apache-2.0 — JetBrains.
- **Markwon** (`io.noties.markwon:core`) — Apache-2.0 — Markdown rendering.
- **ZXing** (`com.google.zxing:core`) and **ZXing Android Embedded** (`com.journeyapps:zxing-android-embedded`) — Apache-2.0 — QR generation + scanning.
- **JNA** (`net.java.dev.jna:jna`) — Apache-2.0 / LGPL-2.1 (dual) — calls the native `libfetchit_ffi.so`.

## Fonts (the etchit.io site & the demo-city pages — not bundled in the APK)
- **JetBrains Mono**, **Instrument Serif**, **EB Garamond** — SIL Open Font License 1.1 — served via Google Fonts.

## demo-city content (not part of fetch>it itself)
The `demo-city` site published to Autonomi uses only public-domain / CC0
material — NASA/ESA/STScI imagery, Kimiko Ishizaka's "Open" Bach
recordings (CC0), Project Gutenberg text, NASA video — each credited on
the page that uses it.
