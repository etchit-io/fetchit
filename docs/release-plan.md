# fetch>it release plan

Where each platform stands and what's left to ship. Companion document
to `docs/SECURITY.md` (what the user is trusting) and
`docs/USING.md` (what the user sees).

## Surfaces

| Surface | Source | Status |
|---|---|---|
| Linux desktop | `apps/fetchit-desktop` (Tauri 2) | Active development — branch `fetchit-desktop`. Builds + runs locally. Bundle targets: `.deb`, `.rpm`, AppImage. |
| macOS desktop | `apps/fetchit-desktop` (same code) | Untested host build — need a Mac. Bundle: `.app` / `.dmg`. |
| Windows desktop | `apps/fetchit-desktop` (same code) | Untested host build — need a Windows host. Bundle: `.msi` / `.exe`. |
| Android | `apps/fetchit-android` (Kotlin + uniffi FFI) | Shipping. Signed APK on `v*` tags via `release.yml`. |
| iOS | — | Not started. Plan: scaffold via Tauri 2's iOS target from `apps/fetchit-desktop`, same codebase. Defer until Mac is in hand. |
| Browser extension | `apps/fetchit-web` (Manifest V3) | Shipped (Chrome + Firefox via load-unpacked). Not yet on the Chrome Web Store / Firefox Add-ons. |

## Immediate ship order

1. **Mac + Windows desktop bring-up**. `npm run tauri build` on each host; verify the full feature set (load remote address, render every content type, settings panel, QR share, EPUB reader, deep-link OS scheme registration). Each is one session of polish per host.
2. **Tauri-iOS spike**. `tauri ios init` from `apps/fetchit-desktop/`, build a debug `.ipa`, sideload on iPhone (or use the simulator from the Mac dev host). The spike tests one question: does the in-WebView UX feel right? If yes, commit to the iOS path; if not, revisit.
3. **Desktop CI**. New workflow under `.github/workflows/`: fmt + clippy + `cargo test --workspace` + `vitest run` + `tsc --noEmit` on Linux / macOS / Windows. Mirror `ci.yml`'s structure.
4. **Signed releases**. Extend `release.yml` to also build desktop bundles on `v*` tags. Code signing: Apple Developer + Microsoft Trusted Signing (or `signtool` self-signed for first cuts). The Android keystore flow in `RELEASING.md` is the template.
5. **Browser-extension store listings** (Chrome Web Store + Firefox Add-ons). Lower priority — load-unpacked installs already work for technical users.

## Tauri-iOS — what we need before starting

Prereqs (one-time):
- macOS host with Xcode installed (Tauri's iOS toolchain shells out to `xcodebuild` and `xcrun`).
- Rust toolchain `aarch64-apple-ios` + `aarch64-apple-ios-sim` targets.
- Apple Developer Program enrollment ($99/yr) for device install + TestFlight. Not strictly needed for simulator-only testing.
- `cargo install tauri-cli@^2` (already a dev dep of fetchit-desktop).

Scaffold steps once on the Mac:
1. `cd apps/fetchit-desktop && cargo tauri ios init` — generates `src-tauri/gen/apple/`.
2. Edit `src-tauri/gen/apple/<ProductName>_iOS/Info.plist` to register the `autonomi://` and `fetchit://` URL schemes (parallel to the existing Android intent filter and the Linux `.desktop` registration).
3. `cargo tauri ios dev` — runs in the simulator.
4. `cargo tauri ios build` — produces a release IPA.

Expected friction:
- The custom URI scheme handler (`autonomi://`, `fetchit://`) is registered in `src-tauri/src/lib.rs` via `register_asynchronous_uri_scheme_protocol`. Tauri's iOS implementation supports this but is younger than the desktop path — verify it works before assuming.
- The local media server (`src-tauri/src/server.rs`) binds `127.0.0.1:<random>`. iOS App Transport Security blocks plain `http://` requests by default; need an exception entry in `Info.plist` for `localhost`. Without it, `<audio>` / `<video>` will fail to load.
- Deep-link plugin (`tauri-plugin-deep-link`) supports iOS but the OS registration goes through the Info.plist URL types, not the runtime call we use on Linux. Just config, no code change.

## What "shippable" means per platform

A platform release is shippable when:
- Full content-type sweep works (text, image, audio, video, PDF, EPUB, HTML, archive, JSON, CSV, code with highlighting, etchit envelope).
- OS-level scheme registration is in place (`autonomi://` opens the app).
- QR share-out modal opens and the address copies cleanly.
- Idle disconnect fires + cache clears (if configured).
- Settings panel reads and writes (theme picker on etchit, cache policy + bookmarks on fetchit).
- F12 devtools opens (release build retains the `devtools` feature deliberately).
- No console errors on a clean fetch of a known-good address.

Each platform's first release ships when its sweep passes, not when every platform's does — Mac can ship before Windows is verified.

## What's already done that we'd lose if we forgot

- Desktop sandbox hardening (CSP, neuter script, resource-hint strip, anchor-ping strip, meta-refresh strip — all in `htmlRewriter.ts`). See `docs/SECURITY.md` for the per-vector list.
- Disk cache with three clear modes (`Persist` / `OnClose` / `OnIdle`), off by default. `disk_cache.rs`.
- Bookmarks + inline rename + idle disconnect. `bookmarks.ts`, `idle.ts`, `settings.rs`.
- PDF rendering via pdf.js, hi-DPI canvas. `pdf.ts`.
- EPUB rendering with sandboxed chapter iframe + inlined images. `epub.ts`.
- Syntax-highlighted code rendering (11 languages, hand-rolled regex highlighters). `renderers/syntax/`.
- OS deep-link routing via `tauri-plugin-deep-link`. `lib.rs` setup callback.
- QR share-out modal with branded center glyph + standardised modal layout. `qrModal.ts` + `docs/QR-SHARE.md`.

All of the above is also tested — `npm run test` from `apps/fetchit-desktop/` should report ~185 vitest + clean `tsc --noEmit`.
