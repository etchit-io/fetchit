# fetch&gt;it desktop

A Tauri 2 desktop shell around `fetchit-core` + `fetchit-net`. Paste a
64-hex Autonomi address, see what's there — text, image, audio, video,
PDF, EPUB, archive index, JSON, CSV, code with syntax highlighting,
full HTML SPAs — without leaving the local network and the Autonomi
peers.

Vanilla TypeScript frontend (Vite + vitest), Rust backend, system
WebView. Two custom URI schemes (`fetchit://` and `autonomi://`) plus
a `127.0.0.1` media server are wired in `src-tauri/src/lib.rs` and
resolve every request through the connected `AutonomiClient`.

## Build

The Tauri backend depends on `fetchit-core` and `fetchit-net` via path,
so a checkout of the workspace is enough.

```bash
npm install
npm run tauri dev       # dev shell against the live network
npm run tauri build     # bundle (.deb / .rpm / AppImage / .app / .dmg / .msi)
```

## Test

```bash
npm test                            # vitest watch
npm run test:run                    # vitest, one-shot
(cd src-tauri && cargo test)        # backend tests
```

Frontend tests run under jsdom (`vitest.config.ts`). The desktop crate
is excluded from the workspace, so root-level `cargo` invocations do
not touch it — test from inside `src-tauri/`.

## Layout

- `src/` — TypeScript frontend: `controller.ts` is the entry point,
  `renderers/` mirrors `fetchit-core`'s handler set in TS, `ui/` holds
  the address bar, tab strip, settings panel, QR modal, and keyboard
  bindings. `renderers/htmlRewriter.ts` is the security boundary: CSP
  construction, resource-hint stripping, API neutering — see
  [`../../docs/SECURITY.md`](../../docs/SECURITY.md).
- `src-tauri/` — Rust backend: protocol handlers, the localhost media
  server, in-memory + opt-in on-disk byte cache, settings persistence.
- `index.html` — minimal shell loaded by Vite at `localhost:1420` in
  dev and bundled into the app at build time.
- `tauri.conf.json` — bundle identifier, window config, deep-link
  scheme registration (`autonomi`, `fetchit`).
