# fetch/it — spec for the new Claude session

> *etch it. **fetch it.** chain it.*

You (Claude) are starting a new project, **fetch/it**, alongside the
existing etchit family of clients. The author's framing: *"the ffmpeg of
Autonomi."* That phrase carries weight — read it as **a universal,
modular, embeddable read-only viewer for any content stored on the
Autonomi network, not a one-shot UI app.**

The author has explicitly asked that fetch/it be **a separate clean
project**, not built on top of etchit's codebase. You will *reference*
etchit but not copy from it. Resist the urge to fork.

---

## 1. Mission

fetch/it lets anyone paste an Autonomi address and see what's there —
text, image, audio, video, PDF, archive, code with syntax highlighting,
JSON, CSV, anything — without installing a wallet, signing a message,
or running a node. Read-only by design.

Think of three layers:

1. **`fetchit-core` (Rust library)** — fetches data from the Autonomi
   network given an address; identifies content type; exposes typed
   decoders. The "libavcodec" of fetch/it.
2. **`fetchit` (CLI)** — `fetchit get <addr>` style. Inspects, dumps,
   converts. The "ffmpeg" of fetch/it.
3. **GUI surfaces** — Android first (native Kotlin + uniffi, matching
   etchit-android), then desktop (Tauri 2) later. Web (WASM) and iOS
   are downstream possibilities. All shells are thin layers over
   `fetchit-core`. The "VLC" of fetch/it.

Anyone (etchit, third-party Autonomi apps, embedded systems) should be
able to depend on `fetchit-core` and get content-type detection and
rendering for free.

## 2. Brand and naming

Brand sits in the `/it` family: `etch/it`, **`fetch/it`**, `chain/it`.
Logos use the same monospace + copper-on-ink palette.

| Token | Hex |
| --- | --- |
| COPPER | `#c9732b` |
| COPPER_BRIGHT | `#e58a3f` |
| BONE | `#f5f2eb` |
| BONE_DIM | `#d6cfc0` |
| ASH | `#8a8a8a` |
| INK (background) | `#0a0a0a` |
| INK_2 | `#141414` |
| INK_3 | `#1a1a1a` |
| SIGNAL_OK | `#6ab04c` |

Don't reinvent the visual language. Match etchit and the website at
etchit.io. The user values consistency across the /it family — fetch/it
should *feel* like part of the same product line at first glance.

Specifically, that means:

- **Same fonts**: JetBrains Mono for code/monospace, Instrument Serif
  for occasional italic accents (matches etchit's hero copy).
- **Same panel grammar**: dark `INK` background, `INK_2` cards with a
  1px `#1f1f1f` border and 6px corner radius. Copper for primary
  actions, bone for body text, ash for secondary metadata.
- **Same status patterns**: top bar with network indicator on the
  left, address/wallet zone on the right, identical to etchit's
  layout.

### UX principle: maximum screen for content

fetch/it is a viewer. The chrome — address bar, network status,
bookmark controls — should be **as small as possible** so the fetched
content gets the rest. Concretely:

- **One-line top bar** with the address input (collapses to a chevron
  when content is loaded, leaving a thin status strip).
- **Edge-to-edge content area**. No padding-heavy cards around the
  main rendition. Images render to the available width; text fills
  the viewport; PDFs and video go fullscreen by default with overlaid
  controls that fade out.
- **Bookmark drawer slides in from the side, doesn't pin open**. The
  default state is content-only after fetch.
- **No persistent bottom nav, no left rail**. Mobile Android will use
  a single fragment with the address input and a slide-up bookmark
  sheet, not a bottom nav bar.

## 3. Hard constraints (what fetch/it is NOT)

- **Not a wallet client.** No Reown / WalletConnect. No signing. No
  payments. No private etches. No backups.
- **Not a writer.** No upload paths, no `chunk_put`, no `data_put_*`.
  fetch/it never asks for ANT, never calls `wallet_*`, never modifies
  network state.
- **Not chain/it-aware.** chain/it is etchit's encrypted on-chain index,
  scoped to a wallet. fetch/it doesn't connect a wallet, so it cannot
  decrypt chainmarks. Decoupled by design.
- **Not a content cache.** fetch/it never persists fetched content to
  disk. Bytes come down from the network, get rendered into a typed
  `Rendition`, and live in memory only. Close the app or fetch a new
  address and the previous content is gone. The only on-device state
  is bookmark labels (see §3a).
- **Not a fork of etchit.** Don't `cp -r` etchit and prune. Build the
  Cargo workspace fresh. The temptation to copy will be strong because
  you have a working reference; resist.

## 3a. Bookmarks — the *only* persisted user data

fetch/it lets the user save addresses with custom names so they can
revisit content without re-pasting 64 hex chars. **This is the only
local state the app keeps.** Not history, not view counts, not
thumbnails — just (label, address) pairs.

**Spec for the bookmark feature:**

- **Schema:** `{ id, label: String, address: 64-hex, addedAt: timestamp,
  kind?: "auto-detected-content-type-from-first-fetch" }`. Nothing else.
  No tags, no folders, no notes (yet — could come later, ask first).
- **Storage:** Android `SharedPreferences` (or `EncryptedSharedPreferences`
  if you want belt-and-braces; not strictly necessary since addresses are
  public). Desktop later: a single JSON file under the OS app-data dir.
- **No automatic bookmarking on fetch.** Fetching an address does NOT
  add it to bookmarks. The user must explicitly tap the bookmark icon
  (think browser ⭐ pattern). Otherwise the "history" question creeps
  back in.
- **Custom labels are required, not optional.** When the user taps
  bookmark, the rename modal opens immediately with a sensible default
  (the etch's title from the envelope, or `address[:8]…`). Empty
  string is rejected. This avoids the "row 47, address 4eb6…" UX
  failure mode.
- **Export / import is in scope** — JSON file, share intent on Android.
  Lets users move bookmarks between devices without fetch/it itself
  becoming a sync engine.
- **No remote sync, no chain/it integration, no wallet — ever.**
  fetch/it is permanently wallet-less; that's a defining property, not
  a 0.1.0 limit. Cross-device bookmarks live in the user's hands
  (export/import). chain/it is etchit's job, full stop. If a feature
  proposal requires connecting a wallet, it doesn't belong in fetch/it
  — point it at etchit instead.

The bookmark drawer and the address input are the *only* navigation
chrome. Everything else is content area.

## 4. Architecture principles

- **Library-first.** `fetchit-core` is the canonical implementation.
  Every UI surface (CLI, desktop, web, mobile) is a thin caller. No
  business logic in UI code.
- **Plugin-shaped content handlers.** Each content type (image, text,
  PDF, audio, archive, etc.) is a registered handler implementing a
  small trait. Adding a new type is one file, one registration line.
  Handlers can be excluded at build-time for thin embeds (mobile WASM
  bundles don't need the FFmpeg-backed video decoder).
- **Streaming where possible.** Don't load 200MB into memory if you can
  stream chunks to a decoder. Self-encryption already streams; preserve
  the property.
- **Stateless core.** `fetchit-core` does not persist anything to disk
  by default. Caching is opt-in and lives in the surface layer.
- **No file-system assumptions in core.** No `dirs::data_dir()`, no
  `std::env::var("HOME")`. The author has been bitten by this in
  etchit on Android (see §7). Cache paths come in as constructor args.
- **Test the parsers, not the network.** Content-type detection,
  envelope parsing, sniffing, decoding — all unit-testable with byte
  fixtures. Network code stays thin and integration-tested.

## 5. Recommended tech stack

**Tier 1 (definitely, for the Android-first 0.1.0)**

- **Rust** for `fetchit-core` and the FFI surface
- **uniffi 0.29.x** for the Kotlin binding generator (matches etchit's
  pin — keeps both projects on the same toolchain)
- **Native Android: Kotlin + XML/ViewBinding** (no Compose for the
  frame; matches etchit-android's pattern). Compose only if a specific
  view requires it later.
- **Min SDK 26, Target SDK 34** — same as etchit-android. Min SDK 26
  is what enabled etchit's biometric-prompt path; for fetch/it
  (read-only) you could go lower, but matching etchit keeps the
  ecosystem coherent.
- **Android NDK 27.0.12077973** — same pin as etchit's FFI build
  toolchain. Avoids a parallel toolchain story.

**Tier 2 (after Android 0.1.0 ships)**

- **Tauri 2 + Vite + TypeScript** for the desktop client. Mirror
  etchit-desktop's structure. Build for Linux + Windows + macOS in
  GitHub Actions matrix from the start of the desktop work — etchit
  shipped Linux-only first and is paying interest to bolt on Windows
  retroactively. Don't repeat that mistake.
- **WASM build of `fetchit-core`** for an in-browser viewer at a future
  `fetchit.io` (or `view.etchit.io`). Big reach, lets anyone with a
  link see content without installing. Cost: some decoders don't
  compile cleanly to WASM (FFmpeg-shaped video work isn't in browser).
  Decoders should declare their target support.
- **CLI (`fetchit get <addr>`)** — slot it in alongside `fetchit-core`
  but it's not blocking the Android ship.

**Avoid**

- **Tauri Mobile / Tauri 2 Android.** It exists and is improving, but
  it's not where etchit-android is, and the goal here is family
  coherence. Native Kotlin + uniffi-FFI is the proven path.
- **Electron.** Don't. Even later for desktop, Tauri is smaller,
  Rust-native, and matches the family.
- **Dynamic plugin loading at runtime.** Static handler registration
  via Cargo features keeps the binary auditable and small.
- **A custom protocol parser.** Use `ant-core` / `ant-ffi` for network
  reads. Don't reinvent self-encryption resolution.

## 6. Content-type handler architecture

The "ffmpeg of Autonomi" promise lives or dies here. Sketch:

```rust
// fetchit-core/src/handler.rs
pub trait ContentHandler {
    /// Stable identifier — "image/png", "application/pdf",
    /// "text/markdown", "etchit/envelope-v1", etc.
    fn kind(&self) -> &'static str;

    /// Cheap byte-sniff to decide if this handler matches.
    /// Should peek at the first few KB at most.
    fn can_handle(&self, head: &[u8], hint: &Hint) -> Confidence;

    /// Produce a typed `Rendition` from the full bytes (or a stream).
    fn render(&self, bytes: Bytes, ctx: &RenderContext) -> Result<Rendition>;
}

pub enum Rendition {
    Text { language: Option<String>, body: String },
    Image { mime: String, data: Bytes },
    Audio { mime: String, data: Bytes },
    Video { mime: String, data: Bytes },
    Pdf { data: Bytes },
    Json { value: serde_json::Value },
    Tabular { columns: Vec<String>, rows: Vec<Vec<String>> },
    Archive { entries: Vec<ArchiveEntry> },   // walkable, not extracted
    EtchitEnvelope { title: String, content: String, language: Option<String> },
    OpaqueBinary { mime: String, data: Bytes },
}
```

Handlers register through a `HandlerRegistry`. Detection runs
`can_handle` across registered handlers, picks highest confidence,
renders. UI surfaces dispatch on `Rendition` variant.

**First wave handlers worth shipping in 0.1.0:**

- Etchit envelope (`{"v":1,"meta":{...},"content":"..."}`) — interop
  with the existing ecosystem
- Plain UTF-8 text (with optional BOM stripping)
- PNG / JPEG / GIF / WEBP / BMP
- PDF (`%PDF-` magic)
- JSON (with pretty-print)
- CSV (heuristic — comma-separated UTF-8, multiple rows of consistent
  column count)
- Markdown (plain text but rendered if the consumer supports it)
- ZIP archive (`PK` magic; walkable index, no extraction by default)
- WAV / FLAC / MP3 (browser/WebView can play `<audio>` for these)
- Generic binary fallback with content-type sniffing via `infer` crate

**Second wave (post-0.1.0):**

- Code with syntax highlighting — port etchit's 13-language tokenizer
  if useful, or use `tree-sitter` if you want something more rigorous
- Source archives (`.tar.gz`, `.tar.zst`)
- Subtitle formats (`.srt`, `.vtt`)
- Geospatial (KML, GPX) — view on a map
- E-book (EPUB, MOBI)

## 7. Reference: how to read etchit

Two reference locations. **Read freely; modify nothing in either.**

- **`./etchit/`** — in-project copy of etchit-android-v3 sitting next
  to this spec. Use this for day-to-day reference — it's right here.
- **`~/Desktop/etchit-desktop/`** — the canonical desktop client repo.
  Used less often during 0.1.0 (Android-first) but worth consulting
  when you start the desktop port in 0.2.0.

(There's also `~/Desktop/etchit-android-v3/` outside the project — the
original of `./etchit/`. Treat them as identical. The in-project copy
is the convenient one.)

What's worth studying (paths shown relative to `./etchit/` — append
that prefix mentally):

| Concern | Reference path |
| --- | --- |
| FFI Rust crate (`ant-ffi`) | `ffi/rust/ant-ffi/` |
| FFI rebuild script + symbol-diff verify | `scripts/build-ffi.sh` |
| Pinned dep versions | `ffi/rust/ant-ffi/Cargo.toml` |
| Content-type detection logic | `app/src/main/java/com/autonomi/antpaste/ContentDetector.kt` |
| Envelope parser | `app/src/main/java/com/autonomi/antpaste/PasteUtils.kt` |
| Android-init fix for `HOME` | `app/src/main/java/com/autonomi/antpaste/EtchitApplication.kt` |
| MainActivity layout patterns (single-Activity, ViewBinding) | `app/src/main/java/com/autonomi/antpaste/MainActivity.kt` |

For desktop reference (when 0.2.0 begins), use the path
`~/Desktop/etchit-desktop/`:

| Concern | Reference path |
| --- | --- |
| Tauri command surface (good shape, copy the pattern not the code) | `src-tauri/src/lib.rs` |
| WebKit DMABUF fix on Linux | `src-tauri/src/lib.rs::run()` |
| Syntax highlighter (TS) | `src/syntaxHighlight.ts` |
| Fullscreen viewer pattern | `src/fullscreenEditor.ts` (the read-only branch) |

## 8. Lessons from etchit (specific gotchas)

These are battle-scars. **Heed them or repeat them.**

1. **`ant-core 0.2.3`'s `data_dir()` calls `home_dir().unwrap()` on
   Linux fallback.** On Android, `HOME` is unset → panic with
   `HomeDirNotFound`. etchit fixes this by setting `HOME` via
   `android.system.Os.setenv` in Application.onCreate before any FFI
   call. **For fetch/it on mobile: do the same, but ideally set both
   `HOME` and `XDG_DATA_HOME` to `context.filesDir` for redundancy.**
   Better: don't touch `data_dir()` at all from the core — pass an
   explicit path in.
2. **WebKit2GTK DMABUF rendering bug on Linux.** Set
   `WEBKIT_DISABLE_DMABUF_RENDERER=1` in the Tauri Rust runtime (not
   just in shell scripts) before `Builder::default()`. See
   `etchit-desktop/src-tauri/src/lib.rs::run()`.
3. **Path deps across sibling repos are fragile.** etchit-desktop's
   `Cargo.toml` points at `../../etchit-android-v3/ffi/rust/ant-ffi`.
   For fetch/it: vendor the FFI crate yourself, or publish `ant-ffi` as
   its own repo and depend by git rev. Don't take a sibling-checkout
   dependency.
4. **uniffi binding diffs are noisy.** Doc-comment changes propagate
   through. etchit's `build-ffi.sh` filters kdoc-only diffs from the
   structural-diff check; reuse that pattern.
5. **GitHub Pages cache on `/releases/latest/download/<name>`.** If you
   change asset names between releases, the website's stable download
   link breaks. Pick consistent names (`fetchit-windows-x64.exe`,
   `fetchit-linux-x86_64.AppImage`, etc.) on day one.
6. **Hierarchical data-maps.** Large files split the data-map across
   multiple chunks. `ant-core::data_download` does NOT resolve them —
   only `file_download` does. etchit's FFI works around this with a
   `resolve_data_map` helper using
   `self_encryption::get_root_data_map_parallel`. Copy that pattern
   into `fetchit-core` from day one — the moment someone tries to view
   a 256MB+ etch, you need it.
7. **Reown AppKit is not your concern.** Skip the wallet stack
   entirely. Saves ~5MB of dependencies and a class of crash bugs.
8. **CLA Assistant + DCO.** etchit chose a formal CLA (gist linked at
   cla-assistant.io). For fetch/it, the choice is yours; DCO might be
   simpler given there's no relicensing concern (the project starts
   GPL-3.0 if you stay in the family).

## 9. Anti-patterns — do not do these

- **Don't fork etchit.** Don't even start by copying its directory tree
  and renaming. Write `fetchit-core` fresh; pull individual logic
  patterns (not whole files) only when they're clearly load-bearing.
- **Don't bake content-type assumptions into the core.** If `fetchit-core`
  hard-codes "text or image or binary, take it or leave it," the
  ffmpeg promise is already broken. The handler trait is the contract.
- **Don't copy etchit's UI structure verbatim.** etchit is a
  *creator/owner* tool: history, private etches, chain/it, settings,
  backups. fetch/it is a *visitor* tool: address bar, content, share.
  Different UX patterns.
- **Don't ship without a CLI.** Even at 0.1.0, `fetchit get <addr>`
  matters — it's the integration surface other tools will use.
- **Don't add wallet dependencies later "just in case."** fetch/it's
  read-only nature is a feature; preserve it. If a write story emerges,
  it's a different project.
- **Don't optimize before the handler registry is stable.** Big perf
  work on a single decoder before the architecture is settled is
  premature. Get the trait shape right first.

## 10. Suggested initial milestone

**fetch/it 0.1.0 (Android, signed APK)** — proves the architecture
works end-to-end on the platform that ships first:

- `fetchit-core` library: connect to Autonomi (matching etchit's
  bootstrap-peer + warmup pattern), fetch by address, run detection,
  return a typed `Rendition`. Hierarchical-data-map resolution
  included from day one.
- **Six content handlers**: etchit-envelope, plain text (UTF-8),
  PNG, JPEG, JSON (pretty-printed), generic binary fallback. These
  six cover most of what etchit users will be sharing already.
- **Android app**, signed APK on GitHub Releases:
  - Single-line address input at top, copper Fetch button
  - Edge-to-edge content area below, network-status pill in a thin
    strip when not fetching
  - Bookmark icon in the address bar (⭐-shaped, copper); tap opens
    a rename modal, save commits to local SharedPreferences
  - Slide-up sheet for the bookmark list (`MaterialBottomSheetDialog`),
    not a permanent bottom nav
  - Long-press on a bookmark: rename, delete, share-as-link, export
- **No** wallet, no chain/it, no settings page in 0.1.0 except a
  minimal one for bootstrap-peer override (matching etchit's behaviour)
- **Smoke test**: paste an existing etchit address → envelope renders
  with title + content. Paste a PNG address → image fills viewport.
  Paste a known-broken address → graceful "chunk not found" with a
  retry option.

**Android comes first because:**

- The user's larger audience is on mobile
- The FFI build path is already well-trodden in etchit-android (same
  toolchain, same NDK, same uniffi version, same ant-core pin)
- The bookmark UX maps cleanly to native Android patterns

**0.2.0 (next):** desktop via Tauri 2. Linux + Windows + macOS in
GitHub Actions matrix from the first commit. Same `fetchit-core` —
proves the library-first design.

**0.3.0 (maybe):** WASM-in-browser viewer, CLI binary, more handlers
(audio, video, PDF, archive walk, syntax-highlighted code).

## 11. Repo layout suggestion

```
fetch-it/
├── Cargo.toml                    # workspace root
├── crates/
│   ├── fetchit-core/              # the library
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── client.rs         # network access
│   │   │   ├── handler.rs        # trait + registry
│   │   │   └── handlers/
│   │   │       ├── etchit_envelope.rs
│   │   │       ├── text.rs
│   │   │       ├── image.rs
│   │   │       └── ...
│   │   └── tests/                # byte-fixture unit tests
│   └── fetchit-cli/               # `fetchit` binary
│       └── src/main.rs
├── apps/
│   └── fetchit-desktop/           # Tauri shell (or web/, mobile/)
└── docs/
    ├── README.md
    └── HANDLER-AUTHORS.md        # how to add a content type
```

This makes adding a `apps/fetchit-web/` or `apps/fetchit-android/` later
a clean directory drop, not a refactor.

## 12. Things to clarify with the author before shipping

Already decided (from author):

- ✓ **Android first, desktop later.** Native Kotlin + uniffi-FFI.
- ✓ **No content caching.** Read-only viewer, in-memory only.
- ✓ **Bookmarks with custom labels** are the only persisted state.
- ✓ **Family look-and-feel.** Same fonts, palette, panel grammar.
- ✓ **Maximum screen for content.** Chrome minimised; bookmarks slide
  in, don't pin.

Still open — ask early:

1. **License.** GPL-3.0 (matches etchit family, copyleft) or something
   more permissive (Apache-2.0 / MIT) so third-party apps can embed
   `fetchit-core` without copyleft propagation? *Ask before assuming.*
   Embeddability is a stated goal (the "ffmpeg of Autonomi" framing),
   so a permissive license has weight here.
2. **Brand wordmark sign-off.** "fetch/it" reads naturally in the
   family but confirm before locking into APK metadata, package name,
   GitHub repo name.
3. **Domain.** `fetchit.io`? `view.etchit.io`? Subdomain reduces ops
   overhead but loses brand independence. Probably ask later, when
   the WASM viewer becomes a thing — Android 0.1.0 doesn't need it.
4. **Bookmark export format.** JSON is the obvious default; confirm
   any specific schema/version you should bake in so future fetch/it
   versions stay backwards-compatible. Suggested: `{ version: 1,
   bookmarks: [{ label, address, addedAt }] }`.
5. **Should `fetchit-core` be designed to be embeddable BY etchit
   itself** (replace etchit's ContentDetector with fetchit-core)?
   Detection-and-rendering only — no wallet/state would cross the
   boundary. Would consolidate detection logic but creates a
   dependency between the two projects. v0.2.0+ conversation.
6. **Android package name.** `io.etchit.viewer`? `io.etchit.view`?
   `io.fetchit`? Affects deep-link handling and Play Store scoping if
   the app ever ships there.

## 13. Style notes for working with this author

- They prefer **terse responses** with the recommendation up-front.
- They value **honesty about tradeoffs** over salesmanship — say "this
  is a mitigation, not a fix" when it's true.
- They like **2–3 sentence proposals** before writing code, then
  building.
- Default to **pure ASCII** in any user-facing copy unless asked
  otherwise — Discord/markdown rendering is fussy.
- Comments in code: minimal, explain *why* not *what*. Match etchit's
  existing patterns.
- They don't want planning/decision documents written to disk. Keep
  context in conversation.

---

You have the etchit project open in `~/Desktop/etchit-android-v3/` and
`~/Desktop/etchit-desktop/`. Read freely; modify nothing. When in
doubt about a pattern, ask before copying.

Good luck.
