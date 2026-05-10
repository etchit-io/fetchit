# Using fetch/it

Single-page reference for **what fetch/it does, how to do each thing, and what its limits are**. Comprehensive on purpose — there's a lot of it now. Keep this open as a cheat sheet.

For protocol depth (the `autonomi://` scheme, SPA-author constraints, roadmap) see [`AUTONOMI-WEB.md`](AUTONOMI-WEB.md).

For the original design decisions see [`../FETCHIT-SPEC.md`](../FETCHIT-SPEC.md).

---

## What is fetch/it?

A read-only viewer for content stored on the [Autonomi](https://autonomi.com) network. Paste a 64-hex address, see what's there. Text, images, audio, video, PDF, archives, code with syntax highlighting, JSON, CSV, markdown, HTML — anything.

No wallet. No signing. No node to run. No DNS, no CDN, no traditional web servers. Just bytes from a content-addressed P2P network, rendered locally.

---

## Quick start

1. **Get the APK** onto your phone (`adb install` from the build output, or via GitHub Releases when those land)
2. **Open fetch/it**
3. **Paste an Autonomi address** into the bar at the top. Either form works:
   - bare hex: `c2b0285930b0a2c3df3928d0a4706b4e6d71e84ebeb4f7805c83ffbb63d0ab61`
   - prefixed: `autonomi://c2b0285930b0a2c3df3928d0a4706b4e6d71e84ebeb4f7805c83ffbb63d0ab61`
4. **Tap the big copper button.** Or hit Go on the keyboard.
5. **Wait ~10 seconds for the first connection.** The dog inside the button runs while bootstrap completes; subsequent fetches are warm.

---

## Address bar — what it accepts

| Format | Example | Behavior |
|---|---|---|
| Bare 64-hex | `c2b0…ab61` | Fetched as-is |
| Prefixed | `autonomi://c2b0…ab61` | `autonomi://` is stripped, then fetched |
| Prefixed + path | `autonomi://c2b0…ab61/path` | Path is reserved; only the address resolves today |
| Prefixed + query / fragment | `autonomi://c2b0…ab61?foo=bar` | Query / fragment stripped before fetch |

**Validation:** exactly 64 hex characters (0–9, a–f, mixed case OK). Anything else → friendly Snackbar `address must be 64 hex characters`.

**IME submit:** the keyboard's Go / Send key triggers fetch — no need to reach for the button.

---

## What renders natively

Engine inspects the bytes by magic-byte / content heuristics, picks a handler, hands it to the Android side. **You don't need to declare anything** — fetch/it figures out what kind of content the bytes are.

| Format | How fetch/it renders | Notes |
|---|---|---|
| **etch/it envelope** (`{"v":1,"meta":{...},"content":"..."}`) | Title shown, content rendered honoring `meta.lang` | If `lang` is empty and content looks like markdown, renders as markdown automatically |
| **Plain text** (UTF-8) | Monospace, full-screen scrollable | Auto-detects code language and applies syntax highlighting (Rust, Python, JS/TS, Kotlin, Go, Bash, HTML, CSS, YAML, SQL, JSON) |
| **Markdown** | Rendered with proper formatting (headings, lists, links, code blocks) via Markwon | Detection heuristic — files that look markdown-shaped (headings, fences, multiple markers) qualify |
| **HTML / SPA** (`<!DOCTYPE html>` / `<html` / `<?xml`) | Rendered in a sandboxed WebView with JavaScript on. Inside the page, `<img src="autonomi://addr">` etc. resolve through fetch/it. | See [§ The autonomi:// scheme](#the-autonomi-url-scheme) below |
| **JSON** | Pretty-printed in monospace | Tree-view comes later |
| **CSV** | Column-padded monospace table | First row is headers; quoted fields with commas + doubled `""` escapes handled |
| **Image** (PNG / JPEG / GIF / WEBP / BMP / HEIC) | Rendered fit-to-width, edge-to-edge | All decoded by Android's `BitmapFactory` |
| **Audio** (MP3 / WAV / FLAC / OGG / M4A) | Media3 ExoPlayer, dead-centered with full controls — play / pause / seek / time labels / ±15s skip | In-memory playback (no temp files) |
| **Video** (MP4 / MOV / WebM / MKV / AVI / M4V) | Same Media3 PlayerView with video frame; auto-hide controls; fullscreen button | Tap fullscreen → chrome and system bars hide |
| **PDF** | Inline, page-by-page, scrollable | Uses Android's built-in `PdfRenderer` |
| **ZIP archive** | Entry list (paths + sizes) | No extraction in-app yet — use Open with… for the whole archive |
| **Anything else** | Friendly success message + extension label + Open with… / Save… buttons | Hand off to whatever app you have installed for that MIME |

---

## Top-bar controls

| Element | Action |
|---|---|
| **Address input** | Where you paste / type. Accepts `autonomi://` prefix. IME Go triggers fetch. |
| **★ button** | Opens the bookmark sheet. From there: save current address, list saved bookmarks, export / import, share. |

That's it. Two interactive elements at the top. The fetch button itself sits **dead center** (only visible on the idle screen and during fetch).

---

## Gestures

| Where | Gesture | What happens |
|---|---|---|
| Anywhere on the idle screen | **Pull down from top** | Clears the address input + dismisses any rendition; back to fresh state |
| Anywhere with content showing | **Pull down** | Disabled — protected so you don't accidentally lose a 5MB video mid-view |
| Bottom edge | **Drag up the small handle** | Settings sheet expands. Drag down → collapses |
| `★` button | **Tap** | Bookmark sheet opens |
| `✕` button (top right when content is showing) | **Tap** | Dismiss content, fetch button reappears (back-stack preserved) |
| System back button / gesture | **Press / swipe** | Navigates to the previously fetched address. Works after `✕` too. Empty stack → exits the app |
| Audio / video controls | **Tap fullscreen icon** | Hides chrome + system bars. Tap again to restore |
| Bookmark row in the sheet | **Tap** | Address fills into the bar; sheet dismisses |
| Bookmark row in the sheet | **Long-press** | Menu: rename / share / delete |

---

## The bookmark sheet

Tap the **★** to open. The sheet shows:

1. **Save current** button at the top — only when the input has a valid 64-hex address. Tap → modal asks for a label (empty rejected, default placeholder `name it…`)
2. **export** — system file picker (Storage Access Framework). Save a JSON file anywhere — Downloads, Drive, etc.
3. **import** — pick a JSON file. Imports get prepended; existing addresses with same hex are kept (your label wins).
4. **List of bookmarks**, newest first. Shows label + truncated address.

**Long-press a bookmark** for: **rename** / **share** (Android share-sheet with the address as text) / **delete**.

**Schema** of the export JSON (locked; will stay backwards-compatible):
```json
{
  "version": 1,
  "exportedAt": 1746840000000,
  "bookmarks": [
    { "id": "uuid", "label": "...", "address": "...", "addedAt": 1746840000000, "kind": null }
  ]
}
```

Bookmarks are the **only persistent state fetch/it keeps locally**. Nothing else is cached. No history, no view counts, no thumbnails. All fetched bytes live in memory only and are gone when the rendition is dismissed or the app is killed.

---

## The settings sheet

Drag the small handle at the bottom of the screen up.

- **Network** section: `connected to N peers` — auto-updates every 15s. Goes red when count drops to 0 (honest dip indicator), ash when ≥ 1, green when healthy. No refresh button — it polls.
- **Bootstrap peers** section: collapsed by default. Tap the `BOOTSTRAP PEERS ▾` header to expand.
  - Editor pre-filled with current peer list (production defaults if you've never edited)
  - Format: one peer per line, `ip:port` shorthand or full `/ip4/.../udp/.../quic` multiaddr
  - **Save** persists; next fetch reconnects with the new list
  - **Reset** clears the override; falls back to bundled production defaults

---

## Errors and retry

| Kind | Where it shows | What you can do |
|---|---|---|
| Bad address shape | Snackbar at the bottom: `address must be 64 hex characters` | Paste a valid one; the input is preserved so you can edit |
| Network / decode failure during fetch | Snackbar with a **retry** button | Tap retry → re-runs the same fetch. Or paste a different address |
| Audio playback failed | Same Snackbar with retry | Network or decode issue with the bytes |

---

## Battery behavior

fetch/it keeps the Autonomi connection warm while you're using it, and **drops it after 60 seconds of being backgrounded** so the radio + DHT chatter stop. Coming back later → next fetch pays one ~10s bootstrap, then warm again.

| State | Connection |
|---|---|
| Foreground, idle | warm (cheap) |
| Foreground, fetching / playing | warm (active) |
| Backgrounded < 60s | warm (grace period for quick app switches) |
| Backgrounded ≥ 60s | **dropped** — QUIC + DHT silent until next fetch |
| Process killed by OS | reaped — next launch reconnects |

Settings also lets you save a new peer list — saving forces the connection to drop so the new list takes effect on the next fetch.

---

## Open with… / Save…

Any binary fetch/it doesn't render natively (DOCX, EPUB, niche formats, etc.) lands as a friendly success message:

```
DOCX

✓ 47.3 KB downloaded

fetch/it doesn't have a built-in viewer for this format yet.
Use open with… or save below.
```

Two buttons:

- **open with…** — fires `Intent.ACTION_VIEW` with the bytes via FileProvider. System chooser shows whatever apps you have for that MIME. If nothing handles it, Snackbar `no app installed to open <mime>`.
- **save…** — Storage Access Framework picker. Pick where (Downloads, Drive, anywhere). Filename suggested as `fetchit-<addr>.<ext>`.

The temp file used for Open with… lives in `cacheDir/open_with/`. Wiped on next binary fetch and reaped by Android under cache pressure. Saved files go wherever you picked and persist on their own.

---

## The autonomi:// URL scheme

### As an entry point

Three ways to land on a fetch/it page via `autonomi://<addr>`:

1. **Paste it into the address bar.** The `autonomi://` is stripped automatically and the bare address is fetched.
2. **Tap an `autonomi://` link in another app** (any messenger, mail client, QR scanner). Android shows the chooser; pick fetch/it. It opens with the address pre-loaded and fetches automatically.
3. **`adb` deep-link**: `adb shell am start -W -a android.intent.action.VIEW -d "autonomi://c2b0…ab61" io.etchit.fetchit.dev`

### Inside a rendered SPA

When fetch/it renders an HTML document, the page is loaded with `https://aut.local` as its base origin — a **synthetic, non-routable** origin. Any `autonomi://<64-hex>` URL in the document source is rewritten to `https://aut.local/<64-hex>` at load time. Every request to `aut.local` is intercepted inside the app: the 64-hex path is extracted, bytes are pulled from the connected fetch/it client over Autonomi, and handed back as if from a normal https response.

No DNS query for `aut.local` ever leaves the device. No TLS handshake. No server.

Because the browser engine sees standard https, the **full standard web platform works**:

```html
<!-- Resource elements: rewritten to https://aut.local/<addr> on load -->
<img src="autonomi://7eb0…">
<audio src="autonomi://18a1…" controls></audio>
<video src="autonomi://7eb0…" controls></video>
<link rel="stylesheet" href="autonomi://abc1…">
<script src="autonomi://def2…"></script>

<!-- Top-level navigation: still grabbed by the host so back-stack works -->
<a href="autonomi://4949…">go to chapter 2</a>
```

```js
// fetch() works
const r = await fetch("autonomi://c2b0…");
const text = await r.text();

// So does XHR
const xhr = new XMLHttpRequest();
xhr.open("GET", "autonomi://c2b0…");
xhr.send();

// And Streams, range requests, CORS — anything the Fetch spec
// allows for https — because the engine sees https. (Service
// Workers are not yet supported; see "Honest limitations" below.)
```

**Two equivalent URL forms inside an SPA**:
- `autonomi://<64-hex>` — rewritten to the synthetic form at document load. Use in static HTML and in JS string literals.
- `https://aut.local/<64-hex>` — the canonical runtime form. Use when constructing URLs dynamically that aren't in your source HTML/JS string literals.

The host treats both as equivalent. End-user URLs (the address bar, bookmarks, share sheet, deep-link intents) always use the `autonomi://` form — that's the user-facing scheme.

**Display gotcha.** The rewriter is a global string match on `autonomi://<64-hex>`, so if you put a literal `autonomi://<addr>` into display text or copy (rather than into an attribute or JS string), it gets rewritten to `https://aut.local/<addr>` for display too. Two ways around it:

- Inject the scheme prefix via CSS `::before`:
  ```html
  <div class="addr">c2b0…ab61</div>
  ```
  ```css
  .addr::before { content: "autonomi://"; }
  ```
- Split with an HTML tag so the literal isn't continuous in source:
  ```html
  <span>autonomi://</span><span>c2b0…ab61</span>
  ```

Abstract mentions of the scheme without a real address (`<code>autonomi://</code>` in a docs table) are left alone — the rewrite pattern is anchored to a 64-hex tail.

For depth on what works inside the SPA sandbox + the protocol-level details, see [`AUTONOMI-WEB.md`](AUTONOMI-WEB.md).

---

## Sharing addresses

- **From a bookmark**: long-press → share → Android share sheet (paste into Telegram, mail, whatever)
- **From inside a page**: copy the `autonomi://addr` URL or just the bare hex — recipient pastes either form
- **From the address bar**: select-all + copy — the input is selectable like any EditText

---

## Honest limitations

| What | Why | Workaround |
|---|---|---|
| **No upload from inside fetch/it** | Read-only is a defining property (spec §3); writes are etchit's job | Use `ant file upload <file> --public` or etchit |
| **No private / encrypted etch viewing** | Private etches need a wallet; fetch/it is permanently wallet-less | Use etchit |
| **Multi-file SPAs need inlining today** | ZIP-bundle WebView mount isn't wired yet | Use `vite-plugin-singlefile` or equivalent. Or upload each asset separately and reference via `autonomi://` |
| **Filename is gone** for files uploaded via raw `ant file upload` | Filename is local-FS metadata, not network state | etchit envelopes preserve a title; future fetch/it envelope v2 will preserve `name` + `mime` |
| **No address book / discovery** | No central registry by design | Bookmarks + share. Spec says: addresses live in the user's hands |
| **localStorage / IndexedDB off in HTML** | Sandbox default | Inline state in the page; or wait for opt-in persistent storage (deferred) |
| **Service Workers don't register** | SW state lives in IndexedDB, which is off; Chromium also blocks `blob:` URLs as SW scripts. The API surface is exposed but `register()` fails | Host-level disk caching by address (planned) covers the offline-replay use case without a SW |
| **No syntax highlighting in markdown code blocks** | Markwon needs a Prism4j grammar generator we haven't wired | Code files render highlighted; markdown code blocks render plain. Tracked in roadmap |

---

## Tips

- **First fetch is always slow** (~10s) — it's the DHT bootstrap. Repeat fetches in the same session are fast.
- **Connection drops after 60s in the background** to save battery. Fine. Just expect one re-bootstrap when you come back.
- **The peer count in settings is a real-time honesty signal.** If it dips to 0 (red), the network is being weird; that's an honest report, not a glitch — it usually self-recovers within a poll cycle.
- **For air-gapped use** (no traditional internet), as long as Autonomi peers are reachable somehow (LAN node, satellite link, whatever), fetch/it works. SPAs that inline everything also run fine.
- **For QR codes / link sharing**: encode `autonomi://<addr>` directly. Anyone with fetch/it on Android can scan and land on the page.
- **Always paste the bare hex when in doubt.** It always works. The `autonomi://` prefix is a convenience.

---

## Where to look next

- **`AUTONOMI-WEB.md`** — the protocol depth: scheme spec, SPA author constraints, trust model, roadmap to close gaps with the traditional web
- **`HANDLER-AUTHORS.md`** — how to add a new content handler in `fetchit-core` (one file, one registration line, byte-fixture tests)
- **`../FETCHIT-SPEC.md`** — the original design decisions and constraints
- **`../README.md`** — five-second project description

---

## What's not built yet

A short, honest list:

- **ZIP bundle SPAs** — see Limitations
- **Markdown code-block highlighting** — see Limitations
- **Real launcher icon** — current is a placeholder vector
- **CI for the Android build** — Rust workspace runs in CI, gradle build doesn't yet
- **Signed release APK + GitHub Releases** — the apparatus exists in the spec, not yet wired
- **Tauri desktop client** — 0.2.0
- **WASM in-browser viewer** — 0.3.0

When any of these land, this doc gets updated.
