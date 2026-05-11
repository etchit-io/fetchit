# Autonomi-Native Web — fetch>it's design space

Living document. Companion to [`USING.md`](USING.md) (end-user guide)
and [`HANDLER-AUTHORS.md`](HANDLER-AUTHORS.md) (engine-extension guide).
This file is the protocol-level treatment of **fetch>it as a browser
for the Autonomi network**: how an HTML document, a JS bundle, an
image, or any other web content stored on Autonomi gets loaded and
rendered with no DNS, no CDN, no traditional internet involved.

---

## Vision

A web that is **content-addressed, permanent, server-less, and
DNS-free**. Upload an HTML document to the Autonomi network, get back
a 64-hex address, and anyone with fetch>it (or any future Autonomi-
aware client) can render it — including any JavaScript, any CSS, any
images, any data fetches — **without the traditional web stack getting
involved**.

Concretely that means **no DNS, no X.509 PKI, no HTTPS server, no CDN,
no cloud, no name registrar**. Just IP packets to Autonomi peers.
Anyone who has the bytes can serve the bytes; nobody can revoke an
address; nobody can take it down.

The end state: if you can run fetch>it (or its desktop / WASM siblings
when those land), you can **author and consume the entire stack of a
small webapp** without depending on any centralized service.

---

## What works today (v0.1.0)

Verified on the Android shell against live Autonomi addresses.

| Capability | State |
|---|---|
| Single self-contained HTML doc, rendered in a sandboxed WebView | ✓ |
| Inline JS / CSS / SVG / `data:` URI assets | ✓ |
| External `https://` CDN fetches (when device has traditional internet) | ✓ |
| **`autonomi://<64-hex>` resource references** — `<img>`, `<audio>`, `<video>`, `<script>`, `<link>`, `<a>`, all resolve through the connected fetch>it client | ✓ |
| **`fetch()` / `XMLHttpRequest` / Streams to `autonomi://` URLs** — works because fetch>it loads pages with a synthetic https origin (see § the synthetic-origin trick) | ✓ |
| **Top-level `<a href="autonomi://addr">` navigation** — tap a link inside a rendered page, the new address loads. System back returns | ✓ |
| **Deep-link intent-filter** — `autonomi://` URLs from any other app (QR scanner, messenger, mail client) route to fetch>it | ✓ |
| **Range requests** for media seeking (`<video>` jumping to mid-file is instant after first fetch) | ✓ |
| **HTML video fullscreen** (`requestFullscreen()` / native player chrome) | ✓ |
| **WebAssembly from `autonomi://`** — `.wasm` fetched by hash, compiled and run in-page | ✓ — verified on Android (`add(40,2)=42`). Both paths work: `WebAssembly.instantiateStreaming(fetch("autonomi://…"))` (the bytes are served `Content-Type: application/wasm`) and `WebAssembly.instantiate(arrayBuffer)` |
| **Persistent disk cache** keyed by address — fetched bytes survive app restarts; offline replay of anything you've seen before | ✓ |
| Permissive CORS on `autonomi://` (no DNS origin to attack) | ✓ |
| Sandbox: JS on, network on, **file-system / content-provider access off**, **DOM storage off**, **no JS bridge to native** | ✓ |

A page that uses **only inlined assets and `autonomi://` references**
renders correctly with the device's traditional internet disconnected,
as long as Autonomi peers are reachable.

## What doesn't work yet

| Gap | Workaround / Path |
|---|---|
| Multi-file SPA bundles (`bundle.js`, `style.css`, asset folders) | Inline everything into one HTML, or upload each asset to its own Autonomi address and reference via `autonomi://<addr>` |
| `localStorage` / `sessionStorage` / `IndexedDB` | Off by default for sandbox isolation. Opt-in needed if a real use-case appears |
| **Service Workers** | API surface exposed but `register()` fails — SW state lives in IndexedDB which the sandbox disables. Host-level disk cache (already shipped) covers the offline-replay use case |
| Discoverability of addresses | No address book, no search, no DNS-equivalent. Sharing is bookmarks, QR codes, and out-of-band copy |
| Trust signals (is this address from someone I've seen before?) | None today; out of scope for 0.1.0 |
| Streaming during first fetch | Today the engine waits for the full Autonomi reassembly before serving; the cache makes second-load instant. Truly progressive streaming would need a streaming API on the underlying client |

---

## The synthetic-origin trick

This is the load-bearing piece that makes the full Web platform work
over `autonomi://` content. Worth understanding if you author SPAs.

### The problem

The browser's Fetch API, XHR, and Streams APIs hardcode an allow-list
of URL schemes (`http`, `https`, `data`, `blob`, `file`). Custom
schemes like `autonomi://` are rejected at the URL-parser layer before
any embedder hook fires. Resource elements (`<img>` / `<audio>` /
`<video>` / `<script>` / `<link>` / `<a>`) have a different loader path
in some WebView versions but it's not reliable across the matrix.

So a naive `fetch("autonomi://abc…")` throws `TypeError: Failed to
fetch`. That blocks any modern SPA from doing data loading, fancy
asset orchestration, or anything beyond inline tags.

### The fix

Inside fetch>it's `HtmlView`, every HTML document is loaded into the
WebView with a synthetic origin: `https://aut.local`. Before the
document reaches the browser engine, every `autonomi://<64-hex>`
reference in the source is rewritten to `https://aut.local/<64-hex>`
— a well-formed https URL the Fetch spec accepts.

The engine sees standard https. Every request to that origin is
caught by `WebViewClient.shouldInterceptRequest` inside the app, the
64-hex path is extracted, and the bytes are pulled from the connected
fetch>it client over the Autonomi P2P connection.

**Nothing about `aut.local` ever leaves the device.** No DNS query is
made, no TLS handshake is performed, no server exists. The hostname
is a costume the document wears so the browser cooperates.

### Implications for SPA authors

The host treats both URL forms as equivalent inside the document:

- `autonomi://<64-hex>` — rewritten to the synthetic form at document
  load. Use in static HTML and in JS string literals.
- `https://aut.local/<64-hex>` — the canonical runtime form. Use when
  constructing URLs dynamically in JS (computed at runtime, after the
  rewriter has run).

End-user URLs (the address bar, bookmarks, share sheet, deep-link
intents) always use the `autonomi://` form — that's the user-facing
scheme.

The rewriter is anchored to `autonomi://` followed by exactly 64 hex
characters, so abstract mentions of the scheme in display copy
(`"the autonomi:// URL scheme"`) are left alone.

---

## The `autonomi://` URL scheme

### Syntax

```
autonomi://<address>[/<path>]?<query>#<fragment>
```

- **`<address>`**: 64-character hex (case-insensitive accepted; lowercase
  is canonical). The on-network address of a public data-map.
- **`<path>`**: reserved. Currently ignored — only the address resolves.
- **`<query>`**, **`<fragment>`**: stripped before resolution; the page's
  JS / `<a href>` can still read them via the `URL` API.

### Examples

```html
<!-- Self-rendering image stored on Autonomi -->
<img src="autonomi://c2b0285930b0a2c3df3928d0a4706b4e6d71e84ebeb4f7805c83ffbb63d0ab61">

<!-- JS module loaded from Autonomi -->
<script src="autonomi://7eb0099513397bd49065838ab59978d5c768b2238030022de96dcfa33cbfebd6"></script>

<!-- Stylesheet -->
<link rel="stylesheet" href="autonomi://abc1…">

<!-- Video with native controls + fullscreen -->
<video src="autonomi://7eb0…" controls></video>

<!-- Top-level navigation: tapping the link loads the new address as a fresh fetch -->
<a href="autonomi://4949…">go to chapter 2</a>
```

```js
// fetch() works
const r = await fetch("autonomi://c2b0…");
const text = await r.text();

// XMLHttpRequest works
const xhr = new XMLHttpRequest();
xhr.open("GET", "autonomi://c2b0…");
xhr.send();

// Streams, range requests, CORS, blob URLs — all work,
// because the engine sees a standard https URL.
```

### Resolution semantics

1. fetch>it's `HtmlView` loads the document with `https://aut.local`
   as base URL. `autonomi://<64-hex>` literals in source are rewritten
   to `https://aut.local/<64-hex>` before the document is handed to
   the WebView.
2. `WebViewClient.shouldInterceptRequest` catches every request to
   `aut.local` (and, defence-in-depth, any leftover raw `autonomi://`)
   and routes through the connected `Client`.
3. Cache is three-tier: per-page in-memory (fastest), app-level disk
   cache keyed by address (survives app restarts; gives offline
   replay), Autonomi network on a true miss.
4. Range requests are honoured — a media element's seek to the middle
   of a large file returns a 206 Partial Content slice from cache
   instantly.
5. Errors return synthetic HTTP responses (`400 invalid Autonomi
   address`, `502 fetch failed`, `503 no client connected`).

### What this is **not**

- **Not** a network protocol — `autonomi://` is a URL scheme that the
  WebView resolves through fetch>it's existing P2P client.
- **Not** a routable URL outside fetch>it — pasting `autonomi://abc…`
  into Chrome won't work unless Chrome is taught the scheme.
- **Not** authenticated — anyone with the address can read; no
  signature verification, no per-recipient keys (use etch/it for
  private content).

---

## Resource resolution paths

Two paths work today:

- **Inline** — everything in one HTML body, data-URI assets, no
  external references at all. Smallest deployable unit. Renders fully
  air-gapped (Autonomi peers reachable but no traditional internet).
- **`autonomi://` references** — static and dynamic `autonomi://<addr>`
  URLs in any of `<img>`, `<audio>`, `<video>`, `<script>`, `<link>`,
  `<a>`, `fetch()`, `XHR`, Streams. Rewritten to synthetic https on
  document load. Each referenced address fetches once and caches
  forever (immutable content-addressing).

The `autonomi://<64-hex>` addresses fetch>it resolves are
content-addressed: the address is `BLAKE3(content)`, so the bytes at
an address cannot change — fetch one today and it returns the same
bytes forever. That immutability is what lets the on-device cache
skip revalidation entirely and a bookmark never go stale.

---

## Trust model

### What we trust

- **The bytes addressed by a hash are the bytes** — the address is
  derived cryptographically from the data; tampering is detectable.
- **The user knows the address came from a source they trust** — they
  pasted it, opened a bookmark, scanned a QR they vouch for.

### What we don't trust

- **The content** — could be anything. Default sandbox protects:
  - No file-system reads → can't grep your photos
  - No content-provider access → can't read your contacts
  - No DOM storage → no fingerprinting persistence
  - No JS bridge → can't call into native code
  - No Service Worker registration → can't install a background
    interceptor
- **Third-party CDN refs** — when an SPA links to
  `https://cdn.example.com/lib.js`, that's a normal web call subject
  to normal trust. fetch>it doesn't broker this.

---

## What an SPA author needs to know

1. **One HTML file per fetch.** The top-level upload is a single HTML
   document. Use [`vite-plugin-singlefile`](https://www.npmjs.com/package/vite-plugin-singlefile)
   or equivalent to produce a self-contained bundle.
2. **Or**: a small HTML shell that references other Autonomi addresses
   via `autonomi://<addr>` for assets. Each asset becomes its own
   address upload, but lives forever in fetch>it's disk cache after
   first use.
3. **No relative paths to disk** (`./style.css`) — won't resolve. Use
   `autonomi://<addr>`, `https://aut.local/<addr>` (the canonical
   runtime form), absolute `https://`, or inline.
4. **No `localStorage`, `IndexedDB`, Service Workers** — DOM storage
   is off in the sandbox. State must live in the page or be re-fetched.
5. **Inline fonts** as base64 data URIs if you want truly internet-
   independent rendering.
6. **Display gotcha** — the rewriter matches `autonomi://<64-hex>` in
   source and rewrites to `https://aut.local/<64-hex>`. If you put a
   literal `autonomi://<addr>` into display *text* (rather than into
   an attribute or JS string), it'll show the synthetic form. Inject
   the prefix via CSS `::before` or split the literal across HTML tags
   to keep the user-facing form. See `USING.md` for examples.
7. **Test air-gapped** — fetch the page once over Autonomi, then turn
   off Wi-Fi / cell. Reload — the disk cache should serve it.


