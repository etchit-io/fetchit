# Autonomi-Native Web — fetch/it's design space

Living document. The spec is `FETCHIT-SPEC.md`; this is the deeper
treatment of the **fetch/it as a browser for the Autonomi network**
direction. Updated as the work evolves.

---

## Vision

A web that is **content-addressed, permanent, server-less, and
DNS-free**. You upload an HTML document to the Autonomi network, get
back a 64-hex address, and anyone with fetch/it (or any future
Autonomi-aware client) can render that document — including any
JavaScript, any CSS, any images, any data fetches — **without the
traditional web stack getting involved**.

Concretely that means **no DNS, no X.509 PKI, no HTTPS server, no CDN,
no cloud, no name registrar**. Just IP packets to Autonomi peers.
Anyone who has the bytes can serve the bytes; nobody can revoke an
address; nobody can take it down.

The end state: if you can run fetch/it (or its WASM/desktop siblings),
you can **author and consume the entire stack of a small webapp**
without depending on any centralized service.

---

## What works today (v0.1.0)

| Capability | State |
|---|---|
| Single self-contained HTML doc, rendered in WebView | ✓ |
| Inline JS / CSS / data-URI assets | ✓ |
| External CDN fetches (when device has internet) | ✓ |
| **`autonomi://<64-hex>` URL scheme inside the WebView** — `<img src>`, `<script src>`, `<link href>`, `fetch(…)` all resolve through the connected fetch/it client | ✓ |
| In-memory cache so repeated refs don't refetch | ✓ |
| MIME sniffing on `autonomi://` responses (PNG/JPEG/GIF/WEBP/BMP/HTML/SVG/JSON, fallback `application/octet-stream`) | ✓ |
| Permissive CORS on `autonomi://` (no DNS origin to attack) | ✓ |
| Sandbox: JS on, network on, **file-system / content-provider access off**, **DOM storage off**, **no JS bridge to native** | ✓ |

A page that uses **only inlined assets and `autonomi://` references**
can render correctly with the device's traditional internet
disconnected, as long as Autonomi peers are reachable.

## What doesn't work yet

| Gap | Workaround / Path |
|---|---|
| Multi-file SPA bundles (`bundle.js`, `style.css`, asset folders) | Inline everything into one HTML, OR wait for the ZIP archive handler + virtual-filesystem mode |
| `localStorage` / `sessionStorage` / `IndexedDB` | Off by default. Opt-in needed if a real use-case appears |
| Service workers, cache API | Untested; would need extra WebView config |
| Following links to *other* fetch/it pages (`<a href="autonomi://other-page">`) | The WebView's own `WebViewClient.shouldOverrideUrlLoading` doesn't yet route top-level navigations through fetch/it. **Easy fix, not yet wired.** |
| `<a href="autonomi://addr" download>` | Same — not wired |
| Deep-linking from outside the app (open a fetch/it URL from another app or QR code) | Manifest needs an `intent-filter` for an `autonomi:` scheme |
| Discoverability of addresses | No address book, no search, no DNS-equivalent. Sharing is bookmarks + out-of-band copy |
| Trust signals (is this address from someone I've seen before?) | None today; out of scope for 0.1.0 |
| WASM modules served from `autonomi://` | Should work via the existing handler since wasm bytes go through the same intercept path; not verified |

---

## The `autonomi://` URL scheme

### Syntax

```
autonomi://<address>[/<path>]?<query>#<fragment>
```

- **`<address>`**: 64-character lowercase hex (case-insensitive accepted, normalised to lowercase). The on-network address of a public data-map.
- **`<path>`**: reserved for future multi-file content (ZIP bundles).  Currently ignored — only the address resolves.
- **`<query>`**, **`<fragment>`**: stripped before resolution; the page's JS / `<a href>` can still read them via the URL.

### Examples

```html
<!-- Self-rendering image stored on Autonomi -->
<img src="autonomi://c2b0285930b0a2c3df3928d0a4706b4e6d71e84ebeb4f7805c83ffbb63d0ab61">

<!-- JS module loaded from Autonomi -->
<script src="autonomi://7eb0099513397bd49065838ab59978d5c768b2238030022de96dcfa33cbfebd6"></script>

<!-- Stylesheet -->
<link rel="stylesheet" href="autonomi://18a1f9923d61dcd03266b06bead66c39fc75aea83c42be74d95a32cb42cf89e9">

<!-- JSON data fetch from JS -->
<script>
  fetch("autonomi://952a4a08ea40f4772af61f89fcddcef3a270cdd94d1305414c8c57f21b1556a3")
    .then(r => r.json())
    .then(render);
</script>
```

### Resolution semantics

1. fetch/it's WebView intercepts every resource request (`shouldInterceptRequest`)
2. URLs starting with `autonomi://` are routed through the connected `Client`
3. Other URLs (`https://…`, `data:…`, `blob:`) flow through to the platform's network stack
4. Cache: a successful resolution is kept in an in-memory map for the page's lifetime; cleared on `release()`
5. Errors return synthetic HTTP responses (`400 invalid Autonomi address`, `502 fetch failed`, `503 no client connected`)

### What this is **not**

- **Not** a network protocol — `autonomi://` is a URL scheme that the WebView resolves through fetch/it's existing P2P client
- **Not** a routable URL outside fetch/it — pasting `autonomi://abc…` into Chrome won't work unless Chrome is taught the scheme
- **Not** authenticated — anyone with the address can read; no signature verification, no per-recipient keys (use etchit for private content)

---

## Resource resolution paths — current and future

| Mode | How it works | Status |
|---|---|---|
| **Inline** | Everything in one HTML body, data-URI assets | ✓ shipped |
| **autonomi:// URL scheme** | `<img src="autonomi://addr">` resolves via fetch/it client | ✓ shipped |
| **ZIP bundle** | One Autonomi address holds a ZIP; fetch/it extracts to a virtual mount; relative refs (`./bundle.js`) resolve inside the bundle | ✗ pending — needs ZIP archive handler + WebView path-mapping |
| **Manifest-rooted multi-address** | One address holds a JSON manifest listing other addresses by relative path; fetch/it serves them through autonomi:// transparently | ✗ pending — protocol decision |
| **Streaming / chunked** | Long-lived `fetch()` to an address that updates over time | ✗ Autonomi is content-addressed, immutable. Would need a separate update-pointer concept (chain/it territory) |

---

## Trust model

### What we trust

- **The bytes addressed by a hash are the bytes** — the address is the SHA-256 of the data-map; tampering is detectable
- **The user knows the address came from a source they trust** (they pasted it, opened a bookmark, scanned a QR they vouch for)

### What we don't trust

- **The content** — could be anything. Default sandbox protects:
  - No file-system reads → can't grep your photos
  - No content-provider access → can't read your contacts
  - No DOM storage → no fingerprinting persistence
  - No JS bridge → can't call into native code
- **Third-party CDN refs** — when an SPA links to `https://cdn.example.com/lib.js`, that's a normal web call subject to normal trust. fetch/it doesn't broker this.

### What we should add (open questions)

- A **"running JavaScript" indicator** so users know an Autonomi-served page is interactive vs static
- A **"this page made N autonomi:// fetches"** counter for transparency
- An **opt-out switch** for JS — view the page's static layout without scripting
- A **content origin label** — if the user has bookmarked the address before, "you've been here X times"; otherwise "first visit to this address"

---

## What an SPA author needs to know

(Recap of the constraints in `FETCHIT-SPEC.md` § HTML, plus what
`autonomi://` unlocks.)

1. **One HTML file** — top-level upload. Use `vite-plugin-singlefile` or equivalent.
2. **Or**: HTML file + assets uploaded as separate Autonomi addresses, referenced via `autonomi://<addr>` in the HTML.
3. **No relative paths to disk** (`./style.css`) — won't resolve. Use absolute `https://` (CDN) or `autonomi://`.
4. **No `localStorage`, `IndexedDB`, service workers** — DOM storage is off in the sandbox.
5. **Inline fonts** as base64 data URIs if you want truly internet-independent rendering.
6. **Test air-gapped** — disconnect Wi-Fi, keep Autonomi reachable (e.g., on a known LAN running an Autonomi node), reload, verify the page still works.

---

## Roadmap

Numbered roughly in increasing implementation cost:

1. **`shouldOverrideUrlLoading` for top-level autonomi:// links.** Tap `<a href="autonomi://other">` → fetch/it loads the new page in the same WebView (or pushes a navigation stack).
2. **`autonomi:` deep-link intent-filter** in the manifest. Other apps + QR scanners can open `autonomi://addr` and land in fetch/it.
3. **ZIP bundle handler** + WebView virtual-filesystem mount. Multi-file SPAs work without inlining.
4. **Manifest-rooted multi-address.** A small `fetchit.json` at the root address lists `{ path → autonomi-addr }`; the WebView resolves relative paths through that map.
5. **Address book / discovery.** Some way to surface "popular" or "recommended" addresses without a centralized index. Possibly a manifest-driven curated list, possibly out of scope (sharing is bookmarks + word-of-mouth).
6. **Optional persistent storage** behind a per-page user prompt. Spec change first; implementation second.
7. **Content-source ledger.** Track which addresses the user has visited, surface "trusted before" indicators.
8. **Optional JS-off mode.** A toggle in settings to disable scripting for visited pages.
9. **WASM-runtime support** for `<script type="module">` loaded from `autonomi://`. Probably already works; needs verification.
10. **Protocol-level updates** — pointers from a stable address to the latest version of a moving target. This is `chain/it` territory and out of scope for fetch/it itself, but a fetch/it integration would let a `chainit://` URL resolve through chain/it's index then through fetch/it's renderer.

---

## Open questions

- **Is the `autonomi:` URL the right canonical form**, or should we use `at://` or `etch://` to disambiguate from the `ant` CLI?
- **Should `autonomi:` be a registered URL scheme** (IANA / Android system-wide)? Wider adoption argument vs. lock-in concern.
- **For top-level page navigation, should fetch/it maintain a back stack** like a browser, or a flat one-page-at-a-time model?
- **Per-page CORS or fully permissive?** Right now the autonomi:// resolver attaches `Access-Control-Allow-Origin: *`. Future considerations might lock this down per-page.
- **Where do users bring their address book?** Bookmarks today are local-only with JSON export/import — that's intentional (no central registry), but the discovery problem is real.

---

## Notes for hand-off

If a sister session is building a SPA destined for fetch/it:

1. Read the **§ What an SPA author needs to know** section above.
2. Verify locally with airplane mode + Wi-Fi off after Autonomi peers are reachable.
3. If using `autonomi://` references, verify each referenced address actually fetches via `cargo run -p fetchit-cli get <addr>`.
4. Keep the page **under 1 MB** ideally; the engine's current `max_text_bytes` cap is 16 MB.
5. Use the family palette tokens (`#0a0a0a` ink, `#c9732b` copper, `#9ece6a` status-green, `#f7768e` status-red, `#f5f2eb` bone, `#8a8a8a` ash) if it's an etchit-family-flavored page.
