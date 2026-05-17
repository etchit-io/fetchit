# fetch&gt;it web

A thin browser extension that routes `autonomi://<64-hex-address>` links
to **fetch&gt;it desktop**. The extension itself runs no network code,
holds no Autonomi keys, and never sees content bytes — it is purely a
discovery and routing aid. All fetching and rendering happens in the
desktop app (or the Android app on mobile).

## What it does

1. **Decorates `autonomi://` links** on any page with a small `fetch>it`
   badge so users can see at a glance which links route here.
2. **Right-click → "Open in fetch>it"** on any selected 64-hex address.
3. **Omnibox keyword** &mdash; type `fetchit`, press <kbd>Space</kbd>,
   paste an address, hit Enter. (Works the same in Chrome / Edge /
   Brave / Arc and Firefox. Tab autocompletes in Firefox instead of
   activating the keyword — use Space.)
4. **Popup** with an install link if you don't have fetch&gt;it desktop yet.

## What it does *not* do

- No content rendering. The browser is the wrong place to run a P2P
  client; `ant-core` is Rust, libp2p is QUIC, browsers have neither.
- No telemetry, no analytics, no remote calls. The only permission it
  asks for is `contextMenus`.
- No content-script DOM walking for bare 64-hex strings in arbitrary
  text — that would false-positive on every git commit hash on the
  web. Bare addresses go through the right-click path.

## Supported browsers

| Browser | Version | Status | Notes |
|---|---|---|---|
| Chrome | 109+ | Supported | First version with reliable MV3 service workers + `omnibox`. |
| Edge | 109+ | Supported | Chromium-based, identical to Chrome. |
| Brave | 1.50+ | Supported | Chromium-based; `brave://extensions` instead of `chrome://`. |
| Arc | All | Supported | Chromium-based. |
| Firefox | 121+ | Supported | First version with stable MV3 background service workers (Dec 2023). |
| Safari | — | Not supported | Safari WebExtensions need Xcode packaging + an Apple Developer account. Out of scope for now; on the roadmap. |
| Mobile Chrome / Mobile Firefox | — | Not supported | Mobile browsers don't run desktop extensions. Use the Android app instead. |

## Install (dev, load-unpacked)

Chrome / Edge / Brave / Arc:

1. Open `chrome://extensions` (Edge: `edge://extensions`, Brave: `brave://extensions`).
2. Toggle **Developer mode** on (top right).
3. Click **Load unpacked**, pick `apps/fetchit-web/`.

Firefox (121+):

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…**.
3. Pick `apps/fetchit-web/manifest.json`.

Firefox unloads temporary add-ons on restart — for persistent install,
sign and load through `about:addons`.

## Routing — how `autonomi://` actually opens fetch&gt;it

The extension never opens the desktop app directly. It hands the OS a
URL with the `autonomi://` scheme; the OS consults its registered
protocol handlers and picks fetch&gt;it desktop (registered by the
Tauri build via `tauri-plugin-deep-link`).

If fetch&gt;it desktop isn't installed, the browser will show its
default "no application registered" dialog. The popup links to the
desktop install page for that case.

## Files

| Path | Role |
|---|---|
| `manifest.json` | MV3 declaration. Chrome 109+ / Firefox 121+. |
| `src/addr.js` | Address parser (mirrors `apps/fetchit-desktop/src/address.ts`). |
| `src/content.js` | Link decorator (no module imports — content scripts can't). |
| `src/background.js` | Service worker. Context menu + omnibox handlers. |
| `src/popup.html` + `popup.css` + `popup.js` | Toolbar popup. |
| `icons/` | 16/32/48/128 PNGs, regenerated from `fetchit-desktop/src-tauri/icons/`. |
| `test/addr.test.mjs` | Node-built-in tests for the address parser. |
| `test/sample.html` | Hand-test fixture — anchors of varying shapes for QA. |

## Tests

The address parser is the only thing with non-trivial logic. Tests run on
plain Node (20+), no deps:

```bash
node --test apps/fetchit-web/test/addr.test.mjs
```

Anything that changes `src/addr.js` MUST keep all 15 tests green. If you
change the parser intentionally (e.g., to accept a new input shape), add
a test for the new shape before changing the implementation — divergence
between this parser and `fetchit-desktop/src/address.ts` is exactly the
class of bug that shows up as "the address worked in one place and not
the other."

## Scheme aliasing (technical)

The desktop app's deep-link plugin registers two scheme handlers:

- `autonomi://<64-hex>` — the network-canonical name, used everywhere in
  user-facing copy.
- `fetchit://<64-hex>` — the brand-aliased name. Same hash, same target
  binary, same render path.

The extension's parser, content-script anchor selector, omnibox handler,
and right-click context-menu all silently accept either form. We don't
advertise `fetchit://` to users — the existing site, demo-city, brief
essay, and QR codes all use `autonomi://`, and surfacing two schemes
side-by-side in user docs causes "wait, which?" confusion. But anything
in the wild that happens to use `fetchit://` (third-party tooling, copy-
pasted from a future post, typed from brand memory) will route correctly.

`autonomi://` is the form to share. `fetchit://` is the safety net.

## Opting an anchor out of the badge

The content script adds a small `fetch>it` badge next to every
`<a href="autonomi://...">`. That works well for inline links but can
break card-style layouts (the badge becomes an extra flex/grid child
between siblings). The script already detects flex/grid parents and
skips the badge in those cases.

Page authors can also opt out explicitly by adding the
`data-no-fetchit-badge` attribute on the anchor or any ancestor:

```html
<div data-no-fetchit-badge>
  <a href="autonomi://...">My card</a>  <!-- badge suppressed -->
</div>
```

The anchor still gets the hover tooltip; only the visible badge is
suppressed.

## Debugging a broken install

Symptoms first, then where to look:

**Right-click menu doesn't appear**

Verify the extension is enabled in `chrome://extensions` (or your
browser's equivalent). On Firefox, temporary add-ons clear at restart —
re-load from `about:debugging#/runtime/this-firefox`.

**Right-click menu appears but clicking does nothing**

Open the service-worker DevTools console:

- Chrome / Edge / Brave / Arc → `chrome://extensions` → click "service
  worker" link under the fetch>it card → DevTools opens.
- Firefox → `about:debugging#/runtime/this-firefox` → click "Inspect"
  next to the extension → console tab.

`[fetch>it] failed to open autonomi://… NoApplicationFound` (or similar)
means the OS doesn't have a registered handler for `autonomi://`. Install
fetch>it desktop — that's the part that registers the scheme. Open the
popup and follow the install link.

**Badge doesn't appear next to autonomi:// links**

If `getComputedStyle(parent).display` reports `flex` or `grid` on the
anchor's parent, the badge is suppressed on purpose to avoid breaking
the layout. Hover the anchor — the tooltip still confirms the extension
saw it. If neither badge nor tooltip appears, the content script isn't
loading; check `chrome://extensions` to confirm the extension has
permission for the current site (it asks for `<all_urls>`, so this is
rare).

**Omnibox keyword `fetchit` doesn't suggest anything**

The omnibox only suggests once the input parses as a valid 64-hex
Autonomi address. Until then there's no suggestion — that's by design.
Press the keyword + Space + paste the address. If the address is invalid
the entry path is a no-op and logs to the service-worker console.

## Security posture

The extension's threat surface is narrow on purpose:

- Reads no page content (the content script only looks at `href`
  attributes, never DOM text or form values).
- Writes nothing back to pages (decoration is a sibling element added
  *after* the original anchor, never modifying the page's own DOM —
  except for setting a `title` if the page hasn't already set one).
- Sends no IPC anywhere except the OS scheme handler.
- Permissions are `contextMenus` only. No `tabs`, no `host_permissions`,
  no `webRequest`, no `storage`.

See [`docs/SECURITY.md`](../../docs/SECURITY.md) for fetch&gt;it's
broader trust model.
