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
3. **Omnibox keyword** &mdash; type `fetchit`, press <kbd>Tab</kbd>,
   paste an address, hit Enter.
4. **Popup** with an install link if you don't have fetch&gt;it desktop yet.

## What it does *not* do

- No content rendering. The browser is the wrong place to run a P2P
  client; `ant-core` is Rust, libp2p is QUIC, browsers have neither.
- No telemetry, no analytics, no remote calls. The only permissions it
  asks for are `contextMenus` and `storage`.
- No content-script DOM walking for bare 64-hex strings in arbitrary
  text — that would false-positive on every git commit hash on the
  web. Bare addresses go through the right-click path.

## Install (dev, load-unpacked)

Chrome / Edge / Brave / Arc:

1. Open `chrome://extensions`
2. Toggle **Developer mode** on (top right)
3. Click **Load unpacked**, pick `apps/fetchit-web/`

Firefox (121+):

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…**
3. Pick `apps/fetchit-web/manifest.json`

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
| `manifest.json` | MV3 declaration. Chrome 102+ / Firefox 121+. |
| `src/addr.js` | Address parser (mirrors `apps/fetchit-desktop/src/address.ts`). |
| `src/content.js` | Link decorator (no module imports — content scripts can't). |
| `src/background.js` | Service worker. Context menu + omnibox handlers. |
| `src/popup.html` + `popup.css` + `popup.js` | Toolbar popup. |
| `icons/` | 16/32/48/128 PNGs, regenerated from `fetchit-desktop/src-tauri/icons/`. |

## Security posture

The extension's threat surface is narrow on purpose:

- Reads no page content (the content script only looks at `href`
  attributes, never DOM text or form values).
- Writes nothing back to pages (decoration is a sibling element added
  *after* the original anchor, never modifying the page's own DOM).
- Sends no IPC anywhere except the OS scheme handler.
- Permissions are `contextMenus` and `storage` only. No `tabs`, no
  `host_permissions`, no `webRequest`.

See [`docs/SECURITY.md`](../../docs/SECURITY.md) for fetch&gt;it's
broader trust model.
