# Security model

> **Status — beta, no warranty.** fetch>it is beta software, dual-
> licensed under [`AGPL-3.0-only`](../LICENSE) and a separate commercial
> license (see [`COMMERCIAL.md`](../COMMERCIAL.md)). Both licenses
> disclaim all warranties (AGPL sections 15 / 16): the software is
> provided *"AS IS" without warranty of any kind*, and neither the
> authors nor copyright holders are liable for any damages arising from
> its use.
>
> This document describes the **intent** and current best-effort
> verification of fetch>it's security posture. It is descriptive, not a
> warranty. Claims here are checked against the code at the time of
> writing, but only the source is authoritative; defenses may have
> gaps we haven't found yet, and the underlying browser engines we
> rely on may have CVEs we don't know about. If you spot a divergence
> between this doc and the code — or a gap in the defenses — please
> report it (see [Reporting](#reporting)).

This document describes fetchit's security posture: what threats it
defends against, what it trusts, the sandbox architecture, and the per-
vector defenses. It's the canonical reference for security reviewers,
contributors, and SPA authors who want to know exactly what their
content is allowed to do.

If you find a vulnerability, see [Reporting](#reporting) below. **Please
do not file public issues for security-impacting bugs.**

> **Scope of this document.** This file covers the *reader* surface:
> the iframe sandbox, the host process, the on-disk cache, and the
> LAN-direct chat handshake. The chat surface has additional
> caveats — relay-path confidentiality, group encryption, per-message
> signature verification, KEM-keypair backup — that are documented
> separately in
> [`crates/fetchit-chat/SECURITY.md`](../crates/fetchit-chat/SECURITY.md).
> If the two documents appear to disagree, both are bugs; please
> [report](#reporting) the divergence.

---

## What fetch>it is

fetch>it is a **read-only** viewer for content addressed by 64-hex
hashes on the Autonomi network. It runs no server, ships no wallet,
signs nothing, and writes no content back. The only thing it does on a
user's behalf is fetch bytes by address, decide what type they are, and
render them. Writes to Autonomi are out of scope; that lives in the
sibling project [etch/it](https://etchit.io).

Read-only-ness is load-bearing: every dangerous browser capability we
turn off would otherwise have to be balanced against a "what if SPA
authors need this" use case. Because we have no upload flow, no
session, and no user-supplied secrets in the renderer, the answer to
"what if authors need this" is always **author differently**. See
[`docs/AUTONOMI-WEB.md`](AUTONOMI-WEB.md) for the contract that places
on SPA authors.

---

## Threat model

fetch>it defends against:

1. **Hostile rendered content**. Any address the user pastes is treated
   as untrusted. The renderer assumes the bytes may contain a malicious
   SPA, a malformed media file aimed at the OS decoder, or a chunk
   intended to fingerprint the user or leak local state.
2. **Network egress to non-Autonomi endpoints**. The rendered content
   is sandboxed so it can't reach hosts other than the local Autonomi
   protocol handler. CDN beacons, tracker pixels, font CDNs, error-
   reporting endpoints — blocked by the defenses listed below. (No
   security boundary is perfect; browser-engine bugs are out of scope.)
3. **Local state exfiltration via web APIs**. APIs that surface device
   info (sensors, mediaDevices, geolocation, WebRTC ICE) are locked out
   before any SPA script runs.
4. **Persistent install footprint**. A fresh install with default
   settings leaves zero on-disk trace of what was fetched. The on-disk
   cache is opt-in and clearly labelled.
5. **Cross-SPA leakage**. DOM storage is disabled in the rendered
   iframe, so SPA A cannot leave breadcrumbs that SPA B can find.

fetch>it explicitly does **not** defend against:

- **Browser-engine 0-days**. fetch>it uses the system WebView (WebKitGTK
  on Linux, WKWebView on macOS / iOS, WebView2 on Windows, system
  WebView on Android). A kernel-level exploit in the renderer is outside
  the trust boundary; we mitigate by keeping the OS WebView current and
  shrinking the API surface the renderer exposes.
- **Adversarial content authenticity**. Content is addressed by hash —
  a hash IS its content — but *which* hashes the user trusts is a
  social/UX problem. The reader can't tell that "the official banking
  page" lives at one hash rather than another; users must verify
  addresses via channels they trust.
- **Media-codec bugs in the OS** (Stagefright-class). The same as the
  browser-engine point — kept current at the OS level.
- **OS-level threats**. A keylogger on the host machine, a malicious
  kernel module, or someone with physical access to the device — out of
  scope. fetch>it protects its own renderer; it doesn't substitute for
  OS hygiene.

---

## Trust model

| Trusted | Why |
| --- | --- |
| fetch>it's own Rust + TS code | Read-the-source: AGPL-3.0-only (with a separate commercial license track). `unsafe_code = "forbid"` and clippy pedantic are enforced on every Rust crate in this repo (workspace lints + a matching `[lints]` block on the desktop crate, which is workspace-excluded for build-time reasons). `missing_docs = "warn"` is also enforced |
| The crates listed in `Cargo.toml` (audit them) | We pin `ant-core` to a known git rev and `uniffi` to a specific tag; bumps are deliberate |
| The system WebView | Trusted to the same level a user trusts their OS browser engine. fetch>it doesn't bundle a private renderer |
| The user's input (the address they paste) | The user is responsible for vetting where they got an address from |

| Not trusted | What we do about it |
| --- | --- |
| Rendered bytes at an address | Sandboxed renderer, strict CSP, stripped resource hints, neutered APIs (see below) |
| External `https://` references inside SPA content | Blocked by CSP `connect-src` + neuter script |
| Any other process on the host | We listen only on a `127.0.0.1` random port for the media server; no LAN exposure |

---

## Security boundaries

```
┌──────────────────────────────────────────────────────────────┐
│ Host OS                                                       │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ fetch>it process (Rust)                                  │ │
│ │   • fetchit-net: Autonomi peer client                    │ │
│ │   • fetchit-core: handler registry, parses bytes         │ │
│ │   • Tauri 2 shell, custom URI scheme + media HTTP server │ │
│ │ ┌─────────────────────────────────────────────────────┐  │ │
│ │ │ Main WebView (our UI code only — trusted)           │  │ │
│ │ │   • address bar, tabs, settings panel               │  │ │
│ │ │   • TS code we wrote                                │  │ │
│ │ │ ┌─────────────────────────────────────────────────┐ │  │ │
│ │ │ │ Sandboxed iframe (rendered SPA content)         │ │  │ │
│ │ │ │   • null origin                                 │ │  │ │
│ │ │ │   • allow-scripts allow-forms (only)            │ │  │ │
│ │ │ │   • strict CSP                                  │ │  │ │
│ │ │ │   • API surface neutered before SPA runs        │ │  │ │
│ │ │ └─────────────────────────────────────────────────┘ │  │ │
│ │ └─────────────────────────────────────────────────────┘  │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

Each inner frame trusts everything outside it but treats anything
inside as untrusted. The two boundaries that matter for security audit:
**OS ↔ fetch>it process** (the binary surface) and **our trusted UI ↔
sandboxed iframe** (the rendered-content surface).

---

## Per-vector defenses (rendered content)

| Vector | Defense | Lives in |
| --- | --- | --- |
| `fetch` / `XMLHttpRequest` / `WebSocket` / `EventSource` / Beacon to external host | CSP `connect-src 'self' fetchit: autonomi: <mediaBase>` | `htmlRewriter.ts::buildCsp` |
| `<script src="https://…">`, inline `eval` | CSP `script-src 'self' fetchit: autonomi: 'unsafe-inline' 'unsafe-eval'` (inline / eval allowed because SPAs need them; external script blocked) | `buildCsp` |
| External stylesheets, fonts, images, media | CSP `style-src`, `font-src`, `img-src`, `media-src` — only `self`, `fetchit:`, `autonomi:`, `data:`, `blob:`, and the localhost media server | `buildCsp` |
| `<iframe>`, `<object>`, `<embed>`, `<applet>` (nested browsing context) | CSP `frame-src 'none'`, `object-src 'none'` | `buildCsp` |
| `<base href="https://attacker/">` redirecting relative URLs | CSP `base-uri 'self' fetchit: autonomi:` + injected `<base href="autonomi://<addr>/">` overriding any author base | `buildCsp` + `setBase` |
| `<form action="https://attacker">` | CSP `form-action 'self' fetchit: autonomi:` | `buildCsp` |
| `<link rel="preconnect|dns-prefetch|prefetch|preload|modulepreload">` issuing TCP/TLS handshakes *before* CSP check | Resource-hint `<link>` tags are stripped from the document during parse, before the WebView sees them | `htmlRewriter.ts::stripResourceHints` |
| `<meta http-equiv="refresh" content="0;url=https://attacker">` navigating the iframe | Meta-refresh tags stripped at parse time | `stripMetaRefresh` |
| `<meta http-equiv="Content-Security-Policy" content="…; report-uri https://attacker">` phoning home on CSP violations | Incoming CSP / CSP-Report-Only meta tags stripped before we inject our own | `stripIncomingCsp` |
| `<a ping="https://tracker">` POSTing on click | `ping` attribute stripped from `<a>` / `<area>` elements | `stripAnchorPing` |
| `<audio>` / `<video>` / `<source>` referencing `autonomi://…` (WebKit's media pipeline only accepts http/https/file/blob) | URLs rewritten to `http://127.0.0.1:<port>/<addr>` served by an in-process HTTP server | `rewriteMediaSrc` + `src-tauri/src/server.rs` |
| `RTCPeerConnection` ICE candidate gathering leaking local-network IPs | WebRTC constructors locked to `undefined`, non-writable, non-configurable, **before any SPA script runs** | `htmlRewriter.ts::NEUTER_SCRIPT` |
| `navigator.geolocation` / `mediaDevices` / `bluetooth` / `usb` / `hid` / `serial` / `wakeLock` / `contacts` | Locked to `undefined` via the same neuter script | `NEUTER_SCRIPT` |
| `Notification`, `SharedWorker`, `WebTransport`, `PresentationRequest` | Locked to `undefined` via the neuter script | `NEUTER_SCRIPT` |
| `navigator.sendBeacon` (defense in depth over `connect-src`) | Locked to `undefined` | `NEUTER_SCRIPT` |
| `navigator.share` / `canShare` (system share sheet with URL data) | Locked to `undefined` | `NEUTER_SCRIPT` |
| `navigator.serviceWorker` / `permissions` / `credentials` / `presentation` | Locked to `undefined` | `NEUTER_SCRIPT` |
| `localStorage`, `sessionStorage`, `IndexedDB` | Null-origin iframe → access throws `SecurityError` (no opt-out) | iframe sandbox `allow-scripts allow-forms` (no `allow-same-origin`) |
| `window.top` cross-frame access | Null origin blocks all cross-frame property reads | sandbox |
| Top-frame navigation, popups | No `allow-top-navigation`, no `allow-popups` on the iframe sandbox | `html.ts::SANDBOX` |
| Tauri `__TAURI__` global leaking into iframe | `withGlobalTauri` is main-frame only; iframe is null-origin and gets no Tauri global | tauri.conf.json + iframe sandbox |

---

## Per-vector defenses (host process)

| Vector | Defense |
| --- | --- |
| Auto-updater phoning home | **Not configured** — no updater plugin enabled, no endpoint URL. The binary never calls home. |
| Telemetry / analytics | None. There is no telemetry code anywhere in the workspace. |
| Disk install footprint | The on-disk byte cache is **off by default**. A fresh install leaves no fetched content on disk until the user opts in via Settings. When on, the user picks one of *Persist / Clear on close / Clear after idle*. |
| Process listening on the LAN | The media HTTP server binds to `127.0.0.1` on an OS-chosen port. Not reachable from another host. |
| `unsafe` Rust | Workspace lint: `unsafe_code = "forbid"`. No `unsafe` blocks in our code. Transitive `unsafe` in dependencies is allowed (audit them per `Cargo.lock`). |
| Filesystem reach from rendered content | The sandbox + CSP forbid `file://` resolution; the protocol handler only ever returns bytes by Autonomi address |

---

## Storage policy

- **DOM storage** (`localStorage`, `sessionStorage`, `IndexedDB`): off
  in the rendered iframe. Every access throws `SecurityError`. SPA
  authors that need to persist state need to either author for the
  sandbox or recognise that no persistence is the right semantic for a
  content-addressed reader. See `docs/AUTONOMI-WEB.md` for the pattern.
- **Process memory cache**: a fetched address is held in RAM during the
  session for instant re-render. Cleared on app close or
  `disconnect`. Never written to disk by default.
- **Disk cache**: opt-in via Settings. When enabled, fetched bytes are
  stored under `<app-local-data>/bytes_cache/` keyed by 64-hex address.
  LRU-evicted to a user-set cap. Three clear modes: *Persist /
  Clear on close / Clear after idle*. A *Clear cache now* button is
  always available. With the cache on, the download streams straight
  into the slot — which is also what drives the desktop progress bar;
  the default cache-off fetch stays in memory, behind a spinner.
- **Settings file**: `<app-local-data>/settings.json`. Contains: cache
  policy + bookmarks. Nothing else. Human-readable, deletable.

---

## What's authoritative — files to read

If you're auditing fetch>it, the load-bearing security code lives in:

| File | What's enforced |
| --- | --- |
| `apps/fetchit-desktop/src/renderers/htmlRewriter.ts` | CSP construction, all rewriter strip steps, the neuter script |
| `apps/fetchit-desktop/src/renderers/html.ts` | Iframe sandbox attribute, the `SANDBOX` constant |
| `apps/fetchit-desktop/src-tauri/src/protocol.rs` | `autonomi://` / `fetchit://` URI scheme handler — what gets served |
| `apps/fetchit-desktop/src-tauri/src/server.rs` | The 127.0.0.1 media HTTP server — bind address, range handling |
| `apps/fetchit-desktop/src-tauri/tauri.conf.json` | App config, including the absence of an updater endpoint |
| `apps/fetchit-desktop/src-tauri/capabilities/default.json` | Tauri capability surface — what the WebView's JS side can invoke |
| `apps/fetchit-desktop/src-tauri/src/disk_cache.rs` | On-disk cache: file-mtime LRU, policy gating, clear |
| `apps/fetchit-desktop/src-tauri/src/settings.rs` | Persistence format, defaults |
| `crates/fetchit-chat/src/lan_direct_transport.rs` | LAN-direct transport: TCP dial, accept loop, handshake-binding verifier, reachability gate |
| `crates/fetchit-chat/src/lan_noise.rs` | Framed Noise XX + ML-DSA-65 channel-binding signature on handshake msg2/msg3 |
| `crates/fetchit-chat/src/lan_static.rs` | Sealed at-rest vault for the X25519 static keypair (ChaCha20-Poly1305 + Argon2id) |
| [`crates/fetchit-chat/SECURITY.md`](../crates/fetchit-chat/SECURITY.md) | Chat-specific v1 caveats: relay-path confidentiality, group plaintext, per-message signature verification, KEM-keypair backup, crypto-deps pinning |

**LAN-direct transport** (opt-in, default off): when enabled in
Settings → Network, fetch>it advertises itself on the local
network via mDNS (`_fetchit-chat._tcp.local.`) and accepts inbound
Noise XX connections. The handshake commits to both peers'
advertised `agent_id`s via the Noise prologue and exchanges
ML-DSA-65 signatures over `lan_binding_bytes || handshake_hash`
on messages 2 and 3, verified against the peer's ML-DSA pubkey
already on the local contact card (from share-URI import). A
LAN-announced peer that isn't in the contact store fails
reachability immediately — strangers on the LAN cannot be dialled,
inbound dials from unknown agents fail the post-handshake
signature verification and are dropped. Accept-loop is capped at
32 concurrent handshakes process-wide. No NAT traversal, no WAN.

And the matching `.test.ts` / Rust `#[cfg(test)]` modules: every strip
step and policy default is covered by a test.

---

## Test the air-gap claim yourself

1. Open Settings. Confirm the on-disk cache is off (default).
2. Open devtools (F12). Switch to the Network tab.
3. Fetch any address.
4. **Expected:** every network request is to `127.0.0.1:<media-port>`
   or routed through the `autonomi://` / `fetchit://` schemes (which
   the Tauri WebView shows as internal). No `https://` requests to any
   external host.
5. If you see a request to a host other than `127.0.0.1` while
   rendering Autonomi content, that's a security bug — file a private
   report (below).

---

## Reporting

Please report security-impacting issues **privately** to the maintainer
via GitHub's private security advisory flow at
<https://github.com/etchit-io/fetchit/security/advisories/new> rather
than as a public issue. We'll acknowledge within a few days, agree on
a disclosure timeline, and credit you in the fix's release notes.

For non-security bugs, open a regular issue.
