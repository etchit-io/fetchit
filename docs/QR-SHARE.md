# QR share — design spec

Shared design contract for the QR-share affordance across fetch>it
desktop and fetch>it Android. The spec exists so both platforms ship
the same visual language and a screenshot of the QR from either
unambiguously identifies the address as a fetch>it / etch>it / Autonomi
artifact.

## Why we do this

The Autonomi address (`autonomi://<64-hex>`) doesn't auto-linkify in
Gmail / WhatsApp / SMS — the messengers' allowlist is `http`, `https`,
`mailto`, `tel`. Recipients receive the address as plain text and have
nothing to tap. The QR sidesteps the messengers: scan with a phone
camera, OS routes the `autonomi://` intent to the user's `fetch>it`
install.

Branding the QR has a second-order effect: screenshots of the modal
(or of just the QR alone) carry the wordmark with them. Sharing
spreads the project.

## Two presentation modes

| Mode | Where it shows | Purpose |
|---|---|---|
| **In-app modal** | Both platforms | Preview the QR inside fetch>it — scan from a colocated phone, copy the address, or kick off the share-as-image flow. |
| **Share-as-image card** | Android (mandatory), desktop (TBD) | A self-contained branded PNG fired through the OS share sheet. The artifact users actually receive in their inbox. |

The in-app modal is the primary affordance. The image card is for
sharing into messengers that don't render `autonomi://` links.

## Brand language (both modes)

| Token | Value | Role |
|---|---|---|
| `--bone` / page background | `#F5F1EA` | Modal / card canvas |
| `--ink` | `#1A1814` | QR modules, primary text |
| `--copper` | `#B87333` | Brand accent (chevron, footer domain, button fill, center logo) |
| `--ash` | `#4A4640` (desktop) / `#8A8A8A` (Android) | Secondary text |
| `--line` | `#E8E3DA` | Hairline borders |

Wordmark: **fetch>it** in monospace bold; the `>` chevron is copper,
the surrounding `fetch` and `it` are ink. The chevron has ~0.05em
breathing room on each side. The same mark appears in the QR's center
panel (white rounded square, copper `>` glyph, sized at ~16% of the QR
canvas) and as the modal/card header.

Footer domain: `etchit.io` in copper, weight 600. Tagline copy varies
by platform (see below) but the domain string is always present and
always copper.

## In-app modal

```
┌─────────────────────────────────────────┐
│   fetch>it                          ×   │   ← header (wordmark + close)
│                                         │
│         ┌─────────────────────┐         │
│         │ ████  ▒▒▒▒  ████ ▒  │         │   ← QR (EC level H)
│         │ █  █  ████  █  █ ▓  │         │
│         │ ████  ████  ████ ▒  │         │
│         │            [ > ]    │         │   ← center brand (copper)
│         │ ████  ████  ████ ▓  │         │
│         │ █  █  ████  █  █ ▒  │         │
│         │ ████  ▒▒▒▒  ████ ▓  │         │
│         └─────────────────────┘         │
│                                         │
│       abc123…def890 (selectable)        │   ← short or full hex
│                                         │
│   [ Copy address ] [ Copy autonomi:// ] │   ← two filled copper buttons
│                                         │
│   scan with fetch>it · etchit.io        │   ← footer (ash + copper)
└─────────────────────────────────────────┘
```

**Encoding.** The QR payload is the canonical URL form
`autonomi://<64-hex>`, error correction level `H` (~30% recoverable).
EC level H is mandatory because the center logo occludes ~16% of the
matrix; bumping below H risks unreadable codes.

**Center logo.** A white rounded square ~16% of the matrix side, holding
the copper `>` glyph in monospace bold. White square is needed so the
glyph is readable against the QR; the quiet zone around the glyph
inside the square is ~8% of the box side.

**Close.** Esc on desktop, system back on Android. Backdrop click on
desktop closes; on Android a dialog auto-dismisses on outside touch.

**Copy buttons.** Two actions — bare 64-hex address, and
`autonomi://<addr>` URL. Both flash "Copied!" for ~1.1 s after click.
Buttons are copper-filled (bone text), full width when only one fits,
flex-1 each when two fit side-by-side.

**Tagline copy.**
- Desktop says: *scan with fetch>it on Android · etchit.io*
- Android says: *scan with fetch>it on desktop · etchit.io*

Either always points the scanner at the *other* platform — share-out
implies the recipient is reading the QR from a different device than
the sharer.

## Share-as-image card (Android today, desktop later)

Used when the user picks "Share as image" inside the modal (or directly
from a context menu). The card is a single PNG, ~560 px wide, intended
to flow through Android's `ACTION_SEND` to messengers as an image
attachment. Layout, top to bottom:

```
┌────────────────────────────────────────────────┐
│                                                │
│        ┌────────────────────────────┐          │
│        │  QR  (with [>] center)     │          │  ← QR
│        └────────────────────────────┘          │
│                                                │
│  ────────────── (copper hairline) ──────────── │  ← rule
│                                                │
│                  fetch>it                      │  ← wordmark, INK + COPPER
│                                                │
│  (optional: bookmark label, INK bold, 22sp)    │
│                                                │
│        autonomi://abc12345…def890               │  ← abbreviated address (ASH mono)
│                                                │
│       scan to open on the Autonomi network     │  ← tagline (ASH)
│                                                │
│  fetch>it reads it · etch/it publishes it      │
│              — etchit.io                       │  ← sibling-app line (ASH)
└────────────────────────────────────────────────┘
```

Identical glyph (`>`) in QR center, identical wordmark, identical
copper-on-bone palette. Sibling-app footer (etchit advertised
alongside fetchit) is the load-bearing branding — most recipients see
the image *first*, the address second.

## Platform-specific implementation notes

### Desktop (TypeScript, Tauri)

- `src/qr.ts` exports `renderQrSvg(text, { errorCorrectionLevel, centerLogo })` — inline SVG, currentColor-aware foreground, optional center logo.
- `src/ui/qrModal.ts` mounts the in-app modal at the `#qr-modal` host element.
- Triggered by `▦` button in the header (between `★` and `⚙`) and `Ctrl/Cmd+Shift+S`.
- Share-as-image (PNG export) — **not yet implemented**. Future work: serialize the SVG, paint onto an OffscreenCanvas at 2× DPR, hand the user a download or a clipboard image.

### Android (Kotlin)

- `QrShare.kt` already renders the share-as-image card (PNG via Canvas + ZXing). Keep it.
- New: an in-app QR modal (DialogFragment or AlertDialog) that mirrors the desktop modal — visible QR + selectable address + copy buttons + a *"Share as image"* button that delegates to the existing `QrShare.share()`.
- Triggered by the main share button (currently the toolbar icon that fires `onShareCurrentClicked`) and by bookmark context menu (currently directly fires `QrShare.share()`). Both should funnel through the modal first.
- The bare text-share path in `onShareCurrentClicked` becomes a *third* button inside the modal — *"Share as text"* — for backward compatibility with messengers users prefer.

## Invocation matrix

| Trigger | Platform | Opens |
|---|---|---|
| Header `▦` button | Desktop | Modal |
| `Ctrl/Cmd+Shift+S` | Desktop | Modal |
| Header share icon | Android | Modal |
| Bookmark long-press → "share as QR" | Android | Modal (was: PNG share directly) |
| Modal "Share as image" button | Android | System share sheet with branded PNG |
| Modal "Share as text" button | Android | System share sheet with plain text |
| Modal "Copy address" | Both | Clipboard ← 64-hex |
| Modal "Copy autonomi://…" | Both | Clipboard ← URL form |

## Out of scope

- QR scan-in on desktop. Camera permission flow is heavier than the
  paste flow on desktop; deferred indefinitely.
- A web-shareable URL (something like `etchit.io/qr/<addr>`). Adds DNS
  surface that fetch>it explicitly avoids. The QR + raw address are the
  authoritative artifacts.
- Animated / colored QR variants beyond the brand chevron. The center
  logo is the only deviation from a vanilla QR; everything else is a
  scanner regression risk we don't take.
