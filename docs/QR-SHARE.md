# QR share — design spec

Shared design contract for the QR-share affordance across every
fetch>it / etch/it surface (desktop and mobile, reader and writer).
The spec exists so all four apps ship the same modal and the same
export card; a recipient seeing a QR card has no way to tell which
platform produced it.

## Why we do this

The Autonomi address (`autonomi://<64-hex>`) doesn't auto-linkify in
Gmail / WhatsApp / SMS / iMessage — the messengers' allowlist is
`http`, `https`, `mailto`, `tel`. Recipients receive the address as
plain text and have nothing to tap. The QR sidesteps the messengers:
scan with a phone camera, OS routes the `autonomi://` intent to the
user's `fetch>it` install.

Branding the QR has a second-order effect: screenshots and saved
cards carry the wordmark with them. Sharing spreads the project.

## Two presentation modes

| Mode | Where it shows | Purpose |
|---|---|---|
| **In-app modal** | All four apps | Live preview of the QR. Lets the user copy the address, copy the `autonomi://` URL, save the branded card, or copy the branded card to the clipboard. |
| **Export card (PNG)** | All four apps | A self-contained branded PNG produced by Save image / Copy image. The artifact that actually lands in a messenger. The modal *is* the live preview of this card minus the action row. |

Both modes share the same wordmark, the same QR rendering, the same
abbreviated-address style, and the same footer. The export card adds
nothing the modal doesn't show.

## Brand language (both modes)

| Token | Value | Role |
|---|---|---|
| `--bone` / page background | `#F5F2EB` | Modal / card canvas |
| `--ink` | `#0A0A0A` (mobile) / `#1A1814` (desktop) | QR modules, wordmark, body text |
| `--copper` | `#C9732B` | Brand accent (chevron, center logo, footer domain) |
| `--ash` | `#8A8A8A` | Secondary text (abbreviated address, footer prose) |
| `--line` | `#E8E3DA` | Hairline borders |

Both **fetch>it** and **etch/it** wordmarks appear in monospace bold:
the `>` (fetch>it) or `/` (etch/it) glyph is copper, the surrounding
`fetch`/`etch` and `it` are ink, with ~0.05em breathing room on each
side. The card's center brand and the modal header both use the
**fetch>it** wordmark on every surface — *fetch>it is the reader, so
the recipient (the one who needs to install something) is always
pointed at fetch>it*, regardless of which app produced the share.

## In-app modal

```
┌────────────────────────────────────────────┐
│   fetch>it                              ×  │  ← header (wordmark + close)
│                                            │
│         ┌──────────────────────┐           │
│         │ ████  ▒▒▒▒  ████ ▒   │           │  ← QR (EC level H)
│         │ █  █  ████  █  █ ▓   │           │
│         │ ████  ████  ████ ▒   │           │
│         │            [ > ]     │           │  ← center brand (copper)
│         │ ████  ████  ████ ▓   │           │
│         │ █  █  ████  █  █ ▒   │           │
│         │ ████  ▒▒▒▒  ████ ▓   │           │
│         └──────────────────────┘           │
│                                            │
│      ┌─ add a title (optional) ─┐          │  ← editable input (italic serif)
│      │                          │          │
│      └──────────────────────────┘          │
│                                            │
│            4cc9e528…7902af39               │  ← abbreviated address (ash mono)
│                                            │
│  ┌──────────┐ ┌────────────┐               │
│  │ address  │ │ autonomi://│               │  ← copy-text actions
│  └──────────┘ └────────────┘               │
│  ┌──────────┐ ┌────────────┐               │
│  │save image│ │ copy image │               │  ← image actions
│  └──────────┘ └────────────┘               │
│                                            │
│   scan with fetch>it on mobile · etchit.io │  ← footer (ink + copper)
└────────────────────────────────────────────┘
```

### Encoding

- Payload: `autonomi://<64-hex>` (canonical URL form, **not** bare hex).
- Error correction: level **H** (~30% recoverable). Non-negotiable —
  the center logo occludes ~16% of the matrix; dropping below H
  produces unreadable codes.
- Quiet zone: 2 modules (standard).

### Center logo

- A white rounded square ~16% of the QR matrix side.
- Inside the square: the copper `>` glyph in monospace bold, sized
  at ~78% of the square's side. ~8% inner padding around the glyph.
- The square has a thin (2–3 px) copper stroke so the logo reads
  intentionally even when the surrounding card is removed by a
  recipient cropping the image.

### Title input

A single-line text input sits below the QR.

- **Placeholder:** *add a title (optional)*, in ash.
- **Pre-fill:** when the caller has a meaningful label — an etch's
  title, a fetched page's `<title>`, an envelope's `meta.title`, a
  filename — the input is pre-filled with that string. The user can
  edit or clear it before exporting.
- **Style:** Instrument Serif italic, ink colour, dashed-ash border
  that goes solid copper on focus. The dashed style is the visual
  affordance that says "editable text field, optional."
- **Max length:** 60 characters. Past that the renderer trims with
  an ellipsis when laying out the export card.
- **Visibility in modal vs. export:** the input is always present in
  the modal (so users discover they *can* add one); the export card
  omits the title row entirely when the input is empty.

### Address row

The abbreviated address, **on one line**, in monospace ash. Format:
first 8 hex chars + `…` (single Unicode ellipsis) + last 8 hex
chars. Example: `4cc9e528…7902af39`. The full 64-hex still lives
inside the QR payload and inside the clipboard buttons; the visible
row is purely for human glance-comparison.

### Action row — 2×2 grid

Four buttons, fixed labels, lowercase:

| Label | Action |
|---|---|
| **address** | Copy bare 64-hex to clipboard |
| **autonomi://…** | Copy `autonomi://<hex>` to clipboard |
| **save image** | Native save dialog → PNG of the full branded card (see Export card below) |
| **copy image** | Put the full branded card PNG on the OS clipboard |

Buttons are copper-filled with bone text, each button `flex 1` so the
2×2 stays even. **Each button must be one line, no wrap.** That's
why the text-copy buttons drop the "Copy" prefix — the longer
"Copy autonomi://…" wrapped on narrow Android screens.

On click, the button flashes a short confirmation ("Copied!" /
"Saved!" / "Failed") for ~1.1 s, then reverts. Disabled during the
flash to debounce double-clicks.

### Footer

A single line, centred: **scan with fetch>it on mobile · etchit.io**.

- "fetch" / "it" in ink, the `>` chevron in copper.
- `etchit.io` in copper, weight 600.
- Always the same text on every surface — the footer is the brand
  beacon that survives screen-cropping.

### Close

- Desktop: Esc, backdrop click, or the explicit `×` button.
- Mobile: system back, or the explicit `×` button. (No tap-outside
  dismissal — the modal is fullscreen on mobile.)

## Export card (PNG)

The artifact saved or copied by the image buttons. Layout, top to
bottom:

```
┌────────────────────────────────────────────────┐
│                                                │
│                  fetch>it                      │  ← wordmark (top)
│                                                │
│        ┌────────────────────────────┐          │
│        │  QR  (with [>] center)     │          │
│        └────────────────────────────┘          │
│                                                │
│             example title                      │  ← title (optional, serif italic)
│                                                │
│           4cc9e528…7902af39                    │  ← abbreviated address (ash mono)
│                                                │
│   scan with fetch>it on mobile · etchit.io     │  ← footer
└────────────────────────────────────────────────┘
```

Constraints:

- **Canvas:** ~720 px wide on desktop, ~560 px wide on mobile. Cream
  (`#F5F2EB`) background, no border. Width is chosen for screen-share
  ergonomics (fits on a phone preview without scroll, sharp on
  desktop).
- **QR side:** ~89% of the canvas width, with ~16 px inner inset
  padding inside a thin-stroked rounded panel.
- **Wordmark at the top.** The first thing the recipient sees should
  be the brand, not the QR. This is reversed from older mobile cards
  where the wordmark sat below the QR — bring legacy renderers in
  line on this revision.
- **Title row:** present only when the user typed something. When
  absent the address sits flush below the QR, no empty gap.
- **Address row:** identical abbreviation to the modal
  (`8+…+8`). Mono, ash.
- **Footer:** identical text + colour treatment to the modal footer.

Save image suggested filename: `fetchit-<first8>.png` (when shared
from a fetch>it surface) or `etchit-<first8>.png` (from etch/it). The
first 8 hex chars are enough to disambiguate inside a Downloads
folder.

Copy image clipboard write puts the **PNG of the full branded card**
on the clipboard, never the bare QR. The recipient's paste shows the
card, wordmark and all.

## Behavioural contracts

### Save image

- Opens a native save / file-picker dialog with the suggested name.
- Writes the PNG bytes via the platform's native filesystem layer —
  on Tauri this means a Rust-side command writing through `std::fs`
  (the JS-side `download` attribute trick doesn't work in the
  WebView).
- Toast / status confirmation showing the destination ("Saved to
  Downloads · …") so the user isn't left guessing.

### Copy image

- Decodes the PNG to RGBA in native code, hands it to the OS
  clipboard via a single backend call. On Tauri / desktop this means
  one Rust frame: do not bounce a resource handle across two
  JS-to-Rust IPC hops — webkit2gtk drops those handles before the
  second call completes.
- The screenshot-watcher (etch/it desktop) must suppress its next
  poll when copy image fires, otherwise the user's own QR
  triggers an "etch this image?" prompt.

### Address dedupe

- Same 64-hex → same QR pixels → recipients comparing two cards know
  instantly whether two shares point at the same address.
- Address normalised to lowercase before encoding.

### Title pre-fill sources (by surface)

| Surface | Title source |
|---|---|
| etch/it desktop result row | The just-finished etch's filename / first-line excerpt |
| etch/it desktop screenshot toast | The user-editable filename in the toast |
| etch/it desktop history row | `entry.label` |
| etch/it desktop blog tab | The published blog post title |
| etch/it mobile result row | `binding.resultTitle` |
| etch/it mobile blog | `publishedTitle` |
| etch/it mobile history row | `entry.title` |
| fetch>it desktop "share current" | Page `<title>` or etchitEnvelope title; null otherwise |
| fetch>it desktop bookmark context | `bookmark.label` |
| fetch>it mobile current address | `null` (user types) |
| fetch>it mobile bookmark | `bookmark.label` |

When the source is `null`, the modal opens with an empty input and
the placeholder visible.

## Platform-specific implementation notes

### Desktop (TypeScript + Tauri 2)

- `src/qr.ts` — `renderQrSvg(text, opts)` for the live QR,
  `renderExportCardSvg(address, title?)` for the export card,
  `abbreviateAddress(hex)` for the address row.
- `src/ui/qrModal.ts` — modal mount + open/close API:
  `open(address, title?: string | null)`.
- Backend commands (Rust): `save_bytes_to_path` and
  `copy_png_to_clipboard`. The PNG → RGBA decode happens in Rust
  using the `png` crate; the clipboard plugin's `write_image` only
  accepts already-decoded `Image` values.

### Android (Kotlin)

- `QrShare.kt` — `renderCardFor(address, label?): Bitmap` produces
  the export card. `QrBitmap.renderQrWithLogo(payload, sizePx)` is
  the bare QR used inside the modal.
- `QrPreviewDialog.kt` — modal as a `Dialog` with the share-card
  theme. Title field is an `EditText` (read at export time, not at
  open time, so user typing lands on the saved/copied card).
- Save image writes via `MediaStore.Downloads`; Copy image uses
  `FileProvider` + `ClipData.newUri(... "image/png")`.

### iOS (to do)

- Mirror the same modal + export-card layout. Suggested file split:
  `QRCardRenderer.swift` (Core Graphics; produces both the live QR
  view and the export `UIImage`), `QRShareView.swift` (SwiftUI sheet
  with the four-button grid, the title `TextField`, and the
  abbreviated-address `Text`).
- QR encoding: `CIFilter.qrCodeGenerator()` with input correction
  level `"H"`; composite the copper-stroked white square + `>` glyph
  on top.
- Save image: `UIActivityViewController` with the rendered
  `UIImage`, or write to `Photos` via `PHPhotoLibrary` (decide based
  on App Store guidance; most users expect *Save to Photos*).
- Copy image: `UIPasteboard.general.image = renderedUIImage`. iOS
  pasteboard is synchronous, no JS-IPC dance needed.
- Title pre-fill sources mirror Android — feed in the etch's stored
  title / page title / filename when available, otherwise present
  the empty placeholder.

## Out of scope

- QR scan-in on desktop. Camera permission flow is heavier than the
  paste flow already supported there.
- A web-shareable URL (something like `etchit.io/qr/<addr>`). Adds
  DNS surface that fetch>it explicitly avoids. The QR + raw address
  are the authoritative artifacts.
- Animated / coloured QR variants beyond the brand chevron. The
  center logo is the only deviation from a vanilla QR; everything
  else is a scanner regression risk we don't take.
- Cross-process share-image suppression — if fetch>it and etch/it
  desktop run side-by-side and the user copies a QR from fetch>it,
  etch/it's screenshot watcher will catch it once and prompt. The
  persistent dismissed-set absorbs that into a one-time event per
  unique QR.
