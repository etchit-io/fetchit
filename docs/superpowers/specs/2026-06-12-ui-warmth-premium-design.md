# fetch>it Desktop UI Warmth & Premium Pass (Design)

**Date:** 2026-06-12
**Branch:** chat
**Lane:** [A] Alice (desktop).
**Trigger:** Josh: the UI "is lacking detail and warmth and premium feel...
the original panes and panels are so basic", and "we can add some colors to
the brand if it helps."
**Status:** Direction set under the standing take-charge mandate; Josh can
redirect at any checkpoint. Visual-only layer, fully reversible.

## 1. Goal & scope

Take every chrome surface of the desktop app from "flat 1px-border boxes on
two background levels" to a warm, layered, detailed look that reads as a
crafted product, without changing behavior, structure, or the read-only
charter. The brand stays ink / bone / copper; this pass gives it material,
depth, light, and a small set of sibling colors.

In scope: design tokens v2, one bundled display serif, depth and texture
system, micro-interactions, all 36 inventoried chrome surfaces, and the
consistency rescues (off-brand onboarding palette, unstyled fieldsets,
hardcoded literals).

Out of scope: rendered CONTENT surfaces stay neutral (the reader must not
restyle fetched documents: iframe HTML, images, video, PDF pages, code
token colors). Renderer chrome (toolbars, archive rows, error cards) IS in
scope. No new features, no behavior changes, no Rust changes.

## 2. Aesthetic direction: "warm metal and paper"

The brand is already letterpress-adjacent: ink canvas, bone text, copper
accent. The refresh commits to that story instead of importing a generic
one:

- **Oxidation palette.** Copper is the hero. Its natural family fills the
  roles the palette is missing: **gold** (gilded; highlights, unread,
  special moments), **patina** (verdigris green; success, presence,
  replacing the off-brand lime `#6ab04c`), **rust** (errors; exists).
  One metal, four states: polished, gilded, oxidized, rusted.
- **Material surfaces.** Panels read as stock: a faint top-edge inner
  highlight (light catching the top of a plate), warm umber shadows (never
  pure black), a 2-3% paper-grain texture on canvas-level backgrounds,
  and panel gradients so large fields are not dead-flat.
- **One serif voice.** Instrument Serif (OFL, bundled locally as woff2,
  regular + italic; no runtime font network fetch ever) for display
  moments ONLY: page headings, dialog titles, empty-state taglines, the
  QR-card title it already specifies. Body chrome stays the system sans
  per BRAND.md ("melt into the desktop"). This amends BRAND.md's
  "composer fonts never in chrome" rule into: body chrome stays system;
  display moments use the bundled brand serif.
- **Light behaves like light.** Focus rings glow copper, hovers lift,
  presses settle, active elements carry a soft underglow. Motion uses the
  existing tokens (`--ease-out-expo`, `--dur-micro/-trans/-enter`); the
  unused `--dur-enter` finally earns its keep on dialog/pane entrances.

## 3. Design tokens v2

All additions land in the existing `:root` / `body[data-theme]` blocks in
`src/styles.css`, defined for all three themes, and in `docs/BRAND.md`
(bumped to a v2 table in the same change; etch/it port is an explicit
follow-up so the apps re-sync in lockstep, fetch>it pilots).

New color tokens (dark / dim / light):

| Token | Role | dark | dim | light |
| --- | --- | --- | --- | --- |
| `--gold` | gilded highlight | `#d9a440` | `#d9a440` | `#a87a1f` |
| `--gold-bright` | gold hover | `#e8bc62` | `#e8bc62` | `#8f6512` |
| `--signal-ok` | success, presence (RETUNED to patina) | `#56b292` | `#56b292` | `#2f7e62` |

`--signal-ok` keeps its name (BRAND.md rename rule) but its value moves
from lime to patina so success/presence sits inside the oxidation family.

New material tokens (per-theme values; light theme gets lighter shadows):

- `--shadow-tint`: the warm shadow base, e.g. dark `12 8 4` (rgb triple
  used inside `rgba()`), light `60 44 28`.
- `--elev-1` / `--elev-2` / `--elev-3`: layered box-shadow stacks (card /
  dropdown / modal). Each combines a tight key shadow + soft ambient,
  built on `--shadow-tint`, never pure black.
- `--edge-highlight`: `inset 0 1px 0 0 rgba(245,242,235,0.05)` (bone at
  4-6%), the machined top edge for elevated panels. Light theme uses a
  white inset.
- `--surface-grad`: subtle linear-gradient overlay for panels (bone 2-3%
  at top to transparent), layered over `var(--ink-2)`.
- `--grain`: tiny tiled SVG feTurbulence data-URI, applied as an extra
  background layer on canvas-level surfaces (body/stage/settings/chat
  panel), opacity ~2.5% dark, ~2% light. Implemented via multi-layer
  `background-image` (no extra DOM, no z-index risk).
- `--focus-ring`: `0 0 0 3px color-mix(in srgb, var(--copper) 22%, transparent)`.

New geometry tokens: `--r-ctl: 8px` (inputs, buttons), `--r-card: 12px`
(panels, dialogs, rows may stay 8), `--r-pill: 999px`. Applied surface by
surface; existing odd radii (4/6/10) converge during each surface pass.

Tint discipline: every hardcoded `rgba(201,115,43,x)` copper literal and
sibling literals become `color-mix(in srgb, var(--copper) N%, transparent)`
(color-mix is already in use, webkit2gtk supports it). The unread-badge
red `rgb(220,50,47)` becomes `--gold`; failed-bubble `rgb(255,120,120)`
becomes `var(--rust)`.

## 4. Typography

- Vendor Instrument Serif regular + italic woff2 under
  `apps/fetchit-desktop/src/assets/fonts/` with its OFL license file;
  `@font-face` in `styles.css` with `font-display: swap`.
- New scale rows (added to BRAND.md's table): Display heading 26px/400
  serif (settings h1, pane titles), Display title 18px/400 serif (dialog
  titles, profile name), Display tagline 17px/400 italic serif (empty
  state, onboarding subtitle). Existing rows unchanged; body stays 14px
  system sans.
- The header wordmark `#mark` stays live text per BRAND.md.

## 5. Surface treatments (by phase)

**Foundation (tokens + base):** tokens v2, fonts, grain, `::selection`
(copper 30% tint), thin warm custom scrollbars (webkit), global
`:focus-visible` ring, `prefers-reduced-motion` coverage extended to chat
and fediverse keyframes (currently mascot-only).

**Chrome shell:** `#bar` gets `--surface-grad` + `--edge-highlight` +
`--elev-1` hairline separation; toolbar buttons get transitions (color,
border, transform), hover lift `translateY(-1px)`, press `scale(0.97)`,
copper focus ring; Go button gets a vertical copper gradient fill + inner
top highlight + hover brightness + press; address input gets focus ring
glow; suggestions dropdown gets `--elev-2`, `--r-ctl`, copper-tint hover
(not white); tab strip active tab gets a soft copper underglow and hover
transitions; status bar text gets a subtle fade-in.

**Stage:** empty state recomposed as the brand moment: large fetchit
chevron mark with a soft radial copper glow behind it, serif italic
tagline, gradient CTA; error state cards get the blocked-notice treatment
(left accent, elevated card); archive rows / EPUB nav / audio shell / PDF
toolbar get the standard control polish (radius, transitions, tints).

**Settings + bookmarks + onboarding:** setting groups become elevated
cards (`--elev-1` + `--edge-highlight` + `--surface-grad`, `--r-card`);
h1 goes display serif with a hairline gradient divider; controls get
focus rings; theme picker cards get richer checked states (copper border
+ glow); bookmark rows get hover lift + tint; `.setting-pill` gets a real
gold-tinted pill rule; onboarding overlay is REBUILT on the token system
(ink/bone/copper, serif title, gradient CTA, elev-3 card) so first-run is
on-brand: the blue `#4f8cff` palette dies.

**Chat:** panel header gets grad + edge; sidebar conversation rows get
hover tint, active copper strip + soft glow; avatars get deterministic
warm gradient backgrounds (8 curated two-stop gradients from the
oxidation family, selected by first agent-id byte modulo 8, initials in
bone) in sidebar + profile card; outbound bubbles get a subtle copper
vertical gradient, inbound get `--edge-highlight`; composer input focus
ring + gradient send button; all `.chat-dialog__panel`s get `--elev-3`,
serif titles, and an enter animation (scale 0.985 + translateY 6px,
`--dur-trans`, `--ease-out-expo`); newGroup's `.chat-dialog__fieldset` /
`__radio` get real styles (token radios matching settings'); emoji picker
gets `--elev-2` + radius; profile card gets the premium pass (elev-3,
serif name, gradient avatar fallback, gold link-chip hover); unavailable
card moves onto tokens (rust accent, not blue); unread badge goes gold.

**Fediverse + QR + sweep:** feed posts get card treatment (edge +
hover lift); compose polish; QR modal keeps its premium look, gains
`--elev-3` + serif title via the bundled font (no more Georgia
fallback); then a literal-to-token audit across all CSS, light + dim
theme walkthrough, and the BRAND.md acceptance check.

## 6. Constraints

- Read-only charter untouched; zero behavior change; CSS + tokens + small
  TS only (avatar gradient class selection, font asset imports, onboarding
  markup classes).
- Fetched content rendering stays neutral (no restyling documents).
- No runtime network fetches for assets; fonts bundled, grain is a
  data-URI.
- webkit2gtk performance: no new `backdrop-filter` (the two existing blurs
  stay the only ones); grain via background layers, not fixed overlays;
  shadows are static (no animated box-shadow loops).
- All animation respects `prefers-reduced-motion`.
- Three themes: every new token defined in all three blocks; verify dim
  and light by walkthrough.
- BRAND.md updated in the same stack; etch/it port recorded as follow-up
  (lockstep rule honored by bumping the contract + explicit pending note).
- A11y: focus-visible everywhere interactive; contrast for new tokens
  (gold on ink 7.4:1, patina on ink 7.1:1, both AA+ for their uses).

## 7. Testing

- Vitest stays green (additive classes only; onboarding markup changes
  update its tests in the same task).
- `npx tsc --noEmit` green.
- Per-task gates; full sweep at the end (root fmt/clippy untouched but run
  anyway as the stack gate).
- Manual: theme triple-walkthrough (dark/dim/light) in `tauri dev`, Josh
  eyeball as the final acceptance.

## 8. Decisions log

- Palette expansion = oxidation family (gold + patina retune of
  signal-ok), not new unrelated hues. Rationale: "add colors" while
  keeping one brand story; lime was the only off-family value.
- Bundled Instrument Serif for display moments; body stays system sans.
  Amends BRAND.md chrome-font rule deliberately; QR card already
  specified the face.
- Grain + edge highlights + warm shadows = the "detail" layer; chosen
  over glassmorphism (backdrop-filter cost on webkit2gtk, and glass is
  off-story for ink/paper/metal).
- Avatar identity = deterministic warm gradients (8 presets); chosen over
  identicons (busy, cold) and solid tints (flat).
- fetch>it pilots tokens v2; etch/it ports after (BRAND.md bumped with a
  pending-port note so the contract stays honest).
