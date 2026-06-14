# Brand tokens contract

Single source of truth for the design tokens shared between
**fetch>it** and **etch/it** desktop apps. The two apps run
side-by-side; their chrome must read as one continuous brand.

When the brand bible at <https://etchit.io/brand.html> moves, update
**both** `apps/*/src/styles.css` files in lockstep and bump this doc.
Do not change one repo without the other.

## Theme tokens

**v2 status:** fetch>it has shipped tokens v2 (this table: gold
highlight, elevation, edge light, surface gradient, grain, focus
ring, radii, display serif; `--signal-ok` retuned from lime to
patina, same token name). The etch/it port is PENDING; the two apps
are not in lockstep until v2 lands there.

Declared at the top of each app's `apps/*-desktop/src/styles.css`.
Names + per-theme values are identical across both apps. Adding a
token: add it everywhere. Renaming: rename everywhere.

| Token              | Role                              |
|--------------------|-----------------------------------|
| `--ink`            | canvas background                 |
| `--ink-2`          | elevated surface                  |
| `--line`           | dividers, hairlines               |
| `--bone`           | primary text                      |
| `--bone-dim`       | secondary text                    |
| `--ash`            | labels, muted                     |
| `--copper`         | accent                            |
| `--copper-bright`  | accent hover                      |
| `--rust`           | error                             |
| `--signal-ok`      | success status (patina, v2)       |
| `--gold`           | rare gold highlight               |
| `--gold-bright`    | gold highlight hover              |
| `--elev-1`         | elevation shadow, low             |
| `--elev-2`         | elevation shadow, mid             |
| `--elev-3`         | elevation shadow, high            |
| `--edge-highlight` | inset top-edge light              |
| `--surface-grad`   | faint top sheen for cards         |
| `--grain`          | canvas film-grain texture         |
| `--focus-ring`     | focus-visible ring                |
| `--r-ctl`          | control corner radius             |
| `--r-card`         | card corner radius                |
| `--r-pill`         | pill corner radius                |
| `--font-display`   | display serif stack               |

`--grain`, `--focus-ring`, the radii, and `--font-display` are
declared once in `:root` (the Dark block below) and inherit into
Dim and Light; do not redefine them per theme. The other v2 tokens
are retuned per theme.

### Dark (default)

```css
--ink: #0a0a0a;       --ink-2: #141414;      --line: #222;
--copper: #c9732b;    --copper-bright: #e58a3f;
--bone: #f5f2eb;      --bone-dim: #d6cfc0;   --ash: #8a8a8a;
--rust: #ff8a7a;      --signal-ok: #56b292;
--gold: #d9a440;      --gold-bright: #e8bc62;
--elev-1: 0 1px 2px rgba(12, 8, 4, 0.5), 0 2px 8px rgba(12, 8, 4, 0.25);
--elev-2: 0 4px 12px rgba(12, 8, 4, 0.45), 0 12px 32px rgba(12, 8, 4, 0.3);
--elev-3: 0 8px 24px rgba(12, 8, 4, 0.5), 0 24px 64px rgba(12, 8, 4, 0.35);
--edge-highlight: inset 0 1px 0 0 rgba(245, 242, 235, 0.05);
--surface-grad: linear-gradient(180deg, rgba(245, 242, 235, 0.025), transparent 56px);
--grain: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='0.035'/%3E%3C/svg%3E");
--focus-ring: 0 0 0 3px color-mix(in srgb, var(--copper) 22%, transparent);
--r-ctl: 8px;  --r-card: 12px;  --r-pill: 999px;
--font-display: "Instrument Serif", "Iowan Old Style", Georgia, serif;
color-scheme: dark;
```

### Dim

"Warm dusk" -- canvas at L≈20%, a literal step between Dark (L≈4%)
and Light (L≈94%). Bone-on-ink ≈ 10.5 : 1 (AAA). Same copper-family
hue as the rest of the palette so no accent retune required.

```css
--ink: #3a322a;       --ink-2: #443c33;      --line: #524a40;
--copper: #c9732b;    --copper-bright: #e58a3f;
--bone: #f5f2eb;      --bone-dim: #d9d2c4;   --ash: #a09a90;
--rust: #ff8a7a;      --signal-ok: #56b292;
--gold: #d9a440;      --gold-bright: #e8bc62;
--elev-1: 0 1px 2px rgba(18, 12, 6, 0.45), 0 2px 8px rgba(18, 12, 6, 0.22);
--elev-2: 0 4px 12px rgba(18, 12, 6, 0.4), 0 12px 32px rgba(18, 12, 6, 0.26);
--elev-3: 0 8px 24px rgba(18, 12, 6, 0.45), 0 24px 64px rgba(18, 12, 6, 0.3);
--edge-highlight: inset 0 1px 0 0 rgba(245, 242, 235, 0.06);
--surface-grad: linear-gradient(180deg, rgba(245, 242, 235, 0.03), transparent 56px);
color-scheme: dark;
```

### Light

```css
--ink: #f5f2eb;       --ink-2: #faf7f2;      --line: #d6cfc0;
--copper: #c9732b;    --copper-bright: #b86420;
--bone: #0a0a0a;      --bone-dim: #1a1814;   --ash: #3a3a3a;
--rust: #c0392b;      --signal-ok: #2f7e62;
--gold: #a87a1f;      --gold-bright: #8f6512;
--elev-1: 0 1px 2px rgba(60, 44, 28, 0.14), 0 2px 8px rgba(60, 44, 28, 0.08);
--elev-2: 0 4px 12px rgba(60, 44, 28, 0.14), 0 12px 32px rgba(60, 44, 28, 0.1);
--elev-3: 0 8px 24px rgba(60, 44, 28, 0.16), 0 24px 64px rgba(60, 44, 28, 0.12);
--edge-highlight: inset 0 1px 0 0 rgba(255, 255, 255, 0.7);
--surface-grad: linear-gradient(180deg, rgba(255, 255, 255, 0.5), transparent 56px);
color-scheme: light;
```

## Fonts

### Body chrome (everywhere except composer previews)

```css
font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
```

System fonts only. No `<link rel="stylesheet">` to Google Fonts for
chrome -- Cantarell on GNOME, San Francisco on macOS, Segoe UI on
Windows. Both apps render with the host OS's UI font so they melt
into the desktop they're running on.

### Monospace

```css
font-family: "JetBrains Mono", "Source Code Pro", Menlo, Consolas, monospace;
```

JBM/SCP are name-preferences (used when the user has them installed
system-wide); the realistic fallback is Menlo/Consolas/system mono.
Neither app ships an external mono font for the chrome.

### Display serif (v2)

```css
--font-display: "Instrument Serif", "Iowan Old Style", Georgia, serif;
```

Instrument Serif is bundled locally (OFL; in-repo woff2 under
`apps/fetchit-desktop/src/assets/fonts/`, never network-loaded).
Used ONLY for display moments: page headings, dialog titles,
taglines, profile/QR titles, always via `--font-display`. Body
chrome is unchanged (system sans); a surface that is not a display
moment does not use the serif.

## Typography scale

One canonical scale, used by chrome in **both** apps. Px units, not
rem -- the body base is `14px/1.5` and that's load-bearing for every
other size below it. Don't introduce in-between sizes.

| Surface                                   | Size | Weight | Notes                                                  |
|-------------------------------------------|-----:|-------:|--------------------------------------------------------|
| Page heading (`h1` -- "Settings", "Etch")  | 22px |   600  | `letter-spacing: -0.01em`                              |
| Section heading (`h2` -- "Appearance")     | 15px |   600  | Mixed case                                             |
| Subsection label (chip / "ABOUT" tag)     | 11px |   600  | `text-transform: uppercase`, `letter-spacing: 0.08em`  |
| Body paragraph (default)                  | 14px |   400  | Body base; `line-height: 1.5`                          |
| Compact body (row text, descriptions)     | 13px |   400  | `line-height: 1.55` when block-level                   |
| Helper / meta                             | 12px |   400  | `color: var(--ash)`                                    |
| Micro chip                                | 11px |   500  | Used for tag pills, counts                             |
| Wordmark (logo)                           | 18px |   700  | Mono family                                            |
| Tab label                                 | 13px |   500  | `letter-spacing: 0.02em`                               |
| Icon button glyph                         | 18px |   400  | Inline-SVG icon set (`src/ui/icons.ts`); sized by the button container |
| Address / data-map / hex code             | 13px |   400  | Mono                                                   |
| Display heading                           | 26px |   400  | serif (`--font-display`)                               |
| Display title                             | 18px |   400  | serif                                                  |
| Display tagline                           | 17px | 400 italic | serif                                              |

Headings use `color: var(--bone)`. Descriptions/help use
`color: var(--ash)`. No theme override needed -- the tokens carry it.

When the design needs a size that's not in this list, add it to
the table (in both repos) before using it. Drift here is what made
the two apps fall out of sync in May 2026.

## Icons and brand marks

Inline-SVG asset families in `apps/*-desktop/src/ui/icons.ts`. Both are
built on a **24x24 grid**, use **`currentColor` only** (no hex literals,
so they recolor with the theme by context), and are parsed with
`DOMParser` (no script execution). Each is decorative (`aria-hidden`) by
default and takes an accessible label on request.

### UI icon set, `icon(name)`

Stroked affordance glyphs (`fill="none"`, `stroke="currentColor"`, 2px
stroke, round caps/joins). The canonical list is `ICON_NAMES`; adding
one means extending that array (the type derives from it) plus a body
entry. Current set: `send`, `attach`, `emoji`, `react`, `reply`,
`close`, `dock`, `settings`, `add-contact`, `new-group`, `join-group`,
`chat`, `fediverse`, `image`, `back`, `bookmark`, `share`, `chevron`.
These replaced the old unicode chrome glyphs.

### Brand marks, `mark(name)`

The Fetch / Etch / LIT logo family: **filled** glyphs
(`fill="currentColor"`, no stroke) on the same grid, used where an
identity mark is wanted (window/About, the chat and fediverse pane
headers, empty states). `MARK_NAMES`:

| Mark      | Glyph         | Meaning                                    |
|-----------|---------------|--------------------------------------------|
| `fetchit` | `>` chevron   | the reader, forward-motion                 |
| `etchit`  | `/` slash     | the publisher, inscription                 |
| `lit`     | 4-point spark | LIT Chat, the spark on the sealed surface  |

Single-accent copper on ink; `fetchit` and `etchit` are the wordmark
glyphs (`>`, `/`) elevated to standalone shapes. The header wordmark
stays live text (`#mark`) for crispness; the marks are the asset form.
App-icon rasterization (replacing `src-tauri/icons/*`) is a downstream
packaging step.

## Composer / canvas fonts (etch/it only)

The etch/it Blogger and Website composers render template previews
that match the brand bible for the *published* page (Instrument
Serif, Playfair Display, Source Serif Pro, Space Grotesk, Inter).
These are loaded via Google Fonts in `index.html` and used inside
`.canvas-*` / template-specific CSS only. fetch>it doesn't need them.

**Never use these fonts for app chrome**: they're for the rendered
content of a published page, not for buttons, tabs, or settings.
One carve-out: the bundled brand serif (Instrument Serif via
`--font-display`, see "Display serif (v2)" above) is allowed for
display moments.

## Adding a new themed surface

1. Use the existing tokens -- do not introduce hex literals in CSS rules.
2. If a new role is genuinely needed (not already covered), add a
   token to **both** apps in the same change and bump this doc.
3. Never check theme by reading hex values in JS. Use the CSS
   variable or `body[data-theme="..."]` selectors.

## Acceptance check

Before claiming a UI change is "matched":

- Launch both desktops side by side (1420 = fetch>it, 1421 = etch/it).
- The title bar, tab strip, headings, body text, code blocks, and
  buttons should be visually indistinguishable in family / weight.
- Toggle each of the three themes; both apps update in lockstep.
- If something looks off, it's either a missing rule in one app or
  this doc has drifted from one of the two `styles.css` files. Fix
  the styles, then update this doc.
