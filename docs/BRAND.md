# Brand tokens contract

Single source of truth for the design tokens shared between
**fetch>it** and **etch/it** desktop apps. The two apps run
side-by-side; their chrome must read as one continuous brand.

When the brand bible at <https://etchit.io/brand.html> moves, update
**both** `apps/*/src/styles.css` files in lockstep and bump this doc.
Do not change one repo without the other.

## Theme tokens

Declared at the top of each app's `apps/*-desktop/src/styles.css`.
Names + per-theme values are identical across both apps. Adding a
token: add it everywhere. Renaming: rename everywhere.

| Token             | Role                              |
|-------------------|-----------------------------------|
| `--ink`           | canvas background                 |
| `--ink-2`         | elevated surface                  |
| `--line`          | dividers, hairlines               |
| `--bone`          | primary text                      |
| `--bone-dim`      | secondary text                    |
| `--ash`           | labels, muted                     |
| `--copper`        | accent                            |
| `--copper-bright` | accent hover                      |
| `--rust`          | error                             |
| `--signal-ok`     | success status                    |

### Dark (default)

```css
--ink: #0a0a0a;       --ink-2: #141414;      --line: #222;
--copper: #c9732b;    --copper-bright: #e58a3f;
--bone: #f5f2eb;      --bone-dim: #d6cfc0;   --ash: #8a8a8a;
--rust: #ff8a7a;      --signal-ok: #6ab04c;
color-scheme: dark;
```

### Dim

```css
--ink: #1a1612;       --ink-2: #221d18;      --line: #2a2520;
--copper: #c9732b;    --copper-bright: #e58a3f;
--bone: #f5f2eb;      --bone-dim: #e6dfd0;   --ash: #a09a90;
--rust: #ff8a7a;      --signal-ok: #6ab04c;
color-scheme: dark;
```

### Light

```css
--ink: #f5f2eb;       --ink-2: #faf7f2;      --line: #d6cfc0;
--copper: #c9732b;    --copper-bright: #b86420;
--bone: #0a0a0a;      --bone-dim: #1a1814;   --ash: #3a3a3a;
--rust: #c0392b;      --signal-ok: #3d7e2c;
color-scheme: light;
```

## Fonts

### Body chrome (everywhere except composer previews)

```css
font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
```

System fonts only. No `<link rel="stylesheet">` to Google Fonts for
chrome — Cantarell on GNOME, San Francisco on macOS, Segoe UI on
Windows. Both apps render with the host OS's UI font so they melt
into the desktop they're running on.

### Monospace

```css
font-family: "JetBrains Mono", "Source Code Pro", Menlo, Consolas, monospace;
```

JBM/SCP are name-preferences (used when the user has them installed
system-wide); the realistic fallback is Menlo/Consolas/system mono.
Neither app ships an external mono font for the chrome.

## Composer / canvas fonts (etch/it only)

The etch/it Blogger and Website composers render template previews
that match the brand bible for the *published* page (Instrument
Serif, Playfair Display, Source Serif Pro, Space Grotesk, Inter).
These are loaded via Google Fonts in `index.html` and used inside
`.canvas-*` / template-specific CSS only. fetch>it doesn't need them.

**Never use these fonts for app chrome** — they're for the rendered
content of a published page, not for buttons, tabs, or settings.

## Adding a new themed surface

1. Use the existing tokens — do not introduce hex literals in CSS rules.
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
