# fetch>it Desktop UI Warmth & Premium Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the "warm metal and paper" visual refresh (spec: `docs/superpowers/specs/2026-06-12-ui-warmth-premium-design.md`) across every chrome surface of the desktop app: tokens v2 (gold, patina, depth, geometry), one bundled display serif, grain/edge/shadow material system, micro-interactions, and the off-brand surface rescues.

**Architecture:** Pure visual layer. CSS custom properties carry the system; surfaces consume tokens only. The only TS changes: a new `avatarColor.ts` helper (deterministic gradient class from an agent id), font asset imports, onboarding markup classes, and tiny class-wiring where avatars mount. No Rust, no behavior change, no renderer-content restyling (fetched documents must render neutrally; only renderer CHROME is touched).

**Tech Stack:** vanilla TS/Vite, CSS custom properties, color-mix(), bundled woff2 (OFL), vitest + tsc gates.

**Branch:** `chat`. **DCO:** every commit signed `git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s`. No em-dashes in committed text. Minimal comments. Honest exit codes (redirect to file + capture `$?`, never `| tail` for status).

**Hard rules for every task:**
- Run gates from `apps/fetchit-desktop/`: `npx tsc --noEmit` and `npm run test:run` must be green before each commit.
- Never edit: `.code-block .tok-*` colors, `.rendered-image`, `.rendered-video`, `.pdf-page`, iframe internals, anything inside `htmlRewriter.ts` (security boundary), or any `src-tauri` file.
- New colors only via tokens or `color-mix()` on tokens. The two sanctioned literal families: avatar identity gradients (theme-invariant by design, like qr.ts) and values INSIDE token definitions.
- All new animation/transition properties must be covered by the global `prefers-reduced-motion` block added in Task 1.
- Each task ends with a commit; nothing ships with a failing gate.

---

## File Structure

| File | Create/Modify | Responsibility |
| --- | --- | --- |
| `apps/fetchit-desktop/src/assets/fonts/` (dir) | Create | InstrumentSerif-Regular.woff2, InstrumentSerif-Italic.woff2, OFL.txt |
| `apps/fetchit-desktop/src/styles.css` | Modify | tokens v2, @font-face, base layer, shell/stage/settings surfaces |
| `apps/fetchit-desktop/src/chat/styles.css` | Modify | chat surface treatments |
| `apps/fetchit-desktop/src/fediverse/styles.css` | Modify | feed/compose treatments |
| `apps/fetchit-desktop/src/onboarding/styles.css` | Modify | rebuild on token system |
| `apps/fetchit-desktop/src/chat/avatarColor.ts` + `.test.ts` | Create | deterministic avatar gradient class |
| `apps/fetchit-desktop/src/chat/sidebar.ts` | Modify | wire avatar gradient class |
| `apps/fetchit-desktop/src/chat/profileCard.ts` | Modify | wire avatar gradient class on the fallback box |
| `docs/BRAND.md` | Modify | tokens v2 table, serif amendment, etch/it port-pending note |

---

## Task 1: Foundation (tokens v2 + fonts + base layer + BRAND.md)

**Files:**
- Create: `apps/fetchit-desktop/src/assets/fonts/{InstrumentSerif-Regular.woff2,InstrumentSerif-Italic.woff2,OFL.txt}`
- Modify: `apps/fetchit-desktop/src/styles.css` (token blocks at top, base layer)
- Modify: `docs/BRAND.md`

- [ ] **Step 1: Vendor the font.** Download Instrument Serif (regular + italic) woff2 and its OFL license. Preferred source: the Google Fonts static woff2 endpoints, e.g. fetch the CSS at `https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&display=swap` with a `Mozilla/5.0` User-Agent, extract the two woff2 URLs from it, download both, and download the license from `https://raw.githubusercontent.com/google/fonts/main/ofl/instrumentserif/OFL.txt`. Save as the three files above. Verify both woff2 files are non-trivial (`stat -c %s`, expect > 10000 bytes each) and start with the `wOF2` magic (`head -c 4`). If the network fails, report BLOCKED.

- [ ] **Step 2: Add @font-face + tokens v2 to `src/styles.css`.** Immediately after the existing header comment block (before `:root`), add:

```css
@font-face {
  font-family: "Instrument Serif";
  src: url("./assets/fonts/InstrumentSerif-Regular.woff2") format("woff2");
  font-weight: 400;
  font-style: normal;
  font-display: swap;
}
@font-face {
  font-family: "Instrument Serif";
  src: url("./assets/fonts/InstrumentSerif-Italic.woff2") format("woff2");
  font-weight: 400;
  font-style: italic;
  font-display: swap;
}
```

Extend the header comment's token legend with one line per new role (gold highlight, signal-ok retune, elevation, edge, grad, grain, focus ring, radii, display serif).

Inside `:root, body[data-theme="dark"]` add (and retune `--signal-ok`):

```css
  --signal-ok: #56b292;
  --gold: #d9a440;
  --gold-bright: #e8bc62;
  --elev-1: 0 1px 2px rgba(12, 8, 4, 0.5), 0 2px 8px rgba(12, 8, 4, 0.25);
  --elev-2: 0 4px 12px rgba(12, 8, 4, 0.45), 0 12px 32px rgba(12, 8, 4, 0.3);
  --elev-3: 0 8px 24px rgba(12, 8, 4, 0.5), 0 24px 64px rgba(12, 8, 4, 0.35);
  --edge-highlight: inset 0 1px 0 0 rgba(245, 242, 235, 0.05);
  --surface-grad: linear-gradient(180deg, rgba(245, 242, 235, 0.025), transparent 56px);
  --grain: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='0.035'/%3E%3C/svg%3E");
  --focus-ring: 0 0 0 3px color-mix(in srgb, var(--copper) 22%, transparent);
  --r-ctl: 8px;
  --r-card: 12px;
  --r-pill: 999px;
  --font-display: "Instrument Serif", "Iowan Old Style", Georgia, serif;
```

(The spec's `--shadow-tint` intent is implemented as these fully-baked per-theme `--elev-*` stacks; no separate triple token.)

In `body[data-theme="dim"]` add the same block with these differing values only:

```css
  --signal-ok: #56b292;
  --gold: #d9a440;
  --gold-bright: #e8bc62;
  --elev-1: 0 1px 2px rgba(18, 12, 6, 0.45), 0 2px 8px rgba(18, 12, 6, 0.22);
  --elev-2: 0 4px 12px rgba(18, 12, 6, 0.4), 0 12px 32px rgba(18, 12, 6, 0.26);
  --elev-3: 0 8px 24px rgba(18, 12, 6, 0.45), 0 24px 64px rgba(18, 12, 6, 0.3);
  --edge-highlight: inset 0 1px 0 0 rgba(245, 242, 235, 0.06);
  --surface-grad: linear-gradient(180deg, rgba(245, 242, 235, 0.03), transparent 56px);
```

(`--grain`, `--focus-ring`, radii, `--font-display` inherit from `:root`; do NOT redefine them in dim/light.)

In `body[data-theme="light"]` add:

```css
  --signal-ok: #2f7e62;
  --gold: #a87a1f;
  --gold-bright: #8f6512;
  --elev-1: 0 1px 2px rgba(60, 44, 28, 0.14), 0 2px 8px rgba(60, 44, 28, 0.08);
  --elev-2: 0 4px 12px rgba(60, 44, 28, 0.14), 0 12px 32px rgba(60, 44, 28, 0.1);
  --elev-3: 0 8px 24px rgba(60, 44, 28, 0.16), 0 24px 64px rgba(60, 44, 28, 0.12);
  --edge-highlight: inset 0 1px 0 0 rgba(255, 255, 255, 0.7);
  --surface-grad: linear-gradient(180deg, rgba(255, 255, 255, 0.5), transparent 56px);
```

- [ ] **Step 3: Base layer.** In `src/styles.css`:
  - `body` background becomes layered: `background-color: var(--ink); background-image: var(--grain);` (keep all other body rules).
  - Add after the body rule:

```css
::selection {
  background: color-mix(in srgb, var(--copper) 32%, transparent);
  color: var(--bone);
}

:focus-visible {
  outline: none;
  box-shadow: var(--focus-ring);
  border-radius: 4px;
}

* {
  scrollbar-width: thin;
  scrollbar-color: color-mix(in srgb, var(--ash) 38%, transparent) transparent;
}
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb {
  background: color-mix(in srgb, var(--ash) 32%, transparent);
  border-radius: var(--r-pill);
  border: 2px solid transparent;
  background-clip: padding-box;
}
::-webkit-scrollbar-thumb:hover {
  background: color-mix(in srgb, var(--copper) 45%, transparent);
  border: 2px solid transparent;
  background-clip: padding-box;
}
::-webkit-scrollbar-track { background: transparent; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001s !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001s !important;
  }
}
```

  NOTE: the existing mascot reduced-motion block stays; this global block extends coverage to chat/fediverse/everything (the spec's gap fix). Check the mascot block does not conflict (it sets the same properties; identical effect).

- [ ] **Step 4: BRAND.md.** Update `docs/BRAND.md`: add the new tokens to the table + per-theme value blocks; change `--signal-ok` values; add a "Display serif (v2)" section: Instrument Serif bundled locally (OFL, in-repo woff2, never network-loaded), used ONLY for display moments (page headings, dialog titles, taglines, profile/QR titles) via `--font-display`; body chrome unchanged (system sans). Amend the "Never use these fonts for app chrome" sentence to carve out the bundled brand serif for display moments. Extend the typography-scale table with: `Display heading | 26px | 400 | serif (--font-display)`, `Display title | 18px | 400 | serif`, `Display tagline | 17px | 400 italic | serif`. Add at the top of the Theme-tokens section: "**v2 status:** fetch>it shipped tokens v2 (this table); etch/it port PENDING; do not consider the apps in lockstep until it lands there."

- [ ] **Step 5: Gates + commit.**

```bash
cd /home/josh/Desktop/fetchit/apps/fetchit-desktop
npx tsc --noEmit >/tmp/ts.log 2>&1; echo "TSC=$?"
npm run test:run >/tmp/vt.log 2>&1; echo "VITEST=$?"
grep -E "Tests  " /tmp/vt.log | tail -1
cd /home/josh/Desktop/fetchit
git add apps/fetchit-desktop/src/assets/fonts apps/fetchit-desktop/src/styles.css docs/BRAND.md
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): design tokens v2 (oxidation palette, depth, grain) + bundled display serif"
```

Expected: TSC=0, VITEST=0 (718 passing).

---

## Task 2: Chrome shell (bar, address, toolbar, tabs, status)

**Files:** Modify `apps/fetchit-desktop/src/styles.css` only. Read each rule before editing; keep selectors and layout properties, change only the visual layer.

- [ ] **Step 1: `#bar`.** Add `background-image: var(--surface-grad); box-shadow: var(--edge-highlight), var(--elev-1); position: relative; z-index: 5;` (keeps the border-bottom hairline; the elev-1 separates the bar from the stage).

- [ ] **Step 2: Toolbar icon buttons** (`#back-toggle, #bookmark-toggle, #share-toggle, #chat-toggle, #settings-toggle` and the fediverse toggle if present in the same rule). Add:

```css
  border-radius: var(--r-ctl);
  transition: color var(--dur-micro), border-color var(--dur-micro),
    background var(--dur-micro), transform var(--dur-micro), box-shadow var(--dur-micro);
```

To their `:hover` rule add `background: color-mix(in srgb, var(--copper) 8%, transparent); transform: translateY(-1px);`. Add a shared `:active` rule: `transform: translateY(0) scale(0.96);`.

- [ ] **Step 3: `#go`.** Replace flat fill with:

```css
  background: linear-gradient(180deg, var(--copper-bright), var(--copper));
  box-shadow: var(--edge-highlight), 0 1px 3px color-mix(in srgb, var(--copper) 35%, transparent);
  border-radius: var(--r-ctl);
  transition: filter var(--dur-micro), transform var(--dur-micro), box-shadow var(--dur-micro);
```

`#go:hover { filter: brightness(1.07); transform: translateY(-1px); }` and `#go:active { transform: translateY(0) scale(0.98); filter: brightness(0.97); }`. Keep the disabled rule, add `box-shadow: none; background: var(--ash);` (flat when disabled).

- [ ] **Step 4: `#addr`.** `border-radius: var(--r-ctl); transition: border-color var(--dur-micro), box-shadow var(--dur-micro);` and on `:focus` add `box-shadow: var(--focus-ring);`.

- [ ] **Step 5: `.addr-suggestions`.** `border-radius: var(--r-ctl); box-shadow: var(--elev-2), var(--edge-highlight); background: var(--ink-2); background-image: var(--surface-grad);`. Suggestion hover/active: replace `rgba(255,255,255,0.05)` with `color-mix(in srgb, var(--copper) 10%, transparent)`.

- [ ] **Step 6: Tab strip.** `.tab`: add `transition: color var(--dur-micro), background var(--dur-micro), border-color var(--dur-micro); border-radius: 6px 6px 0 0;`. `.tab:hover`: add `background: color-mix(in srgb, var(--bone) 4%, transparent);`. Active tab: add `background: linear-gradient(180deg, color-mix(in srgb, var(--copper) 9%, transparent), transparent);` on top of the existing copper border-bottom. `#status`: add `transition: opacity var(--dur-micro);`.

- [ ] **Step 7: Gates + commit** (same gate commands as Task 1 Step 5).

```bash
git add apps/fetchit-desktop/src/styles.css
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "style(desktop): chrome shell depth + micro-interactions (bar, address, tabs)"
```

---

## Task 3: Stage chrome (empty state, errors, archive, EPUB, audio, PDF toolbar, blocked)

**Files:** Modify `apps/fetchit-desktop/src/styles.css`, `apps/fetchit-desktop/src/emptyState.ts` (class additions only if needed). Read `emptyState.ts` and its test first.

- [ ] **Step 1: Empty state = the brand moment.** Style only (the existing DOM has mark + CTA + hint):
  - The mark container gets a soft radial glow behind it: `.tab-empty .brand-mark-large` (or the actual class; read the file) wrapped look via `filter: drop-shadow(0 0 28px color-mix(in srgb, var(--copper) 35%, transparent));`.
  - The hint paragraph becomes the serif tagline: `font: italic 17px/1.5 var(--font-display); color: var(--bone-dim);`.
  - CTA gets the `#go` gradient-button treatment (same properties; consider a shared `.btn-copper` class in styles.css and apply it in both rules via duplication if no shared class exists; do NOT refactor TS for this).
  - If `emptyState.ts` markup lacks a hook for the tagline styling, add a class in TS and update `emptyState.test.ts` expectations in the same commit.

- [ ] **Step 2: Error + blocked cards.** `.tab-error`: give the inner content a card: `background: var(--ink-2); background-image: var(--surface-grad); border: 1px solid var(--line); border-left: 3px solid var(--rust); border-radius: var(--r-card); box-shadow: var(--elev-1), var(--edge-highlight); padding: 18px 22px; max-width: 560px;`. `.blocked-notice`: add `background: var(--ink-2); box-shadow: var(--elev-1), var(--edge-highlight); border-radius: var(--r-card);`.

- [ ] **Step 3: Archive rows.** `.archive-row`: `border-radius: var(--r-ctl); box-shadow: var(--edge-highlight); transition: border-color var(--dur-micro), transform var(--dur-micro), box-shadow var(--dur-micro);` hover: `border-color: color-mix(in srgb, var(--copper) 45%, var(--line)); transform: translateY(-1px); box-shadow: var(--elev-1), var(--edge-highlight);`. Action buttons get `border-radius: 6px;` + existing transition (already has dur-micro).

- [ ] **Step 4: EPUB nav + audio + PDF toolbar.** EPUB nav buttons: add the toolbar-button transition/press treatment from Task 2 Step 2. `.rendered-audio`: wrap visual: give the audio element's container `background: var(--ink-2); background-image: var(--surface-grad); border: 1px solid var(--line); border-radius: var(--r-card); box-shadow: var(--elev-1), var(--edge-highlight); padding: 18px;` (style via existing classes only; read renderers/audio.ts for the class names, do not change its TS). `.pdf-toolbar`: add `background-image: var(--surface-grad);`.

- [ ] **Step 5: Gates + commit.**

```bash
git add apps/fetchit-desktop/src/styles.css apps/fetchit-desktop/src/emptyState.ts apps/fetchit-desktop/src/emptyState.test.ts
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "style(desktop): stage chrome warmth (empty state, error cards, archive, media shells)"
```

(Only add the TS/test files if actually modified.)

---

## Task 4: Settings + bookmarks + onboarding rescue

**Files:** Modify `apps/fetchit-desktop/src/styles.css`, `apps/fetchit-desktop/src/onboarding/styles.css`; read `src/onboarding/welcome.ts` + its test (update test only if markup classes change).

- [ ] **Step 1: Setting groups.** `.setting-group`: `background-image: var(--surface-grad); border-radius: var(--r-card); box-shadow: var(--elev-1), var(--edge-highlight);`. Settings `h1`: `font: 400 26px/1.2 var(--font-display); letter-spacing: 0;` and add below it a gradient hairline: the existing divider (or add `border-bottom: none;` + `background: linear-gradient(90deg, var(--copper) 0%, transparent 60%); height: 1px;` on whatever divider element exists; if none exists, give the h1 `padding-bottom: 14px;` + `background: linear-gradient(90deg, color-mix(in srgb, var(--copper) 55%, transparent), transparent 320px) bottom left / 100% 1px no-repeat;`).

- [ ] **Step 2: Controls.** Checkbox/select/number/textarea focus: add `box-shadow: var(--focus-ring);` on their existing `:focus` rules. `.setting-action`: `border-radius: var(--r-ctl); transition: background var(--dur-micro), color var(--dur-micro), transform var(--dur-micro);` hover adds `transform: translateY(-1px);`, add `:active { transform: scale(0.98); }`. Theme option cards (`.settings-theme-option`): add `transition: border-color var(--dur-micro), background var(--dur-micro), box-shadow var(--dur-micro);`; the `:has(input:checked)` state adds `box-shadow: 0 0 0 1px var(--copper), 0 2px 12px color-mix(in srgb, var(--copper) 25%, transparent);`.

- [ ] **Step 3: `.setting-pill` (currently unstyled).** Add:

```css
.setting-pill {
  display: inline-block;
  margin-left: 8px;
  padding: 1px 8px 2px;
  font: 500 11px/1.6 ui-sans-serif, system-ui, sans-serif;
  font-style: normal;
  letter-spacing: 0.04em;
  color: var(--gold);
  border: 1px solid color-mix(in srgb, var(--gold) 45%, transparent);
  border-radius: var(--r-pill);
  background: color-mix(in srgb, var(--gold) 10%, transparent);
}
```

- [ ] **Step 4: Bookmark rows.** `.bookmark-row`: `transition: border-color var(--dur-micro), transform var(--dur-micro), box-shadow var(--dur-micro); box-shadow: var(--edge-highlight);` hover adds `transform: translateY(-1px); box-shadow: var(--elev-1), var(--edge-highlight);`.

- [ ] **Step 5: Onboarding rebuild on tokens.** Rewrite `src/onboarding/styles.css` replacing every `var(--x, #fallback)` custom palette with the app tokens (this file loads in the same document, tokens are available): overlay backdrop `color-mix(in srgb, var(--ink) 72%, transparent)` (keep the existing blur, it is one of the two sanctioned), card `background: var(--ink-2); background-image: var(--surface-grad); border: 1px solid var(--line); border-radius: var(--r-card); box-shadow: var(--elev-3), var(--edge-highlight);`, title `font: 400 26px/1.25 var(--font-display); color: var(--bone);`, input on ink with focus ring, primary button = the copper gradient button (Task 2 Step 3 values), skip link `var(--ash)` hover `var(--bone)`. The BLUE `#4f8cff` accent must not survive anywhere in the file. Read `welcome.ts` + its test first; keep all class names unless a new hook is essential.

- [ ] **Step 6: Gates + commit.**

```bash
git add apps/fetchit-desktop/src/styles.css apps/fetchit-desktop/src/onboarding/styles.css
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "style(desktop): settings depth, gold pill, onboarding moved onto brand tokens"
```

---

## Task 5: Chat surface

**Files:** Create `apps/fetchit-desktop/src/chat/avatarColor.ts` + `avatarColor.test.ts`; modify `apps/fetchit-desktop/src/chat/styles.css`, `sidebar.ts`, `profileCard.ts` (one-line class wiring each).

- [ ] **Step 1 (TDD): avatar gradient helper test first.** `avatarColor.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { avatarGradientClass } from "./avatarColor";

describe("avatarGradientClass", () => {
  it("is deterministic for the same agent id", () => {
    const id = "ab".repeat(32);
    expect(avatarGradientClass(id)).toBe(avatarGradientClass(id));
  });
  it("maps the first byte modulo 8", () => {
    expect(avatarGradientClass("00" + "11".repeat(31))).toBe("chat-avatar--g0");
    expect(avatarGradientClass("07" + "11".repeat(31))).toBe("chat-avatar--g7");
    expect(avatarGradientClass("0f" + "11".repeat(31))).toBe("chat-avatar--g7");
    expect(avatarGradientClass("10" + "11".repeat(31))).toBe("chat-avatar--g0");
  });
  it("falls back to g0 on malformed input", () => {
    expect(avatarGradientClass("")).toBe("chat-avatar--g0");
    expect(avatarGradientClass("zz")).toBe("chat-avatar--g0");
  });
});
```

Run `npm run test:run -- avatarColor` first: expect FAIL (module missing). Then implement `avatarColor.ts`:

```typescript
/// Deterministic warm-gradient class for an agent id avatar. The eight
/// gradients are theme-invariant identity colors (same rationale as the
/// QR export card's baked palette).
export function avatarGradientClass(agentId: string): string {
  const byte = Number.parseInt(agentId.slice(0, 2), 16);
  const idx = Number.isFinite(byte) ? byte % 8 : 0;
  return `chat-avatar--g${idx}`;
}
```

Run the test again: expect PASS.

- [ ] **Step 2: Gradient classes in `chat/styles.css`** (identity literals sanctioned by the plan header):

```css
/* Deterministic identity gradients (theme-invariant, like the QR card). */
.chat-avatar--g0 { background: linear-gradient(135deg, #c9732b, #8a4a16); }
.chat-avatar--g1 { background: linear-gradient(135deg, #d9a440, #9a6b1a); }
.chat-avatar--g2 { background: linear-gradient(135deg, #56b292, #2e6e57); }
.chat-avatar--g3 { background: linear-gradient(135deg, #c2553e, #7e2f1f); }
.chat-avatar--g4 { background: linear-gradient(135deg, #a8743a, #6b4520); }
.chat-avatar--g5 { background: linear-gradient(135deg, #8a5a62, #54323a); }
.chat-avatar--g6 { background: linear-gradient(135deg, #8fae56, #5a7330); }
.chat-avatar--g7 { background: linear-gradient(135deg, #6e86a8, #3e4f68); }
.chat-avatar--g0 .chat-conv__avatar-initials, .chat-avatar--g1 .chat-conv__avatar-initials,
.chat-avatar--g2 .chat-conv__avatar-initials, .chat-avatar--g3 .chat-conv__avatar-initials,
.chat-avatar--g4 .chat-conv__avatar-initials, .chat-avatar--g5 .chat-conv__avatar-initials,
.chat-avatar--g6 .chat-conv__avatar-initials, .chat-avatar--g7 .chat-conv__avatar-initials {
  color: #f5f2eb;
}
```

Read `sidebar.ts` for the avatar element + initials class names FIRST and adapt the initials selector to the real class (the above assumes `.chat-conv__avatar-initials`; if initials are direct text content of the avatar element, instead set `color: #f5f2eb;` inside each `--g*` rule). Wire `avatarGradientClass(agentId)` onto the avatar element in `sidebar.ts`, and onto the profile card's avatar placeholder box in `profileCard.ts` (only when no image has loaded). Keep existing sidebar tests green; extend one sidebar test to assert an avatar element carries a `chat-avatar--g` class if straightforward, otherwise rely on avatarColor tests.

- [ ] **Step 3: Panel + sidebar treatments.** `.chat-panel__header` (read actual class names): `background-image: var(--surface-grad); box-shadow: var(--edge-highlight);`. Sidebar conv rows: hover `background: color-mix(in srgb, var(--copper) 6%, transparent);` (replace any white tint), active row keeps the copper strip and adds `background: linear-gradient(90deg, color-mix(in srgb, var(--copper) 10%, transparent), transparent 70%);`. Unread badge: `background: var(--gold); color: var(--ink);` (kills `rgb(220,50,47)` + `#fff`). The header unread dot on `#chat-toggle` likewise goes gold.

- [ ] **Step 4: Bubbles + composer.** Outbound bubble: `background: linear-gradient(180deg, var(--copper-bright), var(--copper) 82%);` keep radius/tail; inbound bubble adds `box-shadow: var(--edge-highlight);`. Failed-status text `rgb(255,120,120)` becomes `var(--rust)` (all three occurrences). Composer textarea focus adds `box-shadow: var(--focus-ring);`; send button gets the gradient-button treatment (Task 2 Step 3 values, radius 8px stays).

- [ ] **Step 5: Dialogs + pickers + profile card.** Add a dialog-panel enter animation:

```css
@keyframes chat-panel-enter {
  from { opacity: 0; transform: translateY(6px) scale(0.985); }
  to { opacity: 1; transform: none; }
}
```

Apply `animation: chat-panel-enter var(--dur-trans) var(--ease-out-expo);` + `box-shadow: var(--elev-3), var(--edge-highlight); background-image: var(--surface-grad);` to `.chat-dialog__panel` and `.chat-profile__panel`. Dialog `h2`/title rows: `font: 400 18px/1.3 var(--font-display);`. Style `newGroup`'s bare controls (read `newGroup.ts` for exact classes):

```css
.chat-dialog__fieldset {
  border: 1px solid var(--line);
  border-radius: var(--r-ctl);
  padding: 10px 12px;
  margin: 0;
}
.chat-dialog__radio { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
.chat-dialog__radio input[type="radio"] { accent-color: var(--copper); }
```

Emoji picker: `box-shadow: var(--elev-2), var(--edge-highlight); border-radius: var(--r-card);`; cell hover becomes `color-mix(in srgb, var(--copper) 12%, transparent)`. Profile card: name `font: 400 20px/1.25 var(--font-display);`, avatar fallback box gets the gradient class (Step 2), link chips hover adds `border-color: var(--gold); color: var(--gold-bright); background: color-mix(in srgb, var(--gold) 10%, transparent);`. `unavailableCard` styles: replace the entire fallback-var palette with tokens (`var(--rust)` left accent, `var(--ink-2)` panel, `var(--bone)`/`var(--ash)` text); the blue accent must not survive. Outbox banner + notices: replace `rgba(201,115,43,x)` literals with `color-mix(in srgb, var(--copper) X%, transparent)` equivalents (12->12%, 18->18%, 35->35%).

- [ ] **Step 6: Gates + commit.**

```bash
cd /home/josh/Desktop/fetchit/apps/fetchit-desktop
npx tsc --noEmit >/tmp/ts.log 2>&1; echo "TSC=$?"
npm run test:run >/tmp/vt.log 2>&1; echo "VITEST=$?"
grep -E "Tests  " /tmp/vt.log | tail -1
cd /home/josh/Desktop/fetchit
git add apps/fetchit-desktop/src/chat
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "style(desktop): chat warmth pass (identity avatars, gold badges, dialog depth)"
```

---

## Task 6: Fediverse + QR modal + literal-to-token sweep

**Files:** Modify `apps/fetchit-desktop/src/fediverse/styles.css`, `apps/fetchit-desktop/src/styles.css`.

- [ ] **Step 1: Fediverse.** `.feed-post`: `background-image: var(--surface-grad); box-shadow: var(--edge-highlight); transition: border-color var(--dur-micro), transform var(--dur-micro), box-shadow var(--dur-micro);` hover: `transform: translateY(-1px); box-shadow: var(--elev-1), var(--edge-highlight); border-color: color-mix(in srgb, var(--copper) 35%, var(--line));`. Compose buttons get the gradient-button treatment; header pane title may take `var(--font-display)` 18px if a title element exists (read the file).

- [ ] **Step 2: QR modal.** Title input font-family becomes `var(--font-display)` (now actually loads). Card: `box-shadow: var(--elev-3);` replacing its hardcoded shadow. Backdrop `rgba(26,24,20,0.55)` becomes `color-mix(in srgb, var(--ink) 60%, transparent)`. Keep its white QR area + light card (deliberate).

- [ ] **Step 3: Literal sweep in `src/styles.css` + `chat/styles.css`.** Convert remaining decorative literals to tokens or color-mix: suggestion-dropdown shadow (now elev-2, done in T2), `.self-contained-badge` background to `color-mix(in srgb, var(--ink) 82%, transparent)`, EPUB TOC hover `rgba(184,115,51,0.06)` to `color-mix(in srgb, var(--copper) 7%, transparent)`, inline-code chip `rgba(255,255,255,0.08)` to `color-mix(in srgb, var(--bone) 9%, transparent)`. DO NOT touch: `#000` video backdrop, `#fff`/white content surfaces (QR area, PDF pages, EPUB iframe), qr.ts baked SVG palette, avatar identity gradients.

- [ ] **Step 4: Gates + commit.**

```bash
git add apps/fetchit-desktop/src/fediverse/styles.css apps/fetchit-desktop/src/styles.css apps/fetchit-desktop/src/chat/styles.css
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "style(desktop): fediverse cards, QR serif title, literal-to-token sweep"
```

---

## Task 7: Final gates + theme walkthrough + push

- [ ] **Step 1: Full sweep** (root untouched by this stack but run as the stack gate):

```bash
cd /home/josh/Desktop/fetchit
cargo fmt --all --check >/tmp/f.log 2>&1; echo "ROOT_FMT=$?"
cargo clippy --workspace --all-targets -- -D warnings >/tmp/c.log 2>&1; echo "ROOT_CLIPPY=$?"
(cd apps/fetchit-desktop && npx tsc --noEmit >/tmp/ts.log 2>&1; echo "TSC=$?"; npm run test:run >/tmp/vt.log 2>&1; echo "VITEST=$?"; grep -E "Tests  " /tmp/vt.log | tail -1)
```

Expected: all 0.

- [ ] **Step 2: Build check.** `cd apps/fetchit-desktop && npx vite build >/tmp/vb.log 2>&1; echo "VITE=$?"` Expected 0 (verifies the font assets resolve in a production build).

- [ ] **Step 3: Theme walkthrough.** Grep-verify every new token is defined in all three theme blocks (`grep -c -- "--gold:" src/styles.css` returns 3, same for `--elev-1`, `--edge-highlight`, `--surface-grad`, `--signal-ok` unchanged count) and that no `#4f8cff` / `rgb(220,50,47)` / `rgb(255,120,120)` / `#6ab04c` survive anywhere under `apps/fetchit-desktop/src/`. Manual dev-shell walkthrough (dark/dim/light) is Josh's acceptance; note it in the report, do not block on it.

- [ ] **Step 4: Push.**

```bash
git push josh-clsn chat >/tmp/push.log 2>&1; echo "PUSH=$?"
```

---

## Self-Review

- Spec coverage: tokens v2 incl. retune (T1) = spec section 3; serif + scale (T1/T4/T5/T6) = section 4; base layer grain/selection/scrollbars/focus/reduced-motion (T1) = sections 3+5; shell (T2), stage (T3), settings+onboarding (T4), chat incl. avatars+gold badge+unavailable rescue (T5), fediverse+QR+sweep (T6) = section 5 phase list; constraints honored in the hard-rules header (renderer content untouched, no backdrop-filter additions, reduced-motion, three themes) = section 6; gates per task + final sweep (T7) = section 7.
- No placeholders: every CSS step carries exact properties/values; TS steps carry full code; the two "read the file first" hedges (initials class name, empty-state hook) specify the exact fallback behavior.
- Type consistency: `avatarGradientClass` name identical in test, impl, and wiring steps; token names identical across all tasks and BRAND.md step.
