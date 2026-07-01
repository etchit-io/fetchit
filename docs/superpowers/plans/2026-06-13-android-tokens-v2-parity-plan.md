# fetch>it Android -- tokens v2 (oxidation palette + serif) parity Plan

**Goal:** Bring the fetch>it Android shell's theme up to the desktop's
"tokens v2 / oxidation palette" (Alice, `9c0424b` + the warmth stack on
`chat`), so the two surfaces read as one brand.

**Architecture:** Android theming is attribute-based -- `res/values/attrs.xml`
declares `fetchit*` color attrs, `res/values/themes.xml` assigns per-theme
values (Dark/Dim/Light), layouts read `?attr/fetchitX`. This mirrors the
desktop's `:root` / `body[data-theme]` blocks. Canonical values: `docs/BRAND.md`
on `chat` @ `e43bbfc`.

**Branch:** `android-tokens-v2` off `android-lit`. **Lane:** [B] Bob.
**Scope (Josh, 2026-06-13):** palette + serif. Skip desktop-only grain /
edge-highlight / copper focus-ring / hover-lift -- non-idiomatic on touch
(Material3 ripple already covers press; no hover or persistent focus on a phone).

---

## What changes (and what is already correct)

Android Dark and Light already match desktop for ink/bone/line/copper/rust;
the only palette gaps are the **lime `signalOk`**, the **missing gold**, and
the **Dim theme** (a near-dark warm ink, not the new warm-dusk mid-tone).

### Color mapping (byte-identical to BRAND.md v2)

| Token | Dark | Dim | Light | Note |
|---|---|---|---|---|
| `fetchitSignalOk` | `#6ab04c` -> `#56b292` | `#6ab04c` -> `#56b292` | `#3d7e2c` -> `#2f7e62` | lime -> patina (kills the off-brand green Alice replaced) |
| `fetchitGold` (new) | `#d9a440` | `#d9a440` | `#a87a1f` | gilded highlight |
| `fetchitGoldBright` (new) | `#e8bc62` | `#e8bc62` | `#8f6512` | gold hover |

### Dim -> "warm dusk" (L~=20%, a real step between Dark and Light)

| Token | old (near-dark) | new (warm-dusk) |
|---|---|---|
| `fetchitInk`     | `#1a1612` | `#3a322a` |
| `fetchitInk2`    | `#221d18` | `#443c33` |
| `fetchitInk3`    | `#2a241e` | `#4e463c` (*) |
| `fetchitLine`    | `#2a2520` | `#524a40` |
| `fetchitBoneDim` | `#e6dfd0` | `#d9d2c4` |

`fetchitBone`/`fetchitAsh`/`fetchitCopper`/`fetchitCopperBright`/`fetchitRust`
in Dim already equal the desktop warm-dusk values -- unchanged.

(*) **`fetchitInk3` is Android-only** (desktop has no `--ink-3`). The new
value continues the warm-dusk ramp one ~`0x0a` step above `ink2` -- a local
extrapolation, not from BRAND.md.

### Tokyo-Night cleanup

`colors.xml` `status_green #9ece6a` / `status_red #f7768e` are **orphaned**
(zero `@color/status_*` refs in the tree; only a stale comment in `Syntax.kt`,
which is content-syntax highlighting -- out of scope, left alone). Remove both.

### gold has no consumer yet

No unread badge / "special" surface exists in the current LIT layouts, so
`fetchitGold` lands as a palette token only (contract parity per BRAND.md
"add a token everywhere"). First consumers when built: unread badge, gilded
highlights. Not painted onto any surface this pass.

## Serif (display moments only)

Bundle Instrument Serif (OFL), used ONLY for display moments; body chrome
stays monospace (Android's deliberate terminal aesthetic).

- **Provenance:** converted from the *exact* woff2 the desktop vendors
  (`e43bbfc:apps/fetchit-desktop/src/assets/fonts/InstrumentSerif-*.woff2`)
  via fonttools in an isolated venv -- no fresh external binary. License
  ships at `app/src/main/assets/fonts/OFL.txt` (copied from desktop).
- `res/font/instrument_serif_regular.ttf` + `instrument_serif_italic.ttf` +
  `instrument_serif.xml` (font-family: normal->regular, italic->italic;
  native `android:` namespace, minSdk 26).
- Apply `@font/instrument_serif` to the two display moments that exist:
  - `dialog_qr_preview.xml` `qr_title` (keep `textStyle="italic"` -> italic face).
    Spec explicitly calls out the QR-card title for the bundled serif.
  - `view_chat_list.xml` `chat_empty_hint` (add `textStyle="italic"`) -- the
    empty-state tagline.

## Files

- `res/values/attrs.xml` -- add `fetchitGold`, `fetchitGoldBright`.
- `res/values/themes.xml` -- per table above (3 themes).
- `res/values/colors.xml` -- remove the two Tokyo-Night strays.
- `res/font/instrument_serif{_regular,_italic}.ttf` + `instrument_serif.xml`.
- `app/src/main/assets/fonts/OFL.txt`.
- `res/layout/dialog_qr_preview.xml`, `res/layout/view_chat_list.xml`.

## Gates

- `./gradlew :app:assembleDebug` (aapt validates attrs/themes/font refs +
  Kotlin compiles) -- the load-bearing automated gate for declarative theme
  resources. `ThemeTest` stays green (no `Theme` enum logic change).
- Final **visual** acceptance = theme triple-walkthrough on device (Josh
  eyeball), consistent with the desktop pass. Device spin currently deferred
  by Josh; build-level gate covers correctness in the meantime.

## Coordination

Values are byte-identical to Alice's BRAND.md v2. BRAND.md currently tracks
the two desktop apps + "etch/it port pending"; Android is a third (attr-based)
surface. Do NOT edit BRAND.md unilaterally -- propose an Android column to
Alice (she owns the contract). etch/it-android parity = separate follow-up.
