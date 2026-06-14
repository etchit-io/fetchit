# Doc-Drift Prevention -- Phase 2 Implementation Plan

> Owner-executed (Bob). Spec: `fetchit-ops/docs/doc-drift-prevention-design.md` (Phase 2). Cross-review: Alice (hardest on desktop / reader / chat-client sections -- her lane). Gate: Box B (t8b worktree, branch `phase2-doc-prevention` off chat `c9bf634`). Push: I push to josh-clsn; Alice FF-merges.

**Goal:** The lean tracked architecture reference + the gates that keep it honest. ARCHITECTURE.md FIRST (the detector stamps + checks it), then the staleness detector, then the pin-version assert.

**Constraint:** never cargo build/test in the main `fetchit/` checkout; all cargo runs `--manifest-path <t8b>/Cargo.toml`. No em-dashes (`--`). DCO `-s`.

---

## Piece 1: `docs/ARCHITECTURE.md` -- the LEAN tracked source

**The anti-goal:** the old 1428-line `REFERENCE.md` was the drift surface BECAUSE it duplicated code (exhaustive file/type/variant lists, `file:NN-MM` line citations). Phase 1's tripwires + crate-list now LOCK those facts. So ARCHITECTURE.md must NOT restate them -- it carries only what code/tests cannot: the **why/how + the seams**, with **links** to the asserted facts.

**Source to distill from:** the current CODE (truth, in the worktree) + the existing `/home/josh/Desktop/etchit-fetchit/REFERENCE.md` prose (the rationale is mostly still valid; verify every specific against code). Do NOT paste REFERENCE.md sections -- distill.

**Per-section template (hard leanness budget: aim <= ~12 lines/section, prose <= ~5 sentences):**

```markdown
## <Section name>

<2-5 sentences: what it is, its ROLE + the SEAMS to other crates, and the
load-bearing design decisions / invariants. The WHY and HOW. No file lists.>

**Key entry points:** `crate::module::Symbol`, `crate::module::Other` -- by
symbol, NEVER line numbers (line numbers are a drift generator).
**Locked by:** <links to the L1 assertions that hold this section's facts, e.g.
"handler set + order: `crates/fetchit-core/tests/doc_invariants.rs`"; "crate
list: `docs/generated/crate-list.txt`">. Omit if none.

<!-- arch: id=<kebab-id> glob=<repo-relative path glob> verified=<chat-sha> -->
_Last verified: <YYYY-MM-DD> (`<sha>`) -- <owner>._
```

**Rules:** (a) no exhaustive type/variant/file enumerations -- link to the tripwire/crate-list instead; (b) cite by symbol, as rustdoc-style backticked paths, never `file:line`; (c) every section ends with the machine-readable `<!-- arch: ... -->` stamp (the detector parses `id`/`glob`/`verified`) + the human stamp line; (d) WithAutonomi is upstream for ant-core, not maidsafe.

**Sections (the fetchit-architecture slice; box-local workspace-layout + sibling-repo notes deliberately EXCLUDED -- they are not fetchit code and re-create the cross-repo drift trap):**
1. Overview -- the engine + backend + shells shape; the read-in-this-order onboarding; the read-only / no-wallet invariant.
2. fetchit-core (engine) -- glob `crates/fetchit-core/**`
3. fetchit-net (Autonomi backend) -- glob `crates/fetchit-net/**`
4. fetchit-ffi (uniffi) -- glob `crates/fetchit-ffi/**`
5. fetchit-cli -- glob `crates/fetchit-cli/**`
6. fetchit-chat -- glob `crates/fetchit-chat/**`
7. fetchit-relay-proto -- glob `crates/fetchit-relay-proto/**`
8. fetchit-relay-server -- glob `crates/fetchit-relay-server/**`
9. fetchit-relay-client -- glob `crates/fetchit-relay-client/**`
10. fetchit-trust (+ -types / -client) -- glob `crates/fetchit-trust*/**`
11. x0xd-client -- glob `crates/x0xd-client/**`
12. fetchit-fedi -- glob `crates/fetchit-fedi/**`
13. Android shell -- glob `apps/fetchit-android/**`
14. Desktop shell (Tauri 2) -- glob `apps/fetchit-desktop/**`
15. Browser extension -- glob `apps/fetchit-web/**`
16. CI / release -- glob `.github/workflows/**`
17. Production invariants -- (cross-cutting; no single glob -- omit the machine stamp or glob `crates/** apps/**`, human stamp only)
18. Pinned dependencies -- glob `PINS.md Cargo.lock` (links to the Phase-2 pin assert)

**Header:** purpose + truth-rules (symbol citations; link-not-restate; the stamp/detector contract; private/strategic content never here).

**Gate:** `sh scripts/check-doc-paths.sh` clean (paths/symbols resolve) + `sh scripts/check-stale-phrases.sh <base>` clean (no expiring markers) + manual leanness pass (no fact-dump sections). Commit `docs: lean ARCHITECTURE.md (tracked architecture reference, Phase 2)`.

---

## Piece 2: `scripts/check-arch-stamps.sh` -- commit-aware staleness detector (simple v1)

Parse each `<!-- arch: id=.. glob=.. verified=.. -->` stamp in `docs/ARCHITECTURE.md`. For each, run `git log --oneline <verified>..HEAD -- <glob>`; if non-empty, WARN that section may be stale (its covered files changed since its last-verified commit). Simple v1: section-path-glob granularity, NOT precise cited-file mapping. Exit non-zero only in a `--strict` mode (default: warn + exit 0, so it informs without blocking until adopted); the milestone-close sweep (L4) consumes the warnings to target re-verification. Actionable message names the section id + the changed files + "re-verify + bump the stamp." Add to ci.yml `docs-gates` as a non-failing informational step for now (`|| true` or `--warn`). Commit separately.

**Test:** stamp a fake section at an old SHA with a glob that has since changed -> warns; bump verified to HEAD -> silent.

---

## Piece 3: pin-version assert -- `scripts/check-pins.sh` extension OR a test

The repo already has `scripts/check-pins.sh` (PINS.md drift, run in the `pins` CI job). Confirm it already covers ant-core rev + uniffi pin + self_encryption/xor_name == Cargo.toml/Cargo.lock; if it does, Phase 2's "pin assert" is ALREADY satisfied -- document that + add any missing pin (e.g. uniffi `=` version) to it. If a gap exists, extend `check-pins.sh` (actionable failure naming the drifted pin + the fix). Do NOT duplicate it as a new script. Commit separately.

**Self-review note:** verify check-pins.sh's current coverage FIRST (read it) before writing anything -- this piece may largely reduce to "confirm + close any gap," honoring derive-not-duplicate.

---

## Order + handoff
ARCHITECTURE.md -> push -> Alice reviews (her-lane sections hardest) -> then detector -> then pin assert. Each piece its own commit; gate on Box B; I push to josh-clsn; Alice FF-merges. The detector + pin-assert wire into the existing `docs-gates` / `pins` CI jobs.
