# Doc-Drift Prevention -- Phase 1 (CI core) Implementation Plan

> **For agentic workers:** owner-executed (Bob). Steps use `- [ ]` tracking. Spec: `fetchit-ops/docs/doc-drift-prevention-design.md`. Cross-review: Alice (separate review per commit). Gate: Box B (t8b worktree). FF-merge: Alice.

**Goal:** Add the cheap CI core that makes a class of doc-drift impossible to land: broken intra-doc links, expiring "Stage-N/scaffolding" markers on new code, and silent handler/enum/crate-list drift.

**Architecture:** Three kinds of guard, all in the fetchit repo. (a) **Tripwire tests** that lock code shape to a checked-in snapshot and fail with an actionable message naming the fix. (b) **CI scripts** (`scripts/`) wired into `.github/workflows/ci.yml`: a *diff* stale-phrase linter (only new/changed doc-comments, so no historical scrub needed) and a doc-path existence check. (c) **`cargo doc -D warnings`** + **doctests** added as CI jobs, preceded by a bounded broken-link scrub of the crates the doc-fleet never covered (`fetchit-trust*`, `fetchit-relay-client`, `fetchit-cli`).

**Tech Stack:** GitHub Actions YAML, POSIX `sh` + `git` for the linters, Rust `#[test]` for the tripwires, `cargo doc` / `cargo test --doc`.

**Constraint:** never `cargo build/test/doc` in the main `fetchit/` checkout (comms daemon). All builds/gates run in the `fetchit-t8b-test` worktree (branch `phase1-doc-prevention`, off chat `76b027f`).

**Commit discipline:** the broken-link **scrub** (Task 6a) is a SEPARATE commit from the gate-adds, so Alice reviews it on its own (her call). DCO `-s` on every commit.

---

## File structure

| Path | Create/Modify | Responsibility |
|---|---|---|
| `crates/fetchit-core/tests/doc_invariants.rs` | Create | tripwire: handler kinds+order == `default_registry()`; `Rendition` variant set |
| `crates/fetchit-relay-proto/tests/doc_invariants.rs` | Create | tripwire: `EnvelopeKind` variant set |
| `scripts/gen-crate-list.sh` | Create | emit sorted workspace member list from `cargo metadata` |
| `scripts/check-crate-list.sh` | Create | assert `docs/generated/crate-list.txt` == `gen-crate-list.sh` output |
| `docs/generated/crate-list.txt` | Create | the derived crate list (the single source docs reference) |
| `scripts/check-stale-phrases.sh` | Create | diff linter: fail on expiring markers in ADDED `//!`/`///` non-test lines |
| `scripts/check-doc-paths.sh` | Create | fail when a doc-comment cites a repo path that no longer exists |
| `.github/workflows/ci.yml` | Modify | add `docs-gates` job: crate-list, stale-phrases, doc-paths, `cargo doc -D warnings`, doctests |
| (various crates) | Modify | Task 6a scrub: fix broken intra-doc links so `cargo doc -D warnings` is green |

---

## Task 1: Handler + Rendition tripwire (fetchit-core)

**Files:** Create `crates/fetchit-core/tests/doc_invariants.rs`

- [ ] **Step 1: Write the test** (it both documents and locks the registry shape)

```rust
//! Tripwire tests: lock the public shapes that docs describe, so a change
//! to the code forces a conscious doc update. If one fails, update BOTH the
//! snapshot here AND the architecture doc that lists it.

use fetchit_core::handlers::default_registry;

#[test]
fn handler_kinds_and_order_match_snapshot() {
    // The order is load-bearing (ties break by registration order). If you
    // add/remove/reorder a handler, update this snapshot AND docs/ARCHITECTURE.md.
    let expected = [
        "envelope", "image", "audio", "video", "zip", "html", "json", "csv",
        "markdown", "text", "binary",
    ];
    let actual: Vec<&str> = default_registry().handler_kinds().collect();
    assert_eq!(
        actual, expected,
        "handler set/order changed: update the snapshot in this test AND the \
         handler list in docs/ARCHITECTURE.md"
    );
}
```

- [ ] **Step 2: Check `handler_kinds()` exists; if not, add a minimal accessor**

Run: `grep -rn "fn handler_kinds\|fn kind" crates/fetchit-core/src/`
If `HandlerRegistry` exposes no ordered-kind accessor, add to `crates/fetchit-core/src/registry.rs`:

```rust
impl HandlerRegistry {
    /// Kinds in registration order. Used by the doc-invariant tripwire test.
    pub fn handler_kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.handlers.iter().map(|h| h.kind())
    }
}
```
(Confirm `ContentHandler::kind() -> &'static str` exists -- it does per the engine contract. Match the real field name for the handler vec.)

- [ ] **Step 3: Run -- expect PASS once `expected` matches `default_registry()`**

Run (in worktree): `cargo test -p fetchit-core --test doc_invariants 2>&1 | tail -20`
Expected: PASS. If it fails, the snapshot is the source of truth for *current* code -- set `expected` to the actual order printed, do NOT invent it.

- [ ] **Step 4: Add the `Rendition` variant tripwire to the same file**

```rust
#[test]
fn rendition_variants_match_snapshot() {
    // Exhaustive match: adding a Rendition variant breaks compilation here,
    // forcing a doc update. Keeps docs/ARCHITECTURE.md's variant list honest.
    fn _assert(r: &fetchit_core::Rendition) {
        use fetchit_core::Rendition::*;
        match r {
            Text { .. } | Image { .. } | Audio { .. } | Video { .. } | Pdf { .. }
            | Json { .. } | Tabular { .. } | Archive { .. } | Html { .. }
            | EtchitEnvelope { .. } | OpaqueBinary { .. } | Blocked { .. } => {}
        }
    }
}
```
(An exhaustive `match` with no `_` arm is the tripwire: a new variant is a compile error here. Confirm the variant set against `handler.rs` before writing -- it currently includes `Blocked`.)

- [ ] **Step 5: Run + commit**

Run: `cargo test -p fetchit-core --test doc_invariants 2>&1 | tail -20` (PASS)
```bash
git add crates/fetchit-core/tests/doc_invariants.rs crates/fetchit-core/src/registry.rs
git commit -s -m "test(core): doc-invariant tripwires for handler order + Rendition variants"
```

---

## Task 2: EnvelopeKind tripwire (fetchit-relay-proto)

**Files:** Create `crates/fetchit-relay-proto/tests/doc_invariants.rs`

- [ ] **Step 1: Write the exhaustive-match tripwire**

```rust
//! Tripwire: a new EnvelopeKind variant is a compile error here, forcing a
//! conscious doc update (docs/ARCHITECTURE.md envelope-kinds list).

#[test]
fn envelope_kinds_locked() {
    fn _assert(k: &fetchit_relay_proto::EnvelopeKind) {
        use fetchit_relay_proto::EnvelopeKind::*;
        match k {
            // Update this match AND docs/ARCHITECTURE.md when adding a kind.
            // (Fill from the real enum: e.g. Dm, GroupChat, ..., Reserved6,
            //  Reserved7, PublicPost, Unknown(_).)
            _ => {}
        }
    }
}
```

- [ ] **Step 2: Replace the `_ => {}` with the REAL exhaustive arm**

Run: `grep -n "pub enum EnvelopeKind" -A40 crates/fetchit-relay-proto/src/envelope.rs`
Write every variant explicitly (no `_`), so a new variant fails compilation. `Unknown(_)` is a real variant -- include it.

- [ ] **Step 3: Run + commit**

Run: `cargo test -p fetchit-relay-proto --test doc_invariants 2>&1 | tail -20` (PASS)
```bash
git add crates/fetchit-relay-proto/tests/doc_invariants.rs
git commit -s -m "test(relay-proto): doc-invariant tripwire for EnvelopeKind variants"
```

---

## Task 3: Crate-list derive + check (scripts)

**Files:** Create `scripts/gen-crate-list.sh`, `scripts/check-crate-list.sh`, `docs/generated/crate-list.txt`

- [ ] **Step 1: Write the generator**

```sh
#!/usr/bin/env sh
# Emit the sorted workspace member crate names. Single source = cargo metadata.
set -eu
cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[].name' \
  | sort
```

- [ ] **Step 2: Write the checker (actionable failure)**

```sh
#!/usr/bin/env sh
set -eu
dir="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
want="$dir/docs/generated/crate-list.txt"
got="$(sh "$dir/scripts/gen-crate-list.sh")"
if ! printf '%s\n' "$got" | diff -u "$want" - ; then
  echo "ERROR: docs/generated/crate-list.txt is out of sync with cargo metadata." >&2
  echo "FIX: run  scripts/gen-crate-list.sh > docs/generated/crate-list.txt  and commit." >&2
  exit 1
fi
```

- [ ] **Step 3: Generate the baseline + make executable**

Run (in worktree):
```bash
chmod +x scripts/gen-crate-list.sh scripts/check-crate-list.sh
mkdir -p docs/generated
sh scripts/gen-crate-list.sh > docs/generated/crate-list.txt
sh scripts/check-crate-list.sh && echo "check OK"
```
Expected: "check OK".

- [ ] **Step 4: Commit**

```bash
git add scripts/gen-crate-list.sh scripts/check-crate-list.sh docs/generated/crate-list.txt
git commit -s -m "ci(docs): derive workspace crate list from cargo metadata + drift check"
```

---

## Task 4: Stale-phrase DIFF linter

**Files:** Create `scripts/check-stale-phrases.sh`

- [ ] **Step 1: Write the diff linter** (lints only ADDED doc-comment lines vs a base ref; conservative phrase set; `stale-ok:` escape)

```sh
#!/usr/bin/env sh
# Fail if a CHANGED doc-comment (//! or ///) in non-test Rust introduces an
# expiring marker. Lints the diff vs $1 (base ref), so historical comments are
# untouched -- prevention, not cleanup. Escape one line with `stale-ok: <why>`.
set -eu
base="${1:-origin/chat}"
# Conservative starter set (extend only after proving low false-positive):
pat='lands.next.milestone|does(n.t| not) exist today|scaffolding|Stage [0-9]|C[45][[:space:]]|C[45]-scaffold'
fail=0
# Added lines only (+), with file headers, no context.
git diff --unified=0 "$base"...HEAD -- '*.rs' ':(exclude)**/tests/**' \
  | awk '
      /^\+\+\+ b\// { file=substr($0,7); next }
      /^@@/ {
        # @@ -a,b +c,d @@  -> next added line number is c
        match($0, /\+[0-9]+/); ln=substr($0,RSTART+1,RLENGTH-1)+0; next
      }
      /^\+/ && !/^\+\+\+/ { print file ":" ln "\t" substr($0,2); ln++ }
    ' \
  | while IFS="$(printf '\t')" read -r loc line; do
      case "$line" in *"stale-ok:"*) continue;; esac          # explicit escape
      case "$line" in *"//!"*|*"///"*) : ;; *) continue;; esac  # doc-comments only
      if printf '%s' "$line" | grep -qiE "$pat"; then
        echo "STALE-PHRASE: $loc : $line" >&2
        fail=1
      fi
    done
if [ "$fail" -ne 0 ]; then
  echo "ERROR: new doc-comments introduce expiring markers (see above)." >&2
  echo "FIX: describe current state, not a milestone; or annotate the line with 'stale-ok: <reason>'." >&2
  exit 1
fi
```

- [ ] **Step 2: Prove it fails on a planted violation, passes when removed**

Run (in worktree):
```bash
chmod +x scripts/check-stale-phrases.sh
printf '\n/// Stage 9 lands the thing later\npub fn _drift_probe() {}\n' >> crates/fetchit-core/src/lib.rs
sh scripts/check-stale-phrases.sh origin/chat; echo "rc=$?"   # expect STALE-PHRASE + rc=1
git checkout -- crates/fetchit-core/src/lib.rs
sh scripts/check-stale-phrases.sh origin/chat; echo "rc=$?"   # expect rc=0
```
Expected: first run prints `STALE-PHRASE: ... rc=1`; second `rc=0`.

- [ ] **Step 3: Prove the `stale-ok:` escape works**

Run:
```bash
printf '\n/// scaffolding stale-ok: legacy note kept intentionally\npub fn _drift_probe2() {}\n' >> crates/fetchit-core/src/lib.rs
sh scripts/check-stale-phrases.sh origin/chat; echo "rc=$?"   # expect rc=0 (escaped)
git checkout -- crates/fetchit-core/src/lib.rs
```
Expected: `rc=0`.

- [ ] **Step 4: Commit**

```bash
git add scripts/check-stale-phrases.sh
git commit -s -m "ci(docs): diff stale-phrase linter (new doc-comments only, stale-ok escape)"
```

---

## Task 5: Doc-path existence check

**Files:** Create `scripts/check-doc-paths.sh`

- [ ] **Step 1: Write the checker** (flag doc-comments citing a repo-relative path that no longer exists)

```sh
#!/usr/bin/env sh
# Flag doc-comments that cite a repo path which no longer exists. Matches
# `path/to/file.ext` tokens inside //! or /// lines for known repo extensions.
set -eu
dir="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
cd "$dir"
fail=0
# doc-comment lines, extract path-like tokens with a source/doc extension
grep -rnE '(//!|///)' --include='*.rs' crates/ apps/ 2>/dev/null \
  | grep -oE '[A-Za-z0-9_./-]+\.(rs|md|toml|sh|yml|kt|ts)' \
  | sort -u \
  | while read -r p; do
      case "$p" in
        http*|*"::"*) continue;; esac                 # urls / rust paths, skip
      [ -e "$dir/$p" ] && continue
      # tolerate bare filenames (no slash) -- too ambiguous to resolve
      case "$p" in */*) ;; *) continue;; esac
      echo "DOC-PATH MISSING: $p" >&2
      fail=1
    done
if [ "$fail" -ne 0 ]; then
  echo "ERROR: doc-comments cite repo paths that do not exist (see above)." >&2
  echo "FIX: update the path, or drop the citation." >&2
  exit 1
fi
```

- [ ] **Step 2: Run against current tree; record any existing hits**

Run: `sh scripts/check-doc-paths.sh; echo "rc=$?"`
If it flags EXISTING bad paths (likely a few in the uncovered crates), fix those citations in this task (small) OR, if many, move them to the Task 6a scrub commit. Goal: `rc=0`.

- [ ] **Step 3: Commit**

```bash
git add scripts/check-doc-paths.sh
git commit -s -m "ci(docs): doc-comment path-existence check"
```

---

## Task 6a: Broken intra-doc-link SCRUB (separate commit, uncovered crates)

**Files:** Modify (TBD by the scan) -- expect `fetchit-trust*`, `fetchit-relay-client`, `fetchit-cli`.

- [ ] **Step 1: Scope the scrub**

Run (in worktree):
```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features 2>&1 \
  | grep -E '^error|-->' | tee /tmp/p1-doclinks.txt
```
This lists every broken-link site. (Size unknown; Alice expects residue in the uncovered crates.)

- [ ] **Step 2: Fix each** -- demote private-item links to plain code spans (``` `Foo` ```), correct renamed-symbol links, fix cross-crate links not in scope. (Same pattern already applied to relay-server: `[`Priv`]` -> `` `Priv` ``.)

- [ ] **Step 3: Re-run until clean**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features 2>&1 | grep -E '^error' || echo CLEAN`
Expected: `CLEAN`.

- [ ] **Step 4: Commit the scrub ALONE** (Alice reviews separately)

```bash
git add -A
git commit -s -m "docs: fix pre-existing broken intra-doc links (uncovered crates) for the cargo-doc gate"
```

## Task 6b: cargo doc + doctest CI gate

**Files:** Modify `.github/workflows/ci.yml`

- [ ] **Step 1: Read the current CI to match its style/runner**

Run: `sed -n '1,60p' .github/workflows/ci.yml` (note the existing job names, toolchain action, cache).

- [ ] **Step 2: Add a `docs-gates` job** (mirror the existing job's checkout + toolchain + cache; then:)

```yaml
  docs-gates:
    name: doc drift gates
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # diff linter needs history
      - uses: dtolnay/rust-toolchain@stable
      - name: crate-list drift
        run: sh scripts/check-crate-list.sh
      - name: stale-phrase (changed doc-comments)
        run: sh scripts/check-stale-phrases.sh "origin/${{ github.base_ref || 'chat' }}"
      - name: doc-path existence
        run: sh scripts/check-doc-paths.sh
      - name: rustdoc (broken intra-doc links)
        run: RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
      - name: doctests
        run: cargo test --workspace --doc --all-features
```
(Match the repo's actual toolchain action if it is not `dtolnay`. `jq` is preinstalled on ubuntu-latest runners.)

- [ ] **Step 3: Dry-run each gate locally in the worktree**

Run: `cargo test --workspace --doc --all-features 2>&1 | tail -20`
If doctests fail (a doc example that does not compile), fix the example. Re-run until green.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -s -m "ci(docs): add doc-drift gates job (crate-list, stale-phrase, doc-path, rustdoc -D warnings, doctests)"
```

---

## Task 7: Final gate + hand off

- [ ] **Step 1: Full local gate in the worktree**

Run:
```bash
cargo fmt --all --check
cargo test -p fetchit-core -p fetchit-relay-proto --test doc_invariants
sh scripts/check-crate-list.sh && sh scripts/check-stale-phrases.sh origin/chat && sh scripts/check-doc-paths.sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features 2>&1 | grep -E '^error' || echo DOC-CLEAN
```
All green / `DOC-CLEAN`.

- [ ] **Step 2: Push branch + ping Alice with the SHAs**

```bash
git push -u origin phase1-doc-prevention
```
Ping Alice: scrub SHA (Task 6a) for separate review + the gate-add SHAs; she cross-reviews, Box B already gated, she FF-merges to chat.

---

## Self-review

- **Spec coverage:** (1) cargo doc -D warnings = T6b + scrub T6a. (2) doctests = T6b. (3) stale-phrase diff linter w/ conservative set + stale-ok = T4. (4) handler-list assert = T1. (5) enum-variants = T1 (Rendition) + T2 (EnvelopeKind). (6) crate-count/list = T3. (7) doc-path = T5. Actionable messages = every script + tripwire. Scrub split from gate = T6a separate commit. All covered.
- **Placeholder scan:** the only deliberately-deferred specifics are the EnvelopeKind exhaustive arm (T2 S2, filled from the real enum) and the scrub file set (T6a, sized by the scan) -- both have an exact command to resolve them, not a vague TODO.
- **Consistency:** tripwire snapshots reference `docs/ARCHITECTURE.md` (Phase 2) as the doc they protect -- correct forward reference; the tests pass standalone now (snapshot == code).
- **Ordering note:** run Task 5/6a path+link scans early; if either surfaces a LARGE residue, land it as its own commit and flag Alice before the gate-add (per the scrub-split agreement).
