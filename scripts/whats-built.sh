#!/usr/bin/env sh
# whats-built.sh <keyword...> -- answer "is this already built?" BEFORE scoping work.
#
# Searches the code-anchored capability ledger (docs/CAPABILITIES.md) first, then
# the actual code under crates/ and apps/. Run this before calling anything a gap,
# missing, or "to build" (see "Know what's already built" in CONTRIBUTING.md).
#
# CAVEAT: this only sees the CURRENT branch. A capability may live on an unmerged
# branch (e.g. android-lit). Also check `git branch -a` and ask the other box
# before concluding something is absent.
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)" || exit 1

[ "$#" -ge 1 ] || { echo "usage: $(basename "$0") <keyword...>" >&2; exit 2; }
kw="$*"

echo "== capability ledger (docs/CAPABILITIES.md) =="
if [ -f docs/CAPABILITIES.md ]; then
  hits="$(grep -in -- "$kw" docs/CAPABILITIES.md || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
  else
    echo "  (no ledger hits -- not proof of absence; check the code below)"
  fi
else
  echo "  (docs/CAPABILITIES.md missing)"
fi

echo
echo "== code (crates/ apps/, excluding target + node_modules) =="
if command -v rg >/dev/null 2>&1; then
  hits="$(rg -n --no-heading -S -g '!**/target/**' -g '!**/node_modules/**' -- "$kw" crates apps 2>/dev/null | head -50 || true)"
else
  hits="$(grep -rin --include='*.rs' --include='*.ts' --include='*.kt' -- "$kw" crates apps 2>/dev/null \
    | grep -v '/target/' | grep -v '/node_modules/' | head -50 || true)"
fi
if [ -n "$hits" ]; then
  printf '%s\n' "$hits"
else
  echo "  (no code hits on this branch)"
fi
