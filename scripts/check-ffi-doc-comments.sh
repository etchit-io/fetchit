#!/usr/bin/env bash
#
# Guard fetchit-ffi doc-comments against two patterns that silently break the
# generated uniffi Kotlin binding or violate house style. Both were real
# launch-blockers on 2026-06-15 (cheap to grep, expensive to hit):
#
#   1. A slash-star or star-slash inside a doc-comment (/// or //!).
#      uniffi-bindgen 0.29.5 copies exported-item doc-comments VERBATIM into
#      Kotlin /** ... */ block comments, so a nested slash-star opens an
#      unterminated comment and the WHOLE fetchit_ffi.kt fails to compile
#      ("Unclosed comment" -> cascading unresolved references across the app).
#      Reword the doc (e.g. drop a glob star: write /secure, not /secure-star).
#
#   2. An em-dash (U+2014) anywhere in the crate. The project uses -- instead;
#      uniffi surfaces doc em-dashes into the binding too.
#
# Run from the repo root (the docs-gates CI lane invokes it).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/crates/fetchit-ffi/src"

fail=0

# 1. slash-star / star-slash in doc-comment lines (/// or //!).
nested="$(grep -rnE '^[[:space:]]*(///|//!).*(/\*|\*/)' "$SRC" || true)"
if [ -n "$nested" ]; then
  echo "ERROR: slash-star or star-slash in a fetchit-ffi doc-comment -- this"
  echo "       breaks the generated uniffi Kotlin binding (Unclosed comment)."
  echo "       Reword the doc-comment:"
  echo "$nested"
  fail=1
fi

# 2. em-dash (U+2014) anywhere in the FFI source.
emdash="$(grep -rn "$(printf '\xe2\x80\x94')" "$SRC" || true)"
if [ -n "$emdash" ]; then
  echo "ERROR: em-dash (U+2014) in fetchit-ffi src -- use -- instead:"
  echo "$emdash"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "fetchit-ffi doc-comment lint FAILED"
  exit 1
fi
echo "fetchit-ffi doc-comment lint OK"
