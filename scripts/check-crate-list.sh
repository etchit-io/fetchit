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
