#!/usr/bin/env sh
# Emit the sorted workspace member crate names. Single source = cargo metadata.
# Runs against the repo that contains this script (cd to repo root first), so it
# never depends on the caller's cwd.
set -eu
dir="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
cd "$dir"
cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[].name' \
  | sort
