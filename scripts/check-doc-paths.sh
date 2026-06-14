#!/usr/bin/env sh
# Flag doc-comments that cite a repo-ROOT-relative path which no longer exists.
#
# Low false-positive by construction. A token is only treated as a repo-root
# citation when ALL of these hold:
#   - its FIRST path segment is a known top-level repo dir
#     (crates/ apps/ docs/ scripts/ .github/);
#   - it is not a URL and not a rust `::` path;
#   - its doc-comment line does not mark it as an external reference
#     (the word "upstream" on the line -> it lives in another repo).
# That anchor rejects the noisy majority for free:
#   - bare filenames (`lib.rs`, `PINS.md`)        -- no slash, not anchored
#   - crate-relative paths (`handlers/mod.rs`,    -- first segment is not a
#     `src/handler.rs`, `tests/integration.rs`)      top-level repo dir
#   - upstream / OS path illustrations            -- (`config/...`, `XDG_*/...`,
#                                                     x0xd `docs/...` upstream)
set -eu
dir="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
cd "$dir"

# One token per line for every doc-comment line, EXCEPT lines that declare the
# path is external ("upstream"). awk owns the filtering so the result survives
# the pipe (no subshell-scoped flag); the parent then decides pass/fail.
missing="$(
  grep -rhnE '(//!|///)' --include='*.rs' crates/ apps/ 2>/dev/null \
  | awk '
      /[Uu]pstream/ { next }            # external reference, not a repo path
      {
        while (match($0, /[A-Za-z0-9_./-]+\.(rs|md|toml|sh|yml|yaml|kt|ts)/)) {
          print substr($0, RSTART, RLENGTH)
          $0 = substr($0, RSTART + RLENGTH)
        }
      }
    ' \
  | sort -u \
  | while read -r p; do
      case "$p" in
        http*|*"::"*) continue;; esac                 # urls / rust paths
      case "$p" in
        crates/*|apps/*|docs/*|scripts/*|.github/*) : ;;  # repo-root only
        *) continue;;
      esac
      [ -e "$dir/$p" ] || printf '%s\n' "$p"
    done
)"

if [ -n "$missing" ]; then
  printf '%s\n' "$missing" | while IFS= read -r p; do
    echo "DOC-PATH MISSING: $p" >&2
  done
  echo "ERROR: doc-comments cite repo-root paths that do not exist (see above)." >&2
  echo "FIX: update the path, or drop the citation." >&2
  exit 1
fi
