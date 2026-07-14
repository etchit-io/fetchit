#!/usr/bin/env sh
# Fail if a CHANGED doc-comment (//! or ///) in non-test Rust introduces an
# expiring marker. Lints the diff vs $1 (base ref), so historical comments are
# untouched -- prevention, not cleanup. Escape one line with `stale-ok: <why>`.
#
# Diff is two-arg (`git diff <base> -- ...`): it covers both committed changes
# and the working tree, so it fires in CI (PR commits vs base) and locally
# (uncommitted edits). A three-dot `<base>...HEAD` would miss working-tree edits.
set -eu
# Run from repo root regardless of caller CWD, so `git diff` targets THIS repo
# (matches check-crate-list.sh / check-doc-paths.sh). Without it the diff runs
# against the caller's working directory and can flag another checkout's history.
cd "$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
base="${1:-origin/main}"
# Conservative starter set (extend only after proving low false-positive):
pat='lands.next.milestone|does(n.t| not) exist today|scaffolding|Stage [0-9]|C[45][[:space:]]|C[45]-scaffold'

# Emit "file:line<TAB>content" for every ADDED line that is a doc-comment
# (//! or ///) and is NOT escaped with `stale-ok:`. The awk stage owns all
# filtering so the offending set survives the pipe (no subshell-scoped flag).
offenders="$(
  git diff --unified=0 "$base" -- '*.rs' ':(exclude)**/tests/**' \
  | awk '
      /^\+\+\+ b\// { file=substr($0,7); next }
      /^@@/ {
        # @@ -a,b +c,d @@  -> first added line number is the value after +
        match($0, /\+[0-9]+/); ln=substr($0,RSTART+1,RLENGTH-1)+0; next
      }
      /^\+/ && !/^\+\+\+/ {
        body=substr($0,2)
        is_doc  = (index(body,"//!")>0 || index(body,"///")>0)
        escaped = (index(body,"stale-ok:")>0)
        if (is_doc && !escaped) print file ":" ln "\t" body
        ln++
      }
    ' \
  | grep -iE "$pat" || true
)"

if [ -n "$offenders" ]; then
  printf '%s\n' "$offenders" | while IFS= read -r l; do
    echo "STALE-PHRASE: $l" >&2
  done
  echo "ERROR: new doc-comments introduce expiring markers (see above)." >&2
  echo "FIX: describe current state, not a milestone; or annotate the line with 'stale-ok: <reason>'." >&2
  exit 1
fi
