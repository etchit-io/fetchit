#!/usr/bin/env sh
# Commit-aware staleness detector for docs/ARCHITECTURE.md (simple v1).
#
# Each section ends with a machine-readable stamp:
#   <!-- arch: id=<id> glob=<glob...> verified=<sha> -->
# For each stamp this runs `git log --oneline <sha>..HEAD -- <glob tokens>`.
# If that is non-empty, files under the section's glob changed since the
# section was last verified, so the prose may be stale -> WARN (name the id,
# the changed commits, and the fix: re-verify + bump the stamp).
#
# `glob` may hold several space-separated path globs (e.g. `crates/** apps/**`
# or `PINS.md Cargo.lock`); all tokens are passed to `git log -- ...`.
#
# Default mode is informational: print warnings, exit 0 (so it surfaces drift
# without blocking CI until the stamps are adopted). `--strict` exits 1 if any
# section is stale. The milestone-close sweep consumes the warnings to target
# re-verification.
set -eu
# Run from repo root regardless of caller CWD, so `git log` targets THIS repo
# (matches check-crate-list.sh / check-doc-paths.sh / check-stale-phrases.sh).
# A Phase-1 bug was a script that diffed the caller's CWD, not its own repo.
cd "$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"

strict=0
case "${1:-}" in
  --strict) strict=1 ;;
  "") : ;;
  *) echo "usage: $0 [--strict]" >&2; exit 2 ;;
esac

doc="docs/ARCHITECTURE.md"
[ -f "$doc" ] || { echo "ERROR: $doc not found" >&2; exit 2; }

# Emit "id<TAB>sha<TAB>glob..." for every well-formed arch stamp. awk owns the
# parse so the result survives the pipe; the loop below decides pass/warn.
stamps="$(
  awk '
    /<!-- arch:/ {
      id=""; glob=""; sha=""
      # Strip everything up to and including "arch:" and the closing "-->".
      line=$0
      sub(/^.*<!-- arch:[ \t]*/, "", line)
      sub(/[ \t]*-->.*$/, "", line)
      # line is now: id=<id> glob=<glob...> verified=<sha>
      # Capture id (single token) and verified (single token); glob is the
      # span between "glob=" and " verified=" (may contain spaces).
      if (match(line, /id=[^ \t]+/))      { id=substr(line,RSTART+3,RLENGTH-3) }
      if (match(line, /verified=[^ \t]+/)) { sha=substr(line,RSTART+9,RLENGTH-9) }
      gstart=index(line,"glob=")
      if (gstart>0) {
        rest=substr(line,gstart+5)
        vpos=index(rest," verified=")
        if (vpos>0) glob=substr(rest,1,vpos-1); else glob=rest
        sub(/[ \t]+$/, "", glob)
      }
      if (id!="" && sha!="" && glob!="")
        printf "%s\t%s\t%s\n", id, sha, glob
    }
  ' "$doc"
)"

[ -n "$stamps" ] || { echo "no arch stamps found in $doc" >&2; exit 0; }

# A temp file collects the stale ids: the per-stamp loop runs in a pipe
# subshell and cannot set a parent variable, so staleness is recorded on disk
# and the parent reads it after the loop.
flag="$(mktemp)"
trap 'rm -f "$flag"' EXIT INT TERM

# Read tab-separated fields; the glob field keeps its embedded spaces, which we
# split into separate `git log` pathspec args via word-splitting (SC2086).
printf '%s\n' "$stamps" | while IFS='	' read -r id sha glob; do
  # shellcheck disable=SC2086
  changed="$(git log --oneline "$sha"..HEAD -- $glob 2>/dev/null || true)"
  if [ -n "$changed" ]; then
    {
      echo "ARCH-STALE: section '$id' may be stale -- files under its glob ($glob) changed since $sha:"
      printf '%s\n' "$changed" | sed 's/^/    /'
      echo "  FIX: re-verify section '$id' against current code, then bump its 'verified=' stamp in $doc."
    } >&2
    echo "$id" >> "$flag"
  fi
done

if [ -s "$flag" ]; then
  n="$(wc -l < "$flag" | tr -d ' ')"
  echo "check-arch-stamps: $n section(s) may be stale (see ARCH-STALE warnings above)." >&2
  if [ "$strict" -eq 1 ]; then
    exit 1
  fi
  # Default: informational only.
  exit 0
fi

echo "check-arch-stamps: all sections verified at their stamped commit."
exit 0
