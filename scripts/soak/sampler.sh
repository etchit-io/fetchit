#!/usr/bin/env sh
# Soak sampler: per-peer outbox-vault size (du) + process RSS over time -> CSV.
# Catches the leak/drift the collector cannot see: a vault outbox that never
# drains, or RSS that climbs monotonically over a multi-day run.
#
# Usage: sampler.sh INTERVAL_SECS label=/data/dir [label2=/data/dir2 ...]
#   e.g. sampler.sh 300 peer-0=/opt/soak/peer-0 peer-1=/opt/soak/peer-1 > growth.csv
# CSV columns: epoch,label,vault_bytes,rss_kb  (rss_kb blank when no live process)
set -eu
interval="$1"; shift
printf 'epoch,label,vault_bytes,rss_kb\n'
while :; do
  now=$(date +%s)
  for spec in "$@"; do
    label=${spec%%=*}; dir=${spec#*=}
    bytes=$(du -sb "$dir" 2>/dev/null | cut -f1 || true)
    pid=$(pgrep -f -- "--data-dir $dir" 2>/dev/null | head -1 || true)
    if [ -n "${pid:-}" ]; then
      rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || true)
    else
      rss=""
    fi
    printf '%s,%s,%s,%s\n' "$now" "$label" "${bytes:-}" "${rss:-}"
  done
  sleep "$interval"
done
