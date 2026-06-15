#!/usr/bin/env bash
# LIT soak dashboard feeder. Runs on `one` (holds the fleet SSH keys): pulls each
# fleet peer's log, runs Alice's collector.py --prometheus to render soak.prom,
# and -- when SHIP=1 -- ships soak.prom to wyse14's node_exporter textfile dir
# (atomic via tmp + sudo mv). node_exporter -> Prometheus (`node` job) -> Grafana.
#
#   SHIP=1 scripts/soak/soak-dashboard.sh    # full pipeline (needs the wyse14 node scrape job)
#   SHIP=0 scripts/soak/soak-dashboard.sh    # pull + collect only, writes $PROM locally, no wyse14 touch
#
# Shipping is gated on Josh's OK for the wyse14 Prometheus change (it scrapes prod relays).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${FLEET_ENV:-$HERE/fleet.env}"
COLLECTOR="${COLLECTOR:-$HERE/collector.py}"   # repo collector carries --prometheus (landed on chat @ 606bb56)
WORK="${WORK:-/tmp/soak}"; LOGS="$WORK/logs"; PROM="$WORK/soak.prom"
INTERVAL="${INTERVAL:-60}"
SHIP="${SHIP:-0}"
W14="${W14:-wyse14@192.168.1.41}"; W14_PORT="${W14_PORT:-22}"
W14_TEXTFILE="${W14_TEXTFILE:-/var/lib/prometheus/node-exporter/soak.prom}"
mkdir -p "$LOGS"
echo "[soak-dashboard] feeder up: interval=${INTERVAL}s ship=${SHIP} collector=$COLLECTOR"
while true; do
  for row in "${FLEET[@]}"; do
    set -- $row; n=$1; t=$2; p=$3
    scp $SSH_OPTS -P "$p" "$t:soak/$n.log" "$LOGS/$n.log" >/dev/null 2>&1 || true
  done
  python3 "$COLLECTOR" --once --prometheus "$PROM" "$LOGS"/*.log >/dev/null 2>&1 || true
  if [ "$SHIP" = "1" ] && [ -s "$PROM" ]; then
    # Plain scp over the textfile (deploy chowned it to the login user) -> no
    # recurring sudo on the prod host. Not a tmp+rename: the textfile dir is
    # prometheus-owned (no dir-write), so a scrape landing mid-write sees a torn
    # file -- node_exporter sets node_textfile_scrape_error for that one scrape
    # and self-heals next cycle. Acceptable at 60s cadence; true atomicity would
    # need granting dir-write on the prometheus textfile dir (another prod change).
    scp $SSH_OPTS -P "$W14_PORT" "$PROM" "$W14:$W14_TEXTFILE" >/dev/null 2>&1 || true
  fi
  sleep "$INTERVAL"
done
