#!/usr/bin/env bash
# Gradually raise the soak send rate to simulate organic growth, capped at a
# level the current infra absorbs cleanly. Runs detached on `one`. Every
# STEP_SECS it bumps each peer's driver --rate by RATE_STEP (relaunching the
# driver) up to RATE_MAX, then holds.
#
# CONSERVATIVE BY DESIGN: the relay is production (real users), so RATE_MAX is
# set low and raised only after watching the dashboard stay green (delivery
# ~100%, stuck flat, TTD flat, no RSS/vault growth). Tune via env:
#   RATE_START (per-peer msg/min, default 12)
#   RATE_STEP  (increment,            default 12)
#   RATE_MAX   (ceiling per peer,      default 60  -> ~480/min fleet @ 8 peers)
#   STEP_SECS  (seconds between steps, default 1800 = 30 min)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${FLEET_ENV:-$HERE/fleet.env}"
RATE_START="${RATE_START:-12}"; RATE_STEP="${RATE_STEP:-12}"; RATE_MAX="${RATE_MAX:-60}"; STEP_SECS="${STEP_SECS:-1800}"

set_rate() {
  local rate="$1" row n t p
  for row in "${FLEET[@]}"; do
    set -- $row; n=$1; t=$2; p=$3
    ssh $SSH_OPTS -p "$p" "$t" "kill \$(cat ~/soak/$n.driver.pid 2>/dev/null) 2>/dev/null; cd ~/soak; PY=\$(command -v python3); nohup \$PY ~/soak/driver.py --rate $rate --jitter 0.4 --count 0 ~/soak/$n.outbox </dev/null >/dev/null 2>~/soak/$n.driver.log & echo \$! >~/soak/$n.driver.pid" >/dev/null 2>&1 || true
  done
}

rate="$RATE_START"
while :; do
  set_rate "$rate"
  echo "[ramp] per-peer=$rate/min  fleet~$((rate * ${#FLEET[@]}))/min"
  [ "$rate" -ge "$RATE_MAX" ] && { echo "[ramp] cap $RATE_MAX reached -- holding"; break; }
  rate=$((rate + RATE_STEP)); [ "$rate" -gt "$RATE_MAX" ] && rate="$RATE_MAX"
  sleep "$STEP_SECS"
done
