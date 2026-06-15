#!/usr/bin/env bash
# Bob's churn injection for the soak (README section J). Exercises the lifted
# DM outbox under disruption: a restarted peer must RESUME from its cursor
# (no re-send of acked lines, no drop of queued ones), and a peer whose relay
# link drops must reconnect and drain its backlog. Reuses fleet.env + the
# /tmp/soak-ids identity store written by provision.sh.
#
#   churn.sh restart <peer>            # kill + relaunch (outbox cursor resume)
#   churn.sh netdrop <peer> <secs>     # block the relay for <secs>, then restore (needs sudo on the box)
#   churn.sh idle    <peer> <secs>     # pause that peer's driver for <secs> (long-idle WS), then resume
#   churn.sh cycle   <gap_secs>        # rolling restart across the whole fleet, <gap_secs> apart
#
# All waits run remotely (inside ssh) so the caller never blocks on a local sleep.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${FLEET_ENV:-$HERE/fleet.env}"
IDDIR="${IDDIR:-/tmp/soak-ids}"
RELAY_HOST="$(printf '%s' "$RELAY" | sed -E 's#^[a-z]+://([^:/]+).*#\1#')"
RELAY_PORT="$(printf '%s' "$RELAY" | sed -E 's#.*:([0-9]+).*#\1#')"

row_for() { local w="$1" r; for r in "${FLEET[@]}"; do set -- $r; [ "$1" = "$w" ] && { echo "$r"; return 0; }; done; return 1; }

launch_one() {
  local r; r=$(row_for "$1") || { echo "unknown peer $1"; return 1; }
  set -- $r; local n=$1 t=$2 p=$3 partner=$4 pw="soak-$1-pass"
  local pa; pa=$(sed -n 1p "$IDDIR/$partner.id" 2>/dev/null)
  [ -z "$pa" ] && { echo "no partner agent for $n"; return 1; }
  ssh $SSH_OPTS -p "$p" "$t" "cd ~/soak; FETCHIT_PASSPHRASE=$pw nohup ./fetchit-chat-peer --daemonless --data-dir ~/soak/$n --display-name $n --relay $RELAY chat --peer $pa --outbox-file ~/soak/$n.outbox --cursor-file ~/soak/$n.cursor </dev/null >~/soak/$n.run.out 2>>~/soak/$n.log & echo \$! >~/soak/$n.pid; echo \"relaunched $n pid=\$(cat ~/soak/$n.pid) cursor=\$(cat ~/soak/$n.cursor)\""
}

restart() {
  local r; r=$(row_for "$1") || { echo "unknown peer $1"; return 1; }
  set -- $r; local n=$1 t=$2 p=$3
  ssh $SSH_OPTS -p "$p" "$t" "kill \$(cat ~/soak/$n.pid 2>/dev/null) 2>/dev/null; echo \"killed $n at cursor=\$(cat ~/soak/$n.cursor)\""
  launch_one "$1"
}

netdrop() {
  local r; r=$(row_for "$1") || { echo "unknown peer $1"; return 1; }
  set -- $r; local n=$1 t=$2 p=$3; local secs="${2:-30}"
  echo "[churn] netdrop $n: block $RELAY_HOST:$RELAY_PORT for ${secs}s"
  ssh $SSH_OPTS -p "$p" "$t" "sudo iptables -A OUTPUT -d $RELAY_HOST -p tcp --dport $RELAY_PORT -j DROP 2>/dev/null && echo blocked || { echo 'no sudo/iptables -- skipped'; exit 0; }; sleep $secs; sudo iptables -D OUTPUT -d $RELAY_HOST -p tcp --dport $RELAY_PORT -j DROP 2>/dev/null && echo restored"
}

idle() {
  local r; r=$(row_for "$1") || { echo "unknown peer $1"; return 1; }
  set -- $r; local n=$1 t=$2 p=$3; local secs="${2:-90}"
  echo "[churn] idle $n: pause driver ${secs}s (long-idle WS)"
  ssh $SSH_OPTS -p "$p" "$t" "kill \$(cat ~/soak/$n.driver.pid 2>/dev/null) 2>/dev/null; echo 'driver paused'; sleep $secs; cd ~/soak; PY=\$(command -v python3); nohup \$PY ~/soak/driver.py --rate 12 --jitter 0.4 --count 0 ~/soak/$n.outbox </dev/null >/dev/null 2>~/soak/$n.driver.log & echo \$! >~/soak/$n.driver.pid; echo 'driver resumed'"
}

cycle() {
  local gap="${1:-30}"
  for row in "${FLEET[@]}"; do
    set -- $row; local n=$1 t=$2 p=$3
    restart "$n"
    ssh $SSH_OPTS -p "$p" "$t" "sleep $gap"
  done
}

case "${1:-}" in
  restart) restart "$2" ;;
  netdrop) netdrop "$2" "${3:-30}" ;;
  idle)    idle "$2" "${3:-90}" ;;
  cycle)   cycle "${2:-30}" ;;
  *) echo "usage: $0 {restart <peer>|netdrop <peer> <secs>|idle <peer> <secs>|cycle <gap_secs>}"; exit 2 ;;
esac
