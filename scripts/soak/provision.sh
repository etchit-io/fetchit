#!/usr/bin/env bash
# Bob's soak provisioning piece (see README.md). Deploys the daemonless
# fetchit-chat-peer across the fleet, establishes pairwise contact cards via
# the relay pair-share/pair-import pointer path (daemonless-safe; the v2 `card`
# mint is daemon-only), and launches persistent chat peers. Idempotent per phase.
#
# Topology + access live in fleet.env (gitignored -- holds infra IPs). The local
# per-peer agent_id + pair-URI store lives under $IDDIR (/tmp scratch).
#
# Usage: provision.sh {deploy|identity|import|launch|all|status|drive|stop}
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${FLEET_ENV:-$HERE/fleet.env}"
BIN="${BIN:-$HERE/../../target/release/fetchit-chat-peer}"
IDDIR="${IDDIR:-/tmp/soak-ids}"
mkdir -p "$IDDIR"

col() { awk -v n="$2" '{print $n}' <<<"$1"; }
sp()  { local t="$1" p="$2"; shift 2; ssh $SSH_OPTS -p "$p" "$t" "$@"; }
pass_for() { echo "soak-$1-pass"; }

deploy() {
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3)
    sp "$t" "$p" 'mkdir -p ~/soak'
    scp $SSH_OPTS -P "$p" "$BIN" "$t:soak/fetchit-chat-peer" >/dev/null
    scp $SSH_OPTS -P "$p" "$HERE/tsprepend.py" "$t:soak/tsprepend.py" >/dev/null
    echo "[deploy] $n $(sp "$t" "$p" 'chmod +x ~/soak/fetchit-chat-peer; ~/soak/fetchit-chat-peer --version')"
  done
}

identity() {
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3); pw=$(pass_for "$n")
    res=$(sp "$t" "$p" "cd ~/soak; FETCHIT_PASSPHRASE=$pw timeout 45 ./fetchit-chat-peer --daemonless --data-dir ~/soak/$n --display-name $n --relay $RELAY pair-share >~/soak/$n.pair 2>~/soak/$n.boot.log; echo A=\$(grep -o 'agent_id: [0-9a-f]*' ~/soak/$n.boot.log | awk '{print \$2}'); echo U=\$(cat ~/soak/$n.pair)")
    a=$(sed -n 's/^A=//p' <<<"$res"); u=$(sed -n 's/^U=//p' <<<"$res")
    if [[ -n "$a" && -n "$u" ]]; then
      printf '%s\n%s\n' "$a" "$u" >"$IDDIR/$n.id"
      echo "[identity] $n agent=${a:0:12} pair-share ok"
    else
      echo "[identity] $n FAILED: $(tr '\n' ' ' <<<"$res")"
    fi
  done
}

import() {
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3); partner=$(col "$row" 4); pw=$(pass_for "$n")
    u=$(sed -n 2p "$IDDIR/$partner.id" 2>/dev/null)
    [[ -z "$u" ]] && { echo "[import] $n: partner $partner has no URI yet (run identity first)"; continue; }
    echo "[import] $n <- $partner: $(sp "$t" "$p" "cd ~/soak; FETCHIT_PASSPHRASE=$pw timeout 45 ./fetchit-chat-peer --daemonless --data-dir ~/soak/$n --display-name $n --relay $RELAY pair-import --uri '$u' >~/soak/$n.import.log 2>&1; tail -1 ~/soak/$n.import.log")"
  done
}

launch() {
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3); partner=$(col "$row" 4); pw=$(pass_for "$n")
    pa=$(sed -n 1p "$IDDIR/$partner.id" 2>/dev/null)
    [[ -z "$pa" ]] && { echo "[launch] $n: partner $partner agent_id unknown"; continue; }
    # setsid + pipe through tsprepend.py: each log line gets a leading ISO ts so
    # collector.py computes true send->receipt TTD; setsid makes the peer its own
    # process group (survives ssh disconnect, killable via `kill -- -PGID`).
    sp "$t" "$p" "cd ~/soak; [[ -f $n.outbox ]] || : > $n.outbox; [[ -f $n.cursor ]] || printf '0' > $n.cursor; FETCHIT_PASSPHRASE=$pw setsid bash -c './fetchit-chat-peer --daemonless --data-dir ~/soak/$n --display-name $n --relay $RELAY chat --peer $pa --outbox-file ~/soak/$n.outbox --cursor-file ~/soak/$n.cursor 2>&1 | python3 -u ~/soak/tsprepend.py >> ~/soak/$n.log' </dev/null >/dev/null 2>&1 & echo \$! >~/soak/$n.pid"
    echo "[launch] $n -> $partner(${pa:0:12}) pid=$(sp "$t" "$p" "cat ~/soak/$n.pid 2>/dev/null")"
  done
}

# Optional smoke driver (a few lines per peer). Continuous load is Alice's driver.py.
drive() {
  local count="${2:-5}"
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3)
    sp "$t" "$p" "for i in \$(seq 1 $count); do echo \"$n-seq\$i ts\$(date +%s%3N)\" >> ~/soak/$n.outbox; done; echo '[drive] $n +$count'"
  done
}

status() {
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3)
    sp "$t" "$p" "up=\$(kill -0 \$(cat ~/soak/$n.pid 2>/dev/null) 2>/dev/null && echo 1 || echo 0); printf '%-5s alive=%s sent=%s recv=%s inbound_msg=%s cur=%s err=%s\n' '$n' \$up \$(grep -c '\[peer\] sent' ~/soak/$n.log 2>/dev/null) \$(grep -c 'got receipt' ~/soak/$n.log 2>/dev/null) \$(grep -c 'inbound-msg id=' ~/soak/$n.log 2>/dev/null) \$(cat ~/soak/$n.cursor 2>/dev/null) \$(grep -ciE 'error|refused|panic' ~/soak/$n.log 2>/dev/null)"
  done
}

stop() {
  for row in "${FLEET[@]}"; do
    n=$(col "$row" 1); t=$(col "$row" 2); p=$(col "$row" 3)
    sp "$t" "$p" "P=\$(cat ~/soak/$n.pid 2>/dev/null); [ -n \"\$P\" ] && { kill -- -\$P 2>/dev/null; kill \$P 2>/dev/null; }; rm -f ~/soak/$n.pid; echo '[stop] $n'"
  done
}

case "${1:-status}" in
  deploy)   deploy ;;
  identity) identity ;;
  import)   import ;;
  launch)   launch ;;
  all)      deploy; identity; import; launch ;;
  drive)    drive "$@" ;;
  status)   status ;;
  stop)     stop ;;
  *) echo "usage: $0 {deploy|identity|import|launch|all|status|drive|stop}"; exit 2 ;;
esac
