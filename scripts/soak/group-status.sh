#!/usr/bin/env bash
# Emit LIT group-soak metrics (Prometheus textfile lines) to stdout, for the
# feeder (soak-dashboard.sh) to append to soak.prom. Reads the active same-LAN
# group soak: owner wyse21 (g21e.log) -> joiner wyse28 (g28e.log) on group G4,
# plus x0xd mesh health on the 3 group boxes (api-port 9701, --name soak-grp).
#
# Group chat is PROVEN working (join + send + decrypt) once members' v2 cards
# are pre-exchanged. Cross-NAT join converges on x0xd 0.23.1 (verified fresh
# wyse21 .50 <-> wyse43 .54, 2026-06-15) -- the upstream send_replace fix
# (saorsa-labs/x0x#101, closed 2026-06-10) ships in 0.23.1 via PR #102; an
# earlier single-run Welcome-fetch timeout was a transient hole-punch failure,
# NOT a block. Override the owner/joiner log + box list via env for a run.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${FLEET_ENV:-$HERE/fleet.env}"

OWNER="${GRP_OWNER:-wyse21@47.207.67.50}";  OWNER_PORT="${GRP_OWNER_PORT:-22021}"; OWNER_LOG="${GRP_OWNER_LOG:-~/grp/g21e.log}"
JOINER="${GRP_JOINER:-wyse28@47.207.67.50}"; JOINER_PORT="${GRP_JOINER_PORT:-22028}"; JOINER_LOG="${GRP_JOINER_LOG:-~/grp/g28e.log}"

# group boxes for x0xd mesh health: name target port
GRP_BOXES=(
  "wyse21 wyse21@47.207.67.50 22021"
  "wyse28 wyse28@47.207.67.50 22028"
  "wyse43 wyse43@47.207.67.54 22043"
)

num() { local v; v="$(tr -dc '0-9' <<<"${1:-}")"; echo "${v:-0}"; }

sent=$(num "$(ssh $SSH_OPTS -p "$OWNER_PORT" "$OWNER" "grep -c 'group-sent' $OWNER_LOG 2>/dev/null" 2>/dev/null)")
delivered=$(num "$(ssh $SSH_OPTS -p "$JOINER_PORT" "$JOINER" "grep -c 'group-inbound' $JOINER_LOG 2>/dev/null" 2>/dev/null)")
declfail=$(num "$(ssh $SSH_OPTS -p "$JOINER_PORT" "$JOINER" "grep -c 'group-decrypt-fail' $JOINER_LOG 2>/dev/null" 2>/dev/null)")
converged=$(ssh $SSH_OPTS -p "$JOINER_PORT" "$JOINER" "grep -q 'convergence confirmed' $JOINER_LOG 2>/dev/null && echo 1 || echo 0" 2>/dev/null)
converged="$(num "$converged")"

echo "# LIT group soak -- same-LAN owner -> joiner (cards pre-exchanged)"
echo "soak_group_join_converged ${converged:-0}"
echo "soak_group_sent_total ${sent:-0}"
echo "soak_group_delivered_total ${delivered:-0}"
echo "soak_group_decrypt_fail_total ${declfail:-0}"

for row in "${GRP_BOXES[@]}"; do
  set -- $row; n=$1; t=$2; p=$3
  h=$(ssh $SSH_OPTS -p "$p" "$t" 'T=$(cat ~/.local/share/x0x-soak-grp/api-token 2>/dev/null); curl -sS -m4 -H "Authorization: Bearer $T" http://127.0.0.1:9701/health 2>/dev/null' 2>/dev/null)
  peers=$(num "$(grep -o '"peers":[0-9]*' <<<"$h" | head -1)")
  up=0; grep -q '"status":"healthy"' <<<"$h" && up=1
  echo "soak_group_x0xd_up{box=\"$n\"} $up"
  echo "soak_group_x0xd_peers{box=\"$n\"} ${peers:-0}"
done

# Launch test matrix: per-lane status for the dashboard overview row.
#   1 = LIVE/passing, 0 = PENDING/not-built, -1 = BLOCKED (upstream).
# dm_outbox + groups_lan use their real metrics in the panels; this manifest
# covers the not-yet-live lanes -- flip a value (0->1, or -1->...) as each lane
# comes online or unblocks.
echo "# TYPE soak_test_status gauge"
echo 'soak_test_status{lane="groups_crossnat"} 1'
echo 'soak_test_status{lane="groups_autoimport"} 0'
echo 'soak_test_status{lane="fedi_exerciser"} 0'
echo 'soak_test_status{lane="wire_v2v3_skew"} 0'
echo 'soak_test_status{lane="denylist_e2e"} 0'
echo 'soak_test_status{lane="inbound_gate"} 0'
