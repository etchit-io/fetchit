#!/bin/bash
# claude-monitor — chat-pipe + x0xd + chat-peer event watcher.
#
# Both-boxes shared script for the Bob↔Alice pair rig. Parameterised
# so each operator overrides the peer's agent-id hex and (optionally)
# the chat-peer unit name + x0xd port file. Defaults assume Box B
# (Bob's side): peer hex = Alice's a48e8af1….
#
# Distinct marker so a future cleanup pgrep can target this script
# specifically: `pgrep -af '[chatmon]'`.
#
# Robustness notes (Bob's lessons learned, 2026-06-03):
#   * Heartbeat uses `read -t 60` (bash builtin) instead of `sleep 60`
#     — no child process to grep-match under `pgrep -f sleep …`, no
#     SIGTERM-killable subprocess to take down the whole loop. This
#     is the root cause of why the previous monitor died when the
#     keeper-writer cleanup `pgrep -f "sleep infinity"` ran.
#   * Tail+grep is wrapped in `until false; do …; done` so a
#     subprocess death respawns the pipeline.
#   * Self-execs (`exec "$0"`) if children die unexpectedly so the
#     whole event stream restarts cleanly.
#   * Trap on SIGTERM/SIGINT kills the whole process group politely.
#
# Marker — DO NOT remove the bracketed token; it's how cleanup
# commands distinguish this from other watchers: [chatmon]
#
# Env overrides:
#   PEER_AGENT_HEX_PREFIX   default a48e8af1 (Alice, Box B perspective)
#                           override on Box A to Bob's first 8 hex
#                           chars so the tail-grep catches the right
#                           sender prefix.
#   PEER_UNIT               default fetchit-chat-peer-claude
#   X0XD_PORT_FILE          default ~/.local/share/x0x-claude-here/api.port
#   RX_LOG                  default /tmp/claude-rx

set -u

PEER_AGENT_HEX_PREFIX="${PEER_AGENT_HEX_PREFIX:-a48e8af1}"
PEER_UNIT="${PEER_UNIT:-fetchit-chat-peer-claude}"
X0XD_PORT_FILE="${X0XD_PORT_FILE:-${HOME}/.local/share/x0x-claude-here/api.port}"
RX_LOG="${RX_LOG:-/tmp/claude-rx}"

cleanup() {
  trap - TERM INT
  kill -- -$$ 2>/dev/null
  exit 0
}
trap cleanup TERM INT

# Side channel A — peer messages + chat-peer failure signatures.
# Wrapped in `until false` so a tail/grep death respawns the
# pipeline. Each iteration is one full pipe lifetime; if either tail
# or grep dies, we wait briefly (via `read -t`, NOT `sleep`) and
# rebuild it.
(
  until false; do
    tail -F -n 0 "$RX_LOG" 2>/dev/null \
      | grep -E --line-buffered \
        "^\[${PEER_AGENT_HEX_PREFIX}\] \[(A->B|B->A|alice|bob)\]|chat send permanently failed|receipt send error|/agent/sign|DecryptFailed|bridge dispatch|relay (lost|reconnect|disconnect)|signer.*reresolv"
    read -t 5 -r _ </dev/null || true
  done
) &
TAIL_PID=$!

# Side channel B — 60s heartbeat: x0xd health, chat-peer unit
# state, RX_LOG idle detection. `read -t 60` blocks 60s without
# spawning a `sleep` subprocess (the original killer of the earlier
# monitor iteration).
(
  last_x0xd_state="unknown"
  last_peer_state="unknown"
  silent_alerted=0
  while true; do
    read -t 60 -r _ </dev/null || true

    port=""
    [ -f "$X0XD_PORT_FILE" ] && port=$(cut -d: -f2 "$X0XD_PORT_FILE" 2>/dev/null)
    x0xd_state="unknown"
    if [ -n "$port" ]; then
      if curl -sS -m 3 "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
        x0xd_state="active"
      else
        x0xd_state="down (port=$port unreachable)"
      fi
    else
      x0xd_state="down (api.port missing)"
    fi
    if [ "$x0xd_state" != "$last_x0xd_state" ]; then
      echo "[chatmon] x0xd state transition: $last_x0xd_state -> $x0xd_state"
      last_x0xd_state="$x0xd_state"
    fi

    peer_state=$(systemctl --user is-active "$PEER_UNIT" 2>/dev/null)
    if [ "$peer_state" != "$last_peer_state" ]; then
      echo "[chatmon] chat-peer unit transition: $last_peer_state -> $peer_state"
      last_peer_state="$peer_state"
    fi

    rx_mtime=$(stat -c %Y "$RX_LOG" 2>/dev/null)
    now=$(date +%s)
    if [ -n "$rx_mtime" ]; then
      rx_idle=$((now - rx_mtime))
      if [ "$rx_idle" -gt 1800 ] && [ "$silent_alerted" -eq 0 ]; then
        echo "[chatmon] $RX_LOG idle ${rx_idle}s (>30min) — chat link may be dead"
        silent_alerted=1
      elif [ "$rx_idle" -le 1800 ] && [ "$silent_alerted" -eq 1 ]; then
        echo "[chatmon] $RX_LOG active again (idle ${rx_idle}s)"
        silent_alerted=0
      fi
    fi
  done
) &
HEARTBEAT_PID=$!

# Wait for both side channels; if either exits, re-exec the whole
# script so we rebuild cleanly. A short backoff (via `read -t`,
# never `sleep`) avoids a hot restart loop.
while true; do
  wait "$TAIL_PID" "$HEARTBEAT_PID"
  echo "[chatmon] watcher subprocess exited unexpectedly — respawning"
  read -t 5 -r _ </dev/null || true
  exec "$0"
done
