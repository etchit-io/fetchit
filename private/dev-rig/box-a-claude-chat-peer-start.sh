#!/usr/bin/env bash
set -euo pipefail

# Wrapper for fetchit-chat-peer under systemd --user (Alice / Box A).
#
# Uses the persistent-outbox mode shipped in b552a65: the binary owns
# the outbox file directly via --outbox-file + --cursor-file so
# messages survive chat-peer restarts (cursor advances atomically on
# each acked send), and the embedded X0xdSigner self-heals across x0xd
# port drifts via --x0xd-port-file. Together this replaces the
# previous `tail -F /tmp/claude-pair/to-bob.txt | binary` pipeline that
# lost messages on every chat-peer death and wedged the binary against
# a stale x0xd port until manual systemd intervention.
#
# Pair with x0xd-claude-here.service (BindsTo + After) so x0xd's clean
# exit cascades a chat-peer restart, and Restart=always so the
# exit-2-on-permanent-failure dance brings the binary back up against
# the freshly-resolved port.

APIPORT_FILE="${HOME}/.local/share/x0x-claude-here/api.port"
PEER_BIN="${HOME}/Desktop/fetchit/target/debug/fetchit-chat-peer"
DATA_DIR="${HOME}/.local/share/fetchit-claude-peer"
TOKEN_PATH="${HOME}/.local/share/x0x-claude-here/api-token"
PASS_FILE="${DATA_DIR}/passphrase"
OUTBOX="/tmp/claude-pair/to-bob.txt"
CURSOR="${DATA_DIR}/chat-peer.cursor"
INBOX="/tmp/claude-rx"
ERRLOG="/tmp/chat-peer.err.log"
BOB_AGENT="fb9240c617854f28ca0afeb9eaf56ddb75650285ddbec7bcac4dd34505dabde0"

# Wait for api.port to appear (x0xd boot race after restart). The
# binary's self-heal also reads this file after construction, so the
# initial value just needs to be live enough to complete the warmup
# round-trip.
for _ in $(seq 1 30); do
    [[ -s "$APIPORT_FILE" ]] && break
    sleep 1
done

if [[ ! -s "$APIPORT_FILE" ]]; then
    echo "[start] $(date -Iseconds) :: api.port missing/empty — aborting" >> "$INBOX"
    exit 1
fi

PORT="$(awk -F: '{print $2}' "$APIPORT_FILE")"
if [[ -z "$PORT" ]]; then
    echo "[start] $(date -Iseconds) :: api.port unparseable — aborting" >> "$INBOX"
    exit 1
fi

mkdir -p /tmp/claude-pair "$DATA_DIR"
touch "$OUTBOX" "$INBOX"

echo "[start] $(date -Iseconds) :: chat-peer launching on x0xd port ${PORT}, outbox=${OUTBOX}, cursor=${CURSOR}" >> "$INBOX"

exec "$PEER_BIN" \
    --x0xd-base "http://127.0.0.1:${PORT}" \
    --x0xd-token-path "$TOKEN_PATH" \
    --x0xd-port-file "$APIPORT_FILE" \
    --data-dir "$DATA_DIR" \
    --passphrase-file "$PASS_FILE" \
    --display-name claude-fetchit-A \
    chat \
        --peer "$BOB_AGENT" \
        --outbox-file "$OUTBOX" \
        --cursor-file "$CURSOR" \
    >> "$INBOX" 2>> "$ERRLOG"
