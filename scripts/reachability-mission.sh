#!/usr/bin/env bash
# Reachability v1 cross-relay live mission.
#
# Two throwaway fetchit-chat peers, each with its own local x0xd
# instance and home relay, pair over a pointer URI, prove bidirectional
# DM delivery, then one peer migrates to the other's relay and we assert
# the heal landed: the new relay serves the migrated peer's pair record,
# the old relay serves a forwarding record, and a post-migration DM still
# arrives. The peer then migrates back home and we assert supersession:
# the home relay's newer pair record retires its stale forwarding record
# (GET reads 404) while delivery still lands. This is the live, joint-run
# end of Task 12 in the reachability-v1 plan; it stands in for CI's
# #[ignore]-style opt-in.
#
# Topology mirrors the m2_live env-contract style: it refuses to run
# unless the live relays + vault passphrase are supplied, so a plain
# `cargo test` / `bash scripts/*.sh` sweep never trips it.
#
# Required env:
#   MISSION_RELAY_A    Peer A's home relay base URL (e.g. NY
#                      http://67.207.94.66:8088).
#   MISSION_RELAY_B    Peer B's home relay base URL (e.g. FRA).
#   MISSION_VAULT_PASS Argon2id passphrase for both throwaway vaults.
#
# Optional env:
#   MISSION_X0XD_BIN     Path to the x0xd binary (default: `command -v
#                        x0xd`). Fails loudly if neither resolves.
#   MISSION_WORKDIR      Scratch root (default: a fresh `mktemp -d`).
#   MISSION_TIMEOUT_SECS Per-wait ceiling in seconds (default: 120).
#   MISSION_KEEP_WORKDIR Set to 1 to keep the workdir after the run.
#
# Exit 0 only if every step passed; any failure exits non-zero with the
# failing step named.

set -euo pipefail

# ── env contract ──────────────────────────────────────────────────────

fail() {
    echo "[mission] FAIL: $*" >&2
    exit 1
}

require_env() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        fail "missing required env \$$name (this is an opt-in live test; \
see the header for the env contract)"
    fi
}

require_env MISSION_RELAY_A
require_env MISSION_RELAY_B
require_env MISSION_VAULT_PASS

RELAY_A="$MISSION_RELAY_A"
RELAY_B="$MISSION_RELAY_B"
VAULT_PASS="$MISSION_VAULT_PASS"
TIMEOUT_SECS="${MISSION_TIMEOUT_SECS:-120}"

X0XD_BIN="${MISSION_X0XD_BIN:-$(command -v x0xd || true)}"
if [[ -z "$X0XD_BIN" || ! -x "$X0XD_BIN" ]]; then
    fail "no x0xd binary: set MISSION_X0XD_BIN to its path or put x0xd \
on PATH (looked for \`command -v x0xd\`)"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${MISSION_WORKDIR:-$(mktemp -d)}"
mkdir -p "$WORKDIR"

echo "[mission] x0xd:    $X0XD_BIN"
echo "[mission] relay A: $RELAY_A"
echo "[mission] relay B: $RELAY_B"
echo "[mission] workdir: $WORKDIR"

# A run tag isolating this mission's x0xd instances + vaults from any
# others on the box (x0xd derives its data dir from --name).
RUN_TAG="mission-$$-$(date +%s)"
NAME_A="${RUN_TAG}-a"
NAME_B="${RUN_TAG}-b"

# ── process + cleanup bookkeeping ─────────────────────────────────────

declare -a PIDS=()
declare -a X0XD_DATA_DIRS=()

cleanup() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    # Give children a moment to exit on SIGTERM before the workdir goes.
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    local dir
    for dir in "${X0XD_DATA_DIRS[@]:-}"; do
        [[ -n "$dir" ]] && rm -rf "$dir" 2>/dev/null || true
    done
    if [[ "${MISSION_KEEP_WORKDIR:-0}" == "1" ]]; then
        echo "[mission] keeping workdir $WORKDIR (MISSION_KEEP_WORKDIR=1)" >&2
    else
        rm -rf "$WORKDIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

track_pid() { PIDS+=("$1"); }

# ── helpers ───────────────────────────────────────────────────────────

# Wait until `cmd` succeeds or TIMEOUT_SECS elapses. Returns non-zero on
# timeout so callers can name the failing step.
wait_until() {
    local label="$1"
    shift
    local deadline=$(( SECONDS + TIMEOUT_SECS ))
    while (( SECONDS < deadline )); do
        if "$@"; then
            return 0
        fi
        sleep 1
    done
    echo "[mission] timed out after ${TIMEOUT_SECS}s waiting for: $label" >&2
    return 1
}

# Pick a free TCP port. Uses Python (universally present on the rig) to
# bind :0 and read back the kernel-assigned port.
pick_free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Launch a throwaway x0xd instance under `name` on `port`, wait for
# /health to come up, and echo the port on success. Data lives under
# x0xd's per-name dir, which we register for cleanup.
start_x0xd() {
    local name="$1"
    local port="$2"
    local log="$3"
    local data_dir="${HOME}/.local/share/x0x-${name}"
    X0XD_DATA_DIRS+=("$data_dir")

    "$X0XD_BIN" --name "$name" --api-port "$port" --skip-update-check \
        >"$log" 2>&1 &
    track_pid "$!"

    wait_until "x0xd ${name} /health on :${port}" \
        curl -fsS --max-time 5 "http://127.0.0.1:${port}/health" -o /dev/null
}

# Run the peer binary once (non-interactive subcommand), capturing stdout
# (machine-readable line) and stderr (diagnostics) to the given out/err
# file paths.
PEER_BIN=""
run_peer() {
    local data_dir="$1"
    local x0xd_port="$2"
    local relay="$3"
    local out="$4"
    local err="$5"
    local name="$6"
    shift 6
    local token_path="${HOME}/.local/share/x0x-${name}/api-token"
    FETCHIT_PASSPHRASE="$VAULT_PASS" \
        "$PEER_BIN" \
        --x0xd-base "http://127.0.0.1:${x0xd_port}" \
        --x0xd-token-path "$token_path" \
        --data-dir "$data_dir" \
        --relay "$relay" \
        --display-name "$name" \
        "$@" \
        >"$out" 2>"$err"
}

# Spawn the peer binary in persistent chat mode (long-lived). The caller
# backgrounds it; its PID is tracked for cleanup. Inbound DMs land on
# stdout; outbound lines are read from the outbox file.
spawn_peer_chat() {
    local data_dir="$1"
    local x0xd_port="$2"
    local relay="$3"
    local out="$4"
    local err="$5"
    local name="$6"
    local peer_hex="$7"
    local outbox="$8"
    local cursor="$9"
    local token_path="${HOME}/.local/share/x0x-${name}/api-token"
    : >"$outbox"
    rm -f "$cursor"
    FETCHIT_PASSPHRASE="$VAULT_PASS" \
        "$PEER_BIN" \
        --x0xd-base "http://127.0.0.1:${x0xd_port}" \
        --x0xd-token-path "$token_path" \
        --data-dir "$data_dir" \
        --relay "$relay" \
        --display-name "$name" \
        chat --peer "$peer_hex" --outbox-file "$outbox" --cursor-file "$cursor" \
        >"$out" 2>"$err" &
    track_pid "$!"
}

# Extract the agent_id printed on stderr at peer startup
# (`[peer] agent_id: <hex>`).
extract_agent_id() {
    local err="$1"
    grep -m1 '^\[peer\] agent_id:' "$err" | awk '{print $3}'
}

# True when `needle` appears in `file` within TIMEOUT_SECS.
grep_within() {
    local needle="$1"
    local file="$2"
    wait_until "marker '${needle}' in ${file}" grep -qF "$needle" "$file"
}

# True when GET `url` returns 200 with a non-empty body.
http_ok_nonempty() {
    local url="$1"
    local body
    body="$(curl -fsS --max-time 10 "$url" 2>/dev/null)" || return 1
    [[ -n "$body" ]]
}

# Echo the HTTP status code of GET `url` (000 on transport failure).
http_status() {
    curl -s -o /dev/null --max-time 10 -w '%{http_code}' "$1"
}

# True when GET `url` answers exactly 404 (route present, record absent).
http_is_404() {
    [[ "$(http_status "$1")" == "404" ]]
}

PASS_COUNT=0
step_pass() {
    echo "[mission] step $1: PASS -- $2"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
}
step_fail() {
    echo "[mission] step $1: FAIL -- $2" >&2
    fail "step $1 ($2)"
}

# ── build the peer binary once ────────────────────────────────────────

echo "[mission] building fetchit-chat-peer..."
if ! ( cd "$REPO_ROOT" && cargo build -p fetchit-chat --bin fetchit-chat-peer -j 2 ); then
    fail "cargo build of fetchit-chat-peer failed"
fi
PEER_BIN="${REPO_ROOT}/target/debug/fetchit-chat-peer"
[[ -x "$PEER_BIN" ]] || fail "peer binary not found at $PEER_BIN after build"

# ── bring up two throwaway x0xd instances ─────────────────────────────

PORT_A="$(pick_free_port)"
PORT_B="$(pick_free_port)"
# bind-0-close can hand back the same port twice; repick until distinct.
while [[ "$PORT_B" == "$PORT_A" ]]; do
    PORT_B="$(pick_free_port)"
done
echo "[mission] x0xd A on :${PORT_A} (name ${NAME_A})"
echo "[mission] x0xd B on :${PORT_B} (name ${NAME_B})"

start_x0xd "$NAME_A" "$PORT_A" "${WORKDIR}/x0xd-a.log" \
    || fail "x0xd A never became healthy"
start_x0xd "$NAME_B" "$PORT_B" "${WORKDIR}/x0xd-b.log" \
    || fail "x0xd B never became healthy"

DATA_A="${WORKDIR}/vault-a"
DATA_B="${WORKDIR}/vault-b"
mkdir -p "$DATA_A" "$DATA_B"

# ── step 1: pair-share -> capture both URIs ───────────────────────────

run_peer "$DATA_A" "$PORT_A" "$RELAY_A" \
    "${WORKDIR}/share-a.out" "${WORKDIR}/share-a.err" "$NAME_A" pair-share \
    || step_fail 1 "peer A pair-share"
run_peer "$DATA_B" "$PORT_B" "$RELAY_B" \
    "${WORKDIR}/share-b.out" "${WORKDIR}/share-b.err" "$NAME_B" pair-share \
    || step_fail 1 "peer B pair-share"

URI_A="$(tr -d '\n' <"${WORKDIR}/share-a.out")"
URI_B="$(tr -d '\n' <"${WORKDIR}/share-b.out")"
AGENT_A="$(extract_agent_id "${WORKDIR}/share-a.err")"
AGENT_B="$(extract_agent_id "${WORKDIR}/share-b.err")"

[[ "$URI_A" == x0x://pair/* ]] || step_fail 1 "peer A URI not a pair URI: '$URI_A'"
[[ "$URI_B" == x0x://pair/* ]] || step_fail 1 "peer B URI not a pair URI: '$URI_B'"
[[ -n "$AGENT_A" ]] || step_fail 1 "could not read peer A agent_id"
[[ -n "$AGENT_B" ]] || step_fail 1 "could not read peer B agent_id"
step_pass 1 "pair-share: A=${AGENT_A:0:8}.. B=${AGENT_B:0:8}.."

# ── step 2: cross-import the pointer URIs ─────────────────────────────

run_peer "$DATA_A" "$PORT_A" "$RELAY_A" \
    "${WORKDIR}/import-a.out" "${WORKDIR}/import-a.err" "$NAME_A" \
    pair-import --uri "$URI_B" \
    || step_fail 2 "peer A pair-import of B"
run_peer "$DATA_B" "$PORT_B" "$RELAY_B" \
    "${WORKDIR}/import-b.out" "${WORKDIR}/import-b.err" "$NAME_B" \
    pair-import --uri "$URI_A" \
    || step_fail 2 "peer B pair-import of A"
step_pass 2 "cross-import: A<-B and B<-A"

# ── step 3: bidirectional DM proof ────────────────────────────────────

OUT_A="${WORKDIR}/chat-a.out"; ERR_A="${WORKDIR}/chat-a.err"
OUT_B="${WORKDIR}/chat-b.out"; ERR_B="${WORKDIR}/chat-b.err"
OUTBOX_A="${WORKDIR}/outbox-a.txt"; CURSOR_A="${WORKDIR}/cursor-a"
OUTBOX_B="${WORKDIR}/outbox-b.txt"; CURSOR_B="${WORKDIR}/cursor-b"

spawn_peer_chat "$DATA_A" "$PORT_A" "$RELAY_A" "$OUT_A" "$ERR_A" \
    "$NAME_A" "$AGENT_B" "$OUTBOX_A" "$CURSOR_A"
CHAT_A_PID="${PIDS[-1]}"
spawn_peer_chat "$DATA_B" "$PORT_B" "$RELAY_B" "$OUT_B" "$ERR_B" \
    "$NAME_B" "$AGENT_A" "$OUTBOX_B" "$CURSOR_B"
CHAT_B_PID="${PIDS[-1]}"

# Let both chat readers register their relay inbound before sending.
sleep 3

MSG_A2B="mission-a2b-${RUN_TAG}"
MSG_B2A="mission-b2a-${RUN_TAG}"
echo "$MSG_A2B" >>"$OUTBOX_A"
echo "$MSG_B2A" >>"$OUTBOX_B"

grep_within "$MSG_A2B" "$OUT_B" || step_fail 3 "A->B DM not delivered"
grep_within "$MSG_B2A" "$OUT_A" || step_fail 3 "B->A DM not delivered"
step_pass 3 "bidirectional DM: A->B and B->A delivered"

# Stop the chat processes cleanly before the migration step rebinds B's
# relay; a live B chat reader would otherwise race the slot-0 swap.
kill "$CHAT_A_PID" "$CHAT_B_PID" 2>/dev/null || true
sleep 2

# ── step 4: region change -- B migrates to A's relay ──────────────────

run_peer "$DATA_B" "$PORT_B" "$RELAY_B" \
    "${WORKDIR}/migrate-b.out" "${WORKDIR}/migrate-b.err" "$NAME_B" \
    pair-migrate --to "$RELAY_A" \
    || step_fail 4 "peer B pair-migrate to relay A"
MIGRATED_TO="$(tr -d '\n' <"${WORKDIR}/migrate-b.out")"
[[ "$MIGRATED_TO" == "$RELAY_A" ]] \
    || step_fail 4 "migrate did not echo the new relay (got '$MIGRATED_TO')"
step_pass 4 "region change: B migrated to relay A"

# ── step 5: heal assertions (observable only) ─────────────────────────

# Record probes poll under the standard timeout: a single in-flight
# curl against a momentarily stalled relay must not fail the mission
# (clients retry; the mission should match).
# (a) pair record for B now served at the NEW relay (A's).
wait_until "pair-record for B at new relay A" \
    http_ok_nonempty "${RELAY_A%/}/v1/pair-record/${AGENT_B}" \
    || step_fail 5 "pair-record for B absent at new relay A"
# (b) forwarding record for B served at the OLD relay (B's home).
wait_until "forwarding record for B at old relay B" \
    http_ok_nonempty "${RELAY_B%/}/v1/forwarding/${AGENT_B}" \
    || step_fail 5 "forwarding record for B absent at old relay B"

# (c) delivery after migration: A re-resolves B and a fresh DM arrives.
# B now lives on relay A, so B's chat reader binds relay A too.
OUT_A2="${WORKDIR}/chat-a2.out"; ERR_A2="${WORKDIR}/chat-a2.err"
OUT_B2="${WORKDIR}/chat-b2.out"; ERR_B2="${WORKDIR}/chat-b2.err"
OUTBOX_A2="${WORKDIR}/outbox-a2.txt"; CURSOR_A2="${WORKDIR}/cursor-a2"
OUTBOX_B2="${WORKDIR}/outbox-b2.txt"; CURSOR_B2="${WORKDIR}/cursor-b2"

# B re-homes on relay A (where it migrated); A stays on relay A.
spawn_peer_chat "$DATA_B" "$PORT_B" "$RELAY_A" "$OUT_B2" "$ERR_B2" \
    "$NAME_B" "$AGENT_A" "$OUTBOX_B2" "$CURSOR_B2"
CHAT_B2_PID="${PIDS[-1]}"
spawn_peer_chat "$DATA_A" "$PORT_A" "$RELAY_A" "$OUT_A2" "$ERR_A2" \
    "$NAME_A" "$AGENT_B" "$OUTBOX_A2" "$CURSOR_A2"
CHAT_A2_PID="${PIDS[-1]}"
sleep 3

MSG_POST="mission-post-migrate-${RUN_TAG}"
echo "$MSG_POST" >>"$OUTBOX_A2"
grep_within "$MSG_POST" "$OUT_B2" \
    || step_fail 5 "post-migration A->B DM not delivered"
step_pass 5 "heal: pair-record at new relay, forwarding at old, DM delivered"

# Stop the step-5 readers before the return migration rebinds B again.
kill "$CHAT_A2_PID" "$CHAT_B2_PID" 2>/dev/null || true
sleep 2

# ── step 6: return home -- newer pair record supersedes stale pointer ──

# B migrates back to its original home relay. That re-publishes B's pair
# record at relay B with a newer issued_at_ms than the stale step-4
# forwarding record there, which must now read as absent (suppressed,
# not removed), while the fresh forwarding record at relay A serves.
run_peer "$DATA_B" "$PORT_B" "$RELAY_A" \
    "${WORKDIR}/return-b.out" "${WORKDIR}/return-b.err" "$NAME_B" \
    pair-migrate --to "$RELAY_B" \
    || step_fail 6 "peer B pair-migrate back to relay B"
RETURNED_TO="$(tr -d '\n' <"${WORKDIR}/return-b.out")"
[[ "$RETURNED_TO" == "$RELAY_B" ]] \
    || step_fail 6 "return migrate did not echo home relay (got '$RETURNED_TO')"

# (a) B's pair record is re-asserted at its home relay.
wait_until "pair-record for B back at home relay B" \
    http_ok_nonempty "${RELAY_B%/}/v1/pair-record/${AGENT_B}" \
    || step_fail 6 "pair-record for B absent at home relay B after return"
# (b) the stale step-4 forwarding record at home is superseded: 404.
wait_until "superseded forwarding 404 at home relay B" \
    http_is_404 "${RELAY_B%/}/v1/forwarding/${AGENT_B}" \
    || step_fail 6 "stale forwarding at home relay B not superseded (still serving)"
# (c) the fresh return-leg forwarding record at relay A serves.
wait_until "forwarding record for B at relay A after return" \
    http_ok_nonempty "${RELAY_A%/}/v1/forwarding/${AGENT_B}" \
    || step_fail 6 "forwarding record for B absent at relay A after return"

# (d) delivery after the return: B reads from home again; A's send walks
# the relay-A Moved pointer (or hits home directly) and must land either
# way -- deposits at home buffer+Ack instead of bouncing on the stale
# pointer.
OUT_A3="${WORKDIR}/chat-a3.out"; ERR_A3="${WORKDIR}/chat-a3.err"
OUT_B3="${WORKDIR}/chat-b3.out"; ERR_B3="${WORKDIR}/chat-b3.err"
OUTBOX_A3="${WORKDIR}/outbox-a3.txt"; CURSOR_A3="${WORKDIR}/cursor-a3"
OUTBOX_B3="${WORKDIR}/outbox-b3.txt"; CURSOR_B3="${WORKDIR}/cursor-b3"

spawn_peer_chat "$DATA_B" "$PORT_B" "$RELAY_B" "$OUT_B3" "$ERR_B3" \
    "$NAME_B" "$AGENT_A" "$OUTBOX_B3" "$CURSOR_B3"
spawn_peer_chat "$DATA_A" "$PORT_A" "$RELAY_A" "$OUT_A3" "$ERR_A3" \
    "$NAME_A" "$AGENT_B" "$OUTBOX_A3" "$CURSOR_A3"
sleep 3

MSG_RETURN="mission-return-home-${RUN_TAG}"
echo "$MSG_RETURN" >>"$OUTBOX_A3"
grep_within "$MSG_RETURN" "$OUT_B3" \
    || step_fail 6 "post-return A->B DM not delivered"
step_pass 6 "return home: stale pointer superseded (404), records sane, DM delivered"

# ── summary ───────────────────────────────────────────────────────────

echo "[mission] ----------------------------------------"
echo "[mission] summary:"
echo "[mission]   1 pair-share .................. PASS"
echo "[mission]   2 cross-import ................ PASS"
echo "[mission]   3 bidirectional DM ............ PASS"
echo "[mission]   4 region change (migrate) ..... PASS"
echo "[mission]   5 heal (records + delivery) ... PASS"
echo "[mission]   6 return home (supersede) ..... PASS"
echo "[mission] ----------------------------------------"
echo "[mission] ALL ${PASS_COUNT} STEPS PASSED"
exit 0
