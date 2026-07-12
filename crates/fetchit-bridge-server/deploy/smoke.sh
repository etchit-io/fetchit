#!/usr/bin/env bash
# Post-deploy smoke test for fetchit-bridge-server behind its public edge.
#
# Part A (always): edge routing + read paths, and that /health and /metrics
#   are NOT exposed through the public domain. No secrets; run immediately.
# Part B (if an actor.json is given): the full register -> WebFinger-resolve
#   -> fetch-actor-doc chain. Mint the actor.json in etch/it desktop first.
#
# Usage:
#   ./smoke.sh [DOMAIN] [ACTOR_JSON]
#   ./smoke.sh etchit.io
#   ./smoke.sh etchit.io ./alice-actor.json
#
# DOMAIN defaults to etchit.io. Exits non-zero on the first failed check.

set -euo pipefail

DOMAIN="${1:-etchit.io}"
ACTOR_JSON="${2:-}"
BASE="https://${DOMAIN}"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }

# code [curl args...] -> prints the HTTP status (or 000 on a transport error).
code() {
	local out
	out=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$@") || out="000"
	printf '%s' "$out"
}

echo "== Part A: edge + routing (${BASE}) =="

# 1. Site still served (Pages), untouched by the Worker.
c=$(code "${BASE}/")
[ "$c" = "200" ] || fail "site root expected 200, got $c"
pass "site root 200 (still on Pages)"

# 2. WebFinger for an unregistered handle routes Worker -> bridge -> 404.
c=$(code "${BASE}/.well-known/webfinger?resource=acct:nf-smoke-$$@${DOMAIN}")
[ "$c" = "404" ] || fail "webfinger(unknown) expected 404, got $c"
pass "webfinger unknown-handle 404 (Worker -> bridge path live)"

# 3. Actor doc for an unregistered handle -> 404 (also exercises the route).
c=$(code "${BASE}/actors/nf-smoke-$$")
[ "$c" = "404" ] || fail "actor(unknown) expected 404, got $c"
pass "actor unknown-handle 404"

# 4. /health and /metrics MUST NOT be public -- the Worker binds only
#    webfinger + /actors*. A 200 here would leak operator endpoints.
for path in /health /metrics; do
	c=$(code "${BASE}${path}")
	[ "$c" != "200" ] || fail "${path} is publicly reachable (200) -- Worker route too broad"
	pass "${path} not public (got $c)"
done

if [ -z "$ACTOR_JSON" ]; then
	echo
	echo "Part B skipped (no actor.json). To run the full chain:"
	echo "  1. Mint a handle in etch/it desktop."
	echo "  2. Save its actor JSON-LD to a file."
	echo "  3. ./smoke.sh ${DOMAIN} ./that-actor.json"
	exit 0
fi

echo
echo "== Part B: register -> resolve -> fetch (${ACTOR_JSON}) =="
[ -f "$ACTOR_JSON" ] || fail "actor.json not found: $ACTOR_JSON"

# Read the handle from preferredUsername (jq if present, else a simple grep).
if command -v jq >/dev/null 2>&1; then
	handle=$(jq -r '.preferredUsername // empty' "$ACTOR_JSON")
else
	handle=$(grep -o '"preferredUsername"[[:space:]]*:[[:space:]]*"[^"]*"' "$ACTOR_JSON" \
		| head -1 | sed 's/.*"\([^"]*\)"$/\1/')
fi
[ -n "$handle" ] || fail "could not read preferredUsername from $ACTOR_JSON"
pass "handle = ${handle}"

# 5. Register (idempotent: 201 first time, 200 on a re-run).
c=$(code -X POST -H 'content-type: application/activity+json' \
	--data @"$ACTOR_JSON" "${BASE}/actors")
case "$c" in
	201 | 200) pass "register -> $c" ;;
	*) fail "register expected 201/200, got $c" ;;
esac

# 6. WebFinger now resolves the handle.
c=$(code "${BASE}/.well-known/webfinger?resource=acct:${handle}@${DOMAIN}")
[ "$c" = "200" ] || fail "webfinger(${handle}) expected 200, got $c"
pass "webfinger ${handle} 200"

# 7. The actor doc is served and carries the canonical id.
if curl -sS --max-time 15 "${BASE}/actors/${handle}" \
	| grep -q "\"https://${DOMAIN}/actors/${handle}\""; then
	pass "actor doc served with canonical id"
else
	fail "actor doc missing canonical id https://${DOMAIN}/actors/${handle}"
fi

echo
echo "ALL CHECKS PASSED"
