# QR pairing — v1 design

**Status:** design.

QR pairing is the visual surface on top of the v3 profile-manifest
architecture (`docs/profile-manifest-v1.md`). The QR encodes the **v3
share URI**, not the v2 chat-card. The pairing flow piggybacks on
infrastructure etch>it and fetch>it are already building toward the
locked v3 contract; **no new rendezvous protocol is needed.**

## The architecture (recap)

From `project-autonomi-profile-v3` in memory + `docs/profile-manifest-v1.md`:

- A peer's rich profile lives on the Autonomi network as a signed
  JSON blob (≤ 1 KB) addressed by a 64-hex `profile_addr`. Signed
  by the peer's ML-DSA-65 identity (the same one x0xd holds).
- The relay runs a thin profile-index endpoint
  (`/v1/profile/{POST,GET,DELETE}`) that maps `agent_id →
  profile_addr` so consumers don't have to scrape Autonomi.
- The **v3 share URI** carries three things:
  `(agent_id, profile_addr, relay_hint)`. Per the locked design,
  this lands at ~150-200 chars — easily fits any QR code.

So the QR pairing flow is:

```
   ┌── Box A: offering its profile ──┐
   │                                  │
   │  v3 share URI:                   │
   │  fetchit://share/v3/             │
   │  <agent_id>/<profile_addr>?      │
   │  relay=<relay_hint>              │
   │  (~150-200 chars)                │
   │                                  │
   │      ▼ render to QR              │
   │  ┌─────────────┐                 │
   │  │  ███ █ ███  │                 │
   │  │  █ █  █  █  │                 │
   │  │  █ █ ███ █  │                 │
   │  └─────────────┘                 │
   └──────┬───────────────────────────┘
          │
          │ camera scan (phase 2)
          │ or paste (phase 1)
          ▼
   ┌── Box B: accepting ───────────────┐
   │                                    │
   │  1. parse v3 share URI → (aid, p_addr, relay)
   │  2. fetch profile manifest:        │
   │     GET <relay>/v1/profile/<aid>   │
   │       (fast path, relay cache)     │
   │     ┌── on miss / mismatch ──┐     │
   │     │ GET autonomi://p_addr  │     │
   │     │  (slow path, durable)  │     │
   │     └────────────────────────┘     │
   │  3. ProfileManifest::verify        │
   │     (profile.rs, already shipped)  │
   │  4. import as contact, ready to DM │
   │                                    │
   └────────────────────────────────────┘
```

There is no ephemeral token, no 5-minute TTL, no per-pair-attempt
relay-side state. The full profile is durable on Autonomi at a
stable address; the relay index is a cache + freshness pointer.

## v3 share URI literal — pinned

**Both repos implement this exact byte shape.** Drift in any
component breaks pairing.

```
fetchit://share/v3/<AGENT_ID>/<PROFILE_ADDR>?relay=<RELAY_URL>
```

Field rules:

- **Scheme + path:** literal `fetchit://share/v3/`. No alternate
  schemes (no `x0x://` for v3 to keep the chat-card `x0x://agent/`
  URI namespace separate from the profile-rendezvous namespace).
- **`<AGENT_ID>`:** 64 lowercase hex characters. Upper-case is
  rejected on parse — generators emit lowercase only so the QR
  decoder doesn't have to normalise.
- **`<PROFILE_ADDR>`:** 64 lowercase hex characters. The all-zeros
  string is reserved for tombstone records inside the relay index
  and must NOT appear in a share URI — a v3 URI with the tombstone
  address is rejected on parse.
- **`<RELAY_URL>`:** percent-encoded full base URL of the relay
  holding the offerer's profile-index record (e.g.
  `http%3A%2F%2F67.207.94.66%3A8088`). Must include scheme + host;
  scheme is restricted to `http` and `https` (no `file://`,
  `javascript:`, etc.). Trailing slashes are stripped on parse so
  `http://x/` and `http://x` normalise to the same value.
- **Order:** path components are positional; the only query
  parameter is `relay`. Future minor revisions may add additional
  optional query parameters but must not change the positional
  path order. Parsers ignore unknown query parameters.
- **Total length cap:** ≤ 256 bytes. A reference v3 URI lands at
  ~150-180 bytes depending on relay-URL length; 256 leaves headroom
  for future query params and still fits a QR version 11-M (~250
  byte capacity at error-correction level M) — well under any
  realistic camera-scan failure threshold.

Reference example (real production relay):

```
fetchit://share/v3/209574d678357a4987e25162b12f2dcee5ac82a10dfcd394edf9b340c9aa879e/4444444444444444444444444444444444444444444444444444444444444444?relay=http%3A%2F%2F67.207.94.66%3A8088
```

178 bytes. Comfortably under the cap.

Parse errors (`fetchit_chat::profile::V3ShareUriError`):

- `WrongScheme` — not `fetchit://share/v3/`
- `MalformedAgentId` — not 64 lowercase-hex
- `MalformedProfileAddr` — not 64 lowercase-hex, or is the
  all-zeros tombstone sentinel
- `MissingRelay` — no `relay=` query parameter
- `MalformedRelay` — relay URL is not a valid `http(s)` URL
- `TooLong` — total URI exceeds 256 bytes
- `UnsupportedVersion` — path starts with `fetchit://share/` but
  the next segment isn't `v3`

## What this requires (in order)

QR pairing isn't a single self-contained feature. It sits on top of
work that's specced but not yet implemented:

1. **v3 share URI format (parse + emit)** — `fetchit-chat`.
   ~150-200 char URI carrying `(agent_id, profile_addr,
   relay_hint)`. Schema lives in `docs/profile-manifest-v1.md` § 1
   but the URI form itself needs a small fetchit-chat module.

2. **Relay profile-index endpoint** — `fetchit-relay-server`.
   `POST /v1/profile`, `GET /v1/profile/{agent_id}`,
   `DELETE /v1/profile/{agent_id}`. Bodies + auth + canonicalisation
   pinned in `docs/profile-manifest-v1.md` § 4. The relay needs an
   in-memory `agent_id → ProfileIndexRecord` map plus monotonic
   `issued_at_ms` enforcement.

3. **Profile fetcher** — `fetchit-chat`. New `profile::fetch(uri)`
   that walks: relay-index GET → if mismatch / cache miss, fall
   through to Autonomi by `profile_addr`. The verifier (already in
   `profile.rs`) runs after either path.

4. **Profile publisher** — etch>it's Profile-tab. Out of scope for
   fetch>it; tracked on the etch>it side.

5. **Frontend QR display** — `apps/fetchit-desktop`. Render a v3
   share URI as a QR in the share-card dialog. The existing QR
   pane (`renderQrSvg`) handles ~150 chars easily; the "URI too
   large" fallback goes away.

6. **Frontend QR scanner** — `apps/fetchit-desktop`. Add `qr-scanner`
   npm package + Tauri 2 camera permission entry. Add-contact
   dialog grows a "Scan QR" button.

## Phasing

### Phase 1a (foundation, no UI yet)

- v3 share URI format in `fetchit-chat` (`crates/fetchit-chat/src/profile.rs`
  or sibling). `pub fn to_v3_share_uri(...)` + `pub fn from_v3_share_uri(...)`.
- Unit tests on round-trip + malformed input.
- Spec the URI scheme + cap (`fetchit://share/v3/...`) in
  `docs/profile-manifest-v1.md` (small addendum).

This is a small, contained commit. Ships independently and unblocks
everything else.

### Phase 1b (relay surface)

- `POST/GET/DELETE /v1/profile` on `fetchit-relay-server` per
  `docs/profile-manifest-v1.md` § 4.
- In-memory `DashMap<AgentId, ProfileIndexRecord>` with derive-and-
  verify on POST (re-derive `agent_id` from `ml_dsa_pubkey`, cross-
  check, monotonic `issued_at_ms`).
- Integration tests: happy-path POST → GET round-trip; agent_id
  mismatch rejected; non-monotonic POST rejected; DELETE
  tombstones.

Independent of phase 1a; can land in parallel.

### Phase 1c (fetcher + Tauri commands)

- `profile::fetch(v3_uri) → ProfileManifest` in fetchit-chat:
  parses URI, relay-index GET, verify, return.
- Autonomi fallback deferred to phase 2 — for v1 the relay-index is
  the only fetch path. If the relay misses, the user sees a "Couldn't
  fetch profile — try again later" message. This keeps phase 1
  bounded; Autonomi resolution involves `ant-core` integration that
  needs its own design pass.
- Tauri commands `chat_pair_share` (returns the v3 URI for the local
  identity) + `chat_pair_accept` (takes a v3 URI, fetches, imports).

Depends on 1a + 1b.

### Phase 2 (UI surface)

- Share-card dialog renders the v3 URI as QR (no fallback notice).
- Add-contact dialog accepts v3 URIs (paste-only); detection by
  `fetchit://share/v3/` prefix.

Depends on 1c.

### Phase 3 (camera scanner)

- `qr-scanner` package + Tauri camera permission.
- "Scan QR" button in Add-contact opens the scanner; success calls
  `chat_pair_accept`.

Depends on phase 2.

### Phase 4 (Autonomi fallback)

- `profile::fetch` grows the `autonomi://<profile_addr>` fallback
  when the relay-index GET returns 404 or a stale `issued_at_ms`.
- Bounded by `ant-core` integration scope; punt until profile
  publishers are live and we have real read traffic to size against.

### Phase 5 (LAN-direct path)

- Nearby section's "Add" button does a direct LAN card-exchange
  using the already-shipped LAN-direct transport (#100) — skips
  the relay + Autonomi entirely for the same-LAN case. Phase 5
  because it's nice-to-have; phases 1-3 cover the cross-network
  pairing case which is what QR is for.

## Out of scope

- Multi-device profiles (one agent_id, multiple devices). Phase 4+.
- "Booth mode" rotating QR. Phase 4+.
- NFC pairing. Future.
- Group-invite via QR. Future.

## Acceptance criteria

QR pairing ships (phases 1-3 collectively) when:

1. A's share-card dialog shows a working QR (no "URI too large"
   fallback for the v3 URI).
2. B scans A's QR. Within ~3 s, B's app says "Added <display_name>
   as a contact." Both can DM immediately.
3. Round-trip works cross-network (different ISPs, different
   subnets) using only the relay index — no LAN dependency.
4. v3 URI is ≤ 200 chars (QR-version-7-M comfortably).
5. Test coverage: round-trip URI parse, relay-index endpoints,
   profile fetcher.

## Related artifacts

- `docs/profile-manifest-v1.md` — the underlying v3 contract
  (schema, signing, relay index endpoints).
- `crates/fetchit-chat/src/profile.rs` — already-shipped parse +
  verify of the manifest itself (commit `cb5a34f`).
- `tests/fixtures/profile-manifest-v1/` — committed fixtures.
- `project-autonomi-profile-v3` memory — the running coordination
  state with etch>it.
- `docs/launch-polish-plan.md` § 3.6 — placeholder for QR pairing;
  this doc supersedes that one-paragraph sketch.
