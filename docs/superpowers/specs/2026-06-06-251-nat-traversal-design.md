# #251 NAT-traversal design: residential-NAT story for v1.0 launch

**Owner:** [A] design, joint with [B] for M2.5 bridge surface
**Status:** design locked 2026-06-06, ready for implementation plan
**Supersedes:** none (new doc)
**Scope:** the launch-day NAT-traversal story for fetch>it on residential networks

## 1. Purpose

Make group operations work end-to-end on residential NAT topologies
(symmetric, CGNAT, mobile carrier) for v1.0 launch, with an install
experience that survives mass-adoption demand.

The empirical drivers:

- `#262` proved Box A symmetric NAT ↔ Box B cone NAT via NY relay
  closes the `MemberJoined` apply gate via the M2.5 bridge, but
  every other `NamedGroupMetadataEvent` and the MLS Welcome blob
  still rely on x0xd's native peer-to-peer reach.
- `#277` (saorsa-labs/x0x#98) confirmed joiner-side Welcome-blob
  fetch fails with `ReaderExit` on v0.21.2 under residential-NAT
  load. Upstream fix landed on saorsa-labs/x0x main 2026-06-06 as
  sha `63b5c63b` (single-flight Welcome fetches + control-message
  DM path + ACK-slot dedup); not yet in a release tag at the time
  this spec was written. Welcome-blob bridging in Layer 2 (§3.2)
  therefore lands as contingency-only and retires once the bundled
  binary pins a release containing this fix.
- `X0X-0070b` (#271) is upstream's peer-relay fallback, separate
  from the Welcome-fix above, still parked awaiting David's review.

For mass adoption, "install fetch>it, chats just work" must be the
default install story. "Install Saorsa's x0xd separately first" is a
non-starter for the consumer audience.

## 2. Approach (locked: Approach B: bundle by default)

Three composable layers:

1. **Bundled x0xd in fetch>it installer** (primary, unconditional)
2. **M2.5 bridge extension over fetchit-relay** (safety net,
   unconditional)
3. **X0X-0070b/c upstream PR** (parallel, not launch-gating)

Layer 1 is the default path. Layer 2 catches everything Layer 1 can't
reach. Layer 3 is the long-term cleanup that lands silently in a
later fetch>it release when upstream merges.

## 3. Architecture

### 3.1 Layer 1: bundled x0xd

Fetch>it installer carries a current x0xd binary as a build-time
resource.

- **Binary selection at startup.** The desktop shell's x0xd
  supervisor calls `x0xd-client::discover_installed_x0xd()`. If a
  system-wide x0xd is present at version ≥ bundled, the supervisor
  uses the installed binary (preserving Saorsa-aligned power-user
  installs). Otherwise the supervisor spawns the bundled binary on a
  managed local port.
- **Lifecycle.** Supervisor restarts crashed bundled-x0xd subprocess
  up to 3 times in 30 s; on crash-loop trip, emits `chat:warn` and
  disables the bundled binary for the session.
- **TOML preset.** The bundled binary ships with a TOML config that
  pre-pins NY (137.184.155.7) + FRA droplets as peer-relay candidates
  (deployed under `#273`). New users get working peer-relay fallback
  out of the box, no manual config.
- **Patches.** If `X0X-0070b/c` is not yet merged upstream when a
  fetch>it release ships, the bundled binary carries our patched
  build. Once upstream merges, the next fetch>it release's bundled
  binary is the upstream release, no fetch>it code change required.

### 3.2 Layer 2: M2.5 bridge extension over fetchit-relay

Extends the existing bridge (`crates/fetchit-chat/src/groups/bridge.rs`,
proven by `#262`) to cover the full surface group operations depend on:

- `NamedGroupMetadataEvent::MemberLeft` (canonical bytes, sign,
  bridge envelope kind)
- `NamedGroupMetadataEvent::MemberRoleChanged`
- `NamedGroupMetadataEvent::GroupEpochCommitted` (MLS Commit
  propagation)
- `WelcomeBlob` bytes (contingency-only): handles the `#277`
  failure window before David's `63b5c63b` Welcome-retry fix lands
  in a tagged x0xd release. The bridge variant is implemented and
  tested, but stays gated behind a `bundled_x0xd_below_v0_21_3`
  runtime check. Once the bundled binary pins a release containing
  the fix, the bridge variant retires (returns `NotNeeded` and the
  caller falls back to x0xd's native Welcome path).

Each event/blob is wrapped as a `TransitEnvelope` with a dedicated
`EnvelopeKind` variant, signed with the sender's ML-DSA chat-identity
key, sealed to the receiver's ML-KEM chat public key, and shipped via
fetchit-relay. Receiver's chat-peer unwraps and POSTs to its local
x0xd via `/groups/<id>/apply` (events) or `/groups/join-from-bridged-blob`
(Welcome bytes). x0xd dedupes by canonical event hash.

### 3.3 Layer 3: X0X-0070b/c upstream

No fetch>it code change. `#271` chases the parked PR; `#275`
follows up with the capability-bit gate. When David merges, the
next fetch>it release's bundled binary picks it up silently.

### 3.4 Test topologies (gates launch)

| Topology | Anchor | Joiner | NAT class |
|---|---|---|---|
| wyse-rig | wyse21 (Box A) | wyse37 (Box B) | symmetric ↔ cone |
| mobile-carrier | smartphone tethered laptop | wyse37 | mobile NAT ↔ cone |
| CGNAT residential | T-Mobile home internet laptop | wyse37 | CGNAT ↔ cone |

Corporate double-NAT is out of scope for v1.0 and gets a SECURITY.md
caveat (see §7).

## 4. Components

### 4.1 Layer 1

- `apps/fetchit-desktop/src-tauri/build.rs` (new): fetch + verify
  x0xd binary at build time, embed as resource per target OS.
- `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor.rs` (new
  module): detect installed x0xd version, prefer if ≥ bundled,
  otherwise spawn the bundled binary on a managed local port.
  Supervise lifecycle, restart on crash, surface health to UI.
- `apps/fetchit-desktop/src-tauri/src/main.rs`: boot the supervisor
  before app initialization, thread its port + auth token into the
  existing x0xd-client construction.
- `crates/x0xd-client/src/lib.rs`: add `discover_installed_x0xd()`
  returning `Option<InstalledX0xd { version, port, token }>`.
- Bundled `x0xd.toml` preset:
  ```toml
  [peer_relay]
  enabled = true
  candidates = ["<NY-relay-x0xd-agent-id>", "<FRA-relay-x0xd-agent-id>"]
  ```
- Tauri bundle config per OS (`.deb`, `.AppImage`, `.dmg`, `.msi`)
  carrying the bundled binary as a resource.
- Android shell does NOT get a bundled x0xd in v1.0 (FFI-only,
  larger build pipeline change). Android relies entirely on Layer 2
  for NAT-traversal. Documented in SECURITY.md as a v1.0 caveat;
  revisit post-launch.

### 4.2 Layer 2

- `crates/fetchit-chat/src/groups/bridge.rs`: extend with:
  - `canonical_member_left_bytes` + parity fixture vs upstream
    `MEMBER_LEFT_DOMAIN`
  - `canonical_role_changed_bytes` + parity fixture
  - `canonical_epoch_committed_bytes` + parity fixture
  - `welcome_request_envelope` / `welcome_blob_envelope` helpers
- `crates/fetchit-chat/src/dispatch.rs`: dispatch each new event
  kind to local x0xd via `/groups/<id>/apply` (events) or
  `/groups/join-from-bridged-blob` (Welcome blob).
- `crates/fetchit-chat/src/groups/outbox.rs` (or current outbox
  location): extend retry/queue logic for the new event types,
  mirroring the existing `MemberJoined` outbox.
- `crates/fetchit-relay-proto/src/lib.rs`: add `EnvelopeKind`
  variants `NamedGroupMemberLeft`, `NamedGroupRoleChanged`,
  `NamedGroupCommit`, `WelcomeRequest`, `WelcomeBlob`. Wire-version
  stays at 3 (additive).
- Tests: per-event-kind unit + integration coverage, parity
  fixtures vs upstream canonical bytes.

### 4.3 Layer 3

No new fetch>it code. Tracked by `#271` + `#275`.

### 4.4 Test rig infrastructure

- `private/ops/mobile-rig/` (new): instructions for smartphone
  tethered to laptop running chat-peer on cell carrier, protocol =
  wyse-rig 3×24h round-trip clone.
- `private/ops/cgnat-rig/` (new): instructions for T-Mobile home
  internet or equivalent CGNAT residential ISP, protocol same.
- Both reuse `m2_live::live_pq_group_round_trip` test scaffold with
  topology-specific env vars.

## 5. Data flow

### 5.1 Flow A: new member joins (Layer 1 happy path)

```
1. Alice's chat-peer → her x0xd: POST /groups (preset=private_secure,
                                              discoverability=Hidden)
                                  → group_id
2. Alice's chat-peer → her x0xd: POST /groups/<id>/invite
                                  → x0x://invite/<base64>
3. Alice shares invite URI out-of-band (existing share path)
4. Bob pastes invite, his chat-peer → his x0xd:
                                  POST /groups/join {invite}
5. Bob's x0xd fetches Welcome blob from Alice's x0xd via peer-relay
   candidate (NY or FRA droplet, pinned in bundled TOML)
6. MLS state advances; /members shows both. Subsequent MemberJoined
   events propagate via x0xd gossipsub through the same peer-relay
   path.
```

### 5.2 Flow B: Welcome fetch fails, bridge takes over (Layer 2)

```
1. Steps 1–3 same as Flow A.
2. Bob's x0xd Welcome fetch returns ReaderExit or times out
   (the #277 condition).
3. Bob's chat-peer detects via x0xd events feed (kind:
   welcome_fetch_failed).
4. Bob → fetchit-relay → Alice:
       TransitEnvelope {
         kind: WelcomeRequest,
         group_id,
         joiner_card,
         sender_signature: ML-DSA over canonical
       }
       (sealed to Alice's chat KEM pubkey)
5. Alice's chat-peer receives WelcomeRequest, calls local x0xd:
       GET /groups/<id>/pending-welcome/<joiner-agent-id>
       → Welcome blob bytes
6. Alice → fetchit-relay → Bob:
       TransitEnvelope {
         kind: WelcomeBlob,
         group_id,
         blob_b64,
         sender_signature
       }
       (sealed to Bob's chat KEM pubkey)
7. Bob's chat-peer POSTs to his local x0xd:
       POST /groups/join-from-bridged-blob {blob_bytes}
8. x0xd processes the Welcome internally, MLS advances, UI shows
   joined.
```

### 5.3 Flow C: MemberLeft / RoleChanged / EpochCommitted (Layer 2)

```
1. Owner mutates group via x0xd
       POST /groups/<id>/remove-member  (or role-change / commit)
2. x0xd emits NamedGroupMetadataEvent; native gossipsub attempts
   delivery via peer-relay.
3. Owner's chat-peer outbox bridges in parallel (same shape as
   M2.5 MemberJoined): canonical bytes + ML-DSA sign + TransitEnvelope
   through fetchit-relay to each member.
4. Receiver's chat-peer POSTs to local x0xd:
       POST /groups/<id>/apply {event}
5. x0xd deduplicates by canonical event hash; whichever delivery
   arrives first wins. Late arrival is a no-op.
```

### 5.4 Flow D: Group chat message (unchanged from M2)

```
1. fetchit-chat → x0xd /secure/encrypt → EncryptedFrame.
2. Wrap as TransitEnvelope kind=GroupChat, send via fetchit-relay.
3. Receivers: decrypt via local x0xd /secure/decrypt, render.
```

## 6. Error model

| Failure | Layer | Cause | Behavior |
|---|---|---|---|
| `X0xdSupervisorBindFailed` | 1 | Bundled x0xd can't bind managed port | `chat:warn`, retry next port, fall back to system-wide discovery |
| `X0xdSupervisorCrashLoop` | 1 | Bundled x0xd crashed ≥3× in 30s | `chat:warn`, disable bundled binary for session |
| `X0xdVersionMismatch` | 1 | Both bundled and system-wide below required min | UI error: "x0xd needs upgrade"; chat features disabled |
| `WelcomeFetchFailed` | 1→2 | x0xd peer-relay can't deliver Welcome blob | Trigger Layer 2 `WelcomeRequest` bridge (silent escalation, no `chat:warn`) |
| `WelcomeBridgeFailed` | 2 | Both layers exhausted; no Welcome path | `chat:warn`, group join stays `pending`, retry on relay reconnect + manual button |
| `BridgedEventApplyFailed` | 2 | x0xd rejects bridged event (canonical-bytes mismatch, stale sig, wrong epoch) | Log + drop; UI shows possible-epoch-drift indicator |
| `PeerRelayCandidatesEmpty` | 1 | Bundled TOML pin missing, gossip-announce not yet populated | Disable peer-relay; `chat:warn`; all events flow through Layer 2 |
| `LayerOneUnavailableAndroid` | 1 | Android shell has no bundled x0xd in v1.0 | Silent fallthrough to Layer 2; generic "via fetch>it relay" indicator |

Surfacing conventions:

- Bundle-side failures emit `chat:warn` on the existing channel.
- Bridge-side failures emit `chat:warn` only after first retry
  exhausted (normal-mode fallback should not raise noise).
- `WelcomeBridgeFailed` 90-second timeout matches upstream x0xd
  `WELCOME_FETCH_TIMEOUT`; then `chat:warn` + manual retry.

Non-failures (silent by design):

- Layer 1 → Layer 2 escalation is the normal operating mode for
  residential-NAT users. No `chat:warn` on routine fallback.
- Concurrent direct + bridged delivery of the same event: x0xd dedupes
  by canonical hash; late arrival is a silent no-op.

## 7. Testing

### 7.1 Layer 1 unit tests

- `x0xd_supervisor::pick_binary`, system-wide higher-version
  preferred over bundled.
- `x0xd_supervisor::pick_binary`, bundled used when system-wide
  absent or below required min.
- `x0xd_supervisor::spawn_bundled`, port-in-use retry sequence.
- `x0xd_supervisor::supervise`, crash-loop detector trips at 3
  crashes / 30 s.
- `x0xd_supervisor::shutdown`, clean SIGTERM + grace + SIGKILL.
- TOML preset fixture, peer-relay candidates parse + serialize.

### 7.2 Layer 2 unit tests

- `groups::bridge::canonical_member_left_bytes`, parity fixture vs
  upstream `MEMBER_LEFT_DOMAIN`.
- `groups::bridge::canonical_role_changed_bytes`, parity fixture.
- `groups::bridge::canonical_epoch_committed_bytes`, parity fixture.
- `groups::bridge::welcome_request_envelope`, seal/unseal round-trip.
- `groups::bridge::welcome_blob_envelope`, seal/unseal + bytes
  integrity round-trip.
- `dispatch::route_member_left`, POSTs to local x0xd
  `/groups/<id>/apply` with correct payload.
- `dispatch::route_welcome_blob`, POSTs to local x0xd
  `/groups/join-from-bridged-blob`.
- Outbox retry semantics per event kind (parity with `MemberJoined`).

### 7.3 Layer 2 integration tests (against real x0xd)

- 3-agent: Alice creates → invites Bob → invites Carol → Carol
  leaves; all three see consistent MLS state via bridged path.
- Welcome-bridge end-to-end: simulate `ReaderExit` on joiner-side via
  env hook; verify joiner reaches `MemberAdded` via Layer 2 fallback.
- Concurrent direct + bridged event arrival: x0xd dedup verified,
  late arrival no-op.

### 7.4 Layer 3 live cross-internet (`#[ignore]`'d, three topologies)

Each topology = pair (anchor + joiner) → 3 successive 24-hour rounds.
Per round: anchor creates private group, invites joiner, joiner sends
5 messages, anchor receives all. Verify which layer absorbed delivery
via metric counters; heartbeat monitor identical to Bob's wyse soak.

| Topology | Expected primary path |
|---|---|
| wyse-rig | Layer 1 peer-relay via NY/FRA; Layer 2 covers residual |
| mobile-carrier | Layer 1 usually; CGNAT-mobile carriers force Layer 2 |
| CGNAT residential | Mixed: Layer 1 when CGNAT is lenient, Layer 2 for hard CGNAT |

### 7.5 Test gate for v1.0

All three topologies pass 3-of-3 24-hour rounds within a one-week
window. Per-round soak metrics (peer-relay-attempts,
peer-relay-successes, bridge-fallback-counts) published as part of the
launch artifact.

## 8. SECURITY.md amendments

- Add caveat: "v1.0 Android shell uses fetch>it-relay for all group
  state propagation (no bundled x0xd on Android in v1.0)."
- Add caveat: "Corporate double-NAT topologies are not validated for
  v1.0; may require manual peer-relay candidate pin or operator
  support."
- Existing residential-NAT caveat from M2 close updates: replace
  "best-effort" with "validated against the three topologies in
  §7.4."

## 9. Out-of-scope changes

- DM crypto layer untouched.
- Existing public-room group flow untouched.
- Relay protocol auth (`X0xdSigner`, ML-DSA challenge-response)
  untouched.
- LAN-direct transport untouched.
- At-rest vault format untouched.
- fetch>it reader-side / Autonomi protocol untouched.
- Android x0xd FFI integration deferred post-launch.

## 10. Honest-claim posture for v1.0 launch

Binds the `#180` PQ honest-claim audit:

- **What we claim:** "Groups work end-to-end on residential NAT via a
  combination of x0xd's peer-relay fallback and fetch>it's relay
  bridge for the cases peer-relay can't traverse."
- **What we do NOT claim:** "Pure peer-to-peer on every residential
  network" (untrue under symmetric NAT both sides without a relay
  hop); "zero metadata visibility at the relay" (untrue, fetchit-relay
  sees the sender/recipient agent IDs and envelope size, just not
  content); "all NAT topologies work" (corporate double-NAT explicitly
  out of scope).
- **What SECURITY.md mirrors:** the three-layer stack, the per-layer
  visibility, the topology coverage.

## 11. Open questions (resolve during plan-writing or implementation)

1. **X0xd binary distribution mechanism**: bundle at installer build
   time vs first-run download. Lean: build-time bundle.
2. **System-wide vs bundled coexistence behavior**: auto-switch on
   system-wide x0xd install vs prompt vs never. Lean: auto-switch +
   one-shot `chat:warn`.
3. **Bundled x0xd patch sync cadence**: per-fetch>it-release vs
   auto-track. Lean: per-release, pinned to a specific upstream
   commit + our patches; CI gate enforces the pin.
4. **Welcome-bridge escalation trigger**: subscribe to x0xd events
   feed, poll `/groups/<id>/state`, or static timeout. Lean:
   subscribe to events feed.
5. **PeerRelayCandidates production discovery**: static TOML
   refresh per release until `X0X-0070c` gossip-announce subscriber
   lands; then auto-augmented at runtime.
6. **Mobile + CGNAT test rig sourcing (operational)**: specific
   carrier accounts, hardware, who runs them. Decide before
   launching the rig docs.
7. **TransitEnvelope max-payload vs Welcome blob size**: verify
   `MAX_PAYLOAD_BYTES` accepts ~33 KB; chunk only if forced.
8. **Bridge envelope-kind versioning + forward-compat**: chat-peer
   dispatches by kind; unknown kinds log + `chat:warn` + drop.

## 12. References

- `MILESTONES.md` v1.0 gate (M0 + M1 + M2 + M3 + M4 closed)
- `docs/superpowers/specs/2026-06-02-m2-x0xd-mls-adapter-design.md`
  (M2 design, where the M2.5 bridge originates)
- `crates/fetchit-chat/src/groups/bridge.rs` (M2.5 bridge already
  shipped for `MemberJoined`)
- `private/relay-federation-note.md` (hybrid-tier launch positioning;
  pass-through-relay-vs-coordinator distinction)
- `private/x0x-0070b-sender-sketch.md` (sender-side wiring sketch
  matching upstream patterns)
- saorsa-labs/x0x#98 (the `#277` upstream blocker)
- saorsa-labs/x0x#82 (the merged `X0X-0070` MVP that
  `X0X-0070b/c` build on)
