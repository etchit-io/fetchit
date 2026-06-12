# Reachability v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cross-relay DMs, region changes, and community-relay churn work seamlessly, and replace the 12 KB share card with a QR-sized pointer — per `docs/superpowers/specs/2026-06-11-reachability-v1-design.md`.

**Architecture:** One walletless signed `PairRecord` on the relay profile index powers pointer pairing, deposit routing, and hint freshness. RelayTransport gains a per-relay connection pool. The region picker becomes a one-click migration (including the #358 teardown). Relay-server work (additive record fields, forwarding records) is Bob's lane — tasks TB1–TB2 — and lands against the proto contract in Task 1.

**Tech stack:** Rust workspace crates (`fetchit-relay-proto`, `fetchit-chat`, relay-server), Tauri desktop (`src-tauri` + TS/Vite frontend, vitest), existing ML-DSA signing via x0xd, existing QR renderer (`src/qr.ts`).

**Gates per task:** engine crates from root (`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p <crate>`); src-tauri from its own dir; frontend `npx tsc --noEmit` + `npm run test:run`. DCO sign-off on every commit. Tests in the same commit as the code.

---

## THE CONTRACT (Task 1 freezes this; Bob builds the server against it)

```rust
/// Walletless reachability record, stored on the relay profile index.
/// Additive, optional fields on the existing index record so pre-v1
/// records still parse. All-new canonical signing input (NOT the old
/// index-record signing bytes) — domain-separated.
pub struct PairRecordV1 {
    pub agent_id_hex: String,          // lowercase 64-hex
    pub ml_dsa_pubkey_b64: String,     // STANDARD base64
    pub kem_pubkey_b64: String,        // ML-KEM-768, STANDARD base64
    pub advertised_relays: Vec<String>,// priority order, 1..=4 entries,
                                       // each a valid http(s) URL ≤ 256 bytes
    pub issued_at_ms: u64,             // monotonic per agent
    pub sig_b64: String,               // ML-DSA-65 over signing input
}

pub const PAIR_RECORD_DOMAIN: &[u8] = b"fetchit-pair-record-v1";
/// signing input = DOMAIN || lp(agent_id_hex) || lp(ml_dsa_pubkey)
///   || lp(kem_pubkey) || u32_be(n_relays) || lp(relay)* || u64_be(issued_at_ms)
/// lp(x) = u32_be(len) || bytes — same length-prefix discipline as
/// fetchit-fedi attestation.

pub struct ForwardingRecordV1 {
    pub agent_id_hex: String,
    pub moved_to_relays: Vec<String>,  // 1..=4
    pub issued_at_ms: u64,
    pub sig_b64: String,               // domain b"fetchit-forwarding-v1", same lp layout
}
```

Verification everywhere: `hex(derive_agent_id(ml_dsa_pubkey)) == agent_id_hex`, signature valid, `issued_at_ms` strictly greater than the last accepted value for that agent (watermark).

**Watermark-reject wire shape (TB1 ↔ Task 3 contract):** a POST whose
`issued_at_ms` is not strictly greater than the relay's stored value is
rejected with `409 Conflict` and body `{ "current_issued_at_ms": <u64> }`.
The client publish path treats this as non-fatal: bump the logical clock to
`current_issued_at_ms + 1`, re-sign, retry **once**. Any other non-2xx
(400 bad-sig/parse, 5xx) is a real error surfaced to the caller. This is the
only reject the client auto-recovers — it carries the value so no extra GET
is needed. Forwarding-record POST uses the identical shape.

Share pointer URI: `x0x://pair/<agent_id_hex>?r=<urlencoded-relay>[&r=...]` (1..=4 relay params).

---

### Task 1: proto types + canonical bytes + verify (crate `fetchit-relay-proto`)

**Files:** Create `crates/fetchit-relay-proto/src/pair_record.rs`; modify `crates/fetchit-relay-proto/src/lib.rs` (add `pub mod pair_record;`).

- [ ] Write failing tests in the new module: canonical-bytes layout vector (mirror `fetchit-fedi/src/attestation.rs` test style: hand-built expected bytes), `verify` round-trip with a real ML-DSA keypair, reject wrong-key sig, reject derived-id mismatch, reject empty/oversize relay lists (0 and 5 entries), reject relay URL > 256 bytes, serde round-trip, ForwardingRecordV1 same suite.
- [ ] Implement `PairRecordV1`, `ForwardingRecordV1`, `pair_signing_input(...) -> Result<Vec<u8>, PairRecordError>`, `forwarding_signing_input(...)`, `verify_pair_record(&PairRecordV1) -> Result<(), PairRecordError>`, `verify_forwarding_record(...)` using `saorsa_pqc` MlDsa65 + the existing `derive_agent_id`. Watermark comparison is the CALLER's job (lib/server hold the stores) — verify here is stateless.
- [ ] Gates from root; commit `feat(proto): PairRecordV1 + ForwardingRecordV1 wire types`.

### Task 2: lib signing + watermark store (`fetchit-chat`)

**Files:** Create `crates/fetchit-chat/src/pair_record.rs`; modify `crates/fetchit-chat/src/lib.rs`.

- [ ] Failing tests: `build_signed_pair_record(identity, signer, relays)` produces a record that `verify_pair_record` accepts and whose agent id matches the identity; monotonic watermark store accepts greater, rejects equal/lesser (file `pair_record_watermarks.json` under the store layout, atomic temp+rename + mutex — mirror `profile.rs` watermark pattern from src-tauri but lib-side under `StoreLayout`).
- [ ] Implement build/sign via the `Signer` trait (`signer.sign(bytes)` like `sign_actor_attestation`), watermark load/save on `StoreLayout`.
- [ ] Gates; commit.

### Task 3: lib publish + fetch (`fetchit-chat`)

**Files:** Modify `crates/fetchit-chat/src/pair.rs` (fetch side, mirror `fetch_index_record_by_id`), `crates/fetchit-chat/src/pair_record.rs` (publish), `crates/fetchit-chat/src/client.rs` (auto-publish hook on connect).

- [ ] Failing tests (wiremock, same harness as existing pair.rs tests): `publish_pair_record(relay, &record, http)` POSTs to `/v1/pair-record` and surfaces non-2xx; `fetch_pair_record_by_id(relay, agent_id, http)` GETs `/v1/pair-record/<id>`, verifies signature + derive-binding + cross-checks requested id, rejects tampered records; 10s timeout preserved.
- [ ] Implement both; wire auto-publish into client connect path (after relay session up, best-effort with `log::warn` on failure — must not block chat startup).
- [ ] Gates; commit.

### Task 4: pointer URI emit/parse + import (`fetchit-chat`)

**Files:** Modify `crates/fetchit-chat/src/card.rs` (or sibling `pair_uri.rs` if card.rs exceeds ~600 lines), `crates/fetchit-chat/src/client.rs` (import entry point).

- [ ] Failing tests: emit `x0x://pair/<id>?r=...` from agent id + relays (urlencoding, 1..=4 r params); parse round-trip; parse rejects bad hex, zero relays, >4 relays, non-http(s) schemes (SSRF guard — http/https only, host non-empty); `import_pair_uri(uri)` happy path via wiremock relay (fetch record → StoredContactCard saved with kem/dsa keys + advertised relays), error path when no hinted relay reachable.
- [ ] Implement emit/parse + `Client::import_pair_uri` (fetch first reachable hint → verify → persist StoredContactCard + x0xd legacy import like the existing import flow).
- [ ] Gates; commit.

### Task 5: per-relay connection pool + deposit routing (`fetchit-chat`)

**Files:** Modify `crates/fetchit-chat/src/relay_transport.rs` (the `let _ = hints;` line dies here), `crates/fetchit-chat/src/router.rs` if signatures shift.

- [ ] Failing tests: pool returns the same live connection for repeated sends to one relay; creates a second connection for a second relay; `send` with hints deposits at the FIRST reachable hinted relay (wiremock-style fake relays or the existing transport test fakes — follow `relay_transport.rs` test harness); falls back through the hint list on connect failure; no hints → own relay (current behavior preserved); idle connections reaped after `POOL_IDLE_MS` (5 min, constant).
- [ ] Implement: `struct RelayPool { by_url: Mutex<HashMap<String, PooledConn>> }` inside RelayTransport; connection setup reuses the existing challenge/verify auth + WS dial path; own-session (listen) untouched; deposit walk in `send`.
- [ ] Gates; commit. **This is the security-sensitive task — sender auth per pooled connection must be identical to the primary session's.**

### Task 6: in-band hint refresh (`fetchit-chat`)

**Files:** Modify `crates/fetchit-chat/src/conversation/types.rs` (MessagePayload additive field), `crates/fetchit-chat/src/messages.rs` (attach on send), `crates/fetchit-chat/src/conversation/inbound.rs` (apply on verified inbound).

- [ ] Failing tests: payload serde back-compat (old payloads parse, field defaults None); outbound send embeds the sender's current advertised list; verified inbound with a NEWER list updates the StoredContactCard (and not on older/equal `issued_at_ms` — reuse the pair-record watermark per contact); unverified path never updates.
- [ ] Implement with `#[serde(default)] pub advertised_relays: Option<Vec<String>>` + a `hint_epoch_ms: Option<u64>` stamped from the sender's current pair record.
- [ ] Gates; commit.

### Task 7: forwarding records + deposit-failure re-resolve (`fetchit-chat`)

**Files:** Modify `crates/fetchit-chat/src/pair_record.rs` (write/fetch forwarding), `crates/fetchit-chat/src/messages.rs` (re-resolve on deposit failure).

- [ ] Failing tests: `write_forwarding_record(old_relay, moved_to, ...)` POSTs signed record; on deposit walk exhausting all hints, send fetches `/v1/forwarding/<id>` from each stale hint, verifies (sig + derive + watermark), retries deposit at `moved_to_relays`, persists the refreshed card; forged/rolled-back forwarding rejected.
- [ ] Implement; bound the re-resolve to one hop (no forwarding chains — a forwarded-to relay's record is final for this send; log if it also fails).
- [ ] **Forwarding POST response handling (TB2 contract, decided 2026-06-11 — Option A):** the relay verifies the forwarding sig server-side against the agent's stored pair-record. So `write_forwarding_record` must handle: `409 {"current_issued_at_ms":N}` → bump logical clock to N+1, re-sign, retry once (same as pair-record publish); `412 Precondition Failed` (old relay has no pair-record for this agent — evicted edge) → NON-FATAL: log and skip the forwarding write, the migration still succeeds and healing falls back to the in-band hint refresh (Task 6) + Autonomi manifest republish (Task 9). Never fail a region migration because the forwarding write 412'd. `403` (bad sig — shouldn't happen for our own records) → real error.
- [ ] Gates; commit.

### Task 8: home-relay failover (`fetchit-chat`)

**Files:** Modify `crates/fetchit-chat/src/client.rs` + `relay_transport.rs` reconnect path.

- [ ] Failing tests: when the primary relay is unreachable for `FAILOVER_AFTER_MS` (2 min constant; test with short override), the client connects to the next advertised relay, re-registers, republishes its PairRecord there, and emits a state callback (the desktop will toast it); recovery back to primary is NOT automatic (sticky until next boot or manual change — simplest correct behavior, documented).
- [ ] Implement on the existing auto-reconnect machinery (#127) — failover is "reconnect with the next URL + republish."
- [ ] Gates; commit.

### Task 9: desktop — one-click region migration + #358 teardown (`src-tauri`)

**Files:** Modify `apps/fetchit-desktop/src-tauri/src/lib.rs` (`set_relay_url`), `apps/fetchit-desktop/src-tauri/src/chat.rs` (pump lifecycle: store pump JoinHandles on ChatState; abort + respawn on swap).

- [ ] Failing tests (src-tauri unit level where the seams allow): pump-handle registry aborts all handles on `migrate_relay`; new pumps bind the rebuilt client (test via the ChatState test hooks used by existing chat.rs tests); migration sequence = teardown → connect new → publish PairRecord at new → best-effort ForwardingRecord at old → settings persist; each step's failure surfaces in the returned status struct (no silent partial migrations).
- [ ] Implement `migrate_relay(url)` replacing the old `set_relay_url` body; keep the command name (frontend API unchanged) but return a `MigrationReport { connected, pair_published, forwarding_written, manifest_republished: Option<bool> }`.
- [ ] Gates from src-tauri dir; commit.

### Task 10: desktop — share UI swap + import + Advanced demotion (frontend)

**Files:** Modify `apps/fetchit-desktop/src/chat/panel.ts` (Share my card button → pointer URI + QR via existing `src/qr.ts`), `apps/fetchit-desktop/src/chat/api.ts` (+`pairShareUri()`, `importPairUri()` invokes), the add-contact dialog module (accept `x0x://pair/` URIs), `apps/fetchit-desktop/src/settings.ts` (v2 extended URI moves under Advanced with honest copy), matching `src-tauri` commands `chat_pair_share_uri` / `chat_import_pair_uri` wrapping the lib.
- [x] Failing vitest cases first: share dialog renders QR + copyable short URI; add-contact accepts pair URIs and routes to the new invoke; v2 share absent from the chat header flow, present under Advanced; import error states render honestly ("couldn't reach their relay — ask them to re-share").
- [x] Implement; region picker copy gains: "Moving relays republishes your reachability record; your contacts update automatically."
- [x] Gates (tsc + vitest full suite); commit.

### Task 11: headless chat-peer subcommands (`fetchit-chat` bin)

**Files:** Modify `crates/fetchit-chat/src/bin/peer.rs`.

- [x] Failing tests for the pure helpers; subcommands: `pair-share` (print pointer URI), `pair-import --uri <u>` (import via lib), reusing Bob's `send`/`read` for the cross-relay mission.
- [x] Implement; commit.

### Task 12: cross-relay live mission + edge swarm + final gates

- [x] Script `scripts/reachability-mission.sh`: peer A on NY, peer B on FRA (fresh vaults, throwaway x0xd instances per the m2_live topology pattern), pair via pointer URI, A→B and B→A sends asserting exit 0 via Bob's receipt-wait; then simulate a region change (B migrates to NY) and assert healing via forwarding record. Runs in CI as `#[ignore]`-style opt-in.
- [x] Haiku edge swarm (controller dispatches, NOT a plan-task subagent): cheap-model agents generate adversarial vitest/unit cases against the new modules — malformed pair URIs, hostile relay lists (file://, 0-length, unicode hosts, 4096-char URLs), watermark rollback fuzz, pool exhaustion, migration mid-send. Findings folded as tests in a polish commit.
- [ ] Full workspace + src-tauri + frontend gates; push; cross-review exchange with Bob (his TB1/TB2 ↔ my T5/T7 — the deposit auth and forwarding verify are the sensitive seams).

### Bob's lane (work order via pipe; lands against Task 1's proto)

- **TB1:** relay-server `/v1/pair-record` store/serve: POST validates `verify_pair_record` + per-agent watermark (RAM + the same persistence posture as the profile index), GET serves by agent id. Rate-limit POSTs per sender like profile.
- **TB2:** `/v1/forwarding/<id>` store/serve with ~30-day TTL sweep; same validation discipline.
- **TB3:** confirm pooled deposit connections hit the same auth/rate-limit path as primary sessions (expected zero code; verify + test).

---

## Hardening folded from the haiku edge-hunt (2026-06-11)

Kept findings, mapped to owning tasks. Each becomes a test or a small guard
in that task — not new tasks, except the clock item which changes Task 2.

**DESIGN CHANGE — Task 2 (and retro-fixes #191 profile watermark):**
A pure wall-clock millisecond watermark **permanently bricks publishing** if a
device's clock ever moves backward (battery-dead reset, VM snapshot, manual
change) — strict-greater rejects every future publish forever. Grandma
hardware does this. FIX: the publishing side uses a **logical monotonic clock**
— `next = max(wall_clock_ms, last_watermark + 1)`, persisted — so local
publishes are always increasing regardless of the system clock; the relay
keeps its strict-greater check unchanged. Task 2's watermark store implements
this. NOTE (corrected post-build): fetch>it's `src-tauri/profile.rs` watermark
is CONSUMER-side downgrade-defense (strict-reject is correct there, no brick).
The publish-side brick analogue lives in **etch>it's** profile publisher
(separate repo) -- flag as a cross-repo follow-up when in that repo; nothing
to retrofit in fetch>it. Document
single-agent-multi-device as explicitly unsupported in v1 (two devices racing
the same logical clock is out of scope).

**Task 1 (proto) — already covers** strict lowercase-64-hex, http(s)+host-only
relay scheme, ≤256-byte relay, 1..=4 relays. ADD: reject relay URLs carrying
userinfo (`user:pass@`) — credentials never belong in a pair record.

**Task 4 (URI parse) — ADD tests + guards:** total URI length cap (≤512 bytes,
rejects un-scannable QR before render); URL-normalize relays (lowercase host,
strip default port, strip trailing slash) so cosmetic dupes collapse; reject
duplicate-after-normalize relays; honest user-facing error on bad scheme (not
silent); reject importing one's OWN agent id (warn).

**Task 5 (pool/deposit) — ADD tests:** pool keys on the NORMALIZED relay URL
(no duplicate connections for cosmetic variants); a pooled connection whose
auth fails is PURGED, not retained-dead (health-check on checkout); a hint list
containing the sender's own relay reuses the listen session, not a dup.

**Task 5/7 — terminal honest failure (ties to #355):** when the deposit walk
AND forwarding re-resolve both exhaust, the send surfaces a typed
`AllRelaysUnreachable` error to the UI — never a silent drop. Test it.

**Task 6 (in-band refresh) — concurrency + security:** the StoredContactCard
update must be atomic against a concurrent manual import (mutex or CAS); a
verified inbound hint older-or-equal to the stored hint watermark is ignored.
DOC the known limit: a compromised key that published a higher-watermark
record before rotation can poison hints until the victim republishes — key
revocation is the real fix, out of v1 scope; note it in SECURITY.md.

**Task 8 (failover) — ADD:** on failover, prune the dead relay from the local
advertised list and republish, so contacts stop wasting deposits on it.

**Task 9 (migration) — already returns MigrationReport.** ADD: on next boot,
if the persisted relay differs from where the last PairRecord published
(detectable via the watermark store's recorded relay), retry publish +
forwarding — closes the killed-mid-migration gap. Do NOT commit the settings
relay change until the new-relay connect succeeds (avoid the deaf-offline
state).

**Task 10 (share UI) — ADD:** gate the "Share my card" affordance on
PairRecord publish confirmation (show "Publishing…" until confirmed) so a
shared URI never 404s on import; honest "you're offline, can't import" state.

**Amplification note (P3, no code):** a contact advertising a third party's
server only causes ONE 404'd GET there (that server has no signed record for
the agent), so amplification is bounded; the existing signature+derive binding
defends impersonation. No action; recorded so it isn't re-raised.

---

## Task 13: SSRF guard on relay-bound requests (`fetchit-chat`) -- SECURITY, launch-gate

**Found 2026-06-11** during the T4 pointer-URI edge-hunt. The deposit model is the
first time the client issues HTTP requests to relay URLs SUPPLIED BY CONTACTS
(advertised_relays in a signed pair/forwarding record, or a scanned pair URI).
The relay-proto validator checks scheme(http/https)+host+no-userinfo but NOT the
address range. So a malicious-but-paired contact can advertise
`http://127.0.0.1:<port>` / `http://169.254.169.254` / `http://[::1]` / RFC1918
as their relay, and the client will dial it on deposit (POST via the pool),
pair-record GET, and forwarding GET. Desktop-side the main risk is loopback /
link-local probing of the user's own local services (x0xd, media server); the
response must still verify as a signed record so it is blind/probe SSRF, not
direct exfil -- but it is a real trust-boundary expansion for a security-first,
grandma-ready app. Pre-existing on `fetch_pair_record_by_id` (T3); T7 mirrors it.

**Files:** Modify `crates/fetchit-chat/src/pair.rs` (both fetch fns), the deposit
client construction in `relay_transport.rs`, and add a shared
`reject_private_relay_host(url) -> Result<()>` helper (new small module or in
pair_record.rs) reused by every relay-bound request.

- [ ] Failing tests: the guard rejects IP-literal loopback / link-local
  (169.254/16, fe80::/10) / RFC1918 (10/8, 172.16/12, 192.168/16) / ULA (fc00::/7)
  / 0.0.0.0 / metadata 169.254.169.254; accepts public IP literals and DNS names;
  a DEV carve-out (env `FETCHIT_ALLOW_LOCAL_RELAY=1`, matching the #349 dev-relay
  precedent) permits loopback so local dev + the m2_live localhost topology keep
  working. Each relay-bound call site rejects a private URL before dialing.
- [ ] Set `reqwest` redirect policy to `Policy::none()` on these requests (a
  302 -> 169.254.169.254 bypasses a URL-only check). Resolve-and-recheck DNS
  hostnames where cheap; full DNS-rebind race defense is explicitly DEFERRED
  post-v1 (documented limitation in SECURITY.md).
- [ ] Gates; commit. Cross-review with Bob (he owns the M3 trust-path SSRF fold
  #332/#335; reuse his validator if one exists rather than writing a parallel).

**Decision needed from Josh (non-blocking, has a sane default):** how permissive
the dev carve-out is. DEFAULT chosen: loopback allowed ONLY when
`FETCHIT_ALLOW_LOCAL_RELAY=1` (off in shipped builds), private ranges always
rejected in release. Flag if a different posture is wanted.

---

## Post-T6 harden items (do in the T7 review-harden; pair.rs is locked by T7 impl until then)

- **[P1, Bob cross-review 2026-06-11] pair_accept sibling of the import bypass.**
  `pair.rs::pair_accept` does `record_into_stored_contact(...)` (builds card with
  `last_hint_epoch_ms: None`, `rendezvous_hints: None`) then plain
  `stored.save(layout)` -- no CARD_UPDATE_LOCK, no watermark preservation. Same
  downgrade-window re-open that ca695b4 closed in `import_pair_uri`, but on the
  LIVE v3 profile-pair path (`chat_pair_accept` Tauri cmd -> panel.ts). FIX: route
  through `StoredContactCard::save_imported(layout)` (the helper added in ca695b4).
  One line + a regression test mirroring `save_imported_preserves_hint_watermark_*`.
- **[LOW, Bob cross-review 2026-06-11] absurd-future epoch permanently bricks a
  contact's auto-heal.** A malicious verified contact (or a pre-c34355c glitched
  peer) can send ONE `hint_epoch_ms` = huge; `apply_relay_hint` then stores it and
  rejects every real future hint (strict-greater) forever, and `save_imported`
  deliberately preserves it so even a QR rescan can't recover (only deleting the
  contact does). T7 re-resolve also persists via apply_relay_hint so it inherits
  the brick (send still heals per-send via the fetched moved_to, just never
  caches). FIX (cannot be a re-import recovery -- that re-opens the downgrade
  window): clamp at apply time -- reject `hint_epoch_ms > now_ms + MAX_FUTURE_SKEW`
  (generous, e.g. 7 days). Needs `now_ms` threaded into apply_relay_hint; update
  the T7 re-resolve call site in the same commit. Defense-in-depth, genuinely LOW.

### T13 implementation blueprint (from Bob's M4 SSRF primitives, 2026-06-11)

REUSE, do not re-implement. `crates/fetchit-fedi/src/webfinger.rs` already holds the
canonical detection (M4 SSRF fold; doc at line 180 says it was scoped crate-wide
precisely so future fetch paths share ONE detector). `fetchit-chat` already depends
on `fetchit-fedi` (its Cargo.toml ~line 33). Three primitives, currently `pub(crate)`:
- `private_ip_reason(&url::Host)` (line 264) -- pre-flight gate on IP literals in a
  URL; catches `http://127.0.0.1` before any dial.
- `is_private_ip_addr(IpAddr)` (line 192) -- post-DNS twin; covers v4 private/
  loopback/link-local/multicast/broadcast/unspecified + v6 loopback/unspecified/
  multicast/v4-mapped/ULA fc00::/7/link-local fe80::/10.
- `resolve_and_pin_host(host, port)` (line 243) -- lookup_host, validates EVERY
  resolved addr (partial-results-safe), returns SocketAddrs for reqwest
  `resolve_to_addrs` pinning. This is the anti-DNS-rebind piece a naive
  check-then-dial misses (TTL=0 host passes the check then resolves private at
  connect).

Plan (agreed with Bob):
- Lift the three into a neutral `pub mod ssrf` in `fetchit-fedi` (~30 line move) with
  a neutral error type, so `WebFingerError` does not leak into `ChatError`; webfinger
  callers keep their unconditional gate.
- Add CGNAT `100.64.0.0/10` (source gap flagged V-7) to BOTH twins (mirror-for-mirror,
  one line each) -- contact-supplied relay URLs warrant it.
- reqwest paths (`fetch_pair_record_by_id`, T7 forwarding fetch, deposit POST): pin via
  `resolve_to_addrs` + set redirect `Policy::none()`.
- WS pool connect (tokio-tungstenite, in `relay_transport.rs`) CANNOT use
  `resolve_to_addrs`: connect the TCP socket to the pinned `SocketAddr` directly and
  pass the hostname only for SNI/TLS, else the pool re-resolves and reopens the hole.
- Dev carve-out (`FETCHIT_ALLOW_LOCAL_RELAY=1`) lives at the CALL SITE, not inside the
  pure primitives.
- Cross-review with Bob (he owns webfinger.rs).

**T13 UPDATE 2026-06-11: fedi half DONE (Bob, reachability-tb `4760eab`).** New
`crates/fetchit-fedi/src/ssrf.rs` -- `pub is_private_ip_addr` / `private_ip_reason`
/ `resolve_and_pin_host` + neutral `SsrfError {Resolve, PrivateAddress}`; shared
`is_private_v4` folds CGNAT 100.64/10 everywhere incl the IPv4-mapped-IPv6 arm;
boundary tests pin the /10; webfinger+actor callers map locally (zero behavior
change); module docs spell out the 3-step call pattern + dev-carve-out-at-call-site
rule; 19 ssrf tests, gates green. Arrives in `chat` via the reachability-tb merge.
REMAINING (my chat-side, post-T7/T8): wire the 3 reqwest fetch paths
(`fetch_pair_record_by_id`, T7 `fetch_forwarding_record_by_id`, deposit POST) with
`resolve_to_addrs` pin + redirect `Policy::none()`; the WS pool connect with a
pinned-SocketAddr direct TCP + hostname-only SNI; `FETCHIT_ALLOW_LOCAL_RELAY=1`
carve-out at each call site.

---

## Task 8 REVISED (2026-06-11, after code-explorer mapped the real architecture)

The plan's original "failover = reconnect with the next URL" framing was WRONG for
the actual stack. Reality (explorer, file:line cited):
- Production chat uses `MultiHomeTransport` (transport/multi_home.rs), NOT RelaySet's
  fan-out, for own-relay listening. 3 slots: slot 0 = pinned PRIMARY (the only relay
  receiving INBOUND at boot, eviction-IMMUNE), slots 1/2 = LRU outbound-to-contacts.
- Each slot = single-URL RelayTransport -> RelaySet(one URL) -> one Client supervisor.
- #127 reconnect retries the SAME url, backoff 1s..60s, max_reconnect_attempts=20
  (~20 min), then `ConnState::PermanentlyDisconnected` = dead handle, must rebuild.
  NO cross-URL fallback exists anywhere below or at MultiHomeTransport.
- `publish_pair_record` POSTs to `primary_relay_url` and advertises ONLY
  `[primary_relay_url]` (NOT the advertised_relays RwLock).

So T8 is NEW machinery, NOT extending reconnect:
- **T8a -- `MultiHomeTransport::replace_primary(new_url)` primitive (the hard part).**
  Cleanly tear down slot 0 (abort the old inbound pump task, drop the old transport,
  no leaked WS), connect the new URL, spawn the new fan-in pump, swap the slot-0
  handle. MUST verify inbound actually flows on the new relay before declaring success
  (a "connected but deaf" swap is the #358 failure mode). This primitive is shared:
  failover (T8b) and the T9 desktop region-migration both call it, and building it
  right FIXES #358 (set_relay_url hot-swap leaks old WS + detaches inbound pump ->
  silent deaf client) AT THE LIB LAYER. T9 then becomes "call replace_primary".
- **T8b -- failover trigger/policy.** Observe slot-0 `states_receiver()`; when it is
  PermanentlyDisconnected (or Disconnected continuously for FAILOVER_AFTER_MS = 2min,
  no wall-clock gate exists today so add one), pick the next advertised URL, call
  replace_primary, update `Client.primary_relay_url`, republish the pair record at the
  new relay, prune the dead relay from advertised_relays + regenerate the share card,
  emit a state callback (desktop toast). Sticky (no auto-recover to primary in v1).
- Risk: this is the highest-risk task in the plan (slot-0 inbound pump teardown = the
  silent-deaf surface). Bar: tests must assert inbound LIVENESS post-swap, not just
  "connected". Bob cross-reviews (he owns the relay-client reconnect machinery).
- Key files: transport/multi_home.rs (slot-0 pinning, acquire_slot skips idx 0 -> add
  replace_primary), relay_transport.rs (connect + spawn_inbound_pump), client.rs
  (primary_relay_url:398, advertised_relays:370, publish_pair_record:1525), relay-client
  client.rs (ConnState::PermanentlyDisconnected, states_receiver, max_reconnect_attempts).

### T8 model RESOLVED (explorer + Bob reconciled, 2026-06-11)

Definitive (multi_home.rs:6-24 module docs + relay_transport.rs:88 + client.rs):
- Production = `MultiHomeTransport`. Slot 0 = primary, PINNED at boot, NEVER evicted,
  and the ONLY relay listening inbound until outbound traffic to a differently-homed
  contact opens slot 1/2 (those then also fan in). Each slot = single-URL
  RelayTransport -> RelaySet(1 url) -> one Client supervisor.
- Bob was describing the RelaySet PRIMITIVE (all its urls receive) which each slot
  wraps with exactly one url; not a contradiction.
- Per-Client reconnect: same url, backoff, max_reconnect_attempts(~20) ->
  PermanentlyDisconnected = dead, rebuild required. NO cross-url switch anywhere.
- pair-record publish advertises ONLY `[primary_relay_url]` (client.rs:1534), HTTP
  path independent of the WS set.

Failover = REBUILD (set is fixed-size, nothing to promote/swap):
watch slot-0 states_receiver() -> PermanentlyDisconnected (or sustained Disconnected
past FAILOVER_AFTER_MS=2min, add the wall-clock gate) -> build a replacement
Client/slot-0 transport on the next advertised url (clean teardown of the old slot-0
inbound pump = the #358 deaf surface; assert inbound LIVENESS post-swap) -> update
Client.primary_relay_url -> republish pair record at the new relay -> prune dead relay
from advertised_relays + regenerate card -> state callback. Sticky, no auto-recover.

DESIGN SUBTLETY (document, do not over-build): the forwarding record (T7) does NOT
heal the dead-primary case -- you cannot POST or FETCH a forwarding record at a DEAD
relay, and the pair record lists only the dead primary. So a stale sender depositing
per your old pair record is stuck until (a) you send them a DM from the new relay
(T6 in-band hint refresh updates their card) or (b) they read your Autonomi v3 manifest
(T9, wallet tier). Free-tier home-relay-DEATH healing for inbound-from-stale-senders is
therefore best-effort; contacts you actively message heal immediately. Note in
SECURITY.md / the failover state-callback copy. (Region MIGRATION, T9, is different:
the old relay is ALIVE so the forwarding record DOES heal it.)

Bob's T7 cross-review: pair_accept fix VERIFIED clean (save_imported + regression);
full forwarding-vs-TB2 verdict shortly.
