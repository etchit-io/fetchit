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
- [ ] Failing vitest cases first: share dialog renders QR + copyable short URI; add-contact accepts pair URIs and routes to the new invoke; v2 share absent from the chat header flow, present under Advanced; import error states render honestly ("couldn't reach their relay — ask them to re-share").
- [ ] Implement; region picker copy gains: "Moving relays republishes your reachability record; your contacts update automatically."
- [ ] Gates (tsc + vitest full suite); commit.

### Task 11: headless chat-peer subcommands (`fetchit-chat` bin)

**Files:** Modify `crates/fetchit-chat/src/bin/peer.rs`.

- [ ] Failing tests for the pure helpers; subcommands: `pair-share` (print pointer URI), `pair-import --uri <u>` (import via lib), reusing Bob's `send`/`read` for the cross-relay mission.
- [ ] Implement; commit.

### Task 12: cross-relay live mission + edge swarm + final gates

- [ ] Script `scripts/reachability-mission.sh`: peer A on NY, peer B on FRA (fresh vaults, throwaway x0xd instances per the m2_live topology pattern), pair via pointer URI, A→B and B→A sends asserting exit 0 via Bob's receipt-wait; then simulate a region change (B migrates to NY) and assert healing via forwarding record. Runs in CI as `#[ignore]`-style opt-in.
- [ ] Haiku edge swarm (controller dispatches, NOT a plan-task subagent): cheap-model agents generate adversarial vitest/unit cases against the new modules — malformed pair URIs, hostile relay lists (file://, 0-length, unicode hosts, 4096-char URLs), watermark rollback fuzz, pool exhaustion, migration mid-send. Findings folded as tests in a polish commit.
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
