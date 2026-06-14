# Outbox Lift Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the DM resend/durability logic from desktop's `outboxDriver.ts` into a `fetchit-chat` engine module that owns the outbox state, the retry loop, and the policy, so desktop and Android share one implementation.

**Architecture:** A new `outbox` module owns a vault-persisted bubble store (modeled on the in-tree `BridgeConsentStore`/`fedi_vault` pattern) plus a background `OutboxDriver` task that subscribes to the engine's own `presence_events`, re-sends retryable bubbles via `Router::send`, and runs the 24h/boot sweeps. The shell enqueues sends, starts the task, and renders an `OutboxEvent` stream. Spec: `docs/superpowers/specs/2026-06-14-outbox-lift-design.md`.

**Tech Stack:** Rust (fetchit-chat), tokio, serde, ChaCha20-Poly1305 at-rest vault (`at_rest::seal_to_path`), tokio broadcast channel; desktop TS + Tauri (Alice's lane).

**Build/gate constraint:** ALL cargo runs in the `fetchit-t8b-test` worktree (`cargo test -p fetchit-chat ...`); NEVER in the main `fetchit/` checkout (a comms daemon execs its target). Branch `outbox-lift` off chat `eb25897` (carries the merged consent store as an in-tree exemplar). DCO `git commit -s`. No em-dashes in committed code.

---

## File Structure

- **Create** `crates/fetchit-chat/src/outbox/mod.rs` — module root: `OutboxStatus`, `OutboxBubble`, `OutboxEvent` types + `is_retryable` policy fn + re-exports.
- **Create** `crates/fetchit-chat/src/outbox/store.rs` — `OutboxStore` (vault-persisted bubble map + ops + inflight guard), modeled on `groups_reachability::BridgeConsentStore`.
- **Create** `crates/fetchit-chat/src/outbox/driver.rs` — `OutboxDriver` background task with injectable `presence`/`send`/`connect` deps.
- **Modify** `crates/fetchit-chat/src/local_store.rs` — add `outbox_dir` + `outbox_path()` (mirror `bridge_dir`/`bridge_consent_path`).
- **Modify** `crates/fetchit-chat/src/lib.rs` — `pub mod outbox;` + re-exports.
- **Modify** `crates/fetchit-chat/src/client.rs` — `enqueue_dm`, `outbox_snapshot`, `subscribe_outbox`, start the driver in the production ctor (deps wired to `presence_events` / `Router::send` / `messages().connect()`).
- **Modify** `crates/fetchit-ffi/...` — expose enqueue/snapshot/events (Android lane; Task 7).
- **Desktop (Alice's lane, Task 8):** delete `apps/fetchit-desktop/src/chat/outboxDriver.ts`; send Tauri cmd -> `enqueue_dm`; ChatStore outbound bubbles become an `OutboxEvent` projection.

### Shared type definitions (used across tasks; defined in Task 2)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OutboxStatus { Sending, Delivered, Failed }

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OutboxBubble {
    pub id: String,
    pub peer: AgentId,            // DM-only; a future Recipient enum generalizes to groups (additive)
    pub body: String,
    pub status: OutboxStatus,
    pub message_id: Option<String>, // from SendReceipt; Some == relay-ACKed
    pub enqueued_at_ms: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OutboxEvent { pub bubble: OutboxBubble }  // upsert; broadcast to shells
```

---

## Task 1: StoreLayout outbox path

**Files:**
- Modify: `crates/fetchit-chat/src/local_store.rs` (struct `StoreLayout`, `ensure()`, new method)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write failing tests** (mirror the existing `bridge_*` tests)

```rust
#[test]
fn outbox_path_under_outbox_dir() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    let p = layout.outbox_path();
    assert!(p.starts_with(&layout.outbox_dir));
    assert!(p.to_string_lossy().ends_with("outbox.json.enc"));
}

#[test]
fn outbox_dir_is_sibling_and_created() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    assert_eq!(layout.outbox_dir.parent(), Some(layout.root.as_path()));
    assert!(layout.outbox_dir.exists());
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-chat --lib local_store`
Expected: FAIL to compile (`no field outbox_dir`, `no method outbox_path`).

- [ ] **Step 3: Implement** — add `pub outbox_dir: PathBuf` to `StoreLayout`; in `ensure()` add `let outbox_dir = root.join("outbox");`, add `&outbox_dir` to the create-dir loop and `outbox_dir` to the struct init; add:

```rust
/// Path of the per-peer DM outbox vault (`outbox/outbox.json.enc`):
/// a single sealed file holding all pending/failed outbound DM bubbles.
#[must_use]
pub fn outbox_path(&self) -> PathBuf {
    self.outbox_dir.join("outbox.json.enc")
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-chat --lib local_store`
Expected: PASS (all local_store tests).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/local_store.rs
git commit -s -m "feat(outbox): StoreLayout outbox_dir + outbox_path()"
```

---

## Task 2: Outbox types + is_retryable policy

**Files:**
- Create: `crates/fetchit-chat/src/outbox/mod.rs`
- Modify: `crates/fetchit-chat/src/lib.rs` (`pub mod outbox;`)

- [ ] **Step 1: Write failing tests** (in `outbox/mod.rs` `#[cfg(test)]`)

```rust
#[test]
fn bubble_serde_round_trips() {
    let b = OutboxBubble {
        id: "b1".into(), peer: AgentId("aa".repeat(32)), body: "hi".into(),
        status: OutboxStatus::Sending, message_id: Some("m1".into()),
        enqueued_at_ms: 1_000, last_error: None,
    };
    let j = serde_json::to_vec(&b).unwrap();
    assert_eq!(serde_json::from_slice::<OutboxBubble>(&j).unwrap(), b);
}

#[test]
fn is_retryable_matrix() {
    let mk = |status, mid: Option<&str>| OutboxBubble {
        id: "b".into(), peer: AgentId("aa".repeat(32)), body: "x".into(),
        status, message_id: mid.map(Into::into), enqueued_at_ms: 0, last_error: None,
    };
    assert!(is_retryable(&mk(OutboxStatus::Failed, None)));
    assert!(is_retryable(&mk(OutboxStatus::Sending, Some("m"))));
    assert!(!is_retryable(&mk(OutboxStatus::Sending, None))); // in-flight, no ACK
    assert!(!is_retryable(&mk(OutboxStatus::Delivered, Some("m"))));
}
```

- [ ] **Step 2: Run to verify fail** — `cargo test -p fetchit-chat --lib outbox` -> FAIL (module/types absent).

- [ ] **Step 3: Implement** — create `outbox/mod.rs` with the three types from "Shared type definitions" above, `use crate::identity::AgentId;`, and:

```rust
/// A bubble is eligible for retry when its previous attempt failed, or it
/// is still "sending" but the relay already assigned a `message_id` (the
/// initial ACK landed; re-firing is safe). A "sending" bubble with no
/// `message_id` is still in flight -- re-firing would double-send.
#[must_use]
pub fn is_retryable(b: &OutboxBubble) -> bool {
    matches!(b.status, OutboxStatus::Failed)
        || (matches!(b.status, OutboxStatus::Sending) && b.message_id.is_some())
}

pub mod store;
pub mod driver;
```

Add `pub mod outbox;` to `lib.rs` (alphabetical with the other `pub mod`s).

- [ ] **Step 4: Run to verify pass** — `cargo test -p fetchit-chat --lib outbox` -> PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/outbox/mod.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(outbox): OutboxBubble/OutboxStatus/OutboxEvent types + is_retryable"
```

---

## Task 3: OutboxStore (vault persistence + ops)

**Files:**
- Create: `crates/fetchit-chat/src/outbox/store.rs`

Model exactly on `groups_reachability::BridgeConsentStore` (in-tree on this branch): `load(layout, master, kdf_id, argon_salt)` fail-safe to empty; best-effort `flush()` via `at_rest::seal_to_path`; `new()` in-memory (persist `None`). Store shape: `inner: HashMap<String, OutboxBubble>` (keyed by bubble id) + `persist: Option<ConsentPersist-like handle>` + `inflight: HashSet<String>`.

- [ ] **Step 1: Write failing tests**

```rust
fn test_master() -> MasterKey { MasterKey::from_bytes_for_test([7u8; AEAD_KEY_LEN]) }
fn bubble(id: &str, peer: &str) -> OutboxBubble {
    OutboxBubble { id: id.into(), peer: AgentId(peer.repeat(64)), body: "hi".into(),
        status: OutboxStatus::Sending, message_id: None, enqueued_at_ms: 1, last_error: None }
}

#[test]
fn outbox_persists_across_reload() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    let m = test_master();
    let mut s = OutboxStore::load(&layout, &m, 0, None);
    s.upsert(bubble("b1", "a"));
    drop(s);
    let s2 = OutboxStore::load(&layout, &m, 0, None);
    assert_eq!(s2.snapshot().len(), 1);
    assert_eq!(s2.get("b1").unwrap().peer.0, "a".repeat(64));
}

#[test]
fn outbox_wrong_key_falls_back_to_empty() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    let mut s = OutboxStore::load(&layout, &test_master(), 0, None);
    s.upsert(bubble("b1", "a"));
    drop(s);
    let wrong = MasterKey::from_bytes_for_test([9u8; AEAD_KEY_LEN]);
    assert!(OutboxStore::load(&layout, &wrong, 0, None).snapshot().is_empty());
}

#[test]
fn outbox_corrupt_falls_back_to_empty() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    std::fs::write(layout.outbox_path(), b"garbage").unwrap();
    assert!(OutboxStore::load(&layout, &test_master(), 0, None).snapshot().is_empty());
}

#[test]
fn new_store_never_touches_disk() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    let mut s = OutboxStore::new();
    s.upsert(bubble("b1", "a"));
    assert!(!layout.outbox_path().exists());
    assert_eq!(s.snapshot().len(), 1);
}

#[test]
fn inflight_guard_blocks_double_claim() {
    let mut s = OutboxStore::new();
    s.upsert(bubble("b1", "a"));
    assert!(s.try_mark_inflight("b1"));   // first claim wins
    assert!(!s.try_mark_inflight("b1"));  // already inflight
    s.clear_inflight("b1");
    assert!(s.try_mark_inflight("b1"));   // reclaimable after clear
}
```

- [ ] **Step 2: Run to verify fail** — `cargo test -p fetchit-chat --lib outbox::store` -> FAIL (absent).

- [ ] **Step 3: Implement** `OutboxStore` in `store.rs`:
  - fields: `inner: HashMap<String, OutboxBubble>`, `persist: Option<OutboxPersist>` (`{ layout: StoreLayout, master: MasterKey, kdf_id: u8, argon_salt: Option<[u8; ARGON_SALT_LEN]> }`, with a manual `Debug` that redacts `master`, like `ConsentPersist`), `inflight: HashSet<String>`.
  - `new()` -> `Default`; `load(layout, master, kdf_id, argon_salt)` -> read+`open_from_path`+`serde_json::from_slice` into `inner` via a `read_map().unwrap_or_default()` helper (fail-safe), `persist: Some(..)`.
  - `upsert(&mut self, b)` -> `inner.insert(b.id.clone(), b)` then `self.flush()`; `get(&self, id) -> Option<&OutboxBubble>`; `snapshot(&self) -> Vec<OutboxBubble>` (cloned values); `remove(&mut self, id)` -> remove + flush.
  - `try_mark_inflight(&mut self, id) -> bool` (insert into `inflight`, false if present); `clear_inflight(&mut self, id)`.
  - `flush(&self)` -> best-effort `serde_json::to_vec(&self.inner)` + `seal_to_path(&p.layout.outbox_path(), &bytes, &p.master, p.kdf_id, p.argon_salt.as_ref())`, `log::warn!` + swallow on error (exact copy of `BridgeConsentStore::flush`).

- [ ] **Step 4: Run to verify pass** — `cargo test -p fetchit-chat --lib outbox::store` -> PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/outbox/store.rs
git commit -s -m "feat(outbox): vault-persisted OutboxStore + inflight guard (mirrors consent store)"
```

---

## Task 4: OutboxDriver (the loop, injectable deps)

**Files:**
- Create: `crates/fetchit-chat/src/outbox/driver.rs`

The driver owns the policy that drifts. Deps are injectable for testing:

```rust
pub const SEND_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

pub struct OutboxDriver { /* store: Arc<Mutex<OutboxStore>>, events: broadcast::Sender<OutboxEvent>, deps */ }
```

Behavior ports `outboxDriver.ts`: per-peer last-online tracking; on offline->online edge or initial-online pickup -> `flush_peer`; `flush_peer` = for each `is_retryable` bubble for that peer where `try_mark_inflight` succeeds -> `connect(peer)` (best-effort) -> `send(bubble)` -> on Ok mark `Delivered`+`message_id`, on Err mark `Failed`+`last_error` -> `upsert` (persists+emits) -> `clear_inflight`; a 24h timeout sweep; a boot sweep (`Sending` + `message_id` None + `enqueued_at_ms < process_start_ms` -> `Failed`); `flush_all` for the Retry button.

- [ ] **Step 1: Write failing tests** (scripted deps, no network; `now_ms` injected)

```rust
// A scripted send dep: returns a SendReceipt with a message_id, records calls.
// A scripted connect dep: records peers. A presence feed: a Vec of (peer, online).
#[tokio::test]
async fn online_edge_flushes_failed_bubble() {
    let store = Arc::new(Mutex::new(OutboxStore::new()));
    store.lock().await.upsert(OutboxBubble{ /* status: Failed, peer: A */ ..});
    let sent = Arc::new(Mutex::new(Vec::new()));
    let driver = OutboxDriver::new_for_test(store.clone(), record_send(sent.clone()), noop_connect());
    driver.on_presence(peer_a(), /*online=*/true).await;   // offline(default)->online edge
    assert_eq!(sent.lock().await.len(), 1);                // re-sent once
    assert_eq!(store.lock().await.get("b1").unwrap().status, OutboxStatus::Delivered);
}

#[tokio::test]
async fn sending_without_message_id_is_not_resent() {
    /* upsert Sending+None; on_presence online; assert sent == 0 (double-send guard) */
}

#[tokio::test]
async fn timeout_sweep_fails_stale_sending() {
    /* upsert Sending enqueued_at 0; driver.sweep_timeouts(now = SEND_TIMEOUT_MS + 1);
       assert status == Failed */
}

#[tokio::test]
async fn boot_sweep_fails_orphaned_sending() {
    /* store loaded with Sending+None+enqueued_at < process_start;
       driver.boot_sweep(process_start); assert Failed */
}
```

- [ ] **Step 2: Run to verify fail** — `cargo test -p fetchit-chat --lib outbox::driver` -> FAIL (absent).

- [ ] **Step 3: Implement** the driver + the test-only `new_for_test` ctor and the `on_presence`/`flush_peer`/`sweep_timeouts`/`boot_sweep`/`flush_all` methods operating over the injected deps; deps typed as boxed async closures or a small `OutboxDeps` trait (whichever keeps the test doubles simple). The production `run()` loop: `tokio::select!` over the presence stream (parsed into (peer, online) edges) and a 60s sweep timer.

- [ ] **Step 4: Run to verify pass** — `cargo test -p fetchit-chat --lib outbox::driver` -> PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/outbox/driver.rs
git commit -s -m "feat(outbox): OutboxDriver -- presence-edge retry loop + 24h/boot sweeps"
```

---

## Task 5: Client wiring (enqueue_dm, snapshot, events, start driver)

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs`

- [ ] **Step 1: Write failing test** (focused, no full ctor)

```rust
#[tokio::test]
async fn enqueue_dm_emits_sending_before_send() {
    // Build a Client/ChatState test harness exposing the outbox store + a
    // subscribe handle (reuse the cfg(test) ctor pattern at client.rs ~4037).
    // assert: after enqueue_dm, an OutboxEvent with status Sending is observed
    // on the subscribe channel, and the store has the bubble persisted.
}
```

- [ ] **Step 2: Run to verify fail** -> FAIL (no `enqueue_dm`).

- [ ] **Step 3: Implement** on `Client`/`ChatState`:
  - hold `outbox: Arc<tokio::sync::Mutex<OutboxStore>>` + `outbox_tx: broadcast::Sender<OutboxEvent>` in `ChatState` (sibling of `bridge_consent`); the production ctor builds `OutboxStore::load(&layout, &master, kdf_id, argon_salt)` (precompute before `layout`/`argon_salt` are moved, exactly like the consent store) and `broadcast::channel(OUTBOX_CHANNEL_CAP)`; the cfg(test) ctors use `OutboxStore::new()`.
  - `pub async fn enqueue_dm(&self, peer: AgentId, body: String) -> Result<String>`: make a bubble id, upsert `Sending`, emit the `Sending` `OutboxEvent` BEFORE sending (optimistic echo), then attempt the send (build `OutboundEnvelope` + `router.send(&peer, env, hints)`, the existing path at client.rs:1622/2877), mark Delivered/keep-Sending-with-message_id, upsert (persists+emits), return the bubble id.
  - `pub fn outbox_snapshot(&self) -> Vec<OutboxBubble>`; `pub fn subscribe_outbox(&self) -> broadcast::Receiver<OutboxEvent>`.
  - in the production ctor, after building `ChatState`, spawn `OutboxDriver::run` with deps: presence = `self.presence_events()` parsed to edges; send = build-envelope + `router.send`; connect = `self.messages().connect(peer)`; run the boot sweep at startup.

- [ ] **Step 4: Run to verify pass** -> PASS; also `cargo test -p fetchit-chat --lib` (all green; cfg(test) ctors unchanged behavior).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/client.rs
git commit -s -m "feat(outbox): wire enqueue_dm/snapshot/events + start the driver in the prod ctor"
```

---

## Task 6: Engine gate

- [ ] **Step 1:** `cargo fmt --all --check` -> clean.
- [ ] **Step 2:** `cargo clippy -p fetchit-chat --all-targets -- -D warnings` -> exit 0 (fix any nits; `finish_non_exhaustive()` for the redacted `OutboxPersist` Debug, like `ConsentPersist`).
- [ ] **Step 3:** `cargo test -p fetchit-chat --lib` -> all green.
- [ ] **Step 4: Commit** any gate fixes; push `outbox-lift` to josh-clsn; ping Alice with the SHA for cross-review of the engine half.

---

## Task 7: FFI surface (Android lane) -- CROSS-BRANCH

**Reality correction (2026-06-14):** the Android chat surface is the daemonless `ChatClient` in `crates/fetchit-ffi/src/chat_ffi.rs` (branch `android-tokens-v2`), NOT the Autonomi-reader `Client` in `lib.rs`. The outbox engine is on `outbox-lift`. So T7 is done on a worktree that has BOTH: branch `t7-outbox-ffi` off `android-tokens-v2` with `outbox-lift` merged in (clean auto-merge; engine `cargo check` green). Binding regen (`.so` + `fetchit_ffi.kt`) IS part of T7 -- the `.so` embeds uniffi API checksums verified at launch, so it must be regenerated TOGETHER with the `.kt` via `scripts/build-jni-libs.sh` (NDK r27 at `~/Android/Sdk/ndk/27.0.12077973`; `export ANDROID_NDK_HOME` first).

**Files:** Modify `crates/fetchit-ffi/src/chat_ffi.rs` (+ `lib.rs` re-exports); regenerate the committed `fetchit_ffi.kt` + the gitignored `arm64-v8a` `.so`.

- [ ] **Step 1 (TDD red):** add conversion tests in `chat_ffi.rs` for `OutboxStatus -> OutboxStatusFfi` (all variants) and `OutboxBubble -> OutboxBubbleFfi` (fields + peer hex). `cargo test --manifest-path crates/fetchit-ffi/Cargo.toml` -> FAIL (types absent).
- [ ] **Step 2 (impl):** add `OutboxStatusFfi` (uniffi::Enum) + `OutboxBubbleFfi` (uniffi::Record) + `From` impls; add an `Outbox { bubble }` variant to `ChatEventFfi`; in `connect()` subscribe to `inner.subscribe_outbox()` and spawn a drain task feeding the unified `tx` (mirrors the public-post drain); add methods `enqueue_dm(to_hex, body, sender_name)`, `outbox_snapshot()`, `start_outbox(display_name)` (wraps `start_outbox_driver` with a name_provider closure; stores the abort handle), `retry_outbox()`; abort the new tasks in `disconnect()` + `Drop`. Re-export the new types from `lib.rs`.
- [ ] **Step 2b (Delivered path -- CROSS-BOX DEP):** chat_ffi's `run_inbound_pump` uses the 3-arg `dispatch_inbound`, so on the daemonless path Android NEVER marks the outbox Delivered (verified: `take_transport_inbound` is take-once + chat_ffi owns the relay inbound + `spawn_default_dispatcher` has no daemonless caller, so `default_dispatch_one`/the 1462 dispatcher never runs for Android). Left unfixed, a delivered bubble stays `Sending`+message_id -> `is_retryable` true -> the driver RE-SENDS it (double-delivery). FIX: switch `run_inbound_pump` to `dispatch_inbound_with_outbox(transit, identity, registry, Some(&outbox_arc), Some(&outbox_events))` using Alice's additive `Client::outbox_arc()` + `Client::outbox_events()` accessors (on `outbox-lift-t8`; ABSENT on `outbox-lift` 1d60790). The COMPLETING commit, gated on those accessors landing + merged into the T7 worktree. Flagged to Alice 2026-06-14.
- [ ] **Step 3 (green + gate):** rerun FFI tests -> PASS; `cargo fmt --all --check` + `cargo clippy --manifest-path crates/fetchit-ffi/Cargo.toml --all-targets -- -D warnings` -> clean.
- [ ] **Step 4 (bindings):** `scripts/build-jni-libs.sh` -> regenerated `.so` + `fetchit_ffi.kt`; confirm the `.kt` carries the new ChatClient methods + types. Commit (`.so` gitignored; `.kt` committed). LIMITATION: attachments + reply_to are not carried over the FFI outbox yet (body-only bubble; the engine supports both -- a follow-up).

---

## Task 8: Desktop rewire [Alice's lane -- coordinate before executing]

**Files:** `apps/fetchit-desktop/src/chat/outboxDriver.ts` (delete), the send Tauri cmd, `src/chat/state.ts` (ChatStore), the Tauri event pump (chat.rs:1902 pattern).

- [ ] Sync with Alice on who drives this (her authored surface). Deliverables: delete `outboxDriver.ts`; the send path calls `enqueue_dm`; ChatStore outbound bubbles become an `OutboxEvent` projection -- **subscribe to the event stream FIRST, then read `outbox_snapshot`, then apply (idempotent upsert-by-id)**; the projection is **outbound-only**, coexisting with the relay-inbound pump. vitest on the projection; existing send-path tests stay green. `npm run test:run` in `apps/fetchit-desktop`.

---

## Task 9: Final review + FF handoff

- [ ] Full engine gate green (Task 6); desktop gate green (Task 8). Push; hand the branch SHA to Alice for cross-review + FF-merge to chat. (Coordination: consent already merged @ eb25897; outbox-lift rebased onto it.)

---

## Notes for the implementer

- The `BridgeConsentStore` in `crates/fetchit-chat/src/groups_reachability.rs` is the closest in-tree exemplar for Task 3 (vault persistence, fail-safe load, best-effort flush, redacted Debug, atomic seal) -- read it first.
- `at_rest::seal_to_path(path, plaintext, master, kdf_id, argon_salt)` + `open_from_path(path, master)` are the seal/open primitives; `SendReceipt.message_id: Option<String>` is the relay-ACK key.
- The production ctor (`client.rs` ~2320-2504) resolves `(master, kdf_id, argon_salt)` and `layout` -- build the `OutboxStore` BEFORE `argon_salt`/`layout` are moved into the registry/ChatState (same ordering fix the consent store used).
- DM-only; no retry cap (faithful to desktop); a bounded backoff/cap is a deferred Josh-gated improvement.
- **Retry fidelity -- attachment + reply_to drop on resend (faithful LIMITATION).** `OutboxBubble` stores `body` only, so the driver's `RealOutboxTransport::send` re-sends body-only (`messages().send(.., None, None)`): a resent message loses its original attachment + reply context. This matches desktop `outboxDriver.ts` (`deps.sendDm(peer, bubble.body)`), so it is no v1 regression. The INITIAL send via `enqueue_dm` carries `attachment` + `reply_to_message_id` in full; only the automatic retry drops them. Full-fidelity retry (persist attachment/reply per bubble) is a deferred Josh-gated improvement -- the same call as the backoff/cap above, recorded here so the drop is a conscious choice, not a silent gap.
