# Outbox Lift: shared DM resend/durability in `fetchit-chat`

**Date:** 2026-06-14
**Owner:** Bob (Box B) drives the engine + design; Alice cross-reviews the transport/presence/desktop lane.
**Status:** design approved (Josh, 2026-06-14, incl. the three open-question decisions below); pending Alice cross-review, then writing-plans.

## Goal

One DM resend/durability implementation, owned by the `fetchit-chat` engine, so desktop and Android share it and never drift. Desktop's `apps/fetchit-desktop/src/chat/outboxDriver.ts` is retired; the Android chat shell (on the unmerged `android-lit` branch) gets resend-on-reconnect for free with zero orchestration code.

## Background

Desktop carries the resend/durability logic in TypeScript (`outboxDriver.ts`): on each peer offline->online edge (or initial-online pickup) it re-sends every retryable outbound DM bubble; a 24h sweep flips long-stuck "sending" bubbles to "failed"; a boot sweep marks orphaned sends failed; an inflight set plus the relay-ACK `messageId` guard against double-send. None of it lives in the shared engine, so Android would need a Kotlin re-implementation = the exact drift we are lifting to kill.

Code-verified (Alice, 2026-06-14): the engine already owns both loop inputs.
- **Presence:** `Client::presence_events` SSE (client.rs:1870) + `Client::presence()` snapshot (client.rs:1268). Desktop `store.isOnline` is downstream of this (chat.rs:842).
- **Send:** `Router::send` (transport/mod.rs:208) returns `SendReceipt { accepted_at_ms, message_id: Option<String>, transport_name }`; the relay sets `message_id` to the dedupe-key hex, LAN-direct may leave it `None`. This maps exactly onto the desktop bubble's `messageId` double-send semantics. Desktop `sendDm` is downstream of this (chat.rs:805).

So the engine can own the whole retry loop. Persistence follows the at-rest sealed-vault pattern already in the tree (`fedi_vault.rs` + `at_rest::seal_to_path`/`open_from_path`).

## Open-question decisions (approved)

1. **Scope: DM-only.** Matches the proven `outboxDriver` scope. Group messages have their own durability path (MLS catch-up on rejoin), so there is no group-resend gap, and group retry would add member fan-out + epoch complexity for an unproven need. The `OutboxBubble` recipient field is shaped so a future conversation/group key is an additive extension, not a rewrite.
2. **Surfacing: snapshot-on-init + `OutboxEvent` stream.** Mirrors the codebase's own pattern (`presence.rs`: `online()` snapshot + `/presence/events` stream) and how the desktop store already consumes presence/inbound. Exact ChatStore reconciliation is Alice's model.
3. **Warm-connect: expose `Client::connect_peer` now.** Zero-Android-orchestration is the reason for engine-owns-the-loop; a shell-supplied connect callback would leave Android wiring it. `connect_peer` is a small `Http POST /agents/connect` primitive (per-peer direct-path warm; distinct from the X0xdSigner session warmup at client.rs:2343). The driver still takes injectable deps for testability, wired to `Client` primitives in production.

## Architecture

A new `outbox` module in `crates/fetchit-chat/src/` owns:
1. **State** -- pending-DM bubbles, vault-persisted at rest (survive restart).
2. **Loop** -- a background task subscribing to the engine's own `presence_events`, detecting offline->online edges, re-sending retryable bubbles via `Router::send`.
3. **Policy** -- isRetryable / 24h timeout-sweep / boot-sweep / double-send guard, all engine-side.

Shells become thin: enqueue a send, start the task once at client init, render outbox state from the snapshot + event stream.

## Components

### `OutboxBubble`
- `id: String` (client-assigned), `recipient` (newtype over `AgentId` now; the seam for a future conversation key), `body: String`, `status: OutboxStatus` (`Sending` | `Delivered` | `Failed`), `message_id: Option<String>` (from `SendReceipt`; `Some` = relay-ACKed), `enqueued_at_ms: u64`, `last_error: Option<String>`.
- serde-serializable (vault persistence + FFI/event surfacing).

### `OutboxStore`
Bubble map + persistence, modeled on `fedi_vault.rs` / the sibling `BridgeConsentStore`:
- vault-sealed at `<data_dir>/outbox/outbox.json.enc` via `at_rest::seal_to_path` (new `StoreLayout::outbox_dir` + `outbox_path()`, sibling of `contacts/conversations/fedi`, 0700).
- `load(layout, master, kdf_id, argon_salt)` fail-safe to empty on missing/corrupt/wrong-key/unparseable; never hard-fails startup.
- best-effort `flush()` after each mutation (warn+swallow via `log::warn!`; in-memory authoritative; atomic temp+rename).
- in-memory inflight-guard `HashSet<id>` (not persisted -- in-flight tasks die with the process; the boot sweep reclaims orphans).

### `OutboxDriver` (background task)
Injectable deps (so it is unit-testable with scripted doubles):
- `presence`: stream of `PresenceTransition` (prod: `Client::presence_events`).
- `send`: `Fn(&OutboxBubble) -> Future<Result<SendReceipt>>` (prod: build envelope + `Router::send`).
- `connect`: `Fn(&AgentId) -> Future<()>` (prod: `Client::connect_peer`).
- a handle to the `OutboxStore` and the `OutboxEvent` sender.

Behavior (port of `outboxDriver.ts`):
- track per-peer last-online; on offline->online edge OR initial-online pickup -> `flush_peer(peer)`.
- `flush_peer`: each retryable bubble for that peer not already inflight -> mark inflight -> `connect(peer)` (best-effort) -> `send(bubble)` -> mark `Delivered` (+ store `message_id`) / `Failed` (+ `last_error`) -> persist -> emit `OutboxEvent` -> clear inflight.
- `is_retryable`: `Failed` OR (`Sending` AND `message_id.is_some()`).
- 24h timeout sweep on a 60s timer: `Sending` older than `SEND_TIMEOUT_MS` (24h) -> `Failed`.
- boot sweep at start: `Sending` + `message_id` `None` + `enqueued_at_ms` predates this process run -> `Failed`.
- `flush_all()` for the manual Retry button (all online peers' retryables).

### Surfacing -- `OutboxEvent`
- `Client::outbox_snapshot() -> Vec<OutboxBubble>` for initial render.
- an `OutboxEvent` broadcast (bubble upsert) the shell subscribes to for live status changes.

### Warm-connect -- `Client::connect_peer`
New `Client::connect_peer(&AgentId)` = `Http POST /agents/connect`. Self-contained driver; Android wires nothing.

## Data flow

1. UI send -> `Client::enqueue_dm(peer, body)` -> persist (`Sending`) -> attempt `Router::send` -> `SendReceipt` -> `Delivered` (or keep `Sending`-with-`message_id`) -> persist -> emit `OutboxEvent`.
2. Peer offline->online (`presence_events`) -> driver `flush_peer` -> re-send retryables.
3. 60s timer -> 24h timeout sweep -> `Failed`.
4. Restart -> `OutboxStore::load` -> boot sweep -> bubbles resume on the next online edge.

## Error handling

- Send failure -> `Failed` (retryable) + `last_error`.
- Persist failure -> best-effort warn+swallow (consent pattern); in-memory authoritative.
- Double-send -> guarded by `message_id` semantics (never re-fire a `Sending` bubble lacking an ack) + the inflight set.
- Corrupt/unreadable vault -> `load()` empty; never hard-fails the client.

## Desktop rewire (Alice's lane -- cross-review)

- Delete `apps/fetchit-desktop/src/chat/outboxDriver.ts`.
- The send Tauri command calls `enqueue_dm` (not a one-shot send).
- ChatStore outbound bubbles become a projection of `OutboxEvent`s (snapshot on init + event stream); reconciliation upsert-by-id.
- `isOnline`/presence unchanged (already engine-downstream).
- Driver started once at client init; a Tauri event pump (mirroring the relay-inbound pump at chat.rs:1902) forwards `OutboxEvent`s.

## Testing

- Unit (engine): `is_retryable` matrix; 24h timeout-sweep; boot-sweep; double-send guard; `OutboxStore` persistence round-trip + fail-safe (wrong-key/corrupt -> empty); no-tmp-siblings.
- Integration (engine): scripted presence stream + scripted `send`/`connect` deps driving the `OutboxDriver` -- edge -> flush -> mark; restart-resume (persist, reload, boot-sweep, online-edge -> resend).
- Desktop: vitest on the ChatStore projection (apply `OutboxEvent` -> bubble state); existing send-path tests stay green.

## Scope / out of scope

- IN: DM resend/durability in the engine; desktop rewire; `connect_peer` primitive; FFI surface for the Android lane.
- OUT: group-message retry (groups self-heal via MLS catch-up); the Android shell wiring (lands when `android-lit` merges; the engine API is shaped for zero orchestration); changing the relay's 15-min transit TTL (client-carried retention is the design).

## File structure

- Create: `crates/fetchit-chat/src/outbox/` (mod: `store.rs` + `driver.rs` + types + events) or a single `outbox.rs` if it stays small.
- Modify: `local_store.rs` (`outbox_dir` + `outbox_path()`); `client.rs` (`enqueue_dm`, `connect_peer`, `outbox_snapshot`, `OutboxEvent` accessor, start the driver in the production ctor); `lib.rs` (module + re-exports). FFI crate (expose enqueue/snapshot/events/connect) -- separate, for the Android lane.
- Desktop (Alice): delete `outboxDriver.ts`; rewire the send cmd + ChatStore projection + Tauri event pump.

## Coordination

- Branch `outbox-lift` off chat `37499c6`. Box-B gated; Alice FF-merges.
- `outbox-lift` and `bridge-consent-persist` both touch `local_store.rs` (StoreLayout) and `client.rs` (Client ctor), so they are not FF-clean against each other. Land `bridge-consent-persist` first (it is ahead, already handed for FF), then rebase `outbox-lift` onto the new chat tip before its FF.
- Bob drives; Alice cross-reviews (esp. the Q2 desktop surfacing + the transport/presence wiring she authored).
