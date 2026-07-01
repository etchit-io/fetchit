# Self-Healing Chat Pump (#65) — Design

**Status:** Design for review (Alice, 2026-06-24, overnight). NOT yet
implemented — the change touches the core message pump and interacts
with the desktop's existing reconnect, so it wants a decision + a
supervised, cross-reviewed build. Verified against code, not memory.

## Problem

The engine's inbound dispatcher (`Client::spawn_default_dispatcher`,
`crates/fetchit-chat/src/client.rs`) drains the relay transport's inbound
channel in a `while let Some(env) = rx.recv().await` loop. When the
transport's inbound channel closes (relay WS disconnect), the loop simply
**exits and the spawned task ends** — no reconnect.

- **Desktop** survives this because `src-tauri/src/chat.rs` wraps the
  engine with a `RECONNECT_BACKOFF` (5s) supervisor that, on disconnect,
  **rebuilds the whole `Client`** (chat.rs:383 "relay reconnect
  invalidates the cached client") and re-spawns the dispatcher.
- **Android** (adopt-115) uses the engine directly via the FFI with no
  such wrapper, so the pump goes terminal `STOPPED_ERROR` on a transport
  error and recovers only on manual chat-mode re-entry. A phone on a
  flaky connection therefore silently stops receiving until the user
  reopens the chat.

Goal: the engine pump self-heals in the background on ALL shells, so a
transient disconnect doesn't strand the user — without regressing the
desktop's working reconnect.

## Verified current state

- `RelayTransport::connect(base_url, signer)`
  (`crates/fetchit-chat/src/relay_transport.rs`) is **self-contained**:
  it performs the ML-DSA-65 auth handshake via the `Signer` and spawns
  the inbound pump. So re-calling `connect` yields a fresh *authenticated*
  session + inbound channel — the engine does NOT need a shell to
  re-auth.
- The multi-home transport already has slot-failover resubscribe logic
  (`client.rs:992/1077/1179`) — there is precedent for in-engine
  reconnect/resubscribe.
- **Presence re-watch is consumer-driven**: `watch_presence`
  (`client.rs:2827`) is called by the shell, not the transport. After a
  reconnect, presence subscriptions must be re-established by whoever
  owns the contact list.
- **The desktop reconnect is heavyweight**: it rebuilds the `Client`
  (new transport, new auth, fresh registry hydrate, re-watch). Correct
  but not something to run twice.

## The core risk

If the engine dispatcher reconnects on its own AND the desktop's
`src-tauri` supervisor also reconnects (by rebuilding the client), the
two race: double WS sessions, double dispatch, double presence-watch.
**A naive engine self-heal regresses the desktop.** This is the reason
not to rush it.

## Options

### Option A — Engine-owned reconnect; desktop opts out
The engine dispatcher gains a backoff-reconnect loop: on inbound close,
re-`connect` the relay transport (bounded backoff), re-take inbound,
resume dispatch, and emit a connection-state event so the consumer can
re-watch presence. The desktop's `src-tauri` reconnect-supervisor is
then **removed** (the engine owns it), so there's no double-reconnect.
- Pro: one reconnect path for all shells; Android gets it for free.
- Con: touches the desktop's working path (regression risk there);
  presence re-watch must be wired via the connection-state event.

### Option B — Minimal message-pump-only self-heal, gated
The dispatcher self-heals **only the message-receive pump** (re-`connect`
+ re-take inbound + resume), gated behind a flag/builder option that the
desktop leaves OFF (keeps its client-rebuild) and Android turns ON.
Presence/stream re-subscribe stays the consumer's job via an emitted
connection-state event.
- Pro: zero desktop regression risk (desktop path untouched); Android
  gets background message recovery now.
- Con: two reconnect strategies coexist (engine-light for Android,
  client-rebuild for desktop) until unified; presence on Android still
  needs the consumer to re-watch on the state event.

### Option C — Full unified reconnect lifecycle in the engine
Move the entire reconnect lifecycle (transport reconnect, registry
re-hydrate, presence re-watch, stream re-subscribe, idempotent
re-spawn) into the engine as one supervised routine both shells call.
- Pro: the "right" long-term shape — one correct reconnect everywhere.
- Con: the largest, most sensitive change; effectively a refactor of how
  both shells manage the connection lifecycle. Not an overnight job.

## Recommendation

**Option B now, Option C later.** Ship the gated, message-pump-only
self-heal so Android stops stranding users on a flaky connection,
without touching the desktop's working reconnect (zero regression risk).
Emit a `ConnectionState` event on disconnect/reconnect so the consumer
re-watches presence. Then converge to Option C (unified lifecycle) as a
deliberate follow-up once it's proven on Android.

## Sketch (Option B)

- Add a builder flag `self_heal_inbound: bool` (default off) to the
  `Client`/dispatcher.
- When on, replace the `while let Some` drain with:
  ```
  loop {
    while let Some(env) = rx.recv().await { dispatch(env) }
    // inbound closed -> transport dropped
    emit(ConnectionState::Reconnecting)
    rx = reconnect_with_backoff().await?   // RelayTransport::connect, bounded
    emit(ConnectionState::Connected)       // consumer re-watches presence here
  }
  ```
- `reconnect_with_backoff`: exponential backoff (1s, 2s, 4s … cap 30s),
  bounded total attempts, surfaces `ConnectionState::Down` on give-up
  (matching the desktop's `DaemonStatus`).
- Android FFI: surface the `ConnectionState` so the Kotlin shell drives
  the offline banner (already built) + re-watch presence on `Connected`.

## Test plan (TDD, engine)

1. Dispatcher with `self_heal_inbound=false` ends on inbound close
   (current behaviour — regression guard).
2. With `self_heal_inbound=true`, a closed inbound triggers exactly one
   `reconnect_with_backoff` call (mock transport), then resumes dispatch
   on the new inbound.
3. Backoff escalates and caps; give-up emits `Down`.
4. No double-connect: a single close yields a single reconnect.
5. Desktop path unaffected (flag off) — its `src-tauri` reconnect still
   the only reconnect.

## Open decisions (for Josh / cross-review with Bob)

- B vs C: ship the gated minimal self-heal now, or invest in the unified
  lifecycle directly?
- Backoff numbers (1→30s cap?) and give-up bound (or retry forever while
  the app is foregrounded?).
- Presence re-watch: confirm the consumer (desktop + Android) re-watches
  on the `Connected` event, or move presence-watch into the engine too
  (leans toward Option C).
