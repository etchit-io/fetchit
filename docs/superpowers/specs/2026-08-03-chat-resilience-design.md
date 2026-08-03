# Chat Resilience: Epoch Catch-Up + Wedge Watchdog — Design

**Status:** draft for review · **Task:** #297 (v1 launch gate) · **Date:** 2026-08-03

**The bar (Josh, 2026-07-05):** chat that drops on device churn is a joke app.
The user never hears the words epoch, invite, re-pair, or wedge. Every wedge
class either self-heals silently within the relay's 72 h durable-transit
window, or (the ~never case) degrades to one gentle, jargon-free prompt.

## What the code audit established (2026-08-03)

1. **A group epoch-recovery subsystem already exists** in
   `fetchit-chat/src/groups/epoch_recovery/` — gap detection
   (`detect::epoch_relation`), a recovery driver (`driver.rs`,
   fork-log commit source + x0xd applier), a status map with a broadcast
   channel (`status.rs`), and a **written but never wired** wedge decision
   core (`watchdog.rs`: `wedge_should_trip`, `groups_to_recover`,
   `WEDGE_THRESHOLD_MS = 60_000`). Zero producers feed its `WedgeSignals`;
   zero consumers call it.
2. **Android never triggers group recovery.** The only trigger site is
   `Client::default_dispatch_one` (`client.rs:1786-1795`); the FFI inbound
   pump (`chat_ffi.rs:2617-2619`) logs `private_group_decrypt_failed` and
   moves on. On the phone the entire recovery subsystem is dead code.
3. **DM (pairwise) wedges are unrecoverable today.** StaleEpoch /
   KemDecapFailed dispatches are fully swallowed (no counter, no log, no
   event). The only heal is passively receiving a higher-epoch Welcome —
   which nothing proactively sends: `auto_rekey_due` gates on Admin role +
   a 7-day interval, and `establish_dm` refuses existing contacts.
4. **The healing primitive already exists and is exactly right:**
   `install_or_rekey_conversation` (`inbound.rs:673-746`) folds a
   higher-epoch Welcome from an existing member into the conversation
   in place — history, contact row, and nonce windows preserved; lower
   epochs are ignored. The higher-epoch rule is a natural tiebreak:
   simultaneous re-keys from both sides converge on the higher epoch with
   the loser's Welcome benignly ignored. **No coordination protocol is
   needed** — epoch ordering is the coordinator. This dissolves the old
   "coordinated re-pair, single initiator" operational folklore.
5. **Redelivery is already free.** `confirms_delivery` withholds the relay
   ack on StaleEpoch/KemDecap frames, so wedged traffic stays in durable
   transit. Recovery only has to fix the key before the 72 h TTL; the
   stalled messages then arrive late instead of dying.
6. **The reconnect-cap gap is a non-gap** — the chat pump opts into
   unbounded reconnect (`relay_transport.rs:97-99`, guard-tested). The
   real give-up surfaces are the FFI pump's continue-on-error arms and a
   silently dropped dispatcher `JoinHandle`.
7. **Upstream (x0x)** ships reactive TreeKEM catch-up (gap-classified
   inbound → throttled `treekem_catchup_request` → member-keyed paged
   responses) and is actively hardening the recovery cache
   (`wp-tk2-cache-hardening`); v0.35.0 adds GSS rotation on admin remove.
   Recovery *internals* are upstream's; our job is detection, triggering,
   and the DM class upstream doesn't cover.

## Design

Three pillars, ordered by value-per-risk.

### P1 — Wire the existing group recovery, mobile-first

**P1.1 Trigger on the FFI pump.** The pump's group-decrypt `Err` arm does
what `default_dispatch_one` already does: `set_reconnecting(group)` +
`trigger_group_recovery(group, Some(epoch))`. One arm, and the entire
existing subsystem goes live on Android.

**P1.2 Produce the wedge signals.** New per-conversation fields on
`Conversation` (`types.rs`, `#[serde(default)]` so old vaults deserialize):
`last_inbound_ok_ms` (any successful decrypt: message OR receipt) and
`last_epoch_fail_ms` + `epoch_fail_streak` (StaleEpoch / KemDecapFailed /
group-decrypt error). Updated inside the existing dispatch paths under the
per-group lock via `mutate_in_place` (never `save` — the `seen_nonces`
clobber rule). StaleEpoch stops being invisible: it becomes a timestamped
counter. A StaleEpoch frame is itself a **liveness proof** — the peer is
reaching us; only the key is wrong — which is precisely the wedge
signature (the old "receipts flowing but chat dead").

**P1.3 Consume: the watchdog tick.** A thin engine sweep (piggybacked on
the existing 300 s auto-rekey sweeper's pattern, but on a 60 s tick to
match `WEDGE_THRESHOLD_MS`) feeds `WedgeSignals` from P1.2 state into the
already-written `wedge_should_trip` / `groups_to_recover` and calls
`trigger_group_recovery` for each tripped group. Damping is inherent
(threshold + recovery-status guard: never re-trigger a group already
`Reconnecting`).

**P1.4 Surface the affordance.** Export `group_recovery_status` /
`subscribe_group_recovery` through the FFI to a Kotlin `StateFlow`. UI:
the conversation shows the existing quiet "syncing…" treatment while
`Reconnecting`; nothing else, ever. Kotlin side rides alongside the
tripwire loop (same 60 s cadence, same pure-core + thin-loop shape as
`DataTripwire`).

### P2 — The DM epoch ladder (make the unrecoverable class self-heal)

**P2.1 Forced re-key.** New engine API `force_rekey_dm(group_id_hex)`
built on `try_rekey_and_build_welcomes`, bypassing `auto_rekey_due`'s
Admin-role + 7-day gates. Either side may initiate (the receiver-side
member check + higher-epoch tiebreak make races safe by construction).
Welcomes fan to all peer devices via the existing M6.3 per-device seal.

**P2.2 The ladder** (per conversation, driven by the same watchdog tick):

1. **Trip:** `epoch_fail_streak ≥ 3` AND `now − last_inbound_ok_ms >
   WEDGE_THRESHOLD_MS` AND frames are arriving (fail timestamps fresh).
2. **Rung 1 — refresh the peer's device roster:** `resolve_pair_record_v4`
   (their card may be stale after their reinstall — the exact 2026-07-31
   @josh incident shape). Cheap, idempotent.
3. **Rung 2 — force re-key:** send fresh Welcomes at `current_epoch + 1`.
   Peer folds via `install_or_rekey_conversation`; held frames redeliver.
   Damped: at most once per conversation per 10 min, marked before
   delivery (the fedi-sync damping pattern).
4. **Rung 3 — the ~never case:** after N (=3) failed re-key cycles across
   ≥ 30 min, surface ONE quiet prompt on the conversation: "Having trouble
   reaching Josh's phone — tap to reconnect" → the existing pair-share
   flow. No jargon. Telemetry-logged so we know if rung 3 ever fires.

**KemDecapFailed nuance:** decap failure means *our* KEM key doesn't match
what the peer sealed to — rung 1 fixes their view only if they also run
this ladder; our own re-key (rung 2) re-establishes a shared epoch sealed
to their current card either way. Both sides shipping the ladder makes the
pair converge from either end.

### P3 — Close the adjacent gaps (smaller, same branch)

- **Dispatcher liveness:** the FFI pump and desktop dispatcher get a
  watchdog on their `JoinHandle`s — a dead pump is itself a wedge
  (folds task #251's nit).
- **Dedup hardening:** dedupe by `message_id` against recent `history`
  entries at `record_message` time (bounded by the existing 1000-entry
  cap), closing the re-sealed-redelivery and 64-nonce-window-wrap holes
  that recovery's redelivery bursts would otherwise widen.
- **Recovery-cursor persistence:** noted, deliberately deferred — restart
  refetch is bounded by the driver's iteration cap; revisit at the 0.35.x
  bump when upstream's recovery-cache hardening lands.

### Non-goals

- Rebuilding or duplicating upstream TreeKEM recovery internals
  (`wp-tk2-cache-hardening` owns that layer).
- A daemon REST "resync" verb — the fork-log commit source already gives
  proactive recovery; revisit after the 0.35.x bump.
- Any user-facing re-pair flow beyond rung 3's single quiet prompt.
- Group-membership repair (returning-member re-key is already landed in
  the engine-a tail; GSS-rotation interplay is #336's device-verify).

## Test strategy

- Pure cores first: watchdog trip decisions (exists), ladder-rung
  decision fn, damping fn — unit-tested like `DataTripwire`.
- Registry: timestamp/streak updates under `mutate_in_place` (extend the
  existing seen-nonce regression pattern).
- Forced re-key: unit against the existing rekey/Welcome test harness;
  race test = both sides re-key concurrently → higher epoch wins, no
  history loss.
- Device proof (the acceptance gate): fabricate a DM desync between the
  phone and the Box-B peer (bounce the peer's conversation epoch via a
  test hook), verify silent heal < 2 min with held messages arriving
  late; fabricate a group desync on Android, verify P1 recovery fires
  (today: provably dead). Flip-storm regression re-run to confirm no
  interaction with mesh lifecycle.

## Rollout

One branch (`chat-resilience`), P1 → P2 → P3 as separately-gated commits,
full workspace gates + Android compile gates per commit, spawned
cross-review on the P1+P2 diff before merge, device proof before main.
