# Durable group-join: never waste an invite, auto-complete, no scary error

**Status:** approved design (Josh, 2026-07-04). Scope: fetchit-chat only.
**Author:** Fable. **Lane note:** touches `crates/fetchit-chat` group code, which is
Bob's active M6 lane — merge to be coordinated over coord-v1.

## Problem

Joining a private MLS group is a fire-once RPC that either converges within 60 s
or throws `JoinerNotConverged` (`crates/fetchit-chat/src/error.rs:144`). Three
consequences make the UX unacceptable for a launch USP:

1. **Wasted invite / split-brain.** The invite's single-use secret is consumed
   on the *owner's* x0xd at apply-time, but the joiner's `wait_membership` gives
   up at 60 s (`membership.rs:25`, `client.rs:2362-2369`) while the relay's
   store-and-forward buffer holds the bridged event for 15 min (`transit.rs`,
   `config.rs:60`). An owner who comes online at minute 3 applies the join and
   consumes the invite — after the joiner already saw failure. Invite spent,
   user thinks it broke.
2. **Retry re-spends.** The library does not persist the captured join across
   attempts, so a UI "retry" re-runs `join_post` and spends a *fresh* invite
   (`client.rs:2393-2419` only dedupes within a single call).
3. **Scary terminal error.** "Owner offline" surfaces as a hard error, not a
   pending state.

## Fundamental constraint (in scope's honest framing)

Admitting a member to an E2EE group requires a current member's device to
generate the TreeKEM Commit + Welcome. That crypto is entirely inside x0xd
(behind `/groups/join`, `/apply-metadata-event`, `/join-result`). fetchit cannot
remove "some admin must be online at some point." **This design does not try
to.** It guarantees the invite is never *wasted* and the join *auto-completes
with no user action or error* whenever the owner is next reachable.

Out of scope (approved as later steps, need x0xd/relay changes): "any admin (not
just the inviter) may admit"; a relay-hosted durable join mailbox that completes
hours later while the joiner app is fully closed.

## Guarantees delivered

- **G1 — `join_post` runs at most once per invite, ever.** A second single-use
  secret can never be spent because we never request one on retry.
- **G2 — the invite is consumed exactly when the join truly completes.** x0xd
  consumes owner-side at apply and 409s a duplicate apply
  (`secure.rs:593-594,651-653`); re-driving the same captured event is therefore
  idempotent and costs at most one consumption, coincident with convergence.
- **G3 — a non-converged join is durable and self-completing.** It survives app
  restarts and completes automatically when the owner's daemon next processes
  it; the user takes no further action.
- **G4 — no scary error for a recoverable state.** "Owner offline / not yet
  converged" returns `Pending`, never a thrown error. Only genuinely terminal
  causes (malformed invite; x0xd reports the invite already consumed by another
  agent) surface as failures.

## Architecture

Four units, each independently testable, mirroring the existing durable-send
shape (`outbox/{mod,store,driver}.rs`).

### 1. `PendingJoin` record (`groups/pending_join.rs`)

Serde struct persisted per group being joined:

```
group_id            : hex
captured_event_b64  : the ONE signed member_joined from join_post (invite-bearing)
owner_agent_id      : hex (inviter, parsed from the captured event)
owner_kem_pubkey    : cached, resolved once
joiner_kem_pubkey   : our reply hint
created_at_ms, last_attempt_ms, attempts
state               : Submitted | Bridged | KeyedButUnverified | Converged | Failed{reason}
```

`captured_event_b64` is the load-bearing field: persisting the signed bytes is
what lets every later attempt re-bridge instead of re-`join_post` (G1). The bytes
are x0xd's native signed output, never a reconstruction (`join_bridge.rs:6-10`).

State → public outcome mapping: the three non-terminal record states
(`Submitted`, `Bridged`, `KeyedButUnverified`) all present to callers as a single
public `Pending`; `Converged` returns the `Group` then the record is deleted;
`Failed` is terminal and the record is removed. Callers never see the internal
state enum — only `JoinOutcome` and `pending_joins()` views.

### 2. `PendingJoinStore` (`groups/pending_join_store.rs`)

Disk CRUD under `<data_dir>/pending_joins/<group_id>.json`, atomic write +
mode 0600 via the existing `local_store::write_json_atomic` helper. Methods:
`upsert`, `get`, `list`, `remove`. Pure I/O, no network — unit-testable against a
`tempfile` dir exactly like `local_store` tests.

### 3. Split join into submit + resume (`client.rs`)

- `join_group_durable(invite)` (new entrypoint, wraps the existing
  `join_group_auto` engine):
  1. If a `PendingJoin` for this group already exists → skip `join_post`
     entirely, hand off to the driver, return `Pending` or the converged
     `Group`. (Idempotent re-entry; G1.)
  2. Else run `join_post` **exactly once**; on success persist the
     `PendingJoin` *before* bridging.
  3. Run the existing bridge + 60 s wait. Converged → mark `Converged`, remove
     the record, return `Group`. Timed out → return
     `JoinOutcome::Pending { group_id }`, leave the record for the driver.
- The existing `join`/`join_group_bridged`/`join_group_auto` stay as internal
  primitives; `join_group_durable` is the surface shells/peer use.

### 4. `PendingJoinDriver` (`groups/pending_join_driver.rs`)

Mirrors `outbox/driver.rs`. On construction (client startup) and on a backoff
tick while the client lives:
- `store.list()`; for each non-terminal record:
  - Re-bridge the **saved** `captured_event_b64` to `owner_agent_id` over the
    relay (never `join_post`); re-poll `/members`.
  - Converged → `Converged`, remove, emit a `JoinConverged` event.
  - Still absent → bump `attempts`/`last_attempt_ms`, back off (1s→…→cap, e.g.
    60 s), stay `Pending`.
- Backoff is capped and jittered; the driver never spins hot.
- Injected dependencies: the bridge fn, a `/members` poll fn, and a `Clock` —
  so the state machine is unit-tested without a network or real time.

### Split-brain recovery (G3 edge, state `KeyedButUnverified`)

Case: owner applied (we're in `/members`, invite consumed) but the Welcome was
lost (app closed past the 15-min buffer). Detection on resume: roster lists us
but we hold no group secret / a decrypt probe fails. Action: re-request the
staged join-result from the owner (re-bridge a "resend my join-result"; the owner
re-serves via `GET /groups/:id/join-result/:member`) — **no new invite**. Needs
the owner online again but never another invite. If x0xd later exposes a clean
"am I fully joined" probe, swap the decrypt-probe for it.

## Error taxonomy (G4)

| Cause | Outcome |
|---|---|
| owner offline / not yet converged / relay buffered | `Pending` (durable, driver retries) |
| keyed-but-Welcome-lost | `Pending` (KeyedButUnverified; driver re-requests join-result) |
| malformed / unparseable invite | `Failed` terminal |
| x0xd reports invite already consumed by another agent | `Failed` terminal (record removed) |

`JoinerNotConverged` is demoted from a returned error to an internal signal the
driver consumes. The public surface is `JoinOutcome { Converged(Group), Pending {
group_id } }` plus `pending_joins() -> Vec<PendingJoinView>` for shells to render
"Joining '<group>'… finishes when an admin is online."

## Shell / peer surface

`fetchit-chat-peer group-chat --invite-file` uses `join_group_durable`; on
`Pending` it logs `join pending — will auto-complete` and the driver keeps
working. FFI/desktop expose `pending_joins()` for the spinner state. (UI wiring
of the spinner itself is the M6 shells' lane; the engine contract is this
design.)

## Testing plan

- `PendingJoinStore`: create/get/list/remove round-trips against a tempdir;
  atomic-write + 0600 assertion (mirror `local_store` tests).
- `join_group_durable` submit-once invariant: a mock `join_post` counter asserts
  it is called exactly once across an initial attempt + N driver resumes (**G1**).
- Driver state machine with a mock owner that flips offline→applies at tick K and
  an injected clock: asserts `Pending` until K, then `Converged` + record removed
  (**G3**), and that the bridge fn is called each tick but `join_post` never
  (**G1**).
- Idempotent re-drive: a mock apply that 409s a duplicate leaves state
  `Converged` once and never double-consumes (**G2**).
- Split-brain: roster-lists-us + decrypt-probe-fails → `KeyedButUnverified` →
  join-result re-request path, no `join_post` (**G3 edge**).
- Error taxonomy: malformed invite → terminal `Failed`; already-consumed →
  terminal `Failed` + record removed (**G4**).

## Non-goals (restating boundaries)

- No "any admin admits" (needs x0xd inviter-gate change — approved fast-follow).
- No relay-side durable mailbox for fully-closed-app completion (north star).
- No change to x0xd single-use semantics; we rely on x0xd consuming exactly once.

## Implementation status (2026-07-04)

- **DONE + tested (commit `4a1793a`, branch `fable/durable-join`):** the two
  isolated core units — `groups/pending_join.rs` (record + `PendingJoinStore`)
  and `groups/pending_join_driver.rs` (`PendingJoinDriver` + `JoinBridge` /
  `MembershipProbe` / `Clock` traits + `MembershipStatus` / `DriveOutcome`). 14
  tests, mutation-checked. These are additive new files and carry the guarantees
  G1 (structural: driver has no `join_post`), G2, G3, G4.
- **TODO — client wiring (below), coordinated with Bob's M6 lane** because it
  edits `client.rs` (his most-active file) and must reproduce the bridge byte
  format exactly.

## Client wiring spec (implementable as written)

All seams verified against trunk `29b2e20`.

### Store accessor
`StoreLayout.root` is `pub` (`local_store.rs:33`). Add:
```
fn pending_join_store(&self) -> Result<PendingJoinStore> {
    let layout = self.layout().ok_or_else(|| ChatError::Invalid(
        "durable join requires a data_dir".into()))?;
    PendingJoinStore::open(layout.root.join("pending_joins"))
}
```

### New entrypoint `join_group_durable`
Returns a new `JoinOutcome { Converged(Group), Pending { group_id: String } }`
(add to `groups`). Leaves `join_group_auto` untouched — this is additive.

```
pub async fn join_group_durable(&self, invite, display_name) -> Result<JoinOutcome> {
    let store = self.pending_join_store()?;
    let group_id = /* invite.group_id hex */;
    // RESUME: a saved intent exists -> drive it, NEVER join_post (G1).
    if store.get(&group_id)?.is_some() {
        return self.drive_pending_once(&group_id).await; // Converged | Pending
    }
    // FIRST ATTEMPT: exactly one join_post, persist BEFORE the wait.
    let (group, captured) = self.groups().join_post(invite, display_name).await?;
    let record = self.build_pending_join(&group, &captured).await?;
    store.upsert(&record)?;                       // persisted before any wait
    match Self::run_native_then_bridge(Some(captured), native_wait_fn,
                                       bridge_fn).await {
        Ok(())                              => { store.remove(&group_id)?;
                                                Ok(JoinOutcome::Converged(group)) }
        Err(ChatError::JoinerNotConverged{..}) => Ok(JoinOutcome::Pending{ group_id }),
        Err(e) if is_terminal_invite_error(&e)  => { store.remove(&group_id)?; Err(e) }
        Err(_transient)                    => Ok(JoinOutcome::Pending{ group_id }),
    }
}
```
This reuses the already-factored `run_native_then_bridge` (`client.rs:2467`), so
no existing function is modified — only ~20 new lines + the persist-before-wait.

### `build_pending_join` — field sources (all verified)
- `captured_event_b64` = base64(`captured.payload`) — `CapturedSelfJoin.payload`
  is the signed `member_joined` (`join_bridge.rs:25-29`).
- `owner_agent_id` = `inviter_agent_id_from_member_joined(&captured.payload)`
  (`join_bridge.rs:36`).
- `owner_kem_pubkey_b64` = base64(`resolve_owner_kem_with_fallback(...)`)
  (`bridge.rs:291`, already called by `bridge_captured_join`).
- `joiner_kem_pubkey_b64` = base64(our ML-KEM pub from `chat.identity`).

### Concrete trait impls for the driver
- `JoinBridge::rebridge(record)` = decode `captured_event_b64` +
  `owner_kem_pubkey_b64` + `joiner_kem_pubkey_b64` and call the SAME
  `emit_self_join_bridge(signer, owner_kem, joiner_kem, &payload, relay)`
  (`join_bridge.rs:131`) that the first bridge used — byte-identical, no
  `join_post`.
- `JoinBridge::request_join_result(record)` = the reverse-request that makes the
  owner re-serve the staged join-result (owner side: `GET /groups/:id/join-result/:member`).
- `MembershipProbe::status(group_id)`:
  - not in `groups().members(group)` (`mod.rs:612`) → `Absent`.
  - in members AND a `/secure/decrypt` probe succeeds → `ActiveKeyed`.
  - in members but the decrypt probe fails → `ListedButUnkeyed`.
- `Clock::now_ms()` = `SystemTime::now()` epoch ms (saturating).

### Driver lifecycle on the Client
Spawn a `PendingJoinDriver` sweep on client build (drain existing records on
startup — this is what makes a join survive an app restart) and on a capped
backoff tick; also expose `pending_joins() -> Vec<PendingJoinView>` for shells to
render the spinner. Follow the `OutboxDriver` spawn pattern (`outbox/driver.rs`).

### Peer/FFI surface
`fetchit-chat-peer group-chat --invite-file` calls `join_group_durable`; on
`Pending` it logs `join pending — auto-completing` and lets the driver finish.

## Wiring integration details (resolved while implementing, 2026-07-05)

Three specifics the wiring pass must handle, each verified against `3eb7034`:

1. **group_id before `join_post` (for the belt-and-braces resume pre-check).**
   `GroupInvite(pub String)` is an opaque base64-JSON blob whose decoded body
   carries `group_id`. The primary anti-re-spend defense is UX (after `Pending`
   the shell shows "joining…" and never re-calls join; the spawned driver
   completes it), so the pre-check is secondary. If cheap, decode the invite to
   read `group_id` and short-circuit when a record exists; otherwise rely on the
   driver + a UX that doesn't re-invoke join.
2. **Owned handles for the spawned driver.** `self.groups()` borrows `self`; a
   spawned loop needs *owned* clones. Capture: `chat.signer: Arc<dyn Signer>`,
   `self.router: Arc<Router>`, `chat.identity: Arc<FetchitIdentity>`,
   `chat.local_machine_id: [u8;32]` (Copy), `chat.layout: StoreLayout` (clone),
   `self.primary_relay_url` snapshot, and an `Http`/token handle for `members`.
   `ClientJoinBridge` / `ClientMembershipProbe` structs hold these clones and
   impl the driver traits; `start_pending_join_driver` constructs
   `PendingJoinDriver` + spawns the `is_due`-gated loop (N1).
3. **The keyed vs listed probe (`MembershipStatus`).** `Absent` = not in
   `groups().members()`. Keyed vs `ListedButUnkeyed`: attempt a `/secure/decrypt`
   (or the cheapest available "do I hold the group secret" x0xd call, per
   `mod.rs:422`'s note) — success ⇒ `ActiveKeyed`, failure-while-listed ⇒
   `ListedButUnkeyed`.

`rebridge` reproduces `bridge_captured_join` (`client.rs:2350`) verbatim:
reconstruct `CapturedSelfJoin { topic, payload }` from `captured_event_b64`,
resolve owner-KEM via `resolve_owner_kem_with_fallback`, call
`emit_self_join_bridge(captured, &owner_hex, &owner_kem, identity.kem_public_key(),
&local_agent_id, &local_machine_id, signer, &router, hints)`.

## Coordination

New files (`groups/pending_join*.rs`) are additive and already landed on the
branch. The `client.rs` edits above are additive (new methods + a new
`JoinOutcome`; `join_group_auto` untouched), but `client.rs` is Bob's active M6
file — the wiring will be implemented against his current head and merged over
coord-v1 to avoid colliding with in-flight work.
