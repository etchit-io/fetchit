# Returning-Member Re-Key (`MemberReKeyed`) — Design

**Status:** Design (Alice 2026-06-23). Replaces the `rekey-returning-member` remove+add patch (x0x-fork `fc787ae`), which is owner-MLS-correct but models the metadata wrong for the joiner. Pending Bob design cross-review, then build → throwaway-group test → cross-review → land.

**Problem (confirmed end-to-end):** A group member that lost local TreeKEM state (reinstall / new device / data wipe; its agent key persists) cannot rejoin: it stays roster-active but keyless. The owner-side daemon originally bailed before staging a Welcome; the `fc787ae` patch fixed the owner (re-keys via TreeKEM remove+add, proven on throwaway group G2). But the joiner still ends keyless: its x0xd **receives** the re-key `MemberAdded` and **queues** it (`reason=revision_gap` → `treekem_not_ready`), never applying it.

## Root cause (code-confirmed)

The `fc787ae` re-key emits **two metadata commits**: `MemberRemoved@rev3` then `MemberAdded@rev4`. Only the final `MemberAdded@rev4` is staged + bridged to the joiner as its join-result. But:

- The joiner applies via `apply_join_result_endpoint` → `apply_named_group_metadata_event` → the `MemberAdded` arm → `apply_stateful_event_to_group` (x0x-fork `server/mod.rs:8339`), which **validates `commit.prev_state_hash` against local state before** processing the Welcome (`:8380`).
- `MemberAdded@rev4.prev_state_hash` links to `rev3` (the remove), which the joiner **never receives** — it has only its rejoin base (`rev2`). Chain validation fails → returns false → the Welcome at `:8380` is never applied → keyless-with-metadata.
- And `finalize_applied_commit` (x0x `groups/mod.rs:562`) does **not** blindly adopt: it sets revision+prev from the commit, **recomputes** `state_hash` from local `members_v2`, and **errors if it ≠ `commit.state_hash`**. So even delivering the intermediate `MemberRemoved` wouldn't trivially work: that remove is **roster-preserving** (TreeKEM-leaf-only; the member stays in `members_v2`, KP updated only in the second commit), which the *normal* `MemberRemoved` apply closure can't reproduce (it drops the member from `members_v2`).

**Conclusion:** the remove+add-as-two-metadata-commits shape fights the state model. A re-key is **one** roster mutation (the member's KeyPackage swaps), so it should be **one** metadata commit.

## Design: single metadata commit + `MemberReKeyed` event

A re-key is modeled as **one** `GroupStateCommit` (`rev2 → rev3`, `members_v2` = member-with-NEW-KP) carried by a **new** event variant that also carries **both** TreeKEM commits and the Welcome:

```rust
NamedGroupMetadataEvent::MemberReKeyed {
    group_id: String,
    revision: u64,
    actor: String,                          // the inviter/admin authority
    agent_id: String,                        // the returning member
    display_name: Option<String>,
    treekem_remove_commit_b64: Option<String>, // remove the stale leaf (epoch N+1)
    treekem_add_commit_b64: Option<String>,    // add the fresh KeyPackage (epoch N+2)
    treekem_welcome_b64: Option<String>,
    welcome_ref: Option<WelcomeRef>,           // the Welcome from the ADD (epoch N+2)
    treekem_epoch: Option<u64>,                // final epoch (N+2)
    commit: Option<GroupStateCommit>,          // the SINGLE metadata commit (rev3)
}
```

### Owner emit (replaces the `fc787ae` re-key body, x0x-fork `server/mod.rs` ~9616)
On a detected re-key (already-active + TreeKem plane + incoming KP ≠ stored KP) with a fresh valid invite:
1. Consume the fresh invite (authorization), on the `next` clone.
2. `next.set_member_treekem_key_package(member, new_kp)` — the **single** roster mutation.
3. `next.secret_epoch = guard.epoch()+2`; `next.security_binding`; `commit = next.seal_commit(...)` — **one** metadata commit (`rev3`).
4. Under the one guard lock, **back-to-back**: `tk_remove = guard.remove_member_verified(member, stale_kp)` (epoch N+1) then `out = guard.add_member(member, new_kp)` (epoch N+2). (Seal the metadata commit *before* the guard ops, as in the hardened `fc787ae`, so a seal failure leaves the live tree untouched.)
5. Persist once; `stage_treekem_welcome(out.welcome)`; build + stage_join_result + publish + deliver the **one** `MemberReKeyed` event.

### Existing-member apply (new `MemberReKeyed` arm)
1. Validate the single metadata commit via `apply_stateful_event_to_group` with the **KP-update** mutation (`set_member_treekem_key_package(member, new_kp)`). Because the member stays in `members_v2` (only KP changes), the recompute matches the owner's `rev3` hash. Chains on `rev2` ✓.
2. Apply **both** TreeKEM commits to the local tree in order: `remove` (→ N+1) then `add` (→ N+2). Tree reaches epoch N+2, consistent with the roster.

### Joiner-self apply (new `MemberReKeyed`-for-self handling)
1. Validate the single metadata commit (KP-update mutation) against the joiner's `rev2` base → **no revision gap** (this is the fix), recompute matches `rev3` hash.
2. Apply the **Welcome** (self-contained: bootstraps the joiner's whole tree at epoch N+2). The joiner does **not** need the remove/add TreeKEM commits — the Welcome gives it the full tree.

### Why the recompute matches (the crux Bob flagged)
`finalize_applied_commit` recomputes from local `members_v2` and verifies against `commit.state_hash`. The joiner's `rev2` base `members_v2` equals the owner's `rev2` (same group, invite minted at current state), and both apply the identical mutation (member's KP → new). So the recomputed `rev3` hash matches the owner's. (Same reasoning the proven fresh-add relies on.)

## Chat-client wiring (fetchit `crates/fetchit-chat`)
- **Owner reply** (`reply_to_bridged_join`): bridges the staged `MemberReKeyed` join-result back to the joiner (unchanged mechanism; it just carries the new event).
- **Joiner reverse path** (`dispatch_inbound_bridge` reverse arm, `member_added_self_target`): extend to recognize a `MemberReKeyed`-for-self and apply it via the join-result endpoint (same as `MemberAdded`-for-self today).

## File touch-list
- x0x-fork `src/server/mod.rs`: the `MemberReKeyed` event variant; the owner re-key emit (replace `fc787ae` body); the existing-member apply arm; the joiner-self apply; the ~10 event-kind match sites (`"member_rekeyed"` string + routing) that enumerate `NamedGroupMetadataEvent`.
- x0x-fork event serde / `treekem.trace` logging.
- fetchit `crates/fetchit-chat/src/client.rs`: `reply_to_bridged_join` (carry the event), the reverse-apply arm; `crates/fetchit-chat/src/groups/join_bridge.rs`: `member_*_self_target` helper to recognize `MemberReKeyed`.

## Test plan (Bob, throwaway group G2 — never the live group)
1. Owner re-keys a wiped returning member; owner logs `re-keyed returning member`.
2. **Joiner keys + SENDS** (the fix; previously keyless).
3. **Witness existing member STILL decrypts** post-re-key (clean epoch N+2 convergence) — both TreeKEM commits applied in order.
4. Then Bob cross-review → land both repos together (owner-side + joiner-side; neither lands alone).

## Out of scope
Concurrent group changes between invite-mint and re-key (a wider base gap) fall back to the existing queue/catch-up path, same as any join.
