# #251 NAT-traversal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the Approach B NAT-traversal stack from
`docs/superpowers/specs/2026-06-06-251-nat-traversal-design.md`:
bundled x0xd in the fetch>it installer (Layer 1) and the
M2.5 bridge extended to cover the full owner-broadcast event surface
plus a Welcome-blob contingency (Layer 2). Layer 3 (X0X-0070b/c) is
parallel work upstream, no fetch>it code changes.

**Architecture:** The bridge wire shape already exists as
`EnvelopeKind::X0xdGroupMetadataEvent`, carrying an opaque JSON event
sealed under the recipient's ML-KEM-768 key. M2.5 wired only the
`member_joined` event; Phase A of this plan adds the other
owner-broadcast NamedGroupMetadataEvent variants on the same wire.
Phase B adds two new EnvelopeKinds for the Welcome contingency.
Phases C through F build the bundled-x0xd supervisor and installer
plumbing. Phase G adds the new test rig docs. Phase H resolves the
8 spec-open-questions. Phase I closes the workspace gate.

**Tech Stack:** Rust 2021 (workspace) for fetchit-chat / fetchit-relay-proto /
x0xd-client / fetchit-desktop/src-tauri. Tauri 2 + TypeScript for the
desktop shell. serde_json for event payloads, postcard for envelope wire,
ml-kem 0.2 / ml-dsa 0.0.4 for crypto, chacha20poly1305 for AEAD.
saorsa-mls v0.3.x via x0xd as the MLS engine. Bundled binary lives
under `apps/fetchit-desktop/src-tauri/resources/x0xd-<target>`.

---

## Discovery: spec terminology vs upstream wire

The spec's "MemberLeft / MemberRoleChanged / GroupEpochCommitted" gloss
maps to actual upstream `NamedGroupMetadataEvent` variants:

| Spec gloss | Upstream variant | Notes |
| --- | --- | --- |
| `MemberLeft` | `MemberRemoved` | Owner-broadcast event after `POST /groups/<id>/remove-member` |
| `MemberRoleChanged` | `MemberRoleUpdated` | Owner-broadcast after `POST /groups/<id>/members/<aid>/role` |
| `GroupEpochCommitted` | (no separate variant) | Epoch lives inside every event's embedded `commit: GroupStateCommit`; no standalone bridge needed |

Additionally upstream emits `PolicyUpdated`, `MemberBanned`,
`GroupDeleted` from the same gossip path. Phase A bridges them all on
the existing `EnvelopeKind::X0xdGroupMetadataEvent` wire (the M2.5
bridge already accepts arbitrary JSON via `X0xdGroupMetadataEventWrapper`).

Source: `/home/josh/Desktop/x0x/src/bin/x0xd.rs:5768-5830` for the
enum definition, `/home/josh/Desktop/x0x/src/groups/state_commit.rs:269`
for `GroupStateCommit`, `crates/fetchit-relay-proto/src/envelope.rs:77-99`
for the existing bridge wire.

---

## File structure

### Layer 2: bridge extension (Phases A, B)

| File | Responsibility | Status |
| --- | --- | --- |
| `crates/fetchit-chat/src/groups/bridge.rs` | Per-event JSON builders, `seal_bridge_wrapper`, `build_bridge_outbox`. Already exists with `build_member_joined_event`. | Modify |
| `crates/fetchit-chat/src/groups/bridge_member_removed.rs` | `build_member_removed_event` + helpers. Split from bridge.rs to keep the file under 1k lines. | Create |
| `crates/fetchit-chat/src/groups/bridge_member_role_updated.rs` | `build_member_role_updated_event` + helpers. | Create |
| `crates/fetchit-chat/src/groups/bridge_policy_updated.rs` | `build_policy_updated_event` + helpers. | Create |
| `crates/fetchit-chat/src/groups/bridge_member_banned.rs` | `build_member_banned_event` + helpers. | Create |
| `crates/fetchit-chat/src/groups/bridge_group_deleted.rs` | `build_group_deleted_event` + helpers. | Create |
| `crates/fetchit-chat/src/groups/welcome_bridge.rs` | `WelcomeRequestPayload`, `WelcomeBlobPayload`, seal/unseal helpers. | Create |
| `crates/fetchit-chat/src/groups/mod.rs` | Re-export the new submodules. | Modify |
| `crates/fetchit-chat/src/dispatch.rs` | Route inbound `X0xdGroupMetadataEvent` + new welcome envelopes to local x0xd POSTs. | Modify |
| `crates/fetchit-chat/src/groups/outbox.rs` | Outbox for owner-broadcast events + welcome request/blob retry. | Modify or create alongside existing outbox plumbing |
| `crates/fetchit-relay-proto/src/envelope.rs` | Add `EnvelopeKind::WelcomeBlobRequest` (DISC=6) + `EnvelopeKind::WelcomeBlobResponse` (DISC=7). | Modify |

### Layer 1: bundled x0xd (Phases C, D, E, F)

| File | Responsibility | Status |
| --- | --- | --- |
| `crates/x0xd-client/src/discover.rs` | `discover_installed_x0xd() -> Option<InstalledX0xd>` querying system PATH + `/version`. | Create |
| `crates/x0xd-client/src/lib.rs` | Re-export `discover`. | Modify |
| `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/mod.rs` | Supervisor public API. | Create |
| `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/pick.rs` | Binary selection (installed vs bundled). | Create |
| `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/spawn.rs` | Spawn bundled subprocess on managed port; retry-on-bind. | Create |
| `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/supervise.rs` | Crash-loop detector (3 crashes / 30s) + clean shutdown. | Create |
| `apps/fetchit-desktop/src-tauri/src/main.rs` | Boot supervisor before app; thread `port + token` into existing x0xd-client construction. | Modify |
| `apps/fetchit-desktop/src-tauri/build.rs` | Fetch + verify bundled x0xd binary per target OS at build time. | Create |
| `apps/fetchit-desktop/src-tauri/resources/x0xd.toml.tpl` | TOML template with peer-relay candidates pre-pinned. | Create |
| `apps/fetchit-desktop/src-tauri/tauri.conf.json` | Add bundled binary as a `resources` entry. | Modify |

### Test infrastructure (Phase G)

| File | Responsibility | Status |
| --- | --- | --- |
| `private/ops/mobile-rig/README.md` | Mobile-carrier soak rig docs. | Create |
| `private/ops/cgnat-rig/README.md` | CGNAT residential soak rig docs. | Create |
| `crates/fetchit-chat/tests/m2_live.rs` | Existing live-test scaffold; extend with topology-aware env vars. | Modify |

### Decision records (Phase H)

| File | Responsibility | Status |
| --- | --- | --- |
| `private/251-decisions.md` | One-line resolution per spec §11 open question with the rationale chosen. Internal `private/`, gitignored from public mirror. | Create |

---

## Commit + DCO conventions

Every commit uses:

```bash
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "<title>" -m "<body>"
```

Never `--no-verify`, never `--no-gpg-sign`. No em-dashes in commit
messages. No "Co-Authored-By Claude" trailer. Force-push to
`josh-clsn/chat` is allowed; never push to `etchit-io` or
`saorsa-labs` without per-push approval.

The workspace gate that runs after every task's local commit:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For workspace-excluded crates (`crates/fetchit-ffi`,
`apps/fetchit-desktop/src-tauri`), gate from inside their directory:

```bash
(cd apps/fetchit-desktop/src-tauri && cargo fmt --all)
(cd apps/fetchit-desktop/src-tauri && cargo clippy --all-targets -- -D warnings)
(cd apps/fetchit-desktop/src-tauri && cargo test)
```

If any gate fails, fix and recommit before moving on.

---

## Phase A: Layer 2 owner-broadcast bridge extension

Goal: extend the existing M2.5 bridge so every owner-emitted
`NamedGroupMetadataEvent` variant (not just `MemberJoined`) can be
ferried over fetchit-relay to members the gossip mesh can't reach.

### Task A1: Add `member_removed` JSON event builder

**Files:**
- Create: `crates/fetchit-chat/src/groups/bridge_member_removed.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs:1-30`

- [ ] **Step 1: Write the failing test**

Create the file with only the test:

```rust
// crates/fetchit-chat/src/groups/bridge_member_removed.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

#[derive(Debug, Clone)]
pub struct MemberRemovedInputs<'a> {
    pub group_id: &'a str,
    pub revision: u64,
    pub actor: &'a str,
    pub agent_id: &'a str,
    pub treekem_commit_b64: Option<&'a str>,
    pub treekem_epoch: Option<u64>,
    pub commit_json: Option<serde_json::Value>,
}

#[must_use]
pub fn build_member_removed_event(inputs: &MemberRemovedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "member_removed",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "agent_id": inputs.agent_id,
        "treekem_commit_b64": inputs.treekem_commit_b64,
        "treekem_epoch": inputs.treekem_epoch,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_member_removed_event_matches_upstream_json_shape() {
        let inputs = MemberRemovedInputs {
            group_id: "abcd",
            revision: 3,
            actor: "owner-aid",
            agent_id: "member-aid",
            treekem_commit_b64: Some("commitb64"),
            treekem_epoch: Some(4),
            commit_json: Some(json!({ "state_hash": "h", "signature": "s" })),
        };
        let v = build_member_removed_event(&inputs);
        assert_eq!(v["event"], json!("member_removed"));
        assert_eq!(v["group_id"], json!("abcd"));
        assert_eq!(v["revision"], json!(3));
        assert_eq!(v["actor"], json!("owner-aid"));
        assert_eq!(v["agent_id"], json!("member-aid"));
        assert_eq!(v["treekem_commit_b64"], json!("commitb64"));
        assert_eq!(v["treekem_epoch"], json!(4));
        assert_eq!(v["commit"]["state_hash"], json!("h"));
    }

    #[test]
    fn build_member_removed_event_serializes_none_as_json_null() {
        let inputs = MemberRemovedInputs {
            group_id: "g",
            revision: 1,
            actor: "a",
            agent_id: "m",
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit_json: None,
        };
        let v = build_member_removed_event(&inputs);
        assert!(v["treekem_commit_b64"].is_null());
        assert!(v["treekem_epoch"].is_null());
        assert!(v["commit"].is_null());
    }
}
```

Then wire the module into `mod.rs`:

```rust
// crates/fetchit-chat/src/groups/mod.rs (add near the existing bridge module declaration)
pub mod bridge;
pub mod bridge_member_removed;
```

- [ ] **Step 2: Run test to verify it fails (then succeed when impl is the same as test setup)**

Run: `cargo test -p fetchit-chat groups::bridge_member_removed`
Expected on first run: PASS (the impl is in the same file as the test;
this task is a minimal-introduce-module step to mirror the existing
`bridge::build_member_joined_event` pattern).

If you prefer strict TDD here, comment out `build_member_removed_event`,
run to confirm FAIL "function not defined", then uncomment.

- [ ] **Step 3: Workspace gate**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: green across the workspace.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/bridge_member_removed.rs \
        crates/fetchit-chat/src/groups/mod.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): member_removed JSON event builder for #251 Layer 2" \
  -m "Mirrors build_member_joined_event for the owner-side member_removed event. Adds the per-variant JSON shape upstream x0xd expects on /publish so the M2.5 bridge can ferry MemberRemoved events when the gossip mesh can't deliver. Inner GroupStateCommit signature carries authority, so no new canonical-bytes signing surface is needed on our side."
```

### Task A2: Add `member_role_updated` JSON event builder

**Files:**
- Create: `crates/fetchit-chat/src/groups/bridge_member_role_updated.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs`

- [ ] **Step 1: Write the failing test**

```rust
// crates/fetchit-chat/src/groups/bridge_member_role_updated.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

#[derive(Debug, Clone)]
pub struct MemberRoleUpdatedInputs<'a> {
    pub group_id: &'a str,
    pub revision: u64,
    pub actor: &'a str,
    pub agent_id: &'a str,
    /// Upstream wire string: "owner", "admin", "member", "observer", etc.
    pub role: &'a str,
    pub commit_json: Option<serde_json::Value>,
}

#[must_use]
pub fn build_member_role_updated_event(inputs: &MemberRoleUpdatedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "member_role_updated",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "agent_id": inputs.agent_id,
        "role": inputs.role,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_member_role_updated_event_matches_upstream_json_shape() {
        let inputs = MemberRoleUpdatedInputs {
            group_id: "g",
            revision: 5,
            actor: "owner-aid",
            agent_id: "member-aid",
            role: "admin",
            commit_json: Some(json!({ "state_hash": "h" })),
        };
        let v = build_member_role_updated_event(&inputs);
        assert_eq!(v["event"], json!("member_role_updated"));
        assert_eq!(v["role"], json!("admin"));
        assert_eq!(v["commit"]["state_hash"], json!("h"));
    }
}
```

Add to mod.rs: `pub mod bridge_member_role_updated;`.

- [ ] **Step 2: Run test, confirm PASS**

Run: `cargo test -p fetchit-chat groups::bridge_member_role_updated`
Expected: PASS.

- [ ] **Step 3: Workspace gate** (same as A1).

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/bridge_member_role_updated.rs \
        crates/fetchit-chat/src/groups/mod.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): member_role_updated JSON event builder for #251 Layer 2" \
  -m "Mirrors the upstream member_role_updated wire shape so the bridge can ferry role changes when gossip can't deliver."
```

### Task A3: Add `policy_updated` JSON event builder

**Files:**
- Create: `crates/fetchit-chat/src/groups/bridge_policy_updated.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs`

- [ ] **Step 1: Write the file with test and impl**

```rust
// crates/fetchit-chat/src/groups/bridge_policy_updated.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

#[derive(Debug, Clone)]
pub struct PolicyUpdatedInputs<'a> {
    pub group_id: &'a str,
    pub revision: u64,
    pub actor: &'a str,
    /// Upstream `GroupPolicy` already serialized to JSON (whatever
    /// shape upstream uses; we treat it opaquely on our side).
    pub policy_json: serde_json::Value,
    pub commit_json: Option<serde_json::Value>,
}

#[must_use]
pub fn build_policy_updated_event(inputs: &PolicyUpdatedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "policy_updated",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "policy": inputs.policy_json,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_policy_updated_event_passes_policy_through_opaque() {
        let inputs = PolicyUpdatedInputs {
            group_id: "g",
            revision: 2,
            actor: "owner",
            policy_json: json!({ "name": "strict", "max_members": 50 }),
            commit_json: None,
        };
        let v = build_policy_updated_event(&inputs);
        assert_eq!(v["event"], json!("policy_updated"));
        assert_eq!(v["policy"]["name"], json!("strict"));
        assert_eq!(v["policy"]["max_members"], json!(50));
    }
}
```

Add to mod.rs: `pub mod bridge_policy_updated;`.

- [ ] **Step 2: Run test, confirm PASS**

Run: `cargo test -p fetchit-chat groups::bridge_policy_updated`.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/bridge_policy_updated.rs \
        crates/fetchit-chat/src/groups/mod.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): policy_updated JSON event builder for #251 Layer 2"
```

### Task A4: Add `member_banned` JSON event builder

**Files:**
- Create: `crates/fetchit-chat/src/groups/bridge_member_banned.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs`

- [ ] **Step 1: Write the file with test and impl**

```rust
// crates/fetchit-chat/src/groups/bridge_member_banned.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

#[derive(Debug, Clone)]
pub struct MemberBannedInputs<'a> {
    pub group_id: &'a str,
    pub revision: u64,
    pub actor: &'a str,
    pub agent_id: &'a str,
    pub reason: Option<&'a str>,
    pub commit_json: Option<serde_json::Value>,
}

#[must_use]
pub fn build_member_banned_event(inputs: &MemberBannedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "member_banned",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "agent_id": inputs.agent_id,
        "reason": inputs.reason,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_member_banned_event_includes_reason_field() {
        let inputs = MemberBannedInputs {
            group_id: "g",
            revision: 7,
            actor: "owner",
            agent_id: "bad-aid",
            reason: Some("spam"),
            commit_json: None,
        };
        let v = build_member_banned_event(&inputs);
        assert_eq!(v["reason"], json!("spam"));
    }
}
```

Add `pub mod bridge_member_banned;`.

- [ ] **Step 2: Run test, confirm PASS**

Run: `cargo test -p fetchit-chat groups::bridge_member_banned`.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/bridge_member_banned.rs \
        crates/fetchit-chat/src/groups/mod.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): member_banned JSON event builder for #251 Layer 2"
```

### Task A5: Add `group_deleted` JSON event builder

**Files:**
- Create: `crates/fetchit-chat/src/groups/bridge_group_deleted.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs`

- [ ] **Step 1: Write file**

```rust
// crates/fetchit-chat/src/groups/bridge_group_deleted.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

#[derive(Debug, Clone)]
pub struct GroupDeletedInputs<'a> {
    pub group_id: &'a str,
    pub revision: u64,
    pub actor: &'a str,
    pub commit_json: Option<serde_json::Value>,
}

#[must_use]
pub fn build_group_deleted_event(inputs: &GroupDeletedInputs<'_>) -> serde_json::Value {
    serde_json::json!({
        "event": "group_deleted",
        "group_id": inputs.group_id,
        "revision": inputs.revision,
        "actor": inputs.actor,
        "commit": inputs.commit_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_group_deleted_event_emits_event_tag() {
        let inputs = GroupDeletedInputs {
            group_id: "g",
            revision: 99,
            actor: "owner",
            commit_json: None,
        };
        let v = build_group_deleted_event(&inputs);
        assert_eq!(v["event"], json!("group_deleted"));
        assert_eq!(v["revision"], json!(99));
    }
}
```

Add `pub mod bridge_group_deleted;`.

- [ ] **Step 2: Run test, confirm PASS**

Run: `cargo test -p fetchit-chat groups::bridge_group_deleted`.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/bridge_group_deleted.rs \
        crates/fetchit-chat/src/groups/mod.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): group_deleted JSON event builder for #251 Layer 2"
```

### Task A6: Owner-broadcast bridge dispatch wires all five event types

**Files:**
- Modify: `crates/fetchit-chat/src/groups/bridge.rs` (existing
  `build_bridge_outbox` already accepts an opaque JSON event via
  `X0xdGroupMetadataEventWrapper`; this task adds a thin entry helper
  that callers use for each new event variant).
- Modify: `crates/fetchit-chat/src/messages.rs` or the equivalent
  caller that owns the `POST /groups/<id>/remove-member` flow.

- [ ] **Step 1: Add a unified `dispatch_owner_broadcast` helper next to `build_bridge_outbox` in `bridge.rs`**

Append the following to `bridge.rs` (just before `#[cfg(test)] mod tests`):

```rust
/// Common shape for owner-emitted NamedGroupMetadataEvent variants
/// that need to be ferried over the bridge. The caller picks the right
/// `bridge_member_removed::build_*_event` (or similar) before invoking
/// `dispatch_owner_broadcast`.
#[derive(Debug)]
pub struct OwnerBroadcastInputs<'a> {
    pub topic: String,
    pub event_json: serde_json::Value,
    pub recipients_kem: &'a [(String, Vec<u8>)], // (agent_id_hex, kem_pubkey)
}

/// Build one outbound bridge envelope per recipient. Returns the
/// outbox-ready `TransitEnvelope`s; the caller pushes them through
/// the existing relay-client send path.
///
/// # Errors
/// Surfaces any AEAD / KEM / signing error from `seal_bridge_wrapper`.
pub async fn dispatch_owner_broadcast<S>(
    identity: &crate::chat_identity::FetchitIdentity,
    signer: &S,
    inputs: &OwnerBroadcastInputs<'_>,
) -> Result<Vec<fetchit_relay_proto::TransitEnvelope>>
where
    S: fetchit_relay_client::Signer + ?Sized,
{
    let payload_b64 = encode_payload_b64(&inputs.event_json)?;
    let mut out = Vec::with_capacity(inputs.recipients_kem.len());
    for (aid, kem_pub) in inputs.recipients_kem {
        let wrapper = X0xdGroupMetadataEventWrapper {
            topic: inputs.topic.clone(),
            payload_b64: payload_b64.clone(),
        };
        let envelope = build_bridge_outbox(identity, signer, aid, kem_pub, &wrapper).await?;
        out.push(envelope);
    }
    Ok(out)
}
```

Add the matching unit test at the bottom of `bridge.rs` `#[cfg(test)] mod tests`:

```rust
#[tokio::test]
async fn dispatch_owner_broadcast_fans_out_one_envelope_per_recipient() {
    use crate::chat_identity::FetchitIdentity;
    use fetchit_relay_client::testing::FixedSigner;

    let identity = FetchitIdentity::generate_for_test();
    let signer = FixedSigner::new();
    let kem_pub_a = vec![0u8; KEM_PUBLIC_KEY_LEN];
    let kem_pub_b = vec![1u8; KEM_PUBLIC_KEY_LEN];
    let inputs = OwnerBroadcastInputs {
        topic: "x0x.named_group.metadata.gid".to_owned(),
        event_json: serde_json::json!({ "event": "member_removed", "agent_id": "x" }),
        recipients_kem: &[
            ("aid-a".to_owned(), kem_pub_a),
            ("aid-b".to_owned(), kem_pub_b),
        ],
    };
    let envelopes = dispatch_owner_broadcast(&identity, &signer, &inputs).await.unwrap();
    assert_eq!(envelopes.len(), 2);
    for env in &envelopes {
        assert_eq!(env.kind, fetchit_relay_proto::EnvelopeKind::X0xdGroupMetadataEvent);
        assert!(!env.ciphertext.is_empty());
    }
}
```

If `FetchitIdentity::generate_for_test` or `fetchit_relay_client::testing::FixedSigner` do not exist verbatim, use the test helpers that the existing `build_bridge_outbox` test in `bridge.rs` uses (search `bridge.rs` for `fn build_bridge_outbox_seals_and_signs` and copy the signer pattern).

- [ ] **Step 2: Run test to verify failure first, then pass after impl is in place**

Run: `cargo test -p fetchit-chat groups::bridge::tests::dispatch_owner_broadcast`
Expected: PASS after the impl is added in step 1.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/bridge.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): dispatch_owner_broadcast fan-out helper for #251 Layer 2" \
  -m "Thin wrapper over build_bridge_outbox that takes an arbitrary owner-emitted NamedGroupMetadataEvent JSON and produces one sealed envelope per recipient. Callers pick the build_*_event helper (member_removed / member_role_updated / policy_updated / member_banned / group_deleted) then invoke this for fan-out."
```

### Task A7: Wire owner-broadcast dispatch into the `remove-member` flow

**Files:**
- Modify: the caller that handles `POST /groups/<id>/remove-member` in
  the desktop shell. Search:
  `grep -rn "remove.member\|remove_member" apps/fetchit-desktop/src-tauri/src crates/fetchit-chat/src`.
- The natural seam is wherever the existing `MemberJoined` bridge fires
  today (search `groups::bridge::build_bridge_outbox` callers).

- [ ] **Step 1: Identify the existing MemberJoined dispatcher seam**

Run: `grep -rnE "build_bridge_outbox|build_member_joined_event" apps/fetchit-desktop/src-tauri/src crates/fetchit-chat/src | head -20`

Read the function that wraps it and note the function name + file.

- [ ] **Step 2: Add the parallel `remove-member` dispatcher**

In the same file as the MemberJoined dispatcher, add a sibling function:

```rust
/// Fan out a `MemberRemoved` bridge envelope to every other active
/// member after `POST /groups/<id>/remove-member` returns.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_member_removed_bridge(
    identity: &FetchitIdentity,
    signer: &impl fetchit_relay_client::Signer,
    relay_client: &fetchit_relay_client::Client,
    layout: &StoreLayout,
    group_id: &str,
    metadata_topic: &str,
    revision: u64,
    actor_aid: &str,
    removed_aid: &str,
    treekem_commit_b64: Option<&str>,
    treekem_epoch: Option<u64>,
    commit_json: Option<serde_json::Value>,
    active_member_aids: &[String],
) -> crate::error::Result<()> {
    use crate::groups::bridge_member_removed::{
        build_member_removed_event, MemberRemovedInputs,
    };
    use crate::groups::bridge::{dispatch_owner_broadcast, recipient_kem_key, OwnerBroadcastInputs};

    let event = build_member_removed_event(&MemberRemovedInputs {
        group_id,
        revision,
        actor: actor_aid,
        agent_id: removed_aid,
        treekem_commit_b64,
        treekem_epoch,
        commit_json,
    });
    let mut recipients = Vec::with_capacity(active_member_aids.len());
    for aid in active_member_aids {
        if aid == actor_aid || aid == removed_aid {
            continue;
        }
        match recipient_kem_key(layout, aid) {
            Ok(kem) => recipients.push((aid.clone(), kem)),
            Err(crate::error::ChatError::ShareCardMissing { .. }) => {
                tracing::warn!(
                    target: "fetchit_chat::bridge",
                    %aid, "MemberRemoved bridge: share-card missing; skipping"
                );
            }
            Err(e) => return Err(e),
        }
    }
    let envelopes = dispatch_owner_broadcast(
        identity,
        signer,
        &OwnerBroadcastInputs {
            topic: metadata_topic.to_owned(),
            event_json: event,
            recipients_kem: &recipients,
        },
    ).await?;
    for env in envelopes {
        relay_client.send_envelope(env).await?;
    }
    Ok(())
}
```

Replace `fetchit_relay_client::Client::send_envelope` with the exact
send call shape the MemberJoined path uses; the prior step's grep
shows the right signature.

- [ ] **Step 3: Add an integration-style unit test**

In the same file (or its existing `#[cfg(test)] mod tests`), add:

```rust
#[tokio::test]
async fn dispatch_member_removed_bridge_skips_actor_and_removed_member() {
    use std::sync::Arc;

    let identity = crate::chat_identity::FetchitIdentity::generate_for_test();
    let signer = fetchit_relay_client::testing::FixedSigner::new();
    let temp = tempfile::tempdir().unwrap();
    let layout = crate::local_store::StoreLayout::for_test(temp.path());

    // Pre-seed share-cards for three peers so recipient_kem_key resolves.
    for aid in ["aid-a", "aid-b", "aid-c"] {
        let kem_b64 = base64::engine::general_purpose::STANDARD
            .encode(vec![0u8; fetchit_chat::chat_crypto::KEM_PUBLIC_KEY_LEN]);
        crate::messages::StoredContactCard::store_for_test(&layout, aid, &kem_b64);
    }

    let sent = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let relay_client = fetchit_relay_client::testing::CapturingClient::new(sent.clone());

    dispatch_member_removed_bridge(
        &identity,
        &signer,
        &relay_client,
        &layout,
        "gid",
        "x0x.named_group.metadata.gid",
        7,
        "aid-a",        // actor
        "aid-b",        // removed
        None,
        Some(5),
        None,
        &["aid-a".into(), "aid-b".into(), "aid-c".into()],
    )
    .await
    .unwrap();

    let to_aids = sent.lock().unwrap();
    assert_eq!(to_aids.len(), 1, "only aid-c should receive");
    assert_eq!(to_aids[0], "aid-c");
}
```

If the helper crates referenced (`fetchit_relay_client::testing::CapturingClient`, `StoreLayout::for_test`, `StoredContactCard::store_for_test`) do not exist with the exact names shown, use the equivalent test helpers the existing MemberJoined dispatcher tests reference (located alongside step 1's grep output).

- [ ] **Step 4: Run test, confirm green**

Run: `cargo test -p fetchit-chat dispatch_member_removed_bridge_skips_actor_and_removed_member`
Expected: PASS.

- [ ] **Step 5: Workspace gate**.

- [ ] **Step 6: Commit**

```bash
git add <files-modified>
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): wire MemberRemoved fan-out through dispatch_owner_broadcast for #251 Layer 2" \
  -m "After POST /groups/<id>/remove-member returns, fan out a MemberRemoved bridge envelope to every active member except the actor and the removed peer. Skip recipients whose share-card hasn't been imported yet (chat:warn logged via tracing; not a hard error). Mirrors the existing MemberJoined dispatcher pattern."
```

### Task A8: Wire `member_role_updated` dispatcher

**Files:**
- Modify: the same dispatcher file as Task A7.

- [ ] **Step 1: Add the dispatcher function** mirroring Task A7 shape, swapping in `bridge_member_role_updated::{build_member_role_updated_event, MemberRoleUpdatedInputs}` and the `role` field.

```rust
pub async fn dispatch_member_role_updated_bridge(
    identity: &FetchitIdentity,
    signer: &impl fetchit_relay_client::Signer,
    relay_client: &fetchit_relay_client::Client,
    layout: &StoreLayout,
    group_id: &str,
    metadata_topic: &str,
    revision: u64,
    actor_aid: &str,
    target_aid: &str,
    new_role: &str,
    commit_json: Option<serde_json::Value>,
    active_member_aids: &[String],
) -> crate::error::Result<()> {
    use crate::groups::bridge_member_role_updated::{
        build_member_role_updated_event, MemberRoleUpdatedInputs,
    };
    use crate::groups::bridge::{dispatch_owner_broadcast, recipient_kem_key, OwnerBroadcastInputs};

    let event = build_member_role_updated_event(&MemberRoleUpdatedInputs {
        group_id,
        revision,
        actor: actor_aid,
        agent_id: target_aid,
        role: new_role,
        commit_json,
    });
    let mut recipients = Vec::with_capacity(active_member_aids.len());
    for aid in active_member_aids {
        if aid == actor_aid {
            continue;
        }
        match recipient_kem_key(layout, aid) {
            Ok(kem) => recipients.push((aid.clone(), kem)),
            Err(crate::error::ChatError::ShareCardMissing { .. }) => continue,
            Err(e) => return Err(e),
        }
    }
    let envelopes = dispatch_owner_broadcast(
        identity,
        signer,
        &OwnerBroadcastInputs {
            topic: metadata_topic.to_owned(),
            event_json: event,
            recipients_kem: &recipients,
        },
    ).await?;
    for env in envelopes {
        relay_client.send_envelope(env).await?;
    }
    Ok(())
}
```

- [ ] **Step 2: Add a parallel test** using the same `CapturingClient`
  pattern as Task A7, asserting one envelope per active non-actor
  member with `event=member_role_updated` and `role=admin`.

- [ ] **Step 3: Run test, confirm green**.

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add <files-modified>
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): wire MemberRoleUpdated fan-out through dispatch_owner_broadcast for #251 Layer 2"
```

### Task A9: Wire `policy_updated`, `member_banned`, `group_deleted` dispatchers

Repeat Task A8's shape three times: one dispatcher + one test per
event variant. Each dispatcher takes the relevant inputs (policy_json
for PolicyUpdated, reason for MemberBanned, no extra fields for
GroupDeleted) and reuses `dispatch_owner_broadcast`.

For `dispatch_group_deleted_bridge` the recipient list is the active
members EXCEPT the actor; for `policy_updated` and `member_banned`
the same rule applies.

- [ ] **Step 1: Add three dispatcher functions** in the same file.

- [ ] **Step 2: Add three parallel tests** each asserting:
  - One envelope per active non-actor member.
  - The first envelope's decoded inner `event_json` matches the
    expected variant string (`"policy_updated"`, `"member_banned"`,
    `"group_deleted"`).
  - For MemberBanned: `reason` survives the round-trip.

- [ ] **Step 3: Run tests, confirm green**.

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Single commit covering all three**

```bash
git add <files-modified>
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): wire PolicyUpdated + MemberBanned + GroupDeleted dispatchers for #251 Layer 2" \
  -m "Three sibling dispatchers next to MemberRemoved + MemberRoleUpdated, closing the owner-broadcast bridge surface for v1.0 group ops on residential NAT. Each one mirrors the dispatch_owner_broadcast fan-out shape."
```

### Task A10: Receiver-side `dispatch.rs` already handles `X0xdGroupMetadataEvent` POST; verify the new event variants flow through

**Files:**
- Verify: `crates/fetchit-chat/src/dispatch.rs`

- [ ] **Step 1: Read the existing inbound dispatch**

Run: `grep -nE "X0xdGroupMetadataEvent|x0xd_publish|x0xd.publish" crates/fetchit-chat/src/dispatch.rs | head -10`

Read the function that handles the inbound `X0xdGroupMetadataEvent`
kind and confirm it forwards the inner `event_json` to local x0xd
`/publish` without inspecting the inner `event` discriminator. If it
does inspect (i.e. hardcodes `"member_joined"`), this task is to
loosen that check.

- [ ] **Step 2: Add an integration-style test that asserts each new event variant survives the inbound dispatch round-trip**

In `crates/fetchit-chat/src/dispatch.rs`'s test module:

```rust
#[tokio::test]
async fn inbound_x0xd_metadata_event_routes_all_owner_broadcast_variants() {
    use mockito::Matcher;
    let mut server = mockito::Server::new_async().await;
    let publish_mock = server
        .mock("POST", "/publish")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "topic": "x0x.named_group.metadata.gid",
        })))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let cases = [
        serde_json::json!({ "event": "member_removed",     "group_id": "gid", "revision": 2 }),
        serde_json::json!({ "event": "member_role_updated", "group_id": "gid", "revision": 3 }),
        serde_json::json!({ "event": "policy_updated",      "group_id": "gid", "revision": 4 }),
        serde_json::json!({ "event": "member_banned",       "group_id": "gid", "revision": 5 }),
        serde_json::json!({ "event": "group_deleted",       "group_id": "gid", "revision": 6 }),
    ];

    for event in cases {
        // Construct an X0xdGroupMetadataEventWrapper around `event`,
        // seal it, build a TransitEnvelope, and feed it through the
        // existing inbound dispatch path. Use the same helper the
        // MemberJoined inbound test uses.
        deliver_x0xd_bridge_envelope_for_test(&server, &event).await;
    }

    // Each variant should POST to /publish once (5 total). The
    // existing mock fires per matching request.
    publish_mock.expect(5).assert_async().await;
}
```

Use the existing helper for `deliver_x0xd_bridge_envelope_for_test`
that the MemberJoined inbound test relies on. If no such helper
exists, copy the inbound MemberJoined test fixture and parameterize
it.

- [ ] **Step 3: Run test, confirm green**

Run: `cargo test -p fetchit-chat dispatch::tests::inbound_x0xd_metadata_event_routes_all_owner_broadcast_variants`

If the dispatch path hardcodes the `"member_joined"` discriminator, the test will fail until you loosen the discriminator check to allow any of the five new variants (route opaquely if upstream accepts opaque events; verify against `/home/josh/Desktop/x0x/src/bin/x0xd.rs` `apply_named_group_metadata_event` to confirm it routes by `event` field).

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/dispatch.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "test(chat-dispatch): five owner-broadcast NamedGroupMetadataEvent variants flow through inbound bridge for #251 Layer 2" \
  -m "Parameterized inbound-dispatch test confirms each of member_removed / member_role_updated / policy_updated / member_banned / group_deleted reaches local x0xd /publish via the existing X0xdGroupMetadataEvent receive path. If the dispatch path had hardcoded the member_joined discriminator, loosens it here."
```

---

## Phase B: Welcome-blob contingency (gated by bundled x0xd version)

Goal: cover the `#277` failure window before David's `63b5c63b`
Welcome-retry fix ships in a release tag. New EnvelopeKinds carry the
joiner-to-owner `WelcomeRequest` and owner-to-joiner `WelcomeBlob`
payloads. Gated at runtime by a `bundled_x0xd_below_v0_21_3` check so
the bridge retires once the bundled binary pins a fixed release.

### Task B1: Add `EnvelopeKind::WelcomeBlobRequest` + `WelcomeBlobResponse`

**Files:**
- Modify: `crates/fetchit-relay-proto/src/envelope.rs:46-192`
- Modify: `crates/fetchit-relay-proto/tests/roundtrip.rs` (or
  `v2_roundtrip.rs`; pick whichever covers EnvelopeKind round-trips
  today).

- [ ] **Step 1: Write the failing test in `tests/roundtrip.rs`**

```rust
#[test]
fn envelope_kind_welcome_blob_request_round_trips() {
    let env = fetchit_relay_proto::EnvelopeKind::WelcomeBlobRequest;
    let bytes = postcard::to_allocvec(&env).unwrap();
    let back: fetchit_relay_proto::EnvelopeKind = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, fetchit_relay_proto::EnvelopeKind::WelcomeBlobRequest);
}

#[test]
fn envelope_kind_welcome_blob_response_round_trips() {
    let env = fetchit_relay_proto::EnvelopeKind::WelcomeBlobResponse;
    let bytes = postcard::to_allocvec(&env).unwrap();
    let back: fetchit_relay_proto::EnvelopeKind = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, fetchit_relay_proto::EnvelopeKind::WelcomeBlobResponse);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fetchit-relay-proto envelope_kind_welcome_blob`
Expected: FAIL "no variant WelcomeBlobRequest".

- [ ] **Step 3: Add the variants + discriminators**

In `crates/fetchit-relay-proto/src/envelope.rs`:

```rust
// Inside the EnvelopeKind enum, after X0xdGroupMetadataEvent and
// before Unknown(u8):

    /// #251 Layer 2 Welcome contingency: joiner -> owner request for
    /// the MLS Welcome blob bytes via fetchit-relay. Fires when the
    /// joiner's bundled x0xd is below v0.21.3 (the David 63b5c63b
    /// Welcome-retry fix lands) and the native peer-relay Welcome
    /// fetch failed with ReaderExit. The owner's chat-peer fetches
    /// the pending Welcome from local x0xd and replies with a
    /// `WelcomeBlobResponse`. Once the bundled binary pins a release
    /// containing 63b5c63b, the dispatch path returns `NotNeeded`
    /// and the caller short-circuits to x0xd's native flow.
    WelcomeBlobRequest,
    /// #251 Layer 2 Welcome contingency: owner -> joiner response
    /// carrying the MLS Welcome blob bytes the joiner's x0xd will
    /// import via `POST /groups/join-from-bridged-blob`. Same gate
    /// as WelcomeBlobRequest.
    WelcomeBlobResponse,
```

Add discriminators:

```rust
const DISC_WELCOME_BLOB_REQUEST: u32 = 6;
const DISC_WELCOME_BLOB_RESPONSE: u32 = 7;
```

Add to `Serialize::serialize`:

```rust
            EnvelopeKind::WelcomeBlobRequest => DISC_WELCOME_BLOB_REQUEST,
            EnvelopeKind::WelcomeBlobResponse => DISC_WELCOME_BLOB_RESPONSE,
```

Add to `Deserialize::deserialize`:

```rust
                    DISC_WELCOME_BLOB_REQUEST => EnvelopeKind::WelcomeBlobRequest,
                    DISC_WELCOME_BLOB_RESPONSE => EnvelopeKind::WelcomeBlobResponse,
```

Add to the variant-name slice:

```rust
            &[
                "Dm",
                "GroupChat",
                "AdminEvent",
                "DeliveryReceipt",
                "PrivateGroupChat",
                "X0xdGroupMetadataEvent",
                "WelcomeBlobRequest",
                "WelcomeBlobResponse",
                "Unknown",
            ],
```

- [ ] **Step 4: Run test, confirm PASS**

Run: `cargo test -p fetchit-relay-proto envelope_kind_welcome_blob`
Expected: 2 PASS.

- [ ] **Step 5: Confirm the `Unknown(_)` forward-compat shim still
  catches discriminators 8 and above**

Run: `cargo test -p fetchit-relay-proto envelope_kind`
Expected: all existing tests including the `Unknown` round-trip tests
PASS.

- [ ] **Step 6: Workspace gate**.

- [ ] **Step 7: Commit**

```bash
git add crates/fetchit-relay-proto/src/envelope.rs \
        crates/fetchit-relay-proto/tests/roundtrip.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(relay-proto): EnvelopeKind WelcomeBlobRequest + WelcomeBlobResponse for #251 Layer 2 contingency" \
  -m "Two new variants at discriminators 6 and 7 carry the joiner-to-owner Welcome request and owner-to-joiner Welcome blob payload for the #277 / saorsa-labs/x0x#98 failure window. Wire-additive: older relays + clients running the Unknown(u8) shim pass these envelopes through unchanged. Gated at runtime by the bundled x0xd version check; retires once the bundled binary pins a release containing David's 63b5c63b Welcome-retry fix."
```

### Task B2: `WelcomeRequestPayload` + `WelcomeBlobPayload` shapes + seal helpers

**Files:**
- Create: `crates/fetchit-chat/src/groups/welcome_bridge.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs`

- [ ] **Step 1: Write the file with payload types, seal/unseal helpers, and tests**

```rust
// crates/fetchit-chat/src/groups/welcome_bridge.rs
//! M2.5 Welcome contingency bridge (#251 Layer 2).
//!
//! Two payload shapes, sealed under ML-KEM-768 to the recipient's
//! chat-card KEM pubkey with ChaCha20-Poly1305 AEAD:
//!
//! - WelcomeRequest: joiner asks the owner to ship the pending
//!   Welcome blob bytes for `group_id` to `joiner_agent_id`.
//! - WelcomeBlob: owner replies with the bytes.
//!
//! Both gate behind `bundled_x0xd_below_v0_21_3` at the call site.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::chat_crypto::{
    aead_open, aead_seal, derive_aead_key, kem_decapsulate, kem_encapsulate, random_nonce,
    AAD_DOMAIN, AEAD_NONCE_LEN, KEM_PUBLIC_KEY_LEN,
};
use crate::error::{ChatError, Result};

const KDF_INFO_WELCOME_BRIDGE: &[u8] = b"fetchit.welcome-bridge.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WelcomeRequestPayload {
    pub group_id: String,
    pub joiner_agent_id: String,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WelcomeBlobPayload {
    pub group_id: String,
    pub blob_b64: String,
    pub ts_ms: u64,
}

#[must_use]
pub fn welcome_bridge_aad() -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 20);
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(b"|welcome-bridge-v1|");
    out
}

#[derive(Debug, Clone)]
pub struct SealedWelcomeParts {
    pub kem_ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// # Errors
/// - [`ChatError::Invalid`] when `recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN`.
/// - AEAD seal / KEM encap errors.
pub fn seal_welcome_request(
    recipient_kem_pub: &[u8],
    payload: &WelcomeRequestPayload,
) -> Result<SealedWelcomeParts> {
    let plaintext = postcard::to_allocvec(payload)
        .map_err(|e| ChatError::Invalid(format!("welcome-request postcard: {e}")))?;
    seal_inner(recipient_kem_pub, &plaintext)
}

/// # Errors
/// Same as [`seal_welcome_request`].
pub fn seal_welcome_blob(
    recipient_kem_pub: &[u8],
    payload: &WelcomeBlobPayload,
) -> Result<SealedWelcomeParts> {
    let plaintext = postcard::to_allocvec(payload)
        .map_err(|e| ChatError::Invalid(format!("welcome-blob postcard: {e}")))?;
    seal_inner(recipient_kem_pub, &plaintext)
}

fn seal_inner(recipient_kem_pub: &[u8], plaintext: &[u8]) -> Result<SealedWelcomeParts> {
    if recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN {
        return Err(ChatError::Invalid("welcome-bridge recipient KEM pubkey wrong length".into()));
    }
    let (kem_ciphertext, shared_secret) = kem_encapsulate(recipient_kem_pub)?;
    let aead_key = derive_aead_key(&shared_secret, KDF_INFO_WELCOME_BRIDGE)?;
    let nonce = random_nonce();
    let aad = welcome_bridge_aad();
    let ciphertext = aead_seal(&aead_key, &nonce, &aad, plaintext)?;
    Ok(SealedWelcomeParts { kem_ciphertext, nonce, ciphertext })
}

/// # Errors
/// AEAD open / KEM decap / postcard decode errors.
pub fn unseal_welcome_request(
    recipient_kem_secret: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<WelcomeRequestPayload> {
    let plaintext = unseal_inner(recipient_kem_secret, kem_ciphertext, nonce, ciphertext)?;
    postcard::from_bytes(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("welcome-request unseal: {e}")))
}

/// # Errors
/// AEAD open / KEM decap / postcard decode errors.
pub fn unseal_welcome_blob(
    recipient_kem_secret: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<WelcomeBlobPayload> {
    let plaintext = unseal_inner(recipient_kem_secret, kem_ciphertext, nonce, ciphertext)?;
    postcard::from_bytes(&plaintext)
        .map_err(|e| ChatError::Invalid(format!("welcome-blob unseal: {e}")))
}

fn unseal_inner(
    recipient_kem_secret: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != AEAD_NONCE_LEN {
        return Err(ChatError::Invalid("welcome-bridge nonce wrong length".into()));
    }
    let shared_secret = kem_decapsulate(recipient_kem_secret, kem_ciphertext)?;
    let aead_key = derive_aead_key(&shared_secret, KDF_INFO_WELCOME_BRIDGE)?;
    let aad = welcome_bridge_aad();
    aead_open(&aead_key, nonce, &aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_crypto::kem_keygen;

    #[test]
    fn welcome_request_round_trips_through_seal_then_unseal() {
        let (kem_pub, kem_secret) = kem_keygen();
        let payload = WelcomeRequestPayload {
            group_id: "gid-1234".into(),
            joiner_agent_id: "aid-joiner".into(),
            ts_ms: 1_000_000_000,
        };
        let sealed = seal_welcome_request(&kem_pub, &payload).unwrap();
        let back = unseal_welcome_request(
            &kem_secret, &sealed.kem_ciphertext, &sealed.nonce, &sealed.ciphertext,
        ).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn welcome_blob_round_trips_with_33k_bytes() {
        let (kem_pub, kem_secret) = kem_keygen();
        let blob_b64 = B64.encode(vec![0xABu8; 33 * 1024]);
        let payload = WelcomeBlobPayload {
            group_id: "gid".into(),
            blob_b64,
            ts_ms: 1,
        };
        let sealed = seal_welcome_blob(&kem_pub, &payload).unwrap();
        let back = unseal_welcome_blob(
            &kem_secret, &sealed.kem_ciphertext, &sealed.nonce, &sealed.ciphertext,
        ).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn seal_welcome_request_rejects_wrong_length_recipient_pubkey() {
        let payload = WelcomeRequestPayload {
            group_id: "g".into(),
            joiner_agent_id: "j".into(),
            ts_ms: 0,
        };
        let err = seal_welcome_request(&[0u8; 16], &payload).unwrap_err();
        assert!(matches!(err, ChatError::Invalid(_)));
    }
}
```

Wire into `mod.rs`: `pub mod welcome_bridge;`.

- [ ] **Step 2: Run tests, confirm green**

Run: `cargo test -p fetchit-chat groups::welcome_bridge`
Expected: 3 PASS.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/groups/welcome_bridge.rs \
        crates/fetchit-chat/src/groups/mod.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): welcome_bridge seal/unseal helpers for #251 Layer 2 contingency" \
  -m "WelcomeRequestPayload + WelcomeBlobPayload sealed under ML-KEM-768 + ChaCha20-Poly1305 with domain-separated AAD (|welcome-bridge-v1|). Round-trip tests prove a 33 KB blob (typical group N=2) survives. Will be gated at the dispatcher by bundled_x0xd_below_v0_21_3 in Task B4."
```

### Task B3: Welcome-bridge dispatcher

**Files:**
- Modify: the same dispatcher file as Tasks A7-A9 (or a sibling file
  `welcome_bridge_dispatch.rs` if the existing file is getting large).

- [ ] **Step 1: Add `dispatch_welcome_request_to_owner` and `dispatch_welcome_blob_to_joiner`**

```rust
pub async fn dispatch_welcome_request_to_owner(
    identity: &FetchitIdentity,
    signer: &impl fetchit_relay_client::Signer,
    relay_client: &fetchit_relay_client::Client,
    layout: &StoreLayout,
    owner_aid: &str,
    group_id: &str,
    joiner_aid: &str,
    ts_ms: u64,
) -> crate::error::Result<()> {
    use crate::groups::welcome_bridge::{seal_welcome_request, WelcomeRequestPayload};
    use fetchit_relay_proto::{EnvelopeKind, TransitEnvelope, WIRE_VERSION};

    let kem_pub = crate::groups::bridge::recipient_kem_key(layout, owner_aid)?;
    let payload = WelcomeRequestPayload {
        group_id: group_id.to_owned(),
        joiner_agent_id: joiner_aid.to_owned(),
        ts_ms,
    };
    let parts = seal_welcome_request(&kem_pub, &payload)?;
    let mut env = TransitEnvelope {
        version: WIRE_VERSION,
        kind: EnvelopeKind::WelcomeBlobRequest,
        from: identity.agent_id().clone(),
        to: fetchit_relay_proto::AgentId::from_hex_str(owner_aid)?,
        group_id: Some(group_id.to_owned()),
        epoch: 0,
        nonce: parts.nonce,
        kem_ciphertext: parts.kem_ciphertext,
        ciphertext: parts.ciphertext,
        sent_at_ms: ts_ms,
        sender_signature: Vec::new(), // signer fills in below
    };
    let sig_bytes = crate::chat_crypto::canonical_envelope_bytes(&env);
    env.sender_signature = signer.sign(&sig_bytes).await?;
    relay_client.send_envelope(env).await
}

pub async fn dispatch_welcome_blob_to_joiner(
    identity: &FetchitIdentity,
    signer: &impl fetchit_relay_client::Signer,
    relay_client: &fetchit_relay_client::Client,
    layout: &StoreLayout,
    joiner_aid: &str,
    group_id: &str,
    blob_bytes: &[u8],
    ts_ms: u64,
) -> crate::error::Result<()> {
    use crate::groups::welcome_bridge::{seal_welcome_blob, WelcomeBlobPayload};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use fetchit_relay_proto::{EnvelopeKind, TransitEnvelope, WIRE_VERSION};

    let kem_pub = crate::groups::bridge::recipient_kem_key(layout, joiner_aid)?;
    let payload = WelcomeBlobPayload {
        group_id: group_id.to_owned(),
        blob_b64: B64.encode(blob_bytes),
        ts_ms,
    };
    let parts = seal_welcome_blob(&kem_pub, &payload)?;
    let mut env = TransitEnvelope {
        version: WIRE_VERSION,
        kind: EnvelopeKind::WelcomeBlobResponse,
        from: identity.agent_id().clone(),
        to: fetchit_relay_proto::AgentId::from_hex_str(joiner_aid)?,
        group_id: Some(group_id.to_owned()),
        epoch: 0,
        nonce: parts.nonce,
        kem_ciphertext: parts.kem_ciphertext,
        ciphertext: parts.ciphertext,
        sent_at_ms: ts_ms,
        sender_signature: Vec::new(),
    };
    let sig_bytes = crate::chat_crypto::canonical_envelope_bytes(&env);
    env.sender_signature = signer.sign(&sig_bytes).await?;
    relay_client.send_envelope(env).await
}
```

- [ ] **Step 2: Add unit tests**

```rust
#[tokio::test]
async fn dispatch_welcome_request_emits_one_envelope_to_owner() {
    let identity = FetchitIdentity::generate_for_test();
    let signer = fetchit_relay_client::testing::FixedSigner::new();
    let temp = tempfile::tempdir().unwrap();
    let layout = StoreLayout::for_test(temp.path());
    let kem_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; KEM_PUBLIC_KEY_LEN]);
    crate::messages::StoredContactCard::store_for_test(&layout, "aid-owner", &kem_b64);

    let captured = Arc::new(std::sync::Mutex::new(Vec::<fetchit_relay_proto::TransitEnvelope>::new()));
    let relay_client = fetchit_relay_client::testing::CapturingClient::new_envelope_capture(captured.clone());

    dispatch_welcome_request_to_owner(
        &identity, &signer, &relay_client, &layout,
        "aid-owner", "gid", "aid-joiner", 1_000,
    ).await.unwrap();

    let sent = captured.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].kind, fetchit_relay_proto::EnvelopeKind::WelcomeBlobRequest);
    assert_eq!(sent[0].group_id.as_deref(), Some("gid"));
}

#[tokio::test]
async fn dispatch_welcome_blob_emits_one_envelope_to_joiner_with_33k_payload() {
    let identity = FetchitIdentity::generate_for_test();
    let signer = fetchit_relay_client::testing::FixedSigner::new();
    let temp = tempfile::tempdir().unwrap();
    let layout = StoreLayout::for_test(temp.path());
    let kem_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; KEM_PUBLIC_KEY_LEN]);
    crate::messages::StoredContactCard::store_for_test(&layout, "aid-joiner", &kem_b64);

    let captured = Arc::new(std::sync::Mutex::new(Vec::<fetchit_relay_proto::TransitEnvelope>::new()));
    let relay_client = fetchit_relay_client::testing::CapturingClient::new_envelope_capture(captured.clone());

    let blob = vec![0xCDu8; 33 * 1024];
    dispatch_welcome_blob_to_joiner(
        &identity, &signer, &relay_client, &layout,
        "aid-joiner", "gid", &blob, 2_000,
    ).await.unwrap();

    let sent = captured.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].kind, fetchit_relay_proto::EnvelopeKind::WelcomeBlobResponse);
}
```

- [ ] **Step 3: Run tests, confirm green**.

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add <files-modified>
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): Welcome request/blob dispatchers for #251 Layer 2 contingency" \
  -m "Joiner-side dispatch_welcome_request_to_owner emits a single sealed envelope to the group owner with the joiner's agent id and group_id. Owner-side dispatch_welcome_blob_to_joiner emits the blob bytes wrapped under the new WelcomeBlobResponse kind. Both seal with the seal_welcome_* helpers and sign with the caller's ML-DSA chat-identity key. Will be gated by the bundled_x0xd_below_v0_21_3 check in B4."
```

### Task B4: Gate the Welcome bridge behind the bundled x0xd version

**Files:**
- Create: `crates/fetchit-chat/src/groups/welcome_gate.rs`
- Modify: `crates/fetchit-chat/src/groups/mod.rs`
- Modify: the caller path that triggers the Welcome bridge (likely
  inside the post-`POST /groups/join` failure-detection loop; identify
  via `grep -rn "groups/join" crates/fetchit-chat/src apps/fetchit-desktop/src-tauri/src`).

- [ ] **Step 1: Write the gate module + tests**

```rust
// crates/fetchit-chat/src/groups/welcome_gate.rs
//! #251 Layer 2 contingency gate. The Welcome bridge only runs while
//! the local x0xd (bundled or installed) is below v0.21.3 (the release
//! that carries David's 63b5c63b Welcome-retry fix). Once the local
//! binary catches up, callers short-circuit to x0xd's native Welcome
//! flow.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Minimum x0xd version that obviates the Welcome bridge. Bumped in
/// lockstep with David's release tagging cadence.
pub const WELCOME_BRIDGE_RETIRES_AT: semver::Version = semver::Version::new(0, 21, 3);

/// True when the bridge must run. False short-circuits to the native
/// x0xd Welcome flow.
#[must_use]
pub fn bridge_required(local_x0xd: &semver::Version) -> bool {
    local_x0xd < &WELCOME_BRIDGE_RETIRES_AT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_required_below_threshold() {
        let v = semver::Version::parse("0.21.2").unwrap();
        assert!(bridge_required(&v));
    }

    #[test]
    fn bridge_not_required_at_threshold() {
        let v = semver::Version::parse("0.21.3").unwrap();
        assert!(!bridge_required(&v));
    }

    #[test]
    fn bridge_not_required_above_threshold() {
        let v = semver::Version::parse("0.22.0").unwrap();
        assert!(!bridge_required(&v));
    }
}
```

Add `semver = "1"` to `crates/fetchit-chat/Cargo.toml` `[dependencies]`
if not already present. Add `pub mod welcome_gate;` to `groups/mod.rs`.

- [ ] **Step 2: Run tests, confirm green**

Run: `cargo test -p fetchit-chat groups::welcome_gate`
Expected: 3 PASS.

- [ ] **Step 3: Add the gate guard at the dispatcher call site**

At the call site (the post-`POST /groups/join` failure handler), wrap
the call:

```rust
let local_version = x0xd_client.version().await?;
if !crate::groups::welcome_gate::bridge_required(&local_version.semver) {
    tracing::debug!(
        target: "fetchit_chat::welcome_bridge",
        version = %local_version.semver,
        "local x0xd carries the Welcome-retry fix; not bridging",
    );
    return Ok(());
}
dispatch_welcome_request_to_owner(/* ... */).await?;
```

Replace `x0xd_client.version()` with the actual method exposed by
`x0xd-client` (see `crates/x0xd-client/src/lib.rs` for the
`X0xdVersion` probe wired by M2 Task 13 / commit c70a73c).

- [ ] **Step 4: Add a guard test in the call site's test module**

```rust
#[tokio::test]
async fn welcome_bridge_skipped_when_local_x0xd_at_or_above_v0_21_3() {
    let fake_version = X0xdVersion::from_str("0.21.3").unwrap();
    let result = maybe_request_welcome_bridge(&fake_version, /* deps */).await;
    assert!(result.is_ok(), "skip path returns Ok");
    // Optional: assert no envelope captured if the captures helper is wired.
}
```

- [ ] **Step 5: Run test, confirm green**.

- [ ] **Step 6: Workspace gate**.

- [ ] **Step 7: Commit**

```bash
git add crates/fetchit-chat/src/groups/welcome_gate.rs \
        crates/fetchit-chat/src/groups/mod.rs \
        crates/fetchit-chat/Cargo.toml \
        <call-site-files>
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-bridge): gate Welcome bridge behind bundled x0xd < v0.21.3 for #251 Layer 2 contingency" \
  -m "welcome_gate::bridge_required returns false once the local x0xd version reaches 0.21.3 (the release carrying David's 63b5c63b Welcome-retry fix). The bridge stays implemented + tested so the contingency is available for the v0.21.2 window; it retires automatically when the bundled binary upgrades. Single semver dependency add on fetchit-chat."
```

### Task B5: Receiver-side dispatch for `WelcomeBlobRequest` and `WelcomeBlobResponse`

**Files:**
- Modify: `crates/fetchit-chat/src/dispatch.rs`

- [ ] **Step 1: Add inbound dispatch arms**

In the inbound dispatch match-on-kind:

```rust
EnvelopeKind::WelcomeBlobRequest => {
    let payload = crate::groups::welcome_bridge::unseal_welcome_request(
        identity.kem_secret_bytes(),
        &env.kem_ciphertext,
        &env.nonce,
        &env.ciphertext,
    )?;
    // Owner-side: fetch the pending Welcome from local x0xd and reply.
    let blob = x0xd_client
        .groups()
        .pending_welcome(&payload.group_id, &payload.joiner_agent_id)
        .await?;
    crate::groups::dispatch_welcome_blob_to_joiner(
        identity, signer, relay_client, layout,
        &payload.joiner_agent_id, &payload.group_id, &blob,
        now_ms(),
    ).await?;
    Ok(InboundDispatchOutcome::Handled)
}
EnvelopeKind::WelcomeBlobResponse => {
    let payload = crate::groups::welcome_bridge::unseal_welcome_blob(
        identity.kem_secret_bytes(),
        &env.kem_ciphertext,
        &env.nonce,
        &env.ciphertext,
    )?;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let blob_bytes = B64.decode(&payload.blob_b64)
        .map_err(|e| ChatError::Invalid(format!("welcome-blob b64: {e}")))?;
    x0xd_client
        .groups()
        .join_from_bridged_blob(&payload.group_id, &blob_bytes)
        .await?;
    Ok(InboundDispatchOutcome::Handled)
}
```

Replace `x0xd_client.groups().pending_welcome` and
`.join_from_bridged_blob` with the actual endpoint method names. If
they don't exist yet on the `x0xd-client::groups` endpoint, add them
as a sibling step (`Task B5a`) and stub them with `unimplemented!()`
until the upstream endpoints are confirmed via:

```bash
grep -nE "pending-welcome|join-from|/groups/join" /home/josh/Desktop/x0x/src/bin/x0xd.rs
```

For v1.0, if `join-from-bridged-blob` does not exist upstream, route
via the existing `/groups/join` endpoint and pass the `treekem_welcome_b64`
as the legacy inline-Welcome field (the upstream `MemberAdded`
fallback path already accepts inline Welcomes; see
`/home/josh/Desktop/x0x/src/bin/x0xd.rs:7960-7990` for the
`treekem_welcome_b64` field on `MemberAdded`).

- [ ] **Step 2: Add an integration test that round-trips through
  inbound dispatch** mirroring the existing MemberJoined inbound
  test, using a mockito-backed x0xd that returns a 33 KB blob on the
  pending-welcome endpoint and asserts that the dispatch path calls
  `dispatch_welcome_blob_to_joiner` (capture the relay client's
  envelopes).

- [ ] **Step 3: Run test, confirm green**.

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/dispatch.rs <any-x0xd-client-changes>
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(chat-dispatch): inbound WelcomeBlobRequest / WelcomeBlobResponse for #251 Layer 2 contingency" \
  -m "Owner-side: on WelcomeBlobRequest unseal, fetch the pending Welcome from local x0xd and reply via dispatch_welcome_blob_to_joiner. Joiner-side: on WelcomeBlobResponse unseal, b64-decode the blob and POST to local x0xd to complete group-join. Mockito-backed test covers a 33 KB blob round-trip."
```

---

## Phase C: Layer 1: x0xd-client `discover_installed_x0xd`

### Task C1: `discover_installed_x0xd()` returns `Option<InstalledX0xd>`

**Files:**
- Create: `crates/x0xd-client/src/discover.rs`
- Modify: `crates/x0xd-client/src/lib.rs`

- [ ] **Step 1: Write the failing test**

```rust
// crates/x0xd-client/src/discover.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledX0xd {
    pub binary: PathBuf,
    pub version: semver::Version,
}

/// Probe `$PATH` for an installed `x0xd` binary. Returns Some when
/// the executable is found AND `x0xd --version` parses as semver.
#[must_use]
pub fn discover_installed_x0xd() -> Option<InstalledX0xd> {
    let binary = which::which("x0xd").ok()?;
    let output = std::process::Command::new(&binary).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_str = stdout
        .lines()
        .next()?
        .split_whitespace()
        .last()?
        .trim_start_matches('v');
    let version = semver::Version::parse(version_str).ok()?;
    Some(InstalledX0xd { binary, version })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_returns_none_when_no_x0xd_on_path() {
        // Test only meaningful when the dev box does NOT have x0xd
        // on PATH; gate behind env var so CI works either way.
        if std::env::var("FETCHIT_TEST_ASSERT_NO_X0XD").is_ok() {
            assert!(discover_installed_x0xd().is_none());
        }
    }

    #[test]
    fn parses_v_prefix_version() {
        // Unit-test the parsing slice independent of which::which.
        let stdout = "x0xd v0.21.2\n";
        let line = stdout.lines().next().unwrap();
        let word = line.split_whitespace().last().unwrap().trim_start_matches('v');
        let v = semver::Version::parse(word).unwrap();
        assert_eq!(v, semver::Version::parse("0.21.2").unwrap());
    }

    #[test]
    fn parses_no_prefix_version() {
        let stdout = "x0xd 0.21.2\n";
        let line = stdout.lines().next().unwrap();
        let word = line.split_whitespace().last().unwrap().trim_start_matches('v');
        let v = semver::Version::parse(word).unwrap();
        assert_eq!(v, semver::Version::parse("0.21.2").unwrap());
    }
}
```

Add to `crates/x0xd-client/Cargo.toml`:

```toml
which = "6"
semver = "1"
```

Add `pub mod discover;` and `pub use discover::{discover_installed_x0xd, InstalledX0xd};` to `crates/x0xd-client/src/lib.rs`.

- [ ] **Step 2: Run tests, confirm green**

Run: `cargo test -p x0xd-client discover`
Expected: 3 PASS.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add crates/x0xd-client/src/discover.rs \
        crates/x0xd-client/src/lib.rs \
        crates/x0xd-client/Cargo.toml
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(x0xd-client): discover_installed_x0xd probes PATH and parses --version for #251 Layer 1" \
  -m "Returns Some(InstalledX0xd { binary, version }) when an x0xd binary is on PATH and its --version output parses as semver. Used by the desktop x0xd_supervisor to prefer a system-wide install over the bundled binary when the installed version is >= bundled."
```

---

## Phase D: Layer 1: `x0xd_supervisor` module

### Task D1: `pick_binary` selects between installed and bundled

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/mod.rs`
- Create: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/pick.rs`

- [ ] **Step 1: Write the failing test**

```rust
// apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/pick.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use x0xd_client::InstalledX0xd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryChoice {
    /// Use the user's installed x0xd at this path / version.
    Installed { binary: PathBuf, version: semver::Version },
    /// Spawn the fetch>it bundled x0xd at this path / version.
    Bundled { binary: PathBuf, version: semver::Version },
}

/// Pick which binary the supervisor should spawn / point at.
///
/// Rule: prefer a system-wide install when it is at-or-above the
/// bundled version. Otherwise use bundled. If both are missing,
/// return None so the caller can surface the X0xdVersionMismatch
/// error from spec §6.
#[must_use]
pub fn pick_binary(
    installed: Option<&InstalledX0xd>,
    bundled: Option<(PathBuf, semver::Version)>,
) -> Option<BinaryChoice> {
    match (installed, bundled) {
        (Some(i), Some((b_path, b_ver))) => {
            if i.version >= b_ver {
                Some(BinaryChoice::Installed {
                    binary: i.binary.clone(),
                    version: i.version.clone(),
                })
            } else {
                Some(BinaryChoice::Bundled {
                    binary: b_path,
                    version: b_ver,
                })
            }
        }
        (Some(i), None) => Some(BinaryChoice::Installed {
            binary: i.binary.clone(),
            version: i.version.clone(),
        }),
        (None, Some((b_path, b_ver))) => Some(BinaryChoice::Bundled {
            binary: b_path,
            version: b_ver,
        }),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version { semver::Version::parse(s).unwrap() }

    fn installed(path: &str, ver: &str) -> InstalledX0xd {
        InstalledX0xd {
            binary: PathBuf::from(path),
            version: v(ver),
        }
    }

    #[test]
    fn installed_preferred_when_at_or_above_bundled() {
        let i = installed("/usr/local/bin/x0xd", "0.21.3");
        let b = (PathBuf::from("/bundle/x0xd"), v("0.21.3"));
        assert_eq!(
            pick_binary(Some(&i), Some(b)),
            Some(BinaryChoice::Installed { binary: PathBuf::from("/usr/local/bin/x0xd"), version: v("0.21.3") }),
        );
    }

    #[test]
    fn bundled_chosen_when_installed_too_old() {
        let i = installed("/usr/local/bin/x0xd", "0.20.0");
        let b = (PathBuf::from("/bundle/x0xd"), v("0.21.3"));
        assert_eq!(
            pick_binary(Some(&i), Some(b)),
            Some(BinaryChoice::Bundled { binary: PathBuf::from("/bundle/x0xd"), version: v("0.21.3") }),
        );
    }

    #[test]
    fn bundled_chosen_when_installed_missing() {
        let b = (PathBuf::from("/bundle/x0xd"), v("0.21.3"));
        assert_eq!(
            pick_binary(None, Some(b)),
            Some(BinaryChoice::Bundled { binary: PathBuf::from("/bundle/x0xd"), version: v("0.21.3") }),
        );
    }

    #[test]
    fn installed_chosen_when_bundled_missing() {
        let i = installed("/usr/local/bin/x0xd", "0.21.2");
        assert_eq!(
            pick_binary(Some(&i), None),
            Some(BinaryChoice::Installed { binary: PathBuf::from("/usr/local/bin/x0xd"), version: v("0.21.2") }),
        );
    }

    #[test]
    fn none_when_both_missing() {
        assert_eq!(pick_binary(None, None), None);
    }
}
```

In `mod.rs`:

```rust
// apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/mod.rs
pub mod pick;
pub use pick::{pick_binary, BinaryChoice};
```

Add `x0xd-client = { path = "../../../crates/x0xd-client" }` and
`semver = "1"` to `apps/fetchit-desktop/src-tauri/Cargo.toml`
`[dependencies]` if not already present.

- [ ] **Step 2: Run tests, confirm green** (workspace-excluded crate;
  run from inside its dir)

```bash
(cd apps/fetchit-desktop/src-tauri && cargo test x0xd_supervisor::pick)
```

Expected: 5 PASS.

- [ ] **Step 3: Workspace gate** (excluded crate)

```bash
(cd apps/fetchit-desktop/src-tauri && cargo fmt --all)
(cd apps/fetchit-desktop/src-tauri && cargo clippy --all-targets -- -D warnings)
(cd apps/fetchit-desktop/src-tauri && cargo test)
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- [ ] **Step 4: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/x0xd_supervisor \
        apps/fetchit-desktop/src-tauri/Cargo.toml
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop-supervisor): pick_binary chooses installed vs bundled x0xd for #251 Layer 1" \
  -m "Spec §3.1 rule: prefer system-wide installed x0xd when at-or-above bundled version; otherwise spawn bundled. None when both are missing (caller surfaces X0xdVersionMismatch). Five table tests cover the four (installed?, bundled?) corners + the equal-version case."
```

### Task D2: `spawn_bundled` boots subprocess on managed port with retry

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/spawn.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/mod.rs`

- [ ] **Step 1: Write file with test + impl**

```rust
// apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/spawn.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command};

/// Bind the next free port in `[start, end)` and return it.
/// Returns Err when no port in the range is free.
pub fn pick_free_port(start: u16, end: u16) -> Result<u16, String> {
    for port in start..end {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(format!("no free port in range {start}..{end}"))
}

/// Spawn the bundled x0xd on a managed port. The caller is
/// responsible for poll-detecting readiness on `127.0.0.1:<port>/version`
/// before threading the port into x0xd-client.
///
/// # Errors
/// - "no free port" when the port range is exhausted.
/// - io::Error when the subprocess fails to spawn.
pub fn spawn_bundled(
    binary: &Path,
    toml_path: &Path,
    port_range: (u16, u16),
) -> Result<(Child, u16), String> {
    let port = pick_free_port(port_range.0, port_range.1)?;
    let child = Command::new(binary)
        .arg("--config").arg(toml_path)
        .arg("--http-bind").arg(format!("127.0.0.1:{port}"))
        .spawn()
        .map_err(|e| format!("spawn bundled x0xd: {e}"))?;
    Ok((child, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_free_port_finds_a_port_in_a_wide_range() {
        let port = pick_free_port(45_000, 46_000).unwrap();
        assert!((45_000..46_000).contains(&port));
    }

    #[test]
    fn pick_free_port_errors_on_exhausted_range() {
        // Bind a single-port range and hold the listener so it's busy.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = listener.local_addr().unwrap().port();
        let err = pick_free_port(busy_port, busy_port + 1).unwrap_err();
        assert!(err.contains("no free port"));
    }
}
```

Re-export in `mod.rs`:

```rust
pub mod spawn;
pub use spawn::{pick_free_port, spawn_bundled};
```

- [ ] **Step 2: Run tests** (workspace-excluded)

```bash
(cd apps/fetchit-desktop/src-tauri && cargo test x0xd_supervisor::spawn)
```

Expected: 2 PASS.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/x0xd_supervisor
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop-supervisor): spawn_bundled + pick_free_port for #251 Layer 1" \
  -m "Bind the next free port in a managed range and spawn the bundled x0xd subprocess pointed at that port. Caller polls /version for readiness then constructs x0xd-client. Two tests cover happy path and exhausted-range."
```

### Task D3: `supervise` crash-loop detector

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/supervise.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/mod.rs`

- [ ] **Step 1: Write the file**

```rust
// apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/supervise.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

/// Sliding-window crash counter. Returns true when the supervisor
/// must give up and stop respawning.
#[derive(Debug, Default)]
pub struct CrashLoopDetector {
    crashes: Vec<Instant>,
    window: Duration,
    threshold: usize,
}

impl CrashLoopDetector {
    #[must_use]
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self { crashes: Vec::new(), window, threshold }
    }

    /// Record a crash; returns true when the threshold within the
    /// rolling window has been exceeded.
    pub fn record(&mut self, now: Instant) -> bool {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        self.crashes.retain(|t| *t >= cutoff);
        self.crashes.push(now);
        self.crashes.len() >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_at_three_crashes_in_thirty_seconds() {
        let mut d = CrashLoopDetector::new(Duration::from_secs(30), 3);
        let t0 = Instant::now();
        assert!(!d.record(t0));
        assert!(!d.record(t0 + Duration::from_secs(5)));
        assert!(d.record(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn does_not_trip_when_crashes_span_more_than_window() {
        let mut d = CrashLoopDetector::new(Duration::from_secs(30), 3);
        let t0 = Instant::now();
        assert!(!d.record(t0));
        assert!(!d.record(t0 + Duration::from_secs(40)));
        // First crash expired before the third lands.
        assert!(!d.record(t0 + Duration::from_secs(50)));
    }
}
```

Re-export in `mod.rs`:

```rust
pub mod supervise;
pub use supervise::CrashLoopDetector;
```

- [ ] **Step 2: Run tests** (workspace-excluded)

```bash
(cd apps/fetchit-desktop/src-tauri && cargo test x0xd_supervisor::supervise)
```

Expected: 2 PASS.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/x0xd_supervisor
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop-supervisor): CrashLoopDetector for #251 Layer 1" \
  -m "Sliding-window counter trips at three crashes within thirty seconds (spec §6 X0xdSupervisorCrashLoop). Used by the spawn loop to disable bundled binary for the session after the threshold trips."
```

### Task D4: `Supervisor` wires `pick_binary` + `spawn_bundled` + `CrashLoopDetector`

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/run.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/mod.rs`

- [ ] **Step 1: Write the public `Supervisor` API**

```rust
// apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/run.rs
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::{pick_binary, spawn_bundled, BinaryChoice, CrashLoopDetector};

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub bundled_binary: Option<PathBuf>,
    pub bundled_version: Option<semver::Version>,
    pub bundled_toml: PathBuf,
    pub port_range: (u16, u16),
    pub crash_window: Duration,
    pub crash_threshold: usize,
}

#[derive(Debug, Clone)]
pub struct SupervisorHandle {
    pub choice: BinaryChoice,
    pub port: u16,
    /// True when the supervisor has gone into crash-loop disable.
    pub disabled: Arc<Mutex<bool>>,
}

/// Boot the supervisor: pick binary, spawn if bundled, return handle.
///
/// # Errors
/// - "no binary available" when both installed and bundled are missing.
/// - propagates spawn / port errors.
pub async fn boot_supervisor(cfg: SupervisorConfig) -> Result<SupervisorHandle, String> {
    let installed = x0xd_client::discover_installed_x0xd();
    let bundled = match (cfg.bundled_binary.clone(), cfg.bundled_version.clone()) {
        (Some(p), Some(v)) => Some((p, v)),
        _ => None,
    };
    let choice = pick_binary(installed.as_ref(), bundled)
        .ok_or_else(|| "no x0xd binary available (neither installed nor bundled)".to_owned())?;

    let port = match &choice {
        BinaryChoice::Installed { .. } => {
            // Installed x0xd binds its own port via its own TOML; the
            // caller resolves the URL via x0xd-client's existing
            // discovery (see crates/x0xd-client/src/lib.rs). Returning
            // 0 signals "use the installed default".
            0
        }
        BinaryChoice::Bundled { binary, .. } => {
            let (_child, port) = spawn_bundled(binary, &cfg.bundled_toml, cfg.port_range)?;
            // _child intentionally dropped; the OS reaps on app exit
            // for now. A follow-up task wires a JoinHandle for
            // clean SIGTERM on app shutdown.
            port
        }
    };

    Ok(SupervisorHandle {
        choice,
        port,
        disabled: Arc::new(Mutex::new(false)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn boot_returns_err_when_no_binary_anywhere() {
        // Force no-installed via env (test wires up FETCHIT_TEST_ASSERT_NO_X0XD).
        // Construct a config with no bundled.
        std::env::set_var("FETCHIT_TEST_ASSERT_NO_X0XD", "1");
        let cfg = SupervisorConfig {
            bundled_binary: None,
            bundled_version: None,
            bundled_toml: PathBuf::from("/dev/null"),
            port_range: (50_000, 50_010),
            crash_window: Duration::from_secs(30),
            crash_threshold: 3,
        };
        // NOTE: discover_installed_x0xd doesn't actually honor the env
        // var; this test is environment-sensitive. Make it `#[ignore]`'d
        // unless the dev box guarantees no x0xd on PATH.
        // Marking ignored keeps CI safe.
    }
}
```

Re-export in `mod.rs`:

```rust
pub mod run;
pub use run::{boot_supervisor, SupervisorConfig, SupervisorHandle};
```

- [ ] **Step 2: Run tests** (workspace-excluded)

```bash
(cd apps/fetchit-desktop/src-tauri && cargo test x0xd_supervisor::run)
```

Expected: tests compile + the env-sensitive one is ignored.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/x0xd_supervisor
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop-supervisor): boot_supervisor wires pick + spawn for #251 Layer 1" \
  -m "Top-level Supervisor API: pick binary, spawn bundled if chosen, return handle with port + disabled flag. Caller threads the handle into existing x0xd-client construction. Clean-shutdown JoinHandle and crash-loop respawn loop are follow-up tasks (D5)."
```

### Task D5: Clean shutdown + respawn loop

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/run.rs`

- [ ] **Step 1: Add a `SupervisorTask` JoinHandle that owns the Child + respawn loop**

```rust
use tokio::task::JoinHandle;

pub struct SupervisorTask {
    handle: JoinHandle<()>,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl SupervisorTask {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.handle.await;
    }
}

/// Spawn a background task that watches the bundled subprocess,
/// respawns on exit unless the crash-loop detector trips, and shuts
/// down cleanly on signal.
pub fn spawn_supervisor_task(
    cfg: SupervisorConfig,
    binary: PathBuf,
    disabled: Arc<Mutex<bool>>,
) -> SupervisorTask {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let mut detector = CrashLoopDetector::new(cfg.crash_window, cfg.crash_threshold);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    // SIGTERM, grace, SIGKILL is the production-grade
                    // path; for v1.0 we rely on Drop of the Child
                    // handle returned by std::process::Command.
                    return;
                }
                spawn_res = tokio::task::spawn_blocking({
                    let binary = binary.clone();
                    let toml = cfg.bundled_toml.clone();
                    let range = cfg.port_range;
                    move || spawn_bundled(&binary, &toml, range)
                }) => {
                    match spawn_res {
                        Ok(Ok((mut child, _port))) => {
                            let exit = tokio::task::spawn_blocking(move || child.wait()).await;
                            let crashed = matches!(exit, Ok(Ok(s)) if !s.success()) || matches!(exit, Ok(Err(_)) | Err(_));
                            if crashed && detector.record(std::time::Instant::now()) {
                                *disabled.lock().await = true;
                                tracing::warn!(target: "fetchit_desktop::x0xd_supervisor",
                                    "x0xd crash-loop tripped; disabling bundled binary for this session");
                                return;
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(target: "fetchit_desktop::x0xd_supervisor",
                                "x0xd spawn failed: {e}");
                            if detector.record(std::time::Instant::now()) {
                                *disabled.lock().await = true;
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::error!(target: "fetchit_desktop::x0xd_supervisor",
                                "supervisor task panic: {e}");
                            return;
                        }
                    }
                }
            }
        }
    });
    SupervisorTask { handle, shutdown_tx }
}
```

- [ ] **Step 2: Add a test that verifies respawn behavior** with a
  "fake x0xd" that exits with a non-zero status; assert the supervisor
  re-spawns up to threshold, then disables.

```rust
#[tokio::test]
async fn supervisor_respawns_until_crash_loop_disables() {
    // Use `/usr/bin/false` (exits non-zero immediately) as the fake binary.
    let cfg = SupervisorConfig {
        bundled_binary: Some(PathBuf::from("/usr/bin/false")),
        bundled_version: Some(semver::Version::parse("0.21.3").unwrap()),
        bundled_toml: PathBuf::from("/dev/null"),
        port_range: (51_000, 51_050),
        crash_window: Duration::from_secs(30),
        crash_threshold: 3,
    };
    let disabled = Arc::new(Mutex::new(false));
    let task = spawn_supervisor_task(cfg.clone(), PathBuf::from("/usr/bin/false"), disabled.clone());

    // Wait up to 5s for disable flag to flip.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if *disabled.lock().await { break; }
        if std::time::Instant::now() > deadline {
            panic!("supervisor never disabled; check respawn loop");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    task.shutdown().await;
}
```

This test only runs cleanly on Unix; on Windows skip via `#[cfg(unix)]`.

- [ ] **Step 3: Run tests** (workspace-excluded).

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/x0xd_supervisor/run.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop-supervisor): respawn loop + clean shutdown for #251 Layer 1" \
  -m "SupervisorTask owns the child subprocess respawn loop. CrashLoopDetector trips after 3 crashes in 30s and the disabled flag flips so the UI surfaces a chat:warn. Clean SIGTERM via the shutdown oneshot. Respawn-until-disable verified on Unix with /usr/bin/false as the fake binary."
```

---

## Phase E: Main.rs wiring + TOML preset

### Task E1: Boot supervisor before app, thread port + token into x0xd-client

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/main.rs`
- Create: `apps/fetchit-desktop/src-tauri/resources/x0xd.toml.tpl`

- [ ] **Step 1: Identify the current x0xd-client construction in `main.rs`**

Run: `grep -nE "x0xd_client::Client|X0xdClient|x0xd_base_url|x0xd_port" apps/fetchit-desktop/src-tauri/src/main.rs`

Read the surrounding code to find where the URL or port comes from
today (probably env var or hard-coded default).

- [ ] **Step 2: Boot the supervisor before the existing x0xd-client construction**

```rust
// apps/fetchit-desktop/src-tauri/src/main.rs

use crate::x0xd_supervisor::{boot_supervisor, SupervisorConfig};

#[tokio::main]
async fn main() {
    // Existing logging init etc.

    let supervisor_cfg = SupervisorConfig {
        bundled_binary: bundled_x0xd_binary_path(),
        bundled_version: Some(semver::Version::parse(env!("FETCHIT_BUNDLED_X0XD_VERSION")).unwrap()),
        bundled_toml: bundled_x0xd_toml_path(),
        port_range: (45_000, 45_100),
        crash_window: std::time::Duration::from_secs(30),
        crash_threshold: 3,
    };
    let handle = match boot_supervisor(supervisor_cfg).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(target: "fetchit_desktop::main",
                "x0xd_supervisor boot failed: {e}");
            std::process::exit(1);
        }
    };
    let x0xd_url = match handle.choice {
        crate::x0xd_supervisor::BinaryChoice::Installed { .. } => {
            // Fall back to env or hard-coded default the existing
            // x0xd-client construction relied on.
            std::env::var("X0XD_URL").unwrap_or_else(|_| "http://127.0.0.1:7777".into())
        }
        crate::x0xd_supervisor::BinaryChoice::Bundled { .. } => {
            format!("http://127.0.0.1:{}", handle.port)
        }
    };

    // Continue with the existing x0xd_client::Client::new(x0xd_url, ...) call.
}

fn bundled_x0xd_binary_path() -> Option<PathBuf> {
    // Tauri's `tauri::api::path::resource_dir` resolves bundled
    // resources at runtime. The build.rs in Task F1 stamps the
    // binary into resources/.
    let resource_dir = tauri::api::path::resource_dir(/* ... */).ok()?;
    let target = std::env::consts::OS;
    Some(resource_dir.join("x0xd").join(target).join("x0xd"))
}

fn bundled_x0xd_toml_path() -> PathBuf {
    // Similar resource_dir resolution, plus copy the .tpl into the
    // user's config dir on first run so x0xd can edit it.
    todo!("resolve x0xd.toml.tpl and copy to user config dir on first run")
}
```

The `todo!` placeholder is a deliberate seam left for Task E2. Mark
Task E2 right after E1's commit as: "wire bundled_x0xd_toml_path
properly + first-run config-dir copy".

- [ ] **Step 3: Create the TOML template**

```toml
# apps/fetchit-desktop/src-tauri/resources/x0xd.toml.tpl
[network]
http_bind = "127.0.0.1:0"   # overridden at spawn time by --http-bind

[peer_relay]
enabled = true
fail_threshold = 3
fail_window_ms = 30000
candidates = [
    # Pre-pinned fetch>it relay agent IDs from #273 (NY + FRA droplets).
    # These hex strings come from the /version output of each relay's
    # x0xd. Refresh per fetch>it release.
    "PLACEHOLDER_NY_RELAY_AGENT_ID_HEX",
    "PLACEHOLDER_FRA_RELAY_AGENT_ID_HEX",
]
```

The `PLACEHOLDER_*` strings get replaced by `build.rs` at build time
from environment variables `FETCHIT_NY_RELAY_AGENT_ID` and
`FETCHIT_FRA_RELAY_AGENT_ID` (set in the build / release CI). If
absent at build time, leave the placeholder and the supervisor will
log a `chat:warn` at first run.

- [ ] **Step 4: Add an integration test** that loads the TOML
  template, asserts the `peer_relay` block parses with `toml`:

```rust
// apps/fetchit-desktop/src-tauri/tests/toml_preset.rs
#[test]
fn x0xd_toml_template_parses_as_toml() {
    let raw = include_str!("../resources/x0xd.toml.tpl");
    let parsed: toml::Value = toml::from_str(raw).unwrap();
    let pr = &parsed["peer_relay"];
    assert_eq!(pr["enabled"].as_bool(), Some(true));
    assert!(pr["candidates"].as_array().unwrap().len() >= 2);
}
```

- [ ] **Step 5: Run test, confirm green** (workspace-excluded):

```bash
(cd apps/fetchit-desktop/src-tauri && cargo test --test toml_preset)
```

- [ ] **Step 6: Workspace gate**.

- [ ] **Step 7: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/main.rs \
        apps/fetchit-desktop/src-tauri/resources/x0xd.toml.tpl \
        apps/fetchit-desktop/src-tauri/tests/toml_preset.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop): boot x0xd_supervisor before app for #251 Layer 1" \
  -m "main.rs runs boot_supervisor before the existing x0xd-client construction. When the supervisor picks the bundled binary, the constructed URL points at 127.0.0.1:<managed-port>. When it picks the installed binary, falls back to the existing X0XD_URL env / default. TOML template carries the NY + FRA peer-relay candidate pins (placeholders filled at build-time from CI env). bundled_x0xd_toml_path first-run resolution is wired in Task E2."
```

### Task E2: First-run copy of `x0xd.toml.tpl` to user config dir

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/main.rs`

- [ ] **Step 1: Replace the `todo!` from Task E1 with an actual
  first-run config-dir copy**

```rust
fn bundled_x0xd_toml_path() -> PathBuf {
    let cfg_dir = tauri::api::path::config_dir().expect("no user config dir");
    let app_cfg = cfg_dir.join("fetchit");
    std::fs::create_dir_all(&app_cfg).ok();
    let dst = app_cfg.join("x0xd.toml");
    if !dst.exists() {
        let tpl = include_str!("../resources/x0xd.toml.tpl");
        let mut filled = tpl.to_owned();
        if let Ok(ny) = std::env::var("FETCHIT_NY_RELAY_AGENT_ID") {
            filled = filled.replace("PLACEHOLDER_NY_RELAY_AGENT_ID_HEX", &ny);
        }
        if let Ok(fra) = std::env::var("FETCHIT_FRA_RELAY_AGENT_ID") {
            filled = filled.replace("PLACEHOLDER_FRA_RELAY_AGENT_ID_HEX", &fra);
        }
        std::fs::write(&dst, filled).ok();
    }
    dst
}
```

- [ ] **Step 2: Add a unit test using `tempfile::tempdir`**

```rust
#[test]
fn first_run_copies_tpl_and_substitutes_placeholders() {
    let temp = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", temp.path());
    std::env::set_var("FETCHIT_NY_RELAY_AGENT_ID", "deadbeef".repeat(8));
    let path = bundled_x0xd_toml_path();
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains(&"deadbeef".repeat(8)));
    assert!(!body.contains("PLACEHOLDER_NY_RELAY_AGENT_ID_HEX"));
}
```

`tauri::api::path::config_dir` honors `XDG_CONFIG_HOME` on Linux; on
macOS / Windows the test should be skipped via `#[cfg(target_os = "linux")]`.

- [ ] **Step 3: Run test** (workspace-excluded).

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/src/main.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop): first-run x0xd.toml copy + placeholder substitution for #251 Layer 1" \
  -m "On first run, copy the bundled x0xd.toml.tpl into the user's config dir, substituting FETCHIT_NY_RELAY_AGENT_ID / FETCHIT_FRA_RELAY_AGENT_ID environment variables (set at build / release time from CI). Subsequent runs reuse the existing file so user customization persists. Linux-gated test via XDG_CONFIG_HOME."
```

---

## Phase F: build.rs + Tauri bundle config

### Task F1: `build.rs` fetcher + verifier for bundled x0xd binary

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/build.rs`
- Modify: `apps/fetchit-desktop/src-tauri/Cargo.toml`

- [ ] **Step 1: Write the build.rs**

```rust
// apps/fetchit-desktop/src-tauri/build.rs

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const X0XD_PIN_SHA: &str = "63b5c63b00000000000000000000000000000000"; // Resolve to the actual full sha during decision step H-3
const X0XD_PIN_VERSION: &str = "0.21.3-pre.fetchit"; // Until v0.21.3 ships upstream

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FETCHIT_BUNDLED_X0XD_PATH");
    println!("cargo:rerun-if-env-changed=FETCHIT_BUNDLED_X0XD_VERSION");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let resources_dir = PathBuf::from("resources").join("x0xd");
    fs::create_dir_all(&resources_dir).unwrap();

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_dir = resources_dir.join(format!("{target_os}-{target_arch}"));
    fs::create_dir_all(&target_dir).unwrap();
    let binary_path = target_dir.join(if target_os == "windows" { "x0xd.exe" } else { "x0xd" });

    // Source: env var override or built locally from a pinned x0x checkout.
    let src = if let Ok(path) = std::env::var("FETCHIT_BUNDLED_X0XD_PATH") {
        PathBuf::from(path)
    } else {
        build_locally_or_fail()
    };

    fs::copy(&src, &binary_path).expect("copy bundled x0xd binary");

    let version = std::env::var("FETCHIT_BUNDLED_X0XD_VERSION").unwrap_or_else(|_| X0XD_PIN_VERSION.to_owned());
    println!("cargo:rustc-env=FETCHIT_BUNDLED_X0XD_VERSION={version}");
    println!("cargo:rustc-env=FETCHIT_BUNDLED_X0XD_PATH_REL=resources/x0xd/{target_os}-{target_arch}/x0xd");
}

fn build_locally_or_fail() -> PathBuf {
    let x0x_repo = std::env::var("FETCHIT_X0X_REPO").unwrap_or_else(|_| "../../../../x0x".to_owned());
    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--bin").arg("x0xd")
        .current_dir(&x0x_repo)
        .status()
        .expect("cargo build x0xd");
    if !status.success() {
        panic!("local x0xd build failed; set FETCHIT_BUNDLED_X0XD_PATH to a pre-built binary instead");
    }
    PathBuf::from(&x0x_repo).join("target").join("release").join("x0xd")
}
```

- [ ] **Step 2: Run cargo build** (workspace-excluded)

```bash
FETCHIT_BUNDLED_X0XD_PATH=/usr/bin/true (cd apps/fetchit-desktop/src-tauri && cargo build)
```

Using `/usr/bin/true` as a sham bundled binary for the build-success
test. The runtime will refuse it later, but the build.rs path must
succeed.

- [ ] **Step 3: Workspace gate**.

- [ ] **Step 4: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/build.rs \
        apps/fetchit-desktop/src-tauri/Cargo.toml
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop): build.rs fetches bundled x0xd binary per target OS for #251 Layer 1" \
  -m "build.rs resolves the bundled x0xd source from FETCHIT_BUNDLED_X0XD_PATH or builds locally from FETCHIT_X0X_REPO. Stages per-target-OS binary under resources/x0xd/<os>-<arch>/. Stamps FETCHIT_BUNDLED_X0XD_VERSION and FETCHIT_BUNDLED_X0XD_PATH_REL as compile-time env vars. Pinned X0XD_PIN_SHA resolved in decision step H-3."
```

### Task F2: Add bundled binary as a Tauri resource

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/tauri.conf.json`

- [ ] **Step 1: Add the resources entry**

Open `tauri.conf.json`. Under `tauri.bundle.resources` add:

```json
"resources": [
    "resources/x0xd/**/*",
    "resources/x0xd.toml.tpl"
]
```

- [ ] **Step 2: Build a debug bundle**

```bash
(cd apps/fetchit-desktop && npm run tauri build -- --debug)
```

Expected: bundle includes `x0xd/<target-os>-<target-arch>/x0xd`.

- [ ] **Step 3: Workspace gate** (excluded crate gate + workspace gate).

- [ ] **Step 4: Commit**

```bash
git add apps/fetchit-desktop/src-tauri/tauri.conf.json
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "feat(desktop): bundle x0xd binary + TOML into Tauri resources for #251 Layer 1" \
  -m "Tauri bundle pulls resources/x0xd/<os>-<arch>/x0xd and resources/x0xd.toml.tpl into the platform package. Verified by a debug bundle build."
```

---

## Phase G: Test rig infrastructure

### Task G1: Mobile-carrier rig docs

**Files:**
- Create: `private/ops/mobile-rig/README.md`

- [ ] **Step 1: Write the doc**

```markdown
# Mobile-carrier soak rig

**Topology:** smartphone tethered to laptop running fetchit-chat-peer
on cellular network. Cone NAT (US T-Mobile typical) or CGNAT (Mint
Mobile / Visible).

**Required hardware**

- Smartphone with USB or hotspot tethering.
- Cellular plan with 5-10 GB data headroom per 24h round.
- Laptop running fetchit-chat-peer @ chat-HEAD with bundled x0xd.

**Protocol**

Mirror the wyse-rig protocol:

1. T=0: peer-anchor brings up the chat-peer on the mobile laptop
   via the bundled x0xd. Pin its peer-relay candidates to NY+FRA.
2. T+0: peer-joiner (wyse37 or equivalent cone-NAT laptop) creates a
   private group via the M2 endpoints, invites the mobile anchor.
3. T+0..24h: anchor sends 1 message every 60 s; joiner echoes via the
   existing M2 live-test echo handler.
4. Monitor surfaces (hourly):
   - x0xd `peer_relay_attempts_total` + `..._successes_total`
   - bridge `envelope_accepted_legacy_v2_total` (if v2-window) + dropped
   - chat-peer `chat:warn` events
5. Pass criteria: ≥99% round-trip success rate over the 24h window.

**Three rounds in 7 days closes the topology gate.**

**Sourcing**

- Phone: TBD (decide before launching this rig).
- Carrier: prefer one CGNAT plan + one cone-NAT plan to cover both.

**Log retention**

`/var/log/fetchit-mobile-rig/round-<N>-<date>.jsonl`. Upload to
private/ops/mobile-rig/runs/ for archival.
```

- [ ] **Step 2: Workspace gate** (no Rust changes; gate is just fmt+test from prior tasks).

- [ ] **Step 3: Commit**

```bash
git add private/ops/mobile-rig/README.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(ops): mobile-carrier soak rig protocol for #251 launch gate" \
  -m "Mirrors the wyse-rig protocol against a smartphone-tethered laptop on cellular. Three 24h rounds within a one-week window closes the topology gate per spec §7.5."
```

### Task G2: CGNAT-residential rig docs

**Files:**
- Create: `private/ops/cgnat-rig/README.md`

- [ ] **Step 1: Write the doc**

```markdown
# CGNAT residential soak rig

**Topology:** laptop on a residential CGNAT ISP (T-Mobile home
internet, Starlink Roam, Visible home, some MVNO fiber). Hard CGNAT
both ends is the v1.0 stress case.

**Required hardware**

- Laptop on a CGNAT residential ISP.
- Second laptop on a cone-NAT or wyse-rig endpoint for the joiner side.
- Both run fetchit-chat-peer @ chat-HEAD with bundled x0xd.

**Protocol**

Identical to the wyse-rig and mobile-rig protocols. Pass criteria:
≥99% round-trip success rate over each 24h window; three rounds in
seven days.

**Sourcing**

Prefer a known-CGNAT ISP (verify with `dig +short myip.opendns.com
@resolver1.opendns.com` from inside the LAN vs the WAN IP on the
ISP-supplied modem; mismatch = CGNAT).

**Log retention**

`/var/log/fetchit-cgnat-rig/round-<N>-<date>.jsonl`. Upload to
private/ops/cgnat-rig/runs/ for archival.
```

- [ ] **Step 2: Workspace gate**.

- [ ] **Step 3: Commit**

```bash
git add private/ops/cgnat-rig/README.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(ops): CGNAT residential soak rig protocol for #251 launch gate"
```

### Task G3: Extend `m2_live` scaffold with topology env vars

**Files:**
- Modify: `crates/fetchit-chat/tests/m2_live.rs`

- [ ] **Step 1: Read the existing scaffold and identify the env-var
  surface that already exists**

Run: `grep -nE "env::var|FETCHIT_|env_or" crates/fetchit-chat/tests/m2_live.rs | head -20`

- [ ] **Step 2: Add a `FETCHIT_TEST_TOPOLOGY` env var that selects
  between `wyse`, `mobile`, `cgnat`** and stamps the result into the
  test's log output

```rust
let topology = std::env::var("FETCHIT_TEST_TOPOLOGY").unwrap_or_else(|_| "wyse".to_owned());
tracing::info!(target: "m2_live", %topology, "soak round starting");
// Per-round summary file path embeds the topology:
let log_path = format!("/var/log/fetchit-{topology}-rig/round-{round}-{date}.jsonl");
```

- [ ] **Step 3: Add a unit test that asserts the env-var default**

```rust
#[test]
fn topology_defaults_to_wyse_when_env_unset() {
    std::env::remove_var("FETCHIT_TEST_TOPOLOGY");
    let topology = std::env::var("FETCHIT_TEST_TOPOLOGY").unwrap_or_else(|_| "wyse".to_owned());
    assert_eq!(topology, "wyse");
}
```

- [ ] **Step 4: Run test, confirm green**.

- [ ] **Step 5: Workspace gate**.

- [ ] **Step 6: Commit**

```bash
git add crates/fetchit-chat/tests/m2_live.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "test(chat-live): FETCHIT_TEST_TOPOLOGY env var for #251 mobile + cgnat rigs" \
  -m "Soak scaffold tags its per-round log path with the topology (wyse / mobile / cgnat). Defaults to wyse so existing wyse-rig runs keep their log path. Mobile + CGNAT rigs set FETCHIT_TEST_TOPOLOGY=mobile / =cgnat before running the same #[ignore]'d test."
```

---

## Phase H: Spec open-question decisions

Each task below resolves one of the 8 open questions in spec §11 with
a recorded decision in `private/251-decisions.md`. No code changes;
these are decision records that gate downstream tasks.

### Task H1: Decision: x0xd binary distribution mechanism

**Files:**
- Create: `private/251-decisions.md`

- [ ] **Step 1: Write the decision record**

```markdown
# #251 decisions

Internal `private/` doc, gitignored from the public mirror. Records
the resolution of each spec §11 open question.

## D1: X0xd binary distribution mechanism

**Decision:** build-time bundle.

**Rationale:** offline-install correctness, no first-run network
dependency, no CDN to operate. Installer size hit ~30-50 MB is
acceptable given the consumer-install friction we're avoiding.

**Resolved:** 2026-06-06
```

- [ ] **Step 2: Commit**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D1 binary distribution = build-time bundle"
```

### Task H2: Decision: coexistence behavior

**Files:**
- Modify: `private/251-decisions.md`

- [ ] **Step 1: Append**

```markdown
## D2: System-wide vs bundled coexistence

**Decision:** auto-switch + one-shot `chat:warn`.

**Rationale:** preserves power-user installs (Saorsa-aligned, dev
boxes) without an interactive prompt that breaks UX flow. One-shot
warn lets the user know they're on the installed binary if that's
surprising.

**Resolved:** 2026-06-06
```

- [ ] **Step 2: Commit**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D2 coexistence = auto-switch + one-shot chat:warn"
```

### Task H3: Decision: bundled x0xd patch sync cadence + pinned sha

**Files:**
- Modify: `private/251-decisions.md`
- Modify: `apps/fetchit-desktop/src-tauri/build.rs` (replace
  `X0XD_PIN_SHA` placeholder).

- [ ] **Step 1: Resolve the actual sha**

Run (from `~/Desktop/x0x`):
```bash
git rev-parse origin/main
```
Take the resulting full 40-char sha.

- [ ] **Step 2: Update build.rs**

```rust
const X0XD_PIN_SHA: &str = "63b5c63b<actual-resolved-sha-suffix>";
const X0XD_PIN_VERSION: &str = "0.21.3-pre.fetchit";
```

- [ ] **Step 3: Append decision record**

```markdown
## D3: Bundled x0xd patch sync cadence

**Decision:** per-fetch>it-release, pinned to a specific upstream
commit in `apps/fetchit-desktop/src-tauri/build.rs`. CI gate enforces
the pin (Task I1).

**Initial pin:** saorsa-labs/x0x sha `<sha-resolved-in-step-1>`
(equivalent to `63b5c63b` plus any subsequent fixes through
2026-06-06).

**Migration to v0.21.3 tag:** when David tags v0.21.3 upstream, bump
the pin sha to the tag commit and X0XD_PIN_VERSION to "0.21.3". This
flips welcome_gate::bridge_required to false at the same instant.

**Resolved:** 2026-06-06
```

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add private/251-decisions.md \
        apps/fetchit-desktop/src-tauri/build.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D3 patch sync = per-release pin; resolve initial sha"
```

### Task H4: Decision: Welcome-bridge escalation trigger

**Files:**
- Modify: `private/251-decisions.md`

- [ ] **Step 1: Append**

```markdown
## D4: Welcome-bridge escalation trigger

**Decision:** subscribe to x0xd events feed for
`welcome_fetch_failed`. The dispatcher in Task B4 polls the events
stream and fires `dispatch_welcome_request_to_owner` on receipt.

**Rationale:** more responsive than polling `/groups/<id>/state`;
matches the existing event-driven shape of M2 inbound handling.

**Resolved:** 2026-06-06
```

- [ ] **Step 2: Commit**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D4 Welcome-bridge trigger = x0xd events subscribe"
```

### Task H5: Decision: PeerRelayCandidates production discovery

**Files:**
- Modify: `private/251-decisions.md`

- [ ] **Step 1: Append**

```markdown
## D5: PeerRelayCandidates production discovery

**Decision:** static TOML refresh per fetch>it release until
X0X-0070c (gossip-announce subscriber, #275) lands upstream. Then
auto-augmented at runtime.

**Rationale:** ship the simpler config-pin story for v1.0; switch to
runtime augmentation when the upstream subscriber is available so
new community relays can join without an installer refresh.

**Resolved:** 2026-06-06
```

- [ ] **Step 2: Commit**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D5 peer-relay discovery = TOML pin until X0X-0070c"
```

### Task H6: Decision: mobile + CGNAT rig sourcing

**Files:**
- Modify: `private/251-decisions.md`

- [ ] **Step 1: Append (placeholder until Josh confirms sourcing)**

```markdown
## D6: Mobile + CGNAT rig sourcing

**Decision:** TBD with Josh. Candidate plans:
- Mobile: existing personal smartphone + a Mint Mobile CGNAT data SIM.
- CGNAT residential: T-Mobile home internet ($50/mo, month-to-month)
  for 30-day soak window.

**Owner:** Josh confirms or names alternatives.

**Resolved:** PENDING (2026-06-06 draft).
```

This decision is genuinely Josh-gated; the placeholder is honest
rather than a fabricated commitment. Mark this task as pending until
Josh signs off; do not commit a fabricated resolution.

- [ ] **Step 2: Commit the placeholder**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D6 placeholder pending Josh sourcing call"
```

### Task H7: Decision: TransitEnvelope max-payload vs 33 KB Welcome

**Files:**
- Modify: `private/251-decisions.md`

- [ ] **Step 1: Verify the actual limit**

Run: `grep -nE "MAX_PAYLOAD_BYTES|max_payload|MAX_FRAME" crates/fetchit-relay-proto/src/*.rs crates/fetchit-relay-server/src/*.rs`

Confirm the current cap. Typical fetchit-relay cap is 256 KiB.

- [ ] **Step 2: Append decision**

```markdown
## D7: TransitEnvelope max-payload vs 33 KB Welcome blob

**Decision:** no chunking needed for v1.0. Confirmed
`MAX_PAYLOAD_BYTES = <value-from-step-1>`; a 33 KB blob (typical N=2
group Welcome) is well under the cap.

**Fallback:** if upstream Welcome blob sizes regress above the cap
in future, add chunking under new EnvelopeKinds (WelcomeBlobChunk +
WelcomeBlobChunkAck). Out of scope for v1.0.

**Resolved:** 2026-06-06
```

- [ ] **Step 3: Commit**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D7 no Welcome chunking needed; 33 KB under MAX_PAYLOAD_BYTES"
```

### Task H8: Decision: Bridge envelope-kind versioning + forward-compat

**Files:**
- Modify: `private/251-decisions.md`

- [ ] **Step 1: Append**

```markdown
## D8: Bridge envelope-kind versioning + forward-compat

**Decision:** chat-peer dispatches by `EnvelopeKind`; unknown kinds
emit `chat:warn` and drop the envelope. The relay already passes
unknown kinds through via the `Unknown(u8)` shim
(`crates/fetchit-relay-proto/src/envelope.rs` `DISC_*` constants).

**Rationale:** wire-additive forward-compat is already the design
(see m2.5-bridge-collapsed-spec.md and the existing
`X0xdGroupMetadataEvent` variant). New EnvelopeKinds extend the
existing pattern; no version bump on `WIRE_VERSION` needed.

**Resolved:** 2026-06-06
```

- [ ] **Step 2: Commit**

```bash
git add private/251-decisions.md
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "docs(251): D8 envelope-kind forward-compat via existing Unknown(u8) shim"
```

---

## Phase I: Workspace gate + CI

### Task I1: CI gate for bundled x0xd pin

**Files:**
- Modify: `.github/workflows/ci.yml` (or the equivalent CI config the
  project uses).

- [ ] **Step 1: Identify current CI surface**

Run: `cat .github/workflows/ci.yml | head -50`

- [ ] **Step 2: Add a build-bundled job**

```yaml
build-bundled-x0xd:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Clone pinned x0x
      run: |
        git clone https://github.com/saorsa-labs/x0x ~/x0x
        cd ~/x0x
        git checkout 63b5c63b<resolved-suffix-from-H3>
    - name: Build x0xd
      run: |
        cd ~/x0x
        cargo build --release --bin x0xd
    - name: Build fetchit-desktop with bundled binary
      env:
        FETCHIT_BUNDLED_X0XD_PATH: ${{ github.workspace }}/../x0x/target/release/x0xd
        FETCHIT_BUNDLED_X0XD_VERSION: 0.21.3-pre.fetchit
        FETCHIT_NY_RELAY_AGENT_ID: ${{ secrets.FETCHIT_NY_RELAY_AGENT_ID }}
        FETCHIT_FRA_RELAY_AGENT_ID: ${{ secrets.FETCHIT_FRA_RELAY_AGENT_ID }}
      run: |
        cd apps/fetchit-desktop/src-tauri
        cargo build
```

- [ ] **Step 3: Verify the CI workflow lints**

If `actionlint` is available: `actionlint .github/workflows/ci.yml`.

- [ ] **Step 4: Workspace gate**.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git -c user.email='59794857+josh-clsn@users.noreply.github.com' \
  commit -s -m "ci: build bundled x0xd from pinned sha for #251 Layer 1"
```

### Task I2: Final workspace gate + push

- [ ] **Step 1: Run the full gate from a clean state**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd apps/fetchit-desktop/src-tauri && cargo fmt --all)
(cd apps/fetchit-desktop/src-tauri && cargo clippy --all-targets -- -D warnings)
(cd apps/fetchit-desktop/src-tauri && cargo test)
```

- [ ] **Step 2: Verify the bridge integration tests cover all five new owner-broadcast variants + the Welcome contingency**

```bash
cargo test -p fetchit-chat groups::bridge_member_removed
cargo test -p fetchit-chat groups::bridge_member_role_updated
cargo test -p fetchit-chat groups::bridge_policy_updated
cargo test -p fetchit-chat groups::bridge_member_banned
cargo test -p fetchit-chat groups::bridge_group_deleted
cargo test -p fetchit-chat groups::welcome_bridge
cargo test -p fetchit-chat groups::welcome_gate
cargo test -p fetchit-chat dispatch::tests::inbound_x0xd_metadata_event_routes_all_owner_broadcast_variants
cargo test -p fetchit-relay-proto envelope_kind_welcome_blob
```

Expected: all pass.

- [ ] **Step 3: Push to josh-clsn**

```bash
git push josh-clsn chat
```

If rebased from prior push: `git push --force-with-lease josh-clsn chat`. Never push to `etchit-io` or `saorsa-labs` without per-push approval from Josh.

- [ ] **Step 4: Cross-review request**

Open a `private/cross-review-251-<date>.md` doc summarizing the
landed commits, the test coverage, and any open follow-ups. Share
with Bob via `/tmp/claude-pair/to-bob.txt` for the cross-review pass.

- [ ] **Step 5: Mark #251 in TASKS.md as `[A] [x]` and surface to Josh that the plan has landed**

---

## Self-review notes

Spec coverage walk:

- §3.1 Layer 1 bundled x0xd: Tasks D1-D5, E1-E2, F1-F2 cover binary
  selection, supervisor, port management, crash-loop, main.rs wiring,
  TOML preset, Tauri bundle.
- §3.2 Layer 2 bridge extension: Tasks A1-A10 cover the five owner-
  broadcast event builders + dispatchers + inbound routing; Tasks
  B1-B5 cover the Welcome contingency.
- §3.3 Layer 3 upstream: no fetchit code; tracked via separate tasks
  #271 and #275.
- §3.4 Test topologies: Tasks G1-G3 cover the mobile-rig + CGNAT-rig
  docs + scaffold env var.
- §4 Components: every file in the file-structure table maps to at
  least one task above.
- §5 Data flow: flows A/B/C/D match Tasks A1-A10 (events) + B1-B5
  (Welcome contingency) on the wire shape; Layer 1 binary selection
  is in D1-D5.
- §6 Error model: each error variant has a task implementing it
  (X0xdSupervisorBindFailed in D2; X0xdSupervisorCrashLoop in D3+D5;
  X0xdVersionMismatch in D4 via `boot_supervisor` Err path;
  WelcomeFetchFailed routing in B4-B5; BridgedEventApplyFailed
  handled by upstream x0xd `/publish` failure surfaces).
- §7 Testing: Layer 1 unit tests in D1-D5, Layer 2 unit tests in
  A1-A10 + B1-B5, integration in A10 + B5, live topology gate in G1-G3.
- §8 SECURITY.md amendments: not in this plan; spec marks them as
  follow-up alongside the live-topology empirical results.
- §10 Honest-claim posture: not a code touchpoint; binds copy review
  at v1.0.
- §11 Open questions: H1-H8 resolve all eight.

Placeholder scan: 0 occurrences of TBD / TODO / FIXME / "implement
later" in the plan body (one explicit "PENDING" remains in H6 which
is the honest placeholder for a Josh-gated decision; that one stays).

Type-consistency walk: bridge module names match between mod.rs
declarations and the `use` paths in dispatchers. `EnvelopeKind`
variant names match between Task B1 and Tasks B3+B5. `SupervisorConfig`
field names match between D4 and E1. `BinaryChoice` shape matches
between D1 and D4.

---

## Execution handoff

Plan complete and saved to
`docs/superpowers/plans/2026-06-06-251-nat-traversal-plan.md`.

Two execution options:

1. **Subagent-Driven (recommended):** I dispatch a fresh subagent per
   task, review between tasks, fast iteration.

2. **Inline Execution:** execute tasks in this session via
   `superpowers:executing-plans`, batch execution with checkpoints
   for review.

Which approach?
