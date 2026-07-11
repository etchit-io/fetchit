# #297 Lane A: Warm Epoch-Recovery CommitSource + CommitApplier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Light up the warm (commits-since-N) epoch-recovery path so a group member that fell behind the MLS epoch catches up by pulling durable Commit/JoinResult records from the relay group-log and applying them through x0xd's signature-verifying apply endpoints, instead of staying `Reconnecting`.

**Architecture:** The recovery driver, watchdog, keyed-status probe, cold-path delegation, cursor store, and status broadcast are already built and live (`crates/fetchit-chat/src/groups/epoch_recovery/`). Two seams in `Client::recover_group_once` are inert placeholders: `DeferredSource` (a `CommitSource`) and `DeferredApplier` (a `CommitApplier`). This plan replaces them with production impls backed by the relay group-log transport (`log_fetch`) and the x0xd apply endpoints (`apply_metadata_event` / `apply_join_result`), routes the two through new `RelaySet`/`RelayTransport` passthroughs, and (Bob-gated) adds the producer-side `log_append` so the log has records to serve. The routing decisions (wire→record mapping, which apply endpoint per kind) are extracted as pure functions so the security-critical logic is unit-tested without network.

**Tech Stack:** Rust (tokio async), `fetchit-chat`, `fetchit-relay-client`, `fetchit-relay-proto`, `x0xd-client`; base64 `general_purpose::STANDARD`; `hex`.

## Global Constraints

- Workspace lints are hard: `unsafe_code = "forbid"`, `missing_docs = "warn"` (every new public item carries rustdoc), and clippy `pedantic` with `unwrap_used` / `expect_used` / `panic` / `todo` / `dbg_macro` all warn. No `unwrap()`/`expect()`/`panic!` outside `#[cfg(test)]`.
- Per-task gate (all three green before commit): `cargo test -p fetchit-chat && cargo test -p fetchit-relay-client` and `cargo clippy -p fetchit-chat -p fetchit-relay-client --all-targets -- -D warnings`.
- SECURITY-CRITICAL: the applier feeds relay-fetched bytes into local MLS state. It MUST go only through `SecureGroupsEndpoint::apply_metadata_event` / `apply_join_result`, which re-run full membership authority (ML-DSA signature + single-use invite-secret + inviter-gate) daemon-side. NEVER add a bypass, never trust the relay-stamped `author` as authority (it is a routing hint; authority lives in the ML-DSA-verified `committed_by` inside the payload).
- DCO sign-off on every commit (`git commit -s`). No em-dashes in commit messages or code comments. No AI co-author trailer.
- Docs track code: update the stale `DEFERRED` doc-comments (`client.rs:1800-1804` and `epoch_recovery/mod.rs:28-35`) in the SAME task that removes the deferral.
- New public functions ship with their tests in the same commit.

---

## File Structure

- `crates/fetchit-relay-client/src/relay_set.rs` (modify) — add `log_append` + `log_fetch` passthrough on `RelaySet`, targeting the primary relay (`self.relays[0]`). Single coherent seq space for the non-durable cursor; multi-relay log replication is a documented follow-up (our topology is single-relay).
- `crates/fetchit-chat/src/relay_transport.rs` (modify) — add `log_append` + `log_fetch` passthrough on `RelayTransport` delegating to `self.relay_set`.
- `crates/fetchit-chat/src/groups/epoch_recovery/wire_map.rs` (create) — pure `commit_record_from_wire` mapping and the pure `ApplyPlan` decision + `plan_apply`. No I/O, no crypto. Fully unit-tested. This is where the security-critical routing lives in testable form.
- `crates/fetchit-chat/src/groups/epoch_recovery/mod.rs` (modify) — `pub mod wire_map;` + re-exports; refresh the module doc (remove the "no production CommitSource yet" paragraph).
- `crates/fetchit-chat/src/client.rs` (modify) — replace `DeferredSource`/`DeferredApplier` in `recover_group_once` (`1808-1894`) with `LogFetchSource` + `WarmApplier`; refresh the method doc-comment (`1800-1804`). Task 5 (Bob-gated) adds `log_append` on the send path (`send_x0xd_metadata_event`, ~`2117-2215`).

---

## Task 1: `RelaySet` + `RelayTransport` group-log passthrough

**Files:**
- Modify: `crates/fetchit-relay-client/src/relay_set.rs` (add methods after `ack_transit`, ~`330`)
- Modify: `crates/fetchit-chat/src/relay_transport.rs` (add methods after `local_agent_id`, ~`160`)
- Test: `crates/fetchit-relay-client/tests/group_log.rs` (extend; mirror existing append+fetch harness at `47-88`)

**Interfaces:**
- Consumes: leaf `fetchit_relay_client::Client::log_append(group_id: GroupId, kind: LogRecordKind, recipient: Option<AgentId>, payload: Vec<u8>) -> Result<(), ClientError>` (`client.rs:487`) and `Client::log_fetch(group_id: GroupId, since_seq: u64) -> Result<Vec<LogRecordWire>, ClientError>` (`client.rs:520`).
- Produces: `RelaySet::log_append(...) -> Result<(), ClientError>`, `RelaySet::log_fetch(group_id, since_seq) -> Result<Vec<LogRecordWire>, ClientError>`; identical passthroughs on `RelayTransport` returning `crate::error::Result<Vec<LogRecordWire>>` (chat crate error type).

- [ ] **Step 1: Write the failing test** (extend `crates/fetchit-relay-client/tests/group_log.rs`)

Mirror the existing harness (a running mock/real relay-server + two connected `RelaySet`s). Add:

```rust
#[tokio::test]
async fn relay_set_log_append_then_fetch_round_trips() {
    let h = harness().await; // same helper the existing tests use
    let set = h.owner_set();  // an Arc<RelaySet>
    let gid = h.group_id();
    set.log_append(gid, LogRecordKind::Commit, None, b"commit-1".to_vec())
        .expect("append queued");
    // append is fire-and-forget; the existing tests already poll fetch to settle
    let recs = h.fetch_until_nonempty(&set, gid, 0).await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].seq, 1);
    assert_eq!(recs[0].kind, LogRecordKind::Commit);
    assert_eq!(recs[0].payload, b"commit-1");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fetchit-relay-client relay_set_log_append_then_fetch_round_trips`
Expected: FAIL — `no method named log_append found for struct RelaySet`.

- [ ] **Step 3: Implement the passthrough on `RelaySet`** (`relay_set.rs`, after `ack_transit`)

```rust
/// Append one record to the primary relay's per-group durable log.
///
/// Fire-and-forget: the relay assigns the seq. Targets the PRIMARY relay
/// (index 0) so the single recovery cursor tracks one coherent seq space;
/// multi-relay log replication is a follow-up (`#297`), unneeded on a
/// single-relay topology.
///
/// # Errors
/// [`ClientError::InboxClosed`] when no relay is present.
pub fn log_append(
    &self,
    group_id: GroupId,
    kind: LogRecordKind,
    recipient: Option<AgentId>,
    payload: Vec<u8>,
) -> Result<(), ClientError> {
    let Some(client) = self.relays.first() else {
        return Err(ClientError::InboxClosed);
    };
    client.log_append(group_id, kind, recipient, payload)
}

/// Fetch group-log records with `seq > since_seq` from the primary relay,
/// ascending. Backs the epoch-recovery `CommitSource` (`#297`).
///
/// # Errors
/// [`ClientError::InboxClosed`] when no relay is present; propagates
/// [`ClientError::LogFetchTimeout`] from the leaf client.
pub async fn log_fetch(
    &self,
    group_id: GroupId,
    since_seq: u64,
) -> Result<Vec<LogRecordWire>, ClientError> {
    let Some(client) = self.relays.first() else {
        return Err(ClientError::InboxClosed);
    };
    client.log_fetch(group_id, since_seq).await
}
```

Add `LogRecordKind, LogRecordWire` to the `fetchit_relay_proto` import at the top of `relay_set.rs` if not present.

- [ ] **Step 4: Run the relay-set test to verify it passes**

Run: `cargo test -p fetchit-relay-client relay_set_log_append_then_fetch_round_trips`
Expected: PASS.

- [ ] **Step 5: Add the `RelayTransport` passthrough** (`relay_transport.rs`, after `local_agent_id` ~`160`)

```rust
/// Append one record to the group-log via the underlying [`RelaySet`].
///
/// # Errors
/// Propagates the relay-client error mapped into the chat crate error.
pub fn log_append(
    &self,
    group_id: fetchit_relay_proto::GroupId,
    kind: fetchit_relay_proto::LogRecordKind,
    recipient: Option<fetchit_relay_proto::identity::AgentId>,
    payload: Vec<u8>,
) -> crate::error::Result<()> {
    self.relay_set
        .log_append(group_id, kind, recipient, payload)
        .map_err(crate::error::ChatError::from)
}

/// Fetch group-log records with `seq > since_seq` via the [`RelaySet`].
///
/// # Errors
/// Propagates the relay-client error mapped into the chat crate error.
pub async fn log_fetch(
    &self,
    group_id: fetchit_relay_proto::GroupId,
    since_seq: u64,
) -> crate::error::Result<Vec<fetchit_relay_proto::LogRecordWire>> {
    self.relay_set
        .log_fetch(group_id, since_seq)
        .await
        .map_err(crate::error::ChatError::from)
}
```

Confirm `ChatError: From<fetchit_relay_client::ClientError>` already exists (the send path at `client.rs:2211` relies on it). If not, this task adds that `From` impl in `crates/fetchit-chat/src/error.rs`.

- [ ] **Step 6: Run the gate and commit**

Run: `cargo test -p fetchit-relay-client && cargo clippy -p fetchit-chat -p fetchit-relay-client --all-targets -- -D warnings`
Expected: PASS / clean.

```bash
git add crates/fetchit-relay-client/src/relay_set.rs crates/fetchit-chat/src/relay_transport.rs crates/fetchit-relay-client/tests/group_log.rs
git commit -s -m "feat(relay): log_append/log_fetch passthrough on RelaySet + RelayTransport (#297 Lane A)"
```

---

## Task 2: Pure wire->record mapping + apply-plan decision

**Files:**
- Create: `crates/fetchit-chat/src/groups/epoch_recovery/wire_map.rs`
- Modify: `crates/fetchit-chat/src/groups/epoch_recovery/mod.rs` (add `pub mod wire_map;` + re-export)
- Test: inline `#[cfg(test)]` in `wire_map.rs`

**Interfaces:**
- Consumes: `fetchit_relay_proto::LogRecordWire { seq: u64, kind: LogRecordKind, recipient: Option<AgentId>, payload: Vec<u8>, author: Option<AgentId>, inserted_at_ms: u64 }`; `CommitRecord`, `CommitRecordKind` (`mod.rs:56-82`).
- Produces:
  - `pub fn commit_record_from_wire(w: &LogRecordWire) -> CommitRecord`
  - `pub enum ApplyPlan { Metadata { payload_b64: String, author_hex: String }, JoinResult { stable_group_id: String, member: String, payload_b64: String, owner_hex: String }, Skip(&'static str) }`
  - `pub fn plan_apply(rec: &CommitRecord, my_agent_hex: &str) -> ApplyPlan`

- [ ] **Step 1: Write the failing tests** (`wire_map.rs`)

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_proto::identity::{AgentId, AGENT_ID_LEN};
    use fetchit_relay_proto::{LogRecordKind, LogRecordWire};

    fn wire(kind: LogRecordKind, author: Option<[u8; AGENT_ID_LEN]>) -> LogRecordWire {
        LogRecordWire {
            seq: 7,
            kind,
            recipient: None,
            payload: b"hello".to_vec(),
            author: author.map(AgentId::from_bytes),
            inserted_at_ms: 123,
        }
    }

    #[test]
    fn maps_commit_wire_to_record_base64_and_hex() {
        let w = wire(LogRecordKind::Commit, Some([0xab; AGENT_ID_LEN]));
        let r = commit_record_from_wire(&w);
        assert_eq!(r.seq, 7);
        assert_eq!(r.kind, CommitRecordKind::Commit);
        assert_eq!(r.payload_b64, "aGVsbG8="); // base64("hello")
        assert_eq!(r.author_agent_id_hex.as_deref(), Some(&"ab".repeat(32)[..]));
    }

    #[test]
    fn maps_missing_author_to_none() {
        let w = wire(LogRecordKind::JoinResult, None);
        let r = commit_record_from_wire(&w);
        assert_eq!(r.kind, CommitRecordKind::JoinResult);
        assert!(r.author_agent_id_hex.is_none());
    }

    #[test]
    fn commit_plan_routes_to_metadata_with_author() {
        let r = CommitRecord {
            seq: 1,
            kind: CommitRecordKind::Commit,
            payload_b64: "cA==".into(),
            author_agent_id_hex: Some("cc".repeat(32)),
        };
        match plan_apply(&r, "me00") {
            ApplyPlan::Metadata { payload_b64, author_hex } => {
                assert_eq!(payload_b64, "cA==");
                assert_eq!(author_hex, "cc".repeat(32));
            }
            other => panic!("expected Metadata, got {other:?}"),
        }
    }

    #[test]
    fn commit_without_author_is_skipped_not_applied() {
        let r = CommitRecord {
            seq: 1,
            kind: CommitRecordKind::Commit,
            payload_b64: "cA==".into(),
            author_agent_id_hex: None,
        };
        assert!(matches!(plan_apply(&r, "me00"), ApplyPlan::Skip(_)));
    }
}
```

Note: `plan_apply` for a `JoinResult` needs to inspect the decoded payload via `member_added_self_target`, which is exercised in Task 4's integration test (it needs a real MemberAdded JSON). Keep the `JoinResult` unit test minimal here (a garbage payload yields `Skip`).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fetchit-chat wire_map`
Expected: FAIL — module `wire_map` does not exist.

- [ ] **Step 3: Implement `wire_map.rs`**

```rust
//! Pure mapping from relay group-log wire records to the recovery loop's
//! [`CommitRecord`], and the pure decision of which x0xd apply endpoint a
//! record routes to. No I/O, no crypto: the security-critical routing is
//! testable in isolation. The actual apply (which re-verifies daemon-side)
//! lives in `Client`'s `WarmApplier`.

use base64::Engine as _;
use fetchit_relay_proto::{LogRecordKind, LogRecordWire};

use super::{CommitRecord, CommitRecordKind};

/// Map a relay group-log wire record into the recovery loop's record shape:
/// base64-encode the raw payload and hex-encode the (routing-hint) author.
#[must_use]
pub fn commit_record_from_wire(w: &LogRecordWire) -> CommitRecord {
    let kind = match w.kind {
        LogRecordKind::Commit => CommitRecordKind::Commit,
        LogRecordKind::JoinResult => CommitRecordKind::JoinResult,
    };
    CommitRecord {
        seq: w.seq,
        kind,
        payload_b64: base64::engine::general_purpose::STANDARD.encode(&w.payload),
        author_agent_id_hex: w.author.map(|a| a.to_hex()),
    }
}

/// Which x0xd apply endpoint a fetched record routes to. `author` is a
/// routing hint only; the daemon endpoints re-verify the ML-DSA
/// `committed_by` inside the payload, so a spoofed author cannot force an
/// unauthorized apply, only a rejected one.
#[derive(Debug)]
pub enum ApplyPlan {
    /// Route to `apply_metadata_event` (a group commit).
    Metadata {
        /// Base64 signed metadata event.
        payload_b64: String,
        /// The author agent id (hex) passed as `sender_agent_id`.
        author_hex: String,
    },
    /// Route to `apply_join_result` (a Welcome addressed to this node).
    JoinResult {
        /// Stable group id parsed from the MemberAdded payload.
        stable_group_id: String,
        /// The joining member (this node) parsed from the payload.
        member: String,
        /// Base64 MemberAdded event.
        payload_b64: String,
        /// The owner/creator agent id (hex) = the record author.
        owner_hex: String,
    },
    /// Nothing to apply (malformed, missing author, or not addressed to us).
    Skip(&'static str),
}

/// Decide how to apply one fetched record. Pure: decodes the payload to
/// classify a JoinResult's self-target, but performs no network or crypto.
#[must_use]
pub fn plan_apply(rec: &CommitRecord, my_agent_hex: &str) -> ApplyPlan {
    let Some(author_hex) = rec.author_agent_id_hex.clone() else {
        return ApplyPlan::Skip("record carries no author");
    };
    match rec.kind {
        CommitRecordKind::Commit => ApplyPlan::Metadata {
            payload_b64: rec.payload_b64.clone(),
            author_hex,
        },
        CommitRecordKind::JoinResult => {
            let Ok(bytes) =
                base64::engine::general_purpose::STANDARD.decode(rec.payload_b64.as_bytes())
            else {
                return ApplyPlan::Skip("join-result payload not base64");
            };
            match crate::groups::join_bridge::member_added_self_target(&bytes, my_agent_hex) {
                Some((stable_group_id, member)) => ApplyPlan::JoinResult {
                    stable_group_id,
                    member,
                    payload_b64: rec.payload_b64.clone(),
                    owner_hex: author_hex,
                },
                None => ApplyPlan::Skip("join-result not addressed to this node"),
            }
        }
    }
}
```

Add to `mod.rs`: `pub mod wire_map;` and `pub use wire_map::{commit_record_from_wire, plan_apply, ApplyPlan};`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-chat wire_map`
Expected: PASS (all mapping + plan tests green).

- [ ] **Step 5: Gate + commit**

Run: `cargo test -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings`

```bash
git add crates/fetchit-chat/src/groups/epoch_recovery/wire_map.rs crates/fetchit-chat/src/groups/epoch_recovery/mod.rs
git commit -s -m "feat(chat): pure wire->CommitRecord mapping + apply-plan routing (#297 Lane A)"
```

---

## Task 3: Production `LogFetchSource` (replace `DeferredSource`)

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs` (`recover_group_once`, replace `DeferredSource` `1864-1873`)
- Test: `crates/fetchit-chat/src/client.rs` inline `#[cfg(test)]`, plus an integration assertion in `crates/fetchit-relay-client/tests/group_log.rs` if a chat-level harness is impractical.

**Interfaces:**
- Consumes: `RelayTransport::log_fetch` (Task 1); `commit_record_from_wire` (Task 2); `self.relay: Option<Arc<RelayTransport>>` (`client.rs:434`); `fetchit_relay_proto::GroupId::from_bytes([u8; 32])` via `hex::decode_to_slice`.
- Produces: `struct LogFetchSource<'a> { client: &'a Client }` implementing `CommitSource::fetch_since(&self, group_id: &str, since_seq: u64) -> Result<Vec<CommitRecord>>`.

- [ ] **Step 1: Write the failing test**

At the chat level, drive `fetch_since` through a `Client` connected to the group_log test harness (mirror how `client.rs` tests build a relay-backed `Client`). If the existing chat test harness cannot reach a live relay, assert the behaviour in `tests/group_log.rs` by constructing the mapping over a real `log_fetch` result and comparing to `commit_record_from_wire`. Minimal chat-level shape:

```rust
#[tokio::test]
async fn log_fetch_source_maps_relay_records_in_seq_order() {
    let (client, relay_harness) = relay_backed_client().await; // existing test helper pattern
    let gid_hex = relay_harness.group_id_hex();
    relay_harness.append_commit(&gid_hex, b"c1").await;
    relay_harness.append_commit(&gid_hex, b"c2").await;
    let src = super::LogFetchSource { client: &client };
    let recs = <_ as CommitSource>::fetch_since(&src, &gid_hex, 0).await.unwrap();
    assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(recs[0].payload_b64, base64_std("c1"));
}
```

If no `relay_backed_client()` helper exists, this task first adds one mirroring the relay setup in the existing `recover_group_once`-adjacent tests; keep it in `#[cfg(test)]`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fetchit-chat log_fetch_source_maps_relay_records`
Expected: FAIL — `LogFetchSource` not found / no relay wiring.

- [ ] **Step 3: Implement `LogFetchSource` inside `recover_group_once`** (replacing `DeferredSource` at `1864-1873`)

```rust
// Warm commit source: pull durable group-log records the relay serves
// (commits for everyone + join-results addressed to us) and map them into
// the loop's record shape. No relay configured (REST/LAN-only) -> empty,
// so a behind member correctly falls through to the cold pending-join
// resume rather than a false Live.
struct LogFetchSource<'a> {
    client: &'a Client,
}
impl CommitSource for LogFetchSource<'_> {
    async fn fetch_since(&self, group_id: &str, since_seq: u64) -> Result<Vec<CommitRecord>> {
        let Some(relay) = self.client.relay.as_ref() else {
            return Ok(Vec::new());
        };
        let mut gid_bytes = [0u8; fetchit_relay_proto::identity::GROUP_ID_LEN];
        hex::decode_to_slice(group_id, &mut gid_bytes)
            .map_err(|e| ChatError::Invalid(format!("recover: group id hex: {e}")))?;
        let gid = fetchit_relay_proto::GroupId::from_bytes(gid_bytes);
        let wire = relay.log_fetch(gid, since_seq).await?;
        Ok(wire
            .iter()
            .map(crate::groups::epoch_recovery::commit_record_from_wire)
            .collect())
    }
}
```

Then swap the driver construction (`1886-1893`) `DeferredSource` -> `LogFetchSource { client: self }`. Import `commit_record_from_wire` via the existing `use crate::groups::epoch_recovery::{...}` block. Confirm the `GROUP_ID_LEN` const path (`fetchit_relay_proto::identity::GROUP_ID_LEN`); adjust to the actual module if the compiler disagrees.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-chat log_fetch_source_maps_relay_records`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `cargo test -p fetchit-chat && cargo test -p fetchit-relay-client && cargo clippy -p fetchit-chat -p fetchit-relay-client --all-targets -- -D warnings`

```bash
git add crates/fetchit-chat/src/client.rs crates/fetchit-relay-client/tests/group_log.rs
git commit -s -m "feat(chat): production LogFetch-backed CommitSource for warm recovery (#297 Lane A)"
```

---

## Task 4: Production `WarmApplier` (replace `DeferredApplier`) + doc refresh

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs` (`recover_group_once`, replace `DeferredApplier` `1877-1884`; refresh doc `1800-1804`)
- Modify: `crates/fetchit-chat/src/groups/epoch_recovery/mod.rs` (refresh module doc `28-35`)
- Test: `crates/fetchit-chat/src/client.rs` inline `#[cfg(test)]` (end-to-end: append a real commit, recover, assert Applied)

**Interfaces:**
- Consumes: `plan_apply` + `ApplyPlan` (Task 2); `self.secure_groups() -> Result<SecureGroupsEndpoint>` (`client.rs:1761`); the local agent-id hex (mirror the cold path: `identity.agent_id_hex()` — resolve the exact `Client` accessor at compile time, candidates `self.identity().agent_id_hex()` / `hex::encode(self.signer.agent_id())`); `SecureGroupsEndpoint::apply_metadata_event(gid, event_b64, sender_agent_id) -> Result<bool>` and `apply_join_result(gid, member, event_b64, sender_agent_id) -> Result<bool>` (`x0xd-client/src/secure.rs:687,744`).
- Produces: `struct WarmApplier<'a> { client: &'a Client, my_agent_hex: String }` implementing `CommitApplier::apply(&self, group_id: &str, record: &CommitRecord) -> Result<ApplyOutcome>`.

- [ ] **Step 1: Write the failing end-to-end test**

```rust
#[tokio::test]
async fn warm_recovery_applies_relay_commit_and_reports_live() {
    // Owner creates a group, adds a member; the member's daemon is behind.
    // Owner appends the metadata commit to the group-log. Member runs
    // recover_group_once and ends keyed at the new epoch (status Live).
    let world = two_member_group_relay_backed().await; // existing multi-member test scaffold
    world.owner_append_commit_to_log().await;
    let outcome = world
        .member
        .recover_group_once(&world.group_id_hex, Some(world.target_epoch))
        .await
        .unwrap();
    assert!(matches!(outcome, RecoverOutcome::Converged));
    assert!(world.member_is_keyed_at(world.target_epoch).await);
}
```

If the repo lacks a two-member relay-backed scaffold reachable from a unit test, assert the narrower contract instead: construct a `WarmApplier`, feed it a `CommitRecord` whose `apply_metadata_event` the mocked `SecureGroupsEndpoint` answers `Ok(true)`, and assert `ApplyOutcome::Applied`; feed a `Ok(false)` and assert `AlreadyApplied`. Prefer the end-to-end form if the scaffold exists (grep `two_member` / `owner`/`joiner` in `client.rs` tests).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fetchit-chat warm_recovery_applies_relay_commit`
Expected: FAIL — `WarmApplier` not found / `DeferredApplier` errors "warm commit apply not yet wired".

- [ ] **Step 3: Implement `WarmApplier`** (replacing `DeferredApplier` at `1877-1884`)

```rust
// Warm applier: route each fetched record to x0xd's signature-verifying
// apply endpoint. NEVER a bypass -- the daemon re-runs full membership
// authority (ML-DSA committed_by + single-use invite-secret + inviter-gate)
// on the payload, so the relay-stamped author is only a routing hint.
struct WarmApplier<'a> {
    client: &'a Client,
    my_agent_hex: String,
}
impl CommitApplier for WarmApplier<'_> {
    async fn apply(&self, group_id: &str, record: &CommitRecord) -> Result<ApplyOutcome> {
        use crate::groups::epoch_recovery::{plan_apply, ApplyPlan};
        let secure = self.client.secure_groups()?;
        let applied = match plan_apply(record, &self.my_agent_hex) {
            ApplyPlan::Metadata { payload_b64, author_hex } => secure
                .apply_metadata_event(group_id, &payload_b64, &author_hex)
                .await
                .map_err(ChatError::from)?,
            ApplyPlan::JoinResult { stable_group_id, member, payload_b64, owner_hex } => secure
                .apply_join_result(&stable_group_id, &member, &payload_b64, &owner_hex)
                .await
                .map_err(ChatError::from)?,
            ApplyPlan::Skip(_reason) => {
                // Nothing to apply; treat as already-satisfied so the loop
                // advances its cursor past this record rather than stalling.
                return Ok(ApplyOutcome::AlreadyApplied);
            }
        };
        Ok(if applied {
            ApplyOutcome::Applied
        } else {
            ApplyOutcome::AlreadyApplied
        })
    }
}
```

Swap the driver construction `DeferredApplier` -> `WarmApplier { client: self, my_agent_hex: <local agent hex> }`. Resolve `<local agent hex>` at compile time against the cold-path accessor.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-chat warm_recovery_applies_relay_commit`
Expected: PASS.

- [ ] **Step 5: Refresh the stale docs (docs-track-code)**

Rewrite `recover_group_once`'s doc-comment (`client.rs:1800-1804`) to describe the LIVE warm path (fetch group-log commits since cursor, apply via the verifying endpoints, re-probe). Rewrite the "no production CommitSource yet" paragraph in `epoch_recovery/mod.rs:28-35` to state the warm path is live over the relay group-log. Do NOT write expiring phrasing.

- [ ] **Step 6: Gate + commit**

Run: `cargo test -p fetchit-chat && cargo test -p fetchit-relay-client && cargo clippy -p fetchit-chat -p fetchit-relay-client --all-targets -- -D warnings`

```bash
git add crates/fetchit-chat/src/client.rs crates/fetchit-chat/src/groups/epoch_recovery/mod.rs
git commit -s -m "feat(chat): production warm CommitApplier via x0xd verifying apply path (#297 Lane A)"
```

---

## Task 5 (BOB-GATED): Producer-side `log_append` on the send path

> **DO NOT START until Bob confirms this piece is Alice's.** The producer-append is the piece with cross-box ownership ambiguity (flagged to Bob over the pipe). Without it the warm fetch returns an empty log and Tasks 3-4 are correct-but-dormant. Tasks 1-4 land and are valuable independently. If Bob owns it, stop after Task 4 and cross-review his append instead.

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs` (`send_x0xd_metadata_event`, ~`2117-2215`)
- Test: `crates/fetchit-chat/src/client.rs` inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `RelayTransport::log_append` (Task 1); the signed event bytes already in hand at the send site (`signed_event_json_bytes` base64-encoded to `payload_b64` at `client.rs:2168`); `LogRecordKind::{Commit, JoinResult}`; the recipient agent id for a JoinResult.
- Produces: an additive `log_append` call alongside the existing `self.router.send(...)` (`2211`). Fire-and-forget; a failed append must NOT fail the send (the DM bridge is the live delivery; the log is durability for catch-up).

- [ ] **Step 1: Write the failing test** — sending a group metadata commit appends a `Commit` record (recipient `None`) to the relay group-log; a self-Welcome/JoinResult send appends a `JoinResult` record addressed to the joiner. Assert via `log_fetch` after send.

- [ ] **Step 2: Run to verify failure** — `cargo test -p fetchit-chat send_appends_commit_to_group_log`; FAIL (log empty after send).

- [ ] **Step 3: Implement** — after the successful `self.router.send(...)` in `send_x0xd_metadata_event`, if `self.relay` is present, build the `GroupId` (hex-decode) and call `relay.log_append(gid, kind, recipient, signed_event_json_bytes.to_vec())`. `kind`/`recipient`: `Commit`/`None` for a broadcast metadata commit; `JoinResult`/`Some(joiner_agent_id)` when the event is a Welcome addressed to a joiner. Derive kind from the same classification the send site already computes (grep the metadata-event kind switch). Log-and-ignore any append error (`if let Err(e) = ... { tracing::warn!(...) }`). Do not `?` it.

- [ ] **Step 4: Run to verify pass** — PASS.

- [ ] **Step 5: Gate + commit**

```bash
git add crates/fetchit-chat/src/client.rs
git commit -s -m "feat(chat): append group commits/join-results to durable relay log on send (#297 Lane A)"
```

---

## Post-tasks

- [ ] Full-workspace regression: `cargo test --workspace` green (the warm path touches shared crates).
- [ ] Update `docs/CAPABILITIES.md`: mark warm epoch-recovery as live (anchored + stamped), per the "know what's built" rule.
- [ ] Hand the full branch diff to Bob for adversarial cross-review BEFORE landing to main (security-sensitive: applies relay-fetched bytes to MLS state). Do not land Task 5 without his ownership sign-off.

## Self-Review notes

- Spec coverage: passthrough (T1), source (T3), applier (T4), producer-append (T5), pure routing extracted for testability (T2), doc refresh folded into T4. All four scope items covered.
- Type consistency: `CommitRecord`/`CommitRecordKind`/`ApplyOutcome` names match `mod.rs`; `LogRecordWire` fields match `frame.rs:240-263`; apply endpoint signatures match `secure.rs:687,744`; `member_added_self_target` signature matches `join_bridge.rs:95`.
- Two accessors are resolved at compile time (marked in T3/T4): the `GROUP_ID_LEN` const path and the `Client` local-agent-hex accessor. Both are mechanical and the compiler pins them immediately; they are not design placeholders.
