# Android Private-Group Feature Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the full private-group (PQ MLS/TreeKEM) chat feature on Android for v1 -- create/join/send/receive groups -- by embedding x0xd in-process in the FFI and adding a group surface to the FFI and the Kotlin shell.

**Architecture:** The Android chat FFI runs the daemonless engine profile (local ML-DSA-65 vault signer, proven DM path). Groups need x0xd's `/secure/*` TreeKEM endpoints, so the FFI embeds x0xd **in-process** via `x0x::daemon::serve()` on a loopback port and points the engine's `base_url`/`token` at it -- the engine's intended "P2 in-process-router" shape (`daemonless(true)` keeps the local-vault signer; `base_url` only redirects the x0xd HTTP surface). A new engine `messages().send_to_group()` routes by cached group kind (private -> `send_private_group`, public -> `groups().send`); receive mirrors the desktop seam (`is_private_group_envelope -> receive_private_group_envelope -> Persisted/Replay/Err`). The Kotlin shell reuses the existing conversation screen, keyed by group_id.

**Tech Stack:** Rust (fetchit-chat engine, fetchit-ffi uniffi 0.29.5, x0xd-client, the josh-clsn/x0x fork `mobile-serve-entrypoint`), Kotlin/Android (Material3 shell), cargo-ndk + uniffi-bindgen (arm64-v8a).

**Worktree:** `/home/josh/Desktop/etchit-fetchit/fetchit-android-groups`, branch `android-groups`, based on chat tip `f063feb`. All `cargo`/`gradle` runs happen IN THIS WORKTREE (its `target/` is separate from the main `fetchit/` checkout -- never build in `fetchit/`, the comms chat-peer execs `fetchit/target/debug/fetchit-chat-peer`).

**Branch choreography (coordinated with Alice):** Task 1 is a SHARED engine deliverable. It is the bottom commit of this stack; after it gates + Alice cross-reviews, Alice fast-forwards `chat` to the Task-1 commit (unblocks her desktop `chat_group_send` rewire, issue #56). Tasks 2-8 continue stacking on `android-groups` and land as the full Android feature later. Ping Alice (`claude-tx-send`) on the Task-1 push.

**Constraints (every task):** No em-dashes in committed code / commit messages (use `--`). `git commit -s` (DCO) on every commit. No `unwrap()`/`expect()`/`panic!` outside `#[cfg(test)]`. Workspace lints are `-D warnings` (clippy pedantic, missing_docs). `fetchit-ffi` is workspace-excluded with its own `Cargo.lock`. Add docs-comments + keep them truthful (no expiring "lands-next" comments).

---

## File Structure

**Engine (Task 1 -- shared, lands on chat first):**
- Modify `crates/fetchit-chat/src/groups/mod.rs` -- add `GroupKind`, add `kind: Option<GroupKind>` to `Group`, warm kind on create paths.
- Modify `crates/fetchit-chat/src/messages.rs` -- add `send_to_group()` router + `GroupId -> GroupKind` cache.
- Modify `crates/x0xd-client/src/secure.rs` (or a sibling module) -- add `get_group(group_id) -> GroupMeta { confidentiality }` parsing `GET /groups/<id>` `policy.confidentiality`.

**FFI (Tasks 2-4):**
- Modify `crates/fetchit-ffi/Cargo.toml` -- add `x0x` path dep + `x0xd-client` (if not transitive-exposed).
- Modify `crates/fetchit-ffi/src/chat_ffi.rs` -- in-process `serve()` embed in `connect()`, group methods, `ChatEventFfi::GroupMessage`, drop the daemonless private-group skip + wire the receive seam.
- New `crates/fetchit-ffi/src/group_ffi.rs` (optional split) -- `GroupFfi` record + group methods, to keep `chat_ffi.rs` focused (one-concept-per-file).

**Bindings (Task 5):**
- Regenerated `apps/fetchit-android/app/src/main/jniLibs/arm64-v8a/libfetchit_ffi.so` (gitignored) + `apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt` (committed) via `scripts/build-jni-libs.sh`.

**Kotlin shell (Tasks 6-7):**
- Modify `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatGateway.kt` -- group methods.
- Modify `.../chat/ChatController.kt` -- handle `ChatEventFfi.GroupMessage`, load groups on connect.
- Modify `.../chat/ConversationStore.kt` -- key generalization (group_id keys).
- Modify `.../chat/ChatModeView.kt` -- `Screen.GroupThread`, list entry points (New/Join group), `bindGroupThreadScreen`, group send.
- New `.../chat/NewGroupDialog.kt` + `.../chat/JoinGroupDialog.kt` (mirror `showAddContactDialog`).

---

## Task 1: Engine -- `send_to_group` router + kind cache (SHARED; lands on chat first)

**Files:**
- Modify: `crates/fetchit-chat/src/groups/mod.rs` (Group struct ~104-117; create ~280; create_private ~301)
- Modify: `crates/fetchit-chat/src/messages.rs` (near `send_private_group` ~1025)
- Modify: `crates/x0xd-client/src/secure.rs` (add `get_group`)
- Test: inline `#[cfg(test)]` in `messages.rs` + `groups/mod.rs`

**Context:** Given only a `group_id`, callers can't route: `send_private_group` (TreeKEM, private) vs `groups().send` (SignedPublic, public). x0xd is the source of truth: `GET /groups/<id>` (`get_named_group`, x0x-fork `src/daemon.rs:10159-10189`) returns `policy.confidentiality` = `MlsEncrypted | SignedPublic` (`src/groups/policy.rs:71-79`). `create_private` posts `preset=private_secure`, `create` posts `preset=public_open` -- so kind is known locally at create time.

- [ ] **Step 1: Add `GroupKind` + `kind` field (failing test first).** In `groups/mod.rs`, write a test asserting `Group` round-trips a `kind`:

```rust
#[cfg(test)]
mod kind_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn group_defaults_kind_none_and_serdes() {
        let g = Group { group_id: GroupId::parse("a".repeat(64)).unwrap(), name: None, member_count: 0, is_owner: false, kind: Some(GroupKind::Private) };
        let json = serde_json::to_string(&g).unwrap();
        let back: Group = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, Some(GroupKind::Private));
        // x0xd /groups list omits kind -> deserializes to None.
        let listed: Group = serde_json::from_str(r#"{"group_id":"a","member_count":0,"is_owner":false}"#.replace('a', &"a".repeat(64)).as_str()).unwrap();
        assert_eq!(listed.kind, None);
    }
}
```

- [ ] **Step 2: Run the test, watch it fail** (no `GroupKind`, no `kind` field). Run: `cargo test -p fetchit-chat kind_tests`. Expected: compile error / FAIL.

- [ ] **Step 3: Implement `GroupKind` + field.** In `groups/mod.rs`:

```rust
/// Wire-level confidentiality of a group, mirroring x0xd's
/// `policy.confidentiality`. `Private` is the PQ MLS/TreeKEM path
/// (`send_private_group`); `Public` is the SignedPublic plaintext path
/// (`groups().send`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum GroupKind {
    /// PQ-encrypted MLS group (`preset=private_secure`, confidentiality
    /// `MlsEncrypted`).
    Private,
    /// Plaintext SignedPublic room (`preset=public_open`).
    Public,
}
```

Add to `Group`: `#[serde(default)] pub kind: Option<GroupKind>,`. Set `kind: None` at the existing call sites that deserialize `Group` from x0xd (list/join) -- those come from `#[serde(default)]`, no change needed. In `create_private` set the returned group's `kind = Some(GroupKind::Private)`; in `create` set `Some(GroupKind::Public)` (mutate the deserialized `Group` before returning).

- [ ] **Step 4: Run the test, watch it pass.** Run: `cargo test -p fetchit-chat kind_tests`. Expected: PASS.

- [ ] **Step 5: Add x0xd-client `get_group` (failing test).** In `crates/x0xd-client/src/secure.rs`, write a wiremock-backed test (mirror the existing x0xd-client test style) that `GET /groups/<id>` returning `{"ok":true,"policy":{"confidentiality":"MlsEncrypted"}}` yields `GroupMeta { confidentiality: Confidentiality::MlsEncrypted }`.

- [ ] **Step 6: Run it, watch it fail.** Run: `cargo test -p x0xd-client get_group`. Expected: FAIL (no method).

- [ ] **Step 7: Implement `get_group`.** Add:

```rust
/// Group confidentiality as reported by x0xd `GET /groups/<id>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Confidentiality {
    /// PQ MLS/TreeKEM-encrypted.
    MlsEncrypted,
    /// Plaintext SignedPublic.
    SignedPublic,
}

#[derive(Debug, Clone, Deserialize)]
struct GroupMetaResponse {
    #[serde(default)]
    policy: Option<GroupPolicyMeta>,
}
#[derive(Debug, Clone, Deserialize)]
struct GroupPolicyMeta {
    confidentiality: Confidentiality,
}

impl SecureGroupsEndpoint {
    /// Fetch a group's confidentiality kind from x0xd `GET /groups/<id>`.
    /// The authoritative kind source for cold-cache routing.
    pub async fn get_group_confidentiality(&self, group_id: &str) -> Result<Confidentiality> {
        let path = format!("/groups/{group_id}");
        let resp: GroupMetaResponse = self.http.get_json(&path).await?;
        resp.policy
            .map(|p| p.confidentiality)
            .ok_or_else(|| /* existing crate error: missing policy */ todo!("use the crate's error type, not todo!"))
    }
}
```

(Implementer: verify the exact endpoint struct name -- `SecureGroupsEndpoint` per `crates/fetchit-chat/src/messages.rs:44` import -- and the crate's `Result`/error type; replace the `todo!` placeholder with the real error variant. Confirm x0xd serializes `confidentiality` as the bare strings `"MlsEncrypted"`/`"SignedPublic"` per `x0x-fork/src/groups/policy.rs`; if it uses a different serde rename, match it.)

- [ ] **Step 8: Run it, watch it pass.** Run: `cargo test -p x0xd-client get_group`. Expected: PASS.

- [ ] **Step 9: Add `send_to_group` + cache (failing test).** In `messages.rs`, write tests (wiremock x0xd) asserting: (a) a cached `Private` group routes through the `send_private_group` path (`/secure/encrypt` hit); (b) a cached `Public` group routes through `groups().send` (`/groups/<id>/send` hit); (c) a cold-cache group triggers one `GET /groups/<id>` then routes + caches (second send does NOT re-GET).

- [ ] **Step 10: Run, watch fail.** Run: `cargo test -p fetchit-chat send_to_group`. Expected: FAIL.

- [ ] **Step 11: Implement the cache + router.** On the messages `Endpoint`, add a cache field `group_kinds: Arc<Mutex<HashMap<String, GroupKind>>>` (std `Mutex`, scope every guard so it is dropped BEFORE any `.await` -- mirror the lr-group-keyresolve neg-cache discipline). Implement:

```rust
/// Send `body` to a group, routing by kind: private groups fan out via
/// `send_private_group` (TreeKEM); public rooms post plaintext via
/// `groups().send`. Kind is resolved from a warm `GroupId -> kind` cache
/// (populated by create/join/list) or, on a cold miss, one
/// `GET /groups/<id>` against x0xd. Both shells call this -- it is the
/// single place MLS-vs-SignedPublic routing lives.
///
/// # Errors
/// Surfaces the underlying send error; `ChatError::Denied` if a member is
/// denylisted (private path); the x0xd HTTP error on a cold kind lookup.
pub async fn send_to_group(&self, group_id: &str, body: &str, sender_name: &str) -> Result<Option<String>> {
    let cached = {
        let map = self.group_kinds.lock().expect("group_kinds mutex");
        map.get(group_id).copied()
    }; // guard dropped here, before the await
    let kind = match cached {
        Some(k) => k,
        None => {
            let conf = self.secure_groups().get_group_confidentiality(group_id).await?;
            let k = match conf {
                Confidentiality::MlsEncrypted => GroupKind::Private,
                Confidentiality::SignedPublic => GroupKind::Public,
            };
            self.group_kinds.lock().expect("group_kinds mutex").insert(group_id.to_owned(), k);
            k
        }
    };
    match kind {
        GroupKind::Private => self.send_private_group(group_id, body, sender_name).await,
        GroupKind::Public => {
            let gid = crate::groups::GroupId::parse(group_id)?;
            self.groups_endpoint().send(&gid, body).await.map(|_| None)
        }
    }
}

/// Warm the kind cache (called by create_private/create/join/list).
pub fn note_group_kind(&self, group_id: &str, kind: GroupKind) {
    self.group_kinds.lock().expect("group_kinds mutex").insert(group_id.to_owned(), kind);
}
```

(Implementer: wire `note_group_kind` calls from the `Client`/`groups()` create/create_private/list paths so warm cache populates -- where `create_private` returns, call `messages().note_group_kind(&group.group_id.0, GroupKind::Private)`, etc. Verify how `messages()` reaches the `groups` endpoint + `secure_groups` -- `send_private_group` already fetches the roster via `groups::Endpoint::members`, so the access pattern exists; reuse it. The public `groups().send` returns the daemon's id shape -- map to `Option<String>` consistently with `send_private_group`. Use `#[cfg(not(test))]`-free real types; no `expect` outside the lock-poison case which is acceptable per the codebase's mutex convention -- if clippy forbids it, use `if let Ok(map) = ... ` and fall through.)

- [ ] **Step 12: Run, watch pass.** Run: `cargo test -p fetchit-chat send_to_group`. Expected: PASS.

- [ ] **Step 13: Full engine gate.** Run: `cargo fmt -p fetchit-chat -p x0xd-client && cargo clippy -p fetchit-chat -p x0xd-client --all-targets -- -D warnings && cargo test -p fetchit-chat -p x0xd-client`. Expected: clean + green.

- [ ] **Step 14: Commit.**

```bash
git add crates/fetchit-chat/src/groups/mod.rs crates/fetchit-chat/src/messages.rs crates/x0xd-client/src/secure.rs
git commit -s -m "feat(chat): kind-aware messages().send_to_group + GroupId->kind cache (#56)

Routes private groups to send_private_group (TreeKEM) and public rooms to
groups().send, resolving kind from a warm cache or one GET /groups/<id>
cold lookup. One method both shells call -- fixes the SignedPublic-400 on
private-group send."
```

- [ ] **Step 15: Push + ping Alice for cross-review.** `git push origin android-groups`. Then `claude-tx-send` Alice that the Task-1 commit is pushed for her cross-review + chat FF (she wires desktop `chat_group_send` to `send_to_group`). HALT the stack here until she confirms; resume Tasks 2+ on her OK (do not block her FF behind later commits).

---

## Task 2: FFI -- embed x0xd in-process in `connect()` (no DM regression)

**Files:**
- Modify: `crates/fetchit-ffi/Cargo.toml`
- Modify: `crates/fetchit-ffi/src/chat_ffi.rs` (struct ~153-167; `connect` ~205-261)
- Test: inline `#[cfg(test)]` in `chat_ffi.rs`

**Context:** `connect()` builds `Client::builder().daemonless(true).relay_url().data_dir().passphrase().build()`. The daemonless profile points x0xd at sentinel `127.0.0.1:9`. To serve groups, embed x0xd in-process and set `.base_url()/.token()` (the engine's "P2 in-process-router" shape; `daemonless(true)` keeps the local-vault signer -- no DM change). Recipe verified in the `android-lit-workstream` memory + engine test `daemonless_with_explicit_base_url_still_probes_daemon_version` (client.rs:4293).

**VERIFIED serve() API (x0x-fork `mobile-serve-entrypoint`, read 2026-06-15) + load-bearing flags:**
- `x0x::daemon::serve(config: DaemonConfig, exec_policy: x0x::exec::ExecPolicy, disable_peer_cache: bool) -> anyhow::Result<ServerHandle>` (daemon.rs:1560). Map the `anyhow::Error` via `format!("{e}")`. Use paths: `use x0x::daemon::{serve, DaemonConfig, DaemonUpdateConfig, ServerHandle}; use x0x::exec::ExecPolicy;` (ExecPolicy is under `x0x::exec`, NOT `x0x::daemon`).
- `DaemonConfig` has `api_address: SocketAddr` (HTTP, default 127.0.0.1:12700) AND a SEPARATE `bind_address: SocketAddr` (QUIC gossip, default `[::]:5483`). It has a real `impl Default`, so `DaemonConfig { .., ..Default::default() }` compiles. Set BOTH sockets to ephemeral (port 0) so the embed never clashes with a fixed port on the device.
- FLAG (Play policy / no self-modifying binary): `ExecPolicy::Disabled` gates only remote `x0x-exec`-over-gossip, NOT self-update. Self-update lives in `DaemonConfig.update` (`DaemonUpdateConfig`, daemon.rs:273-309, all flags default ON) -- you MUST also set `update.enabled = false` (and confirm `gossip_updates`/`stop_on_upgrade`) or the embedded x0xd listens for release manifests + tries to update itself on a user's phone.
- FLAG: `ExecPolicy::Disabled` is a 3-field struct variant `{ path: PathBuf, reason: String, loaded_at_unix_ms: u64 }` -- NO `disabled()` constructor; build it inline.
- FLAG (teardown): `ServerHandle::shutdown(&self)` is SYNC + non-consuming -- use it in `disconnect()`/`Drop`. `join(self)` is async + CONSUMES the handle (cannot be called from a uniffi `&self` method); do not use it. `local_addr() -> SocketAddr`, `api_token() -> &str` (copy to owned before the handle moves).
- BLOCKER-RISK (verify in Step 0): the embedded `Agent`'s key storage (`machine.key`/`agent.key`) may default to `~/.x0x/` (home dir), NOT `DaemonConfig.data_dir`. Android has no writable home dir, so HOST tests pass (the host HAS `~/.x0x`) while the device fails. Trace where `serve()` -> `Agent` persists keys; if it does not honor `data_dir`, that is a real Android blocker -- find the Agent-builder knob or flag it to the controller before proceeding.

- [ ] **Step 0: Verify the embedded Agent key-storage path (BLOCKER risk).** Trace `x0x::daemon::serve()` -> the `Agent` build in `x0x-fork/src/daemon.rs` to find where `machine.key`/`agent.key` are persisted. Confirm `DaemonConfig.data_dir` governs it. If the `Agent` hardcodes `~/.x0x/` (home dir), STOP and report BLOCKED -- it fails on Android (no writable home), and host tests would falsely pass. Resolve (find the path knob or flag a fork change) before implementing the embed.

- [ ] **Step 1: Add the x0x dep.** In `crates/fetchit-ffi/Cargo.toml` `[dependencies]`, add `x0x = { path = "../../../x0x-fork" }` (verify the relative path from the worktree: `fetchit-android-groups/crates/fetchit-ffi` -> `../../../x0x-fork` resolves to `/home/josh/Desktop/etchit-fetchit/x0x-fork`). The fork branch must be `mobile-serve-entrypoint` (tip `1716442`, has `serve()` + `ServerHandle::api_token()`). Run `cargo metadata -p fetchit-ffi >/dev/null` to confirm it resolves (heavy -- pulls ant-quic + saorsa-gossip; DISK WATCH).

- [ ] **Step 2: Hold the ServerHandle (failing test).** Add a field `_x0xd: x0x::daemon::ServerHandle,` to `ChatClient`. Write a test that `connect()` against a temp data_dir brings serve() up and the engine version-probe succeeds (or, if a full connect needs a relay, a narrower test: `serve_inprocess()` helper returns a handle whose `local_addr()` is loopback and `api_token()` is non-empty).

- [ ] **Step 3: Run, watch fail.** Run: `cargo test -p fetchit-ffi inprocess`. Expected: FAIL.

- [ ] **Step 4: Implement the embed.** In `connect()`, BEFORE `Client::builder()`:

```rust
// Embed x0xd in-process for group TreeKEM (/secure/*). daemonless(true)
// keeps the local ML-DSA-65 vault signer -- base_url only redirects the
// x0xd HTTP surface (the engine's P2 in-process-router shape).
let x0xd_data = PathBuf::from(&data_dir).join("x0xd");
let cfg = x0x::daemon::DaemonConfig {
    // HTTP control surface: loopback, OS-assigned port (read via local_addr()).
    api_address: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
    // QUIC gossip socket: ephemeral, NOT the fixed default -- avoid a
    // fixed-port clash with any other x0xd on the device.
    bind_address: (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
    data_dir: x0xd_data,
    // Play policy: no self-modifying binary. ExecPolicy gates only remote
    // x0x-exec; self-update lives here and defaults ON.
    update: x0x::daemon::DaemonUpdateConfig { enabled: false, ..Default::default() },
    ..Default::default()
};
// ExecPolicy::Disabled is a 3-field struct variant (no disabled() ctor),
// under x0x::exec (NOT x0x::daemon). Gates remote x0x-exec-over-gossip.
let exec_policy = x0x::exec::ExecPolicy::Disabled {
    path: std::path::PathBuf::new(),
    reason: "embedded_mobile".to_owned(),
    loaded_at_unix_ms: 0,
};
let handle = x0x::daemon::serve(cfg, exec_policy, false)
    .await
    .map_err(|e| ChatFfiError::Network { reason: format!("x0xd serve: {e}") })?;
let x0xd_base = format!("http://{}", handle.local_addr());
let x0xd_token = handle.api_token().to_owned();
```

Then add to the builder chain: `.base_url(Url::parse(&x0xd_base).map_err(|e| ChatFfiError::Invalid { reason: format!("base_url: {e}") })?)` and `.token(x0xd_token)`. Store `handle` in the struct as `x0xd: ServerHandle` (NOT underscore-prefixed -- `disconnect()`/`Drop` call `self.x0xd.shutdown()`). serve() MUST be awaited BEFORE `.build()` (build-time `enforce_m2_treekem_minimum` probes base_url). (Implementer: confirm `DaemonUpdateConfig`'s field names -- the Explore cited `enabled`/`stop_on_upgrade`/`gossip_updates` at daemon.rs:273-309 -- and whether `gossip_updates`/`stop_on_upgrade` also need disabling for full Play-safety. Verify `.base_url()`/`.token()` are the real `ClientBuilder` methods -- per Alice's client.rs trace they are.)

- [ ] **Step 5: Stop x0xd on disconnect/Drop.** `ServerHandle::shutdown(&self)` is SYNC + non-consuming (verified) -- call `self.x0xd.shutdown()` in `disconnect()` and the `Drop` impl, alongside the existing `pump_abort`/`drain_abort` teardown. Do NOT use `join(self)` (async + consumes the handle -- it cannot be called from a uniffi `&self` method).

- [ ] **Step 6: Run, watch pass.** Run: `cargo test -p fetchit-ffi inprocess`. Expected: PASS.

- [ ] **Step 7: DM no-regression gate.** Run the existing FFI test suite: `cargo test -p fetchit-ffi`. Expected: existing DM/connect tests still green (daemonless signer unchanged).

- [ ] **Step 8: Commit.**

```bash
git add crates/fetchit-ffi/Cargo.toml crates/fetchit-ffi/src/chat_ffi.rs crates/fetchit-ffi/Cargo.lock
git commit -s -m "feat(ffi): embed x0xd in-process for group TreeKEM (#110)

connect() runs x0x::daemon::serve() on a loopback port and points the
daemonless engine at it via base_url/token. Keeps the local-vault DM
signer unchanged; gives groups a /secure/* surface on Android."
```

---

## Task 3: FFI -- group methods + `GroupFfi` record

**Files:**
- New: `crates/fetchit-ffi/src/group_ffi.rs` (record + methods) -- or add to `chat_ffi.rs` if simpler; prefer the split (one concept per file).
- Modify: `crates/fetchit-ffi/src/lib.rs` (module decl if new file)
- Modify: `crates/fetchit-ffi/src/chat_ffi.rs` (impl block)

**Context:** Mirror the `send_dm` pattern (`chat_ffi.rs:398-414`). Engine surface from E1: `groups().create_private(name, display_name)`, `groups().create(name, display_name)`, `groups().join(invite, display_name)`, `messages().send_to_group(group_id, body, sender_name)` (Task 1), `groups().list()`, `groups().invite(group_id)`.

- [ ] **Step 1: `GroupFfi` record (failing test).** Write a test constructing `GroupFfi` from a `fetchit_chat::groups::Group`. Define:

```rust
/// A group as surfaced to Android.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupFfi {
    /// 64-hex group id.
    pub group_id: String,
    /// Optional human name.
    pub name: Option<String>,
    /// Local roster size.
    pub member_count: u64,
    /// Whether this agent created it.
    pub is_owner: bool,
    /// True for PQ-encrypted (private) groups -- drives the UI lock icon.
    /// `None` when unknown (e.g. from a bare list before kind resolves).
    pub is_private: Option<bool>,
}
```

with a `From<fetchit_chat::groups::Group>` mapping `kind` -> `is_private` (`Some(Private)->Some(true)`, `Some(Public)->Some(false)`, `None->None`).

- [ ] **Step 2: Run, watch fail.** `cargo test -p fetchit-ffi group_ffi`. Expected: FAIL.

- [ ] **Step 3: Implement the record + `From`.** Add the struct + mapping.

- [ ] **Step 4: Run, watch pass.** Expected: PASS.

- [ ] **Step 5: Add the exported methods** to the `#[uniffi::export(async_runtime = "tokio")] impl ChatClient` block:

```rust
/// Create a group. `private=true` -> PQ MLS (default); false -> public room.
pub async fn create_group(&self, name: String, display_name: Option<String>, private: bool) -> Result<GroupFfi, ChatFfiError> {
    let g = if private {
        self.inner.groups().create_private(&name, display_name.as_deref()).await
    } else {
        self.inner.groups().create(&name, display_name.as_deref()).await
    }.map_err(ChatFfiError::from)?;
    Ok(GroupFfi::from(g))
}

/// Join a group from an `x0x://invite/...` link.
pub async fn join_group(&self, invite: String, display_name: Option<String>) -> Result<GroupFfi, ChatFfiError> {
    let inv = fetchit_chat::groups::GroupInvite::from(invite); // verify constructor
    let g = self.inner.groups().join(&inv, display_name.as_deref()).await.map_err(ChatFfiError::from)?;
    // Best-effort: warm member cards so first inbound decrypts without lazy-fetch.
    if let Ok(members) = self.inner.groups().members(&g.group_id).await {
        if let Some(me) = self.inner.identity_arc().map(|i| i.agent_id().clone()) {
            let _ = self.inner.messages().prefetch_group_member_cards(&members, &me).await;
        }
    }
    Ok(GroupFfi::from(g))
}

/// Send a message to a group (routes private/public via send_to_group).
pub async fn send_group_message(&self, group_id: String, body: String, sender_name: String) -> Result<Option<String>, ChatFfiError> {
    self.inner.messages().send_to_group(&group_id, &body, &sender_name).await.map_err(ChatFfiError::from)
}

/// List groups this agent belongs to.
pub async fn list_groups(&self) -> Result<Vec<GroupFfi>, ChatFfiError> {
    let gs = self.inner.groups().list().await.map_err(ChatFfiError::from)?;
    Ok(gs.into_iter().map(GroupFfi::from).collect())
}

/// Fresh invite link for a group.
pub async fn group_invite(&self, group_id: String) -> Result<String, ChatFfiError> {
    let gid = fetchit_chat::groups::GroupId::parse(group_id).map_err(|e| ChatFfiError::Invalid { reason: e.to_string() })?;
    let inv = self.inner.groups().invite(&gid).await.map_err(ChatFfiError::from)?;
    Ok(inv.0) // verify GroupInvite's public accessor
}
```

(Implementer: verify `GroupInvite`'s constructor from a `String` and its inner accessor; verify `identity_arc()`/`agent_id()` shape used in `run_inbound_pump`; `GroupId`/`AgentId` parse signatures per E1.)

- [ ] **Step 6: Gate.** `cargo fmt -p fetchit-ffi && cargo clippy -p fetchit-ffi --all-targets -- -D warnings && cargo test -p fetchit-ffi`. Expected: clean + green.

- [ ] **Step 7: Commit.** `git commit -s -m "feat(ffi): group create/join/send/list/invite surface"`.

---

## Task 4: FFI -- group RECEIVE (drop the daemonless skip, wire the seam)

**Files:**
- Modify: `crates/fetchit-ffi/src/chat_ffi.rs` (`ChatEventFfi` enum ~18-53; `run_inbound_pump` ~548-676; the skip ~601-607)
- Test: inline `#[cfg(test)]`

**Context:** Mirror the LOCKED desktop seam (Alice, `chat.rs:2078-2128`): `is_private_group_envelope -> self-source filter -> empty-group_id guard -> receive_private_group_envelope -> Persisted=surface / Replay=drop / Err=warn`, NO receipt. The current skip (`chat_ffi.rs:601-607`) logs + `continue`s; replace it.

- [ ] **Step 1: Add the event variant (failing test).** Add to `ChatEventFfi`:

```rust
/// An inbound private-group message (decrypted via in-process x0xd).
GroupMessage {
    /// 64-hex group id.
    group_id: String,
    /// 64-hex sender agent id (ML-DSA verified).
    from_agent_id_hex: String,
    /// Sender display name at send time, if any.
    sender_name: Option<String>,
    /// Plaintext body.
    body: String,
    /// Dedupe/message id.
    message_id: Option<String>,
},
```

Write a unit test over a seam helper `fn project_group_receive(group_id, outcome) -> Option<ChatEventFfi>` asserting `Persisted(entry) -> Some(GroupMessage{..})`, `Replay -> None`.

- [ ] **Step 2: Run, watch fail.** `cargo test -p fetchit-ffi group_receive`. Expected: FAIL.

- [ ] **Step 3: Implement the seam.** Replace the skip block (`chat_ffi.rs:601-607`) with:

```rust
// M2 private-group receive: decrypt via in-process x0xd /secure/decrypt
// and surface a GroupMessage. Mirrors the desktop handle_inbound seam and
// peer.rs decode_private_group: self-source filter, empty-group_id guard,
// then receive_private_group_envelope -> Persisted=surface / Replay=drop /
// Err=warn-never-crash. No DeliveryReceipt for group messages.
if is_private_group_envelope(&transit) {
    let group_id_hex = transit.group_id.as_ref().map(|g| hex::encode(g.as_bytes())).unwrap_or_default();
    if group_id_hex.is_empty() {
        log::warn!("[chat_ffi] private-group envelope without group_id; dropping");
        continue;
    }
    // (self-source already filtered above via route_envelope SelfSource.)
    match client.messages().receive_private_group_envelope(&transit, &group_id_hex).await {
        Ok(fetchit_chat::messages::PrivateGroupReceive::Persisted(entry)) => {
            let _ = tx.send(ChatEventFfi::GroupMessage {
                group_id: group_id_hex,
                from_agent_id_hex: entry.sender_agent_id_hex,
                sender_name: entry.sender_name,
                body: entry.body,
                message_id: Some(entry.message_id),
            });
        }
        Ok(fetchit_chat::messages::PrivateGroupReceive::Replay) => {}
        Err(e) => log::warn!("[chat_ffi] private_group_decrypt_failed: {e}"),
    }
    continue;
}
```

(Implementer: confirm `route_envelope` already drops `SelfSource` before this point -- E3 shows it does (`EnvelopeRoute::SelfSource => continue`); if not, add `if sender_hex == self_hex { continue; }`. Confirm `HistoryEntry` field names per E1: `sender_agent_id_hex`, `sender_name: Option<String>`, `body`, `message_id`.)

- [ ] **Step 4: Run, watch pass.** Expected: PASS.

- [ ] **Step 5: Gate + commit.** `cargo fmt/clippy -D warnings/test -p fetchit-ffi`. `git commit -s -m "feat(ffi): receive + surface inbound private-group messages"`.

---

## Task 5: Regenerate bindings + arm64 cross-build

**Files:** `apps/fetchit-android/app/src/main/jniLibs/arm64-v8a/libfetchit_ffi.so` (gitignored), `apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt` (committed).

- [ ] **Step 1: Build.** Run `./scripts/build-jni-libs.sh` (cargo ndk arm64-v8a release + uniffi-bindgen kotlin). Requires `ANDROID_NDK_HOME=~/Android/Sdk/ndk/27.0.12077973`, `cargo-ndk`, `uniffi-bindgen-cli` matching uniffi 0.29.5. HEAVY (x0x stack) -- DISK WATCH (`df -h /home/josh`). Expected: new `.so` + regenerated `fetchit_ffi.kt`.

- [ ] **Step 2: Verify the new Kotlin surface.** Confirm `fetchit_ffi.kt` now contains `ChatEventFfi.GroupMessage`, `GroupFfi`, and the `createGroup`/`joinGroup`/`sendGroupMessage`/`listGroups`/`groupInvite` methods on `ChatClient`. (Do NOT hand-edit -- it is generated.)

- [ ] **Step 3: Commit the binding.** `git add apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt && git commit -s -m "chore(android): regenerate uniffi bindings for group surface"`. (The `.so` is gitignored; note its rebuilt size in the commit body.)

---

## Task 6: Kotlin -- gateway, store, controller group wiring

**Files:**
- Modify: `.../chat/ChatGateway.kt` (interface ~8-49; impl ~52-63)
- Modify: `.../chat/ConversationStore.kt` (key ~26-27, 33-38)
- Modify: `.../chat/ChatController.kt` (`pumpEvents` ~182-223; load groups in `ensureGateway` ~92-115)
- Test: `apps/fetchit-android/app/src/test/java/.../chat/` (JVM unit tests; `testImplementation org.json:json` per the known stub gotcha)

- [ ] **Step 1: Gateway methods (failing test).** Add to the `ChatGateway` interface + `FfiChatGateway` impl: `suspend fun createGroup(name: String, displayName: String?, private: Boolean): GroupFfi`, `joinGroup(invite, displayName)`, `sendGroupMessage(groupId, body, senderName): String?`, `listGroups(): List<GroupFfi>`, `groupInvite(groupId): String`. Write a fake-gateway test asserting delegation.

- [ ] **Step 2-4: Fail -> implement (delegate to `ChatClient`) -> pass.** Run: `./gradlew :app:testDebugUnitTest --tests '*Gateway*'`.

- [ ] **Step 5: Generalize the conversation key.** In `ConversationStore`, the key is currently `peerAgentIdHex`. Use group ids as keys with a non-colliding prefix to avoid DM/group collision. Add a small helper `convKeyGroup(groupId) = "g:$groupId"` and `convKeyDm(agentId) = agentId` (DM keys stay bare for back-compat) -- OR a `sealed class ConvKey`. Keep it minimal: a `g:` prefix on group keys is enough for v1. Write a test that a group message and a DM with the same hex do not collide.

- [ ] **Step 6: Handle the group event in `pumpEvents`.** Add the case (mirrors the `Dm` arm at `ChatController.kt:207-216`):

```kotlin
is ChatEventFfi.GroupMessage -> convo.append(
    "g:${ev.groupId}",
    ChatMessage(
        outbound = false,
        body = ev.body,
        sentAtMs = System.currentTimeMillis(),
        messageId = ev.messageId,
        senderAgentIdHex = ev.fromAgentIdHex, // add this optional field to ChatMessage for group sender attribution
    ),
)
```

(Add an optional `senderAgentIdHex: String? = null` to `ChatMessage` so group bubbles can show who sent them; DMs leave it null. Update `MessageAdapter.bindDm` to show the sender label when non-null -- small additive change.)

- [ ] **Step 7: Load groups on connect.** In `ensureGateway` (after the pump is RUNNING), call `gw.listGroups()` and seed group conversations (title = `name ?: groupId.take(8)`), mirroring desktop `loadGroups`. Store in a `StateFlow<List<GroupFfi>>` on the controller for the list screen.

- [ ] **Step 8: Gate + commit.** `./gradlew :app:testDebugUnitTest`. `git commit -s -m "feat(android): wire group events + gateway + conversation keys"`.

---

## Task 7: Kotlin UI -- create/join + group thread (reuse conversation screen)

**Files:**
- Modify: `.../chat/ChatModeView.kt` (`Screen` ~71-75; `openThread` ~175-177; `bindThreadScreen` ~348-409; `inflateListScreen` ~235-306; `ContactListAdapter` ~685-764)
- New: `.../chat/NewGroupDialog.kt`, `.../chat/JoinGroupDialog.kt`

- [ ] **Step 1: Add the screen variant.** In `sealed class Screen`, add `data class GroupThread(val groupId: String) : Screen()`. Add `openGroupThread(groupId: String)` pushing it.

- [ ] **Step 2: List-screen entry points.** Add "New group" + "Join group" rows (or a FAB menu) to `inflateListScreen` / `ContactListAdapter`. "New group" opens `NewGroupDialog` (name input + a private/public toggle defaulting to private) -> `gw.createGroup(name, myDisplayName, private)` -> on success, `openGroupThread(group.groupId)` + offer to share `gw.groupInvite(groupId)` via the existing QR/share path. "Join group" opens `JoinGroupDialog` (paste `x0x://invite/...`, validate prefix) -> `gw.joinGroup(uri, myDisplayName)` -> `openGroupThread`. Mirror `showAddContactDialog` (`ChatModeView.kt:323-344`).

- [ ] **Step 3: Group thread screen.** Add `bindGroupThreadScreen(groupId: String)` by copying `bindThreadScreen` and: title from the loaded `GroupFfi.name` (fallback short id); send wired to `gw.sendGroupMessage(groupId, body, senderName)` (DIRECT send, no outbox for groups in v1 -- matches desktop); collect `controller.conversations.messagesFor("g:$groupId")`. Reuse `MessageAdapter` unchanged (bubbles are peer-type agnostic).

- [ ] **Step 4: Show groups in the list.** Render the controller's groups `StateFlow` as conversation rows (last-message preview via `messagesFor("g:$id")`), tapping -> `openGroupThread`.

- [ ] **Step 5: JVM tests where feasible** (dialog validation, screen-state transitions). Run: `./gradlew :app:testDebugUnitTest`.

- [ ] **Step 6: Build the APK.** Run: `cd apps/fetchit-android && ./gradlew :app:assembleDebug`. Expected: BUILD SUCCESSFUL.

- [ ] **Step 7: Commit.** `git commit -s -m "feat(android): create/join group UI + group thread screen"`.

---

## Task 8: Full gates + integrated review + device-smoke plan

- [ ] **Step 1: Engine + FFI gates** (worktree): `cargo fmt --all --check` (the workspace CI gate), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, plus `cargo clippy -p fetchit-ffi --all-targets -- -D warnings && cargo test -p fetchit-ffi` (excluded crate).
- [ ] **Step 2: Android gates:** `./gradlew :app:testDebugUnitTest` + `:app:assembleDebug`; confirm bindings byte-stable vs the committed `.kt` (no drift) or recommit.
- [ ] **Step 3: Integrated self-review** of the whole stack (Bob): the receive seam matches the engine invariant; no `unwrap/expect/panic` outside tests; docs-comments truthful; em-dash scrub (`! grep -rn "\xe2\x80\x94" <changed files>`).
- [ ] **Step 4: Ping Alice** to cross-review the FFI receive-wiring against the shared `receive_private_group_envelope` seam (the cross-shell invariant).
- [ ] **Step 5: Write the device-smoke plan** (`docs/superpowers/plans/2026-06-15-android-groups-device-smoke.md`): create a PQ group on Android, share invite to desktop, desktop joins, bidirectional send/receive both directions decrypt + render; verify a card-less joiner decrypts (Option-B auto-resolve); confirm DM path unaffected. Hand to Josh for on-device run.

---

## Self-Review (writing-plans)

- **Spec coverage:** create (Task 3/7), join (3/7), send (1+3+7, routed correctly via `send_to_group` -- NOT the broken `groups().send`), receive (4+6), list/enumerate (3+6+7), in-process x0xd foundation (2), bindings (5), gates (8). Covered.
- **Type consistency:** `GroupKind{Private,Public}` (engine) -> `Confidentiality{MlsEncrypted,SignedPublic}` (x0xd-client) -> `GroupFfi.is_private: Option<bool>` (FFI) -> Kotlin `GroupFfi`. `send_to_group(group_id, body, sender_name)` signature identical across engine/FFI/desktop. `ChatEventFfi::GroupMessage` fields match `HistoryEntry` (sender_agent_id_hex, sender_name, body, message_id).
- **Known verification points flagged inline** (not placeholders): exact `DaemonConfig`/`ExecPolicy` field names in the fork, `GroupInvite` constructor/accessor, the x0xd `confidentiality` serde spelling, the `ServerHandle` shutdown API. Each is a concrete "confirm X at Y" step the implementer resolves against named files.
- **Risk:** the FFI x0x build is heavy (ant-quic + saorsa-gossip) -- monitor disk each build. Task 1 must land on chat before Alice's desktop #56 wire; halt after Task 1 push for her cross-review.
