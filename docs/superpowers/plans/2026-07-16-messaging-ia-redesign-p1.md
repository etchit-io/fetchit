# Messaging IA Redesign — P1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single buried chat list with a three-tab messaging shell (Chats · People · Feed) whose Chats tab shows every conversation — private DMs, private groups, and fediverse threads — in one list, and whose People tab is the front door for finding, following, and messaging anyone.

**Architecture:** Engine gains a read-only overview of the sealed fedi thread store and a bridge fetch for the follower list; the bridge gains an owner-authed followers endpoint and a real follower count on its public collection; the FFI surfaces both. The Android shell gets a `BottomNavigationView` inside the existing `chatContainer`, three tab-root views (Chats reworked, People new, Feed on a real layout), and a unified conversation-row model. No new crypto, wire formats, or relay/x0x changes — P1 composes existing primitives.

**Tech Stack:** Rust (`fetchit-chat`, `fetchit-bridge-server`, `fetchit-ffi` via uniffi 0.29), Kotlin + classic Android Views + Material Components 1.12.0, JUnit4 pure-JVM unit tests.

## Global Constraints

- **Rust lints are `-D warnings` in CI.** Workspace forbids `unsafe_code`; warns (=error under `-D`) on `clippy::pedantic`, `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro`, `missing_docs`, `unreachable_pub`. Every `pub` item needs a `///` doc. `unwrap()`/`expect()`/`panic!()` are allowed **only** in `#[cfg(test)]` modules, which open with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
- **`fetchit-ffi` is workspace-excluded** with its own `Cargo.lock`. Build/test it from inside `crates/fetchit-ffi/` — `cargo` from the repo root does not touch it.
- **The Android `.so` embeds uniffi API checksums verified at launch.** Any FFI signature change requires regenerating both the `.so` and the Kotlin bindings together via `./scripts/build-jni-libs.sh` (run from `fetchit/`), or the app crashes on launch. After regen, compile **including unit-test sources** (`compileDebugUnitTestKotlin`) — a signature break passes `compileDebugKotlin`/`assembleDebug` but fails CI.
- **arm64-v8a only.** No x86_64.
- **Brand mark:** always `fetch>it` with a copper `>` in UI copy; never bare "fetchit". Copy is plain, grandma-legible.
- **Branch `messaging-ia-redesign`.** Every task commits here with DCO sign-off (`git commit -s`). Nothing merges to `main` until the P1 device-smoke gate (Task 11) passes.
- **Before any push:** `cargo fmt --all --check` (workspace) and `cargo clippy --workspace --all-targets -- -D warnings` must be clean.

---

### Task 1: Engine — fedi thread overview

**Files:**
- Modify: `crates/fetchit-chat/src/fedi_thread.rs` (add `FediThreadSummary` + `FediThreads::overview`)
- Modify: `crates/fetchit-chat/src/fedi_dm.rs` (add `Client::fedi_threads_overview` next to `fedi_thread_history`)
- Test: `crates/fetchit-chat/src/fedi_thread.rs` (`#[cfg(test)]` module already present)

**Interfaces:**
- Consumes: existing `FediThreads { cursor_ms, threads: BTreeMap<String, Vec<FediThreadMsg>> }`, `load_fedi_threads(handle, master, layout)`, `Client::fedi_at_rest() -> Result<(MasterKey, StoreLayout)>`.
- Produces: `FediThreadSummary { label: String, last_body: String, last_at_ms: i64, last_outbound: bool }`; `FediThreads::overview(&self) -> Vec<FediThreadSummary>` (one per non-empty thread, sorted by `last_at_ms` descending, ties broken by `label` ascending for determinism); `Client::fedi_threads_overview(&self, handle: &str) -> Result<Vec<FediThreadSummary>>`.

- [ ] **Step 1: Write the failing test for `overview`**

Add to the `#[cfg(test)]` module in `crates/fetchit-chat/src/fedi_thread.rs`:

```rust
#[test]
fn overview_is_one_row_per_thread_newest_first() {
    let mut t = FediThreads::default();
    // happyborg: last activity at 200 (an inbound reply)
    t.insert("@happyborg@fosstodon.org", outbound("s1", 100));
    t.fold_inbox(&[inbound(
        "https://fosstodon.org/users/happyborg",
        "r1",
        200,
    )]);
    // stranger: last activity at 150
    t.fold_inbox(&[inbound("https://mas.to/users/stranger", "r2", 150)]);

    let ov = t.overview();
    assert_eq!(ov.len(), 2, "one summary per thread");
    // newest-first: happyborg (200) before stranger (150)
    assert_eq!(ov[0].label, "happyborg@fosstodon.org");
    assert_eq!(ov[0].last_at_ms, 200);
    assert_eq!(ov[0].last_body, "body of r1");
    assert!(!ov[0].last_outbound, "last row was an inbound reply");
    assert_eq!(ov[1].label, "stranger@mas.to");
    assert_eq!(ov[1].last_at_ms, 150);
}

#[test]
fn overview_skips_empty_threads_and_is_deterministic_on_ties() {
    let mut t = FediThreads::default();
    // Two threads with the same last_at_ms — label breaks the tie.
    t.insert("@bbb@h", outbound("s1", 100));
    t.insert("@aaa@h", outbound("s2", 100));
    let ov = t.overview();
    assert_eq!(
        ov.iter().map(|s| s.label.as_str()).collect::<Vec<_>>(),
        vec!["aaa@h", "bbb@h"],
        "equal timestamps sort by label ascending",
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p fetchit-chat overview_is_one_row_per_thread -- --nocapture`
Expected: FAIL — `no method named \`overview\`` / `cannot find type \`FediThreadSummary\``.

- [ ] **Step 3: Implement `FediThreadSummary` + `overview`**

In `crates/fetchit-chat/src/fedi_thread.rs`, after the `FediThreads` struct's `impl` block (or extend it), add the type and method:

```rust
/// A one-line summary of a fediverse DM thread, for the unified
/// conversation list. Derived from the last message in each thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FediThreadSummary {
    /// Canonical correspondent label (`user@host`), the `f:<label>`
    /// conversation key without the prefix.
    pub label: String,
    /// The most recent message's plain-text body — the list preview.
    pub last_body: String,
    /// The most recent message's ordering stamp — the list sort key.
    pub last_at_ms: i64,
    /// `true` when the most recent message was sent by this device.
    pub last_outbound: bool,
}
```

Add this method inside `impl FediThreads`:

```rust
/// One [`FediThreadSummary`] per non-empty thread, newest activity
/// first (ties broken by label ascending so the order is stable). The
/// render source for fediverse rows in the unified conversation list.
#[must_use]
pub fn overview(&self) -> Vec<FediThreadSummary> {
    let mut out: Vec<FediThreadSummary> = self
        .threads
        .iter()
        .filter_map(|(label, msgs)| {
            let last = msgs.last()?;
            Some(FediThreadSummary {
                label: label.clone(),
                last_body: last.text.clone(),
                last_at_ms: last.at_ms,
                last_outbound: last.outbound,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.last_at_ms
            .cmp(&a.last_at_ms)
            .then_with(|| a.label.cmp(&b.label))
    });
    out
}
```

Threads are kept time-sorted by `insert`, so `msgs.last()` is the newest message.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p fetchit-chat overview_ -- --nocapture`
Expected: PASS (both `overview_*` tests).

- [ ] **Step 5: Add the `Client::fedi_threads_overview` accessor**

In `crates/fetchit-chat/src/fedi_dm.rs`, add this method inside `impl Client` (next to `fedi_thread_history`), and import the type at the top (`use crate::fedi_thread::{... , FediThreadSummary};`):

```rust
/// Every fediverse DM thread as a one-line summary, newest first —
/// the render source for fediverse rows in the unified conversation
/// list. A device with no minted handle has no threads.
///
/// # Errors
/// [`ChatError`] on store load failures.
pub fn fedi_threads_overview(&self, handle: &str) -> Result<Vec<FediThreadSummary>> {
    let (master, layout) = self.fedi_at_rest()?;
    Ok(load_fedi_threads(handle, &master, &layout)?.overview())
}
```

- [ ] **Step 6: Verify the crate builds clean and commit**

Run: `cargo test -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings`
Expected: tests PASS, clippy clean.

```bash
git add crates/fetchit-chat/src/fedi_thread.rs crates/fetchit-chat/src/fedi_dm.rs
git commit -s -m "feat(chat): fedi thread overview for the unified conversation list"
```

---

### Task 2: Bridge — owner-authed followers list + real public count

**Files:**
- Modify: `crates/fetchit-bridge-server/src/routes/follow.rs` (add `followers_list` handler)
- Modify: `crates/fetchit-bridge-server/src/routes/actors.rs` (replace `followers` empty stub with a real-count collection)
- Modify: `crates/fetchit-bridge-server/src/server.rs` (register the new route)
- Test: `crates/fetchit-bridge-server/tests/` (whichever integration test file exercises follow routes; if none targets followers, add `followers_list.rs`)

**Interfaces:**
- Consumes: existing `Store::followers_list(actor_id) -> Vec<String>`, `auth_actor(state, handle, headers, method, path, body) -> Result<ActorRecord, Response>`, `state.store.actor_by_handle(handle)`.
- Produces: route `GET /actors/:handle/followers/list` returning `{"items":[{"follower_actor_url": "<url>"}...]}` (owner-authed, newest first); public `GET /actors/:handle/followers` now returns `totalItems` = real count with `orderedItems: []`.

- [ ] **Step 1: Write the failing test for the owner-authed list**

The bridge's existing route tests build a `Router` via `Server::router` and drive it with `tower::ServiceExt::oneshot`. Find the existing follow-route test (grep `following/list\|following_list\|record_follow` under `crates/fetchit-bridge-server/tests/`) and mirror its setup helpers (actor registration + a signed `bridge-auth-v1` request). Add:

```rust
#[tokio::test]
async fn followers_list_is_owner_authed_and_lists_rows() {
    let (router, state) = test_router().await; // mirror existing helper
    let (handle, signer) = register_test_actor(&router, &state).await; // mirror existing helper

    // Seed two followers directly through the store.
    state
        .store
        .add_follower(
            &agent_id_for(&handle),
            "https://fosstodon.org/users/happyborg",
            "https://fosstodon.org/users/happyborg/inbox",
            1000,
        )
        .await
        .unwrap();
    state
        .store
        .add_follower(
            &agent_id_for(&handle),
            "https://mas.to/users/stranger",
            "https://mas.to/users/stranger/inbox",
            2000,
        )
        .await
        .unwrap();

    // Unauthed request is rejected.
    let path = format!("/actors/{handle}/followers/list");
    let unauthed = router
        .clone()
        .oneshot(get_request(&path, /* headers */ None))
        .await
        .unwrap();
    assert_eq!(unauthed.status(), StatusCode::UNAUTHORIZED);

    // Owner-authed request lists both, newest first.
    let signed = signed_get(&signer, &handle, &path); // mirror existing helper
    let resp = router.clone().oneshot(signed).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(resp).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["follower_actor_url"], "https://mas.to/users/stranger");
}

#[tokio::test]
async fn public_followers_collection_reports_real_count_without_enumerating() {
    let (router, state) = test_router().await;
    let (handle, _signer) = register_test_actor(&router, &state).await;
    state
        .store
        .add_follower(&agent_id_for(&handle), "https://mas.to/users/x", "https://mas.to/users/x/inbox", 1)
        .await
        .unwrap();

    let resp = router
        .oneshot(get_request(&format!("/actors/{handle}/followers"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["totalItems"], 1, "count is real");
    assert_eq!(body["orderedItems"].as_array().unwrap().len(), 0, "never enumerated publicly");
}
```

> Use the exact helper names the existing follow-route test defines. If the existing tests live in a `#[cfg(test)] mod` inside `routes/follow.rs` rather than `tests/`, add these there instead and reuse its in-module helpers.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p fetchit-bridge-server followers_list_is_owner_authed`
Expected: FAIL — route returns 404 (no such route) or the public-count test sees `totalItems: 0`.

- [ ] **Step 3: Implement the owner-authed list handler**

In `crates/fetchit-bridge-server/src/routes/follow.rs`, add:

```rust
/// `GET /actors/:handle/followers/list` — owner-only list of the
/// accounts following this handle. The PUBLIC AP `followers` collection
/// (in [`crate::routes::actors`]) serves only a count; who follows a
/// user is not publicly enumerable, so this authed route is the one that
/// returns rows. `bridge-auth-v1`, newest first.
pub async fn followers_list(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
    headers: HeaderMap,
) -> Response {
    let path = format!("/actors/{handle}/followers/list");
    let rec = match auth_actor(&state, &handle, &headers, &Method::GET, &path, b"").await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state.store.followers_list(&rec.agent_id).await {
        Ok(list) => {
            let items: Vec<_> = list
                .iter()
                .map(|url| json!({ "follower_actor_url": url }))
                .collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "followers_list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}
```

- [ ] **Step 4: Implement the real-count public collection**

In `crates/fetchit-bridge-server/src/routes/actors.rs`, replace the `followers` handler (keep `outbox` on `empty_collection`):

```rust
/// `GET /actors/:handle/followers` — the public AP collection. Serves
/// the REAL follower count (`totalItems`) but never enumerates rows
/// (`orderedItems` stays empty); the owner reads the list through the
/// authed `/followers/list` route.
pub async fn followers(
    State(state): State<Arc<BridgeState>>,
    Path(handle): Path<String>,
) -> impl IntoResponse {
    let rec = match state.store.actor_by_handle(&handle).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such actor").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "actor_by_handle failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
        }
    };
    let count = state
        .store
        .followers_list(&rec.agent_id)
        .await
        .map(|l| l.len())
        .unwrap_or(0);
    let body = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}/followers", rec.actor_url),
        "type": "OrderedCollection",
        "totalItems": count,
        "orderedItems": []
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/activity+json")],
        body.to_string(),
    )
        .into_response()
}
```

- [ ] **Step 5: Register the new route**

In `crates/fetchit-bridge-server/src/server.rs`, add to the router (next to the other `/actors/:handle/followers...` routes):

```rust
.route(
    "/actors/:handle/followers/list",
    get(routes::follow::followers_list),
)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p fetchit-bridge-server followers`
Expected: PASS (both new tests + the existing follower tests untouched).

- [ ] **Step 7: Full bridge suite + clippy, then commit**

Run: `cargo test -p fetchit-bridge-server && cargo clippy -p fetchit-bridge-server --all-targets -- -D warnings`
Expected: the full bridge suite is green (was 53 tests; now +2) and clippy clean.

```bash
git add crates/fetchit-bridge-server/src/routes/follow.rs crates/fetchit-bridge-server/src/routes/actors.rs crates/fetchit-bridge-server/src/server.rs crates/fetchit-bridge-server/tests/
git commit -s -m "feat(bridge): owner-authed followers list + real public follower count"
```

---

### Task 3: Engine — fetch follower list from the bridge

**Files:**
- Modify: `crates/fetchit-chat/src/fedi_follow.rs` (add `Client::fetch_fedi_followers` + deserialize structs next to `list_fedi_following`)

**Interfaces:**
- Consumes: existing `self.load_actor_identity(handle)`, `actor_origin(&identity)`, `canonical_request("GET", &path, now_ms, b"")`, `self.bridge_auth_sign(&canonical)`, `crate::relay_http::guarded_client()`, the header consts `HEADER_AGENT`/`HEADER_TS`/`HEADER_SIG`, `B64`. The bridge contract from Task 2 (`GET /actors/{handle}/followers/list` → `{"items":[{"follower_actor_url": "..."}]}`).
- Produces: `Client::fetch_fedi_followers(&self, handle: &str, now_ms: u64) -> Result<Vec<String>>` returning follower actor URLs, newest first.

This mirrors `list_fedi_following` exactly (same auth + transport). There is no unit test — like `list_fedi_following`, it is an integration path against a live bridge; its contract is covered by Task 2's bridge tests. Gate on a clean build.

- [ ] **Step 1: Add the deserialize struct + method**

In `crates/fetchit-chat/src/fedi_follow.rs`, add near the other `*ListBody` structs:

```rust
/// Body of the bridge `GET /actors/:handle/followers/list` response.
#[derive(serde::Deserialize)]
struct FollowersListBody {
    items: Vec<FollowerEntry>,
}

/// One row of the followers list.
#[derive(serde::Deserialize)]
struct FollowerEntry {
    follower_actor_url: String,
}
```

Add this method inside `impl Client` (immediately after `list_fedi_following`):

```rust
/// The accounts following our actor `handle`, as recorded at the
/// bridge (owner-only view; the public AP collection serves counts
/// alone). Fetched under `bridge-auth-v1`. Returns follower actor
/// URLs, newest first.
///
/// # Errors
/// [`ChatError::Invalid`] on a missing minted identity, transport
/// failure, a non-2xx bridge answer, or a malformed response body.
pub async fn fetch_fedi_followers(
    &self,
    handle: &str,
    now_ms: u64,
) -> Result<Vec<String>> {
    let identity = self.load_actor_identity(handle).await?.ok_or_else(|| {
        ChatError::Invalid(format!(
            "no fediverse actor identity minted for handle {handle}"
        ))
    })?;
    let origin = actor_origin(&identity)?;
    let path = format!("/actors/{handle}/followers/list");
    let canonical = canonical_request("GET", &path, now_ms, b"");
    let (agent_id_hex, sig) = self.bridge_auth_sign(&canonical).await?;

    let http = crate::relay_http::guarded_client();
    let resp = http
        .get(format!("{origin}{path}"))
        .header(HEADER_AGENT, agent_id_hex)
        .header(HEADER_TS, now_ms.to_string())
        .header(HEADER_SIG, B64.encode(&sig))
        .send()
        .await
        .map_err(|e| ChatError::Invalid(format!("bridge followers GET: {e}")))?;
    if !resp.status().is_success() {
        return Err(ChatError::Invalid(format!(
            "bridge followers list: HTTP {}",
            resp.status().as_u16()
        )));
    }
    let body: FollowersListBody = resp
        .json()
        .await
        .map_err(|e| ChatError::Invalid(format!("bridge followers decode: {e}")))?;
    Ok(body.items.into_iter().map(|e| e.follower_actor_url).collect())
}
```

- [ ] **Step 2: Build + clippy the crate**

Run: `cargo test -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings`
Expected: builds clean, existing tests still pass, clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/fetchit-chat/src/fedi_follow.rs
git commit -s -m "feat(chat): fetch fedi follower list from the bridge (owner-authed)"
```

---

### Task 4: FFI surface + Kotlin bindings regen + gateway wiring

**Files:**
- Modify: `crates/fetchit-ffi/src/chat_ffi.rs` (new record `FediThreadSummaryFfi`, methods `fedi_threads_overview` + `fedi_followers`)
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatGateway.kt` (interface + adapter)
- Generated (do not hand-edit): `apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt`, `app/src/main/jniLibs/arm64-v8a/*.so`

**Interfaces:**
- Consumes: `Client::fedi_threads_overview` (Task 1), `Client::fetch_fedi_followers` (Task 3), existing `self.fedi_actor_status() -> Option<String>`, `crate::fedi_feed::author_label`, `FediThreadSummary` fields.
- Produces (uniffi → Kotlin camelCase): `FediThreadSummaryFfi { label, lastBody, lastAtMs, lastOutbound }`; `ChatClient.fediThreadsOverview(): List<FediThreadSummaryFfi>`; `ChatClient.fediFollowers(): List<String>`. Gateway: `ChatGateway.fediThreadsOverview()`, `ChatGateway.fediFollowers()`.

- [ ] **Step 1: Add the FFI record**

In `crates/fetchit-ffi/src/chat_ffi.rs`, near the other fedi records (`FediFollowingFfi`, `FediPostFfi`):

```rust
/// One fediverse DM thread summarised for the unified conversation
/// list — mirrors [`fetchit_chat::fedi_thread::FediThreadSummary`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FediThreadSummaryFfi {
    /// Canonical `user@host` label (the `f:<label>` conversation key body).
    pub label: String,
    /// Newest message body — the list preview.
    pub last_body: String,
    /// Newest message stamp (epoch ms) — the list sort key.
    pub last_at_ms: i64,
    /// `true` when the newest message was outbound.
    pub last_outbound: bool,
}
```

- [ ] **Step 2: Add the two methods**

Inside the `#[uniffi::export(async_runtime = "tokio")] impl ChatClient` block, near `fedi_following`/`fedi_sync_inbox`:

```rust
/// Every fediverse DM thread as a one-line summary, newest first, for
/// the unified conversation list. A device with no minted handle has
/// no threads and returns an empty list (quiet-hydrate contract —
/// never an error).
///
/// # Errors
/// [`ChatFfiError`] on a thread-store load failure.
pub async fn fedi_threads_overview(&self) -> Result<Vec<FediThreadSummaryFfi>, ChatFfiError> {
    let Some(handle) = self.fedi_actor_status() else {
        return Ok(Vec::new());
    };
    let rows = self
        .inner
        .fedi_threads_overview(&handle)
        .map_err(ChatFfiError::from)?;
    Ok(rows
        .into_iter()
        .map(|s| FediThreadSummaryFfi {
            label: s.label,
            last_body: s.last_body,
            last_at_ms: s.last_at_ms,
            last_outbound: s.last_outbound,
        })
        .collect())
}

/// The accounts following the minted handle, as `@user@host` labels,
/// from the directory's owner-only list. Throws when no handle is
/// minted or the directory is unreachable (mirrors [`Self::fedi_following`]).
///
/// # Errors
/// [`ChatFfiError`] when no handle is minted or the fetch fails.
pub async fn fedi_followers(&self) -> Result<Vec<String>, ChatFfiError> {
    let handle = self
        .fedi_actor_status()
        .ok_or_else(|| ChatFfiError::Invalid {
            reason: "no fediverse handle minted".to_owned(),
        })?;
    let now_ms = now_ms();
    let urls = self
        .inner
        .fetch_fedi_followers(&handle, now_ms)
        .await
        .map_err(ChatFfiError::from)?;
    Ok(urls
        .iter()
        .map(|u| fetchit_chat::fedi_feed::author_label(u))
        .collect())
}
```

> `now_ms()` is the same helper `fedi_follow`/`fedi_dm` FFI methods already call — check the surrounding methods for its exact name (`now_ms()` free fn in this module) and reuse it verbatim.

- [ ] **Step 3: Build the FFI crate (own Cargo.lock, from its own dir)**

Run: `(cd crates/fetchit-ffi && cargo build)`
Expected: compiles clean. (This crate is workspace-excluded; do not run it from the repo root.)

- [ ] **Step 4: Regenerate the `.so` + Kotlin bindings**

Run (from `fetchit/`): `./scripts/build-jni-libs.sh`
Expected: rebuilds `app/src/main/jniLibs/arm64-v8a/libuniffi_fetchit_ffi.so` and regenerates `uniffi/fetchit_ffi/fetchit_ffi.kt`. Confirm the generated `.kt` now contains `class FediThreadSummaryFfi`, `fun fediThreadsOverview`, and `fun fediFollowers`:

```bash
grep -c "fediThreadsOverview\|fediFollowers\|FediThreadSummaryFfi" apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt
```
Expected: ≥ 3.

- [ ] **Step 5: Wire the gateway**

In `ChatGateway.kt`, add imports (`import uniffi.fetchit_ffi.FediThreadSummaryFfi`), add to the `interface ChatGateway`:

```kotlin
    /**
     * Every fediverse DM thread as a one-line summary for the unified
     * conversation list, newest first. Empty when no handle is minted
     * (quiet — never throws for that).
     */
    suspend fun fediThreadsOverview(): List<FediThreadSummaryFfi>

    /**
     * The `@user@host` labels of accounts following the minted handle,
     * newest first. Throws when no handle is minted or the directory is
     * unreachable.
     */
    suspend fun fediFollowers(): List<String>
```

And to `class FfiChatGateway`:

```kotlin
    override suspend fun fediThreadsOverview(): List<FediThreadSummaryFfi> =
        inner.fediThreadsOverview()
    override suspend fun fediFollowers(): List<String> = inner.fediFollowers()
```

- [ ] **Step 6: Compile Android including test sources**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin)`
Expected: BUILD SUCCESSFUL — the regenerated bindings match the `.so` and the gateway compiles.

- [ ] **Step 7: Commit (Rust + regenerated bindings + gateway together)**

```bash
git add crates/fetchit-ffi/src/chat_ffi.rs \
  apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt \
  apps/fetchit-android/app/src/main/jniLibs/arm64-v8a/ \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatGateway.kt
git commit -s -m "feat(ffi): fedi thread overview + follower list; regen bindings"
```

---

### Task 5: Unified conversation-row model (pure Kotlin)

**Files:**
- Create: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatRowModel.kt`
- Test: `apps/fetchit-android/app/src/test/java/io/etchit/fetchit/chat/ChatRowModelTest.kt`

**Interfaces:**
- Consumes: `GroupFfi` (has `groupId`, `isPrivate`), `ChatContact` (has `agentIdHex`, `displayName`), `FediThreadSummaryFfi` (Task 4: `label`, `lastBody`, `lastAtMs`, `lastOutbound`).
- Produces: sealed `ChatRow` (`Contact`, `Group`, `Fedi` variants each carrying a preview + `sortMs`); `fun buildChatRows(contacts, groups, groupPreview, contactPreview, fediThreads): List<ChatRow>` sorted newest-first. `groupPreview`/`contactPreview` are `(key) -> Pair<String, Long>?` lookups (preview body + last stamp) so the model stays pure and testable without the live `ConversationStore`.

- [ ] **Step 1: Write the failing test**

Create `apps/fetchit-android/app/src/test/java/io/etchit/fetchit/chat/ChatRowModelTest.kt`:

```kotlin
package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.fetchit_ffi.FediThreadSummaryFfi

class ChatRowModelTest {

    private fun fedi(label: String, atMs: Long) =
        FediThreadSummaryFfi(label = label, lastBody = "hi $label", lastAtMs = atMs, lastOutbound = false)

    @Test
    fun rowsAreSortedNewestFirstAcrossAllKinds() {
        val contacts = listOf(ChatContact(agentIdHex = "a".repeat(64), displayName = "Mum", addedAtMs = 0L))
        val fedi = listOf(fedi("happyborg@fosstodon.org", 300))
        // Contact "Mum" last spoke at 500 -> should sort above the fedi thread at 300.
        val rows = buildChatRows(
            contacts = contacts,
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { key -> if (key.contains("a".repeat(64))) "see you sunday" to 500L else null },
            fediThreads = fedi,
        )
        assertEquals(2, rows.size)
        assertEquals("Mum", (rows[0] as ChatRow.Contact).contact.displayName)
        assertEquals("happyborg@fosstodon.org", (rows[1] as ChatRow.Fedi).summary.label)
    }

    @Test
    fun aFediThreadWithNoContactsStillProducesARow() {
        // The unseen-correspondent gap: a fedi thread must appear even with
        // zero private contacts and zero groups.
        val rows = buildChatRows(
            contacts = emptyList(),
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { null },
            fediThreads = listOf(fedi("stranger@mas.to", 100)),
        )
        assertEquals(1, rows.size)
        assertEquals("stranger@mas.to", (rows[0] as ChatRow.Fedi).summary.label)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `(cd apps/fetchit-android && ./gradlew :app:testDebugUnitTest --tests "io.etchit.fetchit.chat.ChatRowModelTest")`
Expected: FAIL — `ChatRow` / `buildChatRows` unresolved.

- [ ] **Step 3: Implement the model**

Create `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatRowModel.kt`:

```kotlin
package io.etchit.fetchit.chat

import uniffi.fetchit_ffi.FediThreadSummaryFfi
import uniffi.fetchit_ffi.GroupFfi

/**
 * One row in the unified Chats list. Private DMs and private groups
 * carry a lock; fediverse threads carry a globe. Each row knows its
 * own sort stamp so the whole list orders by most-recent activity
 * regardless of kind.
 */
sealed interface ChatRow {
    /** Sort key: last-activity epoch ms, newest first. */
    val sortMs: Long

    /** A private (PQ) direct message thread. */
    data class Contact(val contact: ChatContact, val preview: String, override val sortMs: Long) : ChatRow

    /** A private/public group thread. */
    data class Group(val group: GroupFfi, val preview: String, override val sortMs: Long) : ChatRow

    /** A fediverse (plaintext-rails) DM thread. */
    data class Fedi(val summary: FediThreadSummaryFfi, override val sortMs: Long) : ChatRow
}

/**
 * Build the unified, most-recent-first conversation list from the three
 * sources. [groupPreview] and [contactPreview] resolve a conversation
 * key to its `(previewBody, lastStampMs)`, or null when the thread has
 * no messages yet — passed in so this stays a pure function over the
 * live [ConversationStore]. A source with no messages sorts oldest
 * (stamp 0) rather than being dropped, so a brand-new contact/group
 * still shows.
 */
fun buildChatRows(
    contacts: List<ChatContact>,
    groups: List<GroupFfi>,
    groupPreview: (convKey: String) -> Pair<String, Long>?,
    contactPreview: (convKey: String) -> Pair<String, Long>?,
    fediThreads: List<FediThreadSummaryFfi>,
): List<ChatRow> {
    val rows = ArrayList<ChatRow>(contacts.size + groups.size + fediThreads.size)
    groups.forEach { g ->
        val (body, ms) = groupPreview(ConversationStore.convKeyGroup(g.groupId)) ?: ("" to 0L)
        rows.add(ChatRow.Group(g, body, ms))
    }
    contacts.forEach { c ->
        val (body, ms) = contactPreview(ConversationStore.convKeyDm(c.agentIdHex)) ?: ("" to 0L)
        rows.add(ChatRow.Contact(c, body, ms))
    }
    fediThreads.forEach { t ->
        rows.add(ChatRow.Fedi(t, t.lastAtMs))
    }
    // Newest first; ties keep insertion order (groups, then contacts, then fedi)
    // via a stable sort.
    return rows.sortedByDescending { it.sortMs }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `(cd apps/fetchit-android && ./gradlew :app:testDebugUnitTest --tests "io.etchit.fetchit.chat.ChatRowModelTest")`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatRowModel.kt \
  apps/fetchit-android/app/src/test/java/io/etchit/fetchit/chat/ChatRowModelTest.kt
git commit -s -m "feat(android): pure unified conversation-row model + tests"
```

---

### Task 6: Bottom-tab scaffold + tab host + persistence

**Files:**
- Modify: `apps/fetchit-android/app/src/main/res/layout/activity_main.xml` (add `BottomNavigationView` inside `chatContainer`)
- Create: `apps/fetchit-android/app/src/main/res/menu/chat_tabs.xml`
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/SettingsStore.kt` (persist selected tab)
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt` (tab roots + tab-bar show/hide)
- Modify: `apps/fetchit-android/app/src/main/res/values/strings.xml` (tab labels)

**Interfaces:**
- Consumes: existing `chatScreenSlot`, `Screen` sealed class, `showScreen`, `SettingsStore` SharedPreferences pattern (`lastMode`/`saveLastMode`).
- Produces: `Screen.Chats`/`Screen.People`/`Screen.Feed` tab roots (replacing `Screen.List`); tab bar visible only on roots; `SettingsStore.lastChatTab()`/`saveLastChatTab(id)`.

This task is UI structure — verified by compile + on-device smoke, not a unit test (view inflation and `BottomNavigationView` need an Activity). The persistence add mirrors the existing `SettingsStoreTest` harness; add a test only if that harness is Robolectric-backed (it is if `SettingsStoreTest` runs under `:app:testDebugUnitTest`).

- [ ] **Step 1: Tab labels + menu**

Add to `res/values/strings.xml`:

```xml
<string name="tab_chats">Chats</string>
<string name="tab_people">People</string>
<string name="tab_feed">Feed</string>
```

Create `res/menu/chat_tabs.xml` (icons: reuse existing `ic_people` for People; use `@android:drawable/ic_dialog_email`-class placeholders only if no brand icon exists — prefer existing `ic_*` drawables, grep `res/drawable` for `ic_chat`, `ic_people`, `ic_feed`/`ic_public`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<menu xmlns:android="http://schemas.android.com/apk/res/android">
    <item android:id="@+id/tabChats" android:title="@string/tab_chats" android:icon="@drawable/ic_chat" />
    <item android:id="@+id/tabPeople" android:title="@string/tab_people" android:icon="@drawable/ic_people" />
    <item android:id="@+id/tabFeed" android:title="@string/tab_feed" android:icon="@drawable/ic_public" />
</menu>
```

> If any `ic_chat`/`ic_people`/`ic_public` drawable is missing, add a minimal vector drawable for it in `res/drawable/` (24dp, `?attr/fetchitCopper` tint via the nav view). Do not block on iconography — a simple glyph vector is fine for P1.

- [ ] **Step 2: Add the `BottomNavigationView` to the chat container**

In `activity_main.xml`, inside the `chatContainer`'s vertical `LinearLayout`, **after** the `chatScreenSlot` `FrameLayout` (so it sits at the bottom), add:

```xml
<com.google.android.material.bottomnavigation.BottomNavigationView
    android:id="@+id/chatTabBar"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:background="?attr/fetchitInk2"
    app:menu="@menu/chat_tabs"
    app:labelVisibilityMode="labeled"
    app:itemTextColor="?attr/fetchitCopper"
    app:itemIconTint="?attr/fetchitCopper" />
```

- [ ] **Step 3: Persist the selected tab**

In `SettingsStore.kt`, mirror `lastMode`/`saveLastMode`:

```kotlin
/** Last-selected chat tab id name ("chats" | "people" | "feed"); defaults to "chats". */
fun lastChatTab(): String = prefs.getString(KEY_LAST_CHAT_TAB, "chats").orEmpty().ifEmpty { "chats" }

/** Persist the last-selected chat tab so re-entry restores it. */
fun saveLastChatTab(tab: String) {
    prefs.edit().putString(KEY_LAST_CHAT_TAB, tab).apply()
}
```

Add the key constant next to the other `KEY_*`: `private const val KEY_LAST_CHAT_TAB = "last_chat_tab"`.

- [ ] **Step 4: Replace `Screen.List` with three tab roots + tab-bar control**

In `ChatModeView.kt`:

1. Change the `Screen` sealed class:

```kotlin
private sealed class Screen {
    data object Chats : Screen()
    data object People : Screen()
    data object Feed : Screen()
    data class Thread(val peer: String) : Screen()
    data class GroupThread(val groupId: String) : Screen()
    data class FediThread(val handle: String) : Screen()
}
```

2. Add a `tabBar` field resolved in the constructor from `container`:

```kotlin
private val tabBar: com.google.android.material.bottomnavigation.BottomNavigationView =
    container.findViewById(R.id.chatTabBar)
```

3. Wire tab selection once (in `init` or the first `onShown`), mapping menu ids to roots and persisting:

```kotlin
private fun wireTabs() {
    tabBar.setOnItemSelectedListener { item ->
        when (item.itemId) {
            R.id.tabChats -> { showRoot(Screen.Chats); SettingsStore(context).saveLastChatTab("chats") }
            R.id.tabPeople -> { showRoot(Screen.People); SettingsStore(context).saveLastChatTab("people") }
            R.id.tabFeed -> { showRoot(Screen.Feed); SettingsStore(context).saveLastChatTab("feed") }
        }
        true
    }
}

/** Show a tab root: reset the stack to just this root and reveal the tab bar. */
private fun showRoot(root: Screen) {
    screenStack.clear()
    showScreen(root, pushToStack = true)
    tabBar.visibility = View.VISIBLE
}
```

4. In `showScreen`, add `Chats`/`People`/`Feed` arms and hide the tab bar on pushed (thread) screens. `Chats` reuses the existing list inflation (rename `inflateListScreen` usage under the new `Screen.Chats` arm; keep its body for Task 7). `People` inflates a placeholder for now (`TextView("People")` — replaced in Task 9). `Feed` keeps calling `bindFeedScreen()` (real layout comes in Task 8). Each thread arm sets `tabBar.visibility = View.GONE` at entry.

5. Update `onShown` to restore the persisted tab and select it on the bar:

```kotlin
fun onShown() {
    wireTabs()
    val tab = when (SettingsStore(context).lastChatTab()) {
        "people" -> R.id.tabPeople
        "feed" -> R.id.tabFeed
        else -> R.id.tabChats
    }
    if (tabBar.selectedItemId != tab) tabBar.selectedItemId = tab else showRoot(rootFor(tab))
    lifecycleScope.launch { connectWithFeedback() }
}
```

(Add a small `rootFor(id)` helper mapping menu id → `Screen`.)

6. Update `onBack`: a pushed screen pops back to its tab root (revealing the bar); on a tab root, return `false` (exit to browse) — the tab bar is not a back target. The existing `screenStack` logic already pops; ensure popping to a root re-shows `tabBar`.

7. Everywhere `showList()` / `Screen.List` was referenced (e.g. `importFromUri`, `linkDeviceFromUri`), replace with `showRoot(Screen.Chats)`.

- [ ] **Step 5: Compile including test sources**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin)`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Device smoke**

Build + install: `(cd apps/fetchit-android && ./gradlew :app:assembleDebug && adb install -r app/build/outputs/apk/debug/app-debug.apk)`
On device, in messaging mode verify:
- The bottom bar shows three tabs; tapping each switches the root.
- Opening a conversation hides the bar; back reveals it on the owning tab.
- Killing + reopening the app restores the last-selected tab.

- [ ] **Step 7: Commit**

```bash
git add apps/fetchit-android/app/src/main/res/layout/activity_main.xml \
  apps/fetchit-android/app/src/main/res/menu/chat_tabs.xml \
  apps/fetchit-android/app/src/main/res/values/strings.xml \
  apps/fetchit-android/app/src/main/res/drawable/ \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/SettingsStore.kt \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt
git commit -s -m "feat(android): three-tab messaging scaffold (Chats/People/Feed) + tab persistence"
```

---

### Task 7: Unified Chats list — render fedi threads, delete the pinned row

**Files:**
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt` (`ContactListAdapter`, `Row`, list collectors)

**Interfaces:**
- Consumes: `buildChatRows` (Task 5), `ChatRow` (Task 5), `controller.fediThreadsOverview()` via gateway (Task 4), `controller.conversations.messagesFor(key)`, `ConversationStore.convKeyGroup/convKeyDm`, `openFediThread(handle)` (exists).
- Produces: a Chats list whose rows are `ChatRow.Contact/Group/Fedi`, sorted newest-first; the pinned `Row.Fediverse` row is removed; tapping a fedi row opens its `FediThread`.

- [ ] **Step 1: Replace the adapter's row model**

Delete `Row.Fediverse` and the `FeedViewHolder`/`TYPE_FEED` path. Rebuild `ContactListAdapter` around `ChatRow` (Task 5): three view types (Contact / Group / Fedi), each bound from a `ChatRow`. The Fedi holder renders 🌐 in the id slot, the label as the name, `summary.lastBody` as the preview; tap → `onFediTap(summary.label)`. Contact/Group holders keep their existing bind bodies (lift verbatim), now reading from `ChatRow.Contact.preview` / `ChatRow.Group.preview` instead of recomputing.

- [ ] **Step 2: Feed fedi threads into the list collector**

In the list-inflation collector (currently `controller.contacts.contacts.combine(controller.groups)`), also pull the fedi overview each emission and call `buildChatRows`:

```kotlin
listContactsJob = lifecycleScope.launch {
    controller.contacts.contacts
        .combine(controller.groups) { contacts, groups -> contacts to groups }
        .collect { (contacts, groups) ->
            val fedi = runCatching { controller.gateway()?.fediThreadsOverview() }.getOrNull().orEmpty()
            val rows = buildChatRows(
                contacts = contacts,
                groups = groups,
                groupPreview = { key ->
                    controller.conversations.messagesFor(key).value.lastOrNull()
                        ?.let { it.body to it.sentAtMs }
                },
                contactPreview = { key ->
                    controller.conversations.messagesFor(key).value.lastOrNull()
                        ?.let { it.body to it.sentAtMs }
                },
                fediThreads = fedi,
            )
            val empty = rows.isEmpty()
            rv.visibility = if (empty) View.GONE else View.VISIBLE
            emptyState.visibility = if (empty) View.VISIBLE else View.GONE
            addBtn.visibility = if (empty) View.GONE else View.VISIBLE
            adapter.submit(rows)
        }
}
```

> `ChatMessage` exposes `sentAtMs` and `body` (confirm the field names in `chat/ChatMessage.kt`; the DM send path already reads `sentAtMs`). Use those exact names.

The empty-state now triggers only when there are zero rows of **any** kind (so a lone fedi thread keeps the list visible).

- [ ] **Step 3: Sync fedi threads on entry so they're fresh**

In the `Screen.Chats` arm (or `showRoot(Screen.Chats)`), kick a background `fediSyncInbox()` then let the collector re-emit (the overview reads the durable store the sync just updated). Reuse the existing `refreshPulledFeed`-style quiet pattern:

```kotlin
private fun syncFediThreadsQuietly() {
    if (controller.fediActorStatus() == null) return
    lifecycleScope.launch {
        val gw = runCatching { connectWithFeedback() }.getOrElse { return@launch }
        runCatching { gw.fediSyncInbox() }
        // Nudge the list to rebuild with the freshly-synced overview.
        controller.contacts.bump() // or re-emit; see note
    }
}
```

> If `ChatContactStore` has no re-emit trigger, instead collect the fedi overview in its own `StateFlow` on the controller and `combine` it into the list collector, so a sync updates the flow and the list rebuilds. Prefer that (cleaner than poking the contacts flow) — add `ChatController.fediThreads: StateFlow<List<FediThreadSummaryFfi>>` refreshed by a `refreshFediThreads()` that calls the gateway, and `combine` it in Step 2 instead of the inline `runCatching`.

- [ ] **Step 4: Compile including test sources**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin :app:testDebugUnitTest)`
Expected: BUILD SUCCESSFUL, `ChatRowModelTest` green.

- [ ] **Step 5: Device smoke**

Build + install (as Task 6 Step 6). Verify:
- Chats shows private DMs, groups, and fediverse threads in one list, newest first.
- No "Public posts" pinned row remains.
- The happyborg fedi thread appears in Chats without opening the feed; tapping it opens the fedi thread.
- A device with a fedi thread but zero contacts still shows that thread (not the empty state).

- [ ] **Step 6: Commit**

```bash
git add apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatController.kt
git commit -s -m "feat(android): unified Chats list with fediverse threads; drop pinned feed row"
```

---

### Task 8: Feed tab on a real layout

**Files:**
- Create: `apps/fetchit-android/app/src/main/res/layout/view_feed.xml`
- Create: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/FeedTabView.kt`
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt` (Feed arm → `FeedTabView`; remove `bindFeedScreen`'s thread-XML reuse + the people-door + @handle header)

**Interfaces:**
- Consumes: `controller.feed.posts` (Flow), `controller.fediActorStatus()`, `blockStore.isBlocked`, `refreshPulledFeed()` logic (lift), `bindFeedCompose`/`showFediMintDialog` (lift), `MessageAdapter` + `MessageRow.Post`.
- Produces: `FeedTabView` bound into the Feed tab root, rendering a post list + a compose box (handle present) or a single mint card (no handle). Author taps route to the profile card (Task 9 provides `showProfileCard`; until then, tap opens the fedi thread via `openFediThread(label)`).

- [ ] **Step 1: Create `view_feed.xml`**

A vertical layout: a top compose slot (`FrameLayout id=feedComposeSlot`), then a `RecyclerView id=feedList` (weight 1). No back button, no members button, no thread header — this is a root screen with the tab bar beneath it. Follow the palette attrs used elsewhere (`?attr/fetchitInk`, `?attr/fetchitBone`, `?attr/fetchitAsh`).

- [ ] **Step 2: Extract `FeedTabView`**

Move the feed logic out of `ChatModeView.bindFeedScreen` into `FeedTabView.kt`: the `feedCollectJob` post collector, `refreshPulledFeed`, `parseIsoToMs`, and compose binding. In the no-handle state, inflate the mint card (`chat_onboard_fediverse` mint dialog trigger) into `feedComposeSlot` instead of the compose row. Drop the `threadMembersButton`/people-door wiring and the `renderFediHubHeader` call — People owns the social graph now.

- [ ] **Step 3: Point the Feed tab arm at `FeedTabView`**

In `ChatModeView.showScreen`, the `Screen.Feed` arm inflates `view_feed.xml` and binds `FeedTabView`. Delete the old `bindFeedScreen` (thread-XML reuse) and its `feedView` cache field. Keep `feedCollectJob` cancellation discipline (cancel on leaving the tab).

- [ ] **Step 4: Compile including test sources**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin)`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Device smoke**

Build + install. Verify:
- Feed tab shows posts on a feed layout (not a chat thread), compose at top when a handle exists.
- With no handle, the compose slot shows the single mint card; minting reveals compose in place.
- No people icon / @handle header on Feed anymore.
- Feed pull still works (posts from followed accounts appear); blocked authors stay filtered.

- [ ] **Step 6: Commit**

```bash
git add apps/fetchit-android/app/src/main/res/layout/view_feed.xml \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/FeedTabView.kt \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt
git commit -s -m "feat(android): Feed tab on a real feed layout; drop thread-XML reuse"
```

---

### Task 9: People tab

**Files:**
- Create: `apps/fetchit-android/app/src/main/res/layout/view_people.xml`
- Create: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/PeopleTabView.kt`
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt` (People arm → `PeopleTabView`; lift `showFediPeopleSheet` rendering)
- Modify: `apps/fetchit-android/app/src/main/res/values/strings.xml` (People search hint)

**Interfaces:**
- Consumes: `classifyAddContactInput` (exists), `controller.contacts.contacts`, `controller.gateway().fediFollowing()`, `controller.gateway().fediFollowers()` (Task 4), `blockStore` (following/blocked rendering exists in `showFediPeopleSheet`), `fediLookup`/profile flows, `onLaunchScanner`.
- Produces: `PeopleTabView` bound into the People tab root; a full-screen People page (search field on top; Your contacts, Following, Followers, Blocked sections); `showProfileCard(handle/actorUrl)` reused by Feed author taps.

- [ ] **Step 1: Create `view_people.xml`**

Vertical: a search row at top (`EditText id=peopleSearch` full-width + a `Button id=peopleScan` "⌖"), then a scrolling container (`LinearLayout id=peopleSections` inside a `ScrollView`) the code fills with section headers + rows. Palette-consistent.

- [ ] **Step 2: Extract + expand into `PeopleTabView`**

Lift the section-rendering logic from `ChatModeView.showFediPeopleSheet` (the `renderFollowing`/`renderBlocked` closures) into `PeopleTabView`, and add:
- **Search** (top): reuse `classifyAddContactInput` — a `PairUri` routes to `importFromUri`; a `FediHandle` routes to `fediLookup` → profile card. Scan button calls `onLaunchScanner`.
- **Your contacts** section: from `controller.contacts.contacts`, each row taps to `openThread(agentIdHex)`, overflow → existing rename/remove menu.
- **Following** section: from `fediFollowing()` (existing render), each row → profile card.
- **Followers** section: from `fediFollowers()` (Task 4) — real rows now; empty copy `fedi_people_followers_empty`.
- **Blocked** section: existing `renderBlocked`.

Add `showProfileCard(...)`: a bottom-sheet with the person's handle + actions message / follow-or-unfollow / block. Reuse the existing per-row action closures from `showFediPeopleSheet` so behavior is identical; this task only relocates + adds the followers section and the search field.

- [ ] **Step 3: Point the People tab arm at `PeopleTabView`**

In `ChatModeView.showScreen`, the `Screen.People` arm inflates `view_people.xml` and binds `PeopleTabView`. Delete the now-duplicated `showFediPeopleSheet` (its logic now lives in `PeopleTabView`), and repoint the Feed author-tap (Task 8) to `PeopleTabView.showProfileCard`.

- [ ] **Step 4: Add the search hint string**

```xml
<string name="people_find_hint">find someone — @name or paste a link</string>
```

- [ ] **Step 5: Compile including test sources**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin)`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Device smoke**

Build + install. Verify:
- People tab: search finds `@happyborg@fosstodon.org` and opens a profile card with message/follow/block.
- Contacts, Following, Followers, Blocked sections render; Followers shows real rows (not the old "no followers yet" stub when you have one).
- **Reachability check (spec §15 P1 gate):** a fedi DM is reachable in ≤ 3 taps from messaging entry — People → tap person → Message.

- [ ] **Step 7: Commit**

```bash
git add apps/fetchit-android/app/src/main/res/layout/view_people.xml \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/PeopleTabView.kt \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt \
  apps/fetchit-android/app/src/main/res/values/strings.xml
git commit -s -m "feat(android): People tab — search, contacts, following, real followers, blocked"
```

---

### Task 10: New-chat sheet (FAB)

**Files:**
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt` (FAB → new-chat sheet)
- Modify: `apps/fetchit-android/app/src/main/res/values/strings.xml` (sheet copy)

**Interfaces:**
- Consumes: `classifyAddContactInput`, `importFromUri`, `fediLookup`, `onLaunchScanner`, `controller.contacts.contacts`, `controller.gateway().fediFollowing()`, `showProfileCard` (Task 9).
- Produces: a single "+ New chat" bottom sheet: one input field (name or pasted link) + scan + a tappable list of the user's people.

- [ ] **Step 1: Rebuild the FAB action as the new-chat sheet**

The Chats FAB (`addContactButton`) currently opens a small actions popup (`showListActionsMenu`). Replace its action with a `showNewChatSheet()` bottom sheet:
- One `EditText` (hint `chat_new_chat_hint`) + a "done" action → `classifyAddContactInput`: `PairUri` → `importFromUri`; `FediHandle` → `fediLookup` → profile card.
- A "scan a code" button → `onLaunchScanner`.
- A "create a group" row → existing `showNewGroupDialog`.
- Below: the user's people (contacts, then following) each tappable to open/start the right thread.

Keep `showNewGroupDialog`, `showAddContactDialog` internals reachable (the sheet composes them); only the entry affordance changes.

- [ ] **Step 2: Add sheet copy**

```xml
<string name="chat_new_chat_fab">New chat</string>
<string name="chat_new_chat_hint">type a name, or paste an invite link</string>
<string name="chat_new_chat_scan">scan a code</string>
```

Set the FAB text to `@string/chat_new_chat_fab`.

- [ ] **Step 3: Compile including test sources**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin)`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Device smoke**

Build + install. Verify from Chats:
- FAB "+ New chat" opens the sheet; typing a name resolves a person; pasting a pair link imports; scan opens the scanner; the people list taps through.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt \
  apps/fetchit-android/app/src/main/res/values/strings.xml
git commit -s -m "feat(android): unified + New chat sheet (name, link, scan, people)"
```

---

### Task 11: Empty-state relabel, full gates, device smoke, Alice handoff

**Files:**
- Modify: `apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatModeView.kt` (empty-state button targets)
- Modify: `apps/fetchit-android/app/src/main/res/values/strings.xml` (any residual copy)
- Modify: `fetchit/docs/ARCHITECTURE.md` + `apps/fetchit-android`-relevant section of `CLAUDE.md` if the Android internals paragraph names the old single-screen model (docs track code).

**Interfaces:**
- Consumes: everything from Tasks 6–10.
- Produces: a coherent P1 build passing all gates + the spec §15 P1 device-smoke checklist; a clean handoff to Alice for the desktop mirror.

- [ ] **Step 1: Relabel the empty-state third button per spec §4**

The empty state's fediverse button: no handle → "Get your @handle" switches to the **People** tab (mint card on top); minted → "See public posts" switches to the **Feed** tab. Update `bindOnboardFediCopy` targets accordingly (previously both went to the old feed screen).

- [ ] **Step 2: Update docs that name the old IA**

If `CLAUDE.md`'s "Android shell internals" paragraph or `docs/ARCHITECTURE.md` describes the single-screen chat list / pinned fediverse row, update it to the three-tab model (Chats/People/Feed, unified list). This is required — docs track code and the `docs-gates` CI job checks for stale phrases.

- [ ] **Step 3: Full workspace gates**

Run:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd crates/fetchit-ffi && cargo build)
(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin :app:testDebugUnitTest :app:assembleDebug)
```
Expected: all clean/green.

- [ ] **Step 4: Full P1 device smoke (spec §15 gate)**

Install the assembled debug APK and verify end-to-end:
- Three tabs; each root reachable; tab bar hides in threads, back returns to the owning tab; last tab restored on relaunch.
- Chats: private DMs, groups, and fedi threads in one newest-first list; no pinned "Public posts" row; a never-added fedi correspondent's thread is visible.
- People: search reaches a person in ≤ 3 taps to Message; Followers shows real rows.
- Feed: real feed layout; compose or mint card; posts still pull; blocked filtered.
- New-chat sheet: name / link / scan / people all work.
- **Regression sweep:** send + receive a private DM; create + send to a private group; send a fedi DM — all unregressed.

- [ ] **Step 5: Commit + push the branch**

```bash
git add -A
git commit -s -m "feat(android): P1 messaging IA — empty-state targets + docs; full gates green"
git push -u origin messaging-ia-redesign
```

- [ ] **Step 6: Sync Alice for the desktop mirror + cross-review**

Send (via `claude-tx-send`, no backticks/`>`/`|`/`!`): P1 landed on `messaging-ia-redesign` at HEAD SHA; engine/FFI/bridge additions are shell-agnostic and ready for the desktop mirror (spec §11); request her cross-review of the bridge followers route + the FFI additions (established sensitive-work rule). Note the branch does not merge to main until Josh signs off on the device build.

---

## P1 completion

When all tasks are done: the messaging entry lands on Chats with every conversation in one list; People is the discoverable front door for finding/following/messaging anyone; Feed is content on its own layout. Go-private escalation (P2) and fedi-rail group invites (P3) are separate plans against this branch.
