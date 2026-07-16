# Messaging IA Redesign — P2 Implementation Plan (Go Private)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user turn a fediverse conversation into a private, post-quantum (PQ) LIT chat with one in-thread button — an invite sent over the fediverse, a human-confirmed link, and the same chat row flipping 🌐 → 🔒 in place — without ever silently downgrading a private conversation back to plaintext.

**Architecture:** A new engine-owned sealed person-link store (fedi handle ↔ agent id) records the go-private lifecycle; the invite is a `send_fedi_dm` carrying the existing pair link; linking is a manual "Same person?" confirm (the pair link crossed a server in the clear, so a human is the trust anchor). Once linked, the unified Chats list collapses the pair to one 🔒 row backed by a merged render (fedi history read-only above a divider, PQ below), and the linked thread offers — never forces — a fediverse fallback when the private rail is down.

**Tech Stack:** Rust (`fetchit-chat`, `fetchit-ffi` via uniffi 0.29), Kotlin + classic Android Views + Material 1.12.0, JUnit4 pure-JVM unit tests. Depends on P1 (`messaging-ia-redesign` @ 04105cf) and the spec §7/§8 (as amended 142a966).

## Global Constraints

- **Rust lints are `-D warnings`.** Forbid `unsafe_code`; `unwrap`/`expect`/`panic`/`todo`/`missing_docs` only in `#[cfg(test)]` (which opens `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`). Every `pub` item needs a `///`.
- **`fetchit-ffi` is workspace-excluded** (own `Cargo.lock`); build/test from inside `crates/fetchit-ffi/`. FFI signature changes require `./scripts/build-jni-libs.sh` (regenerates `.so` + Kotlin bindings together) or the app crashes at launch; after regen, compile **including test sources** (`compileDebugUnitTestKotlin`).
- **Adding a method to `ChatGateway`** breaks the two test doubles in `ChatControllerTest.kt` (`FakeGateway` + the anonymous gateway) — update both, or `compileDebugUnitTestKotlin` fails.
- **Branch `messaging-ia-redesign`.** DCO sign-off (`git commit -s`). Nothing merges to main until the P2 device gate + Josh sign-off. `cargo fmt --all --check` (+ a separate `cargo fmt --check` inside `crates/fetchit-ffi`) and per-crate `clippy -D warnings` before every push.
- **Verify by artifact, not exit code:** gradle piped through `grep`/`tail` reports the pipe's exit; read the real `BUILD SUCCESSFUL`/`BUILD FAILED` line and the `.so`/bindings content.

## Security invariants (non-negotiable — the reason P2 exists in this shape)

1. **No auto-downgrade.** A 🔒 (linked) thread's composer is PQ-only and NEVER silently falls back to the fediverse. A silent downgrade turns an outage — or an adversary jamming the private rail — into an eavesdropping opportunity, and makes the badge a lie. Fallback is a per-message, explicitly-labeled user choice (§7.6).
2. **Linking is human-confirmed, never automatic.** The pair link crossed the recipient's server in plaintext; anyone who saw it can import it. Auto-linking would hand an impersonator a verified-looking @handle. The "Same person?" confirm is the trust step. LIT and fedi identities still share no keys; the link is local-only and never published.
3. **Lock-row contract:** a 🔒 row's composer produces only PQ traffic. Fedi sends to a linked person exist only behind an out-of-the-way "message on fediverse" action.
4. **Sealed at rest:** the person-link store uses the existing master key + atomic-write pattern; no new plaintext at rest.

## File structure

- Create `crates/fetchit-chat/src/fedi_link.rs` — sealed person-link store + `Client` accessors.
- Modify `crates/fetchit-chat/src/local_store.rs` — `StoreLayout::fedi_links_path`.
- Modify `crates/fetchit-chat/src/lib.rs` — `mod fedi_link;` + re-exports.
- Modify `crates/fetchit-ffi/src/chat_ffi.rs` — `FediPersonLinkFfi` + 5 methods.
- Modify `apps/.../chat/ChatGateway.kt` — interface + adapter + the 2 test doubles.
- Modify `apps/.../chat/ChatController.kt` — `personLinks` StateFlow + refresh.
- Modify `apps/.../chat/ChatRowModel.kt` + `ChatRowModelTest.kt` — link-aware dedup.
- Modify `apps/.../chat/ChatModeView.kt` — go-private button, link-confirm, merged thread, fallback banner, group-invite-over-fedi.
- Modify `apps/.../res/values/strings.xml` — the §12 P2 strings.

---

### Task 1: Engine person-link store (sealed)

**Files:**
- Create: `crates/fetchit-chat/src/fedi_link.rs`
- Modify: `crates/fetchit-chat/src/local_store.rs` (add `fedi_links_path`)
- Modify: `crates/fetchit-chat/src/lib.rs` (`mod fedi_link;`)

**Interfaces:**
- Consumes: `crate::at_rest::MasterKey`, `crate::fedi_identity::derive_fedi_vault_key`, `crate::fedi_vault::{read_sealed, write_sealed_atomic}`, `crate::fedi_thread::canonical_thread_label`, `StoreLayout`.
- Produces: `PersonLink { invited_at_ms: Option<i64>, agent_id_hex: Option<String>, linked_at_ms: Option<i64> }`; `FediLinks { links: BTreeMap<String, PersonLink> }` with `record_invite(label, at_ms)`, `link(label, agent_id_hex, at_ms) -> bool`, `unlink(label)`, `pending() -> Vec<String>`, `get(label) -> Option<PersonLink>`, `is_linked_agent(agent_id_hex) -> Option<String>` (reverse lookup: agent id → linked label); `load_fedi_links`/`save_fedi_links`; magic `FFL1`, AAD `fetchit-fedi-links-v1`.

- [ ] **Step 1: Write the failing tests**

Create `crates/fetchit-chat/src/fedi_link.rs` with a `#[cfg(test)]` module (mirror `fedi_thread.rs`'s test scaffolding — `MasterKey::from_bytes_for_test`, `tempdir`, `StoreLayout::ensure`):

```rust
#[test]
fn lifecycle_none_invited_linked() {
    let mut l = FediLinks::default();
    assert!(l.pending().is_empty());
    l.record_invite("@happyborg@fosstodon.org", 100);
    assert_eq!(l.pending(), vec!["happyborg@fosstodon.org"]); // invited, not linked
    assert!(l.link("HappyBorg@Fosstodon.org", "aa".repeat(32).as_str(), 200));
    assert!(l.pending().is_empty(), "linked drops out of pending");
    let got = l.get("happyborg@fosstodon.org").unwrap();
    assert_eq!(got.agent_id_hex.as_deref(), Some("aa".repeat(32).as_str()));
    assert_eq!(l.is_linked_agent(&"aa".repeat(32)).as_deref(), Some("happyborg@fosstodon.org"));
    l.unlink("happyborg@fosstodon.org");
    assert!(l.get("happyborg@fosstodon.org").map_or(true, |p| p.agent_id_hex.is_none()));
    assert!(l.is_linked_agent(&"aa".repeat(32)).is_none());
}

#[test]
fn save_and_load_round_trip_sealed() {
    let dir = tempdir().unwrap();
    let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
    let master = MasterKey::from_bytes_for_test([0x42; AEAD_KEY_LEN]);
    let mut l = FediLinks::default();
    l.record_invite("a@h", 1);
    l.link("a@h", &"bb".repeat(32), 2);
    save_fedi_links("josh", &l, &master, &layout).unwrap();
    let back = load_fedi_links("josh", &master, &layout).unwrap();
    assert_eq!(back.get("a@h").unwrap().agent_id_hex, Some("bb".repeat(32)));
    let raw = std::fs::read(layout.fedi_links_path("josh")).unwrap();
    assert_eq!(&raw[..4], FEDI_LINKS_MAGIC);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fetchit-chat lifecycle_none_invited_linked`
Expected: FAIL — `fedi_link` module / symbols missing.

- [ ] **Step 3: Implement the store**

Mirror `fedi_thread.rs` structure exactly. Key bodies:

```rust
//! Durable at-rest store for the fediverse↔LIT person links (M7 P4).
//! One sealed file per minted handle records the go-private lifecycle
//! (`none → invited → linked`) so the Chats list can collapse a linked
//! pair to one 🔒 row. Same seal shape / derived key as
//! [`crate::fedi_thread`], distinct magic + AAD.

use crate::at_rest::MasterKey;
use crate::error::ChatError;
use crate::fedi_identity::derive_fedi_vault_key;
use crate::fedi_thread::canonical_thread_label;
use crate::fedi_vault::{read_sealed, write_sealed_atomic};
use crate::local_store::StoreLayout;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// File magic identifying a Fetchit Fedi Links v1 file.
pub const FEDI_LINKS_MAGIC: &[u8; 4] = b"FFL1";
/// AAD bound into every seal/open — domain-separated from the thread store.
pub const FEDI_LINKS_AAD: &[u8] = b"fetchit-fedi-links-v1";

/// The go-private state for one fediverse correspondent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonLink {
    /// When a go-private invite was last delivered (`None` = never).
    #[serde(default)]
    pub invited_at_ms: Option<i64>,
    /// The PQ agent id this handle is linked to (`None` = not linked).
    #[serde(default)]
    pub agent_id_hex: Option<String>,
    /// When the link was confirmed.
    #[serde(default)]
    pub linked_at_ms: Option<i64>,
}

/// All person links for one minted handle, keyed by canonical label.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FediLinks {
    #[serde(default)]
    pub links: BTreeMap<String, PersonLink>,
}

impl FediLinks {
    /// Record that a go-private invite was delivered to `label`.
    pub fn record_invite(&mut self, label: &str, at_ms: i64) {
        self.links
            .entry(canonical_thread_label(label))
            .or_default()
            .invited_at_ms = Some(at_ms);
    }

    /// Confirm a link from `label` to `agent_id_hex`. Returns `true` when
    /// this created or changed the link.
    pub fn link(&mut self, label: &str, agent_id_hex: &str, at_ms: i64) -> bool {
        let e = self.links.entry(canonical_thread_label(label)).or_default();
        let changed = e.agent_id_hex.as_deref() != Some(agent_id_hex);
        e.agent_id_hex = Some(agent_id_hex.to_owned());
        e.linked_at_ms = Some(at_ms);
        changed
    }

    /// Drop the link (keeps invite history for the re-open flow).
    pub fn unlink(&mut self, label: &str) {
        if let Some(e) = self.links.get_mut(&canonical_thread_label(label)) {
            e.agent_id_hex = None;
            e.linked_at_ms = None;
        }
    }

    /// Labels invited but not yet linked.
    #[must_use]
    pub fn pending(&self) -> Vec<String> {
        self.links
            .iter()
            .filter(|(_, p)| p.invited_at_ms.is_some() && p.agent_id_hex.is_none())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The link record for `label`.
    #[must_use]
    pub fn get(&self, label: &str) -> Option<PersonLink> {
        self.links.get(&canonical_thread_label(label)).cloned()
    }

    /// Reverse lookup: the canonical label linked to `agent_id_hex`, if any.
    #[must_use]
    pub fn is_linked_agent(&self, agent_id_hex: &str) -> Option<String> {
        self.links
            .iter()
            .find(|(_, p)| p.agent_id_hex.as_deref() == Some(agent_id_hex))
            .map(|(k, _)| k.clone())
    }
}
```

Add `load_fedi_links`/`save_fedi_links` copied from `fedi_thread.rs`'s load/save, swapping magic/AAD/path (`layout.fedi_links_path(handle)`).

In `local_store.rs`, next to `fedi_threads_path`:

```rust
/// Sealed person-link store for `handle` (`<root>/fedi/links/<handle>.json.enc`).
#[must_use]
pub fn fedi_links_path(&self, handle: &str) -> PathBuf {
    self.fedi_dir
        .join("links")
        .join(format!("{}.json.enc", crate::fedi_thread::canonical_thread_label(handle)))
}
```

> Confirm `fedi_threads_path` creates the `threads/` subdir on write via `write_sealed_atomic`'s parent-mkdir (check `write_sealed_atomic` — if it does not `create_dir_all` the parent, add a `std::fs::create_dir_all(parent)` there or in `save_fedi_links`). Mirror whatever `save_fedi_threads` relies on.

In `lib.rs`, add `mod fedi_link;` and re-export `pub use fedi_link::{FediLinks, PersonLink};` alongside the fedi_thread re-exports.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-chat fedi_link:: && cargo test -p fetchit-chat lifecycle_none_invited_linked save_and_load_round_trip_sealed`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `cargo test -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings`
```bash
git add crates/fetchit-chat/src/fedi_link.rs crates/fetchit-chat/src/local_store.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(chat): sealed fediverse person-link store (go-private lifecycle)"
```

---

### Task 2: Engine Client accessors for the link store + invite composite

**Files:**
- Modify: `crates/fetchit-chat/src/fedi_link.rs` (`impl Client` block)

**Interfaces:**
- Consumes: `self.fedi_at_rest() -> Result<(MasterKey, StoreLayout)>`, `self.send_fedi_dm(handle, target, body, now_ms)`, the engine pair-share URI (the method `pair_share_uri` FFI calls — find it on `Client`; it is the source of `ChatClient::pair_share_uri`), `load_fedi_links`/`save_fedi_links`.
- Produces: `Client::go_private_invite(&self, handle, target, now_ms) -> Result<GoPrivateReport>` (`GoPrivateReport { delivered: bool }`) — composes the invite body (spec `go_private_invite_dm` copy, with the pair URI), delivers via `send_fedi_dm`, and records the invite **only when `delivered`** (so pending can't desync from the send); `Client::pending_go_private(handle) -> Result<Vec<String>>`; `Client::link_fedi_person(handle, target, agent_id_hex) -> Result<()>`; `Client::unlink_fedi_person(handle, target) -> Result<()>`; `Client::fedi_person_links(handle) -> Result<Vec<(String, PersonLink)>>`; `Client::linked_label_for_agent(handle, agent_id_hex) -> Result<Option<String>>`.

The store ops are unit-tested in Task 1. `go_private_invite` calls `send_fedi_dm` (live transport) so it is integration-shaped — gate this task on a clean build; the pieces it composes are already tested (`send_fedi_dm` in `fedi_dm.rs`, the store in Task 1).

- [ ] **Step 1: Implement the accessors**

```rust
use crate::client::Client;
use crate::error::Result;

/// Outcome of a go-private invite send.
#[derive(Clone, Debug)]
pub struct GoPrivateReport {
    /// The invite fedi DM reached the recipient's inbox.
    pub delivered: bool,
}

impl Client {
    /// Send a go-private invite to `target` over the fediverse: compose the
    /// invite (carrying this device's pair link) and deliver it as a fedi DM.
    /// Records the pending invite ONLY on delivery, so the pending state can
    /// never claim an invite the recipient never received.
    ///
    /// # Errors
    /// [`ChatError`] on a missing minted identity or a store failure. A
    /// transient inbox outage is `delivered == false`, not an error.
    pub async fn go_private_invite(
        &self,
        handle: &str,
        target: &str,
        now_ms: u64,
    ) -> Result<GoPrivateReport> {
        let pair_uri = self.pair_share_uri().await?; // engine pair-share method
        let display = self.display_name_or_default(); // reuse existing; else fall back to handle
        let body = format!(
            "{display} invited you to a private, post-quantum encrypted chat on \
             fetch>it. Open this link in the fetch>it app to accept: {pair_uri} \
             — new here? Get the app: https://etchit.io/fetch (your fediverse \
             messages stay here; the private chat starts fresh)"
        );
        let report = self.send_fedi_dm(handle, target, &body, now_ms).await?;
        if report.delivered {
            let (master, layout) = self.fedi_at_rest()?;
            let mut links = load_fedi_links(handle, &master, &layout)?;
            links.record_invite(target, i64::try_from(now_ms).unwrap_or(i64::MAX));
            save_fedi_links(handle, &links, &master, &layout)?;
        }
        Ok(GoPrivateReport { delivered: report.delivered })
    }

    /// Handles invited to private chat but not yet linked.
    /// # Errors
    /// [`ChatError`] on store load.
    pub fn pending_go_private(&self, handle: &str) -> Result<Vec<String>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_links(handle, &master, &layout)?.pending())
    }

    /// Link `target` (fediverse label) to a PQ `agent_id_hex` — the manual
    /// "Same person?" confirm. Local only; never published.
    /// # Errors
    /// [`ChatError`] on store IO.
    pub fn link_fedi_person(&self, handle: &str, target: &str, agent_id_hex: &str) -> Result<()> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut links = load_fedi_links(handle, &master, &layout)?;
        links.link(target, agent_id_hex, now_ms_i64());
        save_fedi_links(handle, &links, &master, &layout)
    }

    /// Drop the link for `target`.
    /// # Errors
    /// [`ChatError`] on store IO.
    pub fn unlink_fedi_person(&self, handle: &str, target: &str) -> Result<()> {
        let (master, layout) = self.fedi_at_rest()?;
        let mut links = load_fedi_links(handle, &master, &layout)?;
        links.unlink(target);
        save_fedi_links(handle, &links, &master, &layout)
    }

    /// Every person link for `handle`.
    /// # Errors
    /// [`ChatError`] on store load.
    pub fn fedi_person_links(&self, handle: &str) -> Result<Vec<(String, PersonLink)>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_links(handle, &master, &layout)?
            .links
            .into_iter()
            .collect())
    }

    /// The fediverse label linked to `agent_id_hex`, if any (reverse lookup).
    /// # Errors
    /// [`ChatError`] on store load.
    pub fn linked_label_for_agent(
        &self,
        handle: &str,
        agent_id_hex: &str,
    ) -> Result<Option<String>> {
        let (master, layout) = self.fedi_at_rest()?;
        Ok(load_fedi_links(handle, &master, &layout)?.is_linked_agent(agent_id_hex))
    }
}

fn now_ms_i64() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}
```

> Verify the exact names: `pair_share_uri` on `Client` (the FFI wraps it), and a display-name accessor (`display_name_or_default` or similar — check `client.rs`; if none, pass the handle as the display name). Adjust the two calls to the real signatures.

- [ ] **Step 2: Build + clippy + commit**

Run: `cargo test -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings`
```bash
git add crates/fetchit-chat/src/fedi_link.rs
git commit -s -m "feat(chat): go-private invite composite + link accessors"
```

---

### Task 3: FFI surface + bindings regen + gateway

**Files:**
- Modify: `crates/fetchit-ffi/src/chat_ffi.rs`
- Modify: `apps/.../chat/ChatGateway.kt` (+ regenerated `uniffi/.../fetchit_ffi.kt`)
- Modify: `apps/.../chat/ChatControllerTest.kt` (2 test doubles)

**Interfaces:**
- Produces (Kotlin camelCase): `FediPersonLinkFfi { label, agentIdHex: String?, invited: Boolean, linked: Boolean }`; `ChatClient.fediGoPrivateInvite(target): FediDmReportFfi`-shaped `{ delivered }` → reuse a simple `GoPrivateReportFfi { delivered }`; `fediPendingInvites(): List<String>`; `fediLinkPerson(target, agentIdHex)`; `fediUnlinkPerson(target)`; `fediPersonLinks(): List<FediPersonLinkFfi>`; `fediLinkedLabelForAgent(agentIdHex): String?`. Gateway mirrors all six.

- [ ] **Step 1: Add records + methods** (mirror `fedi_followers`/`fedi_threads_overview` patterns: read `fedi_actor_status()` for the handle, `ChatFfiError::Invalid` when absent for the mutating calls; the read calls return empty when no handle). Add `#[derive(Debug, Clone, uniffi::Record)]` structs and the six `pub async fn`/`pub fn` methods to the `#[uniffi::export(async_runtime = "tokio")] impl ChatClient` block, computing `now_ms` inline as the sibling methods do.

- [ ] **Step 2: Build FFI crate**

Run: `(cd crates/fetchit-ffi && cargo build)` — expect clean.

- [ ] **Step 3: Regenerate bindings**

Run (from `fetchit/`, NDK env set as in P1):
`ANDROID_NDK_HOME=/home/josh/Android/Sdk/ndk/27.0.12077973 ANDROID_HOME=/home/josh/Android/Sdk ./scripts/build-jni-libs.sh`
Verify: `strings -a apps/.../jniLibs/arm64-v8a/libfetchit_ffi.so | grep -c fedi_go_private_invite` ≥ 1, and the generated `.kt` contains `fediGoPrivateInvite`/`FediPersonLinkFfi`.

- [ ] **Step 4: Wire gateway + both test doubles**

Add the six methods to `interface ChatGateway`, `class FfiChatGateway`, and BOTH gateways in `ChatControllerTest.kt` (`FakeGateway` returns empties/no-ops; the anonymous gateway likewise) + import `FediPersonLinkFfi`.

- [ ] **Step 5: Compile incl. tests + commit**

Run: `(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin)`
```bash
git add crates/fetchit-ffi/src/chat_ffi.rs apps/fetchit-android/app/src/main/java/uniffi/ \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatGateway.kt \
  apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatControllerTest.kt
git commit -s -m "feat(ffi): go-private invite + person-link surface; regen bindings"
```

---

### Task 4: Link-aware unified list (dedup linked pair to one 🔒 row)

**Files:**
- Modify: `apps/.../chat/ChatRowModel.kt` + `ChatRowModelTest.kt`
- Modify: `apps/.../chat/ChatController.kt` (`personLinks` flow)
- Modify: `apps/.../chat/ChatModeView.kt` (collector passes links)

**Interfaces:**
- `buildChatRows(...)` gains `linkedFediLabels: Set<String>` — a `ChatRow.Fedi` whose `summary.label` is in the set is **suppressed** (its linked contact row already represents it). `ChatController.personLinks: StateFlow<List<FediPersonLinkFfi>>` refreshed alongside `fediThreads`.

- [ ] **Step 1: Failing test** — add to `ChatRowModelTest.kt`:

```kotlin
@Test
fun aLinkedFediThreadIsSuppressedInFavorOfItsContactRow() {
    val contacts = listOf(ChatContact(agentIdHex = "c".repeat(64), displayName = "Happy", addedAtMs = 0L))
    val fedi = listOf(FediThreadSummaryFfi("happyborg@fosstodon.org", "hi", 300, false))
    val rows = buildChatRows(
        contacts = contacts, groups = emptyList(),
        groupPreview = { null },
        contactPreview = { _ -> "let's talk" to 400L },
        fediThreads = fedi,
        linkedFediLabels = setOf("happyborg@fosstodon.org"),
    )
    assertEquals(1, rows.size)                       // fedi row suppressed
    assertEquals("Happy", (rows[0] as ChatRow.Contact).contact.displayName)
}
```

- [ ] **Step 2: Verify fail**, then **Step 3: implement** — add the param (default `emptySet()` at call sites in tests that don't pass it) and `fediThreads.filterNot { it.label in linkedFediLabels }.forEach { ... }`.

- [ ] **Step 4: Wire the controller flow + collector** — add `ChatController.personLinks` StateFlow + `refreshPersonLinks()` (calls `gateway.fediPersonLinks()`); include it in the Chats `combine`; compute `linkedFediLabels = personLinks.filter { it.linked }.map { it.label }.toSet()`; call `refreshPersonLinks()` in `refreshChatsFediThreads()`.

- [ ] **Step 5: Test + compile + commit** (`:app:testDebugUnitTest` green; commit).

---

### Task 5: Go-private button + invite card in the fediverse thread

**Files:**
- Modify: `apps/.../chat/ChatModeView.kt` (`bindFediThreadScreen`)
- Modify: `apps/.../res/values/strings.xml` (§12 P2 strings)

**Interfaces:**
- Consumes: `controller.gateway().fediGoPrivateInvite(handle)`, `fediPendingInvites()`. The FediThread header (`threadPeerShortId` carries "fediverse · not encrypted").

- [ ] **Step 1:** In `bindFediThreadScreen`, repurpose the (currently `GONE`) `threadMembersButton` (or add a header button) as **🔒 Go private**; tap → confirm card (`go_private_title`/`go_private_body`/`go_private_send`) → `fediGoPrivateInvite(handle)`. On `delivered`, flip the button to a quiet status line (`go_private_pending`) with a resend affordance (`go_private_resend`) after a 24h cooldown; on `!delivered` show the retry snackbar. If the handle is already in `fediPendingInvites()`, render the pending status directly.
- [ ] **Step 2:** Add all §12 P2 strings (`go_private_button/title/body/send/pending/resend/invite_dm/linked`, `link_confirm_*`, `thread_divider_*`, `thread_fallback_banner/action`, `link_confirm_reopen`).
- [ ] **Step 3:** Compile incl. tests. **Device smoke:** open the happyborg fedi thread → Go private → card → send → button becomes "invite sent — waiting". Commit.

---

### Task 6: Manual link-confirm ("Same person?")

**Files:**
- Modify: `apps/.../chat/ChatModeView.kt`

**Interfaces:**
- Consumes: `controller.contacts.contacts` (to detect a newly-added PQ contact), `fediPendingInvites()`, `fediLinkPerson(target, agentIdHex)`.

- [ ] **Step 1:** When a new PQ contact appears (observe `controller.contacts.contacts` for an added agent id) **while `fediPendingInvites()` is non-empty**, show the link-confirm card (`link_confirm_title`/`body`/`yes`/`no`) — as a Chats-list banner and inside the relevant thread. If several invites pend, list the handles and let the user pick one. **Yes** → `fediLinkPerson(pickedLabel, newContact.agentIdHex)`; then `refreshPersonLinks()` + `refreshFediThreads()` so the row collapses.
- [ ] **Step 2:** Add the contact-overflow re-open entry (`link_confirm_reopen`) that lists pending invites, for the decline-then-change-mind path.
- [ ] **Step 3:** Compile incl. tests. **Device smoke (needs a 2nd real device as happyborg):** accept the invite on device B → a new contact appears on your phone → "Same person?" card → Yes → the happyborg row collapses to one 🔒 row. **Impersonation drill:** a second importer of the same pair URI must NOT be auto-labeled happyborg — the card names the contact and requires explicit confirm. Commit.

---

### Task 7: Merged thread render + PQ-only composer + fallback offer

**Files:**
- Modify: `apps/.../chat/ChatModeView.kt` (`bindThreadScreen`)

**Interfaces:**
- Consumes: `controller.gateway().fediLinkedLabelForAgent(peerAgentId)` (or the cached `personLinks`), `fediThreadHistory`/`conversationHistory("f:<label>")`, `controller.pumpState`.

- [ ] **Step 1: Merged history.** In `bindThreadScreen(peer)`, if the peer's agent id has a linked fedi label, prepend that label's fediverse history (read-only) then a divider (`thread_divider_fedi` → `thread_divider_pq`) then the PQ history. Reuse the fedi thread store read.
- [ ] **Step 2: PQ-only composer (invariant 1/3).** The composer in a linked thread sends ONLY PQ (existing DM send). No fediverse send path is wired into this composer.
- [ ] **Step 3: Fallback offer (§7.6, invariant 1).** Collect `controller.pumpState`; on `STOPPED_ERROR`, show the banner (`thread_fallback_banner`) with ONE explicit action (`thread_fallback_action`) that opens the person's fediverse thread (their `f:<label>`). Never send over fedi automatically; the banner clears when the pump returns to `RUNNING`.
- [ ] **Step 4:** Compile incl. tests. **Device smoke:** open the now-linked happyborg (🔒) thread → old fediverse messages appear above the "private from here" divider, PQ below; the composer sends PQ; killing the private rail shows the banner + the explicit fedi-fallback option (and sending via it is labeled not-encrypted). Commit.

---

### Task 8: Invite a fediverse person to a private group

**Files:**
- Modify: `apps/.../chat/ChatModeView.kt` (group members view)
- Modify: `apps/.../res/values/strings.xml`

**Interfaces:**
- Consumes: `controller.gateway().groupInvite(groupId)` (fresh single-use link), `send_fedi_dm`, People (contacts + following).

- [ ] **Step 1:** In the private group thread's members/actions, add **"Invite someone"** → picker listing People (PQ contacts first, fedi follows below). A **PQ contact** → invite over PQ DM (existing rail). A **fedi-only person** → mint a **fresh** `groupInvite(groupId)` (single-use; never reuse) + `fediDm` it with the `group_invite_dm` copy.
- [ ] **Step 2:** Compile incl. tests. **Device smoke:** invite happyborg (fedi-only) to the Devs group → they receive a fedi DM with a fresh single-use group link. Commit.

---

### Task 9: Full gates, device smoke, docs, Alice handoff

- [ ] **Step 1: Full gates.**
```bash
cargo fmt --all --check
(cd crates/fetchit-ffi && cargo fmt --check)
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd crates/fetchit-ffi && cargo build)
(cd apps/fetchit-android && ./gradlew :app:compileDebugKotlin :app:compileDebugUnitTestKotlin :app:testDebugUnitTest :app:assembleDebug)
```
- [ ] **Step 2: P2 device smoke (spec §15 P2 gate)** on the S22 + a 2nd real device as happyborg: Go-private invite over the fedi rail → accept on B → manual "Same person?" link → badge flips 🌐 → 🔒, one row, merged thread, PQ-only composer → fedi-fallback banner appears only when the private rail is down and only sends on explicit tap → impersonation drill (second URI importer not auto-linked) → group invite over fedi. **Regression:** P1 (tabs, unified list, feed, people, new-chat) unchanged; a plain DM/group/fedi send still works.
- [ ] **Step 3: Docs.** If `SECURITY.md` enumerates the messaging privacy contracts, add the no-auto-downgrade invariant + the local-only person link (shares no keys, never published).
- [ ] **Step 4: Push + handoff.** `git push origin messaging-ia-redesign`; sync Alice (SHA + cross-review request on the person-link store + the FFI + the no-downgrade invariant; desktop mirrors §7/§8 from the frozen surface). Nothing merges to main until Josh signs off on the device build.

## Out of scope (P2)

Auto-linking; fedi-side rendering on other servers; escalating a *group* to fully-PQ membership for non-fetch>it members (impossible — they'd need the app); unread counts; the desktop implementation (Alice, separate).
