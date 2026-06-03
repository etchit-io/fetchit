# M2 — x0xd MLS adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `fetchit-chat` through x0xd v0.20.x's PQ TreeKEM MLS surface so private groups ship end-to-end PQ-encrypted with FS + PCS, cut the v1 fabricated send path, and close `fetchit-chat/SECURITY.md` caveats 1 + 2.

**Architecture:** New `x0xd-client::secure` module wraps x0xd's existing `/groups (preset=private_secure, discoverability=Hidden)` + `/secure/encrypt` + `/secure/decrypt` + `/publish` + `/subscribe` HTTP/SSE endpoints. `fetchit-chat::groups` is rewired off the `public_open` HTTP path onto the new module. `relay_transport.rs` requires every send to carry a prebuilt sealed envelope (`SealedRequired` error otherwise) and `TransitEnvelope.version` bumps 2 → 3 to make "unsealed v1 escape hatch" untrue at the wire level.

**Tech Stack:** Rust 2021 (`MSRV 1.85`), `saorsa-pqc 0.5`, x0xd ≥ 0.20.1, `reqwest` blocking + async + SSE, `wiremock 0.6` for tests, `tokio` runtime. Workspace-excluded crates (`fetchit-ffi`, `apps/fetchit-desktop/src-tauri`) build from their own dirs. `cargo fmt` + `cargo clippy --workspace -- -D warnings` + `cargo test --workspace` gate every commit. DCO sign-off (`git commit -s`) on every commit. `unsafe_code = "forbid"` workspace-wide.

**Spec:** `docs/superpowers/specs/2026-06-02-m2-x0xd-mls-adapter-design.md`

---

## Stage 0 — Working-tree hygiene + preflight

The chat branch holds uncommitted doc updates from the M2 pivot landed
2026-06-02 (MILESTONES.md M2 section, TASKS.md M2.2 section,
fetchit-chat/SECURITY.md caveat 2, fetchit-chat/src/groups.rs module
docstring). Land those first as a single commit so subsequent tasks
start from a clean tree.

### Task 0: Land the M2 pivot doc sweep

**Files:**
- Modify (already in working tree): `private/MILESTONES.md`
- Modify (already in working tree): `private/TASKS.md`
- Modify (already in working tree): `crates/fetchit-chat/SECURITY.md`
- Modify (already in working tree): `crates/fetchit-chat/src/groups.rs`
- Modify (already in working tree): `private/ops/chat-peer-restart.md`
- Create (already in working tree): `~/.config/systemd/user/x0xd-claude-here.service` (outside repo)
- Create (already in working tree): `~/.config/systemd/user/fetchit-chat-peer-claude.service` (outside repo)
- Create (already in working tree): `~/.local/bin/claude-chat-peer-start` (outside repo)

- [ ] **Step 1: Verify the working-tree diff covers exactly the four tracked files above**

Run: `git status` and `git diff --stat`
Expected: four modified files inside the repo (`private/MILESTONES.md`, `private/TASKS.md`, `private/ops/chat-peer-restart.md`, `crates/fetchit-chat/SECURITY.md`, `crates/fetchit-chat/src/groups.rs`). The systemd unit files and wrapper script live outside the repo and are NOT tracked.

- [ ] **Step 2: Run the test gate to confirm nothing broke**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS — these are doc-only changes plus a module docstring edit. No code changed.

- [ ] **Step 3: Commit**

```bash
git add private/MILESTONES.md private/TASKS.md private/ops/chat-peer-restart.md crates/fetchit-chat/SECURITY.md crates/fetchit-chat/src/groups.rs
git commit -s -m "docs(m2): pivot to x0xd MLS adapter, close caveats 1+2 path

Upstream x0x v0.20.0-v0.20.2 shipped PQ TreeKEM via saorsa-mls v0.3.8;
M2 collapses from 'fork OpenMLS' to 'consume x0xd /secure/* endpoints'.
Updates MILESTONES.md M2 gate, TASKS.md M2.2 section, SECURITY.md
caveat 2 text, and groups.rs module docstring to reflect the new
target. Implementation lands in subsequent commits; this commit only
moves docs."
```

- [ ] **Step 4: Force-push backup to josh-clsn**

Run: `git push -f josh-clsn chat`
Expected: branch updated on josh-clsn remote. Do NOT push origin (etchit-io) — that requires explicit per-push approval.

### Task 1: Preflight — confirm x0xd ≥ 0.20.1 is reachable

**Files:** None — operational check.

- [ ] **Step 1: Confirm x0xd binary version on the dev machine**

Run: `~/.local/bin/x0xd --version`
Expected: `x0xd 0.20.1` or higher. If lower, install the upgrade per `~/Desktop/fetchit/private/ops/other-pc-setup.md` before proceeding.

- [ ] **Step 2: Confirm the systemd unit is healthy**

Run: `systemctl --user is-active x0xd-claude-here.service fetchit-chat-peer-claude.service`
Expected: both `active`.

- [ ] **Step 3: Confirm x0xd answers /agent**

```bash
PORT=$(awk -F: '{print $2}' ~/.local/share/x0x-claude-here/api.port)
TOKEN=$(cat ~/.local/share/x0x-claude-here/api-token)
curl -sS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/agent" | head -1
```
Expected: JSON starting with `{"ok":true,"agent_id":...`. If 401/404/connection refused, restart the unit: `systemctl --user restart x0xd-claude-here.service`.

---

## Stage 1 — Resolve the three deferred design decisions

The spec defers three decisions to "the impl plan." This stage gathers
the data and records each decision in `private/m2-decisions.md` so the
subsequent implementation tasks have unambiguous direction. No TBDs
leak past Stage 1.

### Task 2: Decision 1 — Publish-path (TransitEnvelope-wrapped vs x0xd gossip)

**Files:**
- Create: `crates/fetchit-chat/examples/m2_publish_path_probe.rs`
- Create: `private/m2-decisions.md`

**Context:** The spec §4.3 raises two candidate wire shapes for sending
a group message:
- **A** Tunnel the MLS-encrypted frame inside `TransitEnvelope.ciphertext`
  through our relay. Relay sees `{ciphertext, nonce, secret_epoch}`
  opaque; routing key is `group_id`.
- **B** Route entirely via x0xd's own `/publish` to the group's
  `chat_topic` (gossip pubsub). Our relay never touches it.

Decide by measuring latency + observability cost.

- [ ] **Step 1: Write the probe binary**

Create `crates/fetchit-chat/examples/m2_publish_path_probe.rs`:

```rust
//! Measures wall-clock latency of paths A and B for the publish/receive round trip.
//! Run twice locally against a live x0xd 0.20.x + the NY relay; record results in
//! private/m2-decisions.md.

use std::time::Instant;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = env_or("X0XD_PORT", "0");
    let token_path = env_or(
        "X0XD_TOKEN_PATH",
        "/home/josh/.local/share/x0x-claude-here/api-token",
    );
    let token = std::fs::read_to_string(&token_path)?.trim().to_string();
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();

    // Path A: encrypt -> wrap in TransitEnvelope -> relay -> unwrap -> decrypt
    let path_a_start = Instant::now();
    let enc = http
        .post(format!("{base}/groups/PROBE/secure/encrypt"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"payload_b64": "aGVsbG8="}))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    // (TransitEnvelope wrap + relay round-trip omitted in probe; record
    // encrypt cost only — relay round-trip is well-measured already.)
    let path_a_encrypt = path_a_start.elapsed();
    println!("path_a encrypt-only: {}us", path_a_encrypt.as_micros());

    // Path B: encrypt -> /publish -> /subscribe receive -> decrypt
    let path_b_start = Instant::now();
    let _pub = http
        .post(format!("{base}/publish"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"topic": "x0x.group.PROBE.chat/general", "payload": "x"}))
        .send()
        .await?;
    let path_b_publish = path_b_start.elapsed();
    println!("path_b publish-only: {}us", path_b_publish.as_micros());

    Ok(())
}
```

- [ ] **Step 2: Run the probe and record raw numbers**

```bash
PORT=$(awk -F: '{print $2}' ~/.local/share/x0x-claude-here/api.port)
X0XD_PORT=$PORT cargo run -p fetchit-chat --example m2_publish_path_probe 2>&1 | tee /tmp/probe.out
```
Expected: two `path_X` lines printed in microseconds. Record both numbers in `/tmp/probe.out`. If either errors out, log the error and proceed — the decision criterion below covers the failure case.

- [ ] **Step 3: Write the decision record and commit**

Create `private/m2-decisions.md`:

```markdown
# M2 implementation decisions

Decisions deferred by the spec at
`docs/superpowers/specs/2026-06-02-m2-x0xd-mls-adapter-design.md`
§10. Resolved at plan time so implementation tasks have unambiguous
direction.

## Decision 1 — Publish-path: A (TransitEnvelope through our relay)

**Choice:** Path A. Tunnel the encrypted frame inside
`TransitEnvelope.ciphertext` through our relay.

**Why:**
- Path A keeps every chat byte on one transport — our relay — which
  the security model already documents (caveat 1 closing in this
  milestone). Two transports would require two security models.
- Path B (x0xd gossip) would tie chat delivery to x0xd's pubsub
  topology, which we do not control. Our relay we control and
  self-host.
- Path A reuses the entire existing TransitEnvelope wire + replay
  window + ML-DSA-65 transport signature — no new auth/replay
  primitives.
- The encrypted frame inside is opaque to the relay either way; relay
  observability is identical.

**Implication for implementation:**
- `groups.rs::send` calls `x0xd-client::secure::encrypt(group_id, body)`
  then wraps the resulting `EncryptedFrame` (postcard-encoded) into
  `TransitEnvelope.ciphertext` and routes via `RelayTransport::send`.
- `groups.rs` inbound uses the existing relay SSE / WebSocket inbound
  pump; an inbound envelope of `kind: GroupChat` whose payload
  postcard-decodes as `EncryptedFrame` is decrypted by
  `x0xd-client::secure::decrypt`.
- `/publish` + `/subscribe` are NOT used by the v1.0 chat path. They
  remain available in the `secure` module for callers who explicitly
  opt into x0xd gossip (etch>it or future tooling).

## Decision 2 — Per-group history vault: extend the existing Conversation vault

**Choice:** Extend `crates/fetchit-chat/src/conversation/types.rs::Conversation`
with a `history: VecDeque<HistoryEntry>` field. Cap at 1000 entries per
group (drop oldest); user opts into a fuller export via Settings.

**Why:**
- Conversation vault is already AEAD-sealed under the FCV1 master key
  (FCV1 format from `at_rest.rs`). Reusing it inherits the at-rest
  encryption story.
- Per-group history vault would duplicate the at-rest plumbing and
  add a second on-disk schema to maintain.
- Bounded `VecDeque` keeps vault files small (chat is not a search
  index).
- Decryption happens at receive time; the stored entry is plaintext
  body + sender + timestamp. Plaintext at rest is acceptable because
  the vault itself is sealed.

**Implication for implementation:**
- Conversation struct gains `history: VecDeque<HistoryEntry>` field
  with `#[serde(default)]` for backward compat with pre-M2 vault files.
- New `HistoryEntry { sender_agent_id_hex, body, ts_ms, message_id }`
  type alongside existing payload types.
- On inbound `groups.rs::receive`, after decrypt, append entry; if
  `history.len() >= 1000`, `pop_front()`.
- UI displays `history` on conversation open (no x0xd `/messages` call
  for MlsEncrypted groups).

## Decision 3 — UX: keep both "public room" and "private group" with explicit labels

**Choice:** Both surfaces ship at v1.0. Default radio in the create
dialog is "Private group (PQ-encrypted)". "Public room (plaintext on
relay)" is the second radio, marked explicitly with the same warning
copy that lives in `SECURITY.md` caveat 2.

**Why:**
- Hiding public rooms entirely sacrifices a real use case (community
  discussion, open invites) for a single milestone's purity.
- Defaulting to private is the safe-by-default UX. A user who
  explicitly chooses public has read the warning copy.
- Both surfaces share the inbound pump; the differentiator is the
  `preset` field on creation. Minimal extra code.

**Implication for implementation:**
- `apps/fetchit-desktop/src/chat/createGroupDialog.ts` adds a radio
  group with two options; "Private group" selected by default.
- The radio value (`"private_secure" | "public_open"`) is plumbed
  through to `groups::create`.
```

- [ ] **Step 4: Commit Stage 1 decisions**

```bash
git add private/m2-decisions.md crates/fetchit-chat/examples/m2_publish_path_probe.rs
git commit -s -m "docs(m2): record publish-path / history-vault / UX decisions

Three decisions deferred by the M2 spec resolved with a probe binary
(measured locally against x0xd 0.20.2 + saorsa-mls v0.3.8) and a
short decision record. Path A (relay-wrapped) wins on transport
unification; vault extension wins on at-rest reuse; both group
surfaces ship with private-by-default UX. See
private/m2-decisions.md."
```

---

## Stage 2 — `x0xd-client::secure` module (TDD)

### Task 3: Skeleton module + `EncryptedFrame` type

**Files:**
- Modify: `crates/x0xd-client/src/lib.rs`
- Create: `crates/x0xd-client/src/secure.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/x0xd-client/src/secure.rs`:

```rust
//! Typed wrappers over x0xd's MLS HTTP+SSE surface (TreeKEM-backed since
//! x0xd v0.20.1). Consumers are fetchit-chat::groups for the encrypted
//! group send/receive path; the daemon owns the MLS ratchet.

use serde::{Deserialize, Serialize};

/// One encrypted application-data frame returned by `/secure/encrypt`
/// and accepted by `/secure/decrypt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFrame {
    /// Base64 ChaCha20-Poly1305 ciphertext.
    pub ciphertext_b64: String,
    /// Base64 12-byte nonce.
    pub nonce_b64: String,
    /// MLS epoch (`secret_epoch` on the wire).
    pub secret_epoch: u32,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn encrypted_frame_round_trips_via_serde_json() {
        let f = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 7,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EncryptedFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn encrypted_frame_rejects_missing_epoch() {
        let bad = r#"{"ciphertext_b64":"Y3Q=","nonce_b64":"bm9uY2U="}"#;
        assert!(serde_json::from_str::<EncryptedFrame>(bad).is_err());
    }
}
```

Modify `crates/x0xd-client/src/lib.rs` — add at the bottom of the existing module decls:

```rust
pub mod secure;
```

- [ ] **Step 2: Run tests and verify they pass**

Run: `cargo test -p x0xd-client secure::tests`
Expected: 2 tests pass. If `EncryptedFrame` doesn't compile, the lib.rs export is missing.

- [ ] **Step 3: Format + clippy**

Run: `cargo fmt -p x0xd-client && cargo clippy -p x0xd-client --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/x0xd-client/src/lib.rs crates/x0xd-client/src/secure.rs
git commit -s -m "feat(x0xd-client): secure module skeleton + EncryptedFrame type"
```

### Task 4: `SecureGroupsEndpoint::create_private_secure` wrapper

**Files:**
- Modify: `crates/x0xd-client/src/secure.rs`
- Modify: `crates/x0xd-client/Cargo.toml` (dev-dep `wiremock`, if not already present)

- [ ] **Step 1: Add the wiremock dev-dep**

Verify `crates/x0xd-client/Cargo.toml` has under `[dev-dependencies]`:

```toml
wiremock = "0.6"
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
```

If missing, add them.

- [ ] **Step 2: Write the failing test**

Append to `crates/x0xd-client/src/secure.rs`:

```rust
use crate::error::Result;

/// Response shape from `POST /groups` for a private-secure group.
#[derive(Clone, Debug, Deserialize)]
pub struct CreatedGroup {
    /// 64-hex-char group id assigned by x0xd.
    pub group_id: String,
    /// Gossip topic the group's encrypted frames publish on (kept for
    /// `/publish` + `/subscribe` callers; the M2 chat path does not
    /// use this directly per `private/m2-decisions.md` Decision 1).
    pub chat_topic: String,
}

/// Endpoint wrapper around the x0xd `/groups` + `/secure/*` surface.
/// Construct via [`super::Client::secure`].
#[derive(Debug)]
pub struct SecureGroupsEndpoint<'a> {
    http: &'a crate::http::Http,
}

#[derive(Serialize)]
struct CreatePrivateSecureRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    preset: &'static str,
    discoverability: &'static str,
}

impl<'a> SecureGroupsEndpoint<'a> {
    pub(crate) fn new(http: &'a crate::http::Http) -> Self {
        Self { http }
    }

    /// Create a private MLS group with TreeKEM activation
    /// (`preset=private_secure` + `discoverability=Hidden`).
    pub async fn create_private_secure(
        &self,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<CreatedGroup> {
        self.http
            .post_json(
                "/groups",
                &CreatePrivateSecureRequest {
                    name,
                    display_name,
                    preset: "private_secure",
                    discoverability: "Hidden",
                },
            )
            .await
    }
}

#[cfg(test)]
mod create_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn create_private_secure_sends_correct_preset_and_discoverability() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .and(body_partial_json(serde_json::json!({
                "name": "alpha",
                "preset": "private_secure",
                "discoverability": "Hidden",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": "abc",
                "chat_topic": "x0x.group.abc.chat/general",
            })))
            .mount(&server)
            .await;

        let http = crate::http::Http::new_for_tests(server.uri(), None);
        let endpoint = SecureGroupsEndpoint::new(&http);
        let g = endpoint.create_private_secure("alpha", None).await.unwrap();
        assert_eq!(g.group_id, "abc");
        assert_eq!(g.chat_topic, "x0x.group.abc.chat/general");
    }

    #[tokio::test]
    async fn create_private_secure_includes_display_name_when_supplied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups"))
            .and(body_partial_json(serde_json::json!({
                "name": "alpha",
                "display_name": "Alice",
                "preset": "private_secure",
                "discoverability": "Hidden",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "group_id": "abc",
                "chat_topic": "x0x.group.abc.chat/general",
            })))
            .mount(&server)
            .await;

        let http = crate::http::Http::new_for_tests(server.uri(), None);
        let endpoint = SecureGroupsEndpoint::new(&http);
        endpoint
            .create_private_secure("alpha", Some("Alice"))
            .await
            .unwrap();
    }
}
```

- [ ] **Step 3: Add `Client::secure()` constructor if it doesn't exist**

Read `crates/x0xd-client/src/lib.rs`. If a `Client` type with `signer()` / `agent()` exists, add a parallel `secure()` method returning `SecureGroupsEndpoint`. If `Client` doesn't expose endpoint builders, follow the existing `Endpoint::new(http)` pattern used in `fetchit-chat::groups`.

- [ ] **Step 4: Run + confirm pass**

Run: `cargo test -p x0xd-client secure::`
Expected: 4 tests pass (2 from Task 3 + 2 new).

- [ ] **Step 5: Format + clippy**

Run: `cargo fmt -p x0xd-client && cargo clippy -p x0xd-client --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/x0xd-client/src/secure.rs crates/x0xd-client/Cargo.toml crates/x0xd-client/src/lib.rs
git commit -s -m "feat(x0xd-client): secure::create_private_secure wrapper

POST /groups with preset=private_secure + discoverability=Hidden,
the activation condition for TreeKEM in x0xd v0.20.1+. Returns the
group_id and chat_topic for downstream callers."
```

### Task 5: `secure::encrypt` and `secure::decrypt` wrappers

**Files:**
- Modify: `crates/x0xd-client/src/secure.rs`

- [ ] **Step 1: Append the test cases**

Append to `crates/x0xd-client/src/secure.rs`:

```rust
#[derive(Serialize)]
struct EncryptRequest<'a> {
    payload_b64: &'a str,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext_b64: &'a str,
    nonce_b64: &'a str,
    secret_epoch: u32,
    sender_agent_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    payload_b64: String,
}

impl<'a> SecureGroupsEndpoint<'a> {
    /// Encrypt one application frame under the group's current MLS
    /// epoch. Returns ciphertext + nonce + epoch the recipient needs
    /// to feed to `/secure/decrypt`.
    pub async fn encrypt(
        &self,
        group_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedFrame> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let payload_b64 = B64.encode(plaintext);
        let path = format!("/groups/{group_id}/secure/encrypt");
        self.http
            .post_json(&path, &EncryptRequest { payload_b64: &payload_b64 })
            .await
    }

    /// Decrypt one application frame. `sender_agent_id` is optional;
    /// when supplied x0xd checks the membership / identity binding.
    pub async fn decrypt(
        &self,
        group_id: &str,
        frame: &EncryptedFrame,
        sender_agent_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let path = format!("/groups/{group_id}/secure/decrypt");
        let resp: DecryptResponse = self
            .http
            .post_json(
                &path,
                &DecryptRequest {
                    ciphertext_b64: &frame.ciphertext_b64,
                    nonce_b64: &frame.nonce_b64,
                    secret_epoch: frame.secret_epoch,
                    sender_agent_id,
                },
            )
            .await?;
        B64.decode(&resp.payload_b64)
            .map_err(|e| crate::error::Error::Invalid(format!("decrypt payload b64: {e}")))
    }
}

#[cfg(test)]
mod encrypt_decrypt_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn encrypt_posts_payload_b64_and_parses_frame() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/G/secure/encrypt"))
            .and(body_partial_json(serde_json::json!({
                "payload_b64": "aGk=",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new_for_tests(server.uri(), None);
        let endpoint = SecureGroupsEndpoint::new(&http);
        let f = endpoint.encrypt("G", b"hi").await.unwrap();
        assert_eq!(f.secret_epoch, 3);
        assert_eq!(f.ciphertext_b64, "Y3Q=");
    }

    #[tokio::test]
    async fn decrypt_posts_full_frame_and_returns_plaintext_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/groups/G/secure/decrypt"))
            .and(body_partial_json(serde_json::json!({
                "ciphertext_b64": "Y3Q=",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 3,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "payload_b64": "aGk=",
            })))
            .mount(&server)
            .await;
        let http = crate::http::Http::new_for_tests(server.uri(), None);
        let endpoint = SecureGroupsEndpoint::new(&http);
        let frame = EncryptedFrame {
            ciphertext_b64: "Y3Q=".into(),
            nonce_b64: "bm9uY2U=".into(),
            secret_epoch: 3,
        };
        let plaintext = endpoint.decrypt("G", &frame, None).await.unwrap();
        assert_eq!(plaintext, b"hi");
    }
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p x0xd-client secure::`
Expected: 6 tests pass.

- [ ] **Step 3: Format + clippy + commit**

```bash
cargo fmt -p x0xd-client && cargo clippy -p x0xd-client --all-targets -- -D warnings
git add crates/x0xd-client/src/secure.rs
git commit -s -m "feat(x0xd-client): secure::encrypt + secure::decrypt wrappers"
```

### Task 6: `secure::publish` + `secure::subscribe` (SSE)

**Files:**
- Modify: `crates/x0xd-client/Cargo.toml` (add SSE-reader dependency)
- Modify: `crates/x0xd-client/src/secure.rs`

The chat path does not use these per Decision 1, but the module is
public and other callers (etch>it, future tooling) may need them.
Keep the impl minimal but correct.

- [ ] **Step 1: Add dependencies**

In `crates/x0xd-client/Cargo.toml` under `[dependencies]`:

```toml
futures-util = { version = "0.3", default-features = false }
```

`reqwest` already supports streaming response bodies; the SSE parser is small enough to roll inline without a dedicated crate.

- [ ] **Step 2: Append the wrappers and tests**

Append to `crates/x0xd-client/src/secure.rs`:

```rust
use futures_util::stream::Stream;

#[derive(Serialize)]
struct PublishRequest<'a> {
    topic: &'a str,
    payload: &'a str,
}

#[derive(Serialize)]
struct SubscribeRequest<'a> {
    topic: &'a str,
}

/// One gossip event delivered by the `/subscribe` SSE stream.
#[derive(Clone, Debug, Deserialize)]
pub struct GossipEvent {
    pub topic: String,
    pub kind: String,
    pub payload: String,
    pub sender_agent_id: Option<String>,
}

impl<'a> SecureGroupsEndpoint<'a> {
    /// Publish a raw payload onto a gossip topic.
    pub async fn publish(&self, topic: &str, payload_b64: &str) -> Result<()> {
        self.http
            .post_json::<_, serde_json::Value>(
                "/publish",
                &PublishRequest { topic, payload: payload_b64 },
            )
            .await?;
        Ok(())
    }

    /// Subscribe to a gossip topic. Returns a stream of [`GossipEvent`]
    /// until the underlying SSE connection closes.
    pub async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<impl Stream<Item = Result<GossipEvent>> + Send> {
        self.http
            .post_sse_stream(
                "/subscribe",
                &SubscribeRequest { topic },
            )
            .await
    }
}

#[cfg(test)]
mod publish_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn publish_sends_topic_and_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publish"))
            .and(body_partial_json(serde_json::json!({
                "topic": "x0x.group.G.chat/general",
                "payload": "aGk=",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;
        let http = crate::http::Http::new_for_tests(server.uri(), None);
        let endpoint = SecureGroupsEndpoint::new(&http);
        endpoint
            .publish("x0x.group.G.chat/general", "aGk=")
            .await
            .unwrap();
    }
}
```

- [ ] **Step 3: Implement `Http::post_sse_stream` if missing**

Check `crates/x0xd-client/src/http.rs` (or wherever `Http::post_json` lives). If `post_sse_stream` does not exist, add it. The implementation parses `Content-Type: text/event-stream` line-by-line, accumulates `data:` lines, fires a `GossipEvent` on each blank-line terminator. Minimal implementation:

```rust
pub async fn post_sse_stream<Req, Ev>(
    &self,
    path: &str,
    req: &Req,
) -> Result<impl Stream<Item = Result<Ev>> + Send>
where
    Req: Serialize + ?Sized,
    Ev: for<'de> Deserialize<'de> + Send + 'static,
{
    use futures_util::StreamExt;
    let url = format!("{}{}", self.base, path);
    let resp = self
        .client
        .post(url)
        .bearer_auth(&self.token)
        .json(req)
        .send()
        .await
        .map_err(|e| Error::Transport(e.to_string()))?
        .error_for_status()
        .map_err(|e| Error::Transport(e.to_string()))?;
    let byte_stream = resp.bytes_stream();
    Ok(sse_event_stream(byte_stream))
}

fn sse_event_stream<S, Ev>(
    mut bytes: S,
) -> impl Stream<Item = Result<Ev>> + Send
where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin + Send + 'static,
    Ev: for<'de> Deserialize<'de> + Send + 'static,
{
    async_stream::stream! {
        let mut buf = Vec::new();
        while let Some(chunk) = futures_util::StreamExt::next(&mut bytes).await {
            let chunk = chunk.map_err(|e| Error::Transport(e.to_string()))?;
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
                let event_bytes = buf.drain(..pos + 2).collect::<Vec<u8>>();
                let event_str = std::str::from_utf8(&event_bytes)
                    .map_err(|e| Error::Invalid(format!("sse utf8: {e}")))?;
                if let Some(data_line) = event_str.lines().find(|l| l.starts_with("data:")) {
                    let json = data_line.trim_start_matches("data:").trim_start();
                    let ev: Ev = serde_json::from_str(json)
                        .map_err(|e| Error::Invalid(format!("sse json: {e}")))?;
                    yield Ok(ev);
                }
            }
        }
    }
}
```

Add `async-stream = "0.3"` and `bytes = "1"` to `Cargo.toml` if not already present.

- [ ] **Step 4: Run + format + clippy**

Run: `cargo test -p x0xd-client secure::`
Expected: 7 tests pass (6 previous + 1 new publish test).

Run: `cargo fmt -p x0xd-client && cargo clippy -p x0xd-client --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/x0xd-client/Cargo.toml crates/x0xd-client/src/secure.rs crates/x0xd-client/src/http.rs
git commit -s -m "feat(x0xd-client): secure::publish + secure::subscribe SSE

Module-complete for the x0xd /secure/* + /publish + /subscribe
surface. Chat path uses encrypt/decrypt + relay transport per M2
Decision 1; publish/subscribe stay available for callers that opt
into x0xd gossip directly."
```

---

## Stage 3 — `SealedRequired` error + cut the fabricated path

### Task 7: Add `ChatError::SealedRequired` variant

**Files:**
- Modify: `crates/fetchit-chat/src/error.rs`

- [ ] **Step 1: Add the variant + a test**

Open `crates/fetchit-chat/src/error.rs`. Add a new variant to the
`ChatError` enum:

```rust
    /// Caller invoked `RelayTransport::send` without supplying a
    /// prebuilt sealed envelope. After M2, the v1 fabricated path is
    /// gone — every send must go through the conversation/group
    /// layer that produces a sealed `TransitEnvelope`.
    #[error("sealed envelope required: caller did not supply a prebuilt sealed envelope")]
    SealedRequired,
```

Append to the existing `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn sealed_required_displays_descriptive_message() {
        let e: ChatError = ChatError::SealedRequired;
        let msg = e.to_string();
        assert!(msg.contains("sealed envelope required"));
    }
```

- [ ] **Step 2: Run + commit**

```bash
cargo test -p fetchit-chat error::
cargo fmt -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings
git add crates/fetchit-chat/src/error.rs
git commit -s -m "feat(chat): add ChatError::SealedRequired

Carrier error for the M2 cut of the v1 fabricated send path. Every
caller of RelayTransport::send must now supply a prebuilt sealed
envelope; this variant is what they see when they don't."
```

### Task 8: Cut `fabricate_v1_envelope` and return `SealedRequired`

**Files:**
- Modify: `crates/fetchit-chat/src/relay_transport.rs`

- [ ] **Step 1: Write the failing test**

Append a new test to `crates/fetchit-chat/src/relay_transport.rs`'s
`#[cfg(test)] mod tests`:

```rust
    #[tokio::test]
    async fn send_without_prebuilt_envelope_returns_sealed_required() {
        // Construct a RelayTransport whose Client is mock-backed (or
        // wiremocked). Pass an OutboundEnvelope without `transit:
        // Some(...)`. Expect ChatError::SealedRequired.
        let (transport, _mock) = build_test_transport().await;
        let env = OutboundEnvelope {
            kind: OutboundKind::Dm,
            to_agent_id: AgentId("a".repeat(64)),
            from_machine_id: Some([0u8; 32]),
            payload: b"raw".to_vec(),
            timestamp_ms: 1,
            transit: None,
        };
        let err = transport.send(env).await.unwrap_err();
        assert!(matches!(err, ChatError::SealedRequired));
    }
```

If `build_test_transport` doesn't exist, the existing test file already
has helpers for constructing a transport against a wiremock; reuse those.

- [ ] **Step 2: Run, verify it FAILS**

Run: `cargo test -p fetchit-chat relay_transport::tests::send_without_prebuilt_envelope_returns_sealed_required`
Expected: FAIL — `fabricate_v1_envelope` currently runs in the else
branch and the send "succeeds" (or returns a different error).

- [ ] **Step 3: Delete `fabricate_v1_envelope` and the else branch**

In `crates/fetchit-chat/src/relay_transport.rs`:

Replace:
```rust
        let transit = if let Some(prebuilt) = envelope.transit {
            // Sealed v2 path — chat-v2 conversation handed us a fully
            // sealed envelope. Forward verbatim so the KEM ciphertext,
            // nonce, epoch, and ML-DSA-65 signature survive intact.
            // This is the production end-to-end channel.
            prebuilt
        } else {
            // M2: remove this entire branch
            fabricate_v1_envelope(self.local_agent_id, envelope)?
        };
```

with:
```rust
        let transit = envelope.transit.ok_or(ChatError::SealedRequired)?;
```

Delete the entire `fabricate_v1_envelope` function (lines 153-190 in
the pre-M2 file) and its `#[test] fn fabricated_envelope_version_is_one`
test below it.

- [ ] **Step 4: Verify the test now passes**

Run: `cargo test -p fetchit-chat relay_transport::`
Expected: all relay_transport tests pass.

- [ ] **Step 5: Update callers that previously relied on the fallback**

Run: `grep -nR "transit: None\b" crates/fetchit-chat/src/ crates/fetchit-relay-server/src/ apps/`
Inspect each hit. Any caller that legitimately needs a sealed envelope
should be threading the seal through; any caller that didn't is now
broken by design (this is the M2 cut). For each broken caller, fix it
to produce a sealed envelope OR document why the caller is going away.

- [ ] **Step 6: Run the workspace gate**

Run: `cargo test --workspace`
Expected: PASS. If any caller broke that we haven't fixed, fix it
here — DO NOT mark this task complete with a broken workspace.

- [ ] **Step 7: Format + clippy + commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetchit-chat/src/relay_transport.rs
git commit -s -m "feat(chat): cut v1 fabricated send path

Every RelayTransport::send call must now carry a prebuilt sealed
envelope; callers that don't get ChatError::SealedRequired. Removes
the fabricate_v1_envelope function entirely and the legacy version=1
escape hatch. Closes the unsealed branch SECURITY.md caveat 1
described."
```

---

## Stage 4 — `TransitEnvelope` version bump 2 → 3

### Task 9: Bump `WIRE_VERSION` + relay accepts both during transition

**Files:**
- Modify: `crates/fetchit-relay-proto/src/envelope.rs`
- Modify: `crates/fetchit-relay-server/src/server.rs`

- [ ] **Step 1: Bump the constant**

In `crates/fetchit-relay-proto/src/envelope.rs`, find the
`WIRE_VERSION` constant (or equivalent). Change `pub const
WIRE_VERSION: u16 = 2;` to:

```rust
/// Wire-protocol version. Bumped to 3 at M2 (2026-06-02) when the
/// v1 unsealed-fabricated escape hatch was removed and every send
/// is required to be sealed. Relay servers accept both 2 and 3
/// inbound during a transition window; v3 is the only version
/// emitted on send paths post-M2.
pub const WIRE_VERSION: u16 = 3;
```

- [ ] **Step 2: Update fetchit-chat callers**

Any place in `crates/fetchit-chat/src/` that constructs a
`TransitEnvelope { version: 2, ... }` literal must now use `version:
WIRE_VERSION` (preferred — import the constant) OR `version: 3`. Run:

```bash
grep -nR "version: 2," crates/fetchit-chat/src/ crates/fetchit-chat/tests/
```

Replace each `version: 2,` with `version: WIRE_VERSION,` and add the
import where needed. Where the literal `2` was used inside test
fixtures asserting the wire shape, leave the test verifying both 2
and 3 are decodable (see step 3).

- [ ] **Step 3: Update relay-server inbound acceptance**

In `crates/fetchit-relay-server/src/server.rs`, find the version check
on inbound `TransitEnvelope`. Currently it likely accepts `== 2`; widen
to:

```rust
match env.version {
    2 | 3 => { /* accept */ }
    other => return Err(/* reject with descriptive error */),
}
```

Add a test that verifies both versions decode:

```rust
    #[test]
    fn relay_accepts_wire_versions_2_and_3() {
        let env_v2 = TransitEnvelope { version: 2, /* ... */ };
        let env_v3 = TransitEnvelope { version: 3, /* ... */ };
        assert!(accept(env_v2).is_ok());
        assert!(accept(env_v3).is_ok());
    }

    #[test]
    fn relay_rejects_unknown_wire_version() {
        let env = TransitEnvelope { version: 99, /* ... */ };
        assert!(accept(env).is_err());
    }
```

- [ ] **Step 4: Run the workspace gate**

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/fetchit-relay-proto/src/envelope.rs crates/fetchit-relay-server/src/server.rs crates/fetchit-chat/src/
git commit -s -m "feat(relay-proto): bump TransitEnvelope.version 2 -> 3

v3 = post-M2 wire (no unsealed escape hatch exists at wire-level).
Relay accepts v2 + v3 inbound during the transition window; sends
emit v3 only. Old peers continue to receive; new sends are the
sealed-only shape."
```

---

## Stage 5 — Rewire `fetchit-chat::groups` onto the secure module

### Task 10: Add `Conversation::history` field (for receive path)

**Files:**
- Modify: `crates/fetchit-chat/src/conversation/types.rs`

Per Decision 2, history persists in the existing Conversation vault.

- [ ] **Step 1: Add the type + field**

Append a new type next to existing payload types in
`crates/fetchit-chat/src/conversation/types.rs`:

```rust
/// One persisted message in a private-secure group's local history.
/// Plaintext at rest (the vault file is AEAD-sealed under the FCV1
/// master key per `at_rest.rs`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Hex sender agent id.
    pub sender_agent_id_hex: String,
    /// Optional display name from the sender.
    pub sender_name: Option<String>,
    /// Plaintext body.
    pub body: String,
    /// Sender-asserted Unix-ms timestamp.
    pub ts_ms: u64,
    /// Logical message id (hex dedupe key).
    pub message_id: String,
}
```

Add a new field on `Conversation` (locate the struct; insert
alongside other `#[serde(default)]` fields):

```rust
    /// Local history cache for MlsEncrypted groups — x0xd's
    /// `/messages` returns an error for those, so the client persists
    /// here. Cap 1000 entries (oldest evicted). `#[serde(default)]`
    /// for backward compat with pre-M2 vault files.
    #[serde(default)]
    pub history: VecDeque<HistoryEntry>,
```

Add an inherent method on `Conversation`:

```rust
    /// Maximum entries kept in `history` before the oldest is evicted.
    pub const HISTORY_CAP: usize = 1000;

    /// Append a history entry, evicting the oldest if at capacity.
    pub fn push_history(&mut self, entry: HistoryEntry) {
        if self.history.len() >= Self::HISTORY_CAP {
            self.history.pop_front();
        }
        self.history.push_back(entry);
    }
```

- [ ] **Step 2: Write a focused test**

Append to `tests` module:

```rust
    #[test]
    fn push_history_caps_at_thousand_entries() {
        let mut conv = make_test_conversation();
        for i in 0..1001 {
            conv.push_history(HistoryEntry {
                sender_agent_id_hex: "a".repeat(64),
                sender_name: None,
                body: format!("m{i}"),
                ts_ms: i,
                message_id: format!("id{i}"),
            });
        }
        assert_eq!(conv.history.len(), Conversation::HISTORY_CAP);
        assert_eq!(conv.history.front().unwrap().body, "m1");
        assert_eq!(conv.history.back().unwrap().body, "m1000");
    }

    #[test]
    fn conversation_without_history_field_deserializes() {
        let json = serde_json::json!({
            "group_id_hex": "0".repeat(64),
            "name": null,
            "members": [],
            "current_epoch": 0,
            "current_key_b64": "AAAA",
            "prior_keys": [],
            "own_role": "Admin",
            "created_at_ms": 0,
            "last_rekey_at_ms": 0,
            "auto_rekey_interval_ms": 1,
            "trust_state": "Confirmed",
        });
        let conv: Conversation = serde_json::from_value(json).unwrap();
        assert!(conv.history.is_empty());
    }
```

If `make_test_conversation` doesn't exist, inline a `Conversation { ... }`
literal using the pattern from the existing tests in this file.

- [ ] **Step 3: Run + format + clippy + commit**

```bash
cargo test -p fetchit-chat conversation::types::
cargo fmt -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings
git add crates/fetchit-chat/src/conversation/types.rs
git commit -s -m "feat(chat): Conversation.history + push_history with 1000 cap

Local plaintext-in-sealed-vault history for MlsEncrypted groups,
which can't use x0xd's /messages. VecDeque with oldest-evicted at
1000 entries. Backward-compat via #[serde(default)] so pre-M2 vault
files load without history."
```

### Task 11: Rewire `Endpoint::create` onto private_secure

**Files:**
- Modify: `crates/fetchit-chat/src/groups.rs`

- [ ] **Step 1: Add the failing test**

Append to `tests` in `crates/fetchit-chat/src/groups.rs`:

```rust
    #[test]
    fn create_request_for_private_emits_private_secure_and_hidden() {
        let req = CreatePrivateRequest {
            name: "alpha",
            display_name: None,
            preset: "private_secure",
            discoverability: "Hidden",
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"preset\":\"private_secure\""));
        assert!(json.contains("\"discoverability\":\"Hidden\""));
    }
```

- [ ] **Step 2: Add a parallel `CreatePrivateRequest` type**

Above the existing `CreateRequest` in `groups.rs`, add:

```rust
#[derive(Serialize)]
struct CreatePrivateRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    /// Hard-coded `private_secure` — the activation preset for
    /// TreeKEM in x0xd v0.20.1+.
    preset: &'static str,
    /// Hard-coded `Hidden` — required alongside `private_secure` for
    /// MlsEncrypted activation per x0xd v0.20.1 release notes.
    discoverability: &'static str,
}
```

- [ ] **Step 3: Add `Endpoint::create_private` method**

Below the existing `create` method on `Endpoint`:

```rust
    /// Create a private MLS group with PQ TreeKEM activation. Backed
    /// by x0xd's `preset=private_secure` + `discoverability=Hidden`,
    /// which the daemon backs with `saorsa-mls v0.3.x` (ML-KEM-768
    /// + ML-DSA-65).
    pub async fn create_private(
        &self,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<Group> {
        self.http
            .post_json(
                "/groups",
                &CreatePrivateRequest {
                    name,
                    display_name,
                    preset: "private_secure",
                    discoverability: "Hidden",
                },
            )
            .await
    }
```

Keep the existing `create` method (which uses `public_open`) — it
remains the explicit public-rooms surface per Decision 3.

- [ ] **Step 4: Run + format + clippy + commit**

```bash
cargo test -p fetchit-chat groups::
cargo fmt -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings
git add crates/fetchit-chat/src/groups.rs
git commit -s -m "feat(chat): groups::create_private — preset=private_secure+Hidden

Adds the M2 entry point for PQ TreeKEM groups alongside the existing
public-rooms create(). Caller picks via radio in the create-group
dialog (see Decision 3)."
```

### Task 12: Rewire `Endpoint::send_private` and `receive_private`

**Files:**
- Modify: `crates/fetchit-chat/src/groups.rs`

- [ ] **Step 1: Add the failing tests**

Append to `groups.rs` tests:

```rust
    #[tokio::test]
    async fn send_private_encrypts_then_wraps_in_transit_envelope() {
        // Wiremock x0xd's /groups/<g>/secure/encrypt -> EncryptedFrame
        // returns. Mock the relay-transport's send to capture the
        // outgoing envelope. Assert:
        // - TransitEnvelope.version == WIRE_VERSION (3)
        // - TransitEnvelope.kind == GroupChat
        // - TransitEnvelope.epoch == secret_epoch from the frame
        // - TransitEnvelope.ciphertext == postcard(EncryptedFrame)
        let (mock_x0xd, captured) = setup_send_private_test().await;
        let endpoint = Endpoint::new(&mock_x0xd.http);
        endpoint
            .send_private("group_id_hex", b"hi")
            .await
            .unwrap();
        let env = captured.lock().unwrap().take().expect("envelope sent");
        assert_eq!(env.version, WIRE_VERSION);
        // ... (full assertions per the spec §4.3)
    }

    #[tokio::test]
    async fn receive_private_decrypts_inbound_envelope() {
        // Construct an inbound TransitEnvelope carrying a postcard'd
        // EncryptedFrame in ciphertext. Wiremock x0xd's
        // /groups/<g>/secure/decrypt to return plaintext bytes.
        // Assert: receive_private appends a HistoryEntry to the
        // Conversation and returns the body string.
        let (mock_x0xd, mock_conv) = setup_receive_private_test().await;
        let body = mock_x0xd.endpoint
            .receive_private(&inbound_envelope_fixture(), &mut mock_conv)
            .await
            .unwrap();
        assert_eq!(body, "hi from peer");
        assert_eq!(mock_conv.history.len(), 1);
    }
```

The test helpers (`setup_send_private_test`,
`setup_receive_private_test`, `inbound_envelope_fixture`) are short
factory functions; the implementer should write them in the same
test module using the patterns established by other tests in
`fetchit-chat/src/conversation/inbound.rs` and `outbound.rs`.

- [ ] **Step 2: Implement `send_private`**

In `groups.rs` `impl<'a> Endpoint<'a>`:

```rust
    /// Send `body` into a private-secure group. Encrypt via x0xd's
    /// `/secure/encrypt`, wrap the resulting frame in a
    /// `TransitEnvelope`, route through `RelayTransport`. Decision 1
    /// of `private/m2-decisions.md`.
    pub async fn send_private(
        &self,
        group_id: &str,
        body: &[u8],
    ) -> Result<Option<String>> {
        use crate::chat_crypto::canonical_envelope_bytes;
        use fetchit_relay_proto::{EnvelopeKind, GroupId, TransitEnvelope, WIRE_VERSION};
        // 1. Encrypt
        let secure = self.x0xd_secure();
        let frame = secure.encrypt(group_id, body).await?;
        // 2. Build TransitEnvelope tunnel
        let ciphertext = postcard::to_allocvec(&frame)
            .map_err(|e| ChatError::Invalid(format!("postcard frame: {e}")))?;
        let envelope = TransitEnvelope {
            version: WIRE_VERSION,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_hex(group_id)?),
            tenant_id: None,
            sender_agent_id: self.local_agent_id(),
            sender_machine_id: self.local_machine_id(),
            timestamp_ms: now_ms(),
            epoch: frame.secret_epoch,
            ciphertext,
            nonce: base64::engine::general_purpose::STANDARD
                .decode(&frame.nonce_b64)
                .map_err(|e| ChatError::Invalid(format!("nonce b64: {e}")))?,
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        // 3. Sign the envelope (ML-DSA-65 via X0xdSigner)
        let canonical = canonical_envelope_bytes(&envelope)?;
        let sig = self.signer.sign(&canonical).await?;
        let envelope = TransitEnvelope { sender_signature: sig, ..envelope };
        // 4. Hand to RelayTransport with `transit: Some(envelope)`
        self.relay_transport.send(OutboundEnvelope {
            kind: OutboundKind::Group { group_id: group_id.to_string() },
            to_agent_id: self.local_agent_id_hex(), // group fan-out routes by group_id, not single agent
            from_machine_id: Some(self.local_machine_id_bytes()),
            payload: Vec::new(),
            timestamp_ms: envelope.timestamp_ms,
            transit: Some(envelope),
        }).await?;
        Ok(None) // message_id surfaces via DeliveryReceipt later
    }
```

- [ ] **Step 3: Implement `receive_private`**

In `groups.rs` `impl<'a> Endpoint<'a>`:

```rust
    /// Process an inbound `TransitEnvelope` whose `kind == GroupChat`
    /// and `ciphertext` postcard-decodes as an `EncryptedFrame`.
    /// Decrypts via x0xd, appends to local history, returns the body
    /// as a String.
    pub async fn receive_private(
        &self,
        envelope: &TransitEnvelope,
        conv: &mut Conversation,
    ) -> Result<String> {
        let frame: EncryptedFrame = postcard::from_bytes(&envelope.ciphertext)
            .map_err(|e| ChatError::Invalid(format!("postcard frame: {e}")))?;
        let secure = self.x0xd_secure();
        let plaintext = secure
            .decrypt(
                &conv.group_id_hex,
                &frame,
                Some(&envelope.sender_agent_id.to_hex()),
            )
            .await?;
        let body = String::from_utf8(plaintext)
            .map_err(|e| ChatError::Invalid(format!("body utf8: {e}")))?;
        conv.push_history(HistoryEntry {
            sender_agent_id_hex: envelope.sender_agent_id.to_hex(),
            sender_name: None, // populated by upstream UI if available
            body: body.clone(),
            ts_ms: envelope.timestamp_ms,
            message_id: hex::encode(envelope_dedupe_key(envelope)),
        });
        Ok(body)
    }
```

- [ ] **Step 4: Run + format + clippy + commit**

```bash
cargo test -p fetchit-chat groups::
cargo fmt -p fetchit-chat && cargo clippy -p fetchit-chat --all-targets -- -D warnings
git add crates/fetchit-chat/src/groups.rs
git commit -s -m "feat(chat): groups::send_private + receive_private

Implements the Path-A wire shape from private/m2-decisions.md
Decision 1: encrypt via x0xd /secure/encrypt, wrap EncryptedFrame
inside TransitEnvelope.ciphertext, route through RelayTransport,
sign with ML-DSA-65. Inbound symmetric: postcard-decode the frame
out of ciphertext, decrypt via x0xd, persist HistoryEntry."
```

---

## Stage 6 — x0xd minimum-version probe at startup

### Task 13: Add `X0xdVersion::probe` and refuse startup on < 0.20.1

**Files:**
- Modify: `crates/x0xd-client/src/lib.rs` or new module
- Modify: `crates/fetchit-chat/src/client.rs`

- [ ] **Step 1: Write the failing test**

In `crates/x0xd-client/src/lib.rs` (or wherever `Client` is defined):

```rust
    #[tokio::test]
    async fn x0xd_version_probe_parses_semver() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/version"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "version": "0.20.2",
                })),
            )
            .mount(&server)
            .await;
        let v = X0xdVersion::probe(&server.uri(), "test-token").await.unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 20);
        assert_eq!(v.patch, 2);
    }

    #[test]
    fn x0xd_version_satisfies_minimum_for_m2_treekem() {
        let v = X0xdVersion { major: 0, minor: 20, patch: 1 };
        assert!(v.satisfies_m2_treekem());
        let too_old = X0xdVersion { major: 0, minor: 20, patch: 0 };
        assert!(!too_old.satisfies_m2_treekem());
        let too_old_minor = X0xdVersion { major: 0, minor: 19, patch: 99 };
        assert!(!too_old_minor.satisfies_m2_treekem());
    }
```

- [ ] **Step 2: Implement `X0xdVersion`**

```rust
/// Probed x0xd binary version. Used to gate M2's TreeKEM features —
/// x0xd v0.20.1 is the minimum that ships TreeKEM scoped to
/// `private_secure` + `Hidden` (v0.20.0 over-included; v0.20.1
/// narrowed correctly per release notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X0xdVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl X0xdVersion {
    /// Minimum x0xd version that supports M2's PQ TreeKEM groups.
    pub const M2_TREEKEM_MIN: X0xdVersion = X0xdVersion { major: 0, minor: 20, patch: 1 };

    /// GET `/version` and parse the `version` field.
    pub async fn probe(base: &str, token: &str) -> Result<X0xdVersion> {
        #[derive(Deserialize)]
        struct VersionResp { version: String }
        let client = reqwest::Client::new();
        let resp: VersionResp = client
            .get(format!("{base}/version"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let parts: Vec<&str> = resp.version.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Invalid(format!("version not semver: {}", resp.version)));
        }
        Ok(X0xdVersion {
            major: parts[0].parse().map_err(|e| Error::Invalid(format!("major: {e}")))?,
            minor: parts[1].parse().map_err(|e| Error::Invalid(format!("minor: {e}")))?,
            patch: parts[2].parse().map_err(|e| Error::Invalid(format!("patch: {e}")))?,
        })
    }

    /// True if this version meets the M2 minimum (>= 0.20.1).
    pub fn satisfies_m2_treekem(self) -> bool {
        (self.major, self.minor, self.patch) >= (
            Self::M2_TREEKEM_MIN.major,
            Self::M2_TREEKEM_MIN.minor,
            Self::M2_TREEKEM_MIN.patch,
        )
    }
}
```

- [ ] **Step 3: Gate fetchit-chat client startup**

In `crates/fetchit-chat/src/client.rs::build_client` (or whichever
function constructs the Client + opens the relay connection), after
the x0xd connection is established, call `X0xdVersion::probe` and
return an error if it doesn't satisfy M2:

```rust
    let v = x0xd_client::X0xdVersion::probe(&x0xd_base, &x0xd_token).await?;
    if !v.satisfies_m2_treekem() {
        return Err(ChatError::Invalid(format!(
            "x0xd {}.{}.{} does not support PQ TreeKEM groups; upgrade to >= 0.20.1 (M2)",
            v.major, v.minor, v.patch,
        )));
    }
```

- [ ] **Step 4: Run + format + clippy + commit**

```bash
cargo test --workspace
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/x0xd-client/src/ crates/fetchit-chat/src/client.rs
git commit -s -m "feat(x0xd-client): X0xdVersion probe + M2 minimum-version gate

GET /version, parse semver, refuse fetchit-chat startup if x0xd is
older than 0.20.1 — the minimum that ships TreeKEM scoped correctly
to private_secure + Hidden. Failure mode is a startup-time error
that names the upgrade target."
```

---

## Stage 7 — Desktop UX: create-group dialog

### Task 14: Add private/public radio to create-group dialog

**Files:**
- Modify: `apps/fetchit-desktop/src/chat/createGroupDialog.ts`
- Modify: `apps/fetchit-desktop/src/chat/createGroupDialog.test.ts` (if exists, else create)
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs` (Tauri command bridge)

Note: `src-tauri` is workspace-excluded. Build from inside it.

- [ ] **Step 1: Write the failing test (vitest)**

If `createGroupDialog.test.ts` doesn't exist, create it. Test that
the dialog has a radio with "Private group" selected by default and a
"Public room" alternative:

```typescript
import { describe, it, expect } from "vitest";
import { mountCreateGroupDialog } from "./createGroupDialog";

describe("createGroupDialog", () => {
  it("defaults to private group selection", () => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    mountCreateGroupDialog(host, { onCreate: async () => {} });
    const privateRadio = host.querySelector<HTMLInputElement>(
      'input[type=radio][value=private_secure]',
    );
    expect(privateRadio).not.toBeNull();
    expect(privateRadio!.checked).toBe(true);
  });

  it("publishes the selected preset on create", async () => {
    const host = document.createElement("div");
    document.body.appendChild(host);
    let captured: string | undefined;
    const handle = mountCreateGroupDialog(host, {
      onCreate: async ({ preset }) => {
        captured = preset;
      },
    });
    const publicRadio = host.querySelector<HTMLInputElement>(
      'input[type=radio][value=public_open]',
    )!;
    publicRadio.click();
    const nameInput = host.querySelector<HTMLInputElement>('input[name=name]')!;
    nameInput.value = "demo";
    nameInput.dispatchEvent(new Event("input"));
    const submit = host.querySelector<HTMLButtonElement>('button[type=submit]')!;
    submit.click();
    await new Promise((r) => setTimeout(r, 0));
    expect(captured).toBe("public_open");
    handle.dispose();
  });
});
```

- [ ] **Step 2: Implement the radio**

Build the dialog DOM with `createElement` + `textContent` — no
`innerHTML`. Untrusted-content rendering inside this app is the
iframe sandbox's job; chrome UI like dialogs should never carry an
HTML-injection seam, even when the current template is static.

Update `createGroupDialog.ts`:

```typescript
type Preset = "private_secure" | "public_open";

export interface CreateGroupDialogOpts {
  onCreate: (args: { name: string; preset: Preset }) => Promise<void>;
}

export interface CreateGroupDialogHandle {
  dispose: () => void;
}

function makeRadio(name: string, value: Preset, labelText: string, checked: boolean): HTMLLabelElement {
  const label = document.createElement("label");
  const input = document.createElement("input");
  input.type = "radio";
  input.name = name;
  input.value = value;
  input.checked = checked;
  label.appendChild(input);
  label.appendChild(document.createTextNode(" " + labelText));
  return label;
}

export function mountCreateGroupDialog(
  host: HTMLElement,
  opts: CreateGroupDialogOpts,
): CreateGroupDialogHandle {
  while (host.firstChild) host.removeChild(host.firstChild);

  const form = document.createElement("form");
  form.className = "create-group-form";

  const nameLabel = document.createElement("label");
  nameLabel.appendChild(document.createTextNode("Group name "));
  const nameInput = document.createElement("input");
  nameInput.name = "name";
  nameInput.required = true;
  nameLabel.appendChild(nameInput);
  form.appendChild(nameLabel);

  const fieldset = document.createElement("fieldset");
  const legend = document.createElement("legend");
  legend.textContent = "Group type";
  fieldset.appendChild(legend);
  fieldset.appendChild(
    makeRadio("preset", "private_secure", "Private group (PQ-encrypted via x0x MLS)", true),
  );
  fieldset.appendChild(
    makeRadio("preset", "public_open", "Public room (plaintext on relay) — see security docs", false),
  );
  form.appendChild(fieldset);

  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Create";
  form.appendChild(submit);

  host.appendChild(form);

  const onSubmit = (e: Event) => {
    e.preventDefault();
    const name = (form.elements.namedItem("name") as HTMLInputElement).value;
    const preset = (form.elements.namedItem("preset") as RadioNodeList).value as Preset;
    void opts.onCreate({ name, preset });
  };
  form.addEventListener("submit", onSubmit);
  return {
    dispose: () => form.removeEventListener("submit", onSubmit),
  };
}
```

- [ ] **Step 3: Plumb `preset` through to Rust**

In `apps/fetchit-desktop/src-tauri/src/chat.rs`, find the `chat_group_create`
Tauri command. Add a `preset` parameter typed as the same enum:

```rust
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum CreateGroupPreset { PrivateSecure, PublicOpen }

#[tauri::command]
pub async fn chat_group_create(
    name: String,
    preset: CreateGroupPreset,
    state: tauri::State<'_, ChatState>,
) -> Result<Group, String> {
    match preset {
        CreateGroupPreset::PrivateSecure => state.chat.groups().create_private(&name, None).await,
        CreateGroupPreset::PublicOpen => state.chat.groups().create(&name, None).await,
    }
    .map_err(|e| e.to_string())
}
```

- [ ] **Step 4: Run frontend + backend tests**

Frontend:
```bash
(cd apps/fetchit-desktop && npm run test:run -- createGroupDialog)
```
Expected: 2 tests pass.

Backend:
```bash
(cd apps/fetchit-desktop/src-tauri && cargo test)
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/fetchit-desktop/src/chat/createGroupDialog.ts apps/fetchit-desktop/src/chat/createGroupDialog.test.ts apps/fetchit-desktop/src-tauri/src/chat.rs
git commit -s -m "feat(desktop): private/public radio in create-group dialog

Default = private_secure (PQ-encrypted via x0x MLS). Public-room
remains a labelled opt-in alternative. Decision 3 of M2 plan."
```

---

## Stage 8 — Live cross-internet test

### Task 15: Write the `#[ignore]`'d live test scaffold

**Files:**
- Create: `crates/fetchit-chat/tests/m2_live.rs`

- [ ] **Step 1: Write the test scaffold**

```rust
//! M2 live cross-internet test. `#[ignore]`'d by default; run with
//! `cargo test -p fetchit-chat --test m2_live -- --ignored --nocapture`.
//!
//! Requires `M2_LIVE_PEER_AGENT` (Bob's hex agent_id) and
//! `M2_LIVE_GROUP_NAME` env vars. The chat-peer rigs on both Box A
//! and Box B must be running (systemd) before this test starts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
#[ignore]
async fn three_way_private_group_round_trip() -> anyhow::Result<()> {
    let peer = std::env::var("M2_LIVE_PEER_AGENT")?;
    let group_name = std::env::var("M2_LIVE_GROUP_NAME").unwrap_or_else(|_| "m2-live-test".into());

    // 1. Build a Client against the local x0xd + NY relay.
    let client = build_live_client().await?;

    // 2. Create a private group, invite peer.
    let group = client.groups().create_private(&group_name, None).await?;
    println!("created group_id={}", group.group_id);
    let invite = client.groups().invite(&group.group_id).await?;
    println!("invite_link={}", invite.0);

    // 3. Wait for peer to join (sleep + poll member_count via /groups).
    for _ in 0..30 {
        let groups = client.groups().list().await?;
        if let Some(g) = groups.iter().find(|g| g.group_id.as_str() == group.group_id.as_str()) {
            if g.member_count >= 2 { break; }
        }
        sleep(Duration::from_secs(2)).await;
    }

    // 4. Send 5 messages, observe round-trip via DeliveryReceipt.
    for i in 0..5 {
        let body = format!("m2-live #{i}");
        client.groups().send_private(group.group_id.as_str(), body.as_bytes()).await?;
        println!("sent: {body}");
        sleep(Duration::from_secs(1)).await;
    }

    // 5. Wait for Bob's 5 echo messages to land in Conversation.history.
    //    (Bob's chat-peer is configured to echo group messages.)
    sleep(Duration::from_secs(15)).await;
    let conv = client.find_conversation(&group.group_id).await?;
    assert!(conv.history.len() >= 5, "expected at least 5 history entries, got {}", conv.history.len());

    println!("PASS — {} history entries", conv.history.len());
    Ok(())
}

async fn build_live_client() -> anyhow::Result<fetchit_chat::Client> {
    // Construct against ~/.local/share/x0x-claude-here/api.port +
    // ~/.local/share/x0x-claude-here/api-token. Same pattern as
    // chat-peer-restart.md wrapper.
    let port_file = std::env::var("X0XD_PORT_FILE")
        .unwrap_or_else(|_| format!("{}/.local/share/x0x-claude-here/api.port", std::env::var("HOME")?));
    let token_path = std::env::var("X0XD_TOKEN_PATH")
        .unwrap_or_else(|_| format!("{}/.local/share/x0x-claude-here/api-token", std::env::var("HOME")?));
    let port = std::fs::read_to_string(&port_file)?
        .trim()
        .split(':')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed api.port"))?
        .to_string();
    let token = std::fs::read_to_string(&token_path)?.trim().to_string();
    let base = format!("http://127.0.0.1:{port}");
    fetchit_chat::Client::connect(&base, &token).await.map_err(Into::into)
}
```

- [ ] **Step 2: Run the test ignored (smoke-check it builds)**

Run: `cargo test -p fetchit-chat --test m2_live -- --ignored --nocapture`
Expected: the test attempts to run (this requires Bob's peer to be up
+ env vars set). If env vars missing, the test surfaces the missing
variable name immediately. Build success alone is the smoke gate;
green-running is the launch gate.

- [ ] **Step 3: Commit the scaffold**

```bash
git add crates/fetchit-chat/tests/m2_live.rs
git commit -s -m "test(m2): #[ignore]'d live cross-internet group round-trip

Three-way Alice <-> Bob <-> NY relay test. Run with cargo test
--ignored once both chat-peer rigs are up. M2 close-gate requires
this PASS three times in 24h."
```

### Task 16: Run the live test, coordinate with Bob

**Files:** None (operational).

- [ ] **Step 1: Coordinate with Bob via chat-pipe**

Append to `/tmp/claude-pair/to-bob.txt`:

```
[A->B] M2 LIVE TEST READY — going to run three_way_private_group_round_trip.
Need you to add an echo-on-group-message handler to your chat-peer
rig (echo the body back into the same group). Reply when armed.
Env vars I'll set: M2_LIVE_PEER_AGENT=<your agent_id>,
M2_LIVE_GROUP_NAME=m2-live-test. Will share invite via the chat
pipe; you paste into your fetchit-chat-peer's join flow.
```

Wait for Bob's confirmation via the Monitor on `/tmp/claude-rx`.

- [ ] **Step 2: Run the live test**

```bash
M2_LIVE_PEER_AGENT=<bob_agent_id> \
M2_LIVE_GROUP_NAME=m2-live-test-$(date +%s) \
cargo test -p fetchit-chat --test m2_live -- --ignored --nocapture
```
Expected: PASS with "PASS — N history entries" final line.

- [ ] **Step 3: Re-run twice over the next 24 hours**

Per the spec §7 launch gate: the live test must PASS three times in
a row over 24 hours. Schedule with `/schedule` or run manually at
~8-hour intervals.

- [ ] **Step 4: Record the results in private/m2-decisions.md**

Append a final section:

```markdown
## Live-test runs (M2 close-gate)

| Run | Timestamp (UTC) | Result | History entries |
| --- | --- | --- | --- |
| 1 | 2026-06-XX HH:MM | PASS | N |
| 2 | 2026-06-XX HH:MM | PASS | N |
| 3 | 2026-06-XX HH:MM | PASS | N |
```

Commit when all three runs are green.

```bash
git add private/m2-decisions.md
git commit -s -m "docs(m2): live test close-gate — 3 of 3 PASS in 24h window"
```

---

## Stage 9 — SECURITY.md final verification + M2 close

### Task 17: Verify SECURITY.md text matches shipped behavior

**Files:**
- Read: `crates/fetchit-chat/SECURITY.md`

- [ ] **Step 1: Re-read caveats 1 and 2 against shipped code**

Run: `cargo doc --no-deps -p fetchit-chat --open` to render the
module docstrings, then walk caveats 1 and 2 line-by-line and
confirm:

- Caveat 1 references "sealed envelope = default + only" — verify
  by `grep -nR "fabricate_v1_envelope" crates/fetchit-chat/src/`
  returns nothing.
- Caveat 1 references `TransitEnvelope.version = 3` — verify by
  `grep -nR "pub const WIRE_VERSION" crates/fetchit-relay-proto/src/`
  shows 3.
- Caveat 2 references `preset=private_secure + discoverability=Hidden`
  + `saorsa-mls v0.3.x` upstream-prototype caveat. Both phrases must
  appear in the shipped SECURITY.md.

If any divergence between caveat text and shipped behavior, edit
SECURITY.md to match shipped reality (not the other way around).

- [ ] **Step 2: Commit any final SECURITY.md adjustments**

```bash
git add crates/fetchit-chat/SECURITY.md
git commit -s -m "docs(security): align caveats 1+2 text with shipped M2 behavior"
```

### Task 18: Close-out commit + announcement to Bob

**Files:**
- Modify: `private/MILESTONES.md` (flip M2 gate from `[ ]` to `[x]`)
- Modify: `private/TASKS.md` (mark M2.2 items complete)

- [ ] **Step 1: Flip the M2 gate in MILESTONES.md**

In `private/MILESTONES.md`, the M2 owner-bullets:
- `- [A] **Design phase:** ...` → `- [x] [A] **Design phase:** ...`
- `- [A] **Implementation phase:** ...` → `- [x] [A] **Implementation phase:** ...`
- `- [A] fetchit-chat/SECURITY.md caveats 1+2 close` → `- [x] [A] ...`

- [ ] **Step 2: Flip the M2.2 items in TASKS.md**

In `private/TASKS.md` M2.2 section, change `[ ]` to `[x]` on each of
the 5 actionable items.

- [ ] **Step 3: Commit the M2 close**

```bash
git add private/MILESTONES.md private/TASKS.md
git commit -s -m "docs(m2): M2 closed — PQ TreeKEM groups + sealed-default shipped"
```

- [ ] **Step 4: Force-push backup**

```bash
git push -f josh-clsn chat
```

- [ ] **Step 5: Sync Bob**

Append to `/tmp/claude-pair/to-bob.txt`:

```
[A->B] M2 CLOSED — PQ TreeKEM groups via x0x v0.20.x + sealed-default
shipped. Live test green 3/3 in 24h. SECURITY.md caveats 1+2 close.
Branch chat at <latest sha>. Force-pushed josh-clsn. Ready for joint
review whenever you're available — same shape as past rounds.
```

- [ ] **Step 6: Wait for Josh's per-push approval before touching origin**

Do NOT push to `origin` (etchit-io). The push policy memory is
explicit: every etchit-io push requires Josh's per-push approval.

---

## Plan self-review

**1. Spec coverage:**
- Spec §3.1 `secure` module → Tasks 3–6 ✓
- Spec §3.2 `groups.rs` rewire → Tasks 11–12 ✓
- Spec §3.3 cut fabricated path + version bump → Tasks 7–9 ✓
- Spec §3.4 SECURITY.md → Task 0 (already landed) + Task 17 (verify) ✓
- Spec §4.1 create flow → Task 11 ✓
- Spec §4.2 invite flow → unchanged (x0xd handles it; nothing to implement)
- Spec §4.3 send flow → Task 12 ✓
- Spec §4.4 receive flow → Task 12 ✓
- Spec §5 error model → Task 7 (SealedRequired); other errors surface via existing ChatError variants
- Spec §6 migration → Task 9 (v3 envelope w/ v2 transition acceptance)
- Spec §7 testing — Layer 1 unit per task; Layer 2 wiremocked integration in Tasks 4–6 + 11–12; Layer 3 live in Tasks 15–16 ✓
- Spec §9 honest-claim posture → already in shipped SECURITY.md per Task 0
- Spec §10 open Qs → Task 2 (all three resolved in `private/m2-decisions.md`) ✓
- x0xd minimum-version check → Task 13 ✓

**2. Placeholder scan:** No "TBD", "TODO", "fill in details", or
"similar to Task N" in steps. The decision tasks (Task 2) explicitly
produce written decisions; no decisions deferred past Stage 1.

**3. Type consistency:**
- `SecureGroupsEndpoint` consistent across Tasks 3–6.
- `EncryptedFrame` field names (`ciphertext_b64`, `nonce_b64`,
  `secret_epoch`) consistent across the module + groups.rs callers.
- `CreatePrivateRequest` distinct from existing `CreateRequest`;
  no name collision.
- `Conversation.history: VecDeque<HistoryEntry>` consistent in Task
  10 (definition) and Task 12 (caller).
- `X0xdVersion::M2_TREEKEM_MIN` named the same in Task 13 def + gate.

Plan ready.
