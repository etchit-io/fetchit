# M3 Relay Federation Constellation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the federation layer above today's single-relay-per-conversation wall: 3 concurrent WS sessions per client, signed denylist (RelayUrl + XorName + AgentId) hard-block enforcement, contact-card-driven invitation-only community-relay discovery.

**Architecture:** New `fetchit-trust-client` crate consumes signed denylists from etchit.io and exposes a `DenylistQuery` interface. New `MultiHomeTransport` wrapper in `fetchit-chat` owns N existing `RelayTransport` instances with slot-0-pinned + slot-1-2-LRU policy and inbound dedup. Card's reserved `v2_rendezvous_hints` slot is populated with a simple `wss://` URL list. Desktop + Android UIs surface advanced relay config, denylist banners, blocked indicators, and the reader's `Rendition::Blocked` placeholder.

**Tech Stack:** Rust (workspace), tokio (async runtime + broadcast channels), reqwest (HTTP client for denylist fetch), postcard (signed payload encoding), ml_dsa via x0xd-client (signature verification), Tauri 2 (desktop IPC), TS/Vite (desktop UI), Kotlin/Material3 (Android UI).

---

## File structure

**New crates:**
- `crates/fetchit-trust-client/` — consumer crate (Cargo.toml + src/{lib,consumer,index,http,cache}.rs + tests/)

**New modules:**
- `crates/fetchit-chat/src/transport/multi_home.rs`
- `crates/fetchit-chat/src/transport/nonce_dedup.rs`

**Modified files:**
- `crates/fetchit-trust/src/types.rs` — `EntryKind` extended; `TargetIdentity::value_hex` → `value`
- `crates/fetchit-trust/src/lib.rs` — `DenylistQuery` trait export
- `crates/fetchit-chat/src/card.rs` — `RendezvousHintsV1` struct + validator + `extend_with_fetchit_fields` signature change
- `crates/fetchit-chat/src/client.rs` — wire `DenylistConsumer` + `MultiHomeTransport` at boot
- `crates/fetchit-chat/src/dispatch.rs` — AgentId block on inbound
- `crates/fetchit-core/src/handler.rs` — `Rendition::Blocked` + `RenderingContext` + `render_with_context`
- `apps/fetchit-desktop/src/settings/network-advanced.ts` — NEW UI surface
- `apps/fetchit-desktop/src/chat/conversation-banner.ts` — relay-denylisted banner
- `apps/fetchit-desktop/src/chat/contacts-list.ts` — agent denylist indicator
- `apps/fetchit-desktop/src/renderers/dispatch.ts` — Blocked variant handler
- `apps/fetchit-desktop/src-tauri/src/main.rs` — `chat_regenerate_card_with_relays` command
- `apps/fetchit-android/.../*.kt` — Settings + banner + contact indicator + Blocked renderer

**Test files:**
- `crates/fetchit-trust-client/tests/consumer.rs`
- `crates/fetchit-trust-client/tests/sig_verify.rs`
- `crates/fetchit-trust-client/tests/disk_cache.rs`
- `crates/fetchit-chat/tests/m3_multi_home_basic.rs`
- `crates/fetchit-chat/tests/m3_multi_home_denylist.rs`
- `crates/fetchit-chat/tests/m3_card_rendezvous_hints.rs`
- `crates/fetchit-chat/tests/m3_live.rs` (`#[ignore]`'d)

---

## Phase A — wire schema lock (Bob convergence)

This phase is co-authored with Bob (M4 Stage 4). One commit lands both `EntryKind` variants AND the field rename. Whichever box touches `fetchit-trust::types` first lands the combined commit; the other adds consumer-only code for its variant.

### Task A1: extend `EntryKind` + rename `value_hex` → `value`

**Files:**
- Modify: `crates/fetchit-trust/src/types.rs`
- Modify: `crates/fetchit-trust/src/storage.rs` (uses `value_hex` per existing grep)

- [ ] **Step 1: Write the failing test**

```rust
// crates/fetchit-trust/src/types.rs (in #[cfg(test)] mod)
#[test]
fn relay_url_entry_kind_lowercases_value() {
    let t = TargetIdentity::new(EntryKind::RelayUrl, "WSS://Relay.Example.com/V1/WS");
    assert_eq!(t.kind, EntryKind::RelayUrl);
    assert_eq!(t.value, "wss://relay.example.com/v1/ws");
}

#[test]
fn actor_url_entry_kind_lowercases_value() {
    let t = TargetIdentity::new(EntryKind::ActorUrl, "HTTPS://Mastodon.example/Users/Eve");
    assert_eq!(t.value, "https://mastodon.example/users/eve");
}
```

Run: `cargo test -p fetchit-trust relay_url_entry_kind`
Expected: FAIL with `no variant RelayUrl`.

- [ ] **Step 2: Add variants + rename**

```rust
pub enum EntryKind {
    XorName,
    AgentId,
    RelayUrl,   // NEW (M3)
    ActorUrl,   // NEW (M4 Stage 4 — Bob's consumer)
}

pub struct TargetIdentity {
    pub kind: EntryKind,
    pub value: String,   // renamed from value_hex
}

impl TargetIdentity {
    #[must_use]
    pub fn new(kind: EntryKind, value: impl Into<String>) -> Self {
        Self { kind, value: value.into().to_ascii_lowercase() }
    }
}
```

Update `storage.rs` references from `value_hex` to `value` (`grep -nE 'value_hex' crates/fetchit-trust/src` and sweep).

- [ ] **Step 3: Run the workspace tests**

Run: `cargo test --workspace`
Expected: green. Any remaining `value_hex` references show up as compile errors and need updating.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-trust/src/types.rs crates/fetchit-trust/src/storage.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(trust): EntryKind RelayUrl + ActorUrl, value_hex -> value rename"
```

### Task A2: `RendezvousHintsV1` struct + validator

**Files:**
- Modify: `crates/fetchit-chat/src/card.rs`
- Test: same file

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn rendezvous_hints_v1_rejects_non_wss_scheme() {
    let json = serde_json::json!({ "relays": ["ws://example.com/v1/ws"] });
    let err = RendezvousHintsV1::from_value(&json).unwrap_err();
    assert!(format!("{err}").contains("wss"));
}

#[test]
fn rendezvous_hints_v1_rejects_empty_list() {
    let json = serde_json::json!({ "relays": [] });
    assert!(RendezvousHintsV1::from_value(&json).is_err());
}

#[test]
fn rendezvous_hints_v1_rejects_too_many() {
    let urls: Vec<_> = (0..9).map(|i| format!("wss://r{i}.example/v1/ws")).collect();
    let json = serde_json::json!({ "relays": urls });
    assert!(RendezvousHintsV1::from_value(&json).is_err());
}

#[test]
fn rendezvous_hints_v1_accepts_simple_list() {
    let json = serde_json::json!({ "relays": ["wss://nyc.etchit.io/v1/ws"] });
    let parsed = RendezvousHintsV1::from_value(&json).unwrap();
    assert_eq!(parsed.relays, vec!["wss://nyc.etchit.io/v1/ws"]);
}
```

Run: `cargo test -p fetchit-chat rendezvous_hints_v1`
Expected: FAIL with `no type RendezvousHintsV1`.

- [ ] **Step 2: Implement struct + validator**

```rust
// in card.rs
const MAX_HINT_RELAYS: usize = 8;
const MAX_HINT_URL_LEN: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousHintsV1 {
    pub relays: Vec<String>,
}

impl RendezvousHintsV1 {
    pub fn from_value(v: &serde_json::Value) -> Result<Self, ChatError> {
        let parsed: Self = serde_json::from_value(v.clone())
            .map_err(|e| ChatError::Invalid(format!("hints decode: {e}")))?;
        if parsed.relays.is_empty() {
            return Err(ChatError::Invalid("hints.relays empty".into()));
        }
        if parsed.relays.len() > MAX_HINT_RELAYS {
            return Err(ChatError::Invalid(format!("hints.relays >{MAX_HINT_RELAYS}")));
        }
        for url in &parsed.relays {
            if url.len() > MAX_HINT_URL_LEN {
                return Err(ChatError::Invalid("hints url too long".into()));
            }
            if !url.starts_with("wss://") {
                return Err(ChatError::Invalid(format!("hints url scheme not wss: {url}")));
            }
        }
        Ok(parsed)
    }

    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("RendezvousHintsV1 serializes")
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p fetchit-chat rendezvous_hints_v1`
Expected: 4/4 PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/card.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(chat): RendezvousHintsV1 + validator (M3)"
```

### Task A3: `extend_with_fetchit_fields` accepts `Option<RendezvousHintsV1>`

**Files:** Modify: `crates/fetchit-chat/src/card.rs`. Test: same file + call sites.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn card_with_hints_round_trips() {
    let signer = mock_signer();
    let x0x = sample_x0x_card();
    let kem = [1u8; 32];
    let hints = RendezvousHintsV1 { relays: vec!["wss://nyc.etchit.io/v1/ws".into()] };
    let card = extend_with_fetchit_fields(&x0x, &kem, &signer, Some(hints.clone())).await.unwrap();
    let parsed = parse_extension_from_value(&card).unwrap();
    assert_eq!(parsed.v2_rendezvous_hints.as_ref().unwrap().v, 1);
    let payload = parsed.v2_rendezvous_hints.unwrap().data;
    let decoded = RendezvousHintsV1::from_value(&payload).unwrap();
    assert_eq!(decoded.relays, hints.relays);
}
```

Run: expected FAIL — `extend_with_fetchit_fields` signature has wrong arity.

- [ ] **Step 2: Change signature + thread hints into the card body**

```rust
pub async fn extend_with_fetchit_fields<S: Signer + ?Sized>(
    x0x_card: &serde_json::Value,
    kem_public_key: &[u8],
    signer: &S,
    hints: Option<RendezvousHintsV1>,
) -> Result<serde_json::Value, ChatError> {
    // ... existing body ...
    let hints_extension = hints.map(|h| RendezvousHints {
        v: 1,
        data: h.to_value(),
    });
    // ... emit into the card JSON as `fetchit_rendezvous_hints` ...
}
```

Update every call site (probably `client.rs`, integration tests) to pass `None` for now (preserves existing behavior until task E1 wires real hints).

- [ ] **Step 3: Run tests**

Run: `cargo test -p fetchit-chat card_with_hints_round_trips`
Expected: PASS.

Run: `cargo test --workspace`
Expected: green.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/card.rs crates/fetchit-chat/src/client.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(chat): extend_with_fetchit_fields accepts Option<RendezvousHintsV1>"
```

---

## Phase B — fetchit-trust extensions

### Task B1: `DenylistQuery` trait

**Files:** Modify: `crates/fetchit-trust/src/lib.rs`. Test: same file.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn dyn_denylist_query_dispatch() {
    struct Stub;
    impl DenylistQuery for Stub {
        fn is_blocked(&self, _: EntryKind, _: &str) -> bool { true }
    }
    let q: Arc<dyn DenylistQuery> = Arc::new(Stub);
    assert!(q.is_blocked(EntryKind::RelayUrl, "wss://x"));
}
```

Run: FAIL — `no trait DenylistQuery`.

- [ ] **Step 2: Add trait + export**

```rust
// crates/fetchit-trust/src/lib.rs
pub trait DenylistQuery: Send + Sync {
    fn is_blocked(&self, kind: EntryKind, value: &str) -> bool;
}
```

- [ ] **Step 3: Run test**

Run: `cargo test -p fetchit-trust dyn_denylist_query_dispatch`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-trust/src/lib.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(trust): DenylistQuery trait (M3)"
```

### Task B2: `TargetIdentity::new` URL validation hook

URLs are not hex; `to_ascii_lowercase()` is a lossy normalization. Lock the URL path explicitly so callers can rely on it.

**Files:** Modify: `crates/fetchit-trust/src/types.rs`. Test: same file.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn xorname_value_must_be_64_hex() {
    let t = TargetIdentity::try_new(EntryKind::XorName, "deadbeef");
    assert!(t.is_err());
}

#[test]
fn relay_url_must_be_wss_or_https() {
    assert!(TargetIdentity::try_new(EntryKind::RelayUrl, "wss://a.example").is_ok());
    assert!(TargetIdentity::try_new(EntryKind::RelayUrl, "ws://a.example").is_err());
    assert!(TargetIdentity::try_new(EntryKind::RelayUrl, "file:///etc/passwd").is_err());
}

#[test]
fn actor_url_must_be_https() {
    assert!(TargetIdentity::try_new(EntryKind::ActorUrl, "https://m.example/u/a").is_ok());
    assert!(TargetIdentity::try_new(EntryKind::ActorUrl, "http://m.example/u/a").is_err());
}
```

Run: FAIL — `try_new` does not exist.

- [ ] **Step 2: Add `try_new` with per-kind validation**

```rust
impl TargetIdentity {
    pub fn try_new(kind: EntryKind, value: impl Into<String>) -> Result<Self, &'static str> {
        let v = value.into().to_ascii_lowercase();
        match kind {
            EntryKind::XorName | EntryKind::AgentId => {
                if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("XorName/AgentId require 64-char lowercase hex");
                }
            }
            EntryKind::RelayUrl => {
                if !v.starts_with("wss://") { return Err("RelayUrl must be wss://"); }
            }
            EntryKind::ActorUrl => {
                if !v.starts_with("https://") { return Err("ActorUrl must be https://"); }
            }
        }
        Ok(Self { kind, value: v })
    }
}
```

Keep the infallible `new` for back-compat callers (existing tests probably use it); they continue to do unchecked lowercase. New code uses `try_new`.

- [ ] **Step 3: Run tests + workspace gate**

Run: `cargo test -p fetchit-trust try_new`
Expected: PASS.

Run: `cargo test --workspace`
Expected: green.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-trust/src/types.rs
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(trust): TargetIdentity::try_new with per-kind validation"
```

---

## Phase C — `fetchit-trust-client` crate

### Task C1: scaffold the new crate

**Files:**
- Create: `crates/fetchit-trust-client/Cargo.toml`
- Create: `crates/fetchit-trust-client/src/lib.rs`
- Modify: root `Cargo.toml` (add to `[workspace.members]`)

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "fetchit-trust-client"
version = "0.1.0"
edition = "2021"
license.workspace = true
rust-version.workspace = true

[lints]
workspace = true

[dependencies]
fetchit-trust = { path = "../fetchit-trust" }
async-trait = "0.1"
postcard = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["sync", "rt", "macros", "time"] }
tracing = { workspace = true }
ml-dsa = { workspace = true }     # via x0xd-client or saorsa-core re-export — confirm name
x0xd-client = { path = "../x0xd-client" }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
```

- [ ] **Step 2: Create lib.rs stub**

```rust
//! Consumer-side denylist verifier for fetch>it clients.
//!
//! Used by both `fetchit-chat` (RelayUrl + AgentId enforcement) and
//! `fetchit-core` / desktop (XorName enforcement for the reader UI).
#![forbid(unsafe_code)]

mod consumer;
mod http;
mod index;
mod cache;

pub use consumer::{BlockEvent, DenylistConsumer, TrustError};
pub use http::HttpClient;
```

Empty `consumer.rs`, `http.rs`, `index.rs`, `cache.rs` with `//!` doc and a `pub use` placeholder.

- [ ] **Step 3: Register in workspace + verify build**

Add `"crates/fetchit-trust-client"` to root `Cargo.toml` `[workspace.members]`.

Run: `cargo build -p fetchit-trust-client`
Expected: clean (empty crate).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/fetchit-trust-client/
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "scaffold(trust-client): new fetchit-trust-client crate (M3)"
```

### Task C2: `HttpClient` trait + reqwest impl

**Files:** Modify: `crates/fetchit-trust-client/src/http.rs`. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn stub_http_client_returns_bytes() {
    struct Stub(Vec<u8>);
    #[async_trait::async_trait]
    impl HttpClient for Stub {
        async fn get(&self, _: &str) -> Result<Vec<u8>, TrustError> { Ok(self.0.clone()) }
    }
    let c = Stub(b"hello".to_vec());
    assert_eq!(c.get("ignored").await.unwrap(), b"hello");
}
```

Run: FAIL — `HttpClient` trait does not exist.

- [ ] **Step 2: Define trait + reqwest impl**

```rust
// http.rs
use async_trait::async_trait;
use crate::consumer::TrustError;

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError>;
}

#[cfg(feature = "reqwest")]
pub struct ReqwestClient(pub reqwest::Client);

#[cfg(feature = "reqwest")]
#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError> {
        let resp = self.0.get(url).send().await.map_err(|e| TrustError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TrustError::Http(format!("status {}", resp.status())));
        }
        Ok(resp.bytes().await.map_err(|e| TrustError::Http(e.to_string()))?.to_vec())
    }
}
```

Gate the reqwest impl behind a feature flag so the crate stays pure-Rust by default.

- [ ] **Step 3: Test passes**

Run: `cargo test -p fetchit-trust-client stub_http_client`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-trust-client/src/http.rs crates/fetchit-trust-client/Cargo.toml
git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(trust-client): HttpClient trait + reqwest impl"
```

### Task C3: `DenylistIndexes` in-memory store

**Files:** Modify: `crates/fetchit-trust-client/src/index.rs`. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn index_replace_swaps_kind_atomically() {
    let mut idx = DenylistIndexes::default();
    idx.replace(EntryKind::RelayUrl, vec!["wss://a".into(), "wss://b".into()]);
    assert!(idx.is_blocked(EntryKind::RelayUrl, "wss://a"));
    assert!(!idx.is_blocked(EntryKind::RelayUrl, "wss://c"));
    idx.replace(EntryKind::RelayUrl, vec!["wss://c".into()]);
    assert!(!idx.is_blocked(EntryKind::RelayUrl, "wss://a"));
    assert!(idx.is_blocked(EntryKind::RelayUrl, "wss://c"));
}

#[test]
fn index_isolates_kinds() {
    let mut idx = DenylistIndexes::default();
    idx.replace(EntryKind::RelayUrl, vec!["wss://a".into()]);
    assert!(!idx.is_blocked(EntryKind::AgentId, "wss://a"));
}
```

Run: FAIL.

- [ ] **Step 2: Implement**

```rust
use std::collections::HashSet;
use fetchit_trust::EntryKind;

#[derive(Default, Debug)]
pub(crate) struct DenylistIndexes {
    xor_names: HashSet<String>,
    agent_ids: HashSet<String>,
    relay_urls: HashSet<String>,
    actor_urls: HashSet<String>,
}

impl DenylistIndexes {
    pub fn replace(&mut self, kind: EntryKind, values: Vec<String>) -> Delta {
        let target = self.bucket_mut(kind);
        let new: HashSet<String> = values.into_iter().collect();
        let added: Vec<String> = new.difference(target).cloned().collect();
        let removed: Vec<String> = target.difference(&new).cloned().collect();
        *target = new;
        Delta { kind, added, removed }
    }

    pub fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        self.bucket(kind).contains(&value.to_ascii_lowercase())
    }

    fn bucket(&self, kind: EntryKind) -> &HashSet<String> { /* match */ }
    fn bucket_mut(&mut self, kind: EntryKind) -> &mut HashSet<String> { /* match */ }
}

pub struct Delta {
    pub kind: EntryKind,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}
```

- [ ] **Step 3: Run tests** → PASS.
- [ ] **Step 4: Commit** `feat(trust-client): DenylistIndexes in-memory store with delta tracking`

### Task C4: `DenylistConsumer::refresh` (single-kind GET + verify + swap)

**Files:** Modify: `crates/fetchit-trust-client/src/consumer.rs`. Test: inline + `tests/sig_verify.rs`.

- [ ] **Step 1: Write failing test**

```rust
// tests/sig_verify.rs
#[tokio::test]
async fn refresh_accepts_signed_response_and_indexes() {
    let (priv_key, pub_key) = test_mldsa_keypair();
    let stub_http = StubHttp::new_signed(&priv_key, EntryKind::RelayUrl, &["wss://bad.example/v1/ws"]);
    let consumer = DenylistConsumer::new(pub_key, "https://etchit.io/v1".into(), None);
    consumer.refresh(&stub_http).await.unwrap();
    assert!(consumer.is_blocked(EntryKind::RelayUrl, "wss://bad.example/v1/ws"));
}

#[tokio::test]
async fn refresh_rejects_bad_signature_and_keeps_old_index() {
    let (good_priv, good_pub) = test_mldsa_keypair();
    let (bad_priv, _) = test_mldsa_keypair();
    let stub = StubHttp::new_signed(&good_priv, EntryKind::RelayUrl, &["wss://a"]);
    let c = DenylistConsumer::new(good_pub, "x".into(), None);
    c.refresh(&stub).await.unwrap();
    assert!(c.is_blocked(EntryKind::RelayUrl, "wss://a"));
    let evil = StubHttp::new_signed(&bad_priv, EntryKind::RelayUrl, &["wss://b"]);
    let err = c.refresh(&evil).await.unwrap_err();
    assert!(matches!(err, TrustError::BadSignature(_)));
    assert!(c.is_blocked(EntryKind::RelayUrl, "wss://a"));  // unchanged
    assert!(!c.is_blocked(EntryKind::RelayUrl, "wss://b"));
}
```

`StubHttp::new_signed` builds the `DenylistResponse` postcard payload + ML-DSA-65 signature in-process so the test has no I/O.

Run: FAIL — `DenylistConsumer` does not exist.

- [ ] **Step 2: Implement consumer + refresh**

```rust
// consumer.rs
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, RwLock};
use fetchit_trust::{DenylistQuery, DenylistResponse, DenylistToSign, EntryKind};
use crate::index::{DenylistIndexes, Delta};
use crate::http::HttpClient;

const ALL_KINDS: [EntryKind; 4] = [
    EntryKind::XorName,
    EntryKind::AgentId,
    EntryKind::RelayUrl,
    EntryKind::ActorUrl,
];

pub struct DenylistConsumer {
    fetch_url_base: String,
    pubkey: VerifyingKey,           // ml-dsa-65
    indexes: Arc<RwLock<DenylistIndexes>>,
    poll_interval: Duration,
    cache_path: Option<PathBuf>,
    tx: broadcast::Sender<BlockEvent>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("HTTP: {0}")] Http(String),
    #[error("decode: {0}")] Decode(String),
    #[error("bad signature: {0}")] BadSignature(String),
    #[error("io: {0}")] Io(String),
}

#[derive(Clone, Debug)]
pub struct BlockEvent {
    pub kind: EntryKind,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl DenylistConsumer {
    pub fn new(pubkey: VerifyingKey, fetch_url_base: String, cache_path: Option<PathBuf>) -> Self { ... }

    pub async fn refresh<C: HttpClient>(&self, client: &C) -> Result<(), TrustError> {
        for kind in ALL_KINDS {
            let url = format!("{}/denylist?kind={}", self.fetch_url_base, kind_query_str(kind));
            let bytes = client.get(&url).await?;
            let resp: DenylistResponse = postcard::from_bytes(&bytes)
                .map_err(|e| TrustError::Decode(e.to_string()))?;
            verify_signed_response(&self.pubkey, &resp)?;
            let values: Vec<String> = resp.entries.iter().map(|e| e.target.value.clone()).collect();
            let delta = {
                let mut idx = self.indexes.write().await;
                idx.replace(resp.kind, values)
            };
            if !delta.added.is_empty() || !delta.removed.is_empty() {
                let _ = self.tx.send(BlockEvent { kind: delta.kind, added: delta.added, removed: delta.removed });
            }
        }
        Ok(())
    }
}

fn verify_signed_response(pubkey: &VerifyingKey, resp: &DenylistResponse) -> Result<(), TrustError> {
    let to_sign = DenylistToSign {
        etag: &resp.etag,
        generated_at_ms: resp.generated_at_ms,
        kind: resp.kind,
        entries: &resp.entries,
    };
    let signing_bytes = postcard::to_allocvec(&to_sign)
        .map_err(|e| TrustError::Decode(e.to_string()))?;
    let sig_bytes = hex::decode(&resp.issuer_signature_hex)
        .map_err(|e| TrustError::Decode(e.to_string()))?;
    pubkey.verify(&signing_bytes, &sig_bytes)
        .map_err(|e| TrustError::BadSignature(e.to_string()))
}
```

Per the brainstorm: refresh fails the WHOLE refresh if ANY kind's response has a bad signature — keeping the per-kind previous good index. Simplest implementation: on per-kind error, log + skip that kind + continue (do NOT clear the index). Tests already validate that.

Adjust the loop to swallow per-kind errors after logging:

```rust
for kind in ALL_KINDS {
    if let Err(e) = self.refresh_one(client, kind).await {
        tracing::warn!(?kind, error=%e, "denylist refresh failed; keeping previous index");
        last_err = Some(e);
    }
}
last_err.map_or(Ok(()), Err)   // surface ONE error if any kind failed
```

- [ ] **Step 3: Tests pass**

Run: `cargo test -p fetchit-trust-client refresh_`
Expected: 2/2 PASS.

- [ ] **Step 4: Commit** `feat(trust-client): DenylistConsumer::refresh with signature verify`

### Task C5: `DenylistConsumer::is_blocked` + `DenylistQuery` impl

**Files:** Modify: `crates/fetchit-trust-client/src/consumer.rs`. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn is_blocked_works_through_dyn_trait() {
    let (priv_k, pub_k) = test_mldsa_keypair();
    let stub = StubHttp::new_signed(&priv_k, EntryKind::AgentId, &["aaaa…"]);
    let consumer = Arc::new(DenylistConsumer::new(pub_k, "x".into(), None));
    consumer.refresh(stub.as_ref()).await.unwrap();
    let dyn_q: Arc<dyn DenylistQuery> = consumer.clone() as Arc<dyn DenylistQuery>;
    assert!(dyn_q.is_blocked(EntryKind::AgentId, "aaaa…"));
}
```

Run: FAIL — `impl DenylistQuery for DenylistConsumer` missing.

- [ ] **Step 2: Implement**

```rust
impl DenylistConsumer {
    pub fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        // RwLock::blocking_read OR a tokio runtime guard — since this is
        // called from sync contexts (renderer, dispatch), use blocking_read.
        // The lock is contended very rarely (refresh path holds write briefly).
        self.indexes.blocking_read().is_blocked(kind, value)
    }
}

impl DenylistQuery for DenylistConsumer {
    fn is_blocked(&self, kind: EntryKind, value: &str) -> bool {
        DenylistConsumer::is_blocked(self, kind, value)
    }
}
```

- [ ] **Step 3: Test passes** → PASS.
- [ ] **Step 4: Commit** `feat(trust-client): DenylistConsumer implements DenylistQuery`

### Task C6: `subscribe()` broadcast channel

**Files:** consumer.rs. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn subscribe_receives_block_events() {
    let (priv_k, pub_k) = test_mldsa_keypair();
    let stub = StubHttp::new_signed(&priv_k, EntryKind::RelayUrl, &["wss://x"]);
    let consumer = DenylistConsumer::new(pub_k, "x".into(), None);
    let mut rx = consumer.subscribe();
    consumer.refresh(&stub).await.unwrap();
    let evt = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await.unwrap().unwrap();
    assert_eq!(evt.kind, EntryKind::RelayUrl);
    assert_eq!(evt.added, vec!["wss://x".to_string()]);
}
```

- [ ] **Step 2: Add `subscribe` method** (channel created in `new`). Already emits via `self.tx.send(BlockEvent)` in `refresh`. Just add the `subscribe()` accessor.
- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(trust-client): BlockEvent broadcast on refresh delta`

### Task C7: `spawn_poll_loop`

**Files:** consumer.rs. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test(start_paused = true)]
async fn poll_loop_refreshes_on_interval() {
    let (priv_k, pub_k) = test_mldsa_keypair();
    let stub = Arc::new(CountingStub::new_signed(&priv_k, EntryKind::RelayUrl, &["wss://x"]));
    let consumer = Arc::new(DenylistConsumer::new_with_interval(
        pub_k, "x".into(), None, Duration::from_secs(60),
    ));
    let _h = Arc::clone(&consumer).spawn_poll_loop(stub.clone());
    tokio::time::sleep(Duration::from_secs(0)).await;   // let the initial fire
    assert_eq!(stub.count(), 4);  // one GET per EntryKind
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(stub.count(), 12); // 4 kinds × (1 initial + 2 polls)
}
```

- [ ] **Step 2: Add `spawn_poll_loop`**

```rust
pub fn spawn_poll_loop<C: HttpClient + 'static>(self: Arc<Self>, client: C) -> JoinHandle<()> {
    let client = Arc::new(client);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(self.poll_interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.refresh(client.as_ref()).await {
                tracing::warn!(error=%e, "denylist refresh");
            }
        }
    })
}
```

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(trust-client): spawn_poll_loop background refresh`

### Task C8: disk cache persist + offline boot

**Files:** Modify: `crates/fetchit-trust-client/src/cache.rs` + consumer.rs. Test: `tests/disk_cache.rs`.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn offline_boot_reads_disk_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("denylist");

    // populate cache via a fully online run
    {
        let (priv_k, pub_k) = test_mldsa_keypair();
        let stub = StubHttp::new_signed(&priv_k, EntryKind::RelayUrl, &["wss://x"]);
        let c = DenylistConsumer::new(pub_k.clone(), "x".into(), Some(cache.clone()));
        c.refresh(&stub).await.unwrap();
    }

    // simulate offline boot
    let (_, pub_k) = same_keypair_as_before();
    let c = DenylistConsumer::new(pub_k, "x".into(), Some(cache));
    c.load_cache_blocking();  // sync at boot
    assert!(c.is_blocked(EntryKind::RelayUrl, "wss://x"));
}
```

- [ ] **Step 2: Implement cache write on refresh + load_cache_blocking on boot**

Cache files: `<cache_path>/<kind>.bin` — raw postcard bytes of the last good `DenylistResponse`. Each refresh writes after successful verify. Boot reads each kind's file, verifies signature again, hydrates index.

- [ ] **Step 3: Test passes.**
- [ ] **Step 4: Commit** `feat(trust-client): disk cache persist + offline boot reload`

### Task C9: poisoning resilience

A test that proves fail-closed against tampering: a poisoned cache file is rejected on boot, the index stays empty for that kind, and a later good refresh recovers.

**Files:** Test: `tests/disk_cache.rs`.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn poisoned_cache_file_is_rejected_index_recovers_on_next_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("denylist");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("relay_url.bin"), b"GARBAGE").unwrap();

    let (priv_k, pub_k) = test_mldsa_keypair();
    let c = DenylistConsumer::new(pub_k, "x".into(), Some(cache));
    c.load_cache_blocking();
    assert!(!c.is_blocked(EntryKind::RelayUrl, "wss://x"));  // poisoned file ignored

    let stub = StubHttp::new_signed(&priv_k, EntryKind::RelayUrl, &["wss://x"]);
    c.refresh(&stub).await.unwrap();
    assert!(c.is_blocked(EntryKind::RelayUrl, "wss://x"));
}
```

- [ ] **Step 2: Already implied by load_cache_blocking using the same verify path.** Make sure it logs + continues per-kind on decode/verify failure.
- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `test(trust-client): poisoned cache rejected, recovers on refresh`

### Task C10: hardcoded etchit-io pubkey placeholder

**Files:** Modify: `crates/fetchit-trust-client/src/lib.rs`.

- [ ] **Step 1: Add a `pub fn etchitio_pubkey() -> VerifyingKey` returning a placeholder** built from a deterministic `[0u8; ML_DSA_65_PUB_LEN]` array or fixture key. Block real-pubkey insertion behind a `// TODO(v1.0-launch): replace with real etchit-io pubkey` so the audit trail records the swap point.

```rust
const PLACEHOLDER_ETCHITIO_PUBKEY: [u8; ML_DSA_65_PUB_LEN] = include_bytes!("../fixtures/placeholder_pubkey.bin").try_into().unwrap();

pub fn etchitio_pubkey() -> VerifyingKey {
    VerifyingKey::from_bytes(&PLACEHOLDER_ETCHITIO_PUBKEY)
        .expect("placeholder pubkey decodes")
}
```

The fixture file is a deterministic test key generated once and checked in. Replacement at launch is a single-file change.

- [ ] **Step 2: Smoke test** — `cargo build -p fetchit-trust-client`. PASS.
- [ ] **Step 3: Commit** `feat(trust-client): placeholder etchitio_pubkey (TODO swap at v1.0)`

---

## Phase D — `MultiHomeTransport` in `fetchit-chat`

### Task D1: `NonceDedup` bounded LRU

**Files:** Create: `crates/fetchit-chat/src/transport/nonce_dedup.rs`. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn dedup_first_seen_wins_duplicate_dropped() {
    let mut d = NonceDedup::new(8, Duration::from_secs(300));
    let k = ("alice".to_string(), [1u8; 12]);
    assert!(d.observe(k.clone(), Instant::now()));   // first seen
    assert!(!d.observe(k.clone(), Instant::now()));  // duplicate
}

#[test]
fn dedup_distinct_nonces_preserved() {
    let mut d = NonceDedup::new(8, Duration::from_secs(300));
    assert!(d.observe(("a".into(), [1u8;12]), Instant::now()));
    assert!(d.observe(("a".into(), [2u8;12]), Instant::now()));
    assert!(d.observe(("b".into(), [1u8;12]), Instant::now()));
}

#[test]
fn dedup_evicts_oldest_at_capacity() {
    let mut d = NonceDedup::new(2, Duration::from_secs(300));
    let now = Instant::now();
    d.observe(("a".into(), [1u8;12]), now);
    d.observe(("a".into(), [2u8;12]), now + Duration::from_millis(1));
    d.observe(("a".into(), [3u8;12]), now + Duration::from_millis(2));
    // [1u8;12] should have evicted; reinserting returns true
    assert!(d.observe(("a".into(), [1u8;12]), now + Duration::from_millis(3)));
}
```

- [ ] **Step 2: Implement bounded LRU**

Use `lru::LruCache` (workspace dep already) keyed on `(String, [u8; 12])` valued `Instant`. `observe` inserts and returns `true` on first-seen, `false` on duplicate. TTL enforcement via best-effort sweep on insert.

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): NonceDedup bounded LRU for multi-home inbound`

### Task D2: `Slot` + `MultiHomeTransport` skeleton

**Files:** Create: `crates/fetchit-chat/src/transport/multi_home.rs`. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn new_opens_slot_zero_to_primary() {
    let mh = MultiHomeTransport::new(
        "wss://primary.test/v1/ws".into(),
        Arc::new(NoopDenylist),
        Arc::new(|_| {}),
        StubRelayBuilder::default(),  // builds RelayTransport from URL
    ).await.unwrap();
    let slots = mh.slots_for_test();
    assert_eq!(slots[0].as_ref().map(|s| s.relay_url.as_str()), Some("wss://primary.test/v1/ws"));
    assert!(slots[1].is_none());
    assert!(slots[2].is_none());
}
```

- [ ] **Step 2: Implement skeleton**

```rust
pub struct MultiHomeTransport<B: RelayBuilder> {
    primary_url: String,
    builder: B,
    slots: Arc<RwLock<[Option<Slot>; 3]>>,
    inbox_dedup: Arc<Mutex<NonceDedup>>,
    denylist: Arc<dyn DenylistQuery>,
    on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
}

struct Slot {
    relay_url: String,
    transport: Arc<RelayTransport>,
    last_traffic_at: SystemTime,
}

#[async_trait]
pub trait RelayBuilder: Send + Sync {
    async fn build(&self, url: &str) -> Result<Arc<RelayTransport>, TransportError>;
}

impl<B: RelayBuilder> MultiHomeTransport<B> {
    pub async fn new(...) -> Result<Self, TransportError> {
        let mut s: [Option<Slot>; 3] = Default::default();
        let primary = builder.build(&primary_url).await?;
        s[0] = Some(Slot { relay_url: primary_url.clone(), transport: primary, last_traffic_at: SystemTime::now() });
        // start fan-in task for slot 0
        // ...
        Ok(Self { ... })
    }
}
```

`RelayBuilder` lets tests inject a `StubRelayBuilder` that returns canned `RelayTransport` instances; prod wires a real builder that takes auth tokens etc.

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): MultiHomeTransport skeleton + slot 0 init`

### Task D3: slot allocation algorithm

**Files:** multi_home.rs. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn send_to_primary_uses_slot_zero() {
    let mh = build_test_multi_home("wss://primary.test/v1/ws").await;
    let env = sample_envelope();
    let hints = RendezvousHintsV1 { relays: vec!["wss://primary.test/v1/ws".into()] };
    mh.send(env, &hints).await.unwrap();
    assert_eq!(mh.slots_for_test()[0].as_ref().unwrap().traffic_count(), 1);
    assert!(mh.slots_for_test()[1].is_none());
}

#[tokio::test]
async fn send_to_secondary_opens_slot_one() {
    let mh = build_test_multi_home("wss://primary.test/v1/ws").await;
    let hints = RendezvousHintsV1 { relays: vec!["wss://secondary.test/v1/ws".into()] };
    mh.send(sample_envelope(), &hints).await.unwrap();
    let s = mh.slots_for_test();
    assert!(s[1].as_ref().is_some_and(|x| x.relay_url == "wss://secondary.test/v1/ws"));
}

#[tokio::test]
async fn send_evicts_lru_of_slots_1_2_when_full() {
    let mh = build_test_multi_home("wss://primary.test/v1/ws").await;
    mh.send(sample_envelope(), &hints("wss://r1.test/v1/ws")).await.unwrap();
    sleep(Duration::from_millis(10)).await;
    mh.send(sample_envelope(), &hints("wss://r2.test/v1/ws")).await.unwrap();
    sleep(Duration::from_millis(10)).await;
    mh.send(sample_envelope(), &hints("wss://r3.test/v1/ws")).await.unwrap();
    let s = mh.slots_for_test();
    let urls: Vec<_> = s.iter().filter_map(|x| x.as_ref().map(|y| y.relay_url.as_str())).collect();
    assert!(urls.contains(&"wss://primary.test/v1/ws"));   // slot 0 immune
    assert!(urls.contains(&"wss://r2.test/v1/ws"));        // most recent
    assert!(urls.contains(&"wss://r3.test/v1/ws"));        // most recent
    assert!(!urls.contains(&"wss://r1.test/v1/ws"));       // LRU evicted
}
```

- [ ] **Step 2: Implement `pick_slot_for_send` + `send`** per the spec's algorithm.
- [ ] **Step 3: 3/3 PASS.**
- [ ] **Step 4: Commit** `feat(chat): MultiHomeTransport slot allocation + LRU eviction`

### Task D4: inbound dedup + fan-in

**Files:** multi_home.rs. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn duplicate_inbound_across_slots_dropped() {
    // ...
}
```

- [ ] **Step 2: Wire each slot's RelayTransport `recv()` stream into a mpsc → `on_inbound` callback with dedup gate.**
- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): MultiHomeTransport inbound dedup fan-in`

### Task D5: denylist enforcement on outbound

**Files:** multi_home.rs. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn send_to_denylisted_relay_returns_blocked_error() {
    let denylist = Arc::new(StubDenylist::with_relay("wss://bad.test/v1/ws"));
    let mh = build_test_multi_home_with_denylist("wss://primary.test/v1/ws", denylist).await;
    let hints = RendezvousHintsV1 { relays: vec!["wss://bad.test/v1/ws".into()] };
    let err = mh.send(sample_envelope(), &hints).await.unwrap_err();
    assert!(matches!(err, TransportError::Blocked(_)));
}

#[tokio::test]
async fn send_to_denylisted_agent_returns_blocked_error() {
    let denylist = Arc::new(StubDenylist::with_agent("dead…beef…64hex"));
    let mh = build_test_multi_home_with_denylist("wss://primary.test/v1/ws", denylist).await;
    let mut env = sample_envelope();
    env.recipient_agent_id = "dead…beef…64hex".into();
    let hints = RendezvousHintsV1 { relays: vec!["wss://primary.test/v1/ws".into()] };
    let err = mh.send(env, &hints).await.unwrap_err();
    assert!(matches!(err, TransportError::Blocked(_)));
}
```

- [ ] **Step 2: Add `TransportError::Blocked(BlockedReason)` + the two checks in `send`.**
- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): MultiHomeTransport denylist enforcement on send`

### Task D6: denylist subscriber background task

**Files:** multi_home.rs. Test: inline.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn mid_session_relay_denylist_drops_active_slot() {
    let denylist = Arc::new(LiveStubDenylist::new());   // mutable
    let mh = build_test_multi_home_with_denylist("wss://primary.test/v1/ws", denylist.clone()).await;
    mh.send(sample_envelope(), &hints("wss://later-blocked.test/v1/ws")).await.unwrap();
    assert!(mh.slots_for_test()[1].is_some());

    denylist.add_relay("wss://later-blocked.test/v1/ws");
    denylist.emit_event(BlockEvent {
        kind: EntryKind::RelayUrl,
        added: vec!["wss://later-blocked.test/v1/ws".into()],
        removed: vec![],
    });
    sleep(Duration::from_millis(50)).await;
    let s = mh.slots_for_test();
    assert!(s.iter().filter_map(|x| x.as_ref()).all(|x| x.relay_url != "wss://later-blocked.test/v1/ws"));
}
```

- [ ] **Step 2: Spawn a background task in `MultiHomeTransport::new` that subscribes to `denylist.subscribe()` (added in C6) + drops matching slots on `BlockEvent { kind: RelayUrl, added }`.** Surface a `chat:relay-denylisted` callback for the desktop layer.
- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): MultiHomeTransport drops slots on mid-session denylist`

### Task D7: inbound dispatch AgentId enforcement

**Files:** Modify: `crates/fetchit-chat/src/dispatch.rs`. Test: same file.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn inbound_from_denylisted_agent_is_dropped() {
    let denylist = Arc::new(StubDenylist::with_agent("evil…64hex"));
    let mut dispatch = test_dispatch_with_denylist(denylist);
    let env = sample_inbound_envelope_from("evil…64hex");
    let result = dispatch.handle_envelope(env).await;
    assert!(matches!(result, Err(ChatError::Blocked(_))));
}
```

- [ ] **Step 2: Add early-block check at the top of `handle_envelope`**:

```rust
if denylist.is_blocked(EntryKind::AgentId, &env.from_agent_id) {
    tracing::warn!(from = %env.from_agent_id, "inbound from denylisted agent dropped");
    self.emit_warn_event(format!("Inbound message from denylisted contact dropped"));
    return Err(ChatError::Blocked(BlockedReason::AgentId));
}
```

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): dispatch drops inbound from denylisted agents`

### Task D8: `Client` boot wiring

**Files:** Modify: `crates/fetchit-chat/src/client.rs`. Test: existing client tests.

- [ ] **Step 1: Write failing test** — assert that `Client::new(...)` returns a client with `denylist: Arc<DenylistConsumer>` field populated. Test against an in-memory denylist (no HTTP) for unit speed.
- [ ] **Step 2: Wire `DenylistConsumer::new(...)` + `spawn_poll_loop` + construct `MultiHomeTransport` instead of bare `RelayTransport`.**
- [ ] **Step 3: PASS + workspace gate.**
- [ ] **Step 4: Commit** `feat(chat): Client wires DenylistConsumer + MultiHomeTransport`

### Task D9: `Client::regenerate_card_with_relays`

**Files:** Modify: `crates/fetchit-chat/src/client.rs`. Test: same file.

- [ ] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn regenerate_card_with_relays_updates_v2_hints() {
    let client = test_client().await;
    client.regenerate_card_with_relays(vec!["wss://nyc.etchit.io/v1/ws".into(), "wss://community.example/v1/ws".into()]).await.unwrap();
    let card = client.current_card().await;
    let parsed = parse_extension_from_value(&card).unwrap();
    let hints = parsed.v2_rendezvous_hints.unwrap();
    assert_eq!(hints.v, 1);
    let v1 = RendezvousHintsV1::from_value(&hints.data).unwrap();
    assert_eq!(v1.relays.len(), 2);
}
```

- [ ] **Step 2: Implement** — validates the input via `RendezvousHintsV1::from_value`, calls `extend_with_fetchit_fields` with `Some(hints)`, swaps in-memory card + republishes v3 profile manifest.
- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(chat): Client::regenerate_card_with_relays (M3)`

### Task D10: workspace gate

- [ ] **Step 1:** Run the full gate: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
- [ ] **Step 2:** Fix anything that surfaces. Push to josh-clsn as a save-point.
- [ ] **Step 3: Commit** any drift in a single `chore(chat): fmt/clippy sweep after M3 Phase D` commit.

---

## Phase E — card population at runtime

### Task E1: thread `relays` through `Client::new`

**Files:** Modify: `crates/fetchit-chat/src/client.rs` + every call site (CLI + desktop + Android).

- [ ] **Step 1: Write failing test** — `Client::new` accepts a `Vec<String>` of initial advertised relays; default behavior when empty is `[primary_url]`.
- [ ] **Step 2: Implement signature change.**
- [ ] **Step 3: PASS + workspace gate.**
- [ ] **Step 4: Commit** `feat(chat): Client::new threads advertised relays into card generation`

### Task E2: desktop Tauri command

**Files:** Modify: `apps/fetchit-desktop/src-tauri/src/main.rs` + `lib.rs` (or commands.rs equivalent).

- [ ] **Step 1: Write failing test (Rust side)** — `chat_regenerate_card_with_relays(["wss://..."])` validates input via `RendezvousHintsV1::from_value` and returns `Result<(), String>` (Tauri command return shape).
- [ ] **Step 2: Implement the command**:

```rust
#[tauri::command]
async fn chat_regenerate_card_with_relays(
    relays: Vec<String>,
    client: tauri::State<'_, Arc<fetchit_chat::Client>>,
) -> Result<(), String> {
    client.regenerate_card_with_relays(relays).await.map_err(|e| e.to_string())
}
```

Wire `.invoke_handler(tauri::generate_handler![..., chat_regenerate_card_with_relays])`.

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(desktop): chat_regenerate_card_with_relays Tauri command`

### Task E3: Settings → Network → Advanced UI

**Files:** Modify: `apps/fetchit-desktop/src/settings/` (new file `network-advanced.ts` + integrate into existing settings panel).

- [ ] **Step 1: Add HTML/JS scaffold** — a panel under Settings → Network with a header "Advertise these relays in my card", an editable list (add/remove buttons), and a "Save" button.
- [ ] **Step 2: Wire the Save click to `invoke('chat_regenerate_card_with_relays', { relays })`.**
- [ ] **Step 3: Manual test** — start dev server, navigate to Settings → Network → Advanced, add a wss URL, save, verify card-regeneration log message. (No automated UI test; that's the existing project pattern.)
- [ ] **Step 4: Commit** `feat(desktop): Settings -> Network -> Advanced relay-advertise UI (M3)`

### Task E4: card round-trip integration test

**Files:** Create: `crates/fetchit-chat/tests/m3_card_rendezvous_hints.rs`.

- [ ] **Step 1: Write the integration test** — Alice mints a card with two relays, Bob parses it, asserts `RendezvousHintsV1::from_value` returns the same list.
- [ ] **Step 2:** PASS.
- [ ] **Step 3: Commit** `test(chat): m3_card_rendezvous_hints integration test`

---

## Phase F — fetchit-core reader-side `Rendition::Blocked`

### Task F1: add `Rendition::Blocked` variant

**Files:** Modify: `crates/fetchit-core/src/handler.rs`. Test: same file.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn rendition_blocked_carries_reason() {
    let r = Rendition::Blocked { reason: "denylisted".into() };
    match r {
        Rendition::Blocked { reason } => assert_eq!(reason, "denylisted"),
        _ => panic!(),
    }
}
```

Run: FAIL — variant missing.

- [ ] **Step 2: Add the variant**

```rust
#[non_exhaustive]
pub enum Rendition {
    // existing variants ...
    Blocked { reason: String },
}
```

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(core): Rendition::Blocked variant (M3)`

### Task F2: `RenderingContext` + `render_with_context`

**Files:** Modify: `crates/fetchit-core/src/handler.rs` + `registry.rs`. Test: same file.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn render_with_context_short_circuits_blocked_xorname() {
    struct Block(&'static str);
    impl fetchit_trust::DenylistQuery for Block {
        fn is_blocked(&self, kind: fetchit_trust::EntryKind, value: &str) -> bool {
            kind == fetchit_trust::EntryKind::XorName && value == self.0
        }
    }
    let reg = default_registry();
    let ctx = RenderingContext {
        denylist: Some(Arc::new(Block("abcd…64hex"))),
        addr_hex: Some("abcd…64hex".into()),
    };
    let r = reg.render_with_context(b"any bytes", &ctx);
    assert!(matches!(r, Rendition::Blocked { .. }));
}
```

- [ ] **Step 2: Implement**

```rust
pub struct RenderingContext {
    pub denylist: Option<Arc<dyn fetchit_trust::DenylistQuery>>,
    pub addr_hex: Option<String>,
}

impl HandlerRegistry {
    pub fn render_with_context(&self, bytes: &[u8], ctx: &RenderingContext) -> Rendition {
        if let (Some(dl), Some(addr)) = (&ctx.denylist, &ctx.addr_hex) {
            if dl.is_blocked(EntryKind::XorName, addr) {
                return Rendition::Blocked { reason: format!("address {addr} is on the safety denylist") };
            }
        }
        self.render(bytes)
    }
}
```

- [ ] **Step 3: PASS.**
- [ ] **Step 4: Commit** `feat(core): RenderingContext + render_with_context with denylist short-circuit`

### Task F3: integration assertion

**Files:** Modify: `crates/fetchit-core/tests/registry_integration.rs`.

- [ ] **Step 1: Add a test** asserting `default_registry().render_with_context(SAMPLE_TEXT, &ctx_with_blocking_denylist)` returns `Rendition::Blocked` and that with no denylist injected it returns `Rendition::Text` as today.
- [ ] **Step 2: PASS.**
- [ ] **Step 3: Commit** `test(core): registry blocked-rendition integration`

---

## Phase G — desktop UI surfaces

### Task G1: conversation banner for `chat:relay-denylisted`

**Files:** Modify: `apps/fetchit-desktop/src/chat/conversation-banner.ts`. Tauri side: Modify `apps/fetchit-desktop/src-tauri/src/main.rs` to emit the event.

- [ ] **Step 1: Add event emission** in the Rust shell when `MultiHomeTransport` calls back with a denylisted slot drop:

```rust
client.set_relay_denylisted_callback({
    let app = app_handle.clone();
    move |url| { let _ = app.emit_all("chat:relay-denylisted", url); }
});
```

- [ ] **Step 2: Add TS listener** for `chat:relay-denylisted` that renders a banner above the active conversation: "The relay you were just connected to was added to the safety denylist. Reconnecting…"
- [ ] **Step 3: Manual smoke test.**
- [ ] **Step 4: Commit** `feat(desktop): chat:relay-denylisted banner (M3)`

### Task G2: contacts list denylist indicator

**Files:** Modify: `apps/fetchit-desktop/src/chat/contacts-list.ts`.

- [ ] **Step 1: Subscribe to `chat:denylist-updated` event** (emit from Rust shell when `DenylistConsumer.subscribe()` emits `BlockEvent { kind: AgentId, .. }`).
- [ ] **Step 2: Render a "blocked" indicator** next to any contact whose `agent_id` is in the denylist; disable the composer for that contact.
- [ ] **Step 3: Manual smoke test.**
- [ ] **Step 4: Commit** `feat(desktop): contacts list denylist indicator (M3)`

### Task G3: renderer dispatch handles `Rendition::Blocked`

**Files:** Modify: `apps/fetchit-desktop/src/renderers/dispatch.ts` + add a new placeholder renderer.

- [ ] **Step 1: Add a `BlockedRenderer`** that renders a fixed placeholder card ("This content is on the safety denylist. Reason: <reason>"). Match etch>it's existing safety-card design language.
- [ ] **Step 2: Wire into the dispatch switch.**
- [ ] **Step 3: Add a vitest** in `apps/fetchit-desktop/test/` that asserts the BlockedRenderer renders the placeholder DOM and never the original bytes.
- [ ] **Step 4: Commit** `feat(desktop): Rendition::Blocked placeholder renderer (M3)`

### Task G4: Tauri side — denylist event emitters

**Files:** Modify: `apps/fetchit-desktop/src-tauri/src/main.rs`. Spawn the `denylist.subscribe()` channel and convert to Tauri events.

- [ ] **Step 1: Spawn the bridge:**

```rust
let mut rx = client.denylist_subscribe();
let app_for_events = app_handle.clone();
tokio::spawn(async move {
    while let Ok(evt) = rx.recv().await {
        let _ = app_for_events.emit_all("chat:denylist-updated", evt);
    }
});
```

- [ ] **Step 2:** PASS (the cycle becomes "no panic on boot; UI listeners receive events").
- [ ] **Step 3: Commit** `feat(desktop): denylist Tauri event bridge (M3)`

---

## Phase H — Android UI parity

### Task H1: Settings → Advanced screen (Kotlin)

**Files:** Modify: `apps/fetchit-android/.../SettingsAdvancedScreen.kt`. Wire to FFI's `chat_regenerate_card_with_relays`.

- [ ] **Step 1: Add the screen + composable.**
- [ ] **Step 2: Manual smoke test on emulator (or device).**
- [ ] **Step 3: Commit** `feat(android): Settings -> Network -> Advanced relay-advertise screen (M3)`

### Task H2: conversation banner for relay-denylisted

**Files:** Modify: `apps/fetchit-android/.../ConversationScreen.kt`.

- [ ] **Step 1: Subscribe to the equivalent FFI callback.**
- [ ] **Step 2: Render banner.**
- [ ] **Step 3: Commit** `feat(android): relay-denylisted banner (M3)`

### Task H3: contacts list denylist indicator

**Files:** Modify: `apps/fetchit-android/.../ContactsScreen.kt`.

- [ ] **Step 1: Subscribe + render indicator.**
- [ ] **Step 2: Commit** `feat(android): contacts denylist indicator (M3)`

### Task H4: `RenditionRenderer` Blocked branch

**Files:** Modify: `apps/fetchit-android/.../RenditionRenderer.kt`.

- [ ] **Step 1: Add Blocked case** with a placeholder Material card.
- [ ] **Step 2: Commit** `feat(android): RenditionRenderer Blocked variant (M3)`

---

## Phase I — integration tests

### Task I1: `m3_multi_home_basic.rs`

**Files:** Create: `crates/fetchit-chat/tests/m3_multi_home_basic.rs`.

- [ ] **Step 1: Write the test** — 3 stubbed relay endpoints in-process (per `m2_live.rs` pattern), 3 agents, assert slots fill correctly under traffic. Send-to-A flows via slot 0, send-to-B opens slot 1, send-to-C opens slot 2, send-to-D evicts LRU of slot 1/2.
- [ ] **Step 2: PASS.**
- [ ] **Step 3: Commit** `test(chat): m3_multi_home_basic integration`

### Task I2: `m3_multi_home_denylist.rs`

**Files:** Create: `crates/fetchit-chat/tests/m3_multi_home_denylist.rs`.

- [ ] **Step 1: Write the test** — in-memory `DenylistConsumer` populated by hand (no HTTP), assert hard-block on RelayUrl outbound, AgentId outbound, AgentId inbound. Mid-test add to denylist via `consumer.observe_test_only(...)` (test-only API), assert active slot drops within one event-loop tick.
- [ ] **Step 2: PASS.**
- [ ] **Step 3: Commit** `test(chat): m3_multi_home_denylist integration`

### Task I3: `m3_card_rendezvous_hints.rs`

Done as part of Task E4. Mark complete here if not already.

---

## Phase J — live test

### Task J1: `m3_live.rs` (`#[ignore]`'d)

**Files:** Create: `crates/fetchit-chat/tests/m3_live.rs`.

- [ ] **Step 1: Write the test** mirroring `m2_live.rs`:
  - 3 agents: Alice@NY (primary), Bob@FRA, Charlie@NY.
  - Use real `MultiHomeTransport` against real NY + FRA relays.
  - Assert slot 0 (NY) carries Alice↔Charlie, slot 1 (FRA) opens dynamically for Alice→Bob.
  - Mid-test: shorten `poll_interval` to 60s, hit a test-denylist endpoint to add an `agent_id`, assert client enforces within 90s.

Gate as `#[ignore]` with a `FETCHIT_LIVE_ADDR`-style env var.

- [ ] **Step 2: Document the run command** in the test docstring: `FETCHIT_M3_LIVE=1 cargo test -p fetchit-chat --test m3_live -- --ignored --nocapture`.
- [ ] **Step 3: Commit** `test(chat): m3_live ignored integration (run manually pre-launch)`

---

## Phase K — workspace gate + docs + close

### Task K1: SECURITY.md amendment

**Files:** Modify: `crates/fetchit-chat/SECURITY.md`.

- [ ] **Step 1: Add a "M3 federation safety" section** covering:
  - 3-WS multi-home default (privacy posture: each operator sees partial graph).
  - Hardcoded etchit-io denylist pubkey; v1 single-signer; multisig migration committed v1.1.
  - Hard-block semantics across RelayUrl / AgentId / XorName.
  - Fail-closed against poisoning, fail-open against unavailability.
  - Invitation-only community-relay discovery — no central registry trust.
- [ ] **Step 2: Cross-link to the design doc.**
- [ ] **Step 3: Commit** `docs(chat): SECURITY.md M3 federation amendment`

### Task K2: workspace gate

- [ ] **Step 1:** `cargo fmt --all` (clean).
- [ ] **Step 2:** `cargo clippy --workspace --all-targets -- -D warnings` (clean).
- [ ] **Step 3:** `cargo test --workspace` (green).
- [ ] **Step 4:** `(cd src-tauri && cargo test)` and `(cd crates/fetchit-ffi && cargo build)` per the workspace-excluded gotcha in CLAUDE.md.
- [ ] **Step 5:** Force-push to `josh-clsn` as save-point.

### Task K3: M3 close commit

- [ ] **Step 1:** Single commit `chore(M3): close M3 federation constellation milestone` summarizing the phases + linking the spec + listing the v1.1 follow-ups for the audit trail.
- [ ] **Step 2:** Push to josh-clsn. NEVER to etchit-io without per-push approval.

---

## Notes for the executor

- DCO sign-off on every commit via `git -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s`.
- No em-dashes in commit messages or code (public-artifact rule). Hyphens, semicolons, parens, restructure as needed.
- No `Co-Authored-By: Claude` trailer.
- `fetchit-ffi` + `src-tauri` are workspace-excluded; build + test from inside their dirs.
- The EntryKind enum + value_hex rename in Phase A is co-authored with Bob's M4 Stage 4 work. Whichever box touches `fetchit-trust::types` first lands the combined commit; the other adds consumer-only code. Bob has already endorsed option (A) (rename) via the chat-pipe.
- Force-push to `josh-clsn` allowed for save-points. NEVER push to `etchit-io` without explicit per-push approval.
- `cargo test --workspace` gates every phase boundary. If a test would be flaky on the default tokio runtime, prefer `#[tokio::test(flavor = "multi_thread", worker_threads = N)]` (lesson from #204).
