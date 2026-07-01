# M5.1 Component D — Discovery bridge endpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline) to implement this plan task-by-task. The tasks share types within one crate module, so inline TDD is the fit (not subagent fan-out). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the self-serve actor registry + fediverse serving half (WebFinger server, actor-doc hosting, `POST`/`PUT /v1/actors`) in `fetchit-relay-server` under `--features fediverse-inbox`, so a minted handle resolves to a verifiable actor card.

**Architecture:** A new `registry/` module beside the existing `inbox/`, same axum + injected-trait shape. Pure verification core (`verify.rs`) calls `fetchit_fedi::attestation::verify_binding_v2` over the canonical actor URL; an `ActorRegistryStore` trait (in-memory impl now, durable impl flagged) enforces FCFS + same-agent continuity + hint-epoch monotonicity; `router.rs` mounts the four routes and merges alongside `inbox_router` at the operator bring-up. Every server response code matches `crates/fetchit-fedi/tests/fixtures/registry-v1/README.md`.

**Tech Stack:** Rust, axum, `fetchit-fedi` (attestation/actor/registry/lookup), `dashmap`, `rsa` (SO-4 SPKI parse), `saorsa_pqc` (ML-DSA via fetchit-fedi), all under the `fediverse-inbox` feature gate.

---

## Contract anchors (read once before starting)

- **Fixtures (frozen wire contract):** `crates/fetchit-fedi/tests/fixtures/registry-v1/` — `register-request.json` (placeholder bytes), `register-request-valid.json` (real ML-DSA-65 + RSA-2048 green vector), `register-response.json` (`{"actor_url":"https://etchit.io/actors/josh"}`), `README.md` (verification obligations + response tables).
- **Canonical `actor_url` (SO-1):** `url::Url::parse("https://{domain}/actors/{handle}")`; `.as_str()` is `https://etchit.io/actors/josh` (NO trailing slash). This exact `&url::Url` is the one byte-sensitive input to `verify_binding_v2`.
- **Handle policy (SO-3):** `[a-z0-9_-]{1,64}`. Reject any uppercase byte with **422** — never silently lowercase (the signature was over the exact handle bytes).
- **SPKI parse-validate (SO-4):** keep it. `verify_binding_v2` covers the SPKI *bytes* in the signed input but does not parse them as a key; parse-validate so the served `publicKeyPem` is a real RSA key. The valid fixture carries a real RSA-2048 SPKI so it stays green.
- **Verify surface:** `fetchit_fedi::attestation::verify_binding_v2(handle: &str, actor_url: &url::Url, spki_der: &[u8], attestation: &ActorAttestationV2) -> Result<String, AttestationVerifyError>`; `Ok` is the derived 64-hex `agent_id`. Derive-then-verify: agent id comes from the attested ML-DSA pubkey, never a claim. Rejects `version != 2`.
- **Wire types (pub):** `fetchit_fedi::registry::{RegisterActorRequest, RegisterActorResponse}`, `fetchit_fedi::attestation::ActorAttestationV2`. NOTE: `RegisterActorResponse` derives `Deserialize` only — the server emits the success body as a `serde_json::json!({"actor_url": ...})` literal, matching `register-response.json` byte-for-byte.
- **Actor-doc building blocks (pub):** `fetchit_fedi::actor::{PQ_ATTESTATION_V2_PROPERTY_URI, spki_der_to_pem}`; round-trip verifier `fetchit_fedi::lookup::RemoteActor::{from_json_ld, verify_attestation_v2}`.
- **Inbox pattern to mirror:** `crates/fetchit-relay-server/src/inbox/router.rs` — `fn inbox_router(state) -> Router`, thin `handle_*(State, HeaderMap, Bytes) -> Response` delegating to a `?`-ergonomic inner `Result<(), InboxError>` that unit tests drive without axum. `InboxRateLimit` (token bucket) is reusable for registry rate limiting.

## Response-code map (from the README tables)

| Route | Code | Cause |
| --- | --- | --- |
| POST /v1/actors | 201 | registered; body `{"actor_url":...}` |
| POST /v1/actors | 409 | handle already registered |
| POST /v1/actors | 422 | handle invalid / attestation invalid / SPKI invalid / malformed body; reason text |
| POST /v1/actors | 429 | per-source rate limit |
| PUT /v1/actors/&lt;h&gt; | 200 | updated; body `{"actor_url":...}` |
| PUT /v1/actors/&lt;h&gt; | 404 | unknown handle |
| PUT /v1/actors/&lt;h&gt; | 409 | agent-id mismatch or stale/equal epoch |
| PUT /v1/actors/&lt;h&gt; | 422 | invalid attestation / path≠body handle / handle invalid |
| PUT /v1/actors/&lt;h&gt; | 429 | per-source rate limit |
| GET /.well-known/webfinger | 200 | JRD for `acct:<h>@<domain>` |
| GET /.well-known/webfinger | 400 | malformed `resource` |
| GET /.well-known/webfinger | 404 | unknown handle or foreign domain |
| GET /actors/&lt;h&gt; | 200 | actor JSON-LD (`application/activity+json`) |
| GET /actors/&lt;h&gt; | 404 | unknown handle |

## File structure

- Create: `crates/fetchit-relay-server/src/registry/mod.rs` — module doc, `ActorRecord`, `ActorRegistryStore` trait, `RegistryStoreError`, `RegistryRejection`, re-exports.
- Create: `crates/fetchit-relay-server/src/registry/verify.rs` — `RegistryConfig`, `validate_registry_handle`, `canonical_actor_url`, `verify_registration`.
- Create: `crates/fetchit-relay-server/src/registry/store.rs` — `InMemoryActorStore` (DashMap) impl + FCFS/continuity/epoch logic.
- Create: `crates/fetchit-relay-server/src/registry/webfinger.rs` — `parse_acct_resource`, `webfinger_jrd`.
- Create: `crates/fetchit-relay-server/src/registry/actor_doc.rs` — `actor_document` JSON-LD builder.
- Create: `crates/fetchit-relay-server/src/registry/router.rs` — `RegistryState`, `registry_router`, the four handlers + testable inner fns.
- Modify: `crates/fetchit-relay-server/src/lib.rs` — `#[cfg(feature = "fediverse-inbox")] pub mod registry;`.
- Modify: `crates/fetchit-relay-server/src/server.rs` (or `main.rs` operator bring-up) — merge `registry_router(state)` onto the fediverse router; construct store + `RegistryConfig`.
- Modify: `crates/fetchit-relay-server/Cargo.toml` — add `dashmap` to the `fediverse-inbox` feature dep set if the gate does not already pull it transitively (it is a base dep today; confirm at Task 1).
- Modify: `REFERENCE.md` — registry sub-section under fetchit-relay-server (Task 14).

---

### Task 1: Module scaffold — `ActorRecord` + `ActorRegistryStore` trait + errors

**Files:**
- Create: `crates/fetchit-relay-server/src/registry/mod.rs`
- Modify: `crates/fetchit-relay-server/src/lib.rs`

- [ ] **Step 1: Write the failing test** (in `registry/mod.rs`)

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_record() -> ActorRecord {
        ActorRecord {
            handle: "josh".into(),
            actor_url: "https://etchit.io/actors/josh".into(),
            agent_id_hex: "a".repeat(64),
            rsa_spki_der: vec![1, 2, 3],
            attestation: sample_attestation(),
            registered_at_ms: 1,
        }
    }

    fn sample_attestation() -> fetchit_fedi::attestation::ActorAttestationV2 {
        fetchit_fedi::attestation::ActorAttestationV2 {
            version: 2,
            profile_addr: "a".repeat(64),
            relay_hint: "https://relay.example:8088/".into(),
            hint_epoch_ms: 1_750_000_000_000,
            ml_dsa_pubkey: vec![0x42; 4],
            signature: vec![0x41; 4],
        }
    }

    #[test]
    fn record_carries_continuity_key_and_epoch() {
        let r = sample_record();
        assert_eq!(r.agent_id_hex.len(), 64);
        assert_eq!(r.attestation.hint_epoch_ms, 1_750_000_000_000);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::mod::tests::record_carries -- --nocapture`
Expected: FAIL to compile — `registry` module / `ActorRecord` not defined.

- [ ] **Step 3: Write minimal implementation** (`registry/mod.rs` top)

```rust
//! Self-serve actor registry + fediverse serving half (M5.1, Component D).
//!
//! Gated behind `fediverse-inbox` like [`crate::inbox`]: the default
//! relay-server (LIT Chat pass-through) ships without it. Operators in
//! the bridge role build with `--features fediverse-inbox`. All response
//! codes match `fetchit-fedi/tests/fixtures/registry-v1/README.md`.

pub mod actor_doc;
pub mod router;
pub mod store;
pub mod verify;
pub mod webfinger;

use fetchit_fedi::attestation::ActorAttestationV2;
use thiserror::Error;

pub use router::{registry_router, RegistryState};
pub use store::InMemoryActorStore;
pub use verify::{verify_registration, RegistryConfig};

/// A stored, verified registration. `agent_id_hex` is the continuity
/// key (a handle never silently changes agent); the whole attestation
/// is retained so the WebFinger record and actor document can serve it
/// verbatim for offline verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRecord {
    /// Lowercase `[a-z0-9_-]{1,64}` handle.
    pub handle: String,
    /// Canonical actor URL (`https://<domain>/actors/<handle>`).
    pub actor_url: String,
    /// Derived chat agent id (64-hex) from the attested ML-DSA pubkey.
    pub agent_id_hex: String,
    /// RSA `SubjectPublicKeyInfo` DER, served as `publicKeyPem`.
    pub rsa_spki_der: Vec<u8>,
    /// The signed v2 attestation, served under
    /// `PQ_ATTESTATION_V2_PROPERTY_URI` for offline verification.
    pub attestation: ActorAttestationV2,
    /// Server clock at first registration (ms since epoch).
    pub registered_at_ms: u64,
}

/// Store-layer outcome distinct from verification rejection: these map
/// to 409/404, verification failures map to 422.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryStoreError {
    /// POST onto an existing handle (FCFS). -> 409.
    #[error("handle already registered")]
    HandleTaken,
    /// PUT on a handle that was never registered. -> 404.
    #[error("unknown handle")]
    UnknownHandle,
    /// PUT whose derived agent id differs from the stored one. -> 409.
    #[error("agent id mismatch: a handle never silently changes agent")]
    AgentMismatch,
    /// PUT whose `hint_epoch_ms` is not strictly greater than stored. -> 409.
    #[error("stale hint epoch")]
    StaleEpoch,
}

/// Verification rejection — every variant maps to HTTP 422 with the
/// `Display` text served back to the user.
#[derive(Debug, Error)]
pub enum RegistryRejection {
    /// Handle failed `[a-z0-9_-]{1,64}` (incl. uppercase) — SO-3.
    #[error("invalid handle: {0}")]
    Handle(String),
    /// `RegisterActorRequest` body did not parse.
    #[error("malformed request body: {0}")]
    Body(String),
    /// SO-4: `rsa_spki_der` is not a parseable RSA public key.
    #[error("invalid RSA SubjectPublicKeyInfo: {0}")]
    Spki(String),
    /// `verify_binding_v2` rejected the attestation.
    #[error("attestation verification failed: {0}")]
    Attestation(String),
    /// PUT path handle did not equal body handle.
    #[error("path handle {path:?} does not match body handle {body:?}")]
    HandleMismatch { path: String, body: String },
}

/// In-memory + future durable store of verified registrations. Sync
/// methods: each is a fast local op with no `.await` inside, so an impl
/// holding a `DashMap` shard guard never crosses an await point.
pub trait ActorRegistryStore: Send + Sync {
    /// First-come-first-served insert. `Err(HandleTaken)` if present.
    ///
    /// # Errors
    /// [`RegistryStoreError::HandleTaken`].
    fn register(&self, record: ActorRecord) -> Result<(), RegistryStoreError>;

    /// Update an existing handle: same-agent + strictly-increasing epoch.
    ///
    /// # Errors
    /// [`RegistryStoreError::UnknownHandle`] / `AgentMismatch` / `StaleEpoch`.
    fn update(&self, record: ActorRecord) -> Result<(), RegistryStoreError>;

    /// Fetch by handle for the serving endpoints.
    fn get(&self, handle: &str) -> Option<ActorRecord>;
}
```

Add to `crates/fetchit-relay-server/src/lib.rs` next to the inbox declaration:

```rust
#[cfg(feature = "fediverse-inbox")]
pub mod registry;
```

Create the four sibling files as empty stubs so `mod.rs` compiles:
`verify.rs`, `store.rs`, `webfinger.rs`, `actor_doc.rs`, `router.rs` each begin with `//! <one-line doc>` and the minimal `pub` item referenced by `mod.rs`'s `pub use` (fill in subsequent tasks; for Task 1 stub `RegistryConfig`, `verify_registration`, `InMemoryActorStore`, `registry_router`, `RegistryState` with `todo!()`-free minimal shells that compile — e.g. an empty `pub struct RegistryConfig { pub domain: String }`). Do NOT use `todo!()` (workspace lint forbids it); stub with the real types from later tasks, bodies returning a trivial value where a body is needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::mod::tests::record_carries`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry crates/fetchit-relay-server/src/lib.rs
git commit -s -m "feat(relay): registry module scaffold for M5.1 bridge endpoints"
```

---

### Task 2: `InMemoryActorStore::register` — FCFS

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/store.rs`

- [ ] **Step 1: Write the failing tests**

```rust
//! In-memory registry store: atomic FCFS + same-agent continuity +
//! strict hint-epoch monotonicity via a `DashMap` keyed by handle.

use crate::registry::{ActorRecord, ActorRegistryStore, RegistryStoreError};
use dashmap::DashMap;

/// `DashMap`-backed store. Per-key atomicity comes from the `entry`
/// API: the FCFS check and the insert happen under the same shard
/// guard, so two concurrent registrations of the same handle cannot
/// both win.
#[derive(Default)]
pub struct InMemoryActorStore {
    by_handle: DashMap<String, ActorRecord>,
}

impl InMemoryActorStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::tests_support::record_with;

    #[test]
    fn first_registration_wins_and_second_is_taken() {
        let store = InMemoryActorStore::new();
        store.register(record_with("josh", "a".repeat(64), 10)).unwrap();
        let dup = store.register(record_with("josh", "b".repeat(64), 99));
        assert_eq!(dup, Err(RegistryStoreError::HandleTaken));
        // The original record is untouched.
        assert_eq!(store.get("josh").unwrap().agent_id_hex, "a".repeat(64));
    }
}
```

Add a tiny shared `tests_support` helper in `mod.rs` (cfg(test)) so store/verify/router tests build records without repetition:

```rust
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    pub(crate) fn record_with(handle: &str, agent_id_hex: String, epoch: u64) -> ActorRecord {
        ActorRecord {
            handle: handle.into(),
            actor_url: format!("https://etchit.io/actors/{handle}"),
            agent_id_hex,
            rsa_spki_der: vec![1, 2, 3],
            attestation: ActorAttestationV2 {
                version: 2,
                profile_addr: "a".repeat(64),
                relay_hint: "https://relay.example:8088/".into(),
                hint_epoch_ms: epoch,
                ml_dsa_pubkey: vec![0x42; 4],
                signature: vec![0x41; 4],
            },
            registered_at_ms: 1,
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::store::tests::first_registration`
Expected: FAIL — `register` unimplemented.

- [ ] **Step 3: Write minimal implementation**

```rust
impl ActorRegistryStore for InMemoryActorStore {
    fn register(&self, record: ActorRecord) -> Result<(), RegistryStoreError> {
        use dashmap::mapref::entry::Entry;
        match self.by_handle.entry(record.handle.clone()) {
            Entry::Occupied(_) => Err(RegistryStoreError::HandleTaken),
            Entry::Vacant(v) => {
                v.insert(record);
                Ok(())
            }
        }
    }

    fn update(&self, _record: ActorRecord) -> Result<(), RegistryStoreError> {
        // Implemented in Task 3.
        Err(RegistryStoreError::UnknownHandle)
    }

    fn get(&self, handle: &str) -> Option<ActorRecord> {
        self.by_handle.get(handle).map(|r| r.clone())
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::store::tests::first_registration`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry
git commit -s -m "feat(relay): in-memory registry store with FCFS register"
```

---

### Task 3: `InMemoryActorStore::update` — same-agent continuity + epoch monotonicity

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/store.rs`

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn update_requires_existing_handle() {
        let store = InMemoryActorStore::new();
        let err = store.update(record_with("ghost", "a".repeat(64), 5));
        assert_eq!(err, Err(RegistryStoreError::UnknownHandle));
    }

    #[test]
    fn update_same_agent_newer_epoch_succeeds() {
        let store = InMemoryActorStore::new();
        let agent = "a".repeat(64);
        store.register(record_with("josh", agent.clone(), 10)).unwrap();
        store.update(record_with("josh", agent.clone(), 11)).unwrap();
        assert_eq!(store.get("josh").unwrap().attestation.hint_epoch_ms, 11);
    }

    #[test]
    fn update_rejects_different_agent() {
        let store = InMemoryActorStore::new();
        store.register(record_with("josh", "a".repeat(64), 10)).unwrap();
        let err = store.update(record_with("josh", "b".repeat(64), 11));
        assert_eq!(err, Err(RegistryStoreError::AgentMismatch));
    }

    #[test]
    fn update_rejects_stale_or_equal_epoch() {
        let store = InMemoryActorStore::new();
        let agent = "a".repeat(64);
        store.register(record_with("josh", agent.clone(), 10)).unwrap();
        assert_eq!(store.update(record_with("josh", agent.clone(), 10)),
                   Err(RegistryStoreError::StaleEpoch));
        assert_eq!(store.update(record_with("josh", agent.clone(), 9)),
                   Err(RegistryStoreError::StaleEpoch));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::store::tests::update_`
Expected: FAIL (current `update` always returns `UnknownHandle`).

- [ ] **Step 3: Implement `update`**

```rust
    fn update(&self, record: ActorRecord) -> Result<(), RegistryStoreError> {
        use dashmap::mapref::entry::Entry;
        match self.by_handle.entry(record.handle.clone()) {
            Entry::Vacant(_) => Err(RegistryStoreError::UnknownHandle),
            Entry::Occupied(mut o) => {
                let current = o.get();
                if current.agent_id_hex != record.agent_id_hex {
                    return Err(RegistryStoreError::AgentMismatch);
                }
                if record.attestation.hint_epoch_ms <= current.attestation.hint_epoch_ms {
                    return Err(RegistryStoreError::StaleEpoch);
                }
                o.insert(record);
                Ok(())
            }
        }
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::store`
Expected: PASS (all store tests).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/store.rs
git commit -s -m "feat(relay): registry update with same-agent + epoch-monotonic guards"
```

---

### Task 4: `validate_registry_handle` — SO-3 policy, server side

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/verify.rs`

- [ ] **Step 1: Write the failing tests**

```rust
//! Pure registry verification: handle policy, canonical actor URL,
//! SO-4 SPKI parse, and the `verify_binding_v2` call. No axum, no IO.

use crate::registry::{ActorRecord, RegistryRejection};
use fetchit_fedi::registry::RegisterActorRequest;

/// Server config for the bridge role.
#[derive(Clone, Debug)]
pub struct RegistryConfig {
    /// The domain this bridge is authoritative for, e.g. `etchit.io`.
    pub domain: String,
}

/// Validate a handle against the SO-3 policy: `[a-z0-9_-]`, 1..=64,
/// lowercase-only. Mirrors `fetchit-chat`'s private `validate_actor_handle`
/// (restated here so the relay-server does not depend on fetchit-chat).
/// Uppercase is rejected, never silently lowercased — the signature was
/// over the exact handle bytes.
///
/// # Errors
/// [`RegistryRejection::Handle`] on any violation (maps to HTTP 422).
pub fn validate_registry_handle(handle: &str) -> Result<(), RegistryRejection> { unimplemented!() }

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accepts_lowercase_digits_underscore_dash() {
        for h in ["josh", "alice_42", "ab-c-d", "x", &"a".repeat(64)] {
            assert!(validate_registry_handle(h).is_ok(), "{h}");
        }
    }

    #[test]
    fn rejects_uppercase_empty_long_and_path_chars() {
        for bad in ["JOSH", "Josh", "alice_42_UPPER", "", &"a".repeat(65),
                    "a.b", "a/b", "a b", "a@b"] {
            assert!(validate_registry_handle(bad).is_err(), "{bad}");
        }
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::verify::tests::accepts`
Expected: FAIL — `unimplemented!()` panics.

- [ ] **Step 3: Implement**

```rust
pub fn validate_registry_handle(handle: &str) -> Result<(), RegistryRejection> {
    if handle.is_empty() {
        return Err(RegistryRejection::Handle("handle must be non-empty".into()));
    }
    if handle.len() > 64 {
        return Err(RegistryRejection::Handle("handle exceeds 64 chars".into()));
    }
    for b in handle.bytes() {
        if !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-') {
            return Err(RegistryRejection::Handle(format!(
                "char {:?} not allowed; handles are lowercase [a-z0-9_-]",
                b as char
            )));
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::verify::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/verify.rs
git commit -s -m "feat(relay): server-side lowercase handle validation (SO-3)"
```

---

### Task 5: `canonical_actor_url` — SO-1 byte-exact

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/verify.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn canonical_url_is_byte_exact_no_trailing_slash() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let url = canonical_actor_url(&cfg, "josh").unwrap();
        assert_eq!(url.as_str(), "https://etchit.io/actors/josh");
    }

    #[test]
    fn canonical_url_rejects_invalid_handle() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        assert!(canonical_actor_url(&cfg, "Josh").is_err());
        assert!(canonical_actor_url(&cfg, "a/b").is_err());
    }
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::verify::tests::canonical`
Expected: FAIL — `canonical_actor_url` not defined.

- [ ] **Step 3: Implement**

```rust
/// Build the canonical `https://<domain>/actors/<handle>` URL (SO-1).
/// Validates the handle first so the path is always well-formed and the
/// `as_str()` form byte-matches the string the client signed over.
///
/// # Errors
/// [`RegistryRejection::Handle`] for a bad handle; [`RegistryRejection::Body`]
/// if URL assembly fails (domain misconfig).
pub fn canonical_actor_url(
    cfg: &RegistryConfig,
    handle: &str,
) -> Result<url::Url, RegistryRejection> {
    validate_registry_handle(handle)?;
    url::Url::parse(&format!("https://{}/actors/{}", cfg.domain, handle))
        .map_err(|e| RegistryRejection::Body(format!("actor url assembly: {e}")))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::verify::tests::canonical`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/verify.rs
git commit -s -m "feat(relay): canonical actor_url construction (SO-1)"
```

---

### Task 6: `verify_registration` — the verification core (SO-4 SPKI + verify_binding_v2)

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/verify.rs`

- [ ] **Step 1: Write the failing tests** (uses the committed green vector — same file as fetchit-fedi's rot-guard)

```rust
    fn valid_request() -> RegisterActorRequest {
        serde_json::from_str(include_str!(
            "../../../fetchit-fedi/tests/fixtures/registry-v1/register-request-valid.json"
        ))
        .expect("valid fixture parses")
    }

    #[test]
    fn committed_valid_fixture_registers_and_derives_agent_id() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let record = verify_registration(&cfg, &valid_request(), 1234).expect("must verify");
        assert_eq!(record.handle, "josh");
        assert_eq!(record.actor_url, "https://etchit.io/actors/josh");
        assert_eq!(record.agent_id_hex.len(), 64);
        assert!(record.agent_id_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(record.registered_at_ms, 1234);
    }

    #[test]
    fn uppercase_handle_is_rejected() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let mut req = valid_request();
        req.handle = "Josh".into();
        assert!(matches!(verify_registration(&cfg, &req, 1).unwrap_err(),
                         RegistryRejection::Handle(_)));
    }

    #[test]
    fn tampered_attestation_is_rejected() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let mut req = valid_request();
        req.attestation_v2.relay_hint = "https://evil.example/".into();
        assert!(matches!(verify_registration(&cfg, &req, 1).unwrap_err(),
                         RegistryRejection::Attestation(_)));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let mut req = valid_request();
        req.attestation_v2.version = 1;
        assert!(matches!(verify_registration(&cfg, &req, 1).unwrap_err(),
                         RegistryRejection::Attestation(_)));
    }

    #[test]
    fn garbage_spki_is_rejected_by_so4_parse() {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let mut req = valid_request();
        req.rsa_spki_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
        // Note: this also breaks the signature (spki is in the signed
        // input), so either Spki or Attestation rejection is correct —
        // both are 422. Assert it is one of them.
        assert!(matches!(verify_registration(&cfg, &req, 1).unwrap_err(),
                         RegistryRejection::Spki(_) | RegistryRejection::Attestation(_)));
    }
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::verify::tests::committed_valid`
Expected: FAIL — `verify_registration` not defined.

- [ ] **Step 3: Implement**

```rust
/// Verify a registration/update request against the bridge's domain.
/// Order: validate handle (422) -> build canonical URL -> SO-4 SPKI
/// parse (422) -> `verify_binding_v2` (422) -> assemble [`ActorRecord`]
/// with the DERIVED agent id. `now_ms` stamps `registered_at_ms`.
///
/// # Errors
/// [`RegistryRejection`] (every variant maps to HTTP 422).
pub fn verify_registration(
    cfg: &RegistryConfig,
    req: &RegisterActorRequest,
    now_ms: u64,
) -> Result<ActorRecord, RegistryRejection> {
    let actor_url = canonical_actor_url(cfg, &req.handle)?;

    // SO-4: parse-validate the SPKI so the served publicKeyPem is a real
    // RSA key. verify_binding_v2 covers the SPKI bytes in the signed
    // input but does not parse them as a key.
    use rsa::pkcs8::DecodePublicKey;
    rsa::RsaPublicKey::from_public_key_der(&req.rsa_spki_der)
        .map_err(|e| RegistryRejection::Spki(e.to_string()))?;

    let agent_id_hex = fetchit_fedi::attestation::verify_binding_v2(
        &req.handle,
        &actor_url,
        &req.rsa_spki_der,
        &req.attestation_v2,
    )
    .map_err(|e| RegistryRejection::Attestation(e.to_string()))?;

    Ok(ActorRecord {
        handle: req.handle.clone(),
        actor_url: actor_url.as_str().to_string(),
        agent_id_hex,
        rsa_spki_der: req.rsa_spki_der.clone(),
        attestation: req.attestation_v2.clone(),
        registered_at_ms: now_ms,
    })
}
```

Confirm `rsa::pkcs8::DecodePublicKey` is the right trait path against the pinned `rsa` version; if the `pkcs8` re-export differs, use `rsa::pkcs8::SubjectPublicKeyInfoRef`/`spki` per the crate's actual API (check `cargo doc -p rsa` or the existing `inbox/sig_verify.rs` RSA usage, which already imports from `rsa`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::verify`
Expected: PASS (all verify tests, incl. the committed green vector deriving a real agent id).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/verify.rs
git commit -s -m "feat(relay): registry verification core over verify_binding_v2 (SO-1/SO-4)"
```

---

### Task 7: WebFinger server — `parse_acct_resource` + JRD + `GET /.well-known/webfinger`

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/webfinger.rs`

- [ ] **Step 1: Write the failing tests** (pure parser + JRD; the route is tested in Task 12's integration step)

```rust
//! Server-side WebFinger: parse `acct:<handle>@<domain>` and build the
//! JRD pointing at the canonical actor URL.

use crate::registry::ActorRecord;
use serde_json::{json, Value};

/// Parse a WebFinger `resource` of the form `acct:<handle>@<domain>`.
/// Returns `(handle, domain)`. Tolerates a leading `acct:` only.
///
/// # Errors
/// `Err(())` on any shape violation (maps to HTTP 400).
pub fn parse_acct_resource(resource: &str) -> Result<(String, String), ()> { unimplemented!() }

/// Build the JRD for a stored record.
#[must_use]
pub fn webfinger_jrd(record: &ActorRecord, domain: &str) -> Value {
    json!({
        "subject": format!("acct:{}@{}", record.handle, domain),
        "aliases": [record.actor_url],
        "links": [{
            "rel": "self",
            "type": "application/activity+json",
            "href": record.actor_url,
        }],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::tests_support::record_with;

    #[test]
    fn parses_well_formed_acct() {
        assert_eq!(parse_acct_resource("acct:josh@etchit.io").unwrap(),
                   ("josh".to_string(), "etchit.io".to_string()));
    }

    #[test]
    fn rejects_missing_prefix_or_at() {
        for bad in ["josh@etchit.io", "acct:joshetchit.io", "acct:@etchit.io",
                    "acct:josh@", "", "acct:a@b@c"] {
            assert!(parse_acct_resource(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn jrd_self_link_points_at_actor_url() {
        let r = record_with("josh", "a".repeat(64), 5);
        let jrd = webfinger_jrd(&r, "etchit.io");
        assert_eq!(jrd["subject"], "acct:josh@etchit.io");
        assert_eq!(jrd["links"][0]["href"], "https://etchit.io/actors/josh");
        assert_eq!(jrd["links"][0]["type"], "application/activity+json");
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::webfinger`
Expected: FAIL — `parse_acct_resource` `unimplemented!()`.

- [ ] **Step 3: Implement `parse_acct_resource`**

```rust
pub fn parse_acct_resource(resource: &str) -> Result<(String, String), ()> {
    let rest = resource.strip_prefix("acct:").ok_or(())?;
    let (handle, domain) = rest.split_once('@').ok_or(())?;
    if handle.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(());
    }
    Ok((handle.to_string(), domain.to_string()))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::webfinger`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/webfinger.rs
git commit -s -m "feat(relay): WebFinger resource parse + JRD builder"
```

---

### Task 8: Actor document — JSON-LD builder + the offline-verifiable round-trip test

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/actor_doc.rs`

- [ ] **Step 1: Write the failing tests** (the crown-jewel: serve the doc, verify it with fetchit-fedi's own client decoder)

```rust
//! Build the ActivityPub actor document. The document carries the
//! `publicKeyPem` and the v2 attestation under
//! `PQ_ATTESTATION_V2_PROPERTY_URI` so any client verifies the full
//! chain offline.

use crate::registry::ActorRecord;
use fetchit_fedi::actor::{spki_der_to_pem, PQ_ATTESTATION_V2_PROPERTY_URI};
use serde_json::{json, Value};

/// Build the actor JSON-LD document for a stored record.
#[must_use]
pub fn actor_document(record: &ActorRecord) -> Value {
    let pem = spki_der_to_pem(&record.rsa_spki_der);
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],
        "id": record.actor_url,
        "type": "Person",
        "preferredUsername": record.handle,
        "inbox": format!("{}/inbox", record.actor_url),
        "publicKey": {
            "id": format!("{}#main-key", record.actor_url),
            "owner": record.actor_url,
            "publicKeyPem": pem,
        },
    });
    doc.as_object_mut().unwrap().insert(
        PQ_ATTESTATION_V2_PROPERTY_URI.to_string(),
        serde_json::to_value(&record.attestation).unwrap(),
    );
    doc
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::verify::{verify_registration, RegistryConfig};
    use fetchit_fedi::lookup::RemoteActor;
    use fetchit_fedi::registry::RegisterActorRequest;

    fn valid_record() -> ActorRecord {
        let cfg = RegistryConfig { domain: "etchit.io".into() };
        let req: RegisterActorRequest = serde_json::from_str(include_str!(
            "../../../fetchit-fedi/tests/fixtures/registry-v1/register-request-valid.json"
        )).unwrap();
        verify_registration(&cfg, &req, 1).unwrap()
    }

    #[test]
    fn served_doc_round_trips_through_client_decoder_and_verifies() {
        let record = valid_record();
        let doc = actor_document(&record);
        // Feed the SERVED doc back through fetchit-fedi's own tolerant
        // client decoder + attestation verify: the chain must close, and
        // the derived agent id must equal what we stored.
        let remote = RemoteActor::from_json_ld(&doc).expect("client decodes served doc");
        let derived = remote.verify_attestation_v2().expect("attestation verifies offline");
        assert_eq!(derived, record.agent_id_hex);
        assert_eq!(remote.preferred_username, "josh");
        assert_eq!(remote.id.as_str(), "https://etchit.io/actors/josh");
    }

    #[test]
    fn doc_has_pem_and_attestation_slots() {
        let record = valid_record();
        let doc = actor_document(&record);
        assert_eq!(doc["type"], "Person");
        assert!(doc["publicKey"]["publicKeyPem"].as_str().unwrap()
                .contains("BEGIN PUBLIC KEY"));
        assert!(doc.get(PQ_ATTESTATION_V2_PROPERTY_URI).is_some());
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::actor_doc`
Expected: FAIL (compile or assertion) until the builder + `dev-dependency` access to the fixture path resolve. If `from_json_ld` rejects on `inbox`/extra fields, drop non-essential keys — the allowlist only requires `id`/`preferredUsername`/`type`; keep `publicKey` + attestation, trim anything that trips the decoder.

- [ ] **Step 3: Confirm/adjust the builder** so the round-trip passes (it should as written; `from_json_ld` is tolerant of extra fields and only strict on `type`, `publicKey.owner==id`, and attestation well-formedness).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::actor_doc`
Expected: PASS — the served doc is provably offline-verifiable.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/actor_doc.rs
git commit -s -m "feat(relay): actor-doc builder + offline round-trip verify test"
```

---

### Task 9: `POST /v1/actors` handler + `RegistryState` + router skeleton

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/router.rs`

- [ ] **Step 1: Write the failing tests** (drive the testable inner fn; the axum wrapper is exercised in Task 12)

```rust
//! Axum router + handlers for the registry + serving endpoints. Thin
//! handlers delegate to `?`-ergonomic inner fns the unit tests drive
//! without the axum layer (mirrors `crate::inbox::router`).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::json;

use crate::inbox::InboxRateLimit;
use crate::registry::verify::{verify_registration, RegistryConfig};
use crate::registry::{
    actor_doc::actor_document, webfinger::{parse_acct_resource, webfinger_jrd},
    ActorRegistryStore, RegistryRejection, RegistryStoreError,
};
use fetchit_fedi::registry::RegisterActorRequest;

/// Shared registry state on the axum router.
#[derive(Clone)]
pub struct RegistryState {
    /// Verified-registration store (FCFS + continuity).
    pub store: Arc<dyn ActorRegistryStore>,
    /// Bridge domain + verification config.
    pub config: RegistryConfig,
    /// Per-source token bucket (reused from the inbox).
    pub rate_limit: Arc<InboxRateLimit>,
}

/// The HTTP outcome of an endpoint: status + body string. Kept as a
/// concrete type so inner fns are unit-testable without axum.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: u16,
    pub body: String,
}

/// Map a verification rejection to its 422 outcome.
fn rejection_outcome(r: &RegistryRejection) -> Outcome {
    Outcome { status: 422, body: r.to_string() }
}

/// Map a store error to its outcome (409/404).
fn store_outcome(e: &RegistryStoreError) -> Outcome {
    let status = match e {
        RegistryStoreError::UnknownHandle => 404,
        RegistryStoreError::HandleTaken
        | RegistryStoreError::AgentMismatch
        | RegistryStoreError::StaleEpoch => 409,
    };
    Outcome { status, body: e.to_string() }
}

/// POST /v1/actors core: parse -> verify -> register. 201 on success.
pub fn register_inner(state: &RegistryState, body: &[u8], now_ms: u64) -> Outcome {
    let req: RegisterActorRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&RegistryRejection::Body(e.to_string())),
    };
    let record = match verify_registration(&state.config, &req, now_ms) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&e),
    };
    let actor_url = record.actor_url.clone();
    match state.store.register(record) {
        Ok(()) => Outcome { status: 201, body: json!({"actor_url": actor_url}).to_string() },
        Err(e) => store_outcome(&e),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::registry::InMemoryActorStore;

    fn state() -> RegistryState {
        RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config: RegistryConfig { domain: "etchit.io".into() },
            rate_limit: Arc::new(InboxRateLimit::new(1000)),
        }
    }

    const VALID: &str = include_str!(
        "../../../fetchit-fedi/tests/fixtures/registry-v1/register-request-valid.json"
    );

    #[test]
    fn register_valid_returns_201_with_actor_url() {
        let st = state();
        let out = register_inner(&st, VALID.as_bytes(), 1);
        assert_eq!(out.status, 201);
        assert_eq!(out.body, r#"{"actor_url":"https://etchit.io/actors/josh"}"#);
    }

    #[test]
    fn register_duplicate_returns_409() {
        let st = state();
        assert_eq!(register_inner(&st, VALID.as_bytes(), 1).status, 201);
        assert_eq!(register_inner(&st, VALID.as_bytes(), 2).status, 409);
    }

    #[test]
    fn register_uppercase_handle_returns_422() {
        let st = state();
        let mut v: serde_json::Value = serde_json::from_str(VALID).unwrap();
        v["handle"] = json!("Josh");
        let out = register_inner(&st, v.to_string().as_bytes(), 1);
        assert_eq!(out.status, 422);
    }

    #[test]
    fn register_malformed_body_returns_422() {
        let st = state();
        assert_eq!(register_inner(&st, b"not json", 1).status, 422);
    }
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router::tests::register_`
Expected: FAIL — until `register_inner` + `RegistryState` compile.

- [ ] **Step 3: Implement** the code above (it is the implementation). Add the axum handler + a partial `registry_router` (POST only for now; other routes added in Tasks 10–11):

```rust
async fn handle_register(State(state): State<RegistryState>, body: Bytes) -> Response {
    let now = now_ms();
    let out = register_inner(&state, &body, now);
    (StatusCode::from_u16(out.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), out.body)
        .into_response()
}

/// Wall-clock ms. Mirrors the relay-server's existing now-ms helper;
/// reuse `crate::<existing now_ms>` if one is already exported.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    })
}

/// Build the registry + serving router.
#[must_use]
pub fn registry_router(state: RegistryState) -> Router {
    Router::new()
        .route("/v1/actors", post(handle_register))
        .with_state(state)
}
```

Check for an existing wall-clock helper in the crate (grep `now_ms`/`unix_millis`) and reuse it instead of the local `now_ms` if present, to keep one clock policy.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router::tests::register_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/router.rs
git commit -s -m "feat(relay): POST /v1/actors register handler + RegistryState"
```

---

### Task 10: `PUT /v1/actors/<handle>` handler

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/router.rs`

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn update_existing_same_agent_newer_epoch_returns_200() {
        let st = state();
        assert_eq!(register_inner(&st, VALID.as_bytes(), 1).status, 201);
        // Bump the epoch on the same signed vector is not possible without
        // re-signing; instead drive update_inner with a re-derived record
        // via a second valid fixture if available. For M5.1 the green path
        // asserts the 200 mapping using a freshly verified record whose
        // agent id matches and epoch increases (see note).
        let mut v: serde_json::Value = serde_json::from_str(VALID).unwrap();
        // Same request => same agent, same epoch => stale => 409 (proves
        // the monotonicity gate is wired through the handler).
        let out = update_inner(&st, "josh", v.to_string().as_bytes(), 2);
        assert_eq!(out.status, 409);
        // Path/body handle mismatch => 422.
        v["handle"] = json!("alice");
        let mismatch = update_inner(&st, "josh", v.to_string().as_bytes(), 3);
        assert_eq!(mismatch.status, 422);
    }

    #[test]
    fn update_unknown_handle_returns_404() {
        let st = state();
        let out = update_inner(&st, "josh", VALID.as_bytes(), 1);
        assert_eq!(out.status, 404);
    }
```

> **Note for the executor:** a clean 200-path test needs a second green vector with the same agent id and a strictly greater `hint_epoch_ms`. Add `register-request-valid-epoch2.json` via the regenerator (`emit_valid_registration_fixture`, edited to bump the epoch and re-sign with the SAME keypair) OR add a `cfg(test)` re-sign helper in `verify.rs` that mints a fresh keypair and produces two records sharing it. Prefer the helper (no new committed fixture): it derives one keypair, signs two epochs, and feeds both through `verify_registration`. Coordinate the fixture choice with Alice (the fixtures dir is the shared contract). Until then, the 409/404/422 mappings above fully exercise the handler wiring; the 200 path is covered at the store layer (Task 3) and gets its handler-level test once the epoch2 vector lands.

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router::tests::update_`
Expected: FAIL — `update_inner` not defined.

- [ ] **Step 3: Implement**

```rust
/// PUT /v1/actors/<handle> core: parse -> path/body handle agreement ->
/// verify -> store.update.
pub fn update_inner(state: &RegistryState, path_handle: &str, body: &[u8], now_ms: u64) -> Outcome {
    let req: RegisterActorRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&RegistryRejection::Body(e.to_string())),
    };
    if req.handle != path_handle {
        return rejection_outcome(&RegistryRejection::HandleMismatch {
            path: path_handle.to_string(),
            body: req.handle.clone(),
        });
    }
    let record = match verify_registration(&state.config, &req, now_ms) {
        Ok(r) => r,
        Err(e) => return rejection_outcome(&e),
    };
    let actor_url = record.actor_url.clone();
    match state.store.update(record) {
        Ok(()) => Outcome { status: 200, body: json!({"actor_url": actor_url}).to_string() },
        Err(e) => store_outcome(&e),
    }
}

async fn handle_update(
    State(state): State<RegistryState>,
    Path(handle): Path<String>,
    body: Bytes,
) -> Response {
    let now = now_ms();
    let out = update_inner(&state, &handle, &body, now);
    (StatusCode::from_u16(out.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), out.body)
        .into_response()
}
```

Add `.route("/v1/actors/{handle}", put(handle_update))` to `registry_router` (axum 0.7+ path syntax is `{handle}`; match the version the crate uses — inbox uses plain string routes, confirm Path capture syntax against the pinned axum).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router::tests::update_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/router.rs
git commit -s -m "feat(relay): PUT /v1/actors/<handle> update handler"
```

---

### Task 11: WebFinger + actor-doc GET routes + per-source rate limit

**Files:**
- Modify: `crates/fetchit-relay-server/src/registry/router.rs`

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn webfinger_known_handle_returns_jrd() {
        let st = state();
        register_inner(&st, VALID.as_bytes(), 1);
        let out = webfinger_inner(&st, Some("resource=acct:josh@etchit.io"));
        assert_eq!(out.status, 200);
        assert!(out.body.contains(r#""href":"https://etchit.io/actors/josh""#));
    }

    #[test]
    fn webfinger_unknown_or_foreign_returns_404_and_malformed_400() {
        let st = state();
        assert_eq!(webfinger_inner(&st, Some("resource=acct:ghost@etchit.io")).status, 404);
        assert_eq!(webfinger_inner(&st, Some("resource=acct:josh@evil.example")).status, 404);
        assert_eq!(webfinger_inner(&st, Some("resource=not-acct")).status, 400);
        assert_eq!(webfinger_inner(&st, None).status, 400);
    }

    #[test]
    fn actor_doc_known_returns_200_unknown_404() {
        let st = state();
        register_inner(&st, VALID.as_bytes(), 1);
        assert_eq!(actor_doc_inner(&st, "josh").status, 200);
        assert_eq!(actor_doc_inner(&st, "ghost").status, 404);
    }

    #[test]
    fn rate_limit_drains_to_429() {
        let st = RegistryState {
            store: Arc::new(InMemoryActorStore::new()),
            config: RegistryConfig { domain: "etchit.io".into() },
            rate_limit: Arc::new(InboxRateLimit::new(1)),
        };
        assert!(st.rate_limit.allow("1.2.3.4"));
        assert!(!st.rate_limit.allow("1.2.3.4"));
        // A different source still has budget.
        assert!(st.rate_limit.allow("5.6.7.8"));
    }
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router::tests::webfinger_known`
Expected: FAIL — `webfinger_inner`/`actor_doc_inner` not defined.

- [ ] **Step 3: Implement**

```rust
/// GET /.well-known/webfinger?resource=acct:<h>@<domain>
pub fn webfinger_inner(state: &RegistryState, raw_query: Option<&str>) -> Outcome {
    let resource = raw_query
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "resource")
                .map(|(_, v)| v.into_owned())
        });
    let Some(resource) = resource else {
        return Outcome { status: 400, body: "missing resource".into() };
    };
    let Ok((handle, domain)) = parse_acct_resource(&resource) else {
        return Outcome { status: 400, body: "malformed resource".into() };
    };
    if domain != state.config.domain {
        return Outcome { status: 404, body: "unknown".into() };
    }
    match state.store.get(&handle) {
        Some(record) => Outcome {
            status: 200,
            body: webfinger_jrd(&record, &state.config.domain).to_string(),
        },
        None => Outcome { status: 404, body: "unknown".into() },
    }
}

/// GET /actors/<handle>
pub fn actor_doc_inner(state: &RegistryState, handle: &str) -> Outcome {
    match state.store.get(handle) {
        Some(record) => Outcome { status: 200, body: actor_document(&record).to_string() },
        None => Outcome { status: 404, body: "unknown".into() },
    }
}
```

Add the axum handlers + routes. WebFinger uses `RawQuery`; actor-doc uses `Path`. Both serve `Content-Type: application/jrd+json` / `application/activity+json` respectively. Add rate-limit gating to `handle_register`/`handle_update` BEFORE parsing, keyed by the source-IP helper:

```rust
/// Extract the rate-limit source key. SECURITY (Alice's flag-2 catch):
/// leftmost `X-Forwarded-For` is CLIENT-SPOOFABLE when a proxy appends
/// rather than overwrites, so we do NOT key on it. The bridge's sole
/// ingress is Cloudflare + the CF Worker; the Worker forwards the
/// authoritative client IP — `CF-Connecting-IP`, which Cloudflare sets
/// and a client cannot forge — in a configured trusted header
/// (`RegistryConfig::trusted_client_ip_header`, default `x-real-ip`).
/// We key on THAT header only, falling back to the connection peer for
/// non-CF / test paths. Origin reachability MUST be restricted to the
/// Worker (Caddy/UFW) so the trusted header cannot be set by a direct
/// caller. The CF Worker (`fetchit-bridge-worker`) gains a matching
/// change to inject the header from `CF-Connecting-IP`.
fn source_key(
    headers: &axum::http::HeaderMap,
    trusted_header: &str,
    peer: Option<std::net::IpAddr>,
) -> String {
    headers
        .get(trusted_header)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| peer.map(|p| p.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}
```

In `handle_register`/`handle_update`, before the inner call: `if !state.rate_limit.allow(&source_key(&headers, &state.config.trusted_client_ip_header, peer)) { return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response(); }` (add `headers: HeaderMap` + `ConnectInfo<SocketAddr>` to the handler signatures and serve with `into_make_service_with_connect_info`). The exact trusted-header name + the sole-ingress assumption are confirmed with Alice/Josh during the plan review; `RegistryConfig` carries it so it is one config knob, not a literal.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router`
Expected: PASS (all router inner-fn tests).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src/registry/router.rs
git commit -s -m "feat(relay): WebFinger + actor-doc GET routes + per-source rate limit"
```

---

### Task 12: Compose into the server + full-router integration test

**Files:**
- Modify: `crates/fetchit-relay-server/src/server.rs` (or `main.rs` operator bring-up — match where `inbox_router` is merged; Stage 7 wired the inbox in `main.rs`/operator path)
- Modify: `crates/fetchit-relay-server/src/registry/router.rs` (integration test)

- [ ] **Step 1: Write the failing integration test** (full axum router via `tower::ServiceExt::oneshot`, mirroring how inbox tests would exercise the HTTP layer)

```rust
    #[tokio::test]
    async fn full_router_register_then_webfinger_then_actor_doc() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let st = state();
        let app = registry_router(st);

        // POST register -> 201
        let resp = app.clone().oneshot(
            Request::builder().method("POST").uri("/v1/actors")
                .header("content-type", "application/json")
                .body(Body::from(VALID)).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // WebFinger -> 200 JRD
        let resp = app.clone().oneshot(
            Request::builder().method("GET")
                .uri("/.well-known/webfinger?resource=acct:josh@etchit.io")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Actor doc -> 200 activity+json
        let resp = app.oneshot(
            Request::builder().method("GET").uri("/actors/josh")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/activity+json");
    }
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox registry::router::tests::full_router`
Expected: FAIL — routes for webfinger/actor-doc not yet mounted, or content-type header missing.

- [ ] **Step 3: Finish `registry_router`** — mount all four routes with correct content-types, then merge into the server. In the operator bring-up where `inbox_router(inbox_state)` is created, build `RegistryState` (shared `Arc<InMemoryActorStore>`, `RegistryConfig{domain}` from operator config, an `InboxRateLimit`) and `.merge(registry_router(registry_state))` onto the same axum `Router`. Add a `--fedi-domain` (default `etchit.io`) operator flag next to the existing inbox flags. Confirm `tower` is a dev-dependency (it is: `tower = { version = "0.5", features = ["util"] }`).

- [ ] **Step 4: Run to verify pass + the whole feature suite**

Run: `cargo test -p fetchit-relay-server --features fediverse-inbox`
Expected: PASS (registry + inbox + existing suites).

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-relay-server/src
git commit -s -m "feat(relay): mount registry router alongside inbox in operator bring-up"
```

---

### Task 13: Durable store backend (DECISION-GATED — recommend SQLite)

**Files:**
- Create: `crates/fetchit-relay-server/src/registry/store_durable.rs`
- Modify: `crates/fetchit-relay-server/Cargo.toml` (add the chosen backend dep under `fediverse-inbox`)
- Modify: operator bring-up (use the durable store in prod; in-memory stays for tests)

> **DECISION (flag to Alice + Josh, [[recommend-when-asking]]):** relay-server is deliberately RAM-only for *chat*, but the registry needs durable handles (FCFS is meaningless if a restart wipes them). The spec's storage statement explicitly sanctions storing the public handle directory. **Recommendation: SQLite via `rusqlite` (bundled), gated under `fediverse-inbox`** — it matches the approved #205–210 foundation's choice, gives atomic FCFS/upsert for free, and stays out of the default relay's dep tree. Alternative: an append-only JSON snapshot with atomic rename (no new dep, but hand-rolled concurrency). Do NOT implement this task until the backend is confirmed.

- [ ] **Step 1:** Confirm the backend choice with Alice/Josh.
- [ ] **Step 2:** Write failing tests: durability across a reopen (register -> drop -> reopen same path -> `get` returns the record); FCFS/continuity/epoch parity with the in-memory tests (run the SAME assertion battery against the durable impl).
- [ ] **Step 3:** Implement `DurableActorStore` behind `ActorRegistryStore`, identical invariant enforcement (atomic via a UNIQUE handle column + a transaction for the same-agent/epoch check on update).
- [ ] **Step 4:** Run to verify pass.
- [ ] **Step 5:** Commit `feat(relay): durable registry store backend`.

---

### Task 14: Full gates + REFERENCE.md + cross-review + sync

**Files:**
- Modify: `REFERENCE.md`

- [ ] **Step 1:** Format + lint, BOTH default and feature builds (the feature gate must not break the default relay):

```bash
cargo fmt --all --check
cargo clippy -p fetchit-relay-server --all-targets -- -D warnings
cargo clippy -p fetchit-relay-server --all-targets --features fediverse-inbox -- -D warnings
```

- [ ] **Step 2:** Tests, default + feature:

```bash
cargo test -p fetchit-relay-server
cargo test -p fetchit-relay-server --features fediverse-inbox
cargo test -p fetchit-fedi   # re-confirm the contract crate stays green
```

- [ ] **Step 3:** Add a `## Registry (Component D)` sub-section to `REFERENCE.md` under fetchit-relay-server: the four routes, the trait/store/verify split, the response-code map, the trusted-proxy rate-limit assumption, and the offline-verify round-trip guarantee.
- [ ] **Step 4:** Self-review the whole branch diff; run the Box-B full gate (workspace fmt/clippy/test) to confirm nothing else regressed.
- [ ] **Step 5:** Commit `docs(relay): REFERENCE.md registry section + M5.1 D-half gates`; push to `origin` (`josh-clsn/fetchit`, free per redlines — NOT etchit-io); sync Alice with the branch range + the two design flags resolved.

---

## Self-review notes (author)

- **Spec coverage:** POST/PUT registry (spec §Component D) = Tasks 9–10; WebFinger server + actor-doc hosting (spec §"Relationship to M4" serving half) = Tasks 7–8, 11–12; attestation-v2 verify as sole signature (pre-spec flag #2) = Task 6; hint-epoch monotonicity + same-agent (spec §trust model) = Task 3; handle policy SO-3 = Task 4; canonical URL SO-1 = Task 5; SO-4 SPKI = Task 6; rate limit (spec §security) = Task 11; durable directory storage (spec §storage statement) = Task 13. Search (Component C) and follow (Component B) are explicitly out of M5.1 (they are M5.3/M5.2).
- **Type consistency:** `Outcome{status,body}` is the single inner-fn return; `RegistryRejection`→422, `RegistryStoreError`→409/404; `verify_registration` returns `ActorRecord`; handlers map `Outcome` to axum `Response`. `actor_url` is always the `as_str()` of the SO-1 URL.
- **Open items to confirm during execution (flagged, non-blocking for Tasks 1–12):** (a) durable backend choice (Task 13 — recommend SQLite/rusqlite); (b) rate-limit source key (Task 11) — per Alice's flag-2 catch, key on the CF-set `CF-Connecting-IP` forwarded by the Worker into a trusted header (`RegistryConfig::trusted_client_ip_header`, default `x-real-ip`), NOT leftmost XFF; needs the sole-ingress assumption + the CF Worker header-injection change + origin reachability lockdown confirmed with Alice/Josh; (c) the PUT 200-path handler test uses a `cfg(test)` re-sign helper, no shared committed fixture (confirmed by Alice); (d) exact `rsa` SPKI-parse API path + axum `Path` capture syntax against the pinned versions.
