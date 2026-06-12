# Android LIT P0 — Daemonless Chat Profile + FFI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `fetchit-chat::Client` buildable with zero x0xd daemon (local ML-DSA-65 signer, relay-only transport) and expose the chat MVP surface (identity, pointer-URI pairing, DM send/receive) through `fetchit-ffi` so the Android shell can consume it.

**Architecture:** A `LocalSignerVault` (encrypted, mirrors the existing chat-identity vault) supplies the ML-DSA-65 keypair and derived `agent_id` that x0xd's `/agent` + `/agent/sign` supply on desktop. A `daemonless` builder flag skips daemon discovery, the TreeKEM version probe, and `X0xdSigner` construction; everything downstream (KEM identity, conversation registry, `MultiHomeTransport`, pair records) already works against `Arc<dyn Signer>` and is unchanged. The FFI adds a `ChatClient` uniffi object in the existing `fetchit-ffi` crate (same `.so`, same tokio runtime).

**Tech Stack:** Rust stable (workspace lints: no unwrap/expect/panic outside tests, missing_docs warns), saorsa-pqc ML-DSA-65, uniffi 0.29.5 (pinned, must match `uniffi-bindgen` CLI), cargo-ndk + NDK r27 (arm64-v8a).

---

## Context for the implementer (read first)

- **Worktree:** work ONLY in `/home/josh/Desktop/etchit-fetchit/fetchit-android-lit` (branch `android-lit`, off `origin/chat` @ ac58994). Do NOT run `cargo build` in `/home/josh/Desktop/etchit-fetchit/fetchit` — the live comms `fetchit-chat-peer` systemd unit execs from that checkout's `target/debug/` and the wedge-healer auto-restarts it.
- **Remotes:** push only to `origin` (josh-clsn/fetchit). NEVER push to the `etchit-io` remote.
- **Commits:** DCO required — always `git commit -s`. Conventional-commit style, e.g. `feat(chat): ...`.
- **Lints are CI-enforced:** `cargo clippy --workspace --all-targets -- -D warnings`. `unwrap()`/`expect()` only inside `#[cfg(test)]` modules opening with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` — but note `fetchit-chat` test modules conventionally use `#[allow(...)]` on the module (see `client.rs:3212-3213`).
- **`crates/fetchit-ffi` is workspace-EXCLUDED** (own `Cargo.lock`). Run all its cargo commands from inside `crates/fetchit-ffi/`. Root `cargo test --workspace` never touches it.
- Key existing types you will reuse (do not redefine):
  - `fetchit_relay_client::MlDsaSigner` (`crates/fetchit-relay-client/src/signer.rs:60-135`): `generate()`, `from_bytes(pk, sk)`, `secret_key_bytes()`, `public_key()`, implements `Signer` with `agent_id() -> [u8; 32]` derived via `fetchit_relay_proto::derive_agent_id`.
  - `crate::at_rest::{open_from_path, seal_to_path, MasterKey, fresh_argon_salt, ARGON_SALT_LEN}` — the vault sealing helpers used by `chat_identity.rs:7,81,113`.
  - `crate::conversation::{dispatch_inbound, InboundDispatch}` — public inbound decoder (see `bin/peer.rs:39,761-804` for the canonical consumer).
  - `Client::take_transport_inbound("relay")`, `Client::identity_arc()`, `Client::registry_arc()` — public; used by `bin/peer.rs`.

## File structure

| File | Responsibility |
|---|---|
| `crates/fetchit-chat/src/local_signer.rs` (new) | Encrypted vault holding the local ML-DSA-65 keypair + machine token; daemonless replacement for x0xd's `/agent` identity |
| `crates/fetchit-chat/src/client.rs` (modify) | `daemonless` builder flag; skip discovery/probe/X0xdSigner; `local_agent_id_hex()` accessor |
| `crates/fetchit-chat/src/lib.rs` (modify) | `mod local_signer;` registration |
| `crates/fetchit-ffi/src/chat_error.rs` (new) | Coarse uniffi error enum for the chat surface |
| `crates/fetchit-ffi/src/chat_ffi.rs` (new) | `ChatClient` uniffi object: connect / agent id / pair share+import / send DM / event stream |
| `crates/fetchit-ffi/src/lib.rs` + `Cargo.toml` (modify) | wire the new modules + `fetchit-chat` dep |
| `REFERENCE.md` (modify) | document the daemonless profile |

---

### Task 1: `LocalSignerVault` — persisted local ML-DSA-65 identity

**Files:**
- Create: `crates/fetchit-chat/src/local_signer.rs`
- Modify: `crates/fetchit-chat/src/lib.rs` (add `mod local_signer;` next to the existing `mod chat_identity;` line)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests** (in `local_signer.rs`, bottom):

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::at_rest::{fresh_argon_salt, kdf_id_argon2, MasterKey, MasterKeySource};
    use fetchit_relay_client::Signer as _;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn test_master(salt: &[u8; crate::at_rest::ARGON_SALT_LEN]) -> MasterKey {
        MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("test-pass".to_owned())),
            Some(salt),
        )
        .unwrap()
    }

    #[test]
    fn create_then_reload_round_trips_agent_id() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);

        let v1 = LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let v2 = LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
            .unwrap();
        assert_eq!(v1.signer.agent_id(), v2.signer.agent_id());
        assert_eq!(v1.machine_token, v2.machine_token);
        assert!(dir.path().join(LOCAL_SIGNER_FILE).exists());
    }

    #[test]
    fn wrong_master_key_errors_instead_of_regenerating() {
        let dir = TempDir::new().unwrap();
        let salt = fresh_argon_salt();
        let master = test_master(&salt);
        let created =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();

        let other_salt = fresh_argon_salt();
        let wrong = MasterKey::resolve(
            &MasterKeySource::Passphrase(Zeroizing::new("other-pass".to_owned())),
            Some(&other_salt),
        )
        .unwrap();
        // A decrypt failure must surface as an error — silently minting a
        // fresh identity would orphan every contact pairing.
        let res =
            LocalSignerVault::load_or_create(dir.path(), &wrong, kdf_id_argon2(), Some(&other_salt));
        assert!(res.is_err());
        // and the original vault is untouched
        let again =
            LocalSignerVault::load_or_create(dir.path(), &master, kdf_id_argon2(), Some(&salt))
                .unwrap();
        assert_eq!(again.signer.agent_id(), created.signer.agent_id());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fetchit-chat local_signer`
Expected: compile FAIL (`LocalSignerVault` not defined).

- [ ] **Step 3: Implement** (top of `local_signer.rs`):

```rust
//! Daemonless local signing identity.
//!
//! On desktop, x0xd owns the ML-DSA-65 keypair and the chat layer
//! signs through `/agent/sign` (`X0xdSigner`). The daemonless profile
//! (Android, or any host without a daemon) instead persists a local
//! keypair in the chat vault, sealed with the same master key as the
//! KEM identity. The agent id is `derive_agent_id(public_key)`, so a
//! local-key agent is a first-class citizen of the relay protocol —
//! pair records and bearer handshakes verify against the public key.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fetchit_relay_client::MlDsaSigner;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::at_rest::{fresh_argon_salt, open_from_path, seal_to_path, MasterKey};
use crate::error::ChatError;

/// Vault file name under the chat data dir, next to `identity.json.enc`.
pub(crate) const LOCAL_SIGNER_FILE: &str = "local_signer.json.enc";

#[derive(Serialize, Deserialize)]
struct LocalSignerPayload {
    version: u8,
    ml_dsa_public_key_b64: String,
    ml_dsa_secret_key_b64: String,
    /// Random per-install token fed to `derive_machine_id`; NOT derived
    /// from the keypair so a restored identity on a new device still
    /// gets a distinct machine fingerprint.
    machine_token: String,
}

/// The local signing identity: an [`MlDsaSigner`] plus the per-install
/// machine token, both persisted encrypted at
/// `data_dir/local_signer.json.enc`.
pub(crate) struct LocalSignerVault {
    pub(crate) signer: MlDsaSigner,
    pub(crate) machine_token: String,
}

impl LocalSignerVault {
    /// Load the vault, generating and persisting a fresh keypair when
    /// the file does not exist. A decrypt or parse failure on an
    /// EXISTING file is an error, never a silent regeneration —
    /// regenerating would orphan every pairing bound to the agent id.
    pub(crate) fn load_or_create(
        data_dir: &Path,
        master: &MasterKey,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        let path = data_dir.join(LOCAL_SIGNER_FILE);
        if path.exists() {
            let bytes = open_from_path(&path, master)?;
            let payload: LocalSignerPayload = serde_json::from_slice(&bytes)
                .map_err(|e| ChatError::Invalid(format!("local signer payload parse: {e}")))?;
            let pk = B64
                .decode(&payload.ml_dsa_public_key_b64)
                .map_err(|e| ChatError::Invalid(format!("local signer pub b64: {e}")))?;
            let sk = B64
                .decode(&payload.ml_dsa_secret_key_b64)
                .map_err(|e| ChatError::Invalid(format!("local signer sec b64: {e}")))?;
            let signer = MlDsaSigner::from_bytes(&pk, &sk)
                .map_err(|e| ChatError::Invalid(format!("local signer rebuild: {e}")))?;
            return Ok(Self {
                signer,
                machine_token: payload.machine_token,
            });
        }

        let signer = MlDsaSigner::generate()
            .map_err(|e| ChatError::Invalid(format!("local signer keygen: {e}")))?;
        let machine_token = hex::encode(fresh_argon_salt());
        let payload = LocalSignerPayload {
            version: 1,
            ml_dsa_public_key_b64: B64.encode(signer.public_key()),
            ml_dsa_secret_key_b64: B64.encode(signer.secret_key_bytes()),
            machine_token: machine_token.clone(),
        };
        let mut plaintext = serde_json::to_vec(&payload)
            .map_err(|e| ChatError::Invalid(format!("local signer serialize: {e}")))?;
        let seal_result = seal_to_path(&path, &plaintext, master, kdf_id, argon_salt);
        plaintext.zeroize();
        seal_result?;
        Ok(Self {
            signer,
            machine_token,
        })
    }
}
```

Notes: `signer.public_key()` comes from the `Signer` trait — add `use fetchit_relay_client::Signer as _;` if not in scope. If `fresh_argon_salt` / `ARGON_SALT_LEN` visibility is `pub(crate)` only inside `at_rest`, that is fine (same crate). If `open_from_path`'s error type differs from `ChatError`, map it the same way `chat_identity.rs` does.

- [ ] **Step 4: Register the module** in `crates/fetchit-chat/src/lib.rs` next to `mod chat_identity;`:

```rust
pub(crate) mod local_signer;
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p fetchit-chat local_signer`
Expected: 2 passed.

- [ ] **Step 6: fmt + clippy + commit**

```bash
cargo fmt --all && cargo clippy -p fetchit-chat --all-targets -- -D warnings
git add crates/fetchit-chat/src/local_signer.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(chat): LocalSignerVault — persisted in-process ML-DSA-65 identity"
```

---

### Task 2: `daemonless` builder flag + daemonless build path

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs` — `ClientBuilder` (lines ~60-269), `from_parts` (~506), `build_with_chat` (~2258-2350), plus a new accessor near `denylist_dropped_inbound_count` (~626)
- Test: `client.rs` tests module

- [ ] **Step 1: Write the failing test** (in `client.rs` `mod tests`):

```rust
#[tokio::test]
async fn daemonless_build_is_offline_and_agent_id_persists() {
    let dir = TempDir::new().unwrap();
    let build = || async {
        Client::builder()
            .daemonless(true)
            .data_dir(dir.path().to_path_buf())
            .passphrase("test-pass".to_owned())
            .build()
            .await
            .unwrap()
    };
    // No relay_url, no daemon, no network: must still build (needs_chat
    // is true via data_dir) and expose a stable 64-hex agent id.
    let c1 = build().await;
    let id1 = c1.local_agent_id_hex().expect("chat state present");
    assert_eq!(id1.len(), 64);
    assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    drop(c1);
    let c2 = build().await;
    assert_eq!(c2.local_agent_id_hex().unwrap(), id1);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fetchit-chat daemonless_build_is_offline`
Expected: compile FAIL (`daemonless` / `local_agent_id_hex` not defined).

- [ ] **Step 3: Implement the builder flag.**

(a) Near the top of `client.rs` (by the other consts):

```rust
/// Sentinel x0xd base URL for daemonless builds. Port 9 (discard) is
/// never an x0xd, so any daemon-only endpoint that does get called in
/// a daemonless client fails fast with an honest connection error
/// instead of hanging on discovery.
const DAEMONLESS_BASE_URL: &str = "http://127.0.0.1:9";
```

(b) Add the field to `ClientBuilder` (after `advertised_relays`):

```rust
    /// Build without any x0xd daemon: skip discovery, skip the TreeKEM
    /// version probe, and sign with a local ML-DSA-65 keypair persisted
    /// in the chat vault ([`crate::local_signer::LocalSignerVault`])
    /// instead of `X0xdSigner`. Daemon-backed surfaces (M1/M2 groups,
    /// presence, v2 card generation) fail with transport errors against
    /// an unconnectable sentinel base URL. Meaningful only together
    /// with `data_dir` (and usually `relay_url` + `passphrase`); the
    /// Android shell is the primary consumer.
    daemonless: bool,
```

Then grep for every `ClientBuilder {` literal initializer (at minimum `Client::builder()` at ~line 501) and add `daemonless: false`. Do NOT rely on the compiler alone — check for `impl Default for ClientBuilder` and any test constructing the struct directly.

(c) Add the setter in `impl ClientBuilder` (after `advertised_relays`):

```rust
    /// Enable the daemonless profile. See the field doc for semantics.
    #[must_use]
    pub fn daemonless(mut self, enabled: bool) -> Self {
        self.daemonless = enabled;
        self
    }
```

(d) In `ClientBuilder::build()` (~line 247), replace the `(base_url, token)` resolution with:

```rust
        let (base_url, token) = if self.daemonless {
            (
                self.base_url
                    .unwrap_or_else(|| DAEMONLESS_BASE_URL.to_owned()),
                self.token.unwrap_or_default(),
            )
        } else {
            match (self.base_url, self.token) {
                (Some(u), Some(t)) => (u, t),
                (u, t) => {
                    let ep = discover_local().await?;
                    (u.unwrap_or(ep.base_url), t.unwrap_or(ep.token))
                }
            }
        };
```

and pass `self.daemonless` as a new trailing argument to `Client::from_parts(...)`.

- [ ] **Step 4: Thread `daemonless` through `from_parts` and `build_with_chat`.**

(a) `from_parts` (~506): add `daemonless: bool` as the last parameter. Gate the announce call (it would just log a warning against the sentinel, but skipping is cleaner):

```rust
        ) = if needs_chat {
            if !daemonless {
                announce_identity_best_effort(&http).await;
            }
            build_with_chat(
                &http,
                &base_url,
                token,
                relay_url,
                data_dir,
                passphrase,
                enable_lan_direct,
                contact_pubkey_lookup,
                x0xd_port_file,
                daemonless,
            )
            .await?
```

(b) `build_with_chat` (~2258): add `daemonless: bool` parameter (and extend the existing `#[allow(clippy::too_many_arguments, ...)]`). Restructure the head of the function — the probe, agent resolution, and signer become conditional; layout/master resolution moves ABOVE agent resolution (it has no daemon dependency):

```rust
    if !daemonless {
        // Gate on x0xd >= 0.20.1 (PQ `TreeKEM` minimum) ... (existing comment)
        enforce_m2_treekem_minimum(base_url, &token).await?;
    }

    let data_dir = match data_dir {
        Some(p) => p,
        None => crate::local_store::default_data_dir()?,
    };
    let layout = StoreLayout::ensure(data_dir)?;

    let identity_vault_path = layout.root.join(IDENTITY_VAULT_FILE);
    let (master, kdf_id, argon_salt) =
        resolve_master_key(identity_vault_path.as_path(), passphrase.as_deref())?;
    let master = Arc::new(master);

    // Resolve the local agent identity. Daemon path: x0xd `/agent` owns
    // the agent id + machine id. Daemonless path: both come from the
    // local signer vault — agent id is derived from the local ML-DSA-65
    // public key, so pair records and relay handshakes verify the same
    // way they do for an x0xd-backed agent.
    let (agent_id_hex, local_machine_id, local_signer): (String, [u8; 32], Option<Arc<dyn Signer>>) =
        if daemonless {
            let vault = crate::local_signer::LocalSignerVault::load_or_create(
                &layout.root,
                &master,
                kdf_id,
                argon_salt.as_ref(),
            )?;
            let agent_id_hex = hex::encode(vault.signer.agent_id());
            let machine = derive_machine_id(&vault.machine_token);
            (agent_id_hex, machine, Some(Arc::new(vault.signer)))
        } else {
            let agent_identity: identity::AgentIdentity = http.get_json("/agent").await?;
            let machine = derive_machine_id(&agent_identity.machine_id);
            (agent_identity.agent_id.0.clone(), machine, None)
        };
```

Then `FetchitIdentity::load_or_create` and `ConversationRegistry::new` stay exactly as they are (they already take `agent_id_hex` / `layout` / `master`). Replace the signer block (the `let x0xd_signer = Arc::new(if let Some(path) = x0xd_port_file { ... })` at ~2337-2349) with:

```rust
    let signer: Arc<dyn Signer> = match local_signer {
        Some(s) => s,
        None => Arc::new(if let Some(path) = x0xd_port_file {
            X0xdSigner::connect_with_port_file(path, token)
                .await
                .map_err(|e| ChatError::MessageTransport(format!("x0xd signer (port-file): {e}")))?
        } else {
            X0xdSigner::connect(
                Url::parse(base_url)
                    .map_err(|e| ChatError::Invalid(format!("x0xd base url: {e}")))?,
                token,
            )
            .await
            .map_err(|e| ChatError::MessageTransport(format!("x0xd signer: {e}")))?
        }),
    };
```

and change the one remaining concrete use, `RealRelayBuilder::new(x0xd_signer.clone())` (~2434), to `RealRelayBuilder::new(signer.clone())` — `RealRelayBuilder::new` already takes `Arc<dyn Signer>` (`multi_home.rs:250`). Keep the existing comment block about the shared signer, updating "x0xd_signer" wording to "signer".

(c) Add the accessor on `Client` (near `denylist_dropped_inbound_count`, ~626):

```rust
    /// The local agent id (lowercase 64-hex), when chat state is wired.
    /// Daemonless consumers (the Android FFI) read identity from here
    /// instead of x0xd's `/agent`.
    #[must_use]
    pub fn local_agent_id_hex(&self) -> Option<String> {
        self.chat
            .as_ref()
            .map(|c| c.identity.agent_id_hex().to_owned())
    }
```

(If `FetchitIdentity::agent_id_hex()` does not exist as a getter, it does — `default_dispatch_one` calls `identity.agent_id_hex()` at `client.rs:1375`.)

- [ ] **Step 5: Run the new test + the whole chat suite**

Run: `cargo test -p fetchit-chat daemonless_build_is_offline` → PASS, then `cargo test -p fetchit-chat 2>&1 | tail -5; echo EXIT:${PIPESTATUS[0]}` → `EXIT:0`.

- [ ] **Step 6: fmt + clippy + commit**

```bash
cargo fmt --all && cargo clippy -p fetchit-chat --all-targets -- -D warnings
git add crates/fetchit-chat/src/client.rs
git commit -s -m "feat(chat): daemonless builder profile — local signer, no x0xd discovery/probe"
```

---

### Task 3: FFI chat surface (`ChatClient` uniffi object)

**Files:**
- Create: `crates/fetchit-ffi/src/chat_error.rs`, `crates/fetchit-ffi/src/chat_ffi.rs`
- Modify: `crates/fetchit-ffi/src/lib.rs` (module wiring), `crates/fetchit-ffi/Cargo.toml`
- Test: `chat_ffi.rs` + `chat_error.rs` inline test modules

All commands in this task run from `crates/fetchit-ffi/` (workspace-excluded).

- [ ] **Step 1: Add dependencies** in `crates/fetchit-ffi/Cargo.toml` `[dependencies]` (versions must agree with the chat crate's tree so the lock unifies cleanly):

```toml
fetchit-chat = { path = "../fetchit-chat" }
url = "2"
hex = "0.4"
tokio = { version = "1", features = ["sync", "rt-multi-thread", "macros", "time"] }
```

- [ ] **Step 2: Write `chat_error.rs`:**

```rust
//! Coarse, stable error surface for the FFI chat client — mirrors the
//! shape of [`crate::error::FetchitError`]: few variants, a `reason`
//! string (named to avoid colliding with Kotlin's `Throwable.message`),
//! no nested causes.

/// Errors surfaced to Kotlin/Swift by the chat FFI.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ChatFfiError {
    /// Malformed input — bad URL, bad agent id, bad pair URI.
    #[error("invalid: {reason}")]
    Invalid {
        /// Human-readable cause.
        reason: String,
    },
    /// Relay or network failure (connect, publish, resolve, send).
    #[error("network: {reason}")]
    Network {
        /// Human-readable cause.
        reason: String,
    },
}

impl From<fetchit_chat::ChatError> for ChatFfiError {
    fn from(e: fetchit_chat::ChatError) -> Self {
        match e {
            fetchit_chat::ChatError::Invalid(reason) => Self::Invalid { reason },
            other => Self::Network {
                reason: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn invalid_maps_to_invalid_and_rest_to_network() {
        let inv: ChatFfiError = fetchit_chat::ChatError::Invalid("x".into()).into();
        assert!(matches!(inv, ChatFfiError::Invalid { .. }));
        let net: ChatFfiError =
            fetchit_chat::ChatError::MessageTransport("down".into()).into();
        assert!(matches!(net, ChatFfiError::Network { .. }));
    }
}
```

(If `ChatError` variants are not exhaustively matchable from outside the crate — `#[non_exhaustive]` — the `other =>` arm already covers it. If `ChatError::MessageTransport` is not pub-constructible in the test, swap the second assertion for any other pub variant; the mapping arm under test is the wildcard.)

- [ ] **Step 3: Write `chat_ffi.rs`:**

```rust
//! Chat surface for mobile shells: a daemonless
//! [`fetchit_chat::Client`] (local ML-DSA-65 signer, relay-only
//! transport) behind a uniffi object.
//!
//! Inbound flow: a background pump drains the relay transport's
//! envelope channel, decodes through
//! [`fetchit_chat::conversation::dispatch_inbound`] (mirroring
//! `fetchit-chat/src/bin/peer.rs::decode_inbound`, the canonical
//! headless consumer), sends best-effort delivery receipts, and queues
//! typed events; Kotlin awaits [`ChatClient::next_event`] in a
//! long-lived coroutine.

use std::sync::Arc;

use fetchit_chat::conversation::{dispatch_inbound, InboundDispatch};
use fetchit_chat::identity::AgentId;

use crate::chat_error::ChatFfiError;

/// One decoded inbound chat event.
#[derive(uniffi::Enum)]
pub enum ChatEventFfi {
    /// A direct message addressed to this agent.
    Dm {
        /// Sender agent id (lowercase 64-hex).
        from_agent_id_hex: String,
        /// Decrypted message body.
        body: String,
        /// Sender-assigned message id, when present.
        message_id: Option<String>,
    },
    /// A delivery receipt for a message this agent sent.
    Receipt {
        /// The message id the peer acknowledged.
        message_id: String,
    },
}

/// Daemonless chat client handle for the Android shell.
#[derive(uniffi::Object)]
pub struct ChatClient {
    inner: fetchit_chat::Client,
    relay_url: String,
    events: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<ChatEventFfi>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatClient {
    /// Build a daemonless client and connect its relay transport.
    ///
    /// `relay_url` is the home relay (e.g. `http://67.207.94.66:8088`),
    /// `data_dir` an app-private directory (Android:
    /// `context.filesDir/chat`), `passphrase` the vault passphrase the
    /// shell persists app-privately (Keystore wrapping is a follow-up).
    ///
    /// # Errors
    /// `Invalid` for a malformed URL; `Network` when the relay
    /// handshake or vault setup fails.
    #[uniffi::constructor]
    pub async fn connect(
        relay_url: String,
        data_dir: String,
        passphrase: String,
    ) -> Result<Arc<Self>, ChatFfiError> {
        let url = url::Url::parse(&relay_url).map_err(|e| ChatFfiError::Invalid {
            reason: format!("relay url: {e}"),
        })?;
        let inner = fetchit_chat::Client::builder()
            .daemonless(true)
            .relay_url(url)
            .data_dir(std::path::PathBuf::from(data_dir))
            .passphrase(passphrase)
            .build()
            .await?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        spawn_inbound_pump(inner.clone(), tx);
        Ok(Arc::new(Self {
            inner,
            relay_url,
            events: tokio::sync::Mutex::new(rx),
        }))
    }

    /// This agent's id (lowercase 64-hex). Empty only if chat state
    /// failed to wire, which `connect` already surfaces as an error.
    pub fn agent_id_hex(&self) -> String {
        self.inner.local_agent_id_hex().unwrap_or_default()
    }

    /// Publish the pair record to the home relay, then return the
    /// QR-sized `x0x://pair/...` pointer URI. Publish runs FIRST so a
    /// shared URI never 404s on import (mirrors the desktop
    /// `chat_pair_share_uri` command and `peer.rs run_pair_share`).
    ///
    /// # Errors
    /// `Network` when the publish fails; `Invalid` when URI assembly
    /// rejects the agent id or relay.
    pub async fn pair_share_uri(&self) -> Result<String, ChatFfiError> {
        self.inner.publish_pair_record().await?;
        let me = self.agent_id_hex();
        fetchit_chat::pair_uri::emit_pair_uri(&me, &[self.relay_url.clone()]).map_err(|e| {
            ChatFfiError::Invalid {
                reason: format!("emit pair uri: {e}"),
            }
        })
    }

    /// Import a contact from a pointer URI (`x0x://pair/...`):
    /// resolves the relay-hosted record, verifies the ML-DSA-65
    /// signature, persists the contact card.
    ///
    /// # Errors
    /// `Invalid` for a malformed URI; `Network` when every advertised
    /// relay is unreachable.
    pub async fn import_pair_uri(&self, uri: String) -> Result<(), ChatFfiError> {
        Ok(self.inner.import_pair_uri(uri.trim()).await?)
    }

    /// Send a DM. Returns the message id when the conversation layer
    /// assigned one.
    ///
    /// # Errors
    /// `Invalid` for a malformed agent id; `Network` for transport
    /// failures.
    pub async fn send_dm(
        &self,
        to_agent_id_hex: String,
        body: String,
        sender_name: String,
    ) -> Result<Option<String>, ChatFfiError> {
        let id = AgentId::parse(to_agent_id_hex).map_err(|e| ChatFfiError::Invalid {
            reason: e.to_string(),
        })?;
        Ok(self
            .inner
            .messages()
            .send(&id, &body, &sender_name, None, None)
            .await?)
    }

    /// Await the next inbound event. Resolves `None` when the pump has
    /// shut down (client dropped). Call from one long-lived coroutine.
    pub async fn next_event(&self) -> Option<ChatEventFfi> {
        self.events.lock().await.recv().await
    }
}

/// Drain relay inbound → decode → receipt → queue. Mirrors
/// `peer.rs::decode_inbound` minus the modes the MVP does not ship
/// (bridge events and PQ group frames are skipped silently — groups
/// are daemon-backed and out of the daemonless profile).
fn spawn_inbound_pump(
    client: fetchit_chat::Client,
    tx: tokio::sync::mpsc::UnboundedSender<ChatEventFfi>,
) {
    let Some(mut rx) = client.take_transport_inbound("relay") else {
        log::warn!("chat ffi: relay inbound unavailable; receive path disabled");
        return;
    };
    tokio::spawn(async move {
        while let Some(mut env) = rx.recv().await {
            let Some(transit) = env.transit.take() else {
                continue;
            };
            let (Some(identity), Some(registry)) =
                (client.identity_arc(), client.registry_arc())
            else {
                continue;
            };
            // Self-source filter: own sends round-trip over the relay.
            if hex::encode(transit.sender_agent_id.as_bytes()) == identity.agent_id_hex() {
                continue;
            }
            match dispatch_inbound(transit, identity.as_ref(), registry.as_ref()).await {
                Ok(InboundDispatch::Message {
                    group_id_hex,
                    sender_agent_id_hex,
                    payload,
                }) => {
                    if let Some(message_id) = payload.message_id.as_deref() {
                        let received_at_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                        if let Err(e) = client
                            .messages()
                            .send_receipt(
                                &group_id_hex,
                                message_id,
                                &sender_agent_id_hex,
                                received_at_ms,
                            )
                            .await
                        {
                            log::warn!("chat ffi: receipt send failed: {e}");
                        }
                    }
                    let _ = tx.send(ChatEventFfi::Dm {
                        from_agent_id_hex: sender_agent_id_hex,
                        body: payload.body,
                        message_id: payload.message_id,
                    });
                }
                Ok(InboundDispatch::Receipt { message_id, .. }) => {
                    let _ = tx.send(ChatEventFfi::Receipt { message_id });
                }
                Ok(_) => {}
                Err(e) => log::warn!("chat ffi: inbound dispatch dropped envelope: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// Live smoke against the production relay — run explicitly with
    /// `cargo test -p fetchit-ffi -- --ignored` on a networked box.
    #[tokio::test]
    #[ignore = "requires network + live relay"]
    async fn connect_against_prod_relay_round_trips_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let c = ChatClient::connect(
            "http://67.207.94.66:8088".to_owned(),
            dir.path().to_string_lossy().into_owned(),
            "smoke-pass".to_owned(),
        )
        .await
        .unwrap();
        assert_eq!(c.agent_id_hex().len(), 64);
        let uri = c.pair_share_uri().await.unwrap();
        assert!(uri.starts_with("x0x://pair/"));
    }
}
```

Adjustments the implementer owns: exact field names of `InboundDispatch::Message`/`Receipt` (verify against `crates/fetchit-chat/src/conversation.rs` — the shapes above are lifted from `peer.rs:761-795`), `AgentId::parse` error type, `messages().send` parameter order (verify against the desktop command at `apps/fetchit-desktop/src-tauri/src/chat.rs:779-804` — `(&id, &body, &name, reply_to: Option<&str>, attachment: Option<&Attachment>)`), and whether `tempfile` needs adding to `[dev-dependencies]`.

- [ ] **Step 4: Wire modules** in `crates/fetchit-ffi/src/lib.rs` (next to the existing `mod error;` etc.):

```rust
mod chat_error;
mod chat_ffi;
pub use chat_error::ChatFfiError;
pub use chat_ffi::{ChatClient, ChatEventFfi};
```

- [ ] **Step 5: Build + tests (from `crates/fetchit-ffi/`)**

Run: `cargo test` → expected: existing tests + `invalid_maps_to_invalid_and_rest_to_network` pass; the live smoke stays ignored.
Run: `cargo clippy --all-targets -- -D warnings` → clean.

- [ ] **Step 6: Live smoke (this box has network):**

Run: `cargo test -- --ignored 2>&1 | tail -5`
Expected: `connect_against_prod_relay_round_trips_identity ... ok` — proves daemonless connect, vault creation, pair-record publish, and URI emit end-to-end against the NYC relay.

- [ ] **Step 7: Commit**

```bash
git add crates/fetchit-ffi/src/chat_error.rs crates/fetchit-ffi/src/chat_ffi.rs crates/fetchit-ffi/src/lib.rs crates/fetchit-ffi/Cargo.toml crates/fetchit-ffi/Cargo.lock
git commit -s -m "feat(ffi): ChatClient — daemonless chat surface for the Android shell"
```

---

### Task 4: Cross-compile + Kotlin bindings regeneration

**Files:**
- Generated: `apps/fetchit-android/app/src/main/jniLibs/arm64-v8a/libfetchit_ffi.so`, `apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt`
- No script changes — `scripts/build-jni-libs.sh` already builds the crate and regenerates bindings together (the `.so` embeds uniffi checksums the Kotlin verifies at startup; NEVER regenerate one without the other).

- [ ] **Step 1: Verify toolchain**

Run: `export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.0.12077973 && cargo ndk --version && uniffi-bindgen --version`
Expected: cargo-ndk present; uniffi-bindgen 0.29.x matching the crate pin (`v0.29.4`/`0.29.5` — must equal the `uniffi` version in `crates/fetchit-ffi/Cargo.toml`).

- [ ] **Step 2: Run the pipeline**

Run: `./scripts/build-jni-libs.sh 2>&1 | tail -15`
Expected: `libfetchit_ffi.so` rebuilt (size will grow over the previous 24 MB — record the delta), `fetchit_ffi.kt` regenerated containing `class ChatClient` with `suspend fun` members.

- [ ] **Step 3: Sanity-check the bindings**

Run: `grep -c "ChatClient\|ChatEventFfi\|pairShareUri" apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt`
Expected: non-zero.

- [ ] **Step 4: Commit** (follow existing repo policy on whether the `.so` is tracked — `git status` will show; commit the `.kt` and whatever the repo already tracks):

```bash
git add apps/fetchit-android/app/src/main/java/uniffi/fetchit_ffi/fetchit_ffi.kt
git status --short apps/fetchit-android/app/src/main/jniLibs/ # add iff already tracked
git commit -s -m "feat(android): regenerate uniffi bindings with ChatClient surface"
```

---

### Task 5: Full gates + docs

- [ ] **Step 1: Workspace gates from the worktree root**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | tail -5; echo EXIT:${PIPESTATUS[0]}
```
Expected: all clean, `EXIT:0`.

- [ ] **Step 2: FFI gates from `crates/fetchit-ffi/`** (workspace-excluded):

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

- [ ] **Step 3: Document** — add to `REFERENCE.md`'s fetchit-chat section: a short paragraph on the daemonless profile (builder flag, LocalSignerVault, which surfaces work without x0xd, which don't), and to the fetchit-ffi section: the ChatClient object. Match the file's existing tone and density.

- [ ] **Step 4: Commit + push the branch**

```bash
git add REFERENCE.md
git commit -s -m "docs: daemonless chat profile + FFI ChatClient reference"
git push -u origin android-lit
```

---

## Out of scope for P0 (lands in P1/P2 plans)

- Kotlin UI (conversation list, thread, QR wiring), foreground service, idle-disconnect — P1.
- Groups (daemon-backed today; x0x-in-process is P2, pending the upstream `lib::serve(config)` ask).
- Honest typed `Unavailable` errors for daemon-only endpoints in daemonless mode (today: connection-refused against the sentinel — acceptable; FFI exposes none of them).
- Android Keystore-wrapped passphrase; message-history persistence; presence.
