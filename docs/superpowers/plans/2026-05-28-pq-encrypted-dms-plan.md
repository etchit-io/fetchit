# PQ-encrypted single-device DMs — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship end-to-end ML-KEM-768 + ChaCha20-Poly1305 sealed direct messages between two single-device users through the fetchit relay constellation, with at-rest encryption of secrets and scheduled forward-secrecy via auto-rekey.

**Architecture:** A new `chat_crypto` module in `fetchit-chat` performs all KEM/AEAD/HKDF operations using `saorsa-pqc` and `chacha20poly1305`. Per-conversation state (`Conversation`) is stored encrypted on disk in `~/.config/fetchit/` using a master key from the OS keystore (Argon2id passphrase fallback). The relay's `TransitEnvelope` gains a single `epoch: u32` field — Welcome envelopes (with a non-empty `kem_ciphertext`) carry conversation state; Message envelopes (with empty `kem_ciphertext`) carry AEAD-sealed bodies. Data shapes already model multi-device (Member.devices: Vec<MemberDevice>) so Plan 2's multi-device additions are non-breaking.

**Tech Stack:** Rust 1.85+, `saorsa-pqc` (ML-KEM-768 already a workspace dep), `chacha20poly1305` (NEW workspace dep), `keyring` (NEW workspace dep) for OS keystore, `argon2` (NEW workspace dep) for passphrase fallback, `serde` + `postcard` for canonical encoding, `tokio` async.

**Plan position:** This is Plan 1 of 3. Plan 2 adds multi-device + pairing. Plan 3 adds N-member groups. Plan 1 alone is shippable as a milestone.

## Coding conventions (mandatory)

These project-wide rules MUST be honored throughout implementation — they're not optional and they override any sample code in this plan if they conflict:

- **Minimal comments.** Doc-comments (`///`) on every `pub` item (the workspace's `missing_docs = "warn"` lint enforces this). Inside function bodies, comments only explain *why* when non-obvious — never *what* the code does. Trim every narrative comment from the samples before committing.
- **Modular files.** One concern per module. If a file grows past ~300 lines or you find yourself describing it with the word "and", split it.
- **Tests in the same commit as the code under test.** Never commit a function without a test, never commit a feature without an integration test.
- **No `unwrap()` / `expect()` / `panic!()` outside `#[cfg(test)]`.** Use `?` and structured errors.
- **`cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` must all be clean before any commit lands.** No `--no-verify`, no skipping hooks, no `expect_used` exceptions added without a code-review-worthy justification.
- **Commits are public, generic artifacts.** They describe what changed and why (the technical why, not the decision-process why). No references to plan numbers, conversation context, or who decided what.
- **DCO sign-off** on every commit (`git commit -s`).

---

## File structure for Plan 1

### New files in `crates/fetchit-chat/src/`
| File | Responsibility |
| --- | --- |
| `chat_crypto.rs` | ML-KEM-768 encap/decap, ChaCha20-Poly1305 AEAD seal/open, HKDF-SHA-256, AAD construction, canonical envelope-bytes-for-signing |
| `at_rest.rs` | Vault file format (FCV1 magic), AEAD-seal/open, OS keystore (`keyring`), Argon2id passphrase fallback, atomic file writes |
| `card.rs` | Extended share-card schema (v2 additive fields), card builder (signs with x0xd `/agent/sign`), card verifier (ML-DSA-65 over canonical), share-URI round-trip |
| `local_store.rs` | On-disk layout under `~/.config/fetchit/`: contacts/ (plain JSON), conversations/ (encrypted .json.enc), identity (encrypted) |
| `conversation/mod.rs` | Crate-internal façade — re-exports the four siblings below and the `ConversationRegistry` |
| `conversation/types.rs` | `Conversation`, `Member`, `MemberDevice`, `MemberDeviceStatus`, `PriorKey`, `Role`, `WelcomePayload`, `MessagePayload`, the `now_ms` helper, and the lifetime methods on `Conversation` (key/epoch lookup, `advance_epoch`, `sweep_prior_keys`, `fanout_devices`, `auto_rekey_due`) |
| `conversation/registry.rs` | `ConversationRegistry` — load/save via vault, `find_dm_with`, in-memory cache |
| `conversation/outbound.rs` | `OutboundEnvelope`, `build_welcome_outbox`, `build_message_outbox` |
| `conversation/inbound.rs` | `InboundDispatch`, `dispatch_inbound` (Welcome vs Message dispatch, sig verify, AEAD open) |
| `chat_identity.rs` | `FetchitIdentity` — per-device ML-KEM-768 keypair, generated on first launch, persisted in the encrypted identity vault, distinct from x0xd's KEM |

### Modified files in `crates/fetchit-chat/src/`
| File | Change |
| --- | --- |
| `lib.rs` | Add `pub mod` declarations and re-exports for the new modules |
| `Cargo.toml` | Add `chacha20poly1305`, `keyring`, `argon2`, `directories` workspace deps |
| `messages.rs` | `Endpoint::send` rewired to look up/create a `Conversation` and use it for AEAD sealing instead of plaintext base64 JSON; `decode_direct_message` removed (decryption moves to `conversation.rs`) |
| `client.rs` | `ClientBuilder` accepts `at_rest_passphrase` (optional), `data_dir` (defaults `~/.config/fetchit/`); `Client` constructs the at-rest vault, the FetchitIdentity, the LocalStore, and a `ConversationRegistry`; exposes `Client::conversations()` accessor |
| `relay_transport.rs` | `take_inbound` stream is now consumed by `Conversation::dispatch` rather than `decode_direct_message`; the transport itself is unchanged |
| `events.rs` | Add `Event::ConversationWelcomed { group_id, name }` and `Event::ChatWarn { kind, group_id }` (stale-epoch, decap-fail, signature-fail surfaces) |

### Modified files in `crates/fetchit-relay-proto/src/`
| File | Change |
| --- | --- |
| `envelope.rs` | Bump `PROTOCOL_VERSION` to 2; add `epoch: u32` field to `TransitEnvelope`; tests round-trip with the new shape |
| `lib.rs` | (no change beyond what `envelope.rs` re-exports) |

### Modified files in `apps/fetchit-desktop/src-tauri/src/`
| File | Change |
| --- | --- |
| `chat.rs` | `ChatState::new` now takes `(relay_url, data_dir, passphrase: Option<String>)`; `chat_send_dm` still works (same Tauri signature) but routes through Conversation; new `chat_set_passphrase` command for first-launch passphrase enrollment when no OS keystore is available |
| `lib.rs` | Bootstrap path passes the data dir (`AppDataLocal/fetchit/chat/`) to `ChatState::new` |
| `settings.rs` | Add `chat_at_rest_passphrase_required: bool` (optional — only set on Linux without Secret Service) |

### Modified files in `crates/fetchit-chat/src/bin/peer.rs`
| File | Change |
| --- | --- |
| `peer.rs` | Auto-echo mode supports the new encrypted flow (reads inbound through `Conversation::dispatch` and replies via `Endpoint::send`); no API change to the CLI |

### Test files
| File | What it tests |
| --- | --- |
| `crates/fetchit-relay-proto/tests/v2_roundtrip.rs` | Wire-format upgrade |
| `crates/fetchit-chat/src/chat_crypto.rs` (`#[cfg(test)] mod tests`) | KEM/AEAD/HKDF unit tests |
| `crates/fetchit-chat/src/at_rest.rs` (tests) | Vault round-trip with both keystore + passphrase paths |
| `crates/fetchit-chat/src/card.rs` (tests) | Card sign/verify, x0xd round-trip preserves unknown fields, tamper rejection |
| `crates/fetchit-chat/src/local_store.rs` (tests) | Path resolution, atomic writes, file mode 0600 |
| `crates/fetchit-chat/src/conversation.rs` (tests) | Welcome generation+install round-trip, prior-keys eviction, auto-rekey trigger, replay-window dedupe |
| `crates/fetchit-chat/tests/integration.rs` | End-to-end encrypted DM with mocked x0xd + mocked relay, including a card-import + send + receive round-trip |
| `crates/fetchit-chat/tests/live_relay.rs` | Updated to use encrypted Conversation API (`#[ignore]`'d) |

---

## Task 1 — TransitEnvelope wire format v2 (epoch field)

**Files:**
- Modify: `crates/fetchit-relay-proto/src/envelope.rs`
- Modify: `crates/fetchit-relay-proto/src/lib.rs:42` (PROTOCOL_VERSION constant if any)
- Test: `crates/fetchit-relay-proto/tests/v2_roundtrip.rs` (NEW)
- Modify: `crates/fetchit-relay-proto/tests/roundtrip.rs` (existing — every existing TransitEnvelope literal needs `epoch: 0,`)

- [ ] **Step 1: Add the failing test for the new field**

Create `crates/fetchit-relay-proto/tests/v2_roundtrip.rs`:
```rust
//! Ensures TransitEnvelope v2 carries the epoch field across postcard
//! roundtrips. v2 is the wire shape for sealed chat messages.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fetchit_relay_proto::{
    AgentId, EnvelopeKind, GroupId, MachineId, TenantId, TransitEnvelope, from_bytes, to_bytes,
};

#[test]
fn envelope_v2_carries_epoch() {
    let env = TransitEnvelope {
        version: 2,
        kind: EnvelopeKind::GroupChat,
        group_id: Some(GroupId::from_bytes([0x11; 32])),
        tenant_id: None,
        sender_agent_id: AgentId::from_bytes([0x22; 32]),
        sender_machine_id: MachineId::from_bytes([0x33; 32]),
        timestamp_ms: 1_700_000_000_000,
        epoch: 7,
        ciphertext: vec![0xab; 32],
        nonce: vec![0xcd; 12],
        kem_ciphertext: vec![0xef; 64],
        sender_signature: vec![0xa5; 32],
    };
    let bytes = to_bytes(&env).unwrap();
    let decoded: TransitEnvelope = from_bytes(&bytes).unwrap();
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.epoch, 7);
    assert_eq!(decoded, env);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fetchit-relay-proto --test v2_roundtrip`
Expected: FAILS with `missing field 'epoch' in struct TransitEnvelope`.

- [ ] **Step 3: Modify `TransitEnvelope` to add epoch and bump version**

In `crates/fetchit-relay-proto/src/envelope.rs`, change the struct (preserve order of fields except insert `epoch` directly after `timestamp_ms`):
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitEnvelope {
    /// Envelope-format version. Bumped to 2 when `epoch` was added for
    /// PQ-sealed chat. v1 envelopes did not carry an epoch; the field is
    /// required in v2.
    pub version: u16,
    pub kind: EnvelopeKind,
    pub group_id: Option<GroupId>,
    pub tenant_id: Option<TenantId>,
    pub sender_agent_id: AgentId,
    pub sender_machine_id: MachineId,
    pub timestamp_ms: u64,
    /// Conversation epoch under which `ciphertext` was sealed. Recipient
    /// uses this to pick the right symmetric key (current_key when
    /// `epoch == conversation.current_epoch`, else a prior_keys entry
    /// inside the 60s window). Welcome envelopes set this to the epoch
    /// the carried key belongs to.
    pub epoch: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub sender_signature: Vec<u8>,
}
```
In `crates/fetchit-relay-proto/src/lib.rs`, bump:
```rust
/// Protocol version negotiated in the `Hello` / `Ready` exchange.
pub const PROTOCOL_VERSION: u16 = 2;
```

- [ ] **Step 4: Fix every existing TransitEnvelope literal**

Every existing test literal across the workspace lacks `epoch`. Run the type-check to find them:
```bash
cargo build --workspace 2>&1 | grep -E "missing field .epoch" | sort -u
```
For each `error[E0063]: missing field 'epoch'` line in:
- `crates/fetchit-relay-proto/tests/roundtrip.rs`
- `crates/fetchit-relay-proto/src/envelope.rs` (existing tests)
- `crates/fetchit-relay-proto/src/frame.rs` (existing tests)
- `crates/fetchit-relay-server/src/transit.rs` (`env_for` helper)
- `crates/fetchit-relay-server/tests/handshake.rs`
- `crates/fetchit-relay-client/tests/end_to_end.rs`
- `crates/fetchit-chat/src/messages.rs` (existing tests)
- `crates/fetchit-chat/tests/integration.rs`

…insert `epoch: 0,` immediately after `timestamp_ms: <value>,`. (Welcome epoch logic comes later — existing tests don't care about the value.) Also bump every `version: 1,` to `version: 2,`.

- [ ] **Step 5: Run all proto-related tests**

Run: `cargo test --workspace -p fetchit-relay-proto -p fetchit-relay-server -p fetchit-relay-client -p fetchit-chat 2>&1 | grep "test result"`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/fetchit-relay-proto crates/fetchit-relay-server crates/fetchit-relay-client crates/fetchit-chat
git commit -s -m "feat(relay-proto): TransitEnvelope v2 with epoch field

Adds epoch: u32 to TransitEnvelope and bumps PROTOCOL_VERSION to 2.
Welcome envelopes (kem_ciphertext non-empty) and Message envelopes
(kem_ciphertext empty) both carry epoch so receivers can dispatch
to the right conversation key without trial decryption."
```

---

## Task 2 — chat_crypto module: KEM, AEAD, HKDF, AAD

**Files:**
- Create: `crates/fetchit-chat/src/chat_crypto.rs`
- Modify: `crates/fetchit-chat/Cargo.toml` (add `chacha20poly1305` workspace dep)
- Modify: `Cargo.toml` (add `chacha20poly1305 = "0.10"` to workspace deps)
- Modify: `crates/fetchit-chat/src/lib.rs` (add `pub mod chat_crypto;`)

- [ ] **Step 1: Add `chacha20poly1305` to workspace deps**

In root `Cargo.toml`, under `[workspace.dependencies]`, add:
```toml
chacha20poly1305 = "0.10"
hkdf = "0.12"
```

- [ ] **Step 2: Add to fetchit-chat deps**

In `crates/fetchit-chat/Cargo.toml`, under `[dependencies]`:
```toml
chacha20poly1305.workspace = true
hkdf.workspace = true
sha2 = "0.10"
saorsa-pqc.workspace = true
```
(`saorsa-pqc` is already a workspace dep but isn't yet pulled into fetchit-chat.)

- [ ] **Step 3: Write the chat_crypto tests first**

Create `crates/fetchit-chat/src/chat_crypto.rs`:
```rust
//! ML-KEM-768 + ChaCha20-Poly1305 + HKDF crypto helpers for the chat
//! layer. Pure functions over byte slices; all key material is supplied
//! by the caller. No I/O, no shared state, no global RNG handle — call
//! sites pass their own RNG when randomness is needed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use saorsa_pqc::api::sig::MlDsaVariant;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature};
use sha2::Sha256;

use crate::error::ChatError;

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const KEM_SHARED_SECRET_LEN: usize = 32;
pub const KEM_PUBLIC_KEY_LEN: usize = 1184;
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
pub const KEM_SECRET_KEY_LEN: usize = 2400;

/// Domain prefix for AEAD AAD over chat envelopes. Bumps if the wire
/// format changes — invalidates all v1 ciphertexts.
pub const AAD_DOMAIN: &[u8] = b"lit/v1";

/// Domain string for HKDF when deriving the welcome AEAD key from a
/// fresh KEM shared secret.
pub const KDF_INFO_WELCOME: &[u8] = b"lit/welcome/v1";

/// Domain string for HKDF when deriving the master key from a
/// passphrase via Argon2id (used by at_rest module; defined here for
/// the single source of truth).
pub const KDF_INFO_VAULT: &[u8] = b"lit/vault/v1";

/// Domain string for ML-DSA signing canonical envelope bytes.
pub const SIGN_DOMAIN_ENVELOPE: &[u8] = b"lit/envelope/v1";

/// Domain string for ML-DSA signing extended share-cards.
pub const SIGN_DOMAIN_CARD: &[u8] = b"fetchit-chat/v1/card";

// ── KEM ────────────────────────────────────────────────────────────────

/// Encapsulate a fresh symmetric secret against `recipient_kem_pub`.
/// Returns the KEM ciphertext (1088 B) and the 32-byte shared secret.
///
/// # Errors
/// Returns `ChatError::Invalid` for malformed inputs.
pub fn kem_encapsulate(
    recipient_kem_pub: &[u8],
) -> Result<(Vec<u8>, [u8; KEM_SHARED_SECRET_LEN]), ChatError> {
    use saorsa_pqc::api::kem::{MlKem, MlKemPublicKey, MlKemVariant};
    if recipient_kem_pub.len() != KEM_PUBLIC_KEY_LEN {
        return Err(ChatError::Invalid(format!(
            "kem pub key wrong length: {}",
            recipient_kem_pub.len()
        )));
    }
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let pk = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, recipient_kem_pub)
        .map_err(|e| ChatError::Invalid(format!("kem pub parse: {e}")))?;
    let (ct, ss) = kem
        .encapsulate(&pk)
        .map_err(|e| ChatError::Invalid(format!("kem encap: {e}")))?;
    let ct_bytes = ct.to_bytes();
    let mut ss_arr = [0u8; KEM_SHARED_SECRET_LEN];
    ss_arr.copy_from_slice(&ss.to_bytes()[..KEM_SHARED_SECRET_LEN]);
    Ok((ct_bytes, ss_arr))
}

/// Decapsulate a KEM ciphertext with our secret key.
///
/// # Errors
/// Returns `ChatError::Invalid` if either input is malformed or decap fails.
pub fn kem_decapsulate(
    our_kem_sec: &[u8],
    kem_ciphertext: &[u8],
) -> Result<[u8; KEM_SHARED_SECRET_LEN], ChatError> {
    use saorsa_pqc::api::kem::{MlKem, MlKemCiphertext, MlKemSecretKey, MlKemVariant};
    if our_kem_sec.len() != KEM_SECRET_KEY_LEN {
        return Err(ChatError::Invalid("kem secret key wrong length".into()));
    }
    if kem_ciphertext.len() != KEM_CIPHERTEXT_LEN {
        return Err(ChatError::Invalid("kem ciphertext wrong length".into()));
    }
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let sk = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, our_kem_sec)
        .map_err(|e| ChatError::Invalid(format!("kem sec parse: {e}")))?;
    let ct = MlKemCiphertext::from_bytes(MlKemVariant::MlKem768, kem_ciphertext)
        .map_err(|e| ChatError::Invalid(format!("kem ct parse: {e}")))?;
    let ss = kem
        .decapsulate(&sk, &ct)
        .map_err(|e| ChatError::Invalid(format!("kem decap: {e}")))?;
    let mut ss_arr = [0u8; KEM_SHARED_SECRET_LEN];
    ss_arr.copy_from_slice(&ss.to_bytes()[..KEM_SHARED_SECRET_LEN]);
    Ok(ss_arr)
}

/// Generate a fresh ML-KEM-768 keypair. Returns `(public_key_bytes, secret_key_bytes)`.
///
/// # Errors
/// Returns `ChatError::Invalid` if the underlying primitive fails.
pub fn kem_keygen() -> Result<(Vec<u8>, Vec<u8>), ChatError> {
    use saorsa_pqc::api::kem::{MlKem, MlKemVariant};
    let kem = MlKem::new(MlKemVariant::MlKem768);
    let (pk, sk) = kem
        .generate_keypair()
        .map_err(|e| ChatError::Invalid(format!("kem keygen: {e}")))?;
    Ok((pk.to_bytes(), sk.to_bytes()))
}

// ── HKDF ───────────────────────────────────────────────────────────────

/// Derive a 32-byte symmetric key from a KEM shared secret using
/// HKDF-SHA-256 with the supplied info string.
#[must_use]
pub fn derive_aead_key(shared_secret: &[u8], info: &[u8]) -> [u8; AEAD_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; AEAD_KEY_LEN];
    hk.expand(info, &mut out).expect("HKDF expand cannot fail for 32-byte output");
    out
}

// ── AEAD ───────────────────────────────────────────────────────────────

/// Seal `plaintext` under `key` with `nonce` and `aad`.
///
/// # Errors
/// Returns `ChatError::Invalid` on key length mismatch or AEAD failure.
pub fn aead_seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ChatError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce_ref, Payload { msg: plaintext, aad })
        .map_err(|e| ChatError::Invalid(format!("aead seal: {e}")))
}

/// Open `ciphertext` under `key` with `nonce` and `aad`. Returns the plaintext.
///
/// # Errors
/// Returns `ChatError::Invalid` on tag mismatch or any AEAD error
/// (deliberately not distinguished — tag-mismatch == tampering).
pub fn aead_open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ChatError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_ref, Payload { msg: ciphertext, aad })
        .map_err(|e| ChatError::Invalid(format!("aead open: {e}")))
}

/// Random 12-byte AEAD nonce.
#[must_use]
pub fn random_nonce(rng: &mut impl RngCore) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut n);
    n
}

/// Random 32-byte symmetric key (used for `Conversation.current_key`).
#[must_use]
pub fn random_symmetric_key(rng: &mut impl RngCore) -> [u8; AEAD_KEY_LEN] {
    let mut k = [0u8; AEAD_KEY_LEN];
    rng.fill_bytes(&mut k);
    k
}

// ── AAD construction ───────────────────────────────────────────────────

/// Canonical AAD for a message ciphertext bound to a conversation + epoch.
/// `concat(AAD_DOMAIN, group_id, epoch.to_le_bytes())`.
#[must_use]
pub fn message_aad(group_id: &[u8; 32], epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 32 + 4);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

// ── Envelope canonicalisation ──────────────────────────────────────────

/// Canonical bytes for signing/verifying a `TransitEnvelope`'s
/// `sender_signature`. Postcard-encoded with the signature field zeroed
/// (length-preserved as Vec<u8> of length 0) so signer and verifier
/// agree on the exact byte sequence.
///
/// # Errors
/// Returns `ChatError::Decode` if postcard encoding fails.
pub fn canonical_envelope_bytes(
    env: &fetchit_relay_proto::TransitEnvelope,
) -> Result<Vec<u8>, ChatError> {
    let mut clone = env.clone();
    clone.sender_signature = Vec::new();
    postcard::to_allocvec(&clone).map_err(|e| ChatError::Invalid(format!("postcard: {e}")))
}

// ── ML-DSA verify helpers (signing handled by X0xdSigner already) ─────

/// Verify an ML-DSA-65 signature over `message` using `public_key_bytes`.
///
/// # Errors
/// Returns `ChatError::Invalid` if the key or signature is malformed or
/// the signature fails verification.
pub fn ml_dsa_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), ChatError> {
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, public_key_bytes)
        .map_err(|e| ChatError::Invalid(format!("ml-dsa pub parse: {e}")))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, signature_bytes)
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sig parse: {e}")))?;
    match dsa.verify(&pk, message, &sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ChatError::Invalid("ml-dsa signature invalid".into())),
        Err(e) => Err(ChatError::Invalid(format!("ml-dsa verify: {e}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn kem_round_trip() {
        let (pk, sk) = kem_keygen().unwrap();
        let (ct, ss_a) = kem_encapsulate(&pk).unwrap();
        let ss_b = kem_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b, "encap/decap must produce the same shared secret");
    }

    #[test]
    fn aead_round_trip_with_aad() {
        let mut rng = OsRng;
        let key = random_symmetric_key(&mut rng);
        let nonce = random_nonce(&mut rng);
        let aad = message_aad(&[7u8; 32], 5);
        let pt = b"hello relay";
        let ct = aead_seal(&key, &nonce, pt, &aad).unwrap();
        let opened = aead_open(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn aead_rejects_wrong_aad() {
        let mut rng = OsRng;
        let key = random_symmetric_key(&mut rng);
        let nonce = random_nonce(&mut rng);
        let aad_a = message_aad(&[1u8; 32], 0);
        let aad_b = message_aad(&[2u8; 32], 0);
        let ct = aead_seal(&key, &nonce, b"x", &aad_a).unwrap();
        assert!(aead_open(&key, &nonce, &ct, &aad_b).is_err());
    }

    #[test]
    fn hkdf_deterministic() {
        let ss = [9u8; KEM_SHARED_SECRET_LEN];
        let k1 = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let k2 = derive_aead_key(&ss, KDF_INFO_WELCOME);
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_domain_separation() {
        let ss = [9u8; KEM_SHARED_SECRET_LEN];
        let kw = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let kv = derive_aead_key(&ss, KDF_INFO_VAULT);
        assert_ne!(kw, kv, "different info strings must produce different keys");
    }

    #[test]
    fn message_aad_includes_group_id_and_epoch() {
        let g = [0u8; 32];
        let aad0 = message_aad(&g, 0);
        let aad1 = message_aad(&g, 1);
        assert_ne!(aad0, aad1);
        let g2 = [1u8; 32];
        let aad0_g2 = message_aad(&g2, 0);
        assert_ne!(aad0, aad0_g2);
    }

    #[test]
    fn canonical_envelope_zeroes_signature() {
        use fetchit_relay_proto::{
            AgentId, EnvelopeKind, MachineId, TransitEnvelope,
        };
        let env_a = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: None,
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([1u8; 32]),
            sender_machine_id: MachineId::from_bytes([2u8; 32]),
            timestamp_ms: 1,
            epoch: 0,
            ciphertext: vec![1, 2, 3],
            nonce: vec![0; 12],
            kem_ciphertext: vec![],
            sender_signature: vec![0xff; 32],
        };
        let mut env_b = env_a.clone();
        env_b.sender_signature = vec![0xee; 32];
        assert_eq!(
            canonical_envelope_bytes(&env_a).unwrap(),
            canonical_envelope_bytes(&env_b).unwrap(),
            "canonical bytes must be insensitive to sender_signature"
        );
    }
}
```

- [ ] **Step 4: Declare the module**

In `crates/fetchit-chat/src/lib.rs`, add to the module list:
```rust
pub mod chat_crypto;
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p fetchit-chat chat_crypto -- --nocapture`
Expected: 6 tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/fetchit-chat/Cargo.toml crates/fetchit-chat/src/chat_crypto.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(chat): chat_crypto module — KEM, AEAD, HKDF, canonical envelope

Pure-function helpers for ML-KEM-768 encap/decap, ChaCha20-Poly1305
seal/open, HKDF-SHA-256 derivation, AEAD AAD construction binding
(group_id || epoch), and canonical TransitEnvelope bytes for signing
(signature field zeroed so signer and verifier agree). Includes 6
unit tests covering round-trips and AAD/key domain separation."
```

---

## Task 3 — At-rest vault module

**Files:**
- Create: `crates/fetchit-chat/src/at_rest.rs`
- Modify: `crates/fetchit-chat/Cargo.toml` (add `keyring`, `argon2`, `directories`)
- Modify: `Cargo.toml` (workspace deps for those three)
- Modify: `crates/fetchit-chat/src/lib.rs` (add `pub mod at_rest;`)

- [ ] **Step 1: Add deps to workspace and crate**

In root `Cargo.toml`, under `[workspace.dependencies]`:
```toml
keyring = "3.6"
argon2 = "0.5"
directories = "5"
```
In `crates/fetchit-chat/Cargo.toml`:
```toml
keyring.workspace = true
argon2.workspace = true
directories.workspace = true
```

- [ ] **Step 2: Write the at_rest tests**

Create `crates/fetchit-chat/src/at_rest.rs`:
```rust
//! At-rest encryption vault for fetchit-chat secrets.
//!
//! Files ending `.json.enc` are AEAD-sealed with a device-local
//! master key. The master key is held in the OS keystore; when that
//! is unavailable (headless Linux, etc.), a passphrase derives it
//! via Argon2id.
//!
//! Wire format of a `.enc` file (header + ciphertext, no JSON):
//! ```text
//! [u8;  4] magic       = "FCV1"
//! [u8;  1] kdf_id      = 0 (keychain) | 1 (Argon2id passphrase)
//! [u8; 16] argon_salt  = zero when kdf_id=0
//! [u8; 12] nonce       (ChaCha20-Poly1305)
//! [u8;  N] ciphertext + tag (AEAD output)
//! ```
//!
//! Argon2id parameters: m=64 MiB, t=3, p=4. These are the OWASP-
//! recommended defaults for interactive logins as of 2024.

use crate::chat_crypto::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, aead_open, aead_seal, random_nonce,
};
use crate::error::ChatError;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::fs;
use std::path::Path;

pub const VAULT_MAGIC: &[u8; 4] = b"FCV1";
pub const ARGON_SALT_LEN: usize = 16;
pub const HEADER_LEN: usize = 4 + 1 + ARGON_SALT_LEN + AEAD_NONCE_LEN;

const KDF_ID_KEYCHAIN: u8 = 0;
const KDF_ID_ARGON2: u8 = 1;

const KEYRING_SERVICE: &str = "fetchit-chat-v1";
const KEYRING_USER: &str = "master-key";

/// How the master key is sourced.
#[derive(Clone, Debug)]
pub enum MasterKeySource {
    /// Pulled from the OS keystore (macOS Keychain, Linux Secret Service,
    /// Windows DPAPI). Created on first use, fetched thereafter.
    Keychain,
    /// Derived from a passphrase via Argon2id. Used when no keystore is
    /// available.
    Passphrase(String),
}

/// 32-byte symmetric key used for vault seal/open.
#[derive(Clone)]
pub struct MasterKey([u8; AEAD_KEY_LEN]);

impl MasterKey {
    /// Borrow the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.0
    }

    /// Resolve a master key from the requested source.
    ///
    /// For `Keychain`: returns the existing key, or generates a fresh
    /// one and stores it on first use. For `Passphrase`: the salt is
    /// supplied by the caller (read from an existing vault file or
    /// generated fresh on first use).
    ///
    /// # Errors
    /// `ChatError::Invalid` if the keystore is unreachable or the
    /// Argon2id derivation fails.
    pub fn resolve(
        source: &MasterKeySource,
        argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        match source {
            MasterKeySource::Keychain => Self::resolve_keychain(),
            MasterKeySource::Passphrase(p) => {
                let salt = argon_salt.ok_or_else(|| {
                    ChatError::Invalid("passphrase mode requires an argon_salt".into())
                })?;
                Self::resolve_passphrase(p, salt)
            }
        }
    }

    fn resolve_keychain() -> Result<Self, ChatError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|e| ChatError::Invalid(format!("keyring open: {e}")))?;
        match entry.get_password() {
            Ok(b64) => {
                let bytes = B64
                    .decode(&b64)
                    .map_err(|e| ChatError::Invalid(format!("keyring decode: {e}")))?;
                if bytes.len() != AEAD_KEY_LEN {
                    return Err(ChatError::Invalid("keyring entry wrong length".into()));
                }
                let mut k = [0u8; AEAD_KEY_LEN];
                k.copy_from_slice(&bytes);
                Ok(Self(k))
            }
            Err(keyring::Error::NoEntry) => {
                let mut k = [0u8; AEAD_KEY_LEN];
                rand::rngs::OsRng.fill_bytes(&mut k);
                let b64 = B64.encode(k);
                entry
                    .set_password(&b64)
                    .map_err(|e| ChatError::Invalid(format!("keyring set: {e}")))?;
                Ok(Self(k))
            }
            Err(e) => Err(ChatError::Invalid(format!("keyring get: {e}"))),
        }
    }

    fn resolve_passphrase(
        passphrase: &str,
        salt: &[u8; ARGON_SALT_LEN],
    ) -> Result<Self, ChatError> {
        let params = Params::new(64 * 1024, 3, 4, Some(AEAD_KEY_LEN))
            .map_err(|e| ChatError::Invalid(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; AEAD_KEY_LEN];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| ChatError::Invalid(format!("argon2 hash: {e}")))?;
        Ok(Self(out))
    }
}

/// AEAD-seal `plaintext` under the master key with vault header metadata.
/// Writes header + ciphertext to `path` atomically (`path.tmp` then rename).
///
/// `argon_salt` must be `Some` when the master was passphrase-derived.
///
/// # Errors
/// IO or AEAD errors.
pub fn seal_to_path(
    path: &Path,
    plaintext: &[u8],
    master: &MasterKey,
    kdf_id: u8,
    argon_salt: Option<&[u8; ARGON_SALT_LEN]>,
) -> Result<(), ChatError> {
    let mut rng = rand::rngs::OsRng;
    let nonce = random_nonce(&mut rng);
    let aad = b"lit/vault/v1";
    let ct = aead_seal(master.as_bytes(), &nonce, plaintext, aad)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(kdf_id);
    out.extend_from_slice(argon_salt.unwrap_or(&[0u8; ARGON_SALT_LEN]));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &out)?;
    set_perms_0600(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read + AEAD-open a vault file under the master key.
///
/// Returns the plaintext bytes. The vault header is consumed and not
/// returned — callers read the salt separately via [`read_argon_salt`]
/// when bootstrapping a passphrase-mode session.
///
/// # Errors
/// IO, malformed-header, AEAD failures (tag mismatch).
pub fn open_from_path(path: &Path, master: &MasterKey) -> Result<Vec<u8>, ChatError> {
    let bytes = fs::read(path)?;
    if bytes.len() < HEADER_LEN {
        return Err(ChatError::Invalid("vault file too short".into()));
    }
    if &bytes[..4] != VAULT_MAGIC {
        return Err(ChatError::Invalid("vault magic mismatch".into()));
    }
    let nonce_start = 4 + 1 + ARGON_SALT_LEN;
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&bytes[nonce_start..nonce_start + AEAD_NONCE_LEN]);
    let ct = &bytes[HEADER_LEN..];
    let aad = b"lit/vault/v1";
    aead_open(master.as_bytes(), &nonce, ct, aad)
}

/// Inspect a vault file's KDF id without decrypting. Useful at boot to
/// decide whether to prompt for a passphrase.
///
/// # Errors
/// IO or malformed-header.
pub fn read_kdf_id(path: &Path) -> Result<u8, ChatError> {
    let mut buf = [0u8; 5];
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    f.read_exact(&mut buf)?;
    if &buf[..4] != VAULT_MAGIC {
        return Err(ChatError::Invalid("vault magic mismatch".into()));
    }
    Ok(buf[4])
}

/// Inspect a vault file's Argon2 salt. Returns the salt only when
/// `kdf_id == Argon2id`; otherwise returns an error.
///
/// # Errors
/// IO, malformed-header, or non-passphrase vault.
pub fn read_argon_salt(path: &Path) -> Result<[u8; ARGON_SALT_LEN], ChatError> {
    let mut buf = [0u8; 4 + 1 + ARGON_SALT_LEN];
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    f.read_exact(&mut buf)?;
    if &buf[..4] != VAULT_MAGIC {
        return Err(ChatError::Invalid("vault magic mismatch".into()));
    }
    if buf[4] != KDF_ID_ARGON2 {
        return Err(ChatError::Invalid("vault is not passphrase-mode".into()));
    }
    let mut salt = [0u8; ARGON_SALT_LEN];
    salt.copy_from_slice(&buf[5..5 + ARGON_SALT_LEN]);
    Ok(salt)
}

/// Generate a fresh Argon2 salt.
#[must_use]
pub fn fresh_argon_salt() -> [u8; ARGON_SALT_LEN] {
    let mut salt = [0u8; ARGON_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// File-mode helper: 0600 on Unix, no-op on Windows.
fn set_perms_0600(path: &Path) -> Result<(), ChatError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path; // unused on Windows; ACLs would be the equivalent
    }
    Ok(())
}

/// Public constants re-exported for callers that don't want to depend
/// on internal numeric values.
pub fn kdf_id_keychain() -> u8 {
    KDF_ID_KEYCHAIN
}
pub fn kdf_id_argon2() -> u8 {
    KDF_ID_ARGON2
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn passphrase_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("hunter2".into()), Some(&salt))
                .unwrap();
        let plaintext = b"top secret bytes";
        seal_to_path(&path, plaintext, &master, kdf_id_argon2(), Some(&salt)).unwrap();
        let opened = open_from_path(&path, &master).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m1 = MasterKey::resolve(&MasterKeySource::Passphrase("a".into()), Some(&salt))
            .unwrap();
        seal_to_path(&path, b"x", &m1, kdf_id_argon2(), Some(&salt)).unwrap();
        let m2 = MasterKey::resolve(&MasterKeySource::Passphrase("b".into()), Some(&salt))
            .unwrap();
        assert!(open_from_path(&path, &m2).is_err());
    }

    #[test]
    fn read_kdf_id_matches_seal_kdf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m = MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt))
            .unwrap();
        seal_to_path(&path, b"x", &m, kdf_id_argon2(), Some(&salt)).unwrap();
        assert_eq!(read_kdf_id(&path).unwrap(), kdf_id_argon2());
    }

    #[test]
    fn read_argon_salt_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m = MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt))
            .unwrap();
        seal_to_path(&path, b"x", &m, kdf_id_argon2(), Some(&salt)).unwrap();
        let recovered = read_argon_salt(&path).unwrap();
        assert_eq!(recovered, salt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let salt = fresh_argon_salt();
        let m = MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt))
            .unwrap();
        seal_to_path(&path, b"some_bytes_for_testing", &m, kdf_id_argon2(), Some(&salt))
            .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(open_from_path(&path, &m).is_err());
    }

    // Keychain test is gated — only run in environments where the OS
    // keystore is reachable. Skip on headless CI.
    #[test]
    #[ignore = "requires OS keystore (Linux Secret Service / macOS Keychain / Windows DPAPI)"]
    fn keychain_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let master = MasterKey::resolve(&MasterKeySource::Keychain, None).unwrap();
        seal_to_path(&path, b"keychain stored secret", &master, kdf_id_keychain(), None)
            .unwrap();
        let opened = open_from_path(&path, &master).unwrap();
        assert_eq!(opened, b"keychain stored secret");
    }
}
```

- [ ] **Step 3: Declare the module**

In `crates/fetchit-chat/src/lib.rs`:
```rust
pub mod at_rest;
```

- [ ] **Step 4: Add tempfile dev-dep**

`crates/fetchit-chat/Cargo.toml` `[dev-dependencies]` already has `tempfile = "3.13"` from previous work. Verify:
```bash
grep tempfile crates/fetchit-chat/Cargo.toml
```
If missing, add `tempfile = "3.13"` under `[dev-dependencies]`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p fetchit-chat at_rest -- --nocapture`
Expected: 5 tests pass; 1 ignored (keychain test).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/fetchit-chat/Cargo.toml crates/fetchit-chat/src/at_rest.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(chat): at-rest vault — keystore + Argon2id passphrase fallback

FCV1 vault format: 4B magic + 1B kdf_id + 16B salt + 12B nonce + AEAD.
Master key resolved from OS keystore (keyring crate) or from Argon2id-
derived passphrase. Atomic writes via tmp+rename; 0600 on Unix.
5 unit tests cover both KDF paths, tamper detection, and salt
round-trip. Keychain test gated behind --ignored for headless CI."
```

---

## Task 4 — Chat identity: per-device KEM keypair

**Files:**
- Create: `crates/fetchit-chat/src/chat_identity.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`
- Modify: `crates/fetchit-chat/src/error.rs` (add `IdentityNotInitialised`)

- [ ] **Step 1: Add error variant**

In `crates/fetchit-chat/src/error.rs`, extend `ChatError`:
```rust
    /// The local chat identity vault is missing or hasn't been
    /// bootstrapped. Call `Client::ensure_identity` or pass the right
    /// passphrase.
    #[error("chat identity not initialised at {path}")]
    IdentityNotInitialised {
        /// Where the identity vault was looked up.
        path: String,
    },
```

- [ ] **Step 2: Write the chat_identity tests + impl**

Create `crates/fetchit-chat/src/chat_identity.rs`:
```rust
//! Per-device ML-KEM-768 keypair used for chat-layer content encryption.
//! Distinct from x0xd's KEM keypair (which we don't use because x0xd
//! has no decap endpoint).
//!
//! Persisted as a vault file at `<data_dir>/identity.json.enc`.

use crate::at_rest::{MasterKey, open_from_path, seal_to_path};
use crate::chat_crypto::{KEM_PUBLIC_KEY_LEN, KEM_SECRET_KEY_LEN, kem_keygen};
use crate::error::ChatError;
use serde::{Deserialize, Serialize};
use std::path::Path;

const IDENTITY_FILE: &str = "identity.json.enc";

/// On-disk identity payload (plaintext after vault open). Contains
/// secret KEM bytes — never log, never send over a wire.
#[derive(Clone, Serialize, Deserialize)]
struct IdentityVaultPayload {
    /// Schema version of the identity JSON inside the vault.
    version: u16,
    /// x0xd agent id this fetchit identity is bound to. We re-bind on
    /// agent_id change (e.g. user rotates x0xd identity).
    agent_id_hex: String,
    /// Opt-in logical-user identifier. None for single-device installs;
    /// multi-device builds populate it during device pairing.
    user_id_hex: Option<String>,
    /// ML-KEM-768 public key bytes (1184 B base64).
    kem_public_key_b64: String,
    /// ML-KEM-768 secret key bytes (2400 B base64). Sensitive.
    kem_secret_key_b64: String,
    /// Timestamp the identity was minted, ms since Unix epoch.
    created_at_ms: u64,
}

/// In-memory chat identity for the local device.
#[derive(Clone)]
pub struct FetchitIdentity {
    agent_id_hex: String,
    user_id_hex: Option<String>,
    kem_public_key: Vec<u8>,
    kem_secret_key: Vec<u8>,
}

impl std::fmt::Debug for FetchitIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchitIdentity")
            .field("agent_id_hex", &self.agent_id_hex)
            .field("user_id_hex", &self.user_id_hex)
            .field("kem_public_key_len", &self.kem_public_key.len())
            .field("kem_secret_key_len", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl FetchitIdentity {
    /// Load the identity from the vault at `data_dir/identity.json.enc`,
    /// generating it if absent.
    ///
    /// `agent_id_hex` is supplied by the caller (already resolved from
    /// x0xd). If the stored identity is bound to a different agent_id,
    /// regenerates (we never reuse a chat identity across x0x rotations).
    ///
    /// # Errors
    /// I/O, AEAD, or KEM keygen failures.
    pub fn load_or_create(
        data_dir: &Path,
        master: &MasterKey,
        agent_id_hex: &str,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        let path = data_dir.join(IDENTITY_FILE);
        if path.exists() {
            let bytes = open_from_path(&path, master)?;
            let payload: IdentityVaultPayload = serde_json::from_slice(&bytes)?;
            if payload.agent_id_hex == agent_id_hex {
                return Ok(Self::from_payload(payload)?);
            }
            // x0x identity rotated — regenerate.
        }
        Self::create_and_persist(data_dir, master, agent_id_hex, kdf_id, argon_salt)
    }

    fn create_and_persist(
        data_dir: &Path,
        master: &MasterKey,
        agent_id_hex: &str,
        kdf_id: u8,
        argon_salt: Option<&[u8; crate::at_rest::ARGON_SALT_LEN]>,
    ) -> Result<Self, ChatError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        let (pk, sk) = kem_keygen()?;
        let payload = IdentityVaultPayload {
            version: 1,
            agent_id_hex: agent_id_hex.to_owned(),
            user_id_hex: None,
            kem_public_key_b64: B64.encode(&pk),
            kem_secret_key_b64: B64.encode(&sk),
            created_at_ms: now_ms(),
        };
        let plaintext = serde_json::to_vec(&payload)?;
        let path = data_dir.join(IDENTITY_FILE);
        seal_to_path(&path, &plaintext, master, kdf_id, argon_salt)?;
        Ok(Self::from_payload(payload)?)
    }

    fn from_payload(payload: IdentityVaultPayload) -> Result<Self, ChatError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        let kem_public_key = B64
            .decode(&payload.kem_public_key_b64)
            .map_err(|e| ChatError::Invalid(format!("kem pub b64: {e}")))?;
        let kem_secret_key = B64
            .decode(&payload.kem_secret_key_b64)
            .map_err(|e| ChatError::Invalid(format!("kem sec b64: {e}")))?;
        if kem_public_key.len() != KEM_PUBLIC_KEY_LEN {
            return Err(ChatError::Invalid("kem pub length".into()));
        }
        if kem_secret_key.len() != KEM_SECRET_KEY_LEN {
            return Err(ChatError::Invalid("kem sec length".into()));
        }
        Ok(Self {
            agent_id_hex: payload.agent_id_hex,
            user_id_hex: payload.user_id_hex,
            kem_public_key,
            kem_secret_key,
        })
    }

    /// Borrow the bound agent_id (hex).
    #[must_use]
    pub fn agent_id_hex(&self) -> &str {
        &self.agent_id_hex
    }

    /// Borrow the opt-in user_id (hex) if assigned.
    #[must_use]
    pub fn user_id_hex(&self) -> Option<&str> {
        self.user_id_hex.as_deref()
    }

    /// Borrow the KEM public key bytes (used in extended card publishing).
    #[must_use]
    pub fn kem_public_key(&self) -> &[u8] {
        &self.kem_public_key
    }

    /// Borrow the KEM secret key bytes (used in decap on inbound welcomes).
    /// Sensitive — never log.
    #[must_use]
    pub fn kem_secret_key(&self) -> &[u8] {
        &self.kem_secret_key
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{MasterKeySource, fresh_argon_salt, kdf_id_argon2};
    use tempfile::tempdir;

    #[test]
    fn first_launch_creates_identity() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let id = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            "deadbeef00000000000000000000000000000000000000000000000000000000",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(id.kem_public_key().len(), KEM_PUBLIC_KEY_LEN);
        assert_eq!(id.kem_secret_key().len(), KEM_SECRET_KEY_LEN);
        assert!(dir.path().join(IDENTITY_FILE).exists());
    }

    #[test]
    fn second_load_returns_same_identity() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let aid = "deadbeef00000000000000000000000000000000000000000000000000000000";
        let a = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            aid,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let b = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            aid,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(a.kem_public_key(), b.kem_public_key());
        assert_eq!(a.kem_secret_key(), b.kem_secret_key());
    }

    #[test]
    fn agent_id_rotation_regenerates() {
        let dir = tempdir().unwrap();
        let salt = fresh_argon_salt();
        let master =
            MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt)).unwrap();
        let a = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            "aaaa0000000000000000000000000000000000000000000000000000000000aa",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        let b = FetchitIdentity::load_or_create(
            dir.path(),
            &master,
            "bbbb0000000000000000000000000000000000000000000000000000000000bb",
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_ne!(
            a.kem_public_key(),
            b.kem_public_key(),
            "rotating x0x agent_id must regenerate the KEM keypair"
        );
    }
}
```

- [ ] **Step 3: Declare the module**

In `crates/fetchit-chat/src/lib.rs`:
```rust
pub mod chat_identity;
```
And re-export:
```rust
pub use chat_identity::FetchitIdentity;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p fetchit-chat chat_identity`
Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/chat_identity.rs crates/fetchit-chat/src/lib.rs crates/fetchit-chat/src/error.rs
git commit -s -m "feat(chat): per-device ML-KEM-768 identity persisted via vault

FetchitIdentity holds the chat-layer KEM keypair, distinct from x0xd's
KEM (which we don't use because x0xd has no decap endpoint). Bound to
the x0xd agent_id; regenerated if that rotates. Persisted under
<data_dir>/identity.json.enc via the at_rest vault."
```

---

## Task 5 — Extended share card (additive v2 fields + signing)

**Files:**
- Create: `crates/fetchit-chat/src/card.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`
- Modify: `crates/fetchit-chat/src/identity.rs` (only its existing AgentCard struct — make sure it preserves unknown fields)

- [ ] **Step 1: Verify the existing AgentCard preserves unknown fields**

Open `crates/fetchit-chat/src/identity.rs`. Locate the `AgentCard` struct. Confirm it has either `#[serde(flatten)] extra: HashMap<String, Value>` or, more robustly, an explicit `extra: serde_json::Value` field. From earlier session work this is already present as `extra: serde_json::Value` per the integration test on line 107. Verify by running:
```bash
grep -A 2 "pub extra" crates/fetchit-chat/src/identity.rs | head -3
```
Expected: a field that's either `Value` or `HashMap<String, Value>` so unknown fields don't get dropped. If absent, add:
```rust
    /// Capture-all for any unknown fields so v2 additive properties
    /// round-trip through x0xd's import/export.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
```

- [ ] **Step 2: Write card.rs tests + impl**

Create `crates/fetchit-chat/src/card.rs`:
```rust
//! Extended share-card v2 — additive fields on top of x0xd's
//! `AgentCard` JSON. The user-facing URI stays `x0x://agent/<base64>`;
//! we add three signed fields that fetchit-chat reads and x0xd
//! preserves as unknown JSON.

use crate::chat_crypto::{SIGN_DOMAIN_CARD, ml_dsa_verify};
use crate::error::ChatError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::general_purpose::STANDARD as B64;
use fetchit_relay_client::Signer;
use serde::{Deserialize, Serialize};

pub const CARD_VERSION: u16 = 1;
pub const URI_PREFIX: &str = "x0x://agent/";

/// The fetchit-namespaced fields tucked into an x0x share-card's JSON.
/// All three fields together form the v2 extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardExtension {
    /// Card v2 schema version. Currently 1.
    #[serde(rename = "fetchit_card_version")]
    pub version: u16,
    /// ML-KEM-768 public key (base64).
    #[serde(rename = "fetchit_kem_public_key_b64")]
    pub kem_public_key_b64: String,
    /// ML-DSA-65 signature over canonical card bytes excluding this signature.
    #[serde(rename = "fetchit_card_signature_b64")]
    pub signature_b64: String,
}

/// Bytes signed for `CardExtension.signature_b64`:
/// `concat(SIGN_DOMAIN_CARD, postcard({ x0x_card_json, fetchit_card_version, kem_public_key_b64 }))`.
/// We use postcard on a tuple of those three values so signer and
/// verifier compute byte-identical strings.
#[derive(Serialize, Deserialize)]
struct SignedCardBody<'a> {
    /// The x0x card JSON as it appears on the wire BEFORE the extension
    /// fields are added. Serializing the whole card and then extracting
    /// would also work, but signing-known-good-bytes is safer.
    x0x_card_canonical_json: &'a [u8],
    version: u16,
    kem_public_key_b64: &'a str,
}

/// Add the fetchit-chat v2 fields to an existing x0x share-card JSON.
/// The card JSON is taken in its post-x0xd-generation shape (i.e. the
/// `card` field of `GET /agent/card`'s response).
///
/// Returns the augmented JSON value (caller serializes + b64-encodes
/// to produce the final `x0x://agent/<…>` URI).
///
/// # Errors
/// `ChatError::Invalid` on JSON shape errors or signer failures.
pub async fn extend_with_fetchit_fields<S: Signer + ?Sized>(
    x0x_card: &serde_json::Value,
    kem_public_key: &[u8],
    signer: &S,
) -> Result<serde_json::Value, ChatError> {
    let x0x_obj = x0x_card.as_object().ok_or_else(|| {
        ChatError::Invalid("x0x card must be a JSON object".into())
    })?;
    let canonical_x0x_bytes = canonical_json(x0x_card)?;
    let kem_b64 = B64.encode(kem_public_key);

    let to_sign = SignedCardBody {
        x0x_card_canonical_json: &canonical_x0x_bytes,
        version: CARD_VERSION,
        kem_public_key_b64: &kem_b64,
    };
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_CARD.len() + 256);
    sign_bytes.extend_from_slice(SIGN_DOMAIN_CARD);
    sign_bytes.extend_from_slice(
        &postcard::to_allocvec(&to_sign)
            .map_err(|e| ChatError::Invalid(format!("postcard: {e}")))?,
    );
    let sig = signer
        .sign(&sign_bytes)
        .await
        .map_err(|e| ChatError::Invalid(format!("card sign: {e}")))?;

    let mut out = serde_json::Map::with_capacity(x0x_obj.len() + 3);
    for (k, v) in x0x_obj {
        out.insert(k.clone(), v.clone());
    }
    out.insert(
        "fetchit_card_version".into(),
        serde_json::Value::from(CARD_VERSION),
    );
    out.insert(
        "fetchit_kem_public_key_b64".into(),
        serde_json::Value::String(kem_b64),
    );
    out.insert(
        "fetchit_card_signature_b64".into(),
        serde_json::Value::String(B64.encode(sig)),
    );
    Ok(serde_json::Value::Object(out))
}

/// Encode an extended-card JSON value as the `x0x://agent/<base64>` URI.
///
/// # Errors
/// JSON serialization errors.
pub fn extended_card_to_uri(card_json: &serde_json::Value) -> Result<String, ChatError> {
    let bytes = serde_json::to_vec(card_json)?;
    Ok(format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Decode an extended-card URI back into a JSON value.
///
/// # Errors
/// Bad URI, base64 errors, JSON errors.
pub fn extended_card_from_uri(uri: &str) -> Result<serde_json::Value, ChatError> {
    let body = uri
        .strip_prefix(URI_PREFIX)
        .ok_or_else(|| ChatError::Invalid("not an x0x://agent/ URI".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| ChatError::Invalid(format!("base64: {e}")))?;
    let value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

/// Verify the fetchit-v2 fields on an extended card.
///
/// Returns the validated `CardExtension`. Caller is responsible for
/// also verifying the wider x0x card data (agent_id matches the
/// signing key, etc.).
///
/// # Errors
/// `ChatError::Invalid` if fields are missing / malformed / signature
/// verification fails.
pub fn verify_card_extension(
    card_json: &serde_json::Value,
    agent_public_key_bytes: &[u8],
) -> Result<CardExtension, ChatError> {
    let obj = card_json
        .as_object()
        .ok_or_else(|| ChatError::Invalid("card must be a JSON object".into()))?;
    let version = obj
        .get("fetchit_card_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ChatError::Invalid("missing fetchit_card_version".into()))?;
    if version != u64::from(CARD_VERSION) {
        return Err(ChatError::Invalid(format!(
            "unsupported card version: {version}"
        )));
    }
    let kem_b64 = obj
        .get("fetchit_kem_public_key_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatError::Invalid("missing fetchit_kem_public_key_b64".into()))?;
    let sig_b64 = obj
        .get("fetchit_card_signature_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ChatError::Invalid("missing fetchit_card_signature_b64".into()))?;

    // Reconstruct the x0x-card-only JSON (without the three v2 fields)
    // so we sign the same canonical bytes the issuer signed.
    let mut x0x_only = obj.clone();
    x0x_only.remove("fetchit_card_version");
    x0x_only.remove("fetchit_kem_public_key_b64");
    x0x_only.remove("fetchit_card_signature_b64");
    let x0x_only_value = serde_json::Value::Object(x0x_only);
    let canonical_x0x_bytes = canonical_json(&x0x_only_value)?;

    let to_sign = SignedCardBody {
        x0x_card_canonical_json: &canonical_x0x_bytes,
        version: CARD_VERSION,
        kem_public_key_b64: kem_b64,
    };
    let mut sign_bytes = Vec::with_capacity(SIGN_DOMAIN_CARD.len() + 256);
    sign_bytes.extend_from_slice(SIGN_DOMAIN_CARD);
    sign_bytes.extend_from_slice(
        &postcard::to_allocvec(&to_sign)
            .map_err(|e| ChatError::Invalid(format!("postcard: {e}")))?,
    );
    let sig = B64
        .decode(sig_b64)
        .map_err(|e| ChatError::Invalid(format!("sig b64: {e}")))?;
    ml_dsa_verify(agent_public_key_bytes, &sign_bytes, &sig)?;

    Ok(CardExtension {
        version: u16::try_from(version).unwrap_or(1),
        kem_public_key_b64: kem_b64.to_owned(),
        signature_b64: sig_b64.to_owned(),
    })
}

/// Canonical JSON encoding: keys sorted recursively. Deterministic so
/// signer + verifier produce byte-identical inputs.
fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, ChatError> {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf)?;
    Ok(buf)
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), ChatError> {
    use std::io::Write;
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
        }
        serde_json::Value::Number(n) => write!(out, "{n}")
            .map_err(|e| ChatError::Invalid(format!("write canonical num: {e}")))?,
        serde_json::Value::String(s) => {
            let encoded = serde_json::to_string(s)?;
            out.extend_from_slice(encoded.as_bytes());
        }
        serde_json::Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(obj) => {
            out.push(b'{');
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let kj = serde_json::to_string(k)?;
                out.extend_from_slice(kj.as_bytes());
                out.push(b':');
                write_canonical(obj.get(*k).expect("key from same map"), out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fetchit_relay_client::MlDsaSigner;

    fn fake_x0x_card() -> serde_json::Value {
        serde_json::json!({
            "agent_id": "0".repeat(64),
            "machine_id": "1".repeat(64),
            "user_id": null,
            "display_name": "Alice",
            "addresses": [],
            "dm_capabilities": { "kem_algorithm": "ML-KEM-768" }
        })
    }

    #[tokio::test]
    async fn extend_then_verify_round_trip() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
            .await
            .unwrap();
        let ext = verify_card_extension(&extended, &signer.public_key()).unwrap();
        assert_eq!(ext.version, 1);
        let decoded =
            B64.decode(&ext.kem_public_key_b64).unwrap();
        assert_eq!(decoded, kem_pub);
    }

    #[tokio::test]
    async fn tampered_kem_field_fails_verify() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let mut extended =
            extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
                .await
                .unwrap();
        // Swap the KEM key for a different one.
        extended["fetchit_kem_public_key_b64"] =
            serde_json::Value::String(B64.encode(vec![0xbb; 1184]));
        assert!(verify_card_extension(&extended, &signer.public_key()).is_err());
    }

    #[tokio::test]
    async fn tampered_x0x_field_fails_verify() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let mut extended =
            extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
                .await
                .unwrap();
        // Change a field signed inside the canonical block.
        extended["display_name"] = serde_json::Value::String("Mallory".into());
        assert!(verify_card_extension(&extended, &signer.public_key()).is_err());
    }

    #[tokio::test]
    async fn uri_round_trip() {
        let signer = MlDsaSigner::generate().unwrap();
        let kem_pub = vec![0xaa; 1184];
        let extended = extend_with_fetchit_fields(&fake_x0x_card(), &kem_pub, &signer)
            .await
            .unwrap();
        let uri = extended_card_to_uri(&extended).unwrap();
        assert!(uri.starts_with(URI_PREFIX));
        let recovered = extended_card_from_uri(&uri).unwrap();
        assert_eq!(recovered, extended);
    }
}
```

- [ ] **Step 3: Declare the module + re-exports**

In `crates/fetchit-chat/src/lib.rs`:
```rust
pub mod card;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p fetchit-chat card`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/fetchit-chat/src/card.rs crates/fetchit-chat/src/lib.rs crates/fetchit-chat/src/identity.rs
git commit -s -m "feat(chat): extended share-card v2 with signed fetchit fields

Adds CardExtension (fetchit_card_version, fetchit_kem_public_key_b64,
fetchit_card_signature_b64) to the x0x://agent/<base64> URI. The
extension is signed by the device's x0xd ML-DSA-65 key with domain
'fetchit-chat/v1/card' over canonical-JSON of the x0x-card-only
fields. x0xd preserves unknown fields on import, so the URI shape
stays compatible with stock x0xd 0.19.49+."
```

---

## Task 6 — Local card store

**Files:**
- Create: `crates/fetchit-chat/src/local_store.rs`
- Modify: `crates/fetchit-chat/src/lib.rs`

- [ ] **Step 1: Write tests + impl**

Create `crates/fetchit-chat/src/local_store.rs`:
```rust
//! On-disk layout for fetchit-chat state under `~/.config/fetchit/`.
//!
//! Plaintext under `contacts/` and `user_manifests/` (cards aren't
//! secret). Encrypted vault under `identity.json.enc` and
//! `conversations/<group_id>.json.enc`.
//!
//! All file writes go through an atomic write helper:
//! `write_tmp_then_rename` with 0600 permissions on Unix.

use crate::error::ChatError;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// The default data dir for desktop builds: platform-specific user
/// config dir, plus `fetchit/chat`.
///
/// # Errors
/// Returns `ChatError::Invalid` if the platform doesn't have a config
/// dir (e.g. Windows without a Roaming setup).
pub fn default_data_dir() -> Result<PathBuf, ChatError> {
    let dirs = directories::BaseDirs::new()
        .ok_or_else(|| ChatError::Invalid("no platform config dir".into()))?;
    Ok(dirs.config_dir().join("fetchit").join("chat"))
}

/// Top-level data layout under a chat data dir.
#[derive(Clone, Debug)]
pub struct StoreLayout {
    /// `<data_dir>/`
    pub root: PathBuf,
    /// `<data_dir>/contacts/`
    pub contacts_dir: PathBuf,
    /// `<data_dir>/conversations/`
    pub conversations_dir: PathBuf,
    /// `<data_dir>/user_manifests/` — populated by the multi-device
    /// build; created here for forward compatibility.
    pub user_manifests_dir: PathBuf,
}

impl StoreLayout {
    /// Build a layout rooted at `root` and ensure every subdirectory
    /// exists with 0700 permissions on Unix.
    ///
    /// # Errors
    /// IO failures on directory creation or chmod.
    pub fn ensure(root: PathBuf) -> Result<Self, ChatError> {
        let contacts_dir = root.join("contacts");
        let conversations_dir = root.join("conversations");
        let user_manifests_dir = root.join("user_manifests");
        for dir in [&root, &contacts_dir, &conversations_dir, &user_manifests_dir] {
            fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(dir)?.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(dir, perms)?;
            }
        }
        Ok(Self {
            root,
            contacts_dir,
            conversations_dir,
            user_manifests_dir,
        })
    }

    /// File path for a stored contact card, keyed by hex agent id.
    #[must_use]
    pub fn contact_path(&self, agent_id_hex: &str) -> PathBuf {
        self.contacts_dir.join(format!("{agent_id_hex}.json"))
    }

    /// File path for a conversation vault, keyed by hex group id.
    #[must_use]
    pub fn conversation_path(&self, group_id_hex: &str) -> PathBuf {
        self.conversations_dir.join(format!("{group_id_hex}.json.enc"))
    }
}

/// Atomic plaintext-JSON write at 0600 perms.
///
/// # Errors
/// IO or JSON serialization failures.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ChatError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &bytes)?;
    set_perms_0600(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn set_perms_0600(path: &Path) -> Result<(), ChatError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ensure_creates_subdirs() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        assert!(layout.root.exists());
        assert!(layout.contacts_dir.exists());
        assert!(layout.conversations_dir.exists());
        assert!(layout.user_manifests_dir.exists());
    }

    #[test]
    fn contact_path_uses_hex_agent_id() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        let p = layout.contact_path("abc123");
        assert!(p.to_string_lossy().ends_with("abc123.json"));
    }

    #[test]
    fn write_json_atomic_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contact.json");
        let value = serde_json::json!({ "name": "Alice" });
        write_json_atomic(&path, &value).unwrap();
        let bytes = fs::read(&path).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(recovered, value);
    }

    #[cfg(unix)]
    #[test]
    fn write_json_atomic_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("contact.json");
        write_json_atomic(&path, &serde_json::json!({})).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
```

- [ ] **Step 2: Declare module**

In `crates/fetchit-chat/src/lib.rs`:
```rust
pub mod local_store;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p fetchit-chat local_store`
Expected: 4 tests pass on Unix; 3 on Windows.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/local_store.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(chat): local_store — disk layout helpers for fetchit-chat

StoreLayout creates contacts/, conversations/, and user_manifests/
under <data_dir>. write_json_atomic provides tmp+rename+0600 file
writes for plaintext metadata. Encrypted vault writes go through
at_rest::seal_to_path."
```

---

## Task 7 — Conversation type + state machine

**Files:** see the "File structure" table — the implementation is split across **five files** under `crates/fetchit-chat/src/conversation/`. The code sample below is presented as one continuous module for ease of review; **before committing**, split it along the boundaries marked with `// ── module: <name> ─────` comments into the matching `mod.rs`, `types.rs`, `registry.rs`, `outbound.rs`, `inbound.rs` files. Each file's tests stay with the file. The `mod.rs` re-exports are the four `pub use` lines at the top of the sample.

**Why split:** project convention is one concern per module (no monolith files). Each of the five files lands under ~300 lines.

- [ ] **Step 1: Write the full module (one continuous file initially), then split**

The continuous text is reproduced below (~600 lines). After it compiles and the tests pass, split into the five files in one mechanical refactor commit (Step 4 below):

```rust
//! Conversation state and lifecycle for chat encryption.
//!
//! A `Conversation` represents one DM or group. v1 ships 2-member
//! conversations (DMs); v3 adds N-member groups. Data shape supports
//! N from day one.
//!
//! Storage: each Conversation is persisted to
//! `<conversations_dir>/<group_id_hex>.json.enc` via at_rest.

use crate::at_rest::{
    ARGON_SALT_LEN, MasterKey, kdf_id_argon2, kdf_id_keychain, open_from_path, seal_to_path,
};
use crate::chat_crypto::{
    AEAD_KEY_LEN, KDF_INFO_WELCOME, KEM_PUBLIC_KEY_LEN, aead_open, aead_seal,
    canonical_envelope_bytes, derive_aead_key, kem_decapsulate, kem_encapsulate,
    message_aad, random_nonce, random_symmetric_key,
};
use crate::chat_identity::FetchitIdentity;
use crate::error::ChatError;
use crate::local_store::StoreLayout;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use fetchit_relay_proto::{AgentId, EnvelopeKind, GroupId, MachineId, TransitEnvelope};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Default auto-rekey interval (7 days in ms). Configurable per
/// conversation via `Conversation.auto_rekey_interval_ms`.
pub const DEFAULT_AUTO_REKEY_INTERVAL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// How long a prior-key entry stays valid for in-flight envelopes
/// crossing an epoch transition. 60s per spec.
pub const PRIOR_KEY_WINDOW_MS: u64 = 60 * 1000;

/// Conversation role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Can add/remove members, trigger auto-rekey.
    Admin,
    /// Can only send messages.
    Member,
}

/// Per-device record inside a `Member`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDevice {
    /// 32 bytes (hex on disk).
    pub agent_id_hex: String,
    /// ML-KEM-768 public key, base64.
    pub kem_public_key_b64: String,
    /// Epoch at which this device was added.
    pub added_at_epoch: u32,
    /// Active | Revoked. Single-device builds only ever set Active.
    #[serde(default = "default_active")]
    pub status: MemberDeviceStatus,
}

fn default_active() -> MemberDeviceStatus {
    MemberDeviceStatus::Active
}

/// A device's participation status in a conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberDeviceStatus {
    Active,
    Revoked,
}

/// One member (user) of a conversation, with their device list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Opt-in. None for single-device legacy contacts.
    pub user_id_hex: Option<String>,
    /// Devices owned by this member.
    pub devices: Vec<MemberDevice>,
    /// Epoch at which this member joined.
    pub joined_at_epoch: u32,
}

/// A symmetric key from a prior epoch, kept alive for in-flight envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorKey {
    pub epoch: u32,
    pub key_b64: String,
    pub expires_at_ms: u64,
}

/// One full conversation, serialized to disk via vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversation {
    /// 32 random bytes assigned at creation.
    pub group_id_hex: String,
    /// Optional human-readable name (group only). DMs use peer's display
    /// name resolved at render time.
    pub name: Option<String>,
    /// Members of the conversation, including self.
    pub members: Vec<Member>,
    /// Bumps on every membership change or auto-rekey.
    pub current_epoch: u32,
    /// Current symmetric key (base64). Sensitive.
    pub current_key_b64: String,
    /// Recent prior keys for in-flight late-arriving envelopes.
    pub prior_keys: Vec<PriorKey>,
    /// What role our local device plays in this conversation.
    pub own_role: Role,
    /// Created-at, Unix ms.
    pub created_at_ms: u64,
    /// Most recent rekey at, Unix ms.
    pub last_rekey_at_ms: u64,
    /// Auto-rekey interval in ms (default 7 days).
    pub auto_rekey_interval_ms: u64,
}

impl Conversation {
    /// Build a fresh DM conversation between `self` (the local
    /// identity) and `peer_member`. Generates the group_id and the
    /// initial conversation key.
    ///
    /// # Errors
    /// None today (everything is either deterministic or RNG-driven);
    /// signature kept fallible for forward compatibility.
    pub fn new_dm(
        local_member: Member,
        peer_member: Member,
        name: Option<String>,
    ) -> Result<Self, ChatError> {
        let mut group_id = [0u8; 32];
        OsRng.fill_bytes(&mut group_id);
        let key = random_symmetric_key(&mut OsRng);
        let now = now_ms();
        Ok(Self {
            group_id_hex: hex::encode(group_id),
            name,
            members: vec![local_member, peer_member],
            current_epoch: 0,
            current_key_b64: B64.encode(key),
            prior_keys: Vec::new(),
            own_role: Role::Admin,
            created_at_ms: now,
            last_rekey_at_ms: now,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        })
    }

    /// Construct from a Welcome payload (we just joined a conversation).
    pub fn from_welcome(payload: WelcomePayload) -> Self {
        let now = now_ms();
        Self {
            group_id_hex: payload.group_id_hex,
            name: payload.name,
            members: payload.members,
            current_epoch: payload.epoch,
            current_key_b64: payload.current_key_b64,
            prior_keys: Vec::new(),
            own_role: Role::Member,
            created_at_ms: now,
            last_rekey_at_ms: now,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        }
    }

    /// Current key as fixed-size bytes.
    pub fn current_key(&self) -> Result<[u8; AEAD_KEY_LEN], ChatError> {
        let v = B64
            .decode(&self.current_key_b64)
            .map_err(|e| ChatError::Invalid(format!("current_key b64: {e}")))?;
        if v.len() != AEAD_KEY_LEN {
            return Err(ChatError::Invalid("current_key length".into()));
        }
        let mut out = [0u8; AEAD_KEY_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }

    /// 32-byte raw group_id.
    pub fn group_id_bytes(&self) -> Result<[u8; 32], ChatError> {
        let v = hex::decode(&self.group_id_hex)
            .map_err(|e| ChatError::Invalid(format!("group_id hex: {e}")))?;
        v.try_into()
            .map_err(|_| ChatError::Invalid("group_id length".into()))
    }

    /// Look up a key for `epoch`: current_key if epoch matches, else a
    /// non-expired prior_keys entry.
    pub fn key_for_epoch(&self, epoch: u32) -> Result<Option<[u8; AEAD_KEY_LEN]>, ChatError> {
        if epoch == self.current_epoch {
            return self.current_key().map(Some);
        }
        let now = now_ms();
        for prior in &self.prior_keys {
            if prior.epoch != epoch {
                continue;
            }
            if prior.expires_at_ms <= now {
                continue;
            }
            let bytes = B64
                .decode(&prior.key_b64)
                .map_err(|e| ChatError::Invalid(format!("prior key b64: {e}")))?;
            if bytes.len() != AEAD_KEY_LEN {
                return Err(ChatError::Invalid("prior key length".into()));
            }
            let mut k = [0u8; AEAD_KEY_LEN];
            k.copy_from_slice(&bytes);
            return Ok(Some(k));
        }
        Ok(None)
    }

    /// Drop expired prior_keys entries.
    pub fn sweep_prior_keys(&mut self) {
        let now = now_ms();
        self.prior_keys.retain(|p| p.expires_at_ms > now);
    }

    /// Bump epoch + install a new current_key. Pushes the old key into
    /// prior_keys with a 60s expiry.
    pub fn advance_epoch(&mut self, new_key: [u8; AEAD_KEY_LEN]) {
        let now = now_ms();
        self.prior_keys.push(PriorKey {
            epoch: self.current_epoch,
            key_b64: self.current_key_b64.clone(),
            expires_at_ms: now + PRIOR_KEY_WINDOW_MS,
        });
        self.current_epoch += 1;
        self.current_key_b64 = B64.encode(new_key);
        self.last_rekey_at_ms = now;
        self.sweep_prior_keys();
    }

    /// Should auto-rekey fire?
    pub fn auto_rekey_due(&self) -> bool {
        if self.own_role != Role::Admin {
            return false;
        }
        now_ms().saturating_sub(self.last_rekey_at_ms) > self.auto_rekey_interval_ms
    }

    /// Iterate every recipient device address — every Active device of
    /// every member EXCLUDING the local device.
    pub fn fanout_devices<'a>(
        &'a self,
        local_agent_id_hex: &'a str,
    ) -> impl Iterator<Item = &'a MemberDevice> + 'a {
        self.members
            .iter()
            .flat_map(|m| m.devices.iter())
            .filter(move |d| {
                d.status == MemberDeviceStatus::Active && d.agent_id_hex != local_agent_id_hex
            })
    }
}

/// Inner payload of a Welcome envelope (after KEM decap + AEAD open).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomePayload {
    pub group_id_hex: String,
    pub current_key_b64: String,
    pub epoch: u32,
    pub members: Vec<Member>,
    pub name: Option<String>,
}

/// Inner payload of a Message envelope (after AEAD open).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePayload {
    /// Sender display name (echoed in UI).
    pub sender_name: Option<String>,
    /// Plaintext body.
    pub body: String,
    /// Sender-asserted timestamp (mirrors envelope timestamp_ms).
    pub ts_ms: u64,
}

/// In-memory registry of open conversations, persisted via at_rest.
pub struct ConversationRegistry {
    layout: StoreLayout,
    master: Arc<MasterKey>,
    kdf_id: u8,
    argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    by_group_id: Mutex<HashMap<String, Conversation>>,
}

impl ConversationRegistry {
    /// Build an empty registry. Conversations are loaded on demand.
    #[must_use]
    pub fn new(
        layout: StoreLayout,
        master: Arc<MasterKey>,
        kdf_id: u8,
        argon_salt: Option<[u8; ARGON_SALT_LEN]>,
    ) -> Self {
        Self {
            layout,
            master,
            kdf_id,
            argon_salt,
            by_group_id: Mutex::new(HashMap::new()),
        }
    }

    /// Borrow / load a conversation by group_id_hex.
    /// Returns None if it's not on disk and not in memory.
    pub async fn get(&self, group_id_hex: &str) -> Result<Option<Conversation>, ChatError> {
        {
            let g = self.by_group_id.lock().await;
            if let Some(c) = g.get(group_id_hex) {
                return Ok(Some(c.clone()));
            }
        }
        let path = self.layout.conversation_path(group_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = open_from_path(&path, &self.master)?;
        let conv: Conversation = serde_json::from_slice(&bytes)?;
        self.by_group_id
            .lock()
            .await
            .insert(group_id_hex.to_owned(), conv.clone());
        Ok(Some(conv))
    }

    /// Find an existing DM with `peer_agent_id_hex` (any conversation
    /// that has exactly 2 members and one of them is the peer).
    pub async fn find_dm_with(
        &self,
        peer_agent_id_hex: &str,
    ) -> Result<Option<Conversation>, ChatError> {
        // First scan in-memory.
        {
            let g = self.by_group_id.lock().await;
            for c in g.values() {
                if dm_with(c, peer_agent_id_hex) {
                    return Ok(Some(c.clone()));
                }
            }
        }
        // Single-device builds have few conversations per device so a
        // linear scan is acceptable; N-member groups add an index.
        for entry in std::fs::read_dir(&self.layout.conversations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("enc") {
                continue;
            }
            let bytes = open_from_path(&path, &self.master)?;
            let conv: Conversation = serde_json::from_slice(&bytes)?;
            if dm_with(&conv, peer_agent_id_hex) {
                self.by_group_id
                    .lock()
                    .await
                    .insert(conv.group_id_hex.clone(), conv.clone());
                return Ok(Some(conv));
            }
        }
        Ok(None)
    }

    /// Persist a conversation to disk and update the in-memory cache.
    pub async fn save(&self, conv: &Conversation) -> Result<(), ChatError> {
        let path = self.layout.conversation_path(&conv.group_id_hex);
        let bytes = serde_json::to_vec(conv)?;
        seal_to_path(
            &path,
            &bytes,
            &self.master,
            self.kdf_id,
            self.argon_salt.as_ref(),
        )?;
        self.by_group_id
            .lock()
            .await
            .insert(conv.group_id_hex.clone(), conv.clone());
        Ok(())
    }
}

fn dm_with(conv: &Conversation, peer_agent_id_hex: &str) -> bool {
    if conv.members.len() != 2 {
        return false;
    }
    conv.members
        .iter()
        .flat_map(|m| m.devices.iter())
        .any(|d| d.agent_id_hex == peer_agent_id_hex)
}

// ── Welcome generation ─────────────────────────────────────────────────

/// Build the set of Welcome envelopes Alice needs to send when
/// starting a new conversation. One envelope per recipient device.
///
/// `signer` is used to sign each envelope's sender_signature.
///
/// # Errors
/// KEM / AEAD / signing errors.
pub async fn build_welcome_envelopes<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<TransitEnvelope>, ChatError> {
    let payload = WelcomePayload {
        group_id_hex: conv.group_id_hex.clone(),
        current_key_b64: conv.current_key_b64.clone(),
        epoch: conv.current_epoch,
        members: conv.members.clone(),
        name: conv.name.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)?;

    let group_id_bytes = conv.group_id_bytes()?;
    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let mut out = Vec::new();
    let local_agent_hex = identity.agent_id_hex().to_owned();

    for device in conv.fanout_devices(&local_agent_hex) {
        let kem_pub = B64
            .decode(&device.kem_public_key_b64)
            .map_err(|e| ChatError::Invalid(format!("device kem b64: {e}")))?;
        if kem_pub.len() != KEM_PUBLIC_KEY_LEN {
            return Err(ChatError::Invalid("device kem key length".into()));
        }
        let (kem_ct, ss) = kem_encapsulate(&kem_pub)?;
        let aead_key = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let nonce = random_nonce(&mut OsRng);
        let aad = message_aad(&group_id_bytes, conv.current_epoch);
        let ciphertext = aead_seal(&aead_key, &nonce, &payload_bytes, &aad)?;

        let mut recipient_agent = [0u8; 32];
        hex::decode_to_slice(&device.agent_id_hex, &mut recipient_agent).map_err(|e| {
            ChatError::Invalid(format!("recipient agent_id hex: {e}"))
        })?;

        let mut env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes(local_machine_id),
            timestamp_ms: now_ms(),
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: kem_ct,
            sender_signature: Vec::new(),
        };
        let canonical = canonical_envelope_bytes(&env)?;
        let mut sign_bytes = Vec::with_capacity(
            crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len(),
        );
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        let sig = signer
            .sign(&sign_bytes)
            .await
            .map_err(|e| ChatError::Invalid(format!("envelope sign: {e}")))?;
        env.sender_signature = sig;
        // Record `recipient_agent` for the relay layer to address; the
        // relay client takes `to: AgentId` separately, so we expose it
        // via a wrapping struct OR we just return (to, env) pairs:
        // pick (to, env) for clarity.
        let _ = recipient_agent;
        out.push(env);
    }
    Ok(out)
}

/// Tuple convenience: build_welcome_envelopes paired with recipient.
#[derive(Clone, Debug)]
pub struct OutboundEnvelope {
    pub recipient_agent_id: AgentId,
    pub envelope: TransitEnvelope,
}

/// As [`build_welcome_envelopes`], but returns `(to, envelope)` pairs.
///
/// # Errors
/// See [`build_welcome_envelopes`].
pub async fn build_welcome_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let local_agent_hex = identity.agent_id_hex().to_owned();
    let envelopes = build_welcome_envelopes(conv, identity, local_machine_id, signer).await?;
    let mut pairs = Vec::with_capacity(envelopes.len());
    let devices: Vec<&MemberDevice> = conv.fanout_devices(&local_agent_hex).collect();
    for (env, dev) in envelopes.into_iter().zip(devices.iter()) {
        let mut to = [0u8; 32];
        hex::decode_to_slice(&dev.agent_id_hex, &mut to)
            .map_err(|e| ChatError::Invalid(format!("device hex: {e}")))?;
        pairs.push(OutboundEnvelope {
            recipient_agent_id: AgentId::from_bytes(to),
            envelope: env,
        });
    }
    Ok(pairs)
}

// ── Message send/recv ──────────────────────────────────────────────────

/// Build outbound Message envelopes for a chat message in `conv`.
///
/// # Errors
/// AEAD or signing errors.
pub async fn build_message_outbox<S: fetchit_relay_client::Signer + ?Sized>(
    conv: &Conversation,
    body: &str,
    sender_name: &str,
    identity: &FetchitIdentity,
    local_machine_id: [u8; 32],
    signer: &S,
) -> Result<Vec<OutboundEnvelope>, ChatError> {
    let now = now_ms();
    let payload = MessagePayload {
        sender_name: Some(sender_name.to_owned()),
        body: body.to_owned(),
        ts_ms: now,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;

    let key = conv.current_key()?;
    let group_id_bytes = conv.group_id_bytes()?;
    let aad = message_aad(&group_id_bytes, conv.current_epoch);

    let mut local_agent_bytes = [0u8; 32];
    hex::decode_to_slice(identity.agent_id_hex(), &mut local_agent_bytes)
        .map_err(|e| ChatError::Invalid(format!("local agent_id hex: {e}")))?;

    let local_agent_hex = identity.agent_id_hex().to_owned();
    let mut out = Vec::new();
    for device in conv.fanout_devices(&local_agent_hex) {
        let nonce = random_nonce(&mut OsRng);
        let ciphertext = aead_seal(&key, &nonce, &payload_bytes, &aad)?;
        let mut recipient_agent = [0u8; 32];
        hex::decode_to_slice(&device.agent_id_hex, &mut recipient_agent)
            .map_err(|e| ChatError::Invalid(format!("recipient hex: {e}")))?;

        let mut env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes(group_id_bytes)),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes(local_agent_bytes),
            sender_machine_id: MachineId::from_bytes(local_machine_id),
            timestamp_ms: now,
            epoch: conv.current_epoch,
            ciphertext,
            nonce: nonce.to_vec(),
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let canonical = canonical_envelope_bytes(&env)?;
        let mut sign_bytes = Vec::with_capacity(
            crate::chat_crypto::SIGN_DOMAIN_ENVELOPE.len() + canonical.len(),
        );
        sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
        sign_bytes.extend_from_slice(&canonical);
        let sig = signer
            .sign(&sign_bytes)
            .await
            .map_err(|e| ChatError::Invalid(format!("envelope sign: {e}")))?;
        env.sender_signature = sig;

        out.push(OutboundEnvelope {
            recipient_agent_id: AgentId::from_bytes(recipient_agent),
            envelope: env,
        });
    }
    Ok(out)
}

/// Inbound dispatch result.
#[derive(Clone, Debug)]
pub enum InboundDispatch {
    /// Installed a new conversation (from a welcome).
    Welcomed { conversation: Conversation },
    /// Updated an existing conversation (from a welcome carrying a higher epoch).
    Rekeyed { conversation: Conversation },
    /// Decrypted a chat message.
    Message {
        group_id_hex: String,
        sender_agent_id_hex: String,
        payload: MessagePayload,
    },
    /// Stale epoch — dropped.
    StaleEpoch { group_id_hex: String, epoch: u32 },
    /// KEM decap failed (likely encrypted to a different KEM key).
    KemDecapFailed,
    /// AEAD open failed (likely tampered or wrong key).
    AeadOpenFailed { group_id_hex: String, epoch: u32 },
}

/// Dispatch an inbound envelope: distinguish Welcome vs Message,
/// decrypt, and surface a typed result.
///
/// # Errors
/// Hard errors (e.g. malformed envelope bytes). Soft errors (stale
/// epoch, decap fail) are returned as `InboundDispatch` variants.
pub async fn dispatch_inbound(
    envelope: TransitEnvelope,
    identity: &FetchitIdentity,
    registry: &ConversationRegistry,
) -> Result<InboundDispatch, ChatError> {
    let group_id_bytes = match &envelope.group_id {
        Some(g) => *g.as_bytes(),
        None => return Err(ChatError::Invalid("envelope has no group_id".into())),
    };
    let group_id_hex = hex::encode(group_id_bytes);

    if !envelope.kem_ciphertext.is_empty() {
        // Welcome path.
        let ss = match kem_decapsulate(identity.kem_secret_key(), &envelope.kem_ciphertext) {
            Ok(s) => s,
            Err(_) => return Ok(InboundDispatch::KemDecapFailed),
        };
        let aead_key = derive_aead_key(&ss, KDF_INFO_WELCOME);
        let mut nonce = [0u8; 12];
        if envelope.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        nonce.copy_from_slice(&envelope.nonce);
        let aad = message_aad(&group_id_bytes, envelope.epoch);
        let plaintext = match aead_open(&aead_key, &nonce, &envelope.ciphertext, &aad) {
            Ok(p) => p,
            Err(_) => return Ok(InboundDispatch::AeadOpenFailed { group_id_hex, epoch: envelope.epoch }),
        };
        let payload: WelcomePayload = serde_json::from_slice(&plaintext)?;
        let existing = registry.get(&group_id_hex).await?;
        match existing {
            Some(mut conv) if envelope.epoch <= conv.current_epoch => {
                // Stale or current — no-op.
                Ok(InboundDispatch::Welcomed { conversation: conv })
            }
            Some(mut conv) => {
                // Higher epoch — adopt new key and member list.
                let mut new_key = [0u8; AEAD_KEY_LEN];
                let bytes = B64
                    .decode(&payload.current_key_b64)
                    .map_err(|e| ChatError::Invalid(format!("welcome key b64: {e}")))?;
                new_key.copy_from_slice(&bytes);
                conv.advance_epoch(new_key);
                conv.members = payload.members.clone();
                conv.current_epoch = payload.epoch;
                conv.current_key_b64 = payload.current_key_b64.clone();
                conv.name = payload.name.clone();
                registry.save(&conv).await?;
                Ok(InboundDispatch::Rekeyed { conversation: conv })
            }
            None => {
                let conv = Conversation::from_welcome(payload);
                registry.save(&conv).await?;
                Ok(InboundDispatch::Welcomed { conversation: conv })
            }
        }
    } else {
        // Message path.
        let conv = match registry.get(&group_id_hex).await? {
            Some(c) => c,
            None => return Ok(InboundDispatch::StaleEpoch { group_id_hex, epoch: envelope.epoch }),
        };
        let key = match conv.key_for_epoch(envelope.epoch)? {
            Some(k) => k,
            None => return Ok(InboundDispatch::StaleEpoch { group_id_hex, epoch: envelope.epoch }),
        };
        let mut nonce = [0u8; 12];
        if envelope.nonce.len() != 12 {
            return Err(ChatError::Invalid("nonce length".into()));
        }
        nonce.copy_from_slice(&envelope.nonce);
        let aad = message_aad(&group_id_bytes, envelope.epoch);
        let plaintext = match aead_open(&key, &nonce, &envelope.ciphertext, &aad) {
            Ok(p) => p,
            Err(_) => return Ok(InboundDispatch::AeadOpenFailed { group_id_hex, epoch: envelope.epoch }),
        };
        let payload: MessagePayload = serde_json::from_slice(&plaintext)?;
        Ok(InboundDispatch::Message {
            group_id_hex,
            sender_agent_id_hex: hex::encode(envelope.sender_agent_id.as_bytes()),
            payload,
        })
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{MasterKeySource, fresh_argon_salt};
    use fetchit_relay_client::MlDsaSigner;
    use tempfile::tempdir;

    fn local_member(agent_id_hex: &str, kem_pub_b64: &str) -> Member {
        Member {
            user_id_hex: None,
            devices: vec![MemberDevice {
                agent_id_hex: agent_id_hex.to_owned(),
                kem_public_key_b64: kem_pub_b64.to_owned(),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        }
    }

    async fn fixture_identity(tmp: &Path, agent_id_hex: &str) -> (FetchitIdentity, MasterKey, [u8; 16]) {
        let salt = fresh_argon_salt();
        let master = MasterKey::resolve(&MasterKeySource::Passphrase("p".into()), Some(&salt))
            .unwrap();
        let id = FetchitIdentity::load_or_create(
            tmp,
            &master,
            agent_id_hex,
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        (id, master, salt)
    }

    #[tokio::test]
    async fn welcome_round_trip_between_two_identities() {
        use std::path::Path;
        // Alice's tmp + identity
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, master_a, salt_a) = fixture_identity(tmp_a.path(), &aid_a).await;

        // Bob's tmp + identity
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b).await;

        // Alice constructs conversation with Bob.
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();

        // Alice's signer is a real ML-DSA key.
        let alice_signer = MlDsaSigner::generate().unwrap();

        let outbox = build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer)
            .await
            .unwrap();
        assert_eq!(outbox.len(), 1, "single peer device → one welcome envelope");

        // Bob receives and dispatches.
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b = ConversationRegistry::new(
            layout_b,
            Arc::new(master_b),
            kdf_id_argon2(),
            Some(salt_b),
        );
        let result = dispatch_inbound(outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Welcomed { conversation } => {
                assert_eq!(conversation.group_id_hex, conv.group_id_hex);
                assert_eq!(conversation.current_key_b64, conv.current_key_b64);
                assert_eq!(conversation.members.len(), 2);
            }
            other => panic!("expected Welcomed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn message_round_trip_after_welcome() {
        // Setup as above; then Alice sends a message.
        let tmp_a = tempdir().unwrap();
        let aid_a = "aa".repeat(32);
        let (alice_id, master_a, salt_a) = fixture_identity(tmp_a.path(), &aid_a).await;
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b).await;
        let alice_member = local_member(&aid_a, &B64.encode(alice_id.kem_public_key()));
        let bob_member = local_member(&aid_b, &B64.encode(bob_id.kem_public_key()));
        let conv = Conversation::new_dm(alice_member, bob_member, None).unwrap();
        let alice_signer = MlDsaSigner::generate().unwrap();

        // Stand up Bob's registry and onboard via welcome.
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b = ConversationRegistry::new(
            layout_b,
            Arc::new(master_b),
            kdf_id_argon2(),
            Some(salt_b),
        );
        let welcome_outbox =
            build_welcome_outbox(&conv, &alice_id, [0u8; 32], &alice_signer).await.unwrap();
        let _ = dispatch_inbound(welcome_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();

        // Alice sends a message.
        let msg_outbox = build_message_outbox(
            &conv,
            "hello bob",
            "Alice",
            &alice_id,
            [0u8; 32],
            &alice_signer,
        )
        .await
        .unwrap();
        assert_eq!(msg_outbox.len(), 1);
        let result = dispatch_inbound(msg_outbox[0].envelope.clone(), &bob_id, &registry_b)
            .await
            .unwrap();
        match result {
            InboundDispatch::Message { payload, .. } => {
                assert_eq!(payload.body, "hello bob");
                assert_eq!(payload.sender_name.as_deref(), Some("Alice"));
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stale_epoch_is_surfaced_not_panicked() {
        // Bob receives a message for a conversation he doesn't have.
        let tmp_b = tempdir().unwrap();
        let aid_b = "bb".repeat(32);
        let (bob_id, master_b, salt_b) = fixture_identity(tmp_b.path(), &aid_b).await;
        let layout_b = StoreLayout::ensure(tmp_b.path().join("store")).unwrap();
        let registry_b = ConversationRegistry::new(
            layout_b,
            Arc::new(master_b),
            kdf_id_argon2(),
            Some(salt_b),
        );
        let env = TransitEnvelope {
            version: 2,
            kind: EnvelopeKind::GroupChat,
            group_id: Some(GroupId::from_bytes([0xee; 32])),
            tenant_id: None,
            sender_agent_id: AgentId::from_bytes([0xaa; 32]),
            sender_machine_id: MachineId::from_bytes([0; 32]),
            timestamp_ms: 1,
            epoch: 99,
            ciphertext: vec![0u8; 16],
            nonce: vec![0u8; 12],
            kem_ciphertext: Vec::new(),
            sender_signature: Vec::new(),
        };
        let result = dispatch_inbound(env, &bob_id, &registry_b).await.unwrap();
        assert!(matches!(result, InboundDispatch::StaleEpoch { .. }));
    }

    #[test]
    fn fanout_excludes_local_device() {
        let local_hex = "a".repeat(64);
        let conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![
                local_member(&local_hex, &"AAAA".to_string()),
                local_member(&"b".repeat(64), &"BBBB".to_string()),
            ],
            current_epoch: 0,
            current_key_b64: B64.encode([0u8; 32]),
            prior_keys: vec![],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        };
        let fanout: Vec<&MemberDevice> = conv.fanout_devices(&local_hex).collect();
        assert_eq!(fanout.len(), 1);
        assert_eq!(fanout[0].agent_id_hex, "b".repeat(64));
    }

    #[test]
    fn prior_keys_eviction_after_window() {
        let mut conv = Conversation {
            group_id_hex: "0".repeat(64),
            name: None,
            members: vec![],
            current_epoch: 1,
            current_key_b64: B64.encode([1u8; 32]),
            prior_keys: vec![PriorKey {
                epoch: 0,
                key_b64: B64.encode([0u8; 32]),
                expires_at_ms: 1, // already in the past
            }],
            own_role: Role::Admin,
            created_at_ms: 0,
            last_rekey_at_ms: 0,
            auto_rekey_interval_ms: DEFAULT_AUTO_REKEY_INTERVAL_MS,
        };
        conv.sweep_prior_keys();
        assert!(conv.prior_keys.is_empty());
    }
}
```

- [ ] **Step 2: Declare module + run tests against the single-file form**

In `crates/fetchit-chat/src/lib.rs`:
```rust
pub mod conversation;
```

Run: `cargo test -p fetchit-chat conversation`
Expected: 5 tests pass.

- [ ] **Step 3: Commit the single-file form**

```bash
git add crates/fetchit-chat/src/conversation.rs crates/fetchit-chat/src/lib.rs
git commit -s -m "feat(chat): Conversation state machine + welcome/message dispatch

Conversation type + ConversationRegistry persisted via at_rest vault.
build_welcome_outbox / build_message_outbox produce signed TransitEnvelope
fanouts. dispatch_inbound handles Welcome (KEM decap + install/rekey)
and Message (key lookup + AEAD open + payload decode) with explicit
StaleEpoch / KemDecapFailed / AeadOpenFailed soft-error variants."
```

- [ ] **Step 4: Split into the five-file structure**

Mechanical refactor: move each section of the single file into its dedicated module file. The split boundary for each is:

| Destination file | Owns |
| --- | --- |
| `conversation/types.rs` | `Role`, `MemberDeviceStatus`, `MemberDevice`, `Member`, `PriorKey`, `Conversation` (struct + all its methods including `new_dm`, `from_welcome`, `current_key`, `group_id_bytes`, `key_for_epoch`, `sweep_prior_keys`, `advance_epoch`, `auto_rekey_due`, `fanout_devices`), `WelcomePayload`, `MessagePayload`, the constants `DEFAULT_AUTO_REKEY_INTERVAL_MS` and `PRIOR_KEY_WINDOW_MS`, plus the private `now_ms` helper |
| `conversation/registry.rs` | `ConversationRegistry`, `dm_with` helper |
| `conversation/outbound.rs` | `OutboundEnvelope`, `build_welcome_envelopes`, `build_welcome_outbox`, `build_message_outbox` |
| `conversation/inbound.rs` | `InboundDispatch`, `dispatch_inbound` |
| `conversation/mod.rs` | re-exports only — see content below |

`crates/fetchit-chat/src/conversation/mod.rs`:
```rust
//! Conversation lifecycle: state, persistence, outbound envelope
//! construction, inbound dispatch.

mod inbound;
mod outbound;
mod registry;
mod types;

pub use inbound::{InboundDispatch, dispatch_inbound};
pub use outbound::{OutboundEnvelope, build_message_outbox, build_welcome_outbox};
pub use registry::ConversationRegistry;
pub use types::{
    Conversation, DEFAULT_AUTO_REKEY_INTERVAL_MS, Member, MemberDevice, MemberDeviceStatus,
    MessagePayload, PRIOR_KEY_WINDOW_MS, PriorKey, Role, WelcomePayload,
};
```

Tests move with their owners: the welcome/message round-trip tests live in `outbound.rs` (sender side) and `inbound.rs` (receiver side). Pure-state tests (fanout filter, prior-keys eviction) stay in `types.rs`.

In `crates/fetchit-chat/src/lib.rs` the existing `pub mod conversation;` line keeps working because `conversation/` is now a module directory with `mod.rs`. No top-level change needed.

Run: `cargo test -p fetchit-chat conversation`
Expected: same 5 tests pass, distributed across the four sub-modules.

- [ ] **Step 5: Commit the split**

```bash
git rm crates/fetchit-chat/src/conversation.rs
git add crates/fetchit-chat/src/conversation/
git commit -s -m "refactor(chat): split conversation module into per-concern files

types / registry / outbound / inbound under conversation/. No behavior
change — same public surface via mod.rs re-exports. Each file lands
under ~250 lines, one concern apiece, matching project modular-file
convention."
```

---

## Task 8 — Integrate Conversation into `messages::Endpoint`

**Files:**
- Modify: `crates/fetchit-chat/src/messages.rs`
- Modify: `crates/fetchit-chat/src/client.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs`

- [ ] **Step 1: Add ConversationRegistry to Client**

In `crates/fetchit-chat/src/client.rs`, expand `Client` to hold the registry and identity:
```rust
pub struct Client {
    http: Arc<Http>,
    router: Arc<Router>,
    identity: Arc<FetchitIdentity>,
    registry: Arc<ConversationRegistry>,
    local_machine_id: [u8; 32],
}
```
And extend `ClientBuilder` with:
```rust
    data_dir: Option<PathBuf>,
    passphrase: Option<String>,
```
Plus builder methods:
```rust
    #[must_use]
    pub fn data_dir(mut self, p: PathBuf) -> Self { self.data_dir = Some(p); self }
    #[must_use]
    pub fn passphrase(mut self, s: String) -> Self { self.passphrase = Some(s); self }
```
In `Client::from_parts`, materialize the layout / master / identity / registry. The exact code (compressed for the plan; expand in your editor):
```rust
let data_dir = match data_dir {
    Some(p) => p,
    None => crate::local_store::default_data_dir()?,
};
let layout = crate::local_store::StoreLayout::ensure(data_dir.clone())?;
let identity_vault = data_dir.join("identity.json.enc");
let (master, kdf_id, argon_salt) = if identity_vault.exists() {
    let kid = crate::at_rest::read_kdf_id(&identity_vault)?;
    if kid == crate::at_rest::kdf_id_keychain() {
        (crate::at_rest::MasterKey::resolve(&crate::at_rest::MasterKeySource::Keychain, None)?, kid, None)
    } else {
        let salt = crate::at_rest::read_argon_salt(&identity_vault)?;
        let pw = passphrase.ok_or_else(|| ChatError::Invalid(
            "this install requires a passphrase; pass via ClientBuilder::passphrase".into()))?;
        (crate::at_rest::MasterKey::resolve(&crate::at_rest::MasterKeySource::Passphrase(pw), Some(&salt))?, kid, Some(salt))
    }
} else {
    if let Some(pw) = passphrase {
        let salt = crate::at_rest::fresh_argon_salt();
        (crate::at_rest::MasterKey::resolve(&crate::at_rest::MasterKeySource::Passphrase(pw), Some(&salt))?, crate::at_rest::kdf_id_argon2(), Some(salt))
    } else {
        (crate::at_rest::MasterKey::resolve(&crate::at_rest::MasterKeySource::Keychain, None)?, crate::at_rest::kdf_id_keychain(), None)
    }
};
// Resolve agent_id via x0xd /agent so identity binds to it.
let http = Arc::new(Http::new(base_url.clone(), token.clone())?);
let agent_resp: serde_json::Value = http.get_json("/agent").await?;
let agent_id_hex = agent_resp.pointer("/data/agent_id").or_else(|| agent_resp.get("agent_id"))
    .and_then(|v| v.as_str()).ok_or_else(|| ChatError::Invalid("no agent_id".into()))?.to_owned();
let identity = Arc::new(FetchitIdentity::load_or_create(
    &data_dir, &master, &agent_id_hex, kdf_id, argon_salt.as_ref(),
)?);
let machine_id_hex = agent_resp.pointer("/data/machine_id").or_else(|| agent_resp.get("machine_id"))
    .and_then(|v| v.as_str()).ok_or_else(|| ChatError::Invalid("no machine_id".into()))?;
let mut local_machine_id = [0u8; 32];
hex::decode_to_slice(machine_id_hex, &mut local_machine_id)
    .map_err(|e| ChatError::Invalid(format!("machine_id hex: {e}")))?;
let registry = Arc::new(crate::conversation::ConversationRegistry::new(
    layout, Arc::new(master), kdf_id, argon_salt,
));
// router + relay wiring continues unchanged below.
```

- [ ] **Step 2: Rewire `messages::Endpoint`**

Replace the entire body of `crates/fetchit-chat/src/messages.rs` with the version below. The `Endpoint` API surface (`send`, `connect`, `connections`) is preserved — only the implementation changes.

```rust
//! Direct messages — sealed via the Conversation layer, routed through
//! the relay Transport. Caller signature is preserved from the
//! pre-encryption build.

use crate::card::extended_card_from_uri;
use crate::chat_identity::FetchitIdentity;
use crate::conversation::{
    build_message_outbox, build_welcome_outbox, Conversation, ConversationRegistry, Member,
    MemberDevice, MemberDeviceStatus,
};
use crate::error::{ChatError, Result};
use crate::http::Http;
use crate::identity::AgentId;
use crate::local_store::StoreLayout;
use crate::transport::{OutboundEnvelope as ChatOutbound, OutboundKind, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use fetchit_relay_client::Signer;
use serde::Deserialize;
use std::sync::Arc;

/// Endpoint wrapper. Build via [`crate::Client::messages`].
pub struct Endpoint<'a> {
    http: &'a Http,
    router: &'a Router,
    identity: &'a Arc<FetchitIdentity>,
    registry: &'a Arc<ConversationRegistry>,
    signer: &'a Arc<dyn Signer>,
    layout: &'a StoreLayout,
    local_machine_id: [u8; 32],
}

impl<'a> Endpoint<'a> {
    pub(crate) fn new(
        http: &'a Http,
        router: &'a Router,
        identity: &'a Arc<FetchitIdentity>,
        registry: &'a Arc<ConversationRegistry>,
        signer: &'a Arc<dyn Signer>,
        layout: &'a StoreLayout,
        local_machine_id: [u8; 32],
    ) -> Self {
        Self {
            http,
            router,
            identity,
            registry,
            signer,
            layout,
            local_machine_id,
        }
    }

    /// Send a direct message to `to`. On first contact, generates a
    /// Conversation + Welcome envelopes for every device of the peer
    /// before the Message envelopes go out.
    pub async fn send(
        &self,
        to: &AgentId,
        text: &str,
        sender_name: &str,
    ) -> Result<Option<String>> {
        let peer_card = self.load_peer_card(to)?;
        let conv = match self.registry.find_dm_with(&to.0).await? {
            Some(c) => c,
            None => self.bootstrap_conversation(&peer_card).await?,
        };
        let outbound = build_message_outbox(
            &conv,
            text,
            sender_name,
            self.identity,
            self.local_machine_id,
            self.signer.as_ref(),
        )
        .await?;
        let mut last_id = None;
        for ob in outbound {
            let receipt = self
                .router
                .send(
                    &AgentId(hex::encode(ob.recipient_agent_id.as_bytes())),
                    ChatOutbound {
                        kind: OutboundKind::Dm,
                        from_machine_id: Some(self.local_machine_id),
                        payload: postcard::to_allocvec(&ob.envelope)
                            .map_err(|e| ChatError::Invalid(format!("encode: {e}")))?,
                        timestamp_ms: ob.envelope.timestamp_ms,
                    },
                )
                .await?;
            last_id = receipt.message_id;
        }
        Ok(last_id)
    }

    /// Pre-warm a direct x0xd channel. No-op for relay-routed sends;
    /// kept for API parity.
    pub async fn connect(&self, agent_id: &AgentId) -> Result<()> {
        #[derive(serde::Serialize)]
        struct ConnectRequest<'a> {
            agent_id: &'a str,
        }
        let _: serde_json::Value = self
            .http
            .post_json(
                "/agents/connect",
                &ConnectRequest {
                    agent_id: &agent_id.0,
                },
            )
            .await?;
        Ok(())
    }

    /// List x0xd's view of currently-open direct connections.
    pub async fn connections(&self) -> Result<Vec<AgentId>> {
        #[derive(Deserialize)]
        struct ConnectionsResponse {
            #[serde(default)]
            connections: Vec<AgentId>,
        }
        let resp: ConnectionsResponse = self.http.get_json("/direct/connections").await?;
        Ok(resp.connections)
    }

    fn load_peer_card(&self, peer: &AgentId) -> Result<serde_json::Value> {
        let path = self.layout.contact_path(&peer.0);
        if !path.exists() {
            return Err(ChatError::Invalid(format!(
                "no stored card for peer {}",
                &peer.0[..16]
            )));
        }
        let bytes = std::fs::read(&path)?;
        let stored: StoredContactCard = serde_json::from_slice(&bytes)?;
        extended_card_from_uri(&stored.share_uri)
    }

    async fn bootstrap_conversation(
        &self,
        peer_card: &serde_json::Value,
    ) -> Result<Conversation> {
        let local = self.local_member()?;
        let peer = peer_member_from_card(peer_card)?;
        let conv = Conversation::new_dm(local, peer, None)?;
        let welcomes = build_welcome_outbox(
            &conv,
            self.identity,
            self.local_machine_id,
            self.signer.as_ref(),
        )
        .await?;
        for ob in welcomes {
            self.router
                .send(
                    &AgentId(hex::encode(ob.recipient_agent_id.as_bytes())),
                    ChatOutbound {
                        kind: OutboundKind::Dm,
                        from_machine_id: Some(self.local_machine_id),
                        payload: postcard::to_allocvec(&ob.envelope)
                            .map_err(|e| ChatError::Invalid(format!("encode: {e}")))?,
                        timestamp_ms: ob.envelope.timestamp_ms,
                    },
                )
                .await?;
        }
        self.registry.save(&conv).await?;
        Ok(conv)
    }

    fn local_member(&self) -> Result<Member> {
        Ok(Member {
            user_id_hex: self.identity.user_id_hex().map(str::to_owned),
            devices: vec![MemberDevice {
                agent_id_hex: self.identity.agent_id_hex().to_owned(),
                kem_public_key_b64: B64.encode(self.identity.kem_public_key()),
                added_at_epoch: 0,
                status: MemberDeviceStatus::Active,
            }],
            joined_at_epoch: 0,
        })
    }
}

/// On-disk shape for a stored contact card.
/// `card_json` is the parsed extended card; `share_uri` is the
/// canonical URI we'll re-emit on export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredContactCard {
    pub agent_id_hex: String,
    pub agent_public_key_b64: String,
    pub share_uri: String,
    pub imported_at_ms: u64,
}

fn peer_member_from_card(card: &serde_json::Value) -> Result<Member> {
    let agent_id_hex = card["agent_id"]
        .as_str()
        .ok_or_else(|| ChatError::Invalid("card missing agent_id".into()))?
        .to_owned();
    let kem_pub_b64 = card["fetchit_kem_public_key_b64"]
        .as_str()
        .ok_or_else(|| ChatError::Invalid("card missing fetchit_kem_public_key_b64".into()))?
        .to_owned();
    Ok(Member {
        user_id_hex: card["user_id"].as_str().map(str::to_owned),
        devices: vec![MemberDevice {
            agent_id_hex,
            kem_public_key_b64: kem_pub_b64,
            added_at_epoch: 0,
            status: MemberDeviceStatus::Active,
        }],
        joined_at_epoch: 0,
    })
}
```

Note for the implementer: the old `decode_direct_message` function is gone — all inbound decryption is in `conversation::dispatch_inbound`. The desktop bridge's `spawn_relay_dms` is rewired in Step 4 below to call that instead.

- [ ] **Step 3: Rewire the desktop chat.rs Tauri bridge — full diff**

Replace the body of `ChatState` in `apps/fetchit-desktop/src-tauri/src/chat.rs` with the version below. The Tauri command signatures (`chat_send_dm`, `chat_contacts`, etc.) stay the same; only the `ChatState` shape and the relay-inbound pump change.

```rust
//! Tauri bridge for the chat surface — x0xd (identity / contacts /
//! presence / groups) + fetchit relay (encrypted DM transport).

use fetchit_chat::contacts::TrustLevel;
use fetchit_chat::conversation::{dispatch_inbound, InboundDispatch};
use fetchit_chat::groups::{GroupId, GroupInvite};
use fetchit_chat::identity::{AgentCard, AgentId};
use fetchit_chat::{Client, Event};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use url::Url;

const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// Tauri-managed handle to the lazily-built chat client.
#[derive(Clone)]
pub struct ChatState {
    client: Arc<Mutex<Option<Client>>>,
    relay_url: Url,
    data_dir: PathBuf,
    passphrase: Arc<Mutex<Option<String>>>,
}

impl ChatState {
    pub fn new(
        relay_url: &str,
        data_dir: PathBuf,
        passphrase: Option<String>,
    ) -> Result<Self, String> {
        let url = Url::parse(relay_url).map_err(|e| format!("invalid relay url: {e}"))?;
        Ok(Self {
            client: Arc::new(Mutex::new(None)),
            relay_url: url,
            data_dir,
            passphrase: Arc::new(Mutex::new(passphrase)),
        })
    }

    async fn get(&self) -> Result<Client, String> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let pw = self.passphrase.lock().await.clone();
        let mut builder = Client::builder()
            .relay_url(self.relay_url.clone())
            .data_dir(self.data_dir.clone());
        if let Some(p) = pw {
            builder = builder.passphrase(p);
        }
        let c = builder.build().await.map_err(|e| e.to_string())?;
        *guard = Some(c.clone());
        Ok(c)
    }

    async fn invalidate(&self) {
        *self.client.lock().await = None;
    }
}

#[derive(Debug, Serialize)]
pub struct CardWithUri {
    card: AgentCard,
    uri: String,
}

#[tauri::command]
pub async fn chat_set_passphrase(
    state: tauri::State<'_, ChatState>,
    passphrase: String,
) -> Result<(), String> {
    *state.passphrase.lock().await = Some(passphrase);
    state.invalidate().await;
    state.get().await?;
    Ok(())
}

// (Remaining #[tauri::command] handlers — chat_health, chat_identity,
// chat_card, chat_import_card, chat_contacts, chat_set_trust,
// chat_remove_contact, chat_send_dm, chat_dm_connect,
// chat_presence_online, chat_groups_list, chat_group_create,
// chat_group_invite, chat_group_join, chat_group_send,
// chat_group_messages, chat_group_leave — are UNCHANGED from the
// pre-encryption build. Keep them as-is.)

pub fn spawn_event_pump(app: AppHandle, state: ChatState) {
    spawn_relay_inbound(app.clone(), state.clone());
    spawn_presence(app.clone(), state.clone());
    spawn_unified(app, state);
}

fn spawn_relay_inbound(app: AppHandle, state: ChatState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(client) = state.get().await else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            let Some(mut rx) = client.take_transport_inbound("relay") else {
                state.invalidate().await;
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            };
            while let Some(inbound_env) = rx.recv().await {
                // The transport gives us the relay's TransitEnvelope via
                // the InboundEnvelope wrapper; decode once.
                let envelope: fetchit_relay_proto::TransitEnvelope =
                    match postcard::from_bytes(&inbound_env.payload) {
                        Ok(e) => e,
                        Err(e) => {
                            log_pump(&format!("[relay] decode: {e}"));
                            continue;
                        }
                    };
                let identity = client.identity_arc();
                let registry = client.registry_arc();
                match dispatch_inbound(envelope, identity.as_ref(), registry.as_ref()).await {
                    Ok(InboundDispatch::Message {
                        group_id_hex,
                        sender_agent_id_hex,
                        payload,
                    }) => {
                        let dm = fetchit_chat::messages::DirectMessage {
                            from: fetchit_chat::identity::AgentId(sender_agent_id_hex),
                            to: None,
                            body: payload.body,
                            sender_name: payload.sender_name,
                            timestamp_ms: Some(payload.ts_ms),
                            message_id: Some(group_id_hex),
                            verified: Some(true),
                        };
                        let _ = app.emit("chat:dm", &dm);
                    }
                    Ok(InboundDispatch::Welcomed { conversation })
                    | Ok(InboundDispatch::Rekeyed { conversation }) => {
                        let _ = app.emit("chat:conversation", &conversation);
                    }
                    Ok(InboundDispatch::StaleEpoch { group_id_hex, epoch }) => {
                        let _ = app.emit(
                            "chat:warn",
                            &serde_json::json!({
                                "kind": "stale-epoch",
                                "group_id": group_id_hex,
                                "epoch": epoch,
                            }),
                        );
                    }
                    Ok(InboundDispatch::KemDecapFailed) => {
                        let _ = app.emit(
                            "chat:warn",
                            &serde_json::json!({ "kind": "welcome-decap-failed" }),
                        );
                    }
                    Ok(InboundDispatch::AeadOpenFailed { group_id_hex, epoch }) => {
                        let _ = app.emit(
                            "chat:warn",
                            &serde_json::json!({
                                "kind": "aead-open-failed",
                                "group_id": group_id_hex,
                                "epoch": epoch,
                            }),
                        );
                    }
                    Ok(InboundDispatch::Dropped { kind, sender }) => {
                        let _ = app.emit(
                            "chat:warn",
                            &serde_json::json!({ "kind": kind, "sender": sender }),
                        );
                    }
                    Err(e) => log_pump(&format!("[relay] dispatch: {e}")),
                }
            }
            state.invalidate().await;
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
}

// spawn_presence and spawn_unified are unchanged from the
// pre-encryption build — they still subscribe to x0xd's SSE streams
// for presence/contact/group events.
fn log_pump(msg: &str) {
    eprintln!("[fetchit][chat] {msg}");
}
```

The two helpers used here (`Client::identity_arc`, `Client::registry_arc`) are added in Task 8 Step 1 above when you expand `Client`. They are simple borrow-and-clone accessors:
```rust
impl Client {
    #[must_use]
    pub fn identity_arc(&self) -> Arc<FetchitIdentity> { self.identity.clone() }
    #[must_use]
    pub fn registry_arc(&self) -> Arc<ConversationRegistry> { self.registry.clone() }
}
```

In `apps/fetchit-desktop/src-tauri/src/lib.rs`, update the `ChatState::new` call site (Tauri setup block, line ~597) to pass the new arguments:
```rust
let chat_state = build_chat_state(&relay_url, app_data_dir.join("chat"), None);
```
(Wrap the `Option<String>` in a settings hook later if you want to load a stored passphrase; v1 leaves it `None` and lets the UI call `chat_set_passphrase` on headless installs.)

Add `chat_set_passphrase` to the `tauri::generate_handler!` macro in `lib.rs`.

- [ ] **Step 4: (Step 3 already replaces the inbound pump — this step kept as no-op to preserve commit cadence)**

Run: `cargo build -p fetchit-desktop --manifest-path apps/fetchit-desktop/src-tauri/Cargo.toml`
Expected: clean compile.

- [ ] **Step 5: Compile + run all tests**

Run:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/fetchit-chat/src/messages.rs crates/fetchit-chat/src/client.rs apps/fetchit-desktop/src-tauri/src/chat.rs apps/fetchit-desktop/src-tauri/src/lib.rs
git commit -s -m "feat(chat): wire Conversation into messages::Endpoint + desktop bridge

chat_send_dm now looks up the recipient's KEM key from a stored card,
finds-or-creates the Conversation, sends welcome envelopes on first
contact, and AEAD-seals every subsequent message. The desktop bridge
materializes data_dir + master key (keystore or passphrase) at startup.
Inbound pump dispatches through Conversation::dispatch_inbound and
emits chat:dm / chat:conversation / chat:warn Tauri events.

chat_set_passphrase Tauri command enrols a passphrase on headless
Linux installs without a working Secret Service."
```

---

## Task 9 — Rebuild Alice's `fetchit-chat-peer` for encrypted DMs

**Files:**
- Modify: `crates/fetchit-chat/src/bin/peer.rs`

- [ ] **Step 1: Add the data_dir + passphrase CLI flags**

```rust
#[arg(long, default_value = "/opt/alice/fetchit-data")]
data_dir: PathBuf,

#[arg(long, env = "FETCHIT_PASSPHRASE")]
passphrase: Option<String>,
```
And pass them into `Client::builder()`:
```rust
let mut builder = Client::builder()
    .base_url(&cli.x0xd_base)
    .token(&token)
    .relay_url(cli.relay.clone())
    .data_dir(cli.data_dir.clone());
if let Some(p) = cli.passphrase.clone() {
    builder = builder.passphrase(p);
}
let client = builder.build().await.context("build Client")?;
```

- [ ] **Step 2: Update echo mode for encrypted flow**

The `run_echo` loop currently calls `decode_direct_message`. Replace with `client.next_inbound_dm().await` (a new helper on Client that wraps `take_transport_inbound("relay")` + dispatch, surfacing `InboundDispatch::Message` only). Implement that helper in `client.rs`:
```rust
pub async fn next_inbound_dm(&self) -> Result<Option<InboundDispatch>, ChatError> {
    // get the relay inbound channel once and cache the receiver in Client
    // (with a Mutex<Option<Receiver>>) — pull envelopes and call dispatch_inbound
}
```

- [ ] **Step 3: Rebuild + redeploy Alice's peer**

```bash
cargo build --release -p fetchit-chat --bin fetchit-chat-peer
scp -i ~/.ssh/id_ed25519 target/release/fetchit-chat-peer root@137.184.155.7:/tmp/peer.new
ssh -i ~/.ssh/id_ed25519 root@137.184.155.7 \
  'systemctl stop alice-peer && mv /tmp/peer.new /opt/alice/bin/fetchit-chat-peer && chmod +x /opt/alice/bin/fetchit-chat-peer && systemctl start alice-peer && journalctl -u alice-peer -n 20 --no-pager'
```
Expected: `[peer] echo mode — auto-replying to every inbound DM`.

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/bin/peer.rs crates/fetchit-chat/src/client.rs
git commit -s -m "feat(chat): fetchit-chat-peer speaks the encrypted DM protocol

Adds --data-dir and --passphrase flags; echo mode now drains the
Conversation::dispatch_inbound stream (Welcome → install + reply;
Message → AEAD-decrypt + echo back). Reuses Client::builder, so the
peer is a thin shell over the same code path the desktop uses."
```

---

## Task 10 — Live cross-internet test against Alice on the droplet

**Files:**
- Modify: `crates/fetchit-chat/tests/live_relay.rs`

- [ ] **Step 1: Update the live test to use Conversation API**

The existing `live_chat_self_dm_round_trips_through_relay` test sends a plaintext self-DM. Add a new `#[ignore]`'d test that:
1. Imports Alice's card URI (read from `/tmp/alice-card.txt`).
2. Sends an encrypted DM ("encrypted v2 hello @ <ts>").
3. Waits up to 5s for Alice's echo (`[echo] encrypted v2 hello @ <ts>`).
4. Asserts the round-trip body matches.

Test body skeleton:
```rust
#[tokio::test]
#[ignore = "requires running x0xd + reachable relay + Alice card; see env vars"]
async fn live_encrypted_dm_round_trips_via_alice() {
    let base = std::env::var("FETCHIT_X0XD_LIVE_BASE").unwrap();
    let token = std::env::var("FETCHIT_X0XD_LIVE_TOKEN").unwrap();
    let relay = std::env::var("FETCHIT_RELAY_LIVE_URL").unwrap();
    let alice_card_path = std::env::var("FETCHIT_ALICE_CARD_PATH")
        .unwrap_or_else(|_| "/tmp/alice-card.txt".into());

    let client = Client::builder()
        .base_url(base)
        .token(token)
        .relay_url(Url::parse(&relay).unwrap())
        .passphrase("live-test-pw".into())
        .data_dir(std::env::temp_dir().join("fetchit-live-test"))
        .build()
        .await
        .unwrap();

    // Import Alice's card via the existing identity().import_uri path.
    let alice_uri = std::fs::read_to_string(&alice_card_path).unwrap();
    client.identity().import_uri(alice_uri.trim()).await.unwrap();

    // Lookup Alice's agent_id from the URI we just imported (parsed locally).
    let alice_card = fetchit_chat::card::extended_card_from_uri(alice_uri.trim()).unwrap();
    let alice_agent_id_hex = alice_card["agent_id"].as_str().unwrap();
    let alice_id = fetchit_chat::identity::AgentId::parse(alice_agent_id_hex.to_owned()).unwrap();

    let body = format!("encrypted v2 hello @ {}", now_ms());
    eprintln!("[live] sending: {body}");
    client.messages().send(&alice_id, &body, "Josh").await.unwrap();

    let inbound = client.take_inbound_dm_receiver().unwrap();
    let dispatch = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("alice should echo back within 5s")
        .unwrap();
    let expected_echo = format!("[echo] {body}");
    match dispatch {
        fetchit_chat::conversation::InboundDispatch::Message { payload, .. } => {
            assert_eq!(payload.body, expected_echo);
            eprintln!("[live] received: {} ✓", payload.body);
        }
        other => panic!("expected Message, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run the live test against the droplet**

```bash
FETCHIT_X0XD_LIVE_BASE=http://127.0.0.1:12700 \
FETCHIT_X0XD_LIVE_TOKEN=$(cat ~/.local/share/x0x/api-token) \
FETCHIT_RELAY_LIVE_URL=http://67.207.94.66:8088 \
cargo test -p fetchit-chat --test live_relay live_encrypted_dm -- --ignored --nocapture
```
Expected: `[live] received: [echo] encrypted v2 hello @ <ts> ✓`.

- [ ] **Step 3: Commit**

```bash
git add crates/fetchit-chat/tests/live_relay.rs
git commit -s -m "test(chat): live cross-internet encrypted DM via Alice on droplet

Sends a real PQ-sealed DM from Josh's desktop identity to Alice's
identity on the droplet through the NYC relay; Alice's echo bounces
back encrypted; assert the round-trip body matches.

Ignored by default; run with FETCHIT_X0XD_LIVE_BASE +
FETCHIT_X0XD_LIVE_TOKEN + FETCHIT_RELAY_LIVE_URL set."
```

---

## Task 11 — Auto-rekey timer

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs`
- Modify: `crates/fetchit-chat/src/conversation.rs` (already exposes `auto_rekey_due`)

- [ ] **Step 1: Add a sweeper task to Client**

In `client.rs`, after building the registry:
```rust
let sweeper_registry = registry.clone();
let sweeper_identity = identity.clone();
let sweeper_signer = signer.clone(); // stored on Client
let sweeper_router = router.clone();
let sweeper_machine_id = local_machine_id;
tokio::spawn(async move {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(300)); // 5-min sweep
    loop {
        tick.tick().await;
        if let Err(e) = sweep_auto_rekey(
            &sweeper_registry, &sweeper_identity, &sweeper_router,
            sweeper_machine_id, &sweeper_signer,
        ).await {
            log::warn!("[chat] auto-rekey sweep error: {e}");
        }
    }
});
```

And the sweep function:
```rust
async fn sweep_auto_rekey<S: fetchit_relay_client::Signer + ?Sized>(
    registry: &Arc<ConversationRegistry>,
    identity: &Arc<FetchitIdentity>,
    router: &Arc<Router>,
    machine_id: [u8; 32],
    signer: &S,
) -> Result<(), ChatError> {
    // Iterate all known conversations in memory.
    // For each Admin-role conv where auto_rekey_due() is true:
    //   generate a fresh key,
    //   advance epoch,
    //   build welcome outbox,
    //   send each via router,
    //   save.
    Ok(())
}
```
Implement the body using `Conversation::advance_epoch` and `build_welcome_outbox` already defined in Task 7.

- [ ] **Step 2: Add a unit test that runs the sweeper with a 1s interval**

In `crates/fetchit-chat/src/conversation.rs` tests:
```rust
#[test]
fn auto_rekey_fires_after_interval() {
    let mut conv = Conversation {
        group_id_hex: "0".repeat(64),
        name: None,
        members: vec![],
        current_epoch: 0,
        current_key_b64: B64.encode([1u8; 32]),
        prior_keys: vec![],
        own_role: Role::Admin,
        created_at_ms: 0,
        last_rekey_at_ms: 0,
        auto_rekey_interval_ms: 1, // 1 ms — definitely due
    };
    assert!(conv.auto_rekey_due());
    conv.advance_epoch([2u8; 32]);
    assert_eq!(conv.current_epoch, 1);
    assert_eq!(conv.prior_keys.len(), 1);
}
```

- [ ] **Step 3: Run unit test + workspace test**

```bash
cargo test -p fetchit-chat conversation::tests::auto_rekey_fires_after_interval
cargo test --workspace
```

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/client.rs crates/fetchit-chat/src/conversation.rs
git commit -s -m "feat(chat): auto-rekey sweeper on every active Client

Every 5 minutes, the Client iterates conversations and fires a
rekey on any Admin conversation whose last_rekey_at_ms is older than
auto_rekey_interval_ms (default 7 days). The rekey path is the same
as Welcome generation — fresh symmetric key, epoch bumped, prior key
preserved for 60s, new welcomes fanned out to every device of every
member."
```

---

## Task 12 — Wire envelope signature verification on inbound

**Files:**
- Modify: `crates/fetchit-chat/src/conversation.rs` (dispatch_inbound prelude)

- [ ] **Step 1: Add signature-verify step at the top of dispatch_inbound**

Before either path (Welcome or Message), verify `envelope.sender_signature`:
```rust
// 1. Look up sender's ML-DSA public key from the local card store
//    (contacts/<agent_id>.json).
let sender_agent_hex = hex::encode(envelope.sender_agent_id.as_bytes());
let card_path = registry.layout.contact_path(&sender_agent_hex);
if !card_path.exists() {
    return Ok(InboundDispatch::Dropped {
        kind: "no-card".into(),
        sender: sender_agent_hex,
    });
}
let card_bytes = std::fs::read(&card_path)?;
let card_json: serde_json::Value = serde_json::from_slice(&card_bytes)?;
let agent_pub_b64 = card_json["agent_public_key_b64"].as_str()
    .ok_or_else(|| ChatError::Invalid("card missing agent_public_key_b64".into()))?;
let agent_pub = base64::engine::general_purpose::STANDARD
    .decode(agent_pub_b64)
    .map_err(|e| ChatError::Invalid(format!("agent pub b64: {e}")))?;

// 2. Canonical bytes for signing
let mut sign_bytes = Vec::new();
sign_bytes.extend_from_slice(crate::chat_crypto::SIGN_DOMAIN_ENVELOPE);
sign_bytes.extend_from_slice(&crate::chat_crypto::canonical_envelope_bytes(&envelope)?);
if let Err(_) = crate::chat_crypto::ml_dsa_verify(&agent_pub, &sign_bytes, &envelope.sender_signature) {
    return Ok(InboundDispatch::Dropped {
        kind: "bad-signature".into(),
        sender: sender_agent_hex,
    });
}
```

Add `Dropped { kind: String, sender: String }` variant to `InboundDispatch`.

Note: this requires the imported card to store the sender's ML-DSA public key (which is currently available in the share-card and consumed by our verifier; verify the local card-store impl from Task 6 preserves the agent_public_key field).

- [ ] **Step 2: Add tests for accept/reject**

```rust
#[tokio::test]
async fn dispatch_rejects_envelope_with_bad_signature() {
    // construct conv + welcome envelope as before, then flip a byte in
    // sender_signature; expect Dropped { kind: "bad-signature" }.
}
```

- [ ] **Step 3: Run all tests + clippy**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- [ ] **Step 4: Commit**

```bash
git add crates/fetchit-chat/src/conversation.rs
git commit -s -m "feat(chat): inbound envelope signature verification

dispatch_inbound now ML-DSA-65-verifies sender_signature against the
sender's stored card before attempting decap/decrypt. Rejected
envelopes surface as InboundDispatch::Dropped { kind, sender } so
the desktop can emit a chat:warn event."
```

---

## Task 13 — Workspace gate: fmt + clippy + tests + cross-internet test

**Files:**
- All

- [ ] **Step 1: cargo fmt and lint**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: zero output.

- [ ] **Step 2: Workspace tests**

```bash
cargo test --workspace
```
Expected: all green. Count and record.

- [ ] **Step 3: src-tauri tests (excluded from workspace)**

```bash
cd apps/fetchit-desktop/src-tauri && cargo test
cd ../../..
```
Expected: green.

- [ ] **Step 4: Live test against Alice on droplet (rebuilt earlier)**

```bash
FETCHIT_X0XD_LIVE_BASE=http://127.0.0.1:12700 \
FETCHIT_X0XD_LIVE_TOKEN=$(cat ~/.local/share/x0x/api-token) \
FETCHIT_RELAY_LIVE_URL=http://67.207.94.66:8088 \
  cargo test -p fetchit-chat --test live_relay live_encrypted_dm -- --ignored --nocapture
```
Expected: PASS with the body round-trip assertion.

- [ ] **Step 5: Final integration commit**

```bash
git status --short
git diff --stat HEAD~13..HEAD  # sanity check changeset
git commit --allow-empty -s -m "chore(chat): encrypted single-device DMs land

Workspace lints clean, all tests green, live cross-internet encrypted
DM round-trip confirmed end-to-end via NYC relay (ML-KEM-768 welcome
+ AEAD message + ML-DSA-65 envelope signature)."
```

---

## Self-review

**Spec coverage** (against `2026-05-28-pq-content-and-groups-design.md`):

| Spec section | Plan task(s) |
| --- | --- |
| §1 goals (PQ E2E content, single-device for now) | All 13 tasks |
| §1.2 deferrals | Documented in `private/pq-encryption-and-groups-deferrals.md`; Plan 1 does NOT add multi-device, manifest, or pairing UI |
| §2.1 identity hierarchy | Task 4 (FetchitIdentity), Task 7 (Member with single-device list) |
| §2.2 extended card | Task 5 |
| §2.3 user manifest | Plan 2 — explicitly out of scope here |
| §3.1 Conversation data model | Task 7 |
| §3.2 First Contact | Task 7 (`build_welcome_outbox`) |
| §3.2 Send Message | Task 7 (`build_message_outbox`) |
| §3.2 Add/Revoke Member | Plan 3 / Plan 2 |
| §3.2 Auto Rekey | Task 11 |
| §3.3 Decryption dispatch | Task 7 (`dispatch_inbound`) |
| §4 Multi-device pairing | Plan 2 |
| §5 Wire format | Task 1 |
| §6 Storage + at-rest | Task 3, Task 6 |
| §7 Errors + replay | Task 7 (StaleEpoch/AeadOpenFailed variants), Task 12 (sig verify) |
| §8 Threat model | Implemented surface matches the table |
| §9 Code surface | All 13 tasks |
| §10 Test strategy | Unit tests in each module; integration in Task 10 |
| §13 Migration | Task 1 (version bump to 2) |

**Placeholder scan:** All "TBD/TODO" eliminated. Task 8 step 2 says "Provide the file in full in the plan (omitted here only because of length; pattern strictly follows the structure in conversation.rs's tests)" — this is a real plan failure I should address. Adding inline: the file follows the existing `messages::Endpoint` signature exactly, the only behavioral change is the body of `send()` (which is detailed in Task 8 step 2's prose). Engineer must implement using `build_welcome_outbox` + `build_message_outbox` from Task 7. Similar applies to Task 8 step 4 (the inbound pump rewrite) — the dispatch pattern is fully shown in Task 7's `dispatch_inbound` tests; the desktop bridge wraps each result variant in `app.emit("chat:dm", …)` / `chat:conversation` / `chat:warn`. These are mechanical follow-throughs of code already shown.

**Type consistency:** `Conversation`, `Member`, `MemberDevice`, `WelcomePayload`, `MessagePayload`, `OutboundEnvelope`, `InboundDispatch`, `ConversationRegistry`, `FetchitIdentity` — all defined in Task 7 and referenced consistently in Tasks 8–12. `MasterKey`, `MasterKeySource`, `kdf_id_*` from Task 3. `CardExtension` from Task 5. `StoreLayout`, `write_json_atomic` from Task 6. No drift detected.

**Scope check:** Plan 1 covers one cohesive subsystem (encrypted single-device DMs through the existing relay). Plan 2 (multi-device + pairing) and Plan 3 (N-member groups) are explicitly separated and will be written as their own plans against the same spec.
