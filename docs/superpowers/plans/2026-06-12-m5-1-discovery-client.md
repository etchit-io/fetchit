# M5.1 Discovery Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attestation v2 (profile address + relay hint inside the signed actor binding), the registry wire contract, and the desktop handle-lookup-to-private-DM bootstrap, per `docs/superpowers/specs/2026-06-12-m5-discovery-design.md` (Components D and A, client lane).

**Architecture:** fetchit-fedi gains the v2 attestation format, a tolerant remote-actor lookup type, and a registry HTTP client whose JSON fixtures are the cross-lane contract for `fetchit-bridge-server` (lane B, planned separately). fetchit-chat gains v2 mint/upgrade and a handle-continuity ledger. The desktop composes the resolution chain (WebFinger, actor doc, attestation verify, relay profile-index, Autonomi manifest) into one `fediverse_lookup` command, and the UI reuses the existing v3 pair-accept and group-invite flows verbatim: a verified lookup result carries a synthesized v3 share URI, so "Message privately" is `chat_pair_accept` on it.

**Tech Stack:** Rust (saorsa-pqc ML-DSA-65, reqwest + wiremock, serde), Tauri 2 commands, vanilla TS + vitest (jsdom).

**Standing constraints:**

- `Actor::from_json_ld` stays STRICT (attestation required). It gates the relay inbox path; loosening it would silently widen ingest, which is M5.2 scope. Lookup uses the new tolerant `RemoteActor` type instead.
- Re-mint / upgrade NEVER regenerates the RSA keypair (HTTP-signature key continuity). v2 is a re-sign over new fields with the same keys.
- Every commit: DCO sign-off via `git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s`. No em-dashes in committed text. Rust gates per commit: `cargo fmt --all` then `cargo clippy --workspace --all-targets -- -D warnings` then the targeted `cargo test -p` for the touched crate. Desktop gates per commit: `npx tsc --noEmit` and `npm run test:run` from `apps/fetchit-desktop/`.
- `unwrap()`/`expect()` only inside `#[cfg(test)]` modules opening with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
- User-facing copy uses the wordmarks `fetch>it` and `LIT Chat`; code identifiers stay `fetchit`.

**File structure:**

| File | Change |
| --- | --- |
| `crates/fetchit-fedi/src/attestation.rs` | v2 struct, `signing_input_v2`, `verify_binding_v2`, new error variants, `b64` widened to `pub(crate)` |
| `crates/fetchit-fedi/src/actor.rs` | optional v2 attestation on `Actor`/`ActorIdentity`, v2 JSON-LD property, shared SSRF client helper factored out of `fetch_actor` |
| `crates/fetchit-fedi/src/lookup.rs` | NEW: tolerant `RemoteActor` + `fetch_remote_actor` |
| `crates/fetchit-fedi/src/registry.rs` | NEW: `register_actor` / `update_actor` client |
| `crates/fetchit-fedi/tests/fixtures/registry-v1/` | NEW: wire-contract fixtures + README (lane-B handshake artifact) |
| `crates/fetchit-chat/src/fedi_identity.rs` | `sign_actor_attestation_v2` |
| `crates/fetchit-chat/src/fedi_vault.rs` | optional `ml_dsa_attestation_v2` field |
| `crates/fetchit-chat/src/client.rs` | `mint_actor_identity_v2`, `upgrade_actor_attestation_v2` |
| `crates/fetchit-chat/src/fedi_resolutions.rs` | NEW: handle-continuity ledger |
| `apps/fetchit-desktop/src-tauri/src/chat.rs` | `self_profile_record` factored out of `chat_pair_share` |
| `apps/fetchit-desktop/src-tauri/src/fediverse.rs` | mint v2 + registration, `fediverse_ensure_v2` |
| `apps/fetchit-desktop/src-tauri/src/fediverse_lookup.rs` | NEW: `fediverse_lookup` command + `LookupDto` |
| `apps/fetchit-desktop/src-tauri/src/profile.rs` | `build_profile_outcome`, `AvatarDto`, `MAX_MANIFEST_BYTES`, `ProfileOutcome` widened to `pub(crate)` |
| `apps/fetchit-desktop/src/fediverse/api.ts` | NEW: typed invoke wrappers |
| `apps/fetchit-desktop/src/fediverse/lookup.ts` | NEW: search box + actor card |
| `apps/fetchit-desktop/src/fediverse/panel.ts` | lookup section, `onOpenDm` handler |
| `apps/fetchit-desktop/src/fediverse/compose.ts` | consent copy, mint DTO, ensure-v2 call |
| `apps/fetchit-desktop/src/chat/panel.ts` | `ChatPanelApi.openDm` |
| `apps/fetchit-desktop/src/chat/addContact.ts` | accepts `@handle@domain` |
| `apps/fetchit-desktop/src/controller.ts` | wires `onOpenDm` |
| `apps/fetchit-desktop/src/fediverse/styles.css` | lookup + actor-card styles |

---

### Task 1: Attestation v2 struct + signing input (fetchit-fedi)

**Files:**
- Modify: `crates/fetchit-fedi/src/attestation.rs`

- [ ] **Step 1: Read the existing v1 code**

Read `crates/fetchit-fedi/src/attestation.rs` lines 1-230 (struct, `b64` helper, `signing_input`, `push_lp`, `SigningInputError`) and the test module from line 282 to mirror style.

- [ ] **Step 2: Write the failing tests**

Append to the existing `#[cfg(test)]` module:

```rust
#[test]
fn v2_domain_separator_is_frozen() {
    assert_eq!(DOMAIN_SEPARATOR_V2, b"fetchit-fedi-actor-attestation-v2");
}

#[test]
fn signing_input_v2_layout_is_canonical() {
    let relay = "https://relay.example:8088/";
    let bytes = signing_input_v2(
        "josh",
        &url("https://etchit.io/actors/josh"),
        VALID_AGENT_HEX,
        &[0xDE, 0xAD, 0xBE, 0xEF],
        &"a".repeat(64),
        relay,
        1_750_000_000_000,
    )
    .unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(DOMAIN_SEPARATOR_V2);
    expected.extend_from_slice(&4u32.to_be_bytes());
    expected.extend_from_slice(b"josh");
    expected.extend_from_slice(&29u32.to_be_bytes());
    expected.extend_from_slice(b"https://etchit.io/actors/josh");
    expected.extend_from_slice(&64u32.to_be_bytes());
    expected.extend_from_slice(VALID_AGENT_HEX.as_bytes());
    expected.extend_from_slice(&4u32.to_be_bytes());
    expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    expected.extend_from_slice(&64u32.to_be_bytes());
    expected.extend_from_slice("a".repeat(64).as_bytes());
    expected.extend_from_slice(&u32::try_from(relay.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(relay.as_bytes());
    expected.extend_from_slice(&1_750_000_000_000u64.to_be_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn signing_input_v2_differs_when_any_field_changes() {
    let base = || {
        signing_input_v2(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[1, 2, 3],
            &"a".repeat(64),
            "https://relay.example/",
            7,
        )
        .unwrap()
    };
    let b = base();
    assert_ne!(
        b,
        signing_input_v2(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[1, 2, 3],
            &"b".repeat(64),
            "https://relay.example/",
            7,
        )
        .unwrap()
    );
    assert_ne!(
        b,
        signing_input_v2(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[1, 2, 3],
            &"a".repeat(64),
            "https://other.example/",
            7,
        )
        .unwrap()
    );
    assert_ne!(
        b,
        signing_input_v2(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[1, 2, 3],
            &"a".repeat(64),
            "https://relay.example/",
            8,
        )
        .unwrap()
    );
}

#[test]
fn signing_input_v2_rejects_bad_profile_addr() {
    let r = signing_input_v2(
        "josh",
        &url("https://etchit.io/actors/josh"),
        VALID_AGENT_HEX,
        &[1],
        "UPPERCASE",
        "https://relay.example/",
        1,
    );
    assert!(matches!(r, Err(SigningInputError::InvalidProfileAddr { .. })));
}

#[test]
fn signing_input_v2_rejects_empty_and_oversized_relay_hint() {
    let mk = |hint: &str| {
        signing_input_v2(
            "josh",
            &url("https://etchit.io/actors/josh"),
            VALID_AGENT_HEX,
            &[1],
            &"a".repeat(64),
            hint,
            1,
        )
    };
    assert!(matches!(mk(""), Err(SigningInputError::InvalidRelayHint { .. })));
    let long = format!("https://{}/", "x".repeat(MAX_RELAY_HINT_LEN));
    assert!(matches!(mk(&long), Err(SigningInputError::InvalidRelayHint { .. })));
}

#[test]
fn attestation_v2_round_trips_through_json() {
    let a = ActorAttestationV2 {
        version: 2,
        profile_addr: "a".repeat(64),
        relay_hint: "https://relay.example/".into(),
        hint_epoch_ms: 5,
        ml_dsa_pubkey: vec![0xDE, 0xAD],
        signature: vec![1, 2, 3],
    };
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"version\":2"));
    assert!(json.contains("\"3q0=\""));
    let back: ActorAttestationV2 = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p fetchit-fedi attestation -- --nocapture` (from repo root)
Expected: compile FAIL (`DOMAIN_SEPARATOR_V2` not found)

- [ ] **Step 4: Implement**

Add below the v1 `signing_input` block, mirroring v1's rustdoc density (every public item documented, layout block in the doc comment):

```rust
/// Domain separator for the v2 attestation signing input. v2 extends
/// the attested tuple with the profile address and relay hint so a
/// verified actor record is sufficient to bootstrap a private contact.
///
/// **Frozen.** Same rule as [`DOMAIN_SEPARATOR`]: changing it is a v3
/// migration, not a patch.
pub const DOMAIN_SEPARATOR_V2: &[u8] = b"fetchit-fedi-actor-attestation-v2";

/// Hard cap on `relay_hint` byte length. Mirrors
/// `fetchit-chat::card::MAX_HINT_URL_LEN` (this crate sits below
/// fetchit-chat in the dependency graph, so the value is restated).
pub const MAX_RELAY_HINT_LEN: usize = 256;

/// v2 actor attestation: the signed binding now also covers the
/// Autonomi profile address and a relay hint, making the record a
/// self-contained pointer for the v3 share-URI bootstrap.
///
/// Wire shape: JSON with base64 byte fields (same [`b64`] helper as
/// v1) plus an explicit integer `version` so consumers dispatch
/// without sniffing fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorAttestationV2 {
    /// Always `2`. [`verify_binding_v2`] rejects anything else.
    pub version: u8,
    /// Autonomi address of the actor's profile manifest, lowercase 64-hex.
    pub profile_addr: String,
    /// Relay URL serving the actor's profile-index record. Bounded by
    /// [`MAX_RELAY_HINT_LEN`]; URL well-formedness is the consumer's
    /// check (it fails closed to the public-only rendering).
    pub relay_hint: String,
    /// Freshness stamp. Same monotonicity semantics as card v2
    /// rendezvous hints: registries and clients reject updates whose
    /// epoch does not strictly increase.
    pub hint_epoch_ms: u64,
    /// ML-DSA-65 public key bytes (raw).
    #[serde(with = "b64")]
    pub ml_dsa_pubkey: Vec<u8>,
    /// ML-DSA-65 signature over [`signing_input_v2`].
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

/// Canonical signing-input bytes for a v2 attestation.
///
/// Layout:
/// ```text
/// DOMAIN_SEPARATOR_V2
/// || u32_be(len(handle))         || handle
/// || u32_be(len(actor_url))      || actor_url
/// || u32_be(len(agent_id_hex))   || agent_id_hex
/// || u32_be(len(rsa_pubkey_der)) || rsa_pubkey_der
/// || u32_be(len(profile_addr))   || profile_addr
/// || u32_be(len(relay_hint))     || relay_hint
/// || u64_be(hint_epoch_ms)
/// ```
///
/// First four fields and their constraints are identical to
/// [`signing_input`]. `profile_addr` must be lowercase 64-hex.
/// `relay_hint` must be non-empty and at most [`MAX_RELAY_HINT_LEN`]
/// bytes. `hint_epoch_ms` is fixed-width 8-byte big-endian, no length
/// prefix.
///
/// # Errors
/// [`SigningInputError`] on any field-constraint violation.
#[allow(clippy::too_many_arguments)]
pub fn signing_input_v2(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    rsa_pubkey_der: &[u8],
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
) -> Result<Vec<u8>, SigningInputError> {
    if handle.is_empty() {
        return Err(SigningInputError::EmptyHandle);
    }
    if !is_lowercase_64_hex(agent_id_hex) {
        return Err(SigningInputError::InvalidAgentIdHex {
            len: agent_id_hex.len(),
        });
    }
    if !is_lowercase_64_hex(profile_addr) {
        return Err(SigningInputError::InvalidProfileAddr {
            len: profile_addr.len(),
        });
    }
    if relay_hint.is_empty() || relay_hint.len() > MAX_RELAY_HINT_LEN {
        return Err(SigningInputError::InvalidRelayHint {
            len: relay_hint.len(),
        });
    }
    let actor_url_str = actor_url.as_str();
    let mut out = Vec::with_capacity(
        DOMAIN_SEPARATOR_V2
            .len()
            .saturating_add(4 + handle.len())
            .saturating_add(4 + actor_url_str.len())
            .saturating_add(4 + agent_id_hex.len())
            .saturating_add(4 + rsa_pubkey_der.len())
            .saturating_add(4 + profile_addr.len())
            .saturating_add(4 + relay_hint.len())
            .saturating_add(8),
    );
    out.extend_from_slice(DOMAIN_SEPARATOR_V2);
    push_lp(&mut out, handle.as_bytes())?;
    push_lp(&mut out, actor_url_str.as_bytes())?;
    push_lp(&mut out, agent_id_hex.as_bytes())?;
    push_lp(&mut out, rsa_pubkey_der)?;
    push_lp(&mut out, profile_addr.as_bytes())?;
    push_lp(&mut out, relay_hint.as_bytes())?;
    out.extend_from_slice(&hint_epoch_ms.to_be_bytes());
    Ok(out)
}
```

Add to `SigningInputError`:

```rust
    /// `profile_addr` was not lowercase 64-hex.
    #[error("attestation profile_addr must be lowercase 64-hex (got len {len})")]
    InvalidProfileAddr {
        /// Length of the offending input in bytes.
        len: usize,
    },
    /// `relay_hint` was empty or exceeded [`MAX_RELAY_HINT_LEN`].
    #[error("attestation relay_hint must be 1..={MAX_RELAY_HINT_LEN} bytes (got {len})", MAX_RELAY_HINT_LEN = MAX_RELAY_HINT_LEN)]
    InvalidRelayHint {
        /// Length of the offending input in bytes.
        len: usize,
    },
```

(If the inline format-arg form fights `thiserror`, use a plain literal: `"attestation relay_hint must be 1..=256 bytes (got {len})"`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-fedi attestation`
Expected: PASS, zero clippy warnings

- [ ] **Step 6: Commit**

```bash
git add crates/fetchit-fedi/src/attestation.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(fedi): attestation v2 signing input and struct'
```

---

### Task 2: verify_binding_v2 (fetchit-fedi)

**Files:**
- Modify: `crates/fetchit-fedi/src/attestation.rs`

- [ ] **Step 1: Write the failing tests**

Add a v2 twin of the `test_attested` helper plus tests:

```rust
/// Build a real-keyed v2 attestation for tests. Returns the
/// attestation plus the derived agent id hex.
#[cfg(test)]
pub(crate) fn test_attested_v2(
    handle: &str,
    actor_url: &url::Url,
    spki_der: &[u8],
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
) -> (ActorAttestationV2, String) {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(&pk.to_bytes()));
    let input = signing_input_v2(
        handle, actor_url, &derived, spki_der, profile_addr, relay_hint, hint_epoch_ms,
    )
    .unwrap();
    let sig = dsa.sign(&sk, &input).unwrap().to_bytes();
    (
        ActorAttestationV2 {
            version: 2,
            profile_addr: profile_addr.to_string(),
            relay_hint: relay_hint.to_string(),
            hint_epoch_ms,
            ml_dsa_pubkey: pk.to_bytes(),
            signature: sig,
        },
        derived,
    )
}
```

Tests (mirror the v1 set):

```rust
#[test]
fn verify_binding_v2_round_trips_with_real_keys() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (att, derived) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    let got = verify_binding_v2("josh", &actor_url, &[9, 9], &att).unwrap();
    assert_eq!(got, derived);
}

#[test]
fn verify_binding_v2_rejects_wrong_version() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (mut att, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    att.version = 1;
    assert!(matches!(
        verify_binding_v2("josh", &actor_url, &[9, 9], &att),
        Err(AttestationVerifyError::WrongVersion { got: 1 })
    ));
}

#[test]
fn verify_binding_v2_rejects_tampered_profile_addr() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (mut att, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    att.profile_addr = "b".repeat(64);
    assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &att).is_err());
}

#[test]
fn verify_binding_v2_rejects_tampered_relay_hint() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (mut att, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    att.relay_hint = "https://evil.example/".into();
    assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &att).is_err());
}

#[test]
fn verify_binding_v2_rejects_tampered_epoch() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (mut att, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    att.hint_epoch_ms = 43;
    assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &att).is_err());
}

#[test]
fn verify_binding_v2_rejects_tampered_handle() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (att, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    assert!(verify_binding_v2("mallory", &actor_url, &[9, 9], &att).is_err());
}

#[test]
fn verify_binding_v2_derives_agent_id_rather_than_trusting_a_claim() {
    // A signature minted under key A cannot bind key B's derived id:
    // swap pubkeys between two valid attestations and both must reject.
    let actor_url = url("https://etchit.io/actors/josh");
    let (att_a, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    let (mut att_b, _) = test_attested_v2(
        "josh", &actor_url, &[9, 9], &"a".repeat(64), "https://relay.example/", 42,
    );
    att_b.ml_dsa_pubkey = att_a.ml_dsa_pubkey.clone();
    assert!(verify_binding_v2("josh", &actor_url, &[9, 9], &att_b).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p fetchit-fedi verify_binding_v2`
Expected: compile FAIL (`verify_binding_v2` not found)

- [ ] **Step 3: Implement**

```rust
/// Cryptographically verify a v2 attestation against the actor fields
/// it claims to bind, returning the **derived** chat `agent_id_hex`.
///
/// Identical derive-then-verify construction to [`verify_binding`];
/// the reconstructed input additionally covers the attestation's own
/// `profile_addr`, `relay_hint`, and `hint_epoch_ms` fields, so
/// tampering with any of them invalidates the signature.
///
/// # Errors
/// Any [`AttestationVerifyError`] means the actor MUST NOT be treated
/// as bound to a chat identity (callers fail closed to public-only).
pub fn verify_binding_v2(
    handle: &str,
    actor_url: &url::Url,
    spki_der: &[u8],
    attestation: &ActorAttestationV2,
) -> Result<String, AttestationVerifyError> {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSignature, MlDsaVariant};

    if attestation.version != 2 {
        return Err(AttestationVerifyError::WrongVersion {
            got: attestation.version,
        });
    }
    let derived = hex::encode(fetchit_relay_proto::derive_agent_id(
        &attestation.ml_dsa_pubkey,
    ));
    let input = signing_input_v2(
        handle,
        actor_url,
        &derived,
        spki_der,
        &attestation.profile_addr,
        &attestation.relay_hint,
        attestation.hint_epoch_ms,
    )?;
    let pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &attestation.ml_dsa_pubkey)
        .map_err(|e| AttestationVerifyError::PubkeyParse(e.to_string()))?;
    let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &attestation.signature)
        .map_err(|e| AttestationVerifyError::SignatureParse(e.to_string()))?;
    let ok = MlDsa::new(MlDsaVariant::MlDsa65)
        .verify(&pk, &input, &sig)
        .map_err(|e| AttestationVerifyError::VerifyBackend(e.to_string()))?;
    if !ok {
        return Err(AttestationVerifyError::SignatureInvalid);
    }
    Ok(derived)
}
```

Add to `AttestationVerifyError`:

```rust
    /// The attestation's `version` field is not the expected `2`.
    #[error("attestation version {got} where 2 expected")]
    WrongVersion {
        /// The version value found on the wire.
        got: u8,
    },
```

- [ ] **Step 4: Run tests, lint, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-fedi attestation`
Expected: PASS

```bash
git add crates/fetchit-fedi/src/attestation.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(fedi): verify_binding_v2 with derive-then-verify'
```

---

### Task 3: Actors carry an optional v2 attestation (fetchit-fedi)

**Files:**
- Modify: `crates/fetchit-fedi/src/actor.rs`
- Modify (compile fixes): `crates/fetchit-chat/src/client.rs`, `crates/fetchit-chat/src/bin/peer.rs`, `crates/fetchit-chat/src/rekey.rs`

- [ ] **Step 1: Read the surrounding code**

Read `crates/fetchit-fedi/src/actor.rs` lines 40-200 (the `ActorIdentity` struct around line 85, its constructor(s) around lines 98 and 118, `Actor` at 158-173, `from_identity` around 194) and lines 270-340 (`from_json_ld` / `to_json_ld`). The strict v1 decode at lines 287-304 stays byte-for-byte as-is.

- [ ] **Step 2: Write the failing tests**

In the actor.rs test module:

```rust
#[test]
fn json_ld_round_trips_v2_attestation() {
    let actor_url = url("https://etchit.io/actors/josh");
    let (att2, _) = crate::attestation::test_attested_v2(
        "josh", &actor_url, &sample_spki_der(), &"a".repeat(64), "https://relay.example/", 9,
    );
    let mut actor = sample_actor(); // reuse whatever existing helper builds a valid Actor
    actor.ml_dsa_attestation_v2 = Some(att2.clone());
    let v = actor.to_json_ld();
    assert!(v.get(PQ_ATTESTATION_V2_PROPERTY_URI).is_some());
    let parsed = Actor::from_json_ld(&v).unwrap();
    assert_eq!(parsed.ml_dsa_attestation_v2, Some(att2));
}

#[test]
fn json_ld_without_v2_attestation_decodes_to_none() {
    let actor = sample_actor();
    let v = actor.to_json_ld();
    assert!(v.get(PQ_ATTESTATION_V2_PROPERTY_URI).is_none());
    let parsed = Actor::from_json_ld(&v).unwrap();
    assert_eq!(parsed.ml_dsa_attestation_v2, None);
}

#[test]
fn malformed_v2_attestation_value_is_a_hard_decode_error() {
    let actor = sample_actor();
    let mut v = actor.to_json_ld();
    v.as_object_mut()
        .unwrap()
        .insert(PQ_ATTESTATION_V2_PROPERTY_URI.into(), serde_json::json!("garbage"));
    assert!(Actor::from_json_ld(&v).is_err());
}

#[test]
fn verify_attestation_v2_passes_and_rejects() {
    let actor_url = url("https://etchit.io/actors/josh");
    // Build an actor whose handle/url/pem match a real v2 attestation,
    // mirroring verify_attestation_passes_after_json_ld_round_trip.
    // Then assert verify_attestation_v2() returns the derived id, and
    // that an actor with ml_dsa_attestation_v2 = None errors.
}
```

Adapt helper names (`sample_actor`, `sample_spki_der`) to what the existing test module actually provides; the existing `verify_attestation_passes_after_json_ld_round_trip` test (line 946) shows the exact recipe for building a real-keyed actor.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p fetchit-fedi actor`
Expected: compile FAIL (no field `ml_dsa_attestation_v2`)

- [ ] **Step 4: Implement**

1. New constant next to the v1 URI (line 49):

```rust
/// JSON-LD property carrying the v2 attestation. Emitted alongside the
/// frozen v1 property during the transition; decoders prefer v2.
pub const PQ_ATTESTATION_V2_PROPERTY_URI: &str = "https://etchit.io/ns#mlDsaAttestation-v2";
```

2. Add `pub ml_dsa_attestation_v2: Option<ActorAttestationV2>` to BOTH `ActorIdentity` and `Actor`, with rustdoc. Keep existing constructor signatures unchanged, initializing the field to `None` inside them, and add a chaining helper on each struct:

```rust
/// Attach a v2 attestation (builder-style; mint paths use this).
#[must_use]
pub fn with_attestation_v2(mut self, att: ActorAttestationV2) -> Self {
    self.ml_dsa_attestation_v2 = Some(att);
    self
}
```

3. `from_identity` copies the field: `ml_dsa_attestation_v2: id.ml_dsa_attestation_v2.clone(),`.

4. `to_json_ld`: after building the existing `json!` value, conditionally insert:

```rust
let mut v = json!({ /* existing body unchanged */ });
if let Some(att2) = &self.ml_dsa_attestation_v2 {
    if let (Some(obj), Ok(val)) = (v.as_object_mut(), serde_json::to_value(att2)) {
        obj.insert(PQ_ATTESTATION_V2_PROPERTY_URI.to_string(), val);
    }
}
v
```

5. `from_json_ld`: after the v1 attestation decode, add the optional v2 decode (absent = `None`; present-but-malformed = hard error, fail closed):

```rust
let ml_dsa_attestation_v2 = match value.get(PQ_ATTESTATION_V2_PROPERTY_URI) {
    None => None,
    Some(raw) => Some(
        serde_json::from_value::<crate::attestation::ActorAttestationV2>(raw.clone())
            .map_err(|e| ActorError::Attestation(format!("v2: {e}")))?,
    ),
};
```

6. New method next to `verify_attestation` (line 352):

```rust
/// Verify the v2 attestation, returning the derived `agent_id_hex`.
///
/// # Errors
/// [`ActorError::Attestation`] when no v2 attestation is present;
/// otherwise the same failure surface as [`Actor::verify_attestation`].
pub fn verify_attestation_v2(&self) -> Result<String, ActorError> {
    let att = self
        .ml_dsa_attestation_v2
        .as_ref()
        .ok_or_else(|| ActorError::Attestation("no v2 attestation on actor".into()))?;
    let spki_der = spki_pem_to_der(&self.rsa_public_key_pem).map_err(|reason| {
        ActorError::InvalidField {
            name: "publicKey.publicKeyPem".into(),
            reason,
        }
    })?;
    Ok(crate::attestation::verify_binding_v2(
        &self.preferred_username,
        &self.id,
        &spki_der,
        att,
    )?)
}
```

7. Compile-fix struct-literal construction sites found by `cargo check -p fetchit-fedi -p fetchit-chat`: known ones are inside `from_json_ld`, the actor.rs test helpers, `crates/fetchit-chat/src/client.rs` (the `ActorIdentity` built by `mint_actor_identity` around lines 2940-2996, gets `ml_dsa_attestation_v2: None` for now; Task 7 threads the real value), `peer.rs` (uses `from_identity`, likely no change), and `rekey.rs:250` test fixture.

- [ ] **Step 5: Run tests, lint, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-fedi -p fetchit-chat`
Expected: PASS (existing strict-v1 tests untouched and green)

```bash
git add crates/fetchit-fedi/src/actor.rs crates/fetchit-chat/src
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(fedi): actors carry optional v2 attestation in JSON-LD'
```

---

### Task 4: Tolerant RemoteActor lookup fetch (fetchit-fedi)

**Files:**
- Create: `crates/fetchit-fedi/src/lookup.rs`
- Modify: `crates/fetchit-fedi/src/actor.rs` (factor shared fetch internals), `crates/fetchit-fedi/src/lib.rs` (declare module)

- [ ] **Step 1: Factor the shared fetch internals (pure refactor, no behavior change)**

In actor.rs, split `fetch_actor` (lines 545-572) and `fetch_actor_at_url` (lines 578-644):

```rust
/// SSRF-hardened client for a single target: private-IP pre-flight,
/// DNS resolve + pin, no redirects, per-call timeout. Shared by the
/// strict actor fetch and the tolerant lookup fetch.
pub(crate) async fn pinned_no_redirect_client(
    target: &url::Url,
    timeout: Duration,
) -> Result<reqwest::Client, FetchActorError> {
    if let Some(host) = target.host() {
        if let Some(reason) = crate::ssrf::private_ip_reason(&host) {
            return Err(FetchActorError::PrivateInstance { host: reason });
        }
    }
    let host_for_pin = target
        .host_str()
        .ok_or_else(|| FetchActorError::Transport("URL has no host".into()))?;
    let port = target.port_or_known_default().unwrap_or(443);
    let pinned = crate::ssrf::resolve_and_pin_host(host_for_pin, port)
        .await
        .map_err(|e| match e {
            crate::ssrf::SsrfError::PrivateAddress { host } => {
                FetchActorError::PrivateInstance { host }
            }
            crate::ssrf::SsrfError::Resolve(msg) => FetchActorError::Transport(msg),
        })?;
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .resolve_to_addrs(host_for_pin, &pinned)
        .build()
        .map_err(|e| FetchActorError::Transport(format!("client builder: {e}")))
}

/// HTTP GET + post-flight host check + body cap + JSON parse. The
/// moved body of fetch_actor_at_url minus the Actor decode.
pub(crate) async fn fetch_json_ld_at_url(
    http: &reqwest::Client,
    target: &url::Url,
    timeout: Duration,
) -> Result<Value, FetchActorError> {
    // body of fetch_actor_at_url lines 583-642, ending at the
    // serde_json::from_slice, returning the Value
}
```

`fetch_actor` becomes `pinned_no_redirect_client` + `fetch_actor_at_url`; `fetch_actor_at_url` becomes `fetch_json_ld_at_url` + `Actor::from_json_ld`. Also widen `required_str` and `is_actor_class_type` to `pub(crate)`, and `ACTOR_FETCH_TIMEOUT` if not already crate-visible.

Run: `cargo test -p fetchit-fedi` to confirm the refactor is invisible (all existing tests green).

- [ ] **Step 2: Write the failing tests for the new module**

`crates/fetchit-fedi/src/lookup.rs` test module (reuse the gargron fixture):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/gargron_actor.json")).unwrap()
    }

    #[test]
    fn vanilla_actor_without_attestation_decodes_with_none() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.attestation_v2.is_none());
        assert!(actor.rsa_public_key_pem.is_some());
        assert_eq!(actor.preferred_username, "Gargron");
    }

    #[test]
    fn actor_without_public_key_decodes_with_none_pem() {
        let mut v = fixture();
        let obj = v.as_object_mut().unwrap();
        obj.remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        obj.remove("publicKey");
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.rsa_public_key_pem.is_none());
    }

    #[test]
    fn non_actor_class_is_rejected() {
        let mut v = fixture();
        v.as_object_mut()
            .unwrap()
            .insert("type".into(), serde_json::json!("Note"));
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn forged_public_key_owner_is_rejected() {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove(crate::actor::PQ_ATTESTATION_PROPERTY_URI);
        v["publicKey"]["owner"] = serde_json::json!("https://evil.example/actors/mallory");
        assert!(RemoteActor::from_json_ld(&v).is_err());
    }

    #[test]
    fn v2_attestation_is_decoded_and_verifies() {
        let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
        let spki_der = vec![7u8; 16];
        let pem = crate::actor::spki_der_to_pem(&spki_der);
        let (att2, derived) = crate::attestation::test_attested_v2(
            "josh", &actor_url, &spki_der, &"a".repeat(64), "https://relay.example/", 3,
        );
        let v = serde_json::json!({
            "id": actor_url.as_str(),
            "type": "Person",
            "preferredUsername": "josh",
            "publicKey": { "owner": actor_url.as_str(), "publicKeyPem": pem },
            crate::actor::PQ_ATTESTATION_V2_PROPERTY_URI: serde_json::to_value(&att2).unwrap(),
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert_eq!(actor.verify_attestation_v2().unwrap(), derived);
    }

    #[test]
    fn verify_without_attestation_or_pem_fails_closed() {
        let v = serde_json::json!({
            "id": "https://x.example/a", "type": "Person", "preferredUsername": "a",
        });
        let actor = RemoteActor::from_json_ld(&v).unwrap();
        assert!(actor.verify_attestation_v2().is_err());
    }
}
```

(If the gargron fixture's `preferredUsername` differs, match the fixture.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p fetchit-fedi lookup`
Expected: compile FAIL (module does not exist)

- [ ] **Step 4: Implement lookup.rs**

```rust
//! Tolerant remote-actor lookup (M5.1, Component A).
//!
//! [`RemoteActor`] decodes ANY well-formed `ActivityPub` actor,
//! attestation present or not, so the desktop can render public-only
//! cards for vanilla fediverse accounts. This type is for CLIENT
//! lookup only: relay-side ingest keeps the strict
//! [`crate::actor::Actor`] decode (attestation required), and that
//! boundary is deliberate; widening relay ingest is M5.2 scope.

use crate::actor::{
    fetch_json_ld_at_url, is_actor_class_type, pinned_no_redirect_client, required_str,
    spki_pem_to_der, ActorError, FetchActorError, PQ_ATTESTATION_V2_PROPERTY_URI,
};
use crate::attestation::ActorAttestationV2;
use serde_json::Value;

/// A remote actor as seen by the lookup path. Every field beyond the
/// identity pair is optional; trust is established exclusively by
/// [`RemoteActor::verify_attestation_v2`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteActor {
    /// Canonical actor URL (`id`).
    pub id: url::Url,
    /// `preferredUsername` as served; the local part of the handle.
    pub preferred_username: String,
    /// `publicKey.publicKeyPem` when served.
    pub rsa_public_key_pem: Option<String>,
    /// v2 attestation when served. Present-but-malformed is a decode
    /// error, never silently `None`.
    pub attestation_v2: Option<ActorAttestationV2>,
}

impl RemoteActor {
    /// Decode from an actor JSON-LD document, tolerating absent
    /// attestation and public key.
    ///
    /// # Errors
    /// [`ActorError`] on missing `id`/`preferredUsername`, a non-actor
    /// `type`, a `publicKey.owner` that does not match `id`, or a
    /// malformed v2 attestation value.
    pub fn from_json_ld(value: &Value) -> Result<Self, ActorError> {
        if let Some(type_str) = value.get("type").and_then(Value::as_str) {
            if !is_actor_class_type(type_str) {
                return Err(ActorError::InvalidField {
                    name: "type".into(),
                    reason: format!(
                        "expected one of {{Person, Service, Application, Organization, Group}}; got {type_str:?}"
                    ),
                });
            }
        }
        let id: url::Url = required_str(value, "id")?
            .parse()
            .map_err(|e| ActorError::InvalidField {
                name: "id".into(),
                reason: format!("{e}"),
            })?;
        let preferred_username = required_str(value, "preferredUsername")?.to_owned();
        let rsa_public_key_pem = match value.get("publicKey") {
            None => None,
            Some(pk) => {
                if let Some(owner) = pk.get("owner").and_then(Value::as_str) {
                    if owner != id.as_str() {
                        return Err(ActorError::InvalidField {
                            name: "publicKey.owner".into(),
                            reason: "owner does not match actor id".into(),
                        });
                    }
                }
                pk.get("publicKeyPem").and_then(Value::as_str).map(str::to_owned)
            }
        };
        let attestation_v2 = match value.get(PQ_ATTESTATION_V2_PROPERTY_URI) {
            None => None,
            Some(raw) => Some(
                serde_json::from_value::<ActorAttestationV2>(raw.clone())
                    .map_err(|e| ActorError::Attestation(format!("v2: {e}")))?,
            ),
        };
        Ok(Self {
            id,
            preferred_username,
            rsa_public_key_pem,
            attestation_v2,
        })
    }

    /// Verify the v2 attestation, returning the derived agent id hex.
    /// Fails closed when either the attestation or the RSA key is
    /// absent; callers render the public-only card on any error.
    ///
    /// # Errors
    /// [`ActorError`] wrapping the attestation failure surface.
    pub fn verify_attestation_v2(&self) -> Result<String, ActorError> {
        let att = self
            .attestation_v2
            .as_ref()
            .ok_or_else(|| ActorError::Attestation("no v2 attestation on actor".into()))?;
        let pem = self.rsa_public_key_pem.as_deref().ok_or_else(|| {
            ActorError::MissingField {
                name: "publicKey.publicKeyPem".into(),
            }
        })?;
        let spki_der = spki_pem_to_der(pem).map_err(|reason| ActorError::InvalidField {
            name: "publicKey.publicKeyPem".into(),
            reason,
        })?;
        Ok(crate::attestation::verify_binding_v2(
            &self.preferred_username,
            &self.id,
            &spki_der,
            att,
        )?)
    }
}

/// Fetch and tolerantly decode a remote actor. Same SSRF hardening as
/// [`crate::actor::fetch_actor`] (private-IP pre-flight, DNS pinning,
/// no redirects, body cap, timeout).
///
/// # Errors
/// Same [`FetchActorError`] surface as the strict fetch.
pub async fn fetch_remote_actor(actor_url: &url::Url) -> Result<RemoteActor, FetchActorError> {
    let timeout = crate::actor::ACTOR_FETCH_TIMEOUT;
    let client = pinned_no_redirect_client(actor_url, timeout).await?;
    let value = fetch_json_ld_at_url(&client, actor_url, timeout).await?;
    RemoteActor::from_json_ld(&value).map_err(FetchActorError::Parse)
}
```

Declare in lib.rs next to the other modules: `pub mod lookup;` (with a module doc-line if lib.rs annotates them). Widen `ACTOR_FETCH_TIMEOUT` to `pub(crate)` if needed.

- [ ] **Step 5: Run tests, lint, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-fedi`
Expected: PASS

```bash
git add crates/fetchit-fedi/src
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(fedi): tolerant remote-actor lookup fetch'
```

---

### Task 5: Registry client + wire-contract fixtures (fetchit-fedi)

**Files:**
- Create: `crates/fetchit-fedi/src/registry.rs`
- Create: `crates/fetchit-fedi/tests/fixtures/registry-v1/register-request.json`
- Create: `crates/fetchit-fedi/tests/fixtures/registry-v1/register-response.json`
- Create: `crates/fetchit-fedi/tests/fixtures/registry-v1/README.md`
- Modify: `crates/fetchit-fedi/src/lib.rs`, `crates/fetchit-fedi/src/attestation.rs` (b64 visibility)

This module is the cross-lane handshake: the fixtures pin the JSON `fetchit-bridge-server` (lane B) must accept and return. Bob reviews these files before implementing the endpoints.

- [ ] **Step 1: Widen the b64 helper**

In attestation.rs change `mod b64` to `pub(crate) mod b64` and its two functions from `pub(super)` to `pub(crate)`. Run `cargo test -p fetchit-fedi attestation` (still green).

- [ ] **Step 2: Write the fixtures**

`register-request.json`:

```json
{
  "handle": "josh",
  "rsa_spki_der": "3q2+7w==",
  "attestation_v2": {
    "version": 2,
    "profile_addr": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "relay_hint": "https://relay.example:8088/",
    "hint_epoch_ms": 1750000000000,
    "ml_dsa_pubkey": "QkJCQg==",
    "signature": "QUFBQQ=="
  }
}
```

`register-response.json`:

```json
{
  "actor_url": "https://etchit.io/actors/josh"
}
```

`README.md` (the contract document, plain prose, no em-dashes):

```markdown
# Registry wire contract v1 (M5.1, Component D)

Client: crates/fetchit-fedi/src/registry.rs. Server: fetchit-bridge-server.
Spec: docs/superpowers/specs/2026-06-12-m5-discovery-design.md.

## POST /v1/actors (register)

Body: register-request.json. The bridge MUST:
1. Validate the handle: [A-Za-z0-9_-], 1..=64 chars.
2. Construct actor_url as https://<domain>/actors/<handle>.
3. Verify attestation_v2 via fetchit_fedi::attestation::verify_binding_v2
   with (handle, actor_url, rsa_spki_der). The agent id is DERIVED from
   the attested ML-DSA pubkey, never read from a claim.
4. Reject version != 2 records (v1 records are re-minted client-side).
5. First come, first served on the handle. Rate-limit per source.

Responses: 201 register-response.json | 409 handle taken |
422 attestation invalid (body: reason text) | 429 rate limited.

## PUT /v1/actors/<handle> (update)

Same body and verification, plus:
1. Same-agent-id continuity: derived agent id MUST equal the registered
   one (a handle never silently changes hands).
2. hint_epoch_ms MUST be strictly greater than the stored record's.

Responses: 200 register-response.json | 404 unknown handle |
409 agent id mismatch or stale epoch | 422 | 429.

The directory serves the stored attestation inside the WebFinger record
and the actor document so any client can verify the chain offline.
```

- [ ] **Step 3: Write the failing tests**

In registry.rs:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn contract_request() -> RegisterActorRequest {
        RegisterActorRequest {
            handle: "josh".into(),
            rsa_spki_der: vec![0xDE, 0xAD, 0xBE, 0xEF],
            attestation_v2: crate::attestation::ActorAttestationV2 {
                version: 2,
                profile_addr: "a".repeat(64),
                relay_hint: "https://relay.example:8088/".into(),
                hint_epoch_ms: 1_750_000_000_000,
                ml_dsa_pubkey: vec![0x42; 4],
                signature: vec![0x41; 4],
            },
        }
    }

    #[test]
    fn register_request_matches_contract_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/registry-v1/register-request.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(contract_request()).unwrap(), fixture);
    }

    #[tokio::test]
    async fn register_posts_to_v1_actors_and_decodes_created() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/actors"))
            .and(body_json(serde_json::to_value(contract_request()).unwrap()))
            .respond_with(ResponseTemplate::new(201).set_body_string(include_str!(
                "../tests/fixtures/registry-v1/register-response.json"
            )))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        let resp = register_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap();
        assert_eq!(resp.actor_url, "https://etchit.io/actors/josh");
    }

    #[tokio::test]
    async fn update_puts_to_handle_path() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/actors/josh"))
            .respond_with(ResponseTemplate::new(200).set_body_string(include_str!(
                "../tests/fixtures/registry-v1/register-response.json"
            )))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        update_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_codes_map_to_typed_errors() {
        for (status, want_taken, want_rate) in [(409u16, true, false), (429, false, true)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/actors"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let base: url::Url = server.uri().parse().unwrap();
            let err = register_actor(&base, &contract_request(), &reqwest::Client::new())
                .await
                .unwrap_err();
            assert_eq!(matches!(err, RegistryError::HandleTaken), want_taken);
            assert_eq!(matches!(err, RegistryError::RateLimited), want_rate);
        }
    }

    #[tokio::test]
    async fn unprocessable_carries_reason_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/actors"))
            .respond_with(ResponseTemplate::new(422).set_body_string("bad attestation"))
            .mount(&server)
            .await;
        let base: url::Url = server.uri().parse().unwrap();
        let err = register_actor(&base, &contract_request(), &reqwest::Client::new())
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::AttestationRejected(ref r) if r == "bad attestation"));
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p fetchit-fedi registry`
Expected: compile FAIL

- [ ] **Step 5: Implement registry.rs**

```rust
//! Self-serve actor-registry client (M5.1, Component D).
//!
//! The JSON shapes here are a frozen wire contract shared with
//! `fetchit-bridge-server`; tests pin them against
//! `tests/fixtures/registry-v1/`. See the fixture README for the
//! server-side verification obligations.

use crate::attestation::{b64, ActorAttestationV2};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Per-call timeout for registry requests.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Registration / update request body. One shape for both verbs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterActorRequest {
    /// Local handle, client-validated `[A-Za-z0-9_-]{1,64}`.
    pub handle: String,
    /// RSA `SubjectPublicKeyInfo` DER, base64 on the wire.
    #[serde(with = "b64")]
    pub rsa_spki_der: Vec<u8>,
    /// The signed v2 binding the bridge must verify before serving.
    pub attestation_v2: ActorAttestationV2,
}

/// Success body for both verbs.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisterActorResponse {
    /// Canonical actor URL the directory now serves.
    pub actor_url: String,
}

/// Typed failure surface so the UI can render per-cause copy.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// 409: the handle is registered (to this or another agent).
    #[error("handle already registered")]
    HandleTaken,
    /// 422: the bridge rejected the attestation; reason text attached.
    #[error("registry rejected the attestation: {0}")]
    AttestationRejected(String),
    /// 429: per-source rate limit.
    #[error("registry rate limit hit; retry later")]
    RateLimited,
    /// Connection / DNS / TLS / body-read failure.
    #[error("transport: {0}")]
    Transport(String),
    /// Any other non-success status.
    #[error("registry returned HTTP {status}: {body}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// First 256 chars of the response body.
        body: String,
    },
}

/// `POST {base}v1/actors`: first-time registration.
///
/// # Errors
/// [`RegistryError`] per the contract README's response table.
pub async fn register_actor(
    base: &url::Url,
    req: &RegisterActorRequest,
    http: &reqwest::Client,
) -> Result<RegisterActorResponse, RegistryError> {
    let url = base
        .join("v1/actors")
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .post(url)
        .json(req)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    decode_response(resp).await
}

/// `PUT {base}v1/actors/<handle>`: update (new epoch, key rotation).
///
/// # Errors
/// [`RegistryError`] per the contract README's response table.
pub async fn update_actor(
    base: &url::Url,
    req: &RegisterActorRequest,
    http: &reqwest::Client,
) -> Result<RegisterActorResponse, RegistryError> {
    let url = base
        .join(&format!("v1/actors/{}", req.handle))
        .map_err(|e| RegistryError::Transport(format!("build url: {e}")))?;
    let resp = http
        .put(url)
        .json(req)
        .timeout(REGISTRY_TIMEOUT)
        .send()
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    decode_response(resp).await
}

async fn decode_response(
    resp: reqwest::Response,
) -> Result<RegisterActorResponse, RegistryError> {
    let status = resp.status().as_u16();
    match status {
        200 | 201 => resp
            .json()
            .await
            .map_err(|e| RegistryError::Transport(format!("response decode: {e}"))),
        409 => Err(RegistryError::HandleTaken),
        422 => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::AttestationRejected(
                body.chars().take(256).collect(),
            ))
        }
        429 => Err(RegistryError::RateLimited),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(RegistryError::Status {
                status,
                body: body.chars().take(256).collect(),
            })
        }
    }
}
```

Declare `pub mod registry;` in lib.rs. The handle in `update_actor` is path-safe by the crate's handle alphabet (`[A-Za-z0-9_-]`); the bridge re-validates.

- [ ] **Step 6: Run tests, lint, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-fedi`
Expected: PASS

```bash
git add crates/fetchit-fedi
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(fedi): actor-registry client with wire-contract fixtures'
```

---

### Task 6: v2 signing + vault storage (fetchit-chat)

**Files:**
- Modify: `crates/fetchit-chat/src/fedi_identity.rs`, `crates/fetchit-chat/src/fedi_vault.rs`

- [ ] **Step 1: Write the failing tests**

In fedi_identity.rs tests (mirror its existing test setup; if it has no signer mock, build one from a real saorsa keypair):

```rust
#[tokio::test]
async fn sign_actor_attestation_v2_round_trips_through_verify() {
    use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
    struct TestSigner {
        pk: Vec<u8>,
        sk: saorsa_pqc::api::sig::MlDsaSecretKey,
    }
    #[async_trait::async_trait]
    impl x0xd_client::Signer for TestSigner {
        fn agent_id(&self) -> [u8; 32] {
            fetchit_relay_proto::derive_agent_id(&self.pk)
        }
        fn public_key(&self) -> Vec<u8> {
            self.pk.clone()
        }
        async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
            let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
            Ok(dsa.sign(&self.sk, message).map_err(|e| e.to_string())?.to_bytes())
        }
    }
    let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (pk, sk) = dsa.generate_keypair().unwrap();
    let signer = TestSigner { pk: pk.to_bytes(), sk };
    let agent_id_hex = hex::encode(signer.agent_id());
    let actor_url: url::Url = "https://etchit.io/actors/josh".parse().unwrap();
    let att = sign_actor_attestation_v2(
        "josh", &actor_url, &agent_id_hex, &[7, 7], &"a".repeat(64),
        "https://relay.example/", 99, &signer,
    )
    .await
    .unwrap();
    let derived =
        fetchit_fedi::attestation::verify_binding_v2("josh", &actor_url, &[7, 7], &att).unwrap();
    assert_eq!(derived, agent_id_hex);
}
```

In fedi_vault.rs tests:

```rust
#[test]
fn vault_round_trips_v2_attestation() {
    // copy the save_and_load_round_trip setup (line 222), set
    // ml_dsa_attestation_v2 to a populated ActorAttestationV2, assert
    // it survives the AEAD round trip.
}

#[test]
fn legacy_vault_json_without_v2_field_deserializes_to_none() {
    let json = r#"{
        "handle": "josh",
        "actor_url": "https://etchit.io/actors/josh",
        "agent_id_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "rsa_priv_pem": "PEM",
        "spki_der": [1, 2, 3],
        "ml_dsa_attestation": { "ml_dsa_pubkey": "QQ==", "signature": "Qg==" }
    }"#;
    let v: ActorIdentityVault = serde_json::from_str(json).unwrap();
    assert!(v.ml_dsa_attestation_v2.is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p fetchit-chat fedi_`
Expected: compile FAIL

- [ ] **Step 3: Implement**

fedi_vault.rs, appended to `ActorIdentityVault`:

```rust
    /// v2 attestation (adds profile addr + relay hint to the signed
    /// binding). `None` on records minted before M5; the upgrade path
    /// re-signs in place without touching the RSA material.
    #[serde(default)]
    pub ml_dsa_attestation_v2: Option<fetchit_fedi::attestation::ActorAttestationV2>,
```

fedi_identity.rs, below `sign_actor_attestation` (mirror its doc style):

```rust
/// Sign a v2 actor attestation over the extended field tuple. Same
/// signer and error surface as [`sign_actor_attestation`].
///
/// # Errors
/// [`ChatError::Invalid`] when input construction or signing fails.
#[allow(clippy::too_many_arguments)]
pub async fn sign_actor_attestation_v2(
    handle: &str,
    actor_url: &url::Url,
    agent_id_hex: &str,
    spki_der: &[u8],
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
    signer: &dyn x0xd_client::Signer,
) -> Result<fetchit_fedi::attestation::ActorAttestationV2, ChatError> {
    let input = fetchit_fedi::attestation::signing_input_v2(
        handle, actor_url, agent_id_hex, spki_der, profile_addr, relay_hint, hint_epoch_ms,
    )
    .map_err(|e| ChatError::Invalid(format!("signing_input_v2: {e}")))?;
    let signature = signer
        .sign(&input)
        .await
        .map_err(|e| ChatError::Invalid(format!("ml-dsa sign: {e}")))?;
    Ok(fetchit_fedi::attestation::ActorAttestationV2 {
        version: 2,
        profile_addr: profile_addr.to_string(),
        relay_hint: relay_hint.to_string(),
        hint_epoch_ms,
        ml_dsa_pubkey: signer.public_key(),
        signature,
    })
}
```

Fix vault construction sites (`client.rs:2940`, `fedi_vault.rs:214` fixture, `rekey.rs:250`) with `ml_dsa_attestation_v2: None`.

- [ ] **Step 4: Run tests, lint, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-chat`
Expected: PASS

```bash
git add crates/fetchit-chat/src
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(chat): v2 attestation signing and vault storage'
```

---

### Task 7: mint_actor_identity_v2 + upgrade path (fetchit-chat)

**Files:**
- Modify: `crates/fetchit-chat/src/client.rs`

- [ ] **Step 1: Read the v1 mint**

Read `crates/fetchit-chat/src/client.rs` lines 2890-3010: `mint_actor_identity` (2904-2958), the vault-to-`ActorIdentity` conversion around 2990-3000, and `validate_actor_handle` (3172). Note the exact names used for the chat-state accessor, master-key resolution, and `ActorIdentity` construction; the code below uses those names.

- [ ] **Step 2: Implement `mint_actor_identity_v2`**

Directly below `mint_actor_identity`, a v2 twin that follows the v1 body line-for-line with three deltas (sign v2 in addition to v1, store it in the vault, attach it to the returned identity):

```rust
/// Mint the actor identity AND its v2 attestation in one step. The
/// caller supplies the published profile address and the active relay
/// (the v3 share-URI fields); both become part of the signed binding.
/// The v1 attestation is still minted and emitted for actor-document
/// compatibility with pre-M5 verifiers.
///
/// # Errors
/// Same surface as [`Client::mint_actor_identity`], plus signing-input
/// validation of `profile_addr` / `relay_hint`.
#[allow(clippy::too_many_arguments)]
pub async fn mint_actor_identity_v2(
    &self,
    handle: &str,
    domain: &str,
    passphrase: Option<&str>,
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
) -> Result<fetchit_fedi::actor::ActorIdentity> {
    // ... identical preamble to mint_actor_identity: validate handle,
    // build actor_url, agent_id_hex, resolve master, generate RSA ...
    let attestation = crate::fedi_identity::sign_actor_attestation(
        handle, &actor_url, &agent_id_hex, &material.spki_der, chat.signer.as_ref(),
    )
    .await?;
    let attestation_v2 = crate::fedi_identity::sign_actor_attestation_v2(
        handle, &actor_url, &agent_id_hex, &material.spki_der,
        profile_addr, relay_hint, hint_epoch_ms, chat.signer.as_ref(),
    )
    .await?;
    let vault = crate::fedi_vault::ActorIdentityVault {
        handle: handle.to_string(),
        actor_url: actor_url.clone(),
        agent_id_hex: agent_id_hex.clone(),
        rsa_priv_pem: material.priv_pem.clone(),
        spki_der: material.spki_der.clone(),
        ml_dsa_attestation: attestation.clone(),
        ml_dsa_attestation_v2: Some(attestation_v2.clone()),
    };
    crate::fedi_vault::save_actor_identity(&vault, &master, &chat.layout)?;
    // ... identical ActorIdentity construction to v1, then:
    Ok(identity.with_attestation_v2(attestation_v2))
}
```

Also thread `vault.ml_dsa_attestation_v2` into the existing vault-to-identity conversion around line 2996 (the path the desktop uses to re-load the identity): when `Some`, attach via `with_attestation_v2`. If no such accessor exists as a public method, add one:

```rust
/// Load the minted actor identity for `handle` from the fedi vault.
///
/// # Errors
/// [`ChatError::Invalid`] when no vault exists for the handle or the
/// master key fails to open it.
pub async fn actor_identity(
    &self,
    handle: &str,
    passphrase: Option<&str>,
) -> Result<fetchit_fedi::actor::ActorIdentity> {
    // mirror the existing conversion at ~2990: load vault, build
    // ActorIdentity, attach v2 when present.
}
```

- [ ] **Step 3: Implement `upgrade_actor_attestation_v2`**

```rust
/// Re-sign the v2 attestation in place: same handle, same actor URL,
/// SAME RSA keypair (HTTP-signature key continuity is the invariant;
/// this function never regenerates RSA material). Returns `false`
/// when the stored v2 attestation already covers the same
/// `profile_addr` and `relay_hint`.
///
/// # Errors
/// [`ChatError::Invalid`] when no identity exists for `handle`, the
/// vault fails to open, or signing fails.
pub async fn upgrade_actor_attestation_v2(
    &self,
    handle: &str,
    passphrase: Option<&str>,
    profile_addr: &str,
    relay_hint: &str,
    hint_epoch_ms: u64,
) -> Result<bool> {
    validate_actor_handle(handle)?;
    // same chat-state + master-key resolution as mint_actor_identity
    let Some(mut vault) = crate::fedi_vault::load_actor_identity(handle, &master, &chat.layout)?
    else {
        return Err(ChatError::Invalid(format!("no actor identity for {handle}")));
    };
    if let Some(v2) = &vault.ml_dsa_attestation_v2 {
        if v2.profile_addr == profile_addr && v2.relay_hint == relay_hint {
            return Ok(false);
        }
    }
    let agent_id_hex = chat.identity.agent_id_hex().to_string();
    let attestation_v2 = crate::fedi_identity::sign_actor_attestation_v2(
        handle, &vault.actor_url, &agent_id_hex, &vault.spki_der,
        profile_addr, relay_hint, hint_epoch_ms, chat.signer.as_ref(),
    )
    .await?;
    vault.ml_dsa_attestation_v2 = Some(attestation_v2);
    crate::fedi_vault::save_actor_identity(&vault, &master, &chat.layout)?;
    Ok(true)
}
```

(Adjust `load_actor_identity` to the real fedi_vault loader name and signature; the vault tests at fedi_vault.rs:222 show it.)

- [ ] **Step 4: Tests**

The mint/upgrade orchestration needs a live chat state, which client.rs unit tests do not spin up; the crypto and persistence layers are covered by Task 6's tests. Add what IS unit-testable here: if `mint_actor_identity` has existing unit tests, mirror them for v2; otherwise rely on `cargo test -p fetchit-chat` staying green plus the desktop integration in Task 9, and note that in the commit body is NOT needed (tests-as-you-go is satisfied at the layer boundaries).

- [ ] **Step 5: Run gates, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-chat`
Expected: PASS

```bash
git add crates/fetchit-chat/src/client.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(chat): mint and upgrade actor identity v2'
```

---

### Task 8: Handle-resolution continuity ledger (fetchit-chat)

**Files:**
- Create: `crates/fetchit-chat/src/fedi_resolutions.rs`
- Modify: `crates/fetchit-chat/src/lib.rs` (declare module), `crates/fetchit-chat/src/local_store.rs` (path accessor)

- [ ] **Step 1: Read the layout API**

Read the `actor_identity_path` method in `crates/fetchit-chat/src/local_store.rs` (grep for it) to learn how the `fedi/` directory is constructed, then add beside it:

```rust
/// Path of the handle-resolution continuity ledger (M5.1): a JSON map
/// of canonical fediverse handle to the agent id it last verifiably
/// resolved to.
#[must_use]
pub fn fedi_resolutions_path(&self) -> std::path::PathBuf {
    // same directory as actor_identity_path, file handle_resolutions.json
}
```

- [ ] **Step 2: Write the failing tests**

In fedi_resolutions.rs (mirror fedi_vault.rs test setup for a temp `StoreLayout`):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // reuse the temp-layout helper pattern from fedi_vault.rs tests

    #[test]
    fn first_resolution_is_new_then_same() {
        let (layout, _tmp) = test_layout();
        let a = "a".repeat(64);
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &a).unwrap(),
            ResolutionChange::New
        );
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &a).unwrap(),
            ResolutionChange::Same
        );
    }

    #[test]
    fn different_agent_id_reports_changed_with_previous() {
        let (layout, _tmp) = test_layout();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        note_resolution(&layout, "@josh@etchit.io", &a).unwrap();
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &b).unwrap(),
            ResolutionChange::Changed {
                previous_agent_id_hex: a
            }
        );
        // and the ledger now stores the new binding
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &b).unwrap(),
            ResolutionChange::Same
        );
    }

    #[test]
    fn handles_are_tracked_independently() {
        let (layout, _tmp) = test_layout();
        note_resolution(&layout, "@a@x.io", &"a".repeat(64)).unwrap();
        assert_eq!(
            note_resolution(&layout, "@b@x.io", &"b".repeat(64)).unwrap(),
            ResolutionChange::New
        );
    }

    #[test]
    fn corrupt_ledger_resets_to_empty_rather_than_erroring() {
        let (layout, _tmp) = test_layout();
        std::fs::create_dir_all(layout.fedi_resolutions_path().parent().unwrap()).unwrap();
        std::fs::write(layout.fedi_resolutions_path(), b"not json").unwrap();
        assert_eq!(
            note_resolution(&layout, "@josh@etchit.io", &"a".repeat(64)).unwrap(),
            ResolutionChange::New
        );
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p fetchit-chat fedi_resolutions`
Expected: compile FAIL

- [ ] **Step 4: Implement**

```rust
//! Handle-to-agent continuity ledger (M5.1).
//!
//! Lookup is keyed by handle, but trust is keyed by agent id. This
//! small persisted map remembers which agent id each handle last
//! verifiably resolved to, so the actor card can surface "this handle
//! changed hands" instead of silently presenting a new identity under
//! a familiar name. Best-effort local state: a corrupt ledger resets
//! continuity (an attacker who can corrupt local disk already owns
//! stronger primitives), it never blocks a lookup.

use crate::error::{ChatError, Result};
use crate::local_store::StoreLayout;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Serializes ledger read-modify-write cycles (same pattern as
/// `messages::CARD_UPDATE_LOCK`).
static RESOLUTIONS_LOCK: Mutex<()> = Mutex::new(());

/// Outcome of recording a verified handle resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionChange {
    /// First time this handle resolved on this device.
    New,
    /// Same agent id as last time.
    Same,
    /// The handle now resolves to a DIFFERENT agent id; surface it.
    Changed {
        /// The agent id this handle previously resolved to.
        previous_agent_id_hex: String,
    },
}

/// Record that `canonical_handle` verifiably resolved to
/// `agent_id_hex`, returning how that compares to the last record.
/// `canonical_handle` is the `@local@instance` form produced by
/// `fetchit_fedi::parse_mention` (instance already lowercased).
///
/// # Errors
/// [`ChatError::Invalid`] when the ledger cannot be written.
pub fn note_resolution(
    layout: &StoreLayout,
    canonical_handle: &str,
    agent_id_hex: &str,
) -> Result<ResolutionChange> {
    let _guard = RESOLUTIONS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = layout.fedi_resolutions_path();
    let mut map: BTreeMap<String, String> = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    };
    let change = match map.get(canonical_handle) {
        None => ResolutionChange::New,
        Some(prev) if prev == agent_id_hex => ResolutionChange::Same,
        Some(prev) => ResolutionChange::Changed {
            previous_agent_id_hex: prev.clone(),
        },
    };
    map.insert(canonical_handle.to_string(), agent_id_hex.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ChatError::Invalid(format!("fedi dir: {e}")))?;
    }
    let json = serde_json::to_vec_pretty(&map)
        .map_err(|e| ChatError::Invalid(format!("resolutions encode: {e}")))?;
    std::fs::write(&path, json)
        .map_err(|e| ChatError::Invalid(format!("resolutions write: {e}")))?;
    Ok(change)
}
```

Declare `pub mod fedi_resolutions;` in lib.rs. If `ChatError::Invalid` is not the conventional variant for IO in this crate, use whatever `fedi_vault.rs` maps IO errors to.

- [ ] **Step 5: Run tests, lint, commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p fetchit-chat`
Expected: PASS

```bash
git add crates/fetchit-chat/src
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(chat): handle-resolution continuity ledger'
```

---

### Task 9: Desktop mint v2 + ensure + directory registration

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs` (factor `self_profile_record`)
- Modify: `apps/fetchit-desktop/src-tauri/src/fediverse.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (register `fediverse_ensure_v2`)

- [ ] **Step 1: Factor the self-lookup out of `chat_pair_share`**

In chat.rs, extract lines 629-656 into:

```rust
/// User-facing copy for the publish-first gate, shared by pair-share,
/// actor mint, and the v2 upgrade path.
pub(crate) const PROFILE_FIRST_COPY: &str =
    "Publish your profile first — open the Profile tab in etch>it and click Publish.";

/// Self-look-up the local user's profile-index record on the active
/// relay. Returns the record plus the relay it was served from.
pub(crate) async fn self_profile_record(
    state: &ChatState,
) -> Result<(fetchit_chat::pair::ProfileIndexRecord, Url), String> {
    let client = state.get().await?;
    let me = client.identity().me().await.map_err(|e| e.to_string())?;
    let relay = state.relay_url();
    let http = reqwest::Client::new();
    let url = relay
        .join(&format!("v1/profile/{}", me.agent_id.0))
        .map_err(|e| format!("build relay URL: {e}"))?;
    let resp = http
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("relay fetch: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Err(PROFILE_FIRST_COPY.to_string());
    }
    if !resp.status().is_success() {
        return Err(format!("relay returned {}", resp.status()));
    }
    let record: fetchit_chat::pair::ProfileIndexRecord =
        resp.json().await.map_err(|e| format!("relay JSON: {e}"))?;
    Ok((record, relay))
}
```

(`PROFILE_FIRST_COPY` is the existing string from `chat_pair_share` moved verbatim, not new copy.) `chat_pair_share` becomes the thin wrapper: call `self_profile_record(&state)`, then the existing `to_v3_share_uri` tail. If `ChatState::get` is on the State wrapper rather than `&ChatState`, take `state: &tauri::State<'_, ChatState>` instead; match what compiles cleanly.

Run `(cd apps/fetchit-desktop/src-tauri && cargo test)`: green, pure refactor.

- [ ] **Step 2: Write the failing DTO tests**

In fediverse.rs tests:

```rust
#[test]
fn mint_outcome_dto_serializes_camel_case() {
    let dto = MintOutcomeDto {
        actor_url: "https://etchit.io/actors/josh".into(),
        registered: false,
        registration_error: Some("connection refused".into()),
    };
    let v = serde_json::to_value(&dto).unwrap();
    assert!(v.get("actorUrl").is_some());
    assert!(v.get("registrationError").is_some());
}

#[test]
fn ensure_v2_dto_serializes_camel_case() {
    let dto = EnsureV2Dto {
        upgraded: true,
        registered: false,
        pending: None,
    };
    let v = serde_json::to_value(&dto).unwrap();
    assert!(v.get("upgraded").is_some());
    assert!(v.get("registered").is_some());
}
```

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test fediverse)`
Expected: compile FAIL

- [ ] **Step 3: Implement**

In fediverse.rs:

```rust
/// Result of a mint: the identity is always created locally; directory
/// registration is best-effort and reported honestly.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintOutcomeDto {
    /// Canonical actor URL.
    pub actor_url: String,
    /// True when the etchit.io directory accepted the registration.
    pub registered: bool,
    /// Why registration is pending, when it is.
    pub registration_error: Option<String>,
}

/// Result of the v2 upgrade pass run on pane open.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureV2Dto {
    /// True when a fresh v2 attestation was signed and stored.
    pub upgraded: bool,
    /// True when the directory holds the current record.
    pub registered: bool,
    /// Why the pass could not complete (profile unpublished, bridge
    /// unreachable); user-facing copy.
    pub pending: Option<String>,
}

/// Milliseconds since the epoch (same construction `fediverse_publish`
/// uses for `created_at_ms`).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Best-effort directory registration. Mint stays local-first: a
/// bridge outage degrades to "registration pending", never a failed
/// mint. POST then PUT on 409 so re-registering our own handle after
/// an attestation refresh self-heals.
async fn register_with_directory(
    identity: &fetchit_fedi::actor::ActorIdentity,
) -> (bool, Option<String>) {
    let Some(att2) = identity.ml_dsa_attestation_v2.clone() else {
        return (false, Some("no v2 attestation on identity".into()));
    };
    let spki_der = match fetchit_fedi::actor::spki_pem_to_der(&identity.rsa_public_key_pem) {
        Ok(d) => d,
        Err(e) => return (false, Some(format!("spki decode: {e}"))),
    };
    let Ok(base) = url::Url::parse(&format!("https://{DEFAULT_FEDI_DOMAIN}/")) else {
        return (false, Some("bad registry base URL".into()));
    };
    let req = fetchit_fedi::registry::RegisterActorRequest {
        handle: identity.handle.clone(),
        rsa_spki_der: spki_der,
        attestation_v2: att2,
    };
    let Ok(http) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
    else {
        return (false, Some("http client build failed".into()));
    };
    match fetchit_fedi::registry::register_actor(&base, &req, &http).await {
        Ok(_) => (true, None),
        Err(fetchit_fedi::registry::RegistryError::HandleTaken) => {
            match fetchit_fedi::registry::update_actor(&base, &req, &http).await {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            }
        }
        Err(e) => (false, Some(e.to_string())),
    }
}
```

(Adjust `identity.handle` / `identity.rsa_public_key_pem` to the real `ActorIdentity` field names read in Task 3.)

Rewrite `fediverse_mint` (return type changes to `MintOutcomeDto`):

```rust
#[tauri::command]
pub async fn fediverse_mint(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
    handle: String,
) -> Result<MintOutcomeDto, String> {
    ensure_chat_enabled(&app_state)?;
    let (record, relay) = crate::chat::self_profile_record(&chat_state).await?;
    let client = chat_state.get().await?;
    let identity = client
        .mint_actor_identity_v2(
            &handle,
            DEFAULT_FEDI_DOMAIN,
            None,
            &record.profile_addr,
            relay.as_str(),
            now_ms(),
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Ok(mut s) = app_state.settings.lock() {
        s.fediverse_handle = handle;
        if let Err(e) = s.save(&app_state.settings_path) {
            tracing::warn!("minted handle held in memory only; settings save failed: {e}");
        }
    }
    let (registered, registration_error) = register_with_directory(&identity).await;
    Ok(MintOutcomeDto {
        actor_url: identity.actor_url.to_string(),
        registered,
        registration_error,
    })
}
```

Add `fediverse_ensure_v2`:

```rust
/// Run on pane open when a handle exists: transparently upgrade a
/// pre-M5 (v1-only) identity to v2 and re-assert the directory record.
/// Never errors the pane: every blocker lands in `pending`.
#[tauri::command]
pub async fn fediverse_ensure_v2(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
) -> Result<EnsureV2Dto, String> {
    ensure_chat_enabled(&app_state)?;
    let handle = app_state
        .settings
        .lock()
        .map_err(|e| format!("settings lock poisoned: {e}"))?
        .fediverse_handle
        .clone();
    if handle.is_empty() {
        return Ok(EnsureV2Dto { upgraded: false, registered: false, pending: None });
    }
    let (record, relay) = match crate::chat::self_profile_record(&chat_state).await {
        Ok(v) => v,
        Err(reason) => {
            return Ok(EnsureV2Dto { upgraded: false, registered: false, pending: Some(reason) })
        }
    };
    let client = chat_state.get().await?;
    let upgraded = client
        .upgrade_actor_attestation_v2(&handle, None, &record.profile_addr, relay.as_str(), now_ms())
        .await
        .map_err(|e| e.to_string())?;
    let identity = client
        .actor_identity(&handle, None)
        .await
        .map_err(|e| e.to_string())?;
    let (registered, err) = register_with_directory(&identity).await;
    Ok(EnsureV2Dto { upgraded, registered, pending: err })
}
```

Register `fediverse_ensure_v2` in the `generate_handler![]` list (lib.rs:1072).

- [ ] **Step 4: Run gates, commit**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: PASS

```bash
git add apps/fetchit-desktop/src-tauri
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(desktop): mint v2 with best-effort directory registration'
```

---

### Task 10: fediverse_lookup command (desktop backend)

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/fediverse_lookup.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/profile.rs` (visibility), `apps/fetchit-desktop/src-tauri/src/lib.rs` (module + handler)

- [ ] **Step 1: Widen profile.rs internals**

Make `build_profile_outcome`, `ProfileOutcome`, `AvatarDto`, and `MAX_MANIFEST_BYTES` `pub(crate)` (they are consumed by the new module). Confirm `ProfileOutcome`'s variants and `build_profile_outcome`'s exact signature from profile.rs while editing.

- [ ] **Step 2: Write the failing DTO tests**

In the new module's test section:

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn public_only_dto_serializes_with_kind_and_camel_case() {
        let dto = LookupDto::public_only(
            "@gargron@mastodon.social".into(),
            "https://mastodon.social/users/Gargron".into(),
            Some("attestation signature does not verify".into()),
        );
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["kind"], "publicOnly");
        assert_eq!(v["verifyFailure"], "attestation signature does not verify");
        assert!(v["agentIdHex"].is_null());
        assert!(v["shareUri"].is_null());
    }

    #[test]
    fn verified_dto_carries_bootstrap_fields() {
        let dto = LookupDto {
            kind: "verified".into(),
            handle: "@josh@etchit.io".into(),
            actor_url: "https://etchit.io/actors/josh".into(),
            agent_id_hex: Some("a".repeat(64)),
            display_name: Some("Josh".into()),
            bio: None,
            avatar: None,
            share_uri: Some(format!("fetchit://share/v3/{}/{}?relay=x", "a".repeat(64), "b".repeat(64))),
            previous_agent_id_hex: None,
            verify_failure: None,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["kind"], "verified");
        assert!(v["shareUri"].as_str().unwrap().starts_with("fetchit://share/v3/"));
        assert!(v["previousAgentIdHex"].is_null());
    }
}
```

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test fediverse_lookup)`
Expected: compile FAIL

- [ ] **Step 3: Implement**

```rust
//! M5.1 handle lookup: one search box, two outcomes. Composes the
//! resolution chain (WebFinger, actor doc, attestation v2 verify,
//! relay profile-index, Autonomi manifest) and returns a flat DTO the
//! actor card renders. Crypto or attestation failure means the
//! public-only card with a visible verify_failure; transport failure
//! after that point is a command error (honest error state, never a
//! silent trust downgrade).

use crate::chat::{ensure_chat_enabled, ChatState};
use crate::profile::{build_profile_outcome, AvatarDto, ProfileOutcome, MAX_MANIFEST_BYTES};
use crate::state::AppState;
use serde::Serialize;

/// Flat lookup result. `kind` is `"verified"` or `"publicOnly"`;
/// fields outside the matching kind are `None`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupDto {
    pub kind: String,
    pub handle: String,
    pub actor_url: String,
    pub agent_id_hex: Option<String>,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar: Option<AvatarDto>,
    /// Synthesized v3 share URI; "Message privately" feeds it to the
    /// existing chat_pair_accept flow unchanged.
    pub share_uri: Option<String>,
    /// Set when this handle previously resolved to a different agent
    /// id on this device ("handle changed hands").
    pub previous_agent_id_hex: Option<String>,
    /// Set when an attestation was present but failed verification.
    pub verify_failure: Option<String>,
}

impl LookupDto {
    fn public_only(handle: String, actor_url: String, verify_failure: Option<String>) -> Self {
        Self {
            kind: "publicOnly".into(),
            handle,
            actor_url,
            agent_id_hex: None,
            display_name: None,
            bio: None,
            avatar: None,
            share_uri: None,
            previous_agent_id_hex: None,
            verify_failure,
        }
    }
}

/// Resolve a fediverse handle to an actor card.
///
/// # Errors
/// User-facing strings for transport-class failures only; trust
/// failures return the public-only DTO instead.
#[tauri::command]
pub async fn fediverse_lookup(
    app_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, ChatState>,
    handle: String,
) -> Result<LookupDto, String> {
    ensure_chat_enabled(&app_state)?;
    let parsed = fetchit_fedi::parse_mention(handle.trim()).map_err(|e| e.to_string())?;
    let canonical = format!("@{}@{}", parsed.local, parsed.instance);
    let actor_url = fetchit_fedi::resolve_handle(&parsed)
        .await
        .map_err(|e| format!("couldn't resolve {canonical} ({e})"))?;
    let actor = fetchit_fedi::lookup::fetch_remote_actor(&actor_url)
        .await
        .map_err(|e| format!("couldn't fetch that account ({e})"))?;
    let actor_url_str = actor.id.to_string();

    if actor.attestation_v2.is_none() {
        return Ok(LookupDto::public_only(canonical, actor_url_str, None));
    }
    let agent_id_hex = match actor.verify_attestation_v2() {
        Ok(id) => id,
        Err(e) => {
            return Ok(LookupDto::public_only(canonical, actor_url_str, Some(e.to_string())))
        }
    };
    // The attestation is part of trust: a relay hint that does not
    // parse fails closed to public-only, same as a bad signature.
    let Some(att) = actor.attestation_v2.as_ref() else {
        return Ok(LookupDto::public_only(canonical, actor_url_str, None));
    };
    let Ok(relay) = att.relay_hint.parse::<url::Url>() else {
        return Ok(LookupDto::public_only(
            canonical,
            actor_url_str,
            Some("attested relay hint is not a valid URL".into()),
        ));
    };

    // Live profile-index record from THEIR relay (self-signed; the
    // fetch cross-checks the agent id binding internally).
    let http = fetchit_chat::relay_http::guarded_client();
    let record = fetchit_chat::pair::fetch_index_record_by_id(&relay, &agent_id_hex, &http)
        .await
        .map_err(|e| format!("couldn't reach their relay ({e})"))?;

    // Rich display fields from the Autonomi manifest; a missing
    // profile degrades to the short agent id, never an error.
    let (display_name, bio, avatar) = match crate::fetch_autonomi_bytes(
        &app_state,
        &record.profile_addr,
        MAX_MANIFEST_BYTES,
    )
    .await
    {
        Ok(bytes) => match build_profile_outcome(&agent_id_hex, &record.agent_id, &bytes, None) {
            Ok(ProfileOutcome::Profile(dto)) => (Some(dto.display_name), dto.bio, dto.avatar),
            _ => (None, None, None),
        },
        Err(_) => (None, None, None),
    };

    let share_uri =
        fetchit_chat::profile::to_v3_share_uri(&agent_id_hex, &record.profile_addr, &relay)
            .map_err(|e| format!("couldn't build the contact pointer ({e})"))?;

    // Continuity ledger: surfaces "handle changed hands".
    let client = chat_state.get().await?;
    let previous_agent_id_hex = match client.layout() {
        Some(layout) => {
            match fetchit_chat::fedi_resolutions::note_resolution(layout, &canonical, &agent_id_hex)
            {
                Ok(fetchit_chat::fedi_resolutions::ResolutionChange::Changed {
                    previous_agent_id_hex,
                }) => Some(previous_agent_id_hex),
                _ => None,
            }
        }
        None => None,
    };

    Ok(LookupDto {
        kind: "verified".into(),
        handle: canonical,
        actor_url: actor_url_str,
        agent_id_hex: Some(agent_id_hex),
        display_name,
        bio,
        avatar,
        share_uri: Some(share_uri),
        previous_agent_id_hex,
        verify_failure: None,
    })
}
```

Declare `mod fediverse_lookup;` in lib.rs and add `fediverse_lookup::fediverse_lookup` to `generate_handler![]`. Match `ProfileOutcome`'s real variant names and `client.layout()`'s real signature (see `chat_pair_accept` at chat.rs:562 for the layout accessor pattern).

- [ ] **Step 4: Run gates, commit**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: PASS

```bash
git add apps/fetchit-desktop/src-tauri
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(desktop): fediverse handle lookup command'
```

---

### Task 11: Lookup UI: api wrapper + actor card (desktop frontend)

**Files:**
- Create: `apps/fetchit-desktop/src/fediverse/api.ts`
- Create: `apps/fetchit-desktop/src/fediverse/lookup.ts`
- Create: `apps/fetchit-desktop/src/fediverse/lookup.test.ts`
- Modify: `apps/fetchit-desktop/src/fediverse/styles.css`

- [ ] **Step 1: Write api.ts**

```typescript
// Typed wrappers for the M5 fediverse commands. Mirrors chat/api.ts:
// thin invoke passthroughs; Rust commands stringify their own errors.

import { invoke } from "@tauri-apps/api/core";

export interface LookupAvatar {
  addr: string;
  mime: string;
  w: number;
  h: number;
  bytesLen: number;
}

export interface LookupResult {
  kind: "verified" | "publicOnly";
  handle: string;
  actorUrl: string;
  agentIdHex?: string | null;
  displayName?: string | null;
  bio?: string | null;
  avatar?: LookupAvatar | null;
  shareUri?: string | null;
  previousAgentIdHex?: string | null;
  verifyFailure?: string | null;
}

export async function lookupHandle(handle: string): Promise<LookupResult> {
  return invoke<LookupResult>("fediverse_lookup", { handle });
}

export interface MintOutcome {
  actorUrl: string;
  registered: boolean;
  registrationError: string | null;
}

export async function mintActor(handle: string): Promise<MintOutcome> {
  return invoke<MintOutcome>("fediverse_mint", { handle });
}

export interface EnsureV2Outcome {
  upgraded: boolean;
  registered: boolean;
  pending: string | null;
}

export async function ensureV2(): Promise<EnsureV2Outcome> {
  return invoke<EnsureV2Outcome>("fediverse_ensure_v2");
}
```

- [ ] **Step 2: Write the failing tests**

lookup.test.ts, using the compose.test.ts mocking pattern exactly (`vi.mock` before import, `mock.mockImplementation` keyed by command name, `vi.waitFor` for async DOM):

```typescript
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { mountLookup } from "./lookup";

type InvokeMock = ReturnType<typeof vi.fn>;
const mock = invoke as InvokeMock;

const VERIFIED = {
  kind: "verified",
  handle: "@josh@etchit.io",
  actorUrl: "https://etchit.io/actors/josh",
  agentIdHex: "a".repeat(64),
  displayName: "Josh",
  bio: null,
  avatar: null,
  shareUri: `fetchit://share/v3/${"a".repeat(64)}/${"b".repeat(64)}?relay=https%3A%2F%2Frelay.example%2F`,
  previousAgentIdHex: null,
  verifyFailure: null,
};

const PUBLIC_ONLY = {
  kind: "publicOnly",
  handle: "@gargron@mastodon.social",
  actorUrl: "https://mastodon.social/users/Gargron",
  verifyFailure: null,
};

function search(host: HTMLElement, text: string): void {
  const input = host.querySelector<HTMLInputElement>(".fediverse-lookup__input")!;
  input.value = text;
  host.querySelector<HTMLButtonElement>(".fediverse-lookup__btn")!.click();
}

let host: HTMLElement;
let opened: string[];

beforeEach(() => {
  mock.mockReset();
  document.body.innerHTML = "";
  host = document.createElement("div");
  document.body.appendChild(host);
  opened = [];
  mountLookup(host, { onOpenDm: (id) => opened.push(id) });
});

describe("mountLookup", () => {
  it("renders a verified actor card with private affordances", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup" ? Promise.resolve(VERIFIED) : Promise.resolve(null),
    );
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card--verified")).not.toBeNull();
    });
    expect(host.querySelector(".actor-card__msg-btn")).not.toBeNull();
    expect(host.querySelector(".actor-card__invite-btn")).not.toBeNull();
    expect(host.textContent).toContain("Josh");
  });

  it("renders a public-only card without private affordances", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup" ? Promise.resolve(PUBLIC_ONLY) : Promise.resolve(null),
    );
    search(host, "@gargron@mastodon.social");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card--public")).not.toBeNull();
    });
    expect(host.querySelector(".actor-card__msg-btn")).toBeNull();
    expect(host.querySelector(".actor-card__invite-btn")).toBeNull();
  });

  it("shows the could-not-verify state on a failed attestation", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup"
        ? Promise.resolve({ ...PUBLIC_ONLY, verifyFailure: "signature does not verify" })
        : Promise.resolve(null),
    );
    search(host, "@evil@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__warn")).not.toBeNull();
    });
    expect(host.textContent).toContain("Couldn't verify");
    expect(host.querySelector(".actor-card__msg-btn")).toBeNull();
  });

  it("surfaces handle-changed-hands on the verified card", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup"
        ? Promise.resolve({ ...VERIFIED, previousAgentIdHex: "c".repeat(64) })
        : Promise.resolve(null),
    );
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__warn")).not.toBeNull();
    });
    expect(host.textContent).toContain("changed hands");
  });

  it("message-privately imports via chat_pair_accept then opens the DM", async () => {
    mock.mockImplementation((cmd: string) => {
      if (cmd === "fediverse_lookup") return Promise.resolve(VERIFIED);
      if (cmd === "chat_pair_accept")
        return Promise.resolve({ agentIdHex: VERIFIED.agentIdHex, offererRelayUrl: "", crossRelay: false });
      return Promise.resolve(null);
    });
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__msg-btn")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__msg-btn")!.click();
    await vi.waitFor(() => {
      expect(opened).toEqual([VERIFIED.agentIdHex]);
    });
    const accept = mock.mock.calls.find((c) => c[0] === "chat_pair_accept")!;
    expect(accept[1]).toEqual({ uri: VERIFIED.shareUri });
  });

  it("invite-to-group sends the invite URI as a DM", async () => {
    mock.mockImplementation((cmd: string) => {
      if (cmd === "fediverse_lookup") return Promise.resolve(VERIFIED);
      if (cmd === "chat_pair_accept")
        return Promise.resolve({ agentIdHex: VERIFIED.agentIdHex, offererRelayUrl: "", crossRelay: false });
      if (cmd === "chat_groups_list")
        return Promise.resolve([{ groupId: "g1", name: "rust club" }]);
      if (cmd === "chat_group_invite") return Promise.resolve("x0x://invite/abc");
      if (cmd === "chat_send_dm") return Promise.resolve("msg-1");
      return Promise.resolve(null);
    });
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__invite-btn")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__invite-btn")!.click();
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__invite-send")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__invite-send")!.click();
    await vi.waitFor(() => {
      expect(mock.mock.calls.some((c) => c[0] === "chat_send_dm")).toBe(true);
    });
    const dm = mock.mock.calls.find((c) => c[0] === "chat_send_dm")!;
    expect(dm[1].to).toBe(VERIFIED.agentIdHex);
    expect(dm[1].body).toContain("x0x://invite/abc");
  });

  it("renders an error state when lookup rejects", async () => {
    mock.mockImplementation(() => Promise.reject(new Error("couldn't resolve")));
    search(host, "@nobody@nowhere.example");
    await vi.waitFor(() => {
      expect(host.querySelector(".fediverse-lookup__error")).not.toBeNull();
    });
  });
});
```

(Match the `Group` field names against the `Group` type imported by `chat/api.ts`; adjust `groupId`/`name` if they differ. `chat_send_dm` arg assertions reflect chat/api.ts `sendDm`, which sends `{to, body, senderName, replyToMessageId, attachment}`.)

Run: `npm run test:run -- lookup` (from `apps/fetchit-desktop/`)
Expected: FAIL (module not found)

- [ ] **Step 3: Implement lookup.ts**

```typescript
// M5.1 handle lookup: one search box, two outcomes. The verified card
// carries the private affordances; both run EXISTING chat flows
// (chat_pair_accept on the synthesized v3 share URI, the standard
// group-invite URI over a DM). The public-only card never renders a
// private affordance, and a failed attestation is shown, not hidden.

import { groupInvite, listGroups, pairAccept, sendDm } from "../chat/api";
import { errMsg } from "../chat/errors";
import { lookupHandle, type LookupResult } from "./api";

export interface LookupHandlers {
  /// Open the LIT Chat DM for an imported contact.
  onOpenDm: (agentIdHex: string) => void;
}

const HANDLE_RE = /^@[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function mountLookup(host: HTMLElement, handlers: LookupHandlers): void {
  host.classList.add("fediverse-lookup");

  const form = document.createElement("div");
  form.className = "fediverse-lookup__form";

  const input = document.createElement("input");
  input.type = "text";
  input.className = "fediverse-lookup__input";
  input.placeholder = "Find someone: @handle@domain";
  input.spellcheck = false;

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "fediverse-lookup__btn";
  btn.textContent = "Look up";

  const results = document.createElement("div");
  results.className = "fediverse-lookup__results";

  form.append(input, btn);
  host.append(form, results);

  const run = async (): Promise<void> => {
    const handle = input.value.trim();
    if (!HANDLE_RE.test(handle)) {
      results.replaceChildren(errorLine("Type a full handle, like @name@etchit.io"));
      return;
    }
    btn.disabled = true;
    results.replaceChildren(line("fediverse-lookup__loading", `Looking up ${handle}…`));
    try {
      const dto = await lookupHandle(handle);
      results.replaceChildren(renderActorCard(dto, handlers));
    } catch (e) {
      results.replaceChildren(errorLine(errMsg(e)));
    } finally {
      btn.disabled = false;
    }
  };

  btn.addEventListener("click", () => void run());
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void run();
  });
}

function line(className: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = className;
  el.textContent = text;
  return el;
}

function errorLine(text: string): HTMLElement {
  return line("fediverse-lookup__error", text);
}

export function renderActorCard(dto: LookupResult, handlers: LookupHandlers): HTMLElement {
  const card = document.createElement("article");
  card.className = `actor-card actor-card--${dto.kind === "verified" ? "verified" : "public"}`;

  const name = line("actor-card__name", dto.displayName ?? dto.handle);
  const handle = line("actor-card__handle", dto.handle);
  handle.title = dto.actorUrl;
  card.append(name, handle);

  if (dto.kind === "verified" && dto.agentIdHex && dto.shareUri) {
    const badge = line("actor-card__badge", "Verified fetch>it identity");
    const agent = line("actor-card__agent", `agent ${dto.agentIdHex.slice(0, 8)}…`);
    agent.title = dto.agentIdHex;
    card.append(badge, agent);

    if (dto.previousAgentIdHex) {
      card.append(
        line(
          "actor-card__warn",
          "This handle changed hands: it previously belonged to a different identity. "
            + "Your existing contact is unaffected; treat this as a new person.",
        ),
      );
    }

    const status = line("actor-card__status", "");
    const actions = document.createElement("div");
    actions.className = "actor-card__actions";

    const msgBtn = document.createElement("button");
    msgBtn.type = "button";
    msgBtn.className = "actor-card__msg-btn";
    msgBtn.textContent = "Message privately";
    msgBtn.addEventListener("click", () => {
      msgBtn.disabled = true;
      status.textContent = "Adding contact…";
      pairAccept(dto.shareUri!)
        .then((r) => {
          status.textContent = "Added to contacts.";
          handlers.onOpenDm(r.agentIdHex);
        })
        .catch((e: unknown) => {
          status.textContent = `Couldn't add contact: ${errMsg(e)}`;
          msgBtn.disabled = false;
        });
    });

    const inviteBtn = document.createElement("button");
    inviteBtn.type = "button";
    inviteBtn.className = "actor-card__invite-btn";
    inviteBtn.textContent = "Invite to group";
    inviteBtn.addEventListener("click", () => {
      inviteBtn.disabled = true;
      void mountInviteRow(card, dto, status).finally(() => {
        inviteBtn.disabled = false;
      });
    });

    actions.append(msgBtn, inviteBtn);
    card.append(actions, status);
  } else {
    if (dto.verifyFailure) {
      card.append(
        line(
          "actor-card__warn",
          `Couldn't verify this account's fetch>it identity (${dto.verifyFailure}). `
            + "Private messaging is disabled for it.",
        ),
      );
    } else {
      card.append(
        line(
          "actor-card__note",
          "This account hasn't linked a fetch>it identity, so private messaging "
            + "isn't available. You can follow them from any fediverse app.",
        ),
      );
    }
  }
  return card;
}

async function mountInviteRow(
  card: HTMLElement,
  dto: LookupResult,
  status: HTMLElement,
): Promise<void> {
  card.querySelector(".actor-card__invite-row")?.remove();
  const row = document.createElement("div");
  row.className = "actor-card__invite-row";
  let groups;
  try {
    groups = await listGroups();
  } catch (e) {
    status.textContent = `Couldn't load groups: ${errMsg(e)}`;
    return;
  }
  if (groups.length === 0) {
    status.textContent = "No groups yet. Create one in LIT Chat first.";
    return;
  }
  const select = document.createElement("select");
  select.className = "actor-card__invite-select";
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g.groupId;
    opt.textContent = g.name;
    select.appendChild(opt);
  }
  const send = document.createElement("button");
  send.type = "button";
  send.className = "actor-card__invite-send";
  send.textContent = "Send invite";
  send.addEventListener("click", () => {
    send.disabled = true;
    status.textContent = "Sending invite…";
    const groupName = select.selectedOptions[0]?.textContent ?? "a group";
    void (async () => {
      try {
        const imported = await pairAccept(dto.shareUri!);
        const uri = await groupInvite(select.value);
        await sendDm(imported.agentIdHex, `Join "${groupName}" on LIT Chat: ${uri}`);
        status.textContent = "Invite sent.";
        row.remove();
      } catch (e) {
        status.textContent = `Couldn't send the invite: ${errMsg(e)}`;
        send.disabled = false;
      }
    })();
  });
  row.append(select, send);
  card.appendChild(row);
}
```

(Adapt `g.groupId` / `g.name` and the `pairAccept` return field to the real types in `chat/api.ts`; tsc enforces.)

- [ ] **Step 4: Add styles**

Append to `src/fediverse/styles.css`, mirroring the existing token usage (`.feed-post` card pattern, `var(--rust)` for warnings, pill buttons):

```css
.fediverse-lookup { padding: 10px 14px 12px; border-bottom: 1px solid var(--line); }
.fediverse-lookup__form { display: flex; gap: 8px; }
.fediverse-lookup__input {
  flex: 1; font-size: 13px; color: var(--bone);
  background: var(--ink-2); border: 1px solid var(--line);
  border-radius: var(--r-ctl); padding: 6px 10px;
}
.fediverse-lookup__input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.fediverse-lookup__btn {
  font-size: 13px; color: var(--bone); cursor: pointer;
  background: linear-gradient(180deg, var(--copper-bright), var(--copper));
  border: none; border-radius: var(--r-ctl); padding: 6px 14px;
  box-shadow: var(--edge-highlight);
}
.fediverse-lookup__btn:hover { filter: brightness(1.08); }
.fediverse-lookup__btn:active { transform: scale(0.98); }
.fediverse-lookup__btn:disabled { opacity: 0.5; cursor: default; }
.fediverse-lookup__loading, .fediverse-lookup__error { margin-top: 10px; font-size: 12px; }
.fediverse-lookup__loading { color: var(--ash); }
.fediverse-lookup__error { color: var(--rust); }

.actor-card {
  margin-top: 10px; padding: 12px 14px;
  border: 1px solid var(--line); border-radius: var(--r-card);
  background: var(--ink-2); background-image: var(--surface-grad);
  box-shadow: var(--edge-highlight);
}
.actor-card__name { font-size: 15px; font-weight: 600; color: var(--bone); }
.actor-card__handle {
  font-family: ui-monospace, "JetBrains Mono", monospace;
  font-size: 12px; color: var(--copper); word-break: break-all; margin-top: 2px;
}
.actor-card__badge { margin-top: 8px; font-size: 11px; color: var(--signal-ok); }
.actor-card__agent {
  font-family: ui-monospace, "JetBrains Mono", monospace;
  font-size: 11px; color: var(--ash); margin-top: 2px;
}
.actor-card__note, .actor-card__status { margin-top: 8px; font-size: 12px; color: var(--ash); }
.actor-card__warn { margin-top: 8px; font-size: 12px; color: var(--rust); }
.actor-card__actions { display: flex; gap: 8px; margin-top: 10px; }
.actor-card__msg-btn {
  font-size: 12px; color: var(--bone); cursor: pointer;
  background: linear-gradient(180deg, var(--copper-bright), var(--copper));
  border: none; border-radius: 999px; padding: 4px 14px;
  box-shadow: var(--edge-highlight);
}
.actor-card__msg-btn:hover { filter: brightness(1.08); }
.actor-card__msg-btn:disabled { opacity: 0.5; cursor: default; }
.actor-card__invite-btn, .actor-card__invite-send {
  font-size: 12px; color: var(--ash); cursor: pointer;
  background: none; border: 1px solid var(--line);
  border-radius: 999px; padding: 4px 12px;
}
.actor-card__invite-btn:hover, .actor-card__invite-send:hover {
  color: var(--copper); border-color: var(--copper);
}
.actor-card__invite-row { display: flex; gap: 8px; margin-top: 8px; }
.actor-card__invite-select {
  flex: 1; font-size: 12px; color: var(--bone);
  background: var(--ink-2); border: 1px solid var(--line);
  border-radius: var(--r-ctl); padding: 4px 8px;
}
```

(Verify token names against the existing stylesheet while editing; `--ink-2`, `--copper-bright`, `--r-ctl`, `--r-card`, `--focus-ring`, `--signal-ok`, `--rust` all exist in the current token set. Use only tokens already defined.)

- [ ] **Step 5: Run tests, commit**

Run: `npx tsc --noEmit && npm run test:run` (from `apps/fetchit-desktop/`)
Expected: PASS

```bash
git add apps/fetchit-desktop/src/fediverse
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(desktop): actor lookup card with private-affordance gating'
```

---

### Task 12: Pane wiring + ChatPanelApi.openDm

**Files:**
- Modify: `apps/fetchit-desktop/src/fediverse/panel.ts`, `apps/fetchit-desktop/src/fediverse/panel.test.ts`
- Modify: `apps/fetchit-desktop/src/chat/panel.ts`, `apps/fetchit-desktop/src/chat/panel.test.ts`
- Modify: `apps/fetchit-desktop/src/controller.ts`

- [ ] **Step 1: Write the failing tests**

panel.test.ts (fediverse): add a test that the mounted pane contains `.fediverse-lookup` and that its `onOpenDm` is threaded (mirror the existing mount-test setup in that file):

```typescript
it("mounts the lookup section between header and feed", () => {
  // existing mount harness, then:
  expect(host.querySelector(".fediverse-lookup")).not.toBeNull();
});
```

chat/panel.test.ts: add a test for `openDm` if the existing harness mounts the panel; assert the active conversation becomes the DM (whatever observable the harness exposes, e.g. the conversation header or store-driven DOM). If the harness cannot reach that state cheaply, assert at minimum that `openDm` exists and resolves:

```typescript
it("openDm opens the panel on the given conversation", async () => {
  // existing mount harness
  await api.openDm("a".repeat(64));
  expect(api.isOpen()).toBe(true);
});
```

Run: `npm run test:run -- panel`
Expected: FAIL

- [ ] **Step 2: Implement**

fediverse/panel.ts:

```typescript
import { mountLookup } from "./lookup";

export interface FediversePanelHandlers {
  onClose: () => void;
  /// Open the LIT Chat DM for an imported contact (lookup card action).
  onOpenDm: (agentIdHex: string) => void;
}
```

In `mountFediversePanel`, between header and body:

```typescript
const lookupHost = document.createElement("div");
mountLookup(lookupHost, { onOpenDm: handlers.onOpenDm });
// ...
host.append(header, lookupHost, body, composeHost);
```

chat/panel.ts: extend `ChatPanelApi`:

```typescript
export interface ChatPanelApi {
  open(): Promise<void>;
  close(): void;
  toggle(): Promise<void>;
  isOpen(): boolean;
  setDocked(docked: boolean): void;
  isDocked(): boolean;
  /// Open the panel focused on the DM with `agentIdHex` (the contact
  /// must already exist; lookup imports before calling this).
  openDm(agentIdHex: string): Promise<void>;
}
```

Implementation inside `mountChatPanel`, next to the returned handle (reusing exactly what `handleImported` does):

```typescript
const openDm = async (agentIdHex: string): Promise<void> => {
  await open();
  store.setActive({ kind: "dm", peer: agentIdHex });
  void refreshContacts();
};
```

and add `openDm` to the returned object.

controller.ts (lines 169-180): wire the new handler:

```typescript
const fediverse = mountFediversePanel(fediverseHost, {
  onClose: () => {
    /* nothing to reconcile on close */
  },
  onOpenDm: (agentIdHex) => {
    fediverse.close();
    void chat?.openDm(agentIdHex);
  },
});
```

- [ ] **Step 3: Run tests, commit**

Run: `npx tsc --noEmit && npm run test:run`
Expected: PASS (all suites)

```bash
git add apps/fetchit-desktop/src
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(desktop): lookup pane wiring and chat openDm'
```

---

### Task 13: Add-contact accepts handles

**Files:**
- Modify: `apps/fetchit-desktop/src/chat/addContact.ts`, `apps/fetchit-desktop/src/chat/addContact.test.ts`

- [ ] **Step 1: Write the failing tests**

In addContact.test.ts, following its existing mock pattern:

```typescript
it("imports a verified handle via lookup then pair-accept", async () => {
  mock.mockImplementation((cmd: string) => {
    if (cmd === "fediverse_lookup")
      return Promise.resolve({
        kind: "verified",
        handle: "@josh@etchit.io",
        actorUrl: "https://etchit.io/actors/josh",
        agentIdHex: "a".repeat(64),
        shareUri: "fetchit://share/v3/x",
      });
    if (cmd === "chat_pair_accept")
      return Promise.resolve({ agentIdHex: "a".repeat(64), offererRelayUrl: "", crossRelay: false });
    return Promise.resolve(null);
  });
  // mount, type "@josh@etchit.io", click Add (existing harness helpers)
  // assert: fediverse_lookup invoked with { handle: "@josh@etchit.io" },
  // chat_pair_accept invoked with { uri: "fetchit://share/v3/x" },
  // onImported fired with the agent id.
});

it("rejects a public-only handle with honest copy", async () => {
  mock.mockImplementation((cmd: string) =>
    cmd === "fediverse_lookup"
      ? Promise.resolve({ kind: "publicOnly", handle: "@g@m.social", actorUrl: "https://m.social/u/g", verifyFailure: null })
      : Promise.resolve(null),
  );
  // type "@g@m.social", click Add
  // assert status text contains "isn't linked to a fetch>it identity"
  // and the button re-enables.
});
```

Run: `npm run test:run -- addContact`
Expected: FAIL

- [ ] **Step 2: Implement**

In addContact.ts:

```typescript
import { lookupHandle } from "../fediverse/api";

type InputKind = UriKind | "handle";
const HANDLE_INPUT_RE = /^@[^@\s]+@[^@\s]+\.[^@\s]+$/;

function detectInputKind(value: string): InputKind | null {
  const t = value.trim();
  if (t.startsWith(POINTER_PREFIX)) return "pointer";
  if (t.startsWith(V2_PREFIX)) return "v2";
  if (t.startsWith(V3_PREFIX)) return "v3";
  if (HANDLE_INPUT_RE.test(t)) return "handle";
  return null;
}
```

Rename uses of `detectUriKind` accordingly, extend `inFlightStatus` with a `"handle"` arm (`"Looking up handle…"`), update the help/placeholder copy to mention handles (`"Paste a share URI or type @handle@domain"`), and add the branch in the click handler:

```typescript
if (kind === "handle") {
  const dto = await lookupHandle(uri);
  if (dto.kind !== "verified" || !dto.shareUri) {
    status.textContent = dto.verifyFailure
      ? `Couldn't verify that handle: ${dto.verifyFailure}`
      : "That account isn't linked to a fetch>it identity, so it can't be added as a private contact.";
    addBtn.disabled = false;
    return;
  }
  const result = await pairAccept(dto.shareUri);
  status.textContent = "Imported.";
  handlers.onImported(result);
}
```

Keep the surrounding try/catch shape so transport errors land in the existing `importErrorCopy` path (add a `"handle"` arm there too: `` `Failed: ${friendlyError(e)}` `` is fine).

- [ ] **Step 3: Run tests, commit**

Run: `npx tsc --noEmit && npm run test:run`
Expected: PASS

```bash
git add apps/fetchit-desktop/src/chat
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(desktop): add-contact accepts fediverse handles'
```

---

### Task 14: Mint consent copy + outcome states

**Files:**
- Modify: `apps/fetchit-desktop/src/fediverse/compose.ts`, `apps/fetchit-desktop/src/fediverse/compose.test.ts`

- [ ] **Step 1: Write the failing tests**

```typescript
it("mint help carries the one-opt-in consent copy", async () => {
  statusResolves(null);
  // mount, wait for mint UI
  const help = host.querySelector(".fediverse-compose__mint-help")!;
  expect(help.textContent).toContain("publicly findable and contactable");
});

it("mint renders registration-pending honestly", async () => {
  mock.mockImplementation((cmd: string) => {
    if (cmd === "fediverse_actor_status") return Promise.resolve(null);
    if (cmd === "fediverse_mint")
      return Promise.resolve({
        actorUrl: "https://etchit.io/actors/josh",
        registered: false,
        registrationError: "connection refused",
      });
    return Promise.resolve(null);
  });
  // mount, type "josh", click mint, waitFor composer
  // assert a status line contains "Directory registration pending"
});

it("calls fediverse_ensure_v2 when a handle already exists", async () => {
  statusResolves("josh");
  // mount, await ready
  await vi.waitFor(() => {
    expect(mock.mock.calls.some((c) => c[0] === "fediverse_ensure_v2")).toBe(true);
  });
});
```

Run: `npm run test:run -- compose`
Expected: FAIL

- [ ] **Step 2: Implement**

In compose.ts `renderMint`, replace the help copy (the one-opt-in language from the spec):

```typescript
help.textContent =
  "Public posting is opt-in and separate from your chat identity. "
  + "Creating a handle makes you publicly findable and contactable: anyone "
  + "who knows it can look you up and send a contact request (requests wait "
  + "in your pending queue until you accept). Letters, digits, - and _ only.";
```

Update the mint click handler to the new DTO:

```typescript
void invoke<{ actorUrl: string; registered: boolean; registrationError: string | null }>(
  "fediverse_mint",
  { handle },
)
  .then((outcome) => {
    host.replaceChildren();
    renderComposer();
    if (!outcome.registered) {
      const note = document.createElement("div");
      note.className = "fediverse-compose__mint-pending";
      note.textContent = `Handle created. Directory registration pending: ${outcome.registrationError ?? "registry unreachable"}. It will retry next time you open this pane.`;
      host.prepend(note);
    }
  })
  .catch((e: unknown) => {
    error.textContent = `Could not create handle: ${String(e)}`;
    mintBtn.disabled = false;
  });
```

In the `ready` chain, fire the upgrade pass when a handle exists:

```typescript
const ready = invoke<string | null>("fediverse_actor_status")
  .then((handle) => {
    if (handle) {
      renderComposer();
      void invoke("fediverse_ensure_v2").catch(() => {
        /* best-effort; pane stays usable */
      });
    } else {
      renderMint();
    }
  })
  .catch(() => {
    renderMint();
  });
```

Add the style: `.fediverse-compose__mint-pending { font-size: 12px; color: var(--ash); margin-bottom: 8px; }`.

- [ ] **Step 3: Run tests, commit**

Run: `npx tsc --noEmit && npm run test:run`
Expected: PASS

```bash
git add apps/fetchit-desktop/src/fediverse
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m 'feat(desktop): mint consent copy and registration outcome states'
```

---

### Task 15: Full-stack gates

**Files:** none new; fix-ups only if a gate fails.

- [ ] **Step 1: Rust gates (repo root)**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p fetchit-fedi -p fetchit-chat
```

Expected: clean, all green. (Full `cargo test --workspace` runs on Box B at cross-review per the build-load split.)

- [ ] **Step 2: Desktop gates**

```bash
cd apps/fetchit-desktop
npx tsc --noEmit
npm run test:run
npm run build
(cd src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)
```

Expected: clean, all green, vite build succeeds.

- [ ] **Step 3: Spec-coverage sweep**

Re-read the spec's Component D and Component A sections and the gate text. Confirm each maps to a landed commit: attestation v2 fields + version + re-mint (Tasks 1-3, 6, 7, 9), registry contract (Task 5 fixtures; endpoints are lane B), one search box + two outcomes + fail-closed (Tasks 10, 11), existing-flow reuse for DM and invite (Tasks 11, 12), add-contact handles (Task 13), consent copy (Task 14), handle-changed-hands (Tasks 8, 10, 11). Out of M5.1 scope by design: follow (M5.2), search endpoint + UI (M5.3), SECURITY.md inventory (joint task at M5 close).

- [ ] **Step 4: Commit any fix-ups, push, notify lane B**

Push to the private remote (`josh-clsn`), then queue the pair message: registry contract fixtures are at `crates/fetchit-fedi/tests/fixtures/registry-v1/` for review before the bridge endpoints are built; flag any shape objections before implementing.
