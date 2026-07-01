# fetch>it Desktop Profile Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render a contact's Autonomi-published v3 `ProfileManifest` read-only in a modal opened from the conversation header, with two thin Tauri commands resolving + verifying the profile and lazily fetching the avatar.

**Architecture:** The security-critical logic (parse, verify, agent-id cross-check, downgrade-defense watermark, avatar sniff) lives in **pure functions** in a new `src-tauri/src/profile.rs`, fixture-tested with no network. Two thin Tauri commands do the I/O (relay index fetch + Autonomi byte fetch) and call the pure cores. The frontend `profileCard.ts` is a modal mirroring the existing `confirmDialog.ts` singleton-host pattern. One new engine helper, `pair::fetch_index_record_by_id`, resolves the relay index without a full share URI.

**Tech Stack:** Rust (Tauri 2, reqwest, serde, the `infer` crate for magic-byte sniff), vanilla TS/Vite + vitest, the existing `fetchit_chat::{profile,pair,local_store}` + `fetchit_relay_proto::derive_agent_id`.

**Branch:** `chat` @ 5269ee5. **DCO:** every commit signed `git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s`. No em-dashes in committed text. Minimal comments. Honest exit codes (redirect to file + capture `$?`, never `| tail`).

---

## File Structure

| File | Create/Modify | Responsibility |
| --- | --- | --- |
| `crates/fetchit-chat/src/pair.rs` | Modify | Add `fetch_index_record_by_id(relay, agent_id, http)` (relay index resolve without a share URI). |
| `apps/fetchit-desktop/src-tauri/src/profile.rs` | Create | DTOs (`ProfileOutcome`/`ProfileDto`/`AvatarDto`), pure `build_profile_outcome`, watermark store, `validate_avatar_to_data_url`, and the two thin Tauri commands. |
| `apps/fetchit-desktop/src-tauri/src/lib.rs` | Modify | `mod profile;` + register the two commands in `generate_handler!`. |
| `apps/fetchit-desktop/src/chat/types.ts` | Modify | TS mirror of `ProfileOutcome`/`ProfileDto`/`AvatarDto`. |
| `apps/fetchit-desktop/src/chat/api.ts` | Modify | `fetchProfile(agentId)` + `fetchAvatar(addr,mime,bytesLen)` invoke wrappers. |
| `apps/fetchit-desktop/src/chat/profileCard.ts` + `.test.ts` | Create | The modal: 4 states, link routing, website confirm, lazy avatar. |
| `apps/fetchit-desktop/src/chat/conversation.ts` | Modify | Header subject becomes a profile button for DMs; new `onViewProfile` handler. |
| `apps/fetchit-desktop/src/chat/controller.ts` | Modify | Wire `onViewProfile` to fetch + mount the modal. |
| `apps/fetchit-desktop/src/chat/styles.css` | Modify | `.chat-profile` block, tokens only. |

**Verified existing APIs (do not redefine):**
- `fetchit_chat::profile::{ProfileManifest, ProfileLink, ProfileAvatar, ProfileError}`. `ProfileManifest::parse(json: &str) -> Result<Self, ProfileError>`; `ProfileManifest::verify(&self, min_issued_at_ms: Option<u64>) -> Result<Vec<u8>, ProfileError>`. Fields: `version,agent_id,display_name,bio:Option<String>,website:Option<String>,links:Vec<ProfileLink>,avatar:Option<ProfileAvatar>,ml_dsa_pubkey,kem_pubkey,issued_at_ms,expires_at_ms:Option<u64>,sig`. `ProfileLink{kind:String,label:String,addr:String}`. `ProfileAvatar{addr:String,mime:String,w:u16,h:u16,bytes_len:u32}`. `ProfileError` has `Stale{issued,minimum}` + `AgentIdMismatch{..}` + `SigVerifyFailed`.
- `fetchit_chat::pair::{ProfileIndexRecord, PairError, verify_index_record}`. `ProfileIndexRecord{agent_id,profile_addr,kem_pubkey,ml_dsa_pubkey,issued_at_ms,sig}`. `verify_index_record(&ProfileIndexRecord) -> Result<Vec<u8>, PairError>`. `PairError::{RelayStatus(u16),Decode(String),AgentIdMismatch,DerivationMismatch,Tombstoned,SigVerifyFailed,Http,...}`. Tombstone sentinel const `ALL_ZEROS_PROFILE_ADDR` (private; replicate the 64-zero literal).
- `fetchit_chat::local_store::{StoreLayout, write_json_atomic}`. `StoreLayout{root:PathBuf,...}`. `write_json_atomic<T:Serialize>(path:&Path, value:&T) -> Result<(), ChatError>`.
- `fetchit_relay_proto::derive_agent_id(public_key:&[u8]) -> [u8;32]`.
- src-tauri: `ChatState::relay_url(&self) -> url::Url` (chat.rs:215). `chat_pair_share` (chat.rs:513) is the relay-GET pattern. AppState reader fetch path in `lib.rs` (`fetch_and_render`) parses a 64-hex into an Autonomi `Address` then `client.fetch(&addr).await`. `infer::get(bytes)` magic-byte sniffer is already a dependency.
- frontend: `chatConfirm(opts:{title,message,confirmLabel?,cancelLabel?}) -> Promise<boolean>` (confirmDialog.ts). `ConversationHandlers` (conversation.ts:16) already has `onProfile(uri)` for v3-URI routing — DO NOT reuse it; add a NEW `onViewProfile(agentId:string)`. `subjectEl` (conversation.ts:56, set at :237) is the header title. `renderImage` (renderers/image.ts) or a plain `<img src=dataUrl>`. invoke pattern: `invoke<T>("cmd", { key: val })`.

---

## Task 1: `pair::fetch_index_record_by_id` (engine)

**Files:**
- Modify: `crates/fetchit-chat/src/pair.rs`
- Test: same file's `#[cfg(test)] mod tests` (wiremock pattern already used there).

- [ ] **Step 1: Write the failing test.** Add to the test module (mirror the existing `mk_signed_record` + wiremock helpers already in the file):

```rust
#[tokio::test]
async fn fetch_by_id_returns_verified_record() {
    let (dsa, sk, pk) = test_keypair();
    let agent_hex = agent_id_hex(&pk.to_bytes());
    let record = mk_signed_record(&dsa, &sk, &pk.to_bytes(), &"ab".repeat(32), 1);
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!("/v1/profile/{agent_hex}")))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&record))
        .mount(&server)
        .await;
    let relay = url::Url::parse(&server.uri()).unwrap();
    let got = fetch_index_record_by_id(&relay, &agent_hex, &reqwest::Client::new())
        .await
        .unwrap();
    assert_eq!(got.agent_id, agent_hex);
}

#[tokio::test]
async fn fetch_by_id_tombstone_maps_to_tombstoned() {
    let (dsa, sk, pk) = test_keypair();
    let agent_hex = agent_id_hex(&pk.to_bytes());
    let record = mk_signed_record(&dsa, &sk, &pk.to_bytes(), ALL_ZEROS_PROFILE_ADDR, 1);
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!("/v1/profile/{agent_hex}")))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&record))
        .mount(&server)
        .await;
    let relay = url::Url::parse(&server.uri()).unwrap();
    let err = fetch_index_record_by_id(&relay, &agent_hex, &reqwest::Client::new())
        .await
        .unwrap_err();
    assert!(matches!(err, PairError::Tombstoned));
}
```

> If the existing test module's helper names differ (`test_keypair`/`agent_id_hex`/`mk_signed_record`), reuse whatever it already defines for the tombstone test at pair.rs:404 — that test already builds a signed all-zeros record. Match its helpers exactly.

- [ ] **Step 2: Run to verify it fails.** Run: `cargo test -p fetchit-chat fetch_by_id 2>/tmp/t.log; echo "EXIT=$?"` Expected: FAIL, "cannot find function `fetch_index_record_by_id`".

- [ ] **Step 3: Implement.** Add the public function (place above `fetch_index_record`). Then refactor `fetch_index_record` to delegate (read its current body first; it builds `{relay}/v1/profile/{agent_id}`, GETs, maps non-2xx to `RelayStatus`, JSON-decodes to `Decode`, calls `verify_index_record`, cross-checks the URI agent_id, and checks the tombstone). The extracted core:

```rust
/// Resolve a contact's relay index record by relay base URL + agent id
/// (no share URI needed). GETs `{relay}/v1/profile/{agent_id}`, verifies
/// the record's ML-DSA signature and self-derivation, cross-checks the
/// returned `agent_id` against the request, and maps the all-zeros
/// address to [`PairError::Tombstoned`].
///
/// # Errors
/// Transport, non-2xx relay status, malformed body, agent-id mismatch,
/// failed verification, or a tombstoned profile.
pub async fn fetch_index_record_by_id(
    relay: &url::Url,
    agent_id: &str,
    http: &reqwest::Client,
) -> std::result::Result<ProfileIndexRecord, PairError> {
    let url = relay
        .join(&format!("v1/profile/{agent_id}"))
        .map_err(|e| PairError::Decode(format!("build relay url: {e}")))?;
    let resp = http.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(PairError::RelayStatus(resp.status().as_u16()));
    }
    let record: ProfileIndexRecord = resp
        .json()
        .await
        .map_err(|e| PairError::Decode(format!("index record json: {e}")))?;
    if record.profile_addr == ALL_ZEROS_PROFILE_ADDR {
        return Err(PairError::Tombstoned);
    }
    // Verifies the record signs itself AND that its pubkey derives its
    // own agent_id (DerivationMismatch otherwise).
    verify_index_record(&record)?;
    if record.agent_id != agent_id {
        return Err(PairError::AgentIdMismatch);
    }
    Ok(record)
}
```

Then make the existing fn delegate:

```rust
pub async fn fetch_index_record(
    uri: &V3ShareUri,
    http: &reqwest::Client,
) -> std::result::Result<ProfileIndexRecord, PairError> {
    fetch_index_record_by_id(&uri.relay, &uri.agent_id, http).await
}
```

> If `fetch_index_record` currently checks the tombstone AFTER verify, keep the by_id ordering above (tombstone first is cheaper and matches the existing `verify_index_record` doc which says it does not check tombstone). Verify the existing `fetch_index_record` tests still pass after delegating.

- [ ] **Step 4: Run to verify pass.** Run: `cargo test -p fetchit-chat pair:: 2>/tmp/t.log; echo "EXIT=$?"; grep "test result" /tmp/t.log` Expected: all pair tests pass.

- [ ] **Step 5: Workspace gate + commit.**

```bash
cargo fmt --all --check >/tmp/f.log 2>&1; echo "FMT=$?"
cargo clippy -p fetchit-chat --all-targets -- -D warnings >/tmp/c.log 2>&1; echo "CLIPPY=$?"
git add crates/fetchit-chat/src/pair.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(chat): pair::fetch_index_record_by_id (resolve relay index without a share URI)"
```

---

## Task 2: backend DTOs + `ProfileFetchError` (src-tauri/profile.rs skeleton)

**Files:**
- Create: `apps/fetchit-desktop/src-tauri/src/profile.rs`
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (add `mod profile;` near the other `mod` lines)

- [ ] **Step 1: Create the file with DTOs (no test — pure types).**

```rust
//! Read-only profile-card commands (desktop). Resolves a contact's v3
//! profile manifest off Autonomi, verifies it, and returns a typed DTO.
//! The security-critical logic lives in pure functions tested against
//! the `fetchit-chat` fixtures; the Tauri commands are thin I/O.

use fetchit_chat::pair::{fetch_index_record_by_id, PairError, ProfileIndexRecord};
use fetchit_chat::profile::{ProfileError, ProfileManifest};
use serde::{Deserialize, Serialize};

/// Outcome of a profile fetch. `none` is the honest non-error state for
/// a contact who has not published (tombstone or relay 404).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ProfileOutcome {
    Profile(ProfileDto),
    None,
}

/// The render-ready profile. Camel-cased for the TS frontend. The avatar
/// carries only metadata; bytes are fetched lazily by `chat_fetch_avatar`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDto {
    pub display_name: String,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub links: Vec<LinkDto>,
    pub avatar: Option<AvatarDto>,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkDto {
    pub kind: String,
    pub label: String,
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarDto {
    pub addr: String,
    pub mime: String,
    pub w: u16,
    pub h: u16,
    pub bytes_len: u32,
}
```

- [ ] **Step 2: Register the module.** In `lib.rs`, add `mod profile;` alongside `mod chat;` / `mod fediverse;`.

- [ ] **Step 3: Compile.** Run (from src-tauri dir): `cargo build 2>/tmp/b.log; echo "EXIT=$?"` Expected: builds (unused-warning-only is fine at this stage; the next task consumes the types).

- [ ] **Step 4: Commit.**

```bash
git add apps/fetchit-desktop/src-tauri/src/profile.rs apps/fetchit-desktop/src-tauri/src/lib.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): profile-card DTO skeleton (ProfileOutcome/ProfileDto)"
```

---

## Task 3: pure `build_profile_outcome` (the verify + cross-check core)

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/profile.rs`
- Test: same file (`#[cfg(test)] mod tests` reading the fetchit-chat fixtures).

**Fixtures (relative to src-tauri):** `../../../crates/fetchit-chat/tests/fixtures/profile-manifest-v1/{maximal,minimal,tampered-maximal}/manifest.json`. `maximal` has avatar + 5 links + bio + website; `tampered-maximal` has a flipped display_name byte with the original signature (verify must fail).

- [ ] **Step 1: Write the failing tests.**

```rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const FIXTURES: &str = "../../../crates/fetchit-chat/tests/fixtures/profile-manifest-v1";

    fn manifest_bytes(dir: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{dir}/manifest.json")).unwrap()
    }
    fn manifest_agent_id(dir: &str) -> String {
        let m = ProfileManifest::parse(&String::from_utf8(manifest_bytes(dir)).unwrap()).unwrap();
        m.agent_id
    }

    #[test]
    fn maximal_builds_dto() {
        let aid = manifest_agent_id("maximal");
        let out = build_profile_outcome(&aid, &aid, &manifest_bytes("maximal"), None).unwrap();
        let ProfileOutcome::Profile(dto) = out else { panic!("expected profile") };
        assert!(!dto.display_name.is_empty());
        assert!(dto.avatar.is_some());
        assert!(!dto.links.is_empty());
    }

    #[test]
    fn tampered_manifest_rejected() {
        let aid = manifest_agent_id("maximal"); // tampered shares the same agent_id
        let err = build_profile_outcome(&aid, &aid, &manifest_bytes("tampered-maximal"), None);
        assert!(err.is_err());
    }

    #[test]
    fn manifest_for_other_identity_rejected() {
        let aid = manifest_agent_id("maximal");
        let wrong = "ff".repeat(32);
        // requested == index == wrong, but the manifest's own agent_id differs.
        let err = build_profile_outcome(&wrong, &wrong, &manifest_bytes("maximal"), None);
        assert!(err.is_err());
    }

    #[test]
    fn stale_manifest_below_watermark_rejected() {
        let aid = manifest_agent_id("maximal");
        let future = u64::MAX;
        let err = build_profile_outcome(&aid, &aid, &manifest_bytes("maximal"), Some(future));
        assert!(err.is_err());
    }

    #[test]
    fn minimal_builds_dto_without_avatar() {
        let aid = manifest_agent_id("minimal");
        let out = build_profile_outcome(&aid, &aid, &manifest_bytes("minimal"), None).unwrap();
        let ProfileOutcome::Profile(dto) = out else { panic!() };
        assert!(dto.avatar.is_none());
    }
}
```

- [ ] **Step 2: Run to verify fail.** Run (src-tauri dir): `cargo test build_profile 2>/tmp/t.log; echo "EXIT=$?"` Expected: FAIL, "cannot find function `build_profile_outcome`".

- [ ] **Step 3: Implement the pure core.**

```rust
/// Verify a fetched manifest and bind it to the expected identity.
///
/// `requested` is the agent id the user asked for; `index_agent_id` is
/// the agent id the relay index returned (already cross-checked == the
/// request by `fetch_index_record_by_id`). `watermark` is the last-seen
/// `issued_at_ms` for downgrade defense. On success returns the
/// render-ready DTO; on any verification failure returns a short,
/// honest, user-facing message.
pub fn build_profile_outcome(
    requested: &str,
    index_agent_id: &str,
    manifest_bytes: &[u8],
    watermark: Option<u64>,
) -> Result<ProfileOutcome, String> {
    let json = std::str::from_utf8(manifest_bytes)
        .map_err(|_| "profile manifest is not valid UTF-8".to_string())?;
    let manifest = ProfileManifest::parse(json).map_err(map_profile_err)?;
    // Re-derives agent_id from the embedded pubkey + ML-DSA-checks the
    // signature; rejects a stale manifest below the watermark.
    manifest.verify(watermark).map_err(map_profile_err)?;
    // Bind the separately-signed manifest to the same identity end to end:
    // requested == index.agent_id == manifest.agent_id (== derive(pubkey),
    // already enforced inside verify()).
    if manifest.agent_id != requested || index_agent_id != requested {
        return Err("this profile belongs to a different identity".to_string());
    }
    Ok(ProfileOutcome::Profile(ProfileDto {
        display_name: manifest.display_name,
        bio: manifest.bio,
        website: manifest.website,
        links: manifest
            .links
            .into_iter()
            .map(|l| LinkDto { kind: l.kind, label: l.label, addr: l.addr })
            .collect(),
        avatar: manifest.avatar.map(|a| AvatarDto {
            addr: a.addr,
            mime: a.mime,
            w: a.w,
            h: a.h,
            bytes_len: a.bytes_len,
        }),
        issued_at_ms: manifest.issued_at_ms,
    }))
}

fn map_profile_err(e: ProfileError) -> String {
    match e {
        ProfileError::Stale { .. } => "a stale copy of this profile was rejected".to_string(),
        ProfileError::SigVerifyFailed | ProfileError::AgentIdMismatch { .. } => {
            "this profile failed verification".to_string()
        }
        other => format!("this profile could not be read ({other})"),
    }
}
```

- [ ] **Step 4: Run to verify pass.** Run (src-tauri dir): `cargo test build_profile 2>/tmp/t.log; echo "EXIT=$?"; grep "test result" /tmp/t.log` Expected: 5 pass.

- [ ] **Step 5: Commit.**

```bash
git add apps/fetchit-desktop/src-tauri/src/profile.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): build_profile_outcome verify + agent-id cross-check core"
```

---

## Task 4: freshness watermark store

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/profile.rs`
- Test: same file's test module (tempdir).

- [ ] **Step 1: Write the failing test.**

```rust
#[test]
fn watermark_roundtrip_and_monotonic() {
    let tmp = std::path::PathBuf::from(std::env::temp_dir()).join(format!("pw-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let aid = "aa".repeat(32);
    assert_eq!(load_watermark(&tmp, &aid), None);
    save_watermark(&tmp, &aid, 100).unwrap();
    assert_eq!(load_watermark(&tmp, &aid), Some(100));
    // Monotonic: an older value never lowers the stored mark.
    save_watermark(&tmp, &aid, 50).unwrap();
    assert_eq!(load_watermark(&tmp, &aid), Some(100));
    std::fs::remove_dir_all(&tmp).ok();
}
```

- [ ] **Step 2: Run to verify fail.** Run (src-tauri dir): `cargo test watermark 2>/tmp/t.log; echo "EXIT=$?"` Expected: FAIL (functions missing).

- [ ] **Step 3: Implement.**

```rust
use std::collections::BTreeMap;
use std::path::Path;

const WATERMARK_FILE: &str = "profile_fetch_watermark.json";

fn watermark_path(chat_root: &Path) -> std::path::PathBuf {
    chat_root.join(WATERMARK_FILE)
}

/// Last-seen `issued_at_ms` for a contact, or None on first view. Plain
/// JSON map at rest (non-secret monotonic timestamps).
pub fn load_watermark(chat_root: &Path, agent_id: &str) -> Option<u64> {
    let raw = std::fs::read(watermark_path(chat_root)).ok()?;
    let map: BTreeMap<String, u64> = serde_json::from_slice(&raw).ok()?;
    map.get(agent_id).copied()
}

/// Persist `issued_at_ms` as the watermark for `agent_id` when it is
/// newer than the stored value (monotonic). Best-effort: a write error
/// is non-fatal (the downgrade check still ran against the loaded value).
pub fn save_watermark(chat_root: &Path, agent_id: &str, issued_at_ms: u64) -> std::io::Result<()> {
    let path = watermark_path(chat_root);
    let mut map: BTreeMap<String, u64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = map.entry(agent_id.to_string()).or_insert(0);
    if issued_at_ms > *entry {
        *entry = issued_at_ms;
    }
    let bytes = serde_json::to_vec(&map).unwrap_or_default();
    std::fs::write(&path, bytes)
}
```

- [ ] **Step 4: Run to verify pass.** Run (src-tauri dir): `cargo test watermark 2>/tmp/t.log; echo "EXIT=$?"; grep "test result" /tmp/t.log` Expected: pass.

- [ ] **Step 5: Commit.**

```bash
git add apps/fetchit-desktop/src-tauri/src/profile.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): per-contact issued_at_ms watermark store (downgrade defense)"
```

---

## Task 5: avatar validation -> data URL

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/profile.rs`
- Test: same file's test module.

- [ ] **Step 1: Write the failing test.**

```rust
#[test]
fn avatar_valid_webp_returns_data_url() {
    // "RIFF????WEBP" minimal header.
    let mut bytes = vec![0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50];
    bytes.extend_from_slice(&[0u8; 20]);
    let len = bytes.len() as u32;
    let url = validate_avatar_to_data_url(&bytes, "image/webp", len).unwrap();
    assert!(url.starts_with("data:image/webp;base64,"));
}

#[test]
fn avatar_oversize_rejected() {
    let bytes = vec![0u8; 600 * 1024];
    let err = validate_avatar_to_data_url(&bytes, "image/webp", bytes.len() as u32);
    assert!(err.is_err());
}

#[test]
fn avatar_non_raster_bytes_rejected() {
    let bytes = b"<svg xmlns='...'/>".to_vec();
    let err = validate_avatar_to_data_url(&bytes, "image/webp", bytes.len() as u32);
    assert!(err.is_err());
}

#[test]
fn avatar_over_declared_len_rejected() {
    let mut bytes = vec![0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50];
    bytes.extend_from_slice(&[0u8; 100]);
    let err = validate_avatar_to_data_url(&bytes, "image/webp", 10);
    assert!(err.is_err());
}
```

- [ ] **Step 2: Run to verify fail.** Run (src-tauri dir): `cargo test avatar 2>/tmp/t.log; echo "EXIT=$?"` Expected: FAIL (function missing).

- [ ] **Step 3: Implement** (uses the `infer` crate, already a dependency; if `infer` is not in src-tauri's Cargo.toml, sniff the WEBP/PNG/JPEG/GIF magic bytes directly):

```rust
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Hard ceiling on avatar bytes regardless of the manifest's declared
/// length. The manifest caps the avatar at 256x256 webp; 512 KiB is
/// comfortably above any honest encoding and well below a DoS.
const MAX_AVATAR_BYTES: usize = 512 * 1024;

const RASTER_MIMES: &[&str] = &["image/jpeg", "image/png", "image/webp", "image/gif"];

/// Validate fetched avatar bytes and return a `data:` URL. Rejects bytes
/// over the declared length or the hard cap, and rejects bytes whose
/// magic-byte type is not the declared raster image (never trust the
/// manifest's mime string alone).
pub fn validate_avatar_to_data_url(
    bytes: &[u8],
    declared_mime: &str,
    declared_bytes_len: u32,
) -> Result<String, String> {
    if bytes.len() > MAX_AVATAR_BYTES || bytes.len() as u64 > u64::from(declared_bytes_len) {
        return Err("avatar image is larger than declared".to_string());
    }
    if !RASTER_MIMES.contains(&declared_mime) {
        return Err("avatar mime is not an allowed raster image".to_string());
    }
    let sniffed = infer::get(bytes).map(|k| k.mime_type());
    if sniffed != Some(declared_mime) {
        return Err("avatar bytes do not match the declared image type".to_string());
    }
    Ok(format!("data:{declared_mime};base64,{}", B64.encode(bytes)))
}
```

> Confirm `base64` + `infer` are in `apps/fetchit-desktop/src-tauri/Cargo.toml`; the workspace already depends on both (chat.rs uses base64; the reader uses infer). Add them to `[dependencies]` if absent (match the workspace-pinned versions).

- [ ] **Step 4: Run to verify pass.** Run (src-tauri dir): `cargo test avatar 2>/tmp/t.log; echo "EXIT=$?"; grep "test result" /tmp/t.log` Expected: 4 pass.

- [ ] **Step 5: Commit.**

```bash
git add apps/fetchit-desktop/src-tauri/src/profile.rs apps/fetchit-desktop/src-tauri/Cargo.toml
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): avatar magic-byte validation + data URL (bounded, raster-only)"
```

---

## Task 6: the two Tauri commands + registration (I/O glue)

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/profile.rs` (append the `#[tauri::command]` fns)
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (register in `generate_handler!`)

No unit test (pure I/O; cores are tested). Verified by compile + clippy + the manual smoke in Task 11.

- [ ] **Step 1: Write the commands.** Read `chat_pair_share` (chat.rs:513) for the relay-GET pattern and `fetch_and_render` (lib.rs) for how a 64-hex string becomes an Autonomi `Address` + `client.fetch(&addr)`. Mirror them:

```rust
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[tauri::command]
pub async fn chat_fetch_profile(
    app_state: tauri::State<'_, crate::AppState>,
    state: tauri::State<'_, crate::chat::ChatState>,
    agent_id: String,
) -> Result<ProfileOutcome, String> {
    crate::chat::ensure_chat_enabled(&app_state)?;
    let relay = state.relay_url();
    let http = reqwest::Client::new();
    // Resolve the relay index; a tombstone / 404 is the "no profile" state.
    let record = match fetch_index_record_by_id(&relay, &agent_id, &http).await {
        Ok(r) => r,
        Err(PairError::Tombstoned) | Err(PairError::RelayStatus(404)) => {
            return Ok(ProfileOutcome::None)
        }
        Err(e) => return Err(format!("couldn't reach the profile index ({e})")),
    };
    // Fetch the manifest bytes off Autonomi (same path the reader uses),
    // capped: a manifest is small capped-field JSON.
    let bytes = crate::fetch_autonomi_bytes(&app_state, &record.profile_addr, MAX_MANIFEST_BYTES)
        .await
        .map_err(|e| format!("couldn't reach the network ({e})"))?;
    let chat_root = state.store_root();
    let watermark = load_watermark(&chat_root, &agent_id);
    let outcome = build_profile_outcome(&agent_id, &record.agent_id, &bytes, watermark)?;
    if let ProfileOutcome::Profile(ref dto) = outcome {
        let _ = save_watermark(&chat_root, &agent_id, dto.issued_at_ms);
    }
    Ok(outcome)
}

#[tauri::command]
pub async fn chat_fetch_avatar(
    app_state: tauri::State<'_, crate::AppState>,
    addr: String,
    mime: String,
    bytes_len: u32,
) -> Result<String, String> {
    let bytes = crate::fetch_autonomi_bytes(&app_state, &addr, MAX_AVATAR_BYTES)
        .await
        .map_err(|e| format!("couldn't load the avatar ({e})"))?;
    validate_avatar_to_data_url(&bytes, &mime, bytes_len)
}
```

> This references two glue helpers to add if absent:
> - `crate::fetch_autonomi_bytes(&app_state, addr_hex, cap) -> Result<Vec<u8>, String>` — factor the reader's existing fetch (parse 64-hex `Address`, `ensure_client`, `client.fetch`, error map, byte-cap check) into a small `pub(crate)` helper in `lib.rs` if one does not already exist. If the reader already exposes an equivalent, call it.
> - `state.store_root() -> PathBuf` — the chat data-dir root (the `StoreLayout.root`). If `ChatState` already exposes the layout/root, use it; otherwise add a thin accessor mirroring `relay_url()`.
> - `crate::chat::ensure_chat_enabled` is already `pub(crate)`; `ChatState` is the chat state type. Confirm exact paths against chat.rs.

- [ ] **Step 2: Register the commands.** In `lib.rs` `generate_handler!`, after `chat::chat_pair_share,` add:

```rust
    profile::chat_fetch_profile,
    profile::chat_fetch_avatar,
```

- [ ] **Step 3: Gate (src-tauri, from its own dir).**

```bash
cd apps/fetchit-desktop/src-tauri
cargo fmt --check >/tmp/f.log 2>&1; echo "FMT=$?"
cargo clippy --all-targets -- -D warnings >/tmp/c.log 2>&1; echo "CLIPPY=$?"
cargo test >/tmp/t.log 2>&1; echo "TEST=$?"; grep "test result" /tmp/t.log
```

Expected: FMT=0, CLIPPY=0, all tests pass.

- [ ] **Step 4: Commit.**

```bash
git add apps/fetchit-desktop/src-tauri/src/profile.rs apps/fetchit-desktop/src-tauri/src/lib.rs
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): chat_fetch_profile + chat_fetch_avatar commands"
```

---

## Task 7: frontend types + api wrappers

**Files:**
- Modify: `apps/fetchit-desktop/src/chat/types.ts`
- Modify: `apps/fetchit-desktop/src/chat/api.ts`

- [ ] **Step 1: Add the TS types** (mirror the camelCase DTOs) to `types.ts`:

```typescript
export interface ProfileAvatarMeta {
  addr: string;
  mime: string;
  w: number;
  h: number;
  bytesLen: number;
}

export interface ProfileLinkDto {
  kind: string;
  label: string;
  addr: string;
}

export interface ProfileDto {
  displayName: string;
  bio?: string | null;
  website?: string | null;
  links: ProfileLinkDto[];
  avatar?: ProfileAvatarMeta | null;
  issuedAtMs: number;
}

export type ProfileOutcome =
  | ({ kind: "profile" } & ProfileDto)
  | { kind: "none" };
```

- [ ] **Step 2: Add the invoke wrappers** to `api.ts` (import the new types):

```typescript
export async function fetchProfile(agentId: string): Promise<ProfileOutcome> {
  return invoke<ProfileOutcome>("chat_fetch_profile", { agentId });
}

export async function fetchAvatar(
  addr: string,
  mime: string,
  bytesLen: number,
): Promise<string> {
  return invoke<string>("chat_fetch_avatar", { addr, mime, bytesLen });
}
```

- [ ] **Step 3: Type-check.** Run: `cd apps/fetchit-desktop && npx tsc --noEmit >/tmp/ts.log 2>&1; echo "EXIT=$?"` Expected: 0.

- [ ] **Step 4: Commit.**

```bash
git add apps/fetchit-desktop/src/chat/types.ts apps/fetchit-desktop/src/chat/api.ts
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): ProfileOutcome TS types + fetchProfile/fetchAvatar wrappers"
```

---

## Task 8: `profileCard.ts` modal (the UI)

**Files:**
- Create: `apps/fetchit-desktop/src/chat/profileCard.ts`
- Create: `apps/fetchit-desktop/src/chat/profileCard.test.ts`

The modal mirrors `confirmDialog.ts`: a webkit2gtk-safe singleton host (built once, hidden; per-open only content + `hidden` change). It exposes a single `openProfileCard(opts)` entry that mounts in the "loading" state and is driven by callbacks the controller supplies (so the module does no I/O itself and is unit-testable).

- [ ] **Step 1: Write the failing test.**

```typescript
import { describe, it, expect, vi } from "vitest";
import { openProfileCard } from "./profileCard";
import type { ProfileOutcome } from "./types";

const PROFILE: ProfileOutcome = {
  kind: "profile",
  displayName: "Alice",
  bio: "hi there",
  website: "https://example.invalid/alice",
  links: [
    { kind: "etchit", label: "my page", addr: "ab".repeat(32) },
    { kind: "x0x", label: "dm me", addr: "cd".repeat(32) },
  ],
  avatar: null,
  issuedAtMs: 5,
};

function card(): HTMLElement | null {
  return document.querySelector(".chat-profile:not([hidden])");
}

describe("openProfileCard", () => {
  it("renders display name + bio + website + link chips from a loaded profile", async () => {
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve("data:image/webp;base64,AA=="),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.textContent).toContain("Alice"));
    expect(card()!.textContent).toContain("hi there");
    expect(card()!.querySelectorAll(".chat-profile__link").length).toBe(2);
  });

  it("shows the empty state when the contact has no profile", async () => {
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve({ kind: "none" }),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.textContent).toMatch(/hasn.t published/i));
  });

  it("shows an error line when the fetch rejects", async () => {
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.reject(new Error("this profile failed verification")),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
    });
    await vi.waitFor(() => expect(card()?.textContent).toContain("failed verification"));
  });

  it("routes an etchit link to onAutonomi and closes", async () => {
    const onAutonomi = vi.fn();
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi,
      onMessage: vi.fn(),
      confirmOpen: vi.fn(),
    });
    await vi.waitFor(() => expect(card()).not.toBeNull());
    card()!.querySelector<HTMLElement>(".chat-profile__link")!.click();
    expect(onAutonomi).toHaveBeenCalledWith(`autonomi://${"ab".repeat(32)}`);
    expect(card()).toBeNull();
  });

  it("fires confirmOpen before opening the website (speed bump)", async () => {
    const confirmOpen = vi.fn();
    openProfileCard({
      agentId: "aa".repeat(32),
      fetchProfile: () => Promise.resolve(PROFILE),
      fetchAvatar: () => Promise.resolve(""),
      onAutonomi: vi.fn(),
      onMessage: vi.fn(),
      confirmOpen,
    });
    await vi.waitFor(() => expect(card()).not.toBeNull());
    card()!.querySelector<HTMLElement>(".chat-profile__website")!.click();
    expect(confirmOpen).toHaveBeenCalledWith("https://example.invalid/alice");
  });
});
```

- [ ] **Step 2: Run to verify fail.** Run: `cd apps/fetchit-desktop && npm run test:run -- profileCard >/tmp/t.log 2>&1; echo "EXIT=$?"` Expected: FAIL (module missing).

- [ ] **Step 3: Implement** `profileCard.ts`. All display text via `textContent` (untrusted). Link routing: `etchit`/`fetchit`/`image` -> `onAutonomi("autonomi://" + addr)` then close; `x0x` -> `onMessage(addr)` then close; `website` (top field + any `website` link) -> `confirmOpen(url)` (the controller does the confirm + system-open). The avatar fetch is fired after the card paints (lazy) and fills a bounded box.

```typescript
import type { ProfileOutcome } from "./types";

export interface ProfileCardOpts {
  agentId: string;
  fetchProfile: (agentId: string) => Promise<ProfileOutcome>;
  fetchAvatar: (addr: string, mime: string, bytesLen: number) => Promise<string>;
  /// Open a 64-hex Autonomi address in the reader (caller closes chat).
  onAutonomi: (uri: string) => void;
  /// The contact themselves (x0x link) — caller is already in the DM.
  onMessage: (agentId: string) => void;
  /// External https website — caller shows a confirm then system-opens.
  confirmOpen: (url: string) => void;
}

interface Host {
  host: HTMLDivElement;
  body: HTMLDivElement;
}
let ref: Host | null = null;

function ensureHost(): Host {
  if (ref) return ref;
  const host = document.createElement("div");
  host.className = "chat-profile";
  host.hidden = true;
  const panel = document.createElement("div");
  panel.className = "chat-profile__panel";
  const close = document.createElement("button");
  close.type = "button";
  close.className = "chat-profile__close";
  close.setAttribute("aria-label", "Close");
  close.textContent = "×";
  close.addEventListener("click", () => closeCard());
  const body = document.createElement("div");
  body.className = "chat-profile__body";
  panel.append(close, body);
  host.appendChild(panel);
  document.body.appendChild(host);
  host.addEventListener("click", (e) => {
    if (e.target === host) closeCard();
  });
  ref = { host, body };
  return ref;
}

function closeCard(): void {
  if (!ref) return;
  ref.host.hidden = true;
  ref.body.replaceChildren();
}

function line(cls: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = cls;
  el.textContent = text;
  return el;
}

export function openProfileCard(opts: ProfileCardOpts): void {
  const { host, body } = ensureHost();
  body.replaceChildren(line("chat-profile__loading", "Loading profile…"));
  host.hidden = false;

  void opts
    .fetchProfile(opts.agentId)
    .then((outcome) => {
      if (outcome.kind === "none") {
        body.replaceChildren(
          line("chat-profile__empty", "This contact hasn't published a profile yet."),
        );
        return;
      }
      renderLoaded(body, outcome, opts);
    })
    .catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : "this profile could not be loaded";
      body.replaceChildren(line("chat-profile__error", msg));
    });
}

function renderLoaded(body: HTMLElement, p: Extract<ProfileOutcome, { kind: "profile" }>, opts: ProfileCardOpts): void {
  body.replaceChildren();

  const avatarBox = document.createElement("div");
  avatarBox.className = "chat-profile__avatar";
  body.appendChild(avatarBox);
  if (p.avatar) {
    const a = p.avatar;
    void opts
      .fetchAvatar(a.addr, a.mime, a.bytesLen)
      .then((dataUrl) => {
        const img = document.createElement("img");
        img.alt = "avatar";
        img.draggable = false;
        img.src = dataUrl;
        avatarBox.replaceChildren(img);
      })
      .catch(() => {
        /* leave the placeholder box */
      });
  }

  body.appendChild(line("chat-profile__name", p.displayName));
  if (p.bio) body.appendChild(line("chat-profile__bio", p.bio));

  if (p.website) {
    const w = document.createElement("button");
    w.type = "button";
    w.className = "chat-profile__website";
    w.textContent = p.website;
    const url = p.website;
    w.addEventListener("click", () => opts.confirmOpen(url));
    body.appendChild(w);
  }

  const links = document.createElement("div");
  links.className = "chat-profile__links";
  for (const l of p.links) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chat-profile__link";
    chip.dataset.kind = l.kind;
    chip.textContent = l.label || l.kind;
    chip.addEventListener("click", () => routeLink(l.kind, l.addr, opts));
    links.appendChild(chip);
  }
  if (p.links.length > 0) body.appendChild(links);
}

function routeLink(kind: string, addr: string, opts: ProfileCardOpts): void {
  if (kind === "etchit" || kind === "fetchit" || kind === "image") {
    closeCard();
    opts.onAutonomi(`autonomi://${addr}`);
  } else if (kind === "x0x") {
    closeCard();
    opts.onMessage(addr);
  } else if (kind === "website") {
    opts.confirmOpen(addr);
  }
}
```

- [ ] **Step 4: Run to verify pass.** Run: `cd apps/fetchit-desktop && npm run test:run -- profileCard >/tmp/t.log 2>&1; echo "EXIT=$?"; grep -E "Tests " /tmp/t.log` Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add apps/fetchit-desktop/src/chat/profileCard.ts apps/fetchit-desktop/src/chat/profileCard.test.ts
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): profile-card modal (states + link routing + lazy avatar)"
```

---

## Task 9: header trigger + controller wiring

**Files:**
- Modify: `apps/fetchit-desktop/src/chat/conversation.ts`
- Modify: `apps/fetchit-desktop/src/chat/controller.ts`

- [ ] **Step 1: Add the handler to `ConversationHandlers`** (conversation.ts:16, alongside `onProfile`):

```typescript
  /// Open the read-only profile card for a DM contact (agent id).
  onViewProfile: (agentId: string) => void;
```

- [ ] **Step 2: Make the DM header subject a profile button.** At conversation.ts ~237 where `subjectEl.textContent = conv.title;` runs, for the DM branch, make the subject clickable. Replace the bare text assignment in the DM path with a button that fires `handlers.onViewProfile(peer)`:

```typescript
    subjectEl.replaceChildren();
    if (conv.key.kind === "dm") {
      const peer = conv.key.peer;
      const nameBtn = document.createElement("button");
      nameBtn.type = "button";
      nameBtn.className = "chat-conv__subject-btn";
      nameBtn.textContent = conv.title;
      nameBtn.title = "View profile";
      nameBtn.addEventListener("click", () => handlers.onViewProfile(peer));
      subjectEl.appendChild(nameBtn);
      // ... existing presence/trust code unchanged ...
    } else {
      subjectEl.textContent = conv.title;
    }
```

> Read the current :237 block first; keep the existing presence/trust wiring intact and only swap how the title text is mounted. If `subjectEl` is a heading element, the button inherits its font via the `.chat-conv__subject-btn { all: unset }`-style CSS added in Task 10.

- [ ] **Step 3: Wire the controller.** In `controller.ts` `mountChatPanel({ ... })` handlers, add `onViewProfile`. It calls the api + opens the card, supplying the routing callbacks:

```typescript
  onViewProfile: (agentId: string) => {
    openProfileCard({
      agentId,
      fetchProfile,
      fetchAvatar,
      onAutonomi: (uri) => {
        const parsed = parseAutonomiUrl(uri);
        if (parsed) {
          chat?.close();
          submit(parsed.address, store, stageEl, parsed.query);
        }
      },
      onMessage: () => {
        // The user is already in / can open this DM; just close the card.
      },
      confirmOpen: (url) => {
        void chatConfirm({
          title: "Open external website",
          message: `This opens an external website in your browser:\n${url}`,
          confirmLabel: "Open",
        }).then((ok) => {
          if (ok) void openExternal(url);
        });
      },
    });
  },
```

> Imports for `controller.ts`: `import { openProfileCard } from "./chat/profileCard";`, `import { fetchProfile, fetchAvatar } from "./chat/api";`, `import { chatConfirm } from "./chat/confirmDialog";`, and the Tauri opener `import { open as openExternal } from "@tauri-apps/plugin-shell";` (confirm the shell-open import the codebase already uses for external links; grep for an existing `plugin-shell` / `openUrl` usage and match it). The `onAutonomi` body mirrors the existing controller `onAutonomi` handler verbatim (reuse `parseAutonomiUrl` + `submit`).

- [ ] **Step 4: Type-check + full frontend test.** Run:

```bash
cd apps/fetchit-desktop
npx tsc --noEmit >/tmp/ts.log 2>&1; echo "TSC=$?"
npm run test:run >/tmp/t.log 2>&1; echo "VITEST=$?"; grep -E "Tests " /tmp/t.log
```

Expected: TSC=0, all vitest pass.

- [ ] **Step 5: Commit.**

```bash
git add apps/fetchit-desktop/src/chat/conversation.ts apps/fetchit-desktop/src/chat/controller.ts
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "feat(desktop): conversation-header profile trigger + controller wiring"
```

---

## Task 10: `.chat-profile` styles

**Files:**
- Modify: `apps/fetchit-desktop/src/chat/styles.css`

- [ ] **Step 1: Add the CSS block** (tokens only, mirror `.chat-dialog`/`.chat-lightbox` overlay + `.chat-icon-btn` patterns). Include: `.chat-profile` overlay (fixed/absolute inset 0, backdrop, grid place-items center, `[hidden]{display:none}`), `.chat-profile__panel` (bounded card, `--panel`/`--line` tokens), `.chat-profile__close`, `.chat-profile__avatar` (bounded <=128px box), `.chat-profile__name`/`__bio`/`__website`/`__links`/`__link` chips (copper accent), and `.chat-conv__subject-btn { all: unset; cursor: pointer; }` so the header button reads as the title. Match the exact token names used elsewhere in the file (`--copper`, `--ink`, `--bone`, `--ash`, `--line`, `--panel`, `--dur-trans`).

- [ ] **Step 2: Type-check (CSS has no test; confirm nothing else broke).** Run: `cd apps/fetchit-desktop && npm run test:run >/tmp/t.log 2>&1; echo "EXIT=$?"; grep -E "Tests " /tmp/t.log` Expected: all pass.

- [ ] **Step 3: Commit.**

```bash
git add apps/fetchit-desktop/src/chat/styles.css
git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "style(desktop): profile-card CSS (tokens only)"
```

---

## Task 11: final gates + manual smoke + push

- [ ] **Step 1: Full gate sweep.**

```bash
cd /home/josh/Desktop/fetchit
cargo fmt --all --check >/tmp/f.log 2>&1; echo "ROOT_FMT=$?"
cargo clippy --workspace --all-targets -- -D warnings >/tmp/c.log 2>&1; echo "ROOT_CLIPPY=$?"
cargo test -p fetchit-chat >/tmp/rt.log 2>&1; echo "ENGINE_TEST=$?"; grep "test result" /tmp/rt.log | tail -1
(cd apps/fetchit-desktop/src-tauri && cargo fmt --check >/tmp/sf.log 2>&1; echo "ST_FMT=$?"; cargo clippy --all-targets -- -D warnings >/tmp/sc.log 2>&1; echo "ST_CLIPPY=$?"; cargo test >/tmp/st.log 2>&1; echo "ST_TEST=$?"; grep "test result" /tmp/st.log | tail -1)
(cd apps/fetchit-desktop && npx tsc --noEmit >/tmp/ts.log 2>&1; echo "TSC=$?"; npm run test:run >/tmp/vt.log 2>&1; echo "VITEST=$?"; grep -E "Tests " /tmp/vt.log | tail -1)
```

Expected: every exit code 0; all test result lines green.

- [ ] **Step 2: Manual smoke (dev shell).** `cd apps/fetchit-desktop && npm run tauri dev`. Open a DM with a contact who has a published profile, click their name in the header, confirm: the card loads, name/bio/website/links render, the avatar fills in lazily, an `etchit`/`fetchit` link opens the reader, the `website` link shows the confirm before opening. Then test a contact with no profile (empty state) and verify the modal closes on backdrop/Escape/×.

- [ ] **Step 3: Push.**

```bash
git push josh-clsn chat 2>&1 | tail -3
```

---

## Self-Review (run against the spec before execution)

**Spec coverage** (docs/superpowers/specs/2026-06-10-profile-tab-design.md):
- §3 architecture flow (resolve index -> fetch manifest -> parse+verify -> cross-check -> watermark -> DTO; lazy avatar) -> Tasks 1,3,4,6.
- §4.1 `chat_fetch_profile` (all 7 steps incl. tombstone->None, 64KiB cap, watermark, agent-id chain) -> Tasks 3,4,6.
- §4.2 `chat_fetch_avatar` (declared-len + hard cap + magic sniff -> data URL) -> Task 5.
- §4.3 watermark store (JSON map, monotonic) -> Task 4.
- §5.1 four states (loading/none/error/stale) -> Task 8 (stale surfaces via the error line from `map_profile_err`'s "stale" message; covered by the error-state test path).
- §5.2 layout (avatar box, name, bio, website, link chips, textContent) -> Task 8.
- §5.3 link routing (etchit/fetchit/image->reader; x0x->message; website->confirm) -> Task 8 + Task 9 wiring.
- §6 security (two ML-DSA verifies via verify_index_record + manifest.verify; agent-id chain; watermark; field caps via parse; avatar bounded + sniffed + <img>; textContent) -> Tasks 1,3,4,5,8.
- §7 tests (fixture-driven happy/tampered/mismatch/tombstone/stale + avatar oversize/non-raster/valid + frontend states/routing/confirm/lazy-avatar) -> Tasks 3,5,8.
- §8 file structure -> matches the table above.

**Gaps consciously deferred:** the §5.1 "stale" state renders through the generic error line (honest message "a stale copy of this profile was rejected" from `map_profile_err`), not a visually distinct 4th card — acceptable per the spec's "honest, specific line" intent; a distinct stale style is a CSS-only follow-up if desired.

**Type consistency:** `ProfileOutcome`/`ProfileDto`/`AvatarDto` (Rust, camelCase serde) == `ProfileOutcome`/`ProfileDto`/`ProfileAvatarMeta` (TS). `fetch_index_record_by_id(relay,agent_id,http)` signature identical in Task 1 def and Task 6 call. `build_profile_outcome(requested,index_agent_id,bytes,watermark)` identical across Tasks 3/6. `load_watermark`/`save_watermark(chat_root,agent_id,..)` identical Tasks 4/6. `openProfileCard(opts)` callback names (`fetchProfile/fetchAvatar/onAutonomi/onMessage/confirmOpen`) identical Tasks 8/9.
