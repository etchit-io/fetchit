# First-Run Onboarding + Key-Custody Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** First launch asks one question ("What should we call you?"), then chat is on and ready with keychain-default key custody, an honest recovery story, a working Settings > Advanced custody switch, and a human card when chat cannot start.

**Architecture:** Frontend overlay module (`src/onboarding/`) gated by a new `Settings.onboarding_done` flag; a runtime `set_chat_enabled` command with an idempotent event-pump guard so chat mounts live without restart; a new `fetchit-chat::rekey` engine module that re-seals every vault file (conversations, fedi actor identities, identity last) between keychain and passphrase custody; desktop `chat_rekey_vault` + `chat_custody_status` commands; a branched "chat unavailable" human card in the panel bootstrap catch; a custody switch panel under Settings.

**Tech Stack:** Rust (fetchit-chat engine crate, workspace member; src-tauri workspace-excluded), Tauri 2 commands, vanilla TS + Vite + vitest (jsdom).

**Spec:** `docs/superpowers/specs/2026-06-10-first-run-onboarding-design.md`

**Conventions that gate every task:** failing test first; `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` from repo root for engine changes; `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)` for desktop Rust (workspace-excluded); `(cd apps/fetchit-desktop && npm run test:run)` for frontend; every commit DCO-signed:
`git -c user.name='josh-clsn' -c user.email='59794857+josh-clsn@users.noreply.github.com' commit -s -m "<msg>"`.
No em-dashes anywhere in committed text. Minimal comments; rustdoc on every public item. Test modules open with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` or the `#[allow(...)]` attribute form already used per file. Tauri invoke args are camelCase in TS, snake_case in Rust.

---

## File map

- Modify: `apps/fetchit-desktop/src-tauri/src/settings.rs` (onboarding_done field)
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (onboarding_done / set_onboarding_done / set_chat_enabled commands, ensure_event_pump boot call, handler registration)
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs` (pump guard, chat_rekey_vault, chat_custody_status)
- Create: `crates/fetchit-chat/src/rekey.rs` (rekey_store_files, rekey_to, custody_status)
- Modify: `crates/fetchit-chat/src/lib.rs` (mod rekey), `crates/fetchit-chat/src/client.rs` (resolve_master_key visibility), `crates/fetchit-chat/src/at_rest.rs` (rotate_keychain_master)
- Create: `apps/fetchit-desktop/src/onboarding/welcome.ts`, `welcome.test.ts`, `styles.css`
- Create: `apps/fetchit-desktop/src/chat/unavailableCard.ts`, `unavailableCard.test.ts`
- Modify: `apps/fetchit-desktop/src/chat/panel.ts` (bootstrap catch renders the card)
- Modify: `apps/fetchit-desktop/index.html` (onboarding section), `apps/fetchit-desktop/src/controller.ts` (extract mountChatSurface, onboarding gate)
- Create: `apps/fetchit-desktop/src/settingsCustody.ts`, `settingsCustody.test.ts`
- Modify: `apps/fetchit-desktop/src/settings.ts` (custody panel template + init)

---

### Task 1: `Settings.onboarding_done` + read/write commands

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/settings.rs` (field after `fediverse_handle` at line ~120, Default impl at ~166, tests at end)
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (commands next to `display_name` at ~401; registration in the `generate_handler![]` list)

- [ ] **Step 1: Write the failing test** in `settings.rs` tests mod (copy the `fediverse_handle_defaults_empty_and_round_trips` shape):

```rust
#[test]
fn onboarding_done_defaults_false_and_round_trips() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("settings.json");
    let mut s = Settings::default();
    assert!(!s.onboarding_done);
    s.onboarding_done = true;
    s.save(&p).unwrap();
    assert!(Settings::load(&p).onboarding_done);
}

#[test]
fn missing_onboarding_done_field_in_file_defaults_false() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("settings.json");
    fs::write(
        &p,
        r#"{"cache":{"enabled":false,"mode":"persist","maxBytes":1}}"#,
    )
    .unwrap();
    assert!(!Settings::load(&p).onboarding_done);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `(cd apps/fetchit-desktop/src-tauri && cargo test onboarding_done)`
Expected: compile error, no field `onboarding_done`.

- [ ] **Step 3: Implement.** In the `Settings` struct after `fediverse_handle`:

```rust
    /// First-run onboarding marker. False until the welcome overlay
    /// completes or is skipped once; the frontend gates the overlay
    /// on this so it never re-prompts.
    #[serde(default)]
    pub onboarding_done: bool,
```

In `Default for Settings`, after `fediverse_handle: String::new(),`:

```rust
            onboarding_done: false,
```

In `lib.rs` after `set_display_name` (~line 420):

```rust
/// Read the first-run onboarding marker.
#[tauri::command]
fn onboarding_done(state: tauri::State<'_, AppState>) -> bool {
    state.settings.lock().is_ok_and(|s| s.onboarding_done)
}

/// Mark first-run onboarding as completed (or skipped). One-way.
#[tauri::command]
fn set_onboarding_done(state: tauri::State<'_, AppState>) {
    let Ok(mut s) = state.settings.lock() else {
        return;
    };
    s.onboarding_done = true;
    let _ = s.save(&state.settings_path);
}
```

Register both in the `tauri::generate_handler![...]` list near `display_name, set_display_name`.

- [ ] **Step 4: PASS**: `(cd apps/fetchit-desktop/src-tauri && cargo test onboarding_done)` then full `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)`.

- [ ] **Step 5: Commit** `feat(desktop): onboarding_done settings flag + commands`

### Task 2: runtime `set_chat_enabled` + idempotent event-pump guard

The pump is started at boot only when the flag resolves on (`lib.rs:980`). Enabling at runtime must start it exactly once; a second enable (or enable after an env-var boot) must not double-spawn.

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs` (ChatState field + `ensure_event_pump` + guard helper + test)
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (command, boot call site, registration)

- [ ] **Step 1: Write the failing test** in `chat.rs` tests mod:

```rust
#[test]
fn pump_guard_fires_exactly_once() {
    let flag = std::sync::atomic::AtomicBool::new(false);
    assert!(pump_should_start(&flag));
    assert!(!pump_should_start(&flag));
    assert!(!pump_should_start(&flag));
}
```

- [ ] **Step 2: Verify failure** (no `pump_should_start`): `(cd apps/fetchit-desktop/src-tauri && cargo test pump_guard)`.

- [ ] **Step 3: Implement.** In `chat.rs`:

Add to `ChatState` struct (after `x0xd_base_url`):

```rust
    /// One-shot latch so the event pump is spawned at most once per
    /// process, whether at boot or via a runtime `set_chat_enabled`.
    pump_started: Arc<std::sync::atomic::AtomicBool>,
```

Initialize in `ChatState::new` (after `x0xd_base_url,`):

```rust
            pump_started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
```

Add near `spawn_event_pump` (chat.rs:882):

```rust
/// True exactly once per latch: the caller that flips it owns the spawn.
fn pump_should_start(flag: &std::sync::atomic::AtomicBool) -> bool {
    !flag.swap(true, std::sync::atomic::Ordering::SeqCst)
}

/// Spawn the chat event pump unless it is already running. Safe to
/// call from boot and from the runtime enable path in any order.
pub fn ensure_event_pump(app: AppHandle, state: ChatState) {
    if pump_should_start(&state.pump_started) {
        spawn_event_pump(app, state);
    }
}
```

In `lib.rs`, replace the boot call (line ~980):

```rust
            if chat_enabled_at_boot {
                chat::ensure_event_pump(app.handle().clone(), chat_state);
            } else {
```

Add the command next to `set_lan_direct_enabled` (~line 443):

```rust
/// Flip the chat feature flag at runtime. Persists the setting, then
/// returns the RESOLVED flag (the FETCHIT_CHAT_ENABLED env override
/// still wins) so the frontend reflects reality. When the resolved
/// flag is on, starts the chat event pump if not already running.
#[tauri::command]
fn set_chat_enabled(
    app: tauri::AppHandle,
    settings_state: tauri::State<'_, AppState>,
    chat_state: tauri::State<'_, chat::ChatState>,
    enabled: bool,
) -> bool {
    if let Ok(mut s) = settings_state.settings.lock() {
        s.chat_enabled = enabled;
        let _ = s.save(&settings_state.settings_path);
    }
    let resolved = settings_state.settings.lock().map_or_else(
        |_| cfg!(debug_assertions),
        |s| settings::resolve_chat_enabled(&s),
    );
    if resolved {
        chat::ensure_event_pump(app, chat_state.inner().clone());
    }
    resolved
}
```

Register `set_chat_enabled` in `generate_handler![]` next to `chat_feature_enabled`.

- [ ] **Step 4: PASS + desktop gate**: `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)`.

- [ ] **Step 5: Commit** `feat(desktop): runtime set_chat_enabled with one-shot pump guard`

### Task 3: `fetchit-chat::rekey` engine module

Re-seals every vault file between custody modes. File classes: `conversations/*.json.enc` (FCV1 via `at_rest`), `fedi/*.json.enc` (sealed under `derive_fedi_vault_key(master)`, format owned by `fedi_vault.rs`), `identity.json.enc` LAST. The identity file's header is the mode authority `resolve_master_key` reads at boot (client.rs:2388), so rewriting it last keeps a crashed half-rekey bootable under the OLD key. Per-file resume: a file that fails to open under the old key but opens under the new key is already migrated and is skipped, so re-running a half-completed rekey converges.

Honest caveat to carry in the module rustdoc: a keychain-target rekey rotates the keychain entry before the file pass, so a crash mid-pass loses the old key for not-yet-migrated conversation files. The window is small, the operation is re-runnable for everything sealed under the new key, and the product's recovery story (new identity, re-add by QR) is the documented floor. Flag for cross-review.

**Files:**
- Create: `crates/fetchit-chat/src/rekey.rs`
- Modify: `crates/fetchit-chat/src/lib.rs` (add `pub mod rekey;` in alphabetical order)
- Modify: `crates/fetchit-chat/src/client.rs:2388` (`fn resolve_master_key` -> `pub(crate) fn resolve_master_key`)
- Modify: `crates/fetchit-chat/src/at_rest.rs` (add `rotate_keychain_master`)

- [ ] **Step 1: Write the failing tests** as the tests mod of the new `rekey.rs` (committed together with the impl; run them red first by stubbing the fns with `todo!()` locally if useful, but do not commit `todo!()`):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::at_rest::{
        fresh_argon_salt, kdf_id_argon2, open_from_path, seal_to_path, MasterKey,
    };
    use crate::local_store::StoreLayout;
    use tempfile::tempdir;

    fn master(b: u8) -> MasterKey {
        MasterKey::from_bytes_for_test([b; 32])
    }

    fn seed_store(root: &std::path::Path, m: &MasterKey, salt: &[u8; 16]) -> StoreLayout {
        let layout = StoreLayout::ensure(root.to_path_buf()).unwrap();
        seal_to_path(
            &layout.conversation_path("aa"),
            b"conv-a",
            m,
            kdf_id_argon2(),
            Some(salt),
        )
        .unwrap();
        seal_to_path(
            &layout.conversation_path("bb"),
            b"conv-b",
            m,
            kdf_id_argon2(),
            Some(salt),
        )
        .unwrap();
        seal_to_path(
            &layout.root.join("identity.json.enc"),
            b"identity",
            m,
            kdf_id_argon2(),
            Some(salt),
        )
        .unwrap();
        layout
    }

    #[test]
    fn rekey_flips_every_file_and_contents_survive() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        let n = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).unwrap();
        assert_eq!(n, 3);
        for p in [
            layout.conversation_path("aa"),
            layout.conversation_path("bb"),
            layout.root.join("identity.json.enc"),
        ] {
            assert!(open_from_path(&p, &old).is_err(), "{p:?} still opens under old");
            assert!(open_from_path(&p, &new).is_ok(), "{p:?} does not open under new");
        }
    }

    #[test]
    fn rekey_skips_files_already_under_the_new_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        // Simulate a prior half-run: conversation aa already migrated.
        seal_to_path(
            &layout.conversation_path("aa"),
            b"conv-a",
            &new,
            kdf_id_argon2(),
            Some(&new_salt),
        )
        .unwrap();
        let n = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).unwrap();
        assert_eq!(n, 2, "already-migrated file is skipped, not an error");
        assert!(open_from_path(&layout.conversation_path("aa"), &new).is_ok());
    }

    #[test]
    fn rekey_errors_when_a_file_opens_under_neither_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        seal_to_path(
            &layout.conversation_path("cc"),
            b"alien",
            &master(9),
            kdf_id_argon2(),
            Some(&old_salt),
        )
        .unwrap();
        assert!(rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt)).is_err());
    }

    #[test]
    fn conversation_failure_leaves_identity_under_the_old_key() {
        let dir = tempdir().unwrap();
        let (old, new) = (master(1), master(2));
        let (old_salt, new_salt) = (fresh_argon_salt(), fresh_argon_salt());
        let layout = seed_store(dir.path(), &old, &old_salt);
        seal_to_path(
            &layout.conversation_path("cc"),
            b"alien",
            &master(9),
            kdf_id_argon2(),
            Some(&old_salt),
        )
        .unwrap();
        let _ = rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&new_salt));
        // Identity is rewritten last, so the failed pass must not have
        // touched it: the store still boots under the old key.
        assert!(open_from_path(&layout.root.join("identity.json.enc"), &old).is_ok());
    }

    #[test]
    fn custody_status_reports_mode_from_identity_header() {
        let dir = tempdir().unwrap();
        let layout = StoreLayout::ensure(dir.path().to_path_buf()).unwrap();
        assert_eq!(custody_status(&layout.root), CustodyStatus::NoVault);
        let salt = fresh_argon_salt();
        seal_to_path(
            &layout.root.join("identity.json.enc"),
            b"identity",
            &master(1),
            kdf_id_argon2(),
            Some(&salt),
        )
        .unwrap();
        assert_eq!(custody_status(&layout.root), CustodyStatus::Passphrase);
    }
}
```

Plus a fedi-file test (uses the real fedi_vault format; read the exact `save_actor_identity` / `load_actor_identity` signatures at `crates/fetchit-chat/src/fedi_vault.rs:85,163` and construct a minimal `ActorIdentityVault` fixture as those tests do):

```rust
    #[test]
    fn rekey_reseals_fedi_actor_identities_under_the_new_derived_key() {
        // Seed one actor identity sealed under derive_fedi_vault_key(old),
        // run rekey_store_files(old -> new), assert load with new master
        // succeeds and load with old master fails. Mirror the fixture
        // construction used in fedi_vault.rs's own tests.
    }
```

(Write this test with the real fixture at implementation time; the assertion contract above is fixed.)

- [ ] **Step 2: Verify red**: `cargo test -p fetchit-chat rekey` fails to compile (module absent).

- [ ] **Step 3: Implement `rekey.rs`:**

```rust
//! Vault custody rekey: re-seal every at-rest file under a new master
//! key, switching between OS-keychain and Argon2id-passphrase custody.
//!
//! Order matters: conversations and fedi actor identities first,
//! `identity.json.enc` LAST. The identity header is the custody-mode
//! authority `resolve_master_key` consults at boot, so a crash before
//! the final write leaves the store fully bootable under the old key.
//! Each file is resumable: one that no longer opens under the old key
//! but opens under the new key is counted as already migrated.
//!
//! Honest caveat: a keychain-target rekey rotates the keychain entry
//! before the file pass. A crash inside the pass can strand
//! not-yet-migrated files with no recoverable key. The window is one
//! file loop; the documented product recovery floor (new identity,
//! contacts re-added by QR) applies. Do not "fix" this with a
//! key-next-to-data escrow file.

use crate::at_rest::{
    fresh_argon_salt, kdf_id_argon2, kdf_id_keychain, open_from_path, read_kdf_id, seal_to_path,
    MasterKey, MasterKeySource, ARGON_SALT_LEN,
};
use crate::error::ChatError;
use crate::local_store::StoreLayout;
use std::path::Path;
use zeroize::Zeroizing;

/// Which custody mode the on-disk vault is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyStatus {
    /// No identity vault exists yet (chat never booted).
    NoVault,
    /// Master key lives in the OS keystore.
    Keychain,
    /// Master key derives from a user passphrase (Argon2id).
    Passphrase,
}

/// Report the custody mode by inspecting the identity vault header.
#[must_use]
pub fn custody_status(root: &Path) -> CustodyStatus {
    let identity = root.join("identity.json.enc");
    if !identity.exists() {
        return CustodyStatus::NoVault;
    }
    match read_kdf_id(&identity) {
        Ok(k) if k == kdf_id_argon2() => CustodyStatus::Passphrase,
        Ok(_) => CustodyStatus::Keychain,
        Err(_) => CustodyStatus::NoVault,
    }
}

/// Re-seal every vault file under `new`. Returns the number of files
/// rewritten (already-migrated files are skipped and not counted).
///
/// # Errors
/// `ChatError` when any file opens under neither key, or on IO/AEAD
/// failures. On error the identity file has not been rewritten.
pub fn rekey_store_files(
    layout: &StoreLayout,
    old: &MasterKey,
    new: &MasterKey,
    new_kdf_id: u8,
    new_salt: Option<&[u8; ARGON_SALT_LEN]>,
) -> Result<usize, ChatError> {
    let mut rewritten = 0usize;
    for entry in list_enc_files(&layout.conversations_dir)? {
        rewritten += rekey_fcv1_file(&entry, old, new, new_kdf_id, new_salt)?;
    }
    rewritten += rekey_fedi_dir(layout, old, new)?;
    let identity = layout.root.join("identity.json.enc");
    if identity.exists() {
        rewritten += rekey_fcv1_file(&identity, old, new, new_kdf_id, new_salt)?;
    }
    Ok(rewritten)
}

fn list_enc_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, ChatError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && path.to_string_lossy().ends_with(".json.enc") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Returns 1 when the file was rewritten, 0 when already migrated.
fn rekey_fcv1_file(
    path: &Path,
    old: &MasterKey,
    new: &MasterKey,
    new_kdf_id: u8,
    new_salt: Option<&[u8; ARGON_SALT_LEN]>,
) -> Result<usize, ChatError> {
    match open_from_path(path, old) {
        Ok(plain) => {
            seal_to_path(path, &plain, new, new_kdf_id, new_salt)?;
            Ok(1)
        }
        Err(_) if open_from_path(path, new).is_ok() => Ok(0),
        Err(e) => Err(ChatError::Invalid(format!(
            "rekey: {} opens under neither key: {e}",
            path.display()
        ))),
    }
}

/// Fedi actor identities are sealed under an HKDF of the master key
/// (`fedi_identity::derive_fedi_vault_key`), so a master change must
/// re-seal them too. Same skip-if-already-new resume rule.
fn rekey_fedi_dir(
    layout: &StoreLayout,
    old: &MasterKey,
    new: &MasterKey,
) -> Result<usize, ChatError> {
    // Implementation note: drive fedi_vault::load_actor_identity /
    // save_actor_identity with the old / new masters per their
    // signatures at fedi_vault.rs:85,163, iterating list_enc_files
    // over layout.fedi_dir and deriving the handle from the file stem.
    // Keep the try-old / fall-back-new / else-error shape of
    // rekey_fcv1_file.
    let _ = (layout, old, new);
    Ok(0) // replaced by the real loop in this same task; test-driven.
}
```

(The `rekey_fedi_dir` body is written against the real fedi_vault signatures in this task; the placeholder shown here never lands because the fedi test from Step 1 forces the real implementation before commit.)

Then `rekey_to`, in the same file:

```rust
/// Orchestrated custody switch for a store rooted at `root`.
///
/// `current_passphrase` unlocks the existing vault when it is in
/// passphrase mode (ignored in keychain mode). `new_passphrase = Some`
/// targets passphrase custody under a fresh salt; `None` targets
/// keychain custody under a freshly rotated keychain key.
///
/// No vault on disk is a no-op returning `Ok(0)`: the caller sets the
/// future client-build passphrase instead.
///
/// # Errors
/// Key resolution, IO, or AEAD failures; see [`rekey_store_files`].
pub fn rekey_to(
    root: &Path,
    current_passphrase: Option<&str>,
    new_passphrase: Option<&str>,
) -> Result<usize, ChatError> {
    let layout = StoreLayout::ensure(root.to_path_buf())?;
    let identity = layout.root.join("identity.json.enc");
    if !identity.exists() {
        return Ok(0);
    }
    let (old, _kdf, _salt) = crate::client::resolve_master_key(&identity, current_passphrase)?;
    match new_passphrase {
        Some(pass) => {
            if pass.trim().is_empty() {
                return Err(ChatError::Invalid("passphrase must not be empty".into()));
            }
            let salt = fresh_argon_salt();
            let new = MasterKey::resolve(
                &MasterKeySource::Passphrase(Zeroizing::new(pass.to_owned())),
                Some(&salt),
            )?;
            rekey_store_files(&layout, &old, &new, kdf_id_argon2(), Some(&salt))
        }
        None => {
            let new = crate::at_rest::rotate_keychain_master()?;
            rekey_store_files(&layout, &old, &new, kdf_id_keychain(), None)
        }
    }
}
```

In `at_rest.rs`, next to `resolve_keychain` (~line 101):

```rust
    /// Delete any existing keychain master entry and mint a fresh one.
    /// Used by custody rekey when returning to keychain mode: reusing
    /// the prior entry would silently keep a key the user believed
    /// replaced.
    ///
    /// # Errors
    /// `ChatError::Invalid` when the keystore is unreachable.
    pub(crate) fn rotate_keychain() -> Result<Self, ChatError> {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
            let _ = entry.delete_credential();
        }
        Self::resolve_keychain()
    }
```

and a free wrapper at module level so `rekey.rs` can call it without widening `MasterKey` internals:

```rust
/// Rotate the OS-keychain master entry and return the fresh key.
///
/// # Errors
/// `ChatError::Invalid` when the keystore is unreachable.
pub(crate) fn rotate_keychain_master() -> Result<MasterKey, ChatError> {
    MasterKey::rotate_keychain()
}
```

Also: `crates/fetchit-chat/src/lib.rs` gains `pub mod rekey;` (alphabetical), `client.rs:2388` becomes `pub(crate) fn resolve_master_key(...)`, and `MasterKey::from_bytes_for_test` plus the existing seal/open helpers are already crate-visible for the tests.

Add an `#[ignore]` keychain-path test mirroring `at_rest.rs`'s `keychain_round_trip` idiom for `rekey_to(root, None, Some("pass"))` and back, gated on a real keystore.

- [ ] **Step 4: Green + workspace gate**: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

- [ ] **Step 5: Commit** `feat(chat): vault custody rekey module (keychain <-> passphrase)`

### Task 4: desktop `chat_rekey_vault` + `chat_custody_status` commands

**Files:**
- Modify: `apps/fetchit-desktop/src-tauri/src/chat.rs` (commands after `chat_set_passphrase` at ~line 802; tests in the file's tests mod)
- Modify: `apps/fetchit-desktop/src-tauri/src/lib.rs` (register both)

- [ ] **Step 1: Failing test** (chat.rs tests mod) for the pure validation helper:

```rust
#[test]
fn rekey_passphrase_validation_rejects_blank() {
    assert!(validate_rekey_passphrase(Some(" ")).is_err());
    assert!(validate_rekey_passphrase(Some("")).is_err());
    assert!(validate_rekey_passphrase(Some("hunter2")).is_ok());
    assert!(validate_rekey_passphrase(None).is_ok());
}
```

- [ ] **Step 2: Red**: `(cd apps/fetchit-desktop/src-tauri && cargo test rekey_passphrase)`.

- [ ] **Step 3: Implement:**

```rust
/// Blank passphrases would silently downgrade custody; reject early.
fn validate_rekey_passphrase(p: Option<&str>) -> Result<(), String> {
    match p {
        Some(s) if s.trim().is_empty() => Err("passphrase must not be empty".into()),
        _ => Ok(()),
    }
}

/// Report the at-rest custody mode: "none" (no vault yet),
/// "keychain", or "passphrase". Drives the Settings custody panel.
#[tauri::command]
pub fn chat_custody_status(state: tauri::State<'_, ChatState>) -> String {
    match fetchit_chat::rekey::custody_status(&state.data_dir) {
        fetchit_chat::rekey::CustodyStatus::NoVault => "none".into(),
        fetchit_chat::rekey::CustodyStatus::Keychain => "keychain".into(),
        fetchit_chat::rekey::CustodyStatus::Passphrase => "passphrase".into(),
    }
}

/// Switch vault custody. `new_passphrase = Some` re-seals everything
/// under an Argon2id passphrase; `None` re-seals under a freshly
/// rotated OS-keychain key. With no vault on disk this only sets the
/// passphrase the next client build will use (first-boot headless
/// enrol, same contract as `chat_set_passphrase`). On success the
/// client is invalidated so the next call rebuilds under the new
/// custody; on error the in-memory state is left untouched.
#[tauri::command]
pub async fn chat_rekey_vault(
    app_state: tauri::State<'_, AppState>,
    state: tauri::State<'_, ChatState>,
    new_passphrase: Option<String>,
) -> Result<(), String> {
    ensure_chat_enabled(&app_state)?;
    validate_rekey_passphrase(new_passphrase.as_deref())?;
    let current = state.passphrase.lock().await.clone();
    let root = state.data_dir.clone();
    let target = new_passphrase.clone();
    tokio::task::spawn_blocking(move || {
        fetchit_chat::rekey::rekey_to(&root, current.as_deref(), target.as_deref())
    })
    .await
    .map_err(|e| format!("rekey task join: {e}"))?
    .map_err(|e| e.to_string())?;
    *state.passphrase.lock().await = new_passphrase;
    state.invalidate().await;
    Ok(())
}
```

(`ChatState.data_dir` is a private field in the same module, accessible here. Confirm `invalidate` is the existing method `chat_set_passphrase` uses.)

Register `chat_custody_status, chat_rekey_vault` in `generate_handler![]` next to `chat_set_passphrase`.

- [ ] **Step 4: Desktop gate**: `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)`.

- [ ] **Step 5: Commit** `feat(desktop): chat_rekey_vault + chat_custody_status commands`

### Task 5: welcome overlay module

**Files:**
- Create: `apps/fetchit-desktop/src/onboarding/welcome.ts`
- Create: `apps/fetchit-desktop/src/onboarding/welcome.test.ts`
- Create: `apps/fetchit-desktop/src/onboarding/styles.css` (and `@import` it from the main stylesheet the way `src/fediverse/styles.css` is imported)

- [ ] **Step 1: Failing tests** (`welcome.test.ts`, mirror the `vi.mock("@tauri-apps/api/core")` idiom from `src/fediverse/compose.test.ts`):

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { ONBOARDING_COPY, initOnboarding } from "./welcome";

type InvokeMock = ReturnType<typeof vi.fn>;

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  document.body.innerHTML = "";
});

function host(): HTMLElement {
  const el = document.createElement("section");
  el.hidden = true;
  document.body.append(el);
  return el;
}

describe("initOnboarding", () => {
  it("stays hidden when onboarding is already done", async () => {
    (invoke as InvokeMock).mockResolvedValue(true);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    expect(h.hidden).toBe(true);
    expect(h.querySelector(".onboarding")).toBeNull();
  });

  it("renders the overlay with the locked honesty copy on first run", async () => {
    (invoke as InvokeMock).mockResolvedValue(false);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    expect(h.hidden).toBe(false);
    expect(h.textContent).toContain(
      "Your chat keys are created on this device and stay only here. " +
        "If you switch computers you start fresh, and add your people " +
        "again with a QR code. Nothing about you is stored in any cloud.",
    );
  });

  it("keeps Start disabled until a 1..=64 char name is typed", async () => {
    (invoke as InvokeMock).mockResolvedValue(false);
    const h = host();
    await initOnboarding(h, { onChatStart: vi.fn() });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    const start = h.querySelector<HTMLButtonElement>(".onboarding__start")!;
    expect(start.disabled).toBe(true);
    input.value = "   ";
    input.dispatchEvent(new Event("input"));
    expect(start.disabled).toBe(true);
    input.value = "x".repeat(65);
    input.dispatchEvent(new Event("input"));
    expect(start.disabled).toBe(true);
    input.value = "Grandma";
    input.dispatchEvent(new Event("input"));
    expect(start.disabled).toBe(false);
  });

  it("Start saves the name, enables chat, marks done, then hands off", async () => {
    const calls: string[] = [];
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      calls.push(cmd);
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "set_chat_enabled") return Promise.resolve(true);
      return Promise.resolve(null);
    });
    const onChatStart = vi.fn().mockResolvedValue(undefined);
    const h = host();
    await initOnboarding(h, { onChatStart });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    input.value = " Grandma ";
    input.dispatchEvent(new Event("input"));
    h.querySelector<HTMLButtonElement>(".onboarding__start")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect((invoke as InvokeMock)).toHaveBeenCalledWith("set_display_name", {
      name: "Grandma",
    });
    expect((invoke as InvokeMock)).toHaveBeenCalledWith("set_chat_enabled", {
      enabled: true,
    });
    expect(calls.indexOf("set_display_name")).toBeLessThan(calls.indexOf("set_chat_enabled"));
    expect(calls.indexOf("set_chat_enabled")).toBeLessThan(calls.indexOf("set_onboarding_done"));
    expect(onChatStart).toHaveBeenCalledTimes(1);
  });

  it("Start does not hand off to chat when the resolved flag is false", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) => {
      if (cmd === "onboarding_done") return Promise.resolve(false);
      if (cmd === "set_chat_enabled") return Promise.resolve(false);
      return Promise.resolve(null);
    });
    const onChatStart = vi.fn();
    const h = host();
    await initOnboarding(h, { onChatStart });
    const input = h.querySelector<HTMLInputElement>(".onboarding__name")!;
    input.value = "Grandma";
    input.dispatchEvent(new Event("input"));
    h.querySelector<HTMLButtonElement>(".onboarding__start")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect(onChatStart).not.toHaveBeenCalled();
  });

  it("Skip marks done and touches nothing else", async () => {
    (invoke as InvokeMock).mockImplementation((cmd: string) =>
      Promise.resolve(cmd === "onboarding_done" ? false : null),
    );
    const onChatStart = vi.fn();
    const h = host();
    await initOnboarding(h, { onChatStart });
    h.querySelector<HTMLButtonElement>(".onboarding__skip")!.click();
    await vi.waitFor(() => expect(h.hidden).toBe(true));
    expect(invoke).toHaveBeenCalledWith("set_onboarding_done");
    expect(invoke).not.toHaveBeenCalledWith("set_display_name", expect.anything());
    expect(invoke).not.toHaveBeenCalledWith("set_chat_enabled", expect.anything());
    expect(onChatStart).not.toHaveBeenCalled();
  });

  it("exports the locked copy object", () => {
    expect(ONBOARDING_COPY.title).toBe("Welcome to fetch>it");
    expect(ONBOARDING_COPY.question).toBe("What should we call you?");
    expect(ONBOARDING_COPY.start).toBe("Start");
    expect(ONBOARDING_COPY.skip).toBe("Skip for now");
  });
});
```

- [ ] **Step 2: Red**: `(cd apps/fetchit-desktop && npm run test:run -- welcome)`.

- [ ] **Step 3: Implement `welcome.ts`:**

```ts
// First-run welcome overlay. One question (display name), honest key
// custody copy, Start enables chat live, Skip just marks done. Gated
// by the persisted onboarding_done settings flag so it shows once.

import { invoke } from "@tauri-apps/api/core";

export const ONBOARDING_COPY = {
  title: "Welcome to fetch>it",
  question: "What should we call you?",
  honesty:
    "Your chat keys are created on this device and stay only here. " +
    "If you switch computers you start fresh, and add your people " +
    "again with a QR code. Nothing about you is stored in any cloud.",
  start: "Start",
  skip: "Skip for now",
} as const;

const NAME_MAX = 64;

export interface OnboardingOpts {
  /// Called after Start succeeds AND the resolved chat flag is on.
  /// The controller mounts the chat surface and opens the panel here;
  /// the panel's own bootstrap mints the identity (and renders the
  /// human card on failure).
  onChatStart: () => Promise<void> | void;
}

/// Mount the overlay into `host` unless onboarding is already done.
export async function initOnboarding(host: HTMLElement, opts: OnboardingOpts): Promise<void> {
  const done = await invoke<boolean>("onboarding_done").catch(() => true);
  if (done) return;

  const root = document.createElement("div");
  root.className = "onboarding";

  const card = document.createElement("div");
  card.className = "onboarding__card";

  const title = document.createElement("h1");
  title.className = "onboarding__title";
  title.textContent = ONBOARDING_COPY.title;

  const label = document.createElement("label");
  label.className = "onboarding__question";
  label.textContent = ONBOARDING_COPY.question;

  const input = document.createElement("input");
  input.className = "onboarding__name";
  input.type = "text";
  input.maxLength = NAME_MAX;
  input.placeholder = "Your name";
  label.append(input);

  const honesty = document.createElement("p");
  honesty.className = "onboarding__honesty";
  honesty.textContent = ONBOARDING_COPY.honesty;

  const start = document.createElement("button");
  start.className = "onboarding__start";
  start.type = "button";
  start.textContent = ONBOARDING_COPY.start;
  start.disabled = true;

  const skip = document.createElement("button");
  skip.className = "onboarding__skip";
  skip.type = "button";
  skip.textContent = ONBOARDING_COPY.skip;

  card.append(title, label, honesty, start, skip);
  root.append(card);
  host.append(root);
  host.hidden = false;
  input.focus();

  const validName = (): string | null => {
    const name = input.value.trim();
    return name.length >= 1 && name.length <= NAME_MAX ? name : null;
  };
  input.addEventListener("input", () => {
    start.disabled = validName() === null;
  });

  const finish = (): void => {
    host.hidden = true;
    root.remove();
  };

  start.addEventListener("click", () => {
    const name = validName();
    if (name === null) return;
    start.disabled = true;
    void (async () => {
      try {
        await invoke("set_display_name", { name });
        const resolved = await invoke<boolean>("set_chat_enabled", { enabled: true });
        await invoke("set_onboarding_done");
        finish();
        if (resolved) await opts.onChatStart();
      } catch (e) {
        console.error("[onboarding] start failed:", e);
        // Still complete: the reader must never be held hostage by
        // a chat bootstrap problem. The chat panel surfaces its own
        // human card on open.
        await invoke("set_onboarding_done").catch(() => {});
        finish();
      }
    })();
  });

  skip.addEventListener("click", () => {
    void invoke("set_onboarding_done").catch(() => {});
    finish();
  });
}
```

`styles.css`: fixed full-window overlay (`position: fixed; inset: 0`), dimmed backdrop, centered card, brand-consistent typography; `.onboarding__skip` styled as a subtle text link. Import alongside the fediverse stylesheet.

- [ ] **Step 4: Green**: `(cd apps/fetchit-desktop && npm run test:run -- welcome)`.

- [ ] **Step 5: Commit** `feat(desktop): first-run welcome overlay with honest custody copy`

### Task 6: chat-unavailable human card

**Files:**
- Create: `apps/fetchit-desktop/src/chat/unavailableCard.ts`
- Create: `apps/fetchit-desktop/src/chat/unavailableCard.test.ts`
- Modify: `apps/fetchit-desktop/src/chat/panel.ts` (bootstrap catch at ~line 572)

- [ ] **Step 1: Failing tests:**

```ts
import { describe, expect, it } from "vitest";
import {
  CHAT_UNAVAILABLE_COPY,
  classifyBootstrapError,
  renderChatUnavailableCard,
} from "./unavailableCard";

describe("classifyBootstrapError", () => {
  it("treats keyring failures as keystore problems", () => {
    expect(classifyBootstrapError(new Error("keyring get: no secret service"))).toBe("keystore");
    expect(classifyBootstrapError("keyring open: dbus down")).toBe("keystore");
  });
  it("treats everything else as transient", () => {
    expect(classifyBootstrapError(new Error("connect refused 127.0.0.1:45000"))).toBe("transient");
    expect(classifyBootstrapError(undefined)).toBe("transient");
  });
});

describe("renderChatUnavailableCard", () => {
  it("renders the keystore copy with the Settings pointer", () => {
    const host = document.createElement("div");
    renderChatUnavailableCard(host, "keystore");
    expect(host.querySelector(".chat-unavailable")).not.toBeNull();
    expect(host.textContent).toContain(CHAT_UNAVAILABLE_COPY.keystore);
    expect(host.textContent).toContain("Settings");
  });
  it("renders the transient copy and replaces a prior card", () => {
    const host = document.createElement("div");
    renderChatUnavailableCard(host, "keystore");
    renderChatUnavailableCard(host, "transient");
    expect(host.querySelectorAll(".chat-unavailable").length).toBe(1);
    expect(host.textContent).toContain(CHAT_UNAVAILABLE_COPY.transient);
  });
});
```

- [ ] **Step 2: Red**: `(cd apps/fetchit-desktop && npm run test:run -- unavailableCard)`.

- [ ] **Step 3: Implement `unavailableCard.ts`:**

```ts
// Human card for a failed chat bootstrap, branched on cause. The
// keystore branch points at the passphrase escape hatch; everything
// else is framed as transient (the panel's retry loop keeps running).

export type ChatUnavailableKind = "keystore" | "transient";

export const CHAT_UNAVAILABLE_COPY = {
  keystore:
    "Chat can't start on this computer. It needs your system's secure " +
    "key storage, which isn't available right now. Reading works fully " +
    "without it.",
  keystoreAction: "To use chat anyway, set a chat passphrase in Settings > Advanced.",
  transient:
    "Chat can't start right now. It usually fixes itself in a moment, " +
    "and reading works fully in the meantime.",
} as const;

export function classifyBootstrapError(e: unknown): ChatUnavailableKind {
  return /keyring/i.test(String(e)) ? "keystore" : "transient";
}

/// Render (or replace) the card inside `host`. Idempotent per host.
export function renderChatUnavailableCard(
  host: HTMLElement,
  kind: ChatUnavailableKind,
): HTMLElement {
  host.querySelector(".chat-unavailable")?.remove();
  const card = document.createElement("div");
  card.className = "chat-unavailable";
  const msg = document.createElement("p");
  msg.className = "chat-unavailable__msg";
  msg.textContent = CHAT_UNAVAILABLE_COPY[kind];
  card.append(msg);
  if (kind === "keystore") {
    const action = document.createElement("p");
    action.className = "chat-unavailable__action";
    action.textContent = CHAT_UNAVAILABLE_COPY.keystoreAction;
    card.append(action);
  }
  host.prepend(card);
  return card;
}
```

Wire into `panel.ts`'s bootstrap `catch` (the block that sets `idBadge.textContent = "Chat unavailable"`): import the two functions, locate the panel's main content element in scope at that point (read the surrounding `open()` body; the element that hosts the contacts/conversation content), and add:

```ts
      renderChatUnavailableCard(contentHost, classifyBootstrapError(e));
```

using the actual in-scope content-element name. Keep the existing badge text, daemon-status pill, and retry timer exactly as they are (the transient card sits above the retry loop; a successful retry re-renders the panel and the card goes with it). Add a `.chat-unavailable` style block to the chat stylesheet matching the panel's card idiom.

- [ ] **Step 4: Green + full frontend suite**: `(cd apps/fetchit-desktop && npm run test:run)`.

- [ ] **Step 5: Commit** `feat(desktop): branched human card for failed chat bootstrap`

### Task 7: controller + index.html wiring

**Files:**
- Modify: `apps/fetchit-desktop/index.html` (line 38 area)
- Modify: `apps/fetchit-desktop/src/controller.ts` (chat-gate block, lines ~106-180)

- [ ] **Step 1: index.html** after the fediverse-panel section:

```html
    <section id="onboarding" hidden aria-label="Welcome"></section>
```

- [ ] **Step 2: controller.ts.** Extract the entire `else` body of the `if (!chatOn)` block (chat badge, `mountChatPanel`, chat button listener, fediverse panel mount, `bindFediverseEvents` wiring, keyboard-relevant assignments) into a local function, and gate double-mounting:

```ts
  let chat: ChatPanelApi | null = null;
  let chatSurfaceMounted = false;
  const mountChatSurface = (): void => {
    if (chatSurfaceMounted) return;
    chatSurfaceMounted = true;
    chatBtn.hidden = false;
    chatHost.hidden = true;
    fediverseBtn.hidden = false;
    // ... the existing else-block body moves here verbatim ...
  };
  if (!chatOn) {
    chatBtn.hidden = true;
    chatHost.hidden = true;
    fediverseBtn.hidden = true;
    fediverseHost.hidden = true;
  } else {
    mountChatSurface();
  }
```

Then, after the chat block, mount the onboarding gate:

```ts
  const onboardingHost = need<HTMLElement>("onboarding");
  void initOnboarding(onboardingHost, {
    onChatStart: async () => {
      mountChatSurface();
      if (chat && !chat.isOpen()) {
        await chat.toggle();
      }
    },
  });
```

with `import { initOnboarding } from "./onboarding/welcome";` at the top. Check `ChatPanelApi` for the exact open/toggle surface and use what exists (`toggle()` is used by the chat button today).

- [ ] **Step 3: Type + build + full suite**: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run && npm run build)` (use the project's existing build script names from package.json; `npm run build` runs the vite production build).

- [ ] **Step 4: Manual smoke**: `rm -f ~/.local/share/<app-dir>/settings.json` equivalent on a throwaway profile, `npm run tauri dev`, verify: overlay appears over the reader, Start with a name lands in the open chat panel, relaunch shows no overlay. Then Skip path on a second wiped profile.

- [ ] **Step 5: Commit** `feat(desktop): first-run onboarding wired into boot, chat mounts live`

### Task 8: Settings custody switch panel

**Files:**
- Create: `apps/fetchit-desktop/src/settingsCustody.ts` (mirror the `settingsAdvertisedRelays.ts` sibling-module pattern: exported IDS const + idempotent `initCustodyPanel(root)`)
- Create: `apps/fetchit-desktop/src/settingsCustody.test.ts`
- Modify: `apps/fetchit-desktop/src/settings.ts` (Advanced-section template block + `initCustodyPanel(root)` call next to `initAdvertisedRelaysPanel(root)` at ~line 112)

- [ ] **Step 1: Failing tests:**

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { CUSTODY_IDS, CUSTODY_COPY, custodyPanelTemplate, initCustodyPanel } from "./settingsCustody";

type InvokeMock = ReturnType<typeof vi.fn>;

function mount(): HTMLElement {
  const root = document.createElement("div");
  root.innerHTML = custodyPanelTemplate();
  document.body.append(root);
  return root;
}

beforeEach(() => {
  (invoke as InvokeMock).mockReset();
  document.body.innerHTML = "";
});

describe("custody panel", () => {
  it("shows the current mode from chat_custody_status", async () => {
    (invoke as InvokeMock).mockResolvedValue("keychain");
    const root = mount();
    initCustodyPanel(root);
    await vi.waitFor(() => {
      expect(
        root.querySelector(`#${CUSTODY_IDS.status}`)?.textContent,
      ).toContain("system keychain");
    });
  });

  it("applying a passphrase calls chat_rekey_vault with it", async () => {
    (invoke as InvokeMock).mockResolvedValue("keychain");
    const root = mount();
    initCustodyPanel(root);
    const pass = root.querySelector<HTMLInputElement>(`#${CUSTODY_IDS.passphrase}`)!;
    pass.value = "hunter2";
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toPassphrase}`)!.click();
    await vi.waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("chat_rekey_vault", {
        newPassphrase: "hunter2",
      });
    });
  });

  it("blocks a blank passphrase client-side", async () => {
    (invoke as InvokeMock).mockResolvedValue("keychain");
    const root = mount();
    initCustodyPanel(root);
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toPassphrase}`)!.click();
    await Promise.resolve();
    expect(invoke).not.toHaveBeenCalledWith("chat_rekey_vault", expect.anything());
    expect(root.querySelector(`#${CUSTODY_IDS.error}`)?.textContent).not.toBe("");
  });

  it("returning to keychain calls chat_rekey_vault with null", async () => {
    (invoke as InvokeMock).mockResolvedValue("passphrase");
    const root = mount();
    initCustodyPanel(root);
    root.querySelector<HTMLButtonElement>(`#${CUSTODY_IDS.toKeychain}`)!.click();
    await vi.waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("chat_rekey_vault", { newPassphrase: null });
    });
  });

  it("carries the specific risk copy", () => {
    expect(CUSTODY_COPY.risk).toContain("can't be recovered");
  });
});
```

- [ ] **Step 2: Red**: `(cd apps/fetchit-desktop && npm run test:run -- settingsCustody)`.

- [ ] **Step 3: Implement.** `settingsCustody.ts` exports:

```ts
export const CUSTODY_IDS = {
  status: "custody-status",
  passphrase: "custody-passphrase",
  toPassphrase: "custody-to-passphrase",
  toKeychain: "custody-to-keychain",
  error: "custody-error",
} as const;

export const CUSTODY_COPY = {
  keychain: "Chat data on this computer is protected by your system keychain.",
  passphrase: "Chat data on this computer is protected by your passphrase.",
  none: "Chat hasn't started yet. The system keychain protects it by default once it does.",
  risk:
    "If you forget the passphrase, chat data on this device can't be " +
    "recovered. Messages live only on this device either way.",
} as const;
```

plus `custodyPanelTemplate(): string` returning the section HTML (status line, risk paragraph, passphrase input, two action buttons, error slot) and `initCustodyPanel(root: HTMLElement): void` with the `dataset.bound` idempotence guard, a `chat_custody_status` query into the status line ("system keychain" / "passphrase" / the none copy), blank-passphrase client-side rejection into the error slot, and the two apply paths invoking `chat_rekey_vault` (`{ newPassphrase: value }` / `{ newPassphrase: null }`) followed by a status re-query. `settings.ts`: insert `custodyPanelTemplate()` into the Advanced section markup and call `initCustodyPanel(root)` beside `initAdvertisedRelaysPanel(root)`.

- [ ] **Step 4: Green + suite**: `(cd apps/fetchit-desktop && npm run test:run)`.

- [ ] **Step 5: Commit** `feat(desktop): Settings custody switch (keychain <-> passphrase)`

### Task 9: full gates, push, handoff

- [ ] **Step 1:** Root: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- [ ] **Step 2:** Desktop Rust: `(cd apps/fetchit-desktop/src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)`.
- [ ] **Step 3:** Frontend: `(cd apps/fetchit-desktop && npx tsc --noEmit && npm run test:run && npm run build)`.
- [ ] **Step 4:** Fix any drift in one `chore` commit if needed; push `chat` to `josh-clsn`.
- [ ] **Step 5:** Ask Bob for cross-review of the rekey module + commands (at-rest custody = sensitive surface per project discipline), with the crash-window caveat called out explicitly.
