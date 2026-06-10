# First-run onboarding + key-custody consistency, design

Date: 2026-06-10. Status: written under the standing execution mandate;
pending owner review. Scope: fetch>it desktop only.

## Goal

A first launch that a non-technical user completes alone: open the app,
type a name, land in a working reader with chat ready and its
empty-state affordances visible. No passphrase prompt, no hex string,
no terminal, no "daemon". Key custody defaults to the OS keychain with
an honest recovery story stated up front.

Locked decisions this design implements:

- Key custody: OS-keychain default, no passphrase prompt. Optional
  passphrase lives under Settings > Advanced. No cloud backup. Recovery
  story is honest and plainly stated: a new device is a new identity;
  contacts are re-added by QR.
- Upstream alignment: x0x ADR 0015 sanctions exactly this pattern
  (no app-layer at-rest passphrases by default, best-effort OS-keystore
  wrapping, no prompt).

## Current state (verified in tree, 2026-06-10)

- The engine already defaults to keychain custody: building the chat
  client with no passphrase resolves a random 32-byte master key from
  the OS keystore (`keyring` 3.6: Secret Service / macOS Keychain /
  Windows credential store), creating it on first use
  (`crates/fetchit-chat/src/at_rest.rs`). The desktop always passes
  `None` (`apps/fetchit-desktop/src-tauri/src/lib.rs`, build path).
- Identity secret keys and conversation history are sealed at rest.
  Contact cards are PLAINTEXT JSON under `contacts/`. Inconsistent.
- Vault files self-describe their key source: header `kdf_id`
  0 = keychain, 1 = Argon2id passphrase (+ salt). `read_kdf_id()`
  exists. A wrong-source master key fails decryption with an error;
  identity is never silently regenerated.
- `chat_set_passphrase` swaps the unlock source for the NEXT client
  build without re-sealing existing vault files: correct for its
  documented purpose (headless first boot, before any vault exists),
  but as a switch on a live vault it bricks chat until reverted.
- `chat_enabled` defaults OFF in release builds (`cfg!(debug_assertions)`),
  resolved once at boot into app state; there is no runtime setter.
  The chat button is hidden when disabled.
- No onboarding UI exists. Display name defaults to empty; the chat
  badge falls back to an `agent-<hex>` placeholder.
- Keystore unavailable (e.g. headless Linux without Secret Service) =
  hard error at client build; the panel shows a terse "Chat unavailable"
  badge with retry.
- Contact add today: share-URI v3 + QR display + paste-a-link. No
  webcam scan (separate roadmap item, #102).

## Design

### 1. First-run gate

New `Settings.onboarding_done: bool`, serde-default false, set true
when the welcome overlay completes OR is skipped. Existing dev profiles
see the overlay once; one click clears it. Inference from
display-name/identity presence was rejected: a skip must persist
without minting anything.

### 2. Welcome overlay

New frontend module `src/onboarding/` (own file per concern, own CSS),
mounted by the controller over the live app when `onboarding_done` is
false. The reader stays visible behind it; the overlay is dismissed
only via Start or Skip.

Content, top to bottom:

- Brand mark + "Welcome to fetch>it".
- One question: "What should we call you?" with a single text input
  (trimmed, 1..=64 chars; Start disabled while invalid).
- The honesty line, verbatim copy locked by test:
  "Your chat keys are created on this device and stay only here.
  If you switch computers you start fresh, and add your people again
  with a QR code. Nothing about you is stored in any cloud."
- Primary button "Start".
- Subtle text link "Skip for now".

No theme, notification, or network questions. Defaults are the answer.

### 3. Start path

On Start, in order, all via existing or new Tauri commands:

1. `set_display_name(name)` (exists).
2. `set_chat_enabled(true)` (NEW, see 5).
3. `chat_identity()` (exists): eagerly mints the chat identity; the
   keychain master key is created on first use. Silent on success.
4. Controller mounts the chat affordance live (no restart) and opens
   the chat panel, which renders its existing empty-state affordances
   (share my card / QR, add contact).
5. `onboarding_done = true`, persist, overlay unmounts.

Failure at step 3 must NOT trap the user in the overlay: the overlay
still completes (name saved, `onboarding_done = true`) and a human
card replaces the chat panel content, branched on the error class:

- Keystore error (keyring failure in the message): "Chat can't start
  on this computer. It needs your system's secure key storage, which
  isn't available right now. Reading works fully without it. To use
  chat anyway, set a chat passphrase in Settings > Advanced."
- Anything else (x0xd unreachable, transient): "Chat can't start
  right now. It usually fixes itself in a moment, and reading works
  fully in the meantime." with the panel's existing retry behavior.

The reader remains first-class throughout.

### 4. Skip path

`onboarding_done = true`, persist, nothing else changes. Chat stays
behind its current default; the user can enable it later in Settings
exactly as today.

### 5. Runtime chat enable: `set_chat_enabled`

New Tauri command: persists `settings.chat_enabled`, then re-runs the
existing boot resolver (env override included, so
`FETCHIT_CHAT_ENABLED` still wins for dev) and updates the app-state
flag the `ensure_chat_enabled` guard reads. Frontend re-queries and
mounts/unmounts the chat button without restart. The settings UI's
existing chat toggle (if any) routes through the same command.

### 6. Custody consistency (engine, fetchit-chat)

(a) Seal contact cards at rest. `contacts/<agent_id>.json` becomes
`contacts/<agent_id>.json.enc` under the same master key and header
format as identity/history. Migration on store open: a plaintext
`.json` found is sealed, fsynced, then removed. No released users
exist; the migration covers dogfood boxes.

(b) Vault rekey. New at_rest-level operation: given the open (old)
master key and a target source, every vault file under the store root
(identity, conversations, contacts) is opened with the old key and
re-sealed under the new key + new header (write-new-then-rename per
file). New engine entry `Client`-adjacent so the desktop can call it,
plus desktop command `chat_rekey_vault(new_passphrase: Option<String>)`:
`Some` = move to Argon2id passphrase custody, `None` = move back to
keychain custody (rotating to a fresh random key is acceptable and
simpler than reusing the stored one). After rekey, the client is
invalidated and rebuilt with the new source.

`chat_set_passphrase` keeps its documented pre-vault headless purpose.
Settings > Advanced gains the user-facing switch: "Protect chat with a
passphrase instead of the system keychain" (and the reverse), routed
through rekey when a vault exists, through set-passphrase when none
does. Risk framing in that UI is specific, not vague: forgetting the
passphrase means chat data on this device is unrecoverable; the
keychain option ties chat data to the computer login instead.

### 7. Out of scope

Webcam QR scan (#102, next grandma item), installers/signing,
auto-update, the full human-language error pass, Android parity.

## Testing

- vitest (`src/onboarding/*.test.ts` + controller test): gate shows
  overlay only when `onboarding_done` false; name validation gates
  Start; Start happy path invokes set_display_name,
  set_chat_enabled(true), chat_identity in order then persists the
  flag and unmounts; identity-failure path completes onboarding and
  renders the human card; Skip persists the flag and invokes nothing
  else; honesty copy locked verbatim.
- src-tauri: `set_chat_enabled` persists + flips the runtime guard +
  env precedence preserved; `chat_rekey_vault` validation and
  client-invalidation contract.
- fetchit-chat: sealed-contacts round-trip; plaintext-contact
  migration (seal + remove); rekey round-trips keychain->passphrase->
  keychain on a temp store using injected test master keys, asserting
  every file's `kdf_id` header flips and contents survive; wrong-key
  open still errors (no regeneration).

## Decisions taken under the mandate (flag on review if wrong)

1. Skip link present but subtle (power users; grandma never sees it).
2. Onboarding completes even when chat boot fails (reader-first,
   honest card; no dead-end modal).
3. Returning to keychain custody mints a fresh random master key
   rather than reusing a prior keychain entry.
4. Welcome copy above is the working draft; the #180 honest-claim
   audit binds final wording before launch copy freezes.
