# Android Fediverse Parity — Design Spec

**Date:** 2026-07-01
**Status:** Draft for review (Josh + Alice)
**Owners:** Bob (Android UI) · Alice (engine/FFI)
**Branch:** `feature/android-fediverse-parity` (off `main` @ 47c0a30)

## Goal

Bring the fetch>it **Android** app to feature parity with the **desktop fediverse (ActivityPub) surface**: a mobile user can opt in, mint a `@handle`, publish public posts, browse the bridged feed, look up fediverse accounts, and bridge a fediverse contact into a PQ DM or group — all under the identity-separation and public-post-honesty invariants.

The engine already does all of this. This is **new FFI surface + Android UI**, not new engine work.

## Non-goals (out of scope)

- **Follow / followers.** Not built on *either* platform (zero Follow activity in `fetchit-fedi/activity.rs` or chat). New cross-platform *engine* work — excluded here unless separately funded.
- **Self-hosted actor-serving (Stage 6).** Actor docs + WebFinger are served by the etchit.io registry (`DEFAULT_FEDI_DOMAIN=etchit.io`); self-hosting is a separate relay-side effort.
- **Wallet / paid handles.** fetch>it stays content-read-only, no wallet. Minting is currently free (no payment), so no wallet dependency; the paid-handle model, if it lands, lives in etch/it.

## Invariants (hard rails — all phases)

1. **Opt-in, default-off.** No fediverse identity exists until the user explicitly mints one. The bridged read-feed may display (it rides the chat event stream), but identity + publishing are gated behind an explicit mint.
2. **Separate identity, no auto-doxx.** The AP `@handle` is a separate classical RSA identity (`fedi_identity`); the chat `agent_id` (ML-DSA) never appears in AP JSON and is never auto-linked. Minting is a deliberate user action; the user picks the handle. `publish` **loads** an existing identity and errors to onboarding if none — it must never auto-mint.
3. **Public-post honesty.** A mandatory confirm before the first publish per session: *"Post publicly to the fediverse. Visible to operators, instance admins, and any subscriber of your actor. Anyone you mention can see it; your community denylist is the only filter."* (mirrors desktop `compose.ts:227-282`).

## Current state (verified — Bob+Alice converged)

| Layer | State |
|---|---|
| Engine (`fetchit-fedi`+`fetchit-chat`) | BUILT: `mint_actor_identity_v2` (client.rs:4038), `publish_public_post` (client.rs:4247), WebFinger, denylist, attestation, transport |
| Desktop | Full surface E2E via 5 Tauri cmds (`actor_status/mint/ensure_v2/publish/lookup`). Publish happy-path to a real remote inbox is **wired-but-not-e2e-verified** (error-path unit-tested only) |
| FFI (uniffi→Kotlin) | RECEIVE-ONLY: `ChatEventFfi.PublicPost { verifiedActorUrl, activityJson }` (chat_ffi.rs:44). No mint/publish/lookup |
| Android | Read-only viewer: `FeedStore` (ConversationStore.kt:180), `Screen.Feed` (send row hidden), pinned `✦` feed row |

## Architecture — the split

- **Alice (engine/FFI):** 5 per-op uniffi wrappers on `ChatClient` exposing existing engine methods. Regen `.so` + `fetchit_ffi.kt` together via `build-jni-libs.sh` (never separately).
- **Bob (Android UI):** a fediverse hub anchored on the existing `Screen.Feed`, plus onboarding / compose / lookup, calling those FFI methods and mirroring desktop UX with Android Views.

## FFI contract (Alice's half — per-op, mirrors desktop DTOs)

Method names illustrative; final names Alice's call. DTO **field names** the Android view-models need:

1. `fediActorStatus() -> String?` — active minted handle, or `null` if none (drives the onboarding gate). *(If the UI later needs the actor_url here too, return a struct; handle-only suffices for the gate.)*
2. `fediMint(handle: String) -> MintOutcomeFfi { actorUrl: String, registered: Boolean, registrationError: String? }`
3. `fediEnsureV2() -> EnsureV2Ffi { upgraded: Boolean, registered: Boolean, pending: String? }`
4. `fediPublish(bodyMd: String, replyToActorUrl: String?) -> PublishReportFfi { delivered: List<String>, failed: List<FailedDeliveryFfi { inbox: String, error: String }> }` *(uniffi has no tuples — `failed` is a list of structs, not `Vec<(String,String)>`)*
5. `fediLookup(handle: String) -> LookupFfi { kind: LookupKindFfi, handle: String, actorUrl: String, agentIdHex: String?, displayName: String?, bio: String?, avatar: String?, shareUri: String?, verifyFailure: String? }` where `LookupKindFfi = Verified | PublicOnly | NotFound`

Receive side is unchanged (existing `PublicPost` event). Feed enrichment (below) parses the existing `activityJson`; **no new FFI needed for the feed**.

## Android UI (Bob's half) — screens mirror desktop

The **Feed screen becomes the fediverse hub** (mirrors desktop's fediverse pane):
- No handle yet → a "join the fediverse" onboarding prompt.
- Handle present → your `@handle` shown, a compose entry, a lookup/search affordance, and the feed.

Components:
- **Feed post** — actor URL attribution (relay-verified only; never body-asserted), inert plain-text body (already stripped), a `from the fediverse · public, non-PQ` badge, `autonomi://` preview reuse, and a reply-publicly action (Phase 3).
- **Onboarding/mint** — handle field (1–64 chars: letters/digits/`-`/`_`), mint, honest pending-state on directory failure (retry via `ensure_v2` on hub open).
- **Compose** — textarea, `@user@host` mention hint, the honesty confirm modal (once/session), publish → delivery report ("delivered X · failed Y").
- **Lookup/profile card** — search `@handle@domain`, verified vs public-only card, view profile, `message privately` (→ existing pair import → DM), `invite to group` (→ existing group-invite).

## Phasing (each phase device-verified on Josh's S22 before the next)

1. **Feed polish** *(FFI-independent — start now):* actor attribution + honesty badge on feed posts. Pure UI over existing `PublicPost` data.
2. **Onboarding + mint** *(needs `fediActorStatus`,`fediMint`):* the hub gate + handle mint.
3. **Compose + publish** *(needs `fediPublish`):* composer + honesty confirm + delivery report; reply-publicly from the feed now works.
4. **Lookup/profile + bridges** *(needs `fediLookup`; DM/group reuse existing code):* profile card, fedi→DM, fedi→group-invite.

## Verification — make it rock, not just wire

- **V1 (e2e publish):** from a minted mobile handle, publish to a real Mastodon account; confirm it appears remotely and a public reply bridges back to the feed. Closes the "wired-but-not-e2e" gap.
- **V2 (inbound attestation):** focused check that the broadcast/feed path actually runs `verify_attestation` (today only in peer.rs + tests). Do **not** claim "verified inbound" until confirmed; fix if the path is unverified.

## Testing

- Unit tests (JUnit/Robolectric, TDD) for the pure Android bits: handle validation, `LookupKind`→card mapping, delivery-report formatting, compose mention extraction (if done client-side).
- Gate every Android change with `compileDebugUnitTestKotlin` + `assembleDebug` (test source compiles too), then device-verify.
- Cross-review: Alice reviews the Android diffs; Bob reviews the FFI diffs.
