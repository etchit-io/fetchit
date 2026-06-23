# Grandma-UI: Android-First Idiot-Proof Chat — Design

**Status:** Approved direction (Josh, 2026-06-23): Android-first · idiot-proof + Tier-1 gaps · full-consumer posture. Phase 0 authorized to start.

**Goal:** An Android chat a non-technical person (the "grandma" bar) can use without being taught — open it, see their people by name and photo, tap, talk. Post-quantum encryption and decentralized identity underneath, completely invisible on top. Every crypto/network/identity truth still exists but lives one tap away in Settings → Advanced.

## Why this, why now

We just proved reliable PQ DMs + multi-member group chat end-to-end (desktop + on-device phone, dual-NAT). The transport/crypto floor works. The remaining gap to a shippable consumer product is **usability**, and the weakest surface is Android — which is also where a non-technical user actually lives. Grounded current state (verified against code):

- **Desktop chat** is already fairly rich: DM + groups, delivery receipts, presence, reply/quote, inline images, emoji picker, markdown, plain-English status/error copy, accessibility. (`apps/fetchit-desktop/src/chat/*`)
- **Android chat is a lean MVP and the real gap**: DM + groups + per-invitee invite + delivery tick, but **no presence, no reply, no attachments, no emoji, and messages are in-memory only (lost on app kill)**. (`apps/fetchit-android/.../chat/ChatModeView.kt`, on `android-apk-adopt-115` / `android-new-invite`)
- A prior `2026-06-08-chat-ui-excellence-m4-pane-design.md` spec covers feature richness + visual identity. **This spec is a different axis — usability/idiot-proofing — and sits on top of it.**

## The core principle

**Grandma-UI is not "more features." It is the opposite axis: fewer decisions, no dead ends, no jargon, impossible to get lost.** Adding industry-standard features makes the app *less* grandma-proof unless every one is added with ruthless progressive disclosure. So the work is two tracks held in balance:

- **Track A — Idiot-proofing:** simplify nav, guarantee onboarding, kill jargon, humanize identity.
- **Track B — Feature parity:** the table-stakes functions we lack, added *only* the grandma-safe way (in the existing thread; defaults that just work; power controls in Settings → Advanced).

### Idiot-proof rule set (binding for all work here)
1. **No 64-hex in the main flow, ever.** The user sees names + photos — contacts, groups, member lists, their own profile. (Today both apps show hex; the single biggest fix.)
2. **One obvious primary action per screen, always visible.** Empty IS a state; a "create" affordance must produce something visible. (Established rule.)
3. **Zero crypto words in the main flow** — no "relay / agent / pair / invite / x0x / MLS / epoch." Map to human words ("your code", "add a friend", "group link").
4. **Onboarding that cannot fail** — first run teaches the one next action with a picture; never an empty void.
5. **No dead ends** — every empty state contains its own next step.
6. **Status in human words** — "Delivered", "Sending…", "No internet — I'll send it when you're back online."
7. **Big tap targets, big text, high contrast.** Destructive/advanced actions tucked into Settings → Advanced with specific (not vague) risk wording.
8. **Honesty floor preserved** (does not contradict full-consumer): the "unverified sender" signal and the "fediverse is public / not post-quantum" truth stay reachable — softened and out of the way, never deleted.

## Tier-1 feature set (the gaps), grandma-safe, ranked by impact

1. **Message persistence on Android** — *must-fix.* In-memory today; messages vanish on app kill. The engine already persists history in the vault (`Conversation::push_history`); Android must persist + reload. Nothing else matters if messages disappear.
2. **Push notifications** — a non-technical user will not keep the app open. The real "always-on" piece. **Values tension (decide consciously):** FCM lets Google observe *that* a message arrived (not content) — a metadata exposure to weigh against our PQ/decentralization posture and state honestly. Evaluate data-only FCM vs alternatives.
3. **Reinstall / new-device re-key** — a returning member who lost local TreeKEM state cannot re-key today (daemon `server/mod.rs:9616` `has_active_member` bails before `stage_join_result`, so no fresh Welcome). Grandma *will* reinstall / get a new phone. Fix is a x0x-fork daemon patch (re-key a returning member: remove stale leaf + add fresh KeyPackage at current epoch → stage Welcome). Diagnosed 2026-06-23; owned by Alice (daemon + engine-A protocol), tested by Bob (owner box + repro).
4. **Names + photos** (identity humanization) — overlaps Track A rule 1; needs contact/group photo storage.
5. **Group member list** — "who is in this group," names + photos.
6. **Photo sharing on Android** — send a picture (desktop has it; engine attachment path exists).
7. **Read receipts ("Seen") + typing indicators + reactions** — expected by any modern chat user; desktop UI for reactions/typing is staged; all three need wire types from Bob.
8. **Voice messages** — high grandma value (hold-to-talk beats typing for older users); bigger build (record/encode/play over the attachment path). Currently out of v1.0 scope; pulled in for this audience.

### Tier-2 (not grandma-critical; later): GIFs/stickers, message edit/delete, group admin, link previews.

## Phasing (buildable, dependency-ordered)

- **Phase 0 — Foundations (no external wire dependency; transforms the app):**
  Android message persistence · names+photos data model + display · onboarding/nav/jargon rewrite · offline status copy · Settings → Advanced (home for all crypto/network/identity truth).
- **Phase 1 — Always-on / reliability:** push notifications (after the metadata-values decision) · reinstall re-key daemon fix.
- **Phase 2 — Richness (wire-gated, Bob owns the wire kinds):** read receipts · typing · reactions · photo sharing.
- **Phase 3 — Delight:** voice messages.

## Dependencies & ownership
- **Bob:** wire kinds for read receipts / typing / reactions (Phase 2); owns the Android integration branch (`android-apk-adopt-115`) + on-device test rig.
- **Alice:** the reinstall re-key daemon patch (x0x-fork `server/mod.rs:9616`); engine/FFI foundations; this spec + plans.
- **Net-new:** push-notification backend + the metadata-values decision (Phase 1).
- **Upstream:** a David note on core MLS reinstall/re-key semantics (we patch the fork now, propose upstream later).

## Cross-cutting constraints
- **Security model holds:** voice/photos widen the untrusted-media surface — validate per `docs/SECURITY.md` (the desktop image path already rejects SVG, sniffs MIME; mirror that discipline).
- **Sealed-by-default:** new message-borne content sealed under the envelope (M2 floor).
- **Metadata honesty:** push notifications and any third-party dependency get stated plainly (content E2EE yes; metadata not private) — match David's framing.
- **Branch coordination:** Android Phase-0 UI work merges *after* Bob's in-flight `adopt-115` + keys-fix rebase settles, to avoid merge conflicts in `ChatModeView.kt` / `strings.xml`. Engine/FFI foundations proceed on the canonical line in parallel.

## Phase 0 detail (what we build first)

**P0.1 Android message persistence.** Back the in-memory `ConversationStore` with durable on-disk history so a conversation survives app kill. Prefer reusing the engine vault history (single source of truth) surfaced via FFI over a parallel Kotlin store, if the FFI exposes it cheaply; otherwise an encrypted-at-rest Kotlin store mirroring the desktop's persistence. Reload on conversation open. (Relates to #42 "DM catch-up parity.")

**P0.2 Names + photos data model.** A contact/group has an optional display name (already partly present) + an optional photo. Add photo storage (encrypted at rest) + a deterministic fallback avatar (initials on a per-identity color, as desktop does). Replace every hex-short-id display in the main flow with name + avatar. Keep the hex reachable only in a contact's Advanced detail.

**P0.2b Per-identity bubble color (group readability — "who is who").** In a group, give each sender a stable, palette-derived visual identity so messages are scannable at a glance (raised live: hard to tell senders apart). Hard constraint: no wild colors — only subtle variations of the oxidation palette (`BRAND.md` / design-tokens-v2). The trick for "more options without more colors" is **combinatorics, not a bigger palette**: combine a few palette-derived axes that multiply —
- *fill tint* (a handful of subtle palette-adjacent bubble backgrounds),
- *accent* (left-border / name color in a palette accent),
- so e.g. 4 fills × 3 accents ≈ 12 distinct on-brand looks from ~5 base tokens.

Each agent gets a **deterministic** (fill, accent) combo derived from its `agent_id` (hash → index), so the same person always looks the same everywhere. Tie it to the **existing per-identity avatar color** (the initials-gradient hue) so avatar + bubble accent + sender-name color all share one hue per person = coherent identity, not just a bubble color. Self keeps the current right-aligned copper convention; others get their left-aligned per-identity treatment. Keep text contrast on every variant (tints stay subtle). Desktop + Android share the same derivation so a person looks identical across shells.

**P0.3 Onboarding + nav + jargon rewrite.** First-run empty state teaches "Add your first person" (Show my code / Scan a code) with a picture and one plain sentence. Nav stays two levels (list ↔ conversation), one "+" → {Message someone, New group}, back always goes home. Audit `strings.xml` end-to-end: replace crypto jargon with human words. (Lands after Bob's Android rebase settles.)

**P0.4 Offline + human status.** Status copy in words, including the offline reassurance ("No internet — I'll send it when you're back online"). Build on the existing delivery-tick + outbox state.

**P0.5 Settings → Advanced.** A single Advanced screen that becomes the home for everything we remove from the main flow: identity/agent id, network/relay status, verification details, the fediverse public/non-PQ disclosure. Risk wording specific, not vague.

**Phase 0 ordering (collision-aware):** start with the data foundations (P0.1 persistence, P0.2 names+photos model) which are mostly new/engine and low-collision; do the UI-copy/nav work (P0.3, P0.4) once Bob's `adopt-115` rebase settles; P0.5 Advanced last (it depends on knowing everything we pulled out of the main flow).

## Out of scope (this effort)
GIF/sticker search, message edit/unsend, group admin/roles, link previews, desktop grandma-pass (follows after Android), fetchit-as-fediverse-instance.
