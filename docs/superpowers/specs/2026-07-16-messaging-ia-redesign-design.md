# Messaging IA Redesign — Design Spec

**Date:** 2026-07-16
**Status:** approved in brainstorm (nav model + escalation model chosen by product owner); pending final spec review
**Scope:** the messaging mode of fetch>it — Android shell leads, desktop shell mirrors the same IA. Browse mode is untouched.
**Depends on:** M7 fedi social (live), pair links (`pairShareUri`), single-use group invites (`groupInvite`), the sealed fedi thread store (`fetchit-chat/src/fedi_thread.rs`).

---

## 1. Problem

Field testing on Android found the messaging IA fails the "grandma test":

- Reaching a fediverse DM from messaging entry takes **6 taps, 3 of them undiscoverable**: conversation list → pinned "Public posts" row → un-labeled people icon (a recycled group-members button slot) → "your fediverse" sheet → "find someone" → message.
- The people/DM/follow world is **nested under a door labeled "Public posts"** — a semantic mismatch. Nobody looks for people inside posts.
- The Feed screen **reuses the DM-thread layout** (`view_chat_thread.xml`), so the feed reads as a broken chat.
- PQ contacts and fedi people have **two disconnected entry paths** (FAB → popup → "add contact" vs feed → icon → sheet → find) for the same human intent: *talk to someone*.
- The Followers section is a **hardcoded empty stub** (bridge serves `totalItems: 0` even though the `followers` table has rows).
- Inviting a fediverse contact to private (PQ) chat is **one passive sentence in a banner** — nothing to tap. The P4 escalation flow has no UI at all.
- A **new fedi correspondent's thread appears nowhere** until the user digs for it (open gap, previously tracked as "surface unseen fedi DM threads").

## 2. Decisions taken (product owner, 2026-07-16)

1. **Navigation skeleton:** three bottom tabs inside messaging mode — **Chats · People · Feed** — with **one unified conversation list** (PQ DMs, PQ groups, fedi threads together). Chosen over a 2-tab variant and a labels-only fix.
2. **Escalation model:** a permanent **Go private** button in every fediverse thread; on completion the **same chat row flips 🌐 → 🔒 in place** with an in-thread divider. Chosen over a second parallel conversation row and over a People-tab-only action. Linking the fedi handle to the new PQ contact is **human-confirmed, never automatic** (security requirement, §7.3).

## 3. Information architecture

```
messaging mode
├── bottom tab bar (Material3 NavigationBar, labels always visible)
│   ├── 💬 Chats   (tab root, default)
│   ├── 👥 People  (tab root)
│   └── 📰 Feed    (tab root)
├── pushed screens (tab bar hidden):
│   ├── Thread (PQ DM)          — pushed from Chats / People / new-chat
│   ├── GroupThread (PQ group)  — pushed from Chats
│   ├── FediThread (fedi DM)    — pushed from Chats / People / Feed / profile card
│   └── (dialogs/sheets: new-chat, profile card, go-private, link-confirm)
```

- The **browse ⇄ messaging top-level switch is unchanged.** Tabs exist only inside messaging.
- **Tab bar visibility rule:** visible on the three tab roots, hidden on any pushed screen. One rule, no exceptions.
- **Back behavior:** inside a pushed screen, back pops to the owning tab root. On a tab root, back exits messaging to browse (today's contract). Switching tabs does not stack — tabs are siblings, and the last-selected tab persists across app restarts alongside the existing last-mode persistence.
- The existing `ChatModeView` screen-stack machinery is retained; the three tab roots replace the single `Screen.List` root.

## 4. Chats tab (home)

**One list, every conversation, most-recent-activity first.**

- Row sources:
  - PQ DM threads — existing contacts + `ConversationStore.convKeyDm` previews.
  - PQ group threads — existing groups + `convKeyGroup` previews (lock glyph already distinguishes private groups).
  - **Fedi threads — new:** enumerated from the engine's durable thread store via a new FFI (§9.1). Every thread in `fedi/threads/<handle>.json.enc` gets a row, including correspondents the user never added — this closes the unseen-thread gap.
- Row badges: 🔒 for PQ DMs and private groups, `#` for public/unknown groups (existing glyph), 🌐 for fedi threads. The badge is the privacy contract at a glance.
- Sort key: last message timestamp per conversation (engine history tail for PQ, `last_at_ms` from the fedi overview FFI).
- **The pinned "Public posts" row is deleted.** The feed is a tab now.
- **FAB "+ New chat"** opens the new-chat sheet:
  - One input field (reuse the unified `AddContactInput` classifier): `@name` → lookup → profile card; `fetchit://pair/…` → pair import + name prompt (existing flow); `fetchit://link/…` → device-link flow (existing); group invite link → join flow (existing).
  - A **scan a code** button (existing scanner entry).
  - Below: the user's people (contacts first, then following) — tap to open/start the right thread kind.
- Empty state: keep the three onboarding buttons — "Add someone you know" (new-chat sheet), "Create a group" (existing dialog), and the mint-state-dependent third button exactly as today: no handle → "Get your @handle" (switches to the People tab, mint card on top); minted → "See public posts" (switches to the Feed tab).
- Identity badge (name + connection dot) stays in the Chats header; it still opens the share-my-code card.

## 5. People tab

Top to bottom:

1. **Search field, full width:** "find someone — @name or paste a link" (same `AddContactInput` classifier as the new-chat sheet) with a scan button beside it.
2. **Your contacts** (🔒): display name; tap → PQ thread; overflow → rename / remove (existing actions).
3. **Following** (🌐): @handle; tap → **profile card**; pending follows show the existing "waiting for their accept" row state.
4. **Followers**: real list from the bridge (§9.3); rows show @handle; tap → profile card. Empty copy: "no followers yet — when someone follows your @name, they'll show up here."
5. **Blocked** (collapsed section at the bottom): existing unblock rows.

**Profile card** (one card used everywhere a person is tapped — People rows, feed post authors, lookup results): handle, follow state, and actions — **message** (opens fedi thread), **follow/unfollow**, **block**, **🔒 go private** (§7). For a linked person (§7.4) the card shows both capabilities ("private ✓ · following ✓") and **message** opens the PQ thread.

**Merged person rows:** once a fedi person is linked to a PQ contact, People shows **one row** for them (contact section, with a small 🌐 affix), not two. Backed by the person-link store (§9.2).

**@handle mint:** if the user has no handle yet, People shows the mint card at the top of Following ("Get your public @name to follow people — takes seconds", existing mint dialog). Feed carries the same card for compose (§6). Mint UI itself is unchanged.

## 6. Feed tab

- **A real feed layout** (new `view_feed.xml`) — not the thread XML. Post list with pull-to-refresh; compose box at the top when a handle exists.
- No handle yet → the compose slot shows the mint card instead ("Get your public @name to post and follow — takes seconds") opening the existing mint dialog.
- Post rows: author @handle (tap → profile card), body, relative time, and the existing per-post honesty badge ("from the fediverse · public, non-PQ") kept but visually lighter.
- The @handle header and the people door **leave this screen** — People owns the social graph now. Feed is content only.
- Feed pull/merge/block-filter logic is unchanged (`FeedStore.mergeRemote`, block filtering).

## 7. Go private (P4 escalation)

### 7.1 Entry points

- Primary: a permanent **`🔒 Go private`** button in the FediThread header (replaces the passive banner sentence; the "fediverse · not encrypted" subtitle stays).
- Secondary: the same action on the profile card.

### 7.2 Invite

Tap → confirmation card:

> **Make this chat private?**
> We'll send @{handle} an invite. When they open it in fetch>it, this chat turns private — post-quantum encrypted, nobody (not even servers) can read it.
> Heads-up: the invite itself travels the open fediverse.
> [Send private invite] [Cancel]

Sending composes a fedi DM: one human sentence + the pair link:

> {display name} invited you to a private, post-quantum encrypted chat on fetch>it. Open this link in the fetch>it app to accept: {pairShareUri} — new here? Get the app: https://etchit.io/fetch

Delivery uses the existing `send_fedi_dm` path. **The pending state is recorded only when the delivery report says `delivered == true`**; an unreachable inbox surfaces the existing retry affordance and records nothing. After a successful send the button becomes a quiet status line: *"invite sent — waiting for them to join"*, with **resend** available after a 24 h cooldown (the pair link is stable — resend just sends the same link again; the cooldown prevents accidental spam).

### 7.3 Linking — human-confirmed, never automatic

When a new PQ contact appears (pair import / first inbound contact) **while at least one go-private invite is pending**, the shell shows a link-confirm card (in the Chats list as a banner and inside both threads):

> **Same person?**
> You invited @{handle} to private chat, and a new private contact "{contact name}" just appeared. Are they the same person?
> Only link them if you're sure — anyone who saw the invite link could pretend to be them. If in doubt, ask them out loud.
> [Yes — link them] [Not now]

**Why manual:** the pair URI crossed the recipient's server in plaintext. Anyone who saw it (their server operator included) can import it. Auto-linking would hand an impersonator a verified-looking @handle label. Manual confirm keeps the human as the trust anchor (verification words remain the deeper check, unchanged). This also honors the hard invariant that LIT and fedi identities share no keys and are never auto-associated — the link is an explicit per-person user action, stored locally only.

If several invites are pending, the card lists the pending handles and the user picks one (or "Not now"). Declining leaves both threads as they are; the card can be re-opened from the contact's overflow menu ("link to a fediverse person…") which lists pending invites.

### 7.4 After linking

- The Chats row flips **🌐 → 🔒** in place. Row title becomes the contact display name, with a small 🌐 affix indicating the linked handle.
- The merged thread renders: fedi history (from the `f:` store) read-only at the top, then the divider, then PQ messages:

```
── messages above traveled the open fediverse ──
── 🔒 private from here — post-quantum encrypted ──
```

- **The composer in a linked thread is PQ-only.** Contract: lock on the row ⇒ nothing typed there is ever plaintext. Sending a fedi DM to that person remains possible, deliberately out of the way, via their profile card ("message on fediverse").
- Removing the PQ contact removes the link (the fedi thread and its history survive as a 🌐 row again).
- Linking is idempotent and survives process death (engine store, §9.2).

### 7.5 States

`none → invited(invited_at_ms) → linked(agent_id_hex, linked_at_ms)`, per canonical handle. Declines don't change state (still `invited`). Unlink returns to `none` (invite history retained in the store for the re-open flow).

## 8. Group invites over the fedi rail

- In a private group thread: members view gains **"Invite someone"** → picker listing People (contacts first, fedi follows below).
- Picking a **PQ contact** sends the invite over PQ DM (existing rail).
- Picking a **fedi-only person** mints a **fresh single-use** invite (`groupInvite(groupId)` — invites are single-use; never reuse a minted link) and sends it over fedi DM with the same card style as §7.2, adapted: "…invited you to the private group "{group name}" on fetch>it…".
- Rule everywhere: **invites travel the most private rail available.**

## 9. Engine / FFI / bridge inventory (new build)

### 9.1 Fedi thread enumeration (engine + FFI)

`fetchit-chat`: an overview read on the existing `FediThreads` store — per thread: canonical label, last message body, last `at_ms`, last direction. FFI (names indicative, plan finalizes): `fediThreadsOverview(handle) -> List<FediThreadSummaryFfi { label, lastBody, lastAtMs, lastOutbound }>`. Pure read of already-sealed data; no new persistence.

### 9.2 Person-link store (engine + FFI)

New sealed store, mirroring `fedi_thread.rs` exactly (same `write_sealed_atomic`/`read_sealed` helpers, same at-rest key):

- Path: `fedi/links/<handle>.json.enc` under `StoreLayout` (per our-actor handle, like threads).
- Magic `FFL1`, AAD `fetchit-fedi-links-v1`, atomic replace via the shared TmpGuard pattern.
- Shape: `BTreeMap<String /* canonical peer handle */, PersonLink { invited_at_ms: Option<i64>, agent_id_hex: Option<String>, linked_at_ms: Option<i64> }>`.
- Engine ops: `record_go_private_invite` (composite: compose body → `send_fedi_dm` → on `delivered` record `invited_at_ms` — one call so pending state can't desync from the send), `pending_go_private()`, `link_fedi_person(handle, agent_id_hex)`, `unlink_fedi_person(handle)`, `person_links()`.
- FFI mirrors those five.
- Unit tests: state transitions, canonicalization, atomicity (mirror the thread-store test set), invite-not-recorded-on-undelivered.

### 9.3 Followers list (bridge + FFI)

- **Public AP collection** `GET /actors/:handle/followers`: return the **real `totalItems`** count, keep `orderedItems` empty — Mastodon-style count-only collection; we don't publicly enumerate a person's followers.
- **Owner-authed list** `GET /actors/:handle/followers/list` (bridge-auth-v1, same auth as `/messages`): rows `{ follower_actor_url, since_ms }` from the `followers` table, newest first.
- FFI: `fediFollowers(handle) -> List<String /* @user@host labels, derived from actor urls */>`.
- Tests: authed/unauthed, owner-only, label derivation.

### 9.4 Explicitly not needed

No new wire formats, no relay changes, no x0x changes, no new crypto. The escalation flow composes existing primitives (`pairShareUri`, `send_fedi_dm`, `importPairUri`, `groupInvite`).

## 10. Android shell restructure

`ChatModeView.kt` is a 132 KB monolith; this redesign splits it (one concept per file):

- `ChatModeView.kt` — orchestrator only: screen stack, tab host, entry points (`importFromUri`, `linkDeviceFromUri`, `openThread`, …).
- `ChatTabs.kt` — bottom NavigationBar + tab-root swapping + persistence of the selected tab.
- `ChatsTabView.kt` — unified list + adapter + FAB/new-chat sheet.
- `PeopleTabView.kt` — search + sections + profile card.
- `FeedTabView.kt` — feed list + compose + mint card.
- `ThreadView.kt` / `GroupThreadView.kt` / `FediThreadView.kt` — the three thread binders (extracted as-is first, then FediThreadView gains go-private).
- `GoPrivateFlow.kt` — invite card, pending status, link-confirm card, merged-thread divider logic.

Layouts: new `view_chat_tabs.xml` (tab scaffold), `view_feed.xml`, `view_people.xml`; `view_chat_list.xml` becomes the Chats tab root; `view_chat_thread.xml` returns to threads only.

## 11. Desktop mirror

Same IA, desktop idiom: the chat panel's sidebar gets the three sections as a segmented control (Chats / People / Feed) in place of today's separate fediverse panel entry. All engine/FFI additions in §9 are shell-agnostic. The desktop shell consumes the same spec; its implementation is planned separately by the desktop owner once this spec is signed.

## 12. Copy (key new strings, grandma voice)

| key | text |
|---|---|
| `tab_chats` | Chats |
| `tab_people` | People |
| `tab_feed` | Feed |
| `people_find_hint` | find someone — @name or paste a link |
| `go_private_button` | Go private |
| `go_private_title` | Make this chat private? |
| `go_private_body` | We'll send @%1$s an invite. When they open it in fetch>it, this chat turns private — post-quantum encrypted, nobody (not even servers) can read it. Heads-up: the invite itself travels the open fediverse. |
| `go_private_send` | Send private invite |
| `go_private_pending` | invite sent — waiting for them to join |
| `go_private_invite_dm` | %1$s invited you to a private, post-quantum encrypted chat on fetch>it. Open this link in the fetch>it app to accept: %2$s — new here? Get the app: https://etchit.io/fetch |
| `link_confirm_title` | Same person? |
| `link_confirm_body` | You invited @%1$s to private chat, and a new private contact "%2$s" just appeared. Are they the same person? Only link them if you're sure — anyone who saw the invite link could pretend to be them. If in doubt, ask them out loud. |
| `link_confirm_yes` | Yes — link them |
| `link_confirm_no` | Not now |
| `thread_divider_fedi` | messages above traveled the open fediverse |
| `thread_divider_pq` | 🔒 private from here — post-quantum encrypted |
| `group_invite_dm` | %1$s invited you to the private group "%2$s" on fetch>it. Open this link in the fetch>it app to join: %3$s — new here? Get the app: https://etchit.io/fetch |

## 13. Security & privacy invariants

1. **No auto-linking** of fedi handle ↔ agent id (§7.3). The link is local, user-confirmed, and never published. LIT and fedi identities continue to share no keys; nothing here changes identity separation.
2. **Sending a go-private invite is explicit per-recipient consent** to reveal your pair card to that person *and* their server path — the card says so in plain words. Same trust model as sharing your code over SMS/email today.
3. **Lock-row contract:** a 🔒 row's composer never produces plaintext-rail traffic. Fedi sends to a linked person exist only behind their profile card.
4. Honesty badges stay: fedi threads keep "not encrypted" subtitles; feed posts keep the public/non-PQ badge; the PQ crypto claims copy is unchanged.
5. Followers are never publicly enumerable (§9.3); only the owner (bridge-auth-v1) reads the list.
6. All new persistence is sealed-at-rest with the existing master key and atomic-write pattern; no new plaintext at rest.

## 14. Resilience requirements

- Pending-invite and link state live in the engine store — they survive process death and app reinstall-with-data.
- Thread merge is a render-time composition of two durable stores (`f:` history + PQ history); no migration, no data rewrite, nothing to corrupt.
- The unified Chats list renders from durable sources only (no in-memory-only rows) — a fedi thread appears even if the app dies between sync and open.
- Re-running a link (idempotent) or unlinking and relinking is safe.

## 15. Testing & gates

- **Engine:** unit tests per §9.1/9.2 listed above; existing thread-store tests untouched.
- **Bridge:** followers endpoint tests per §9.3; existing 53-test suite stays green.
- **FFI:** regenerate bindings via `scripts/build-jni-libs.sh`; then compile Android **including unit-test sources** (`compileDebugUnitTestKotlin`) — the established gate.
- **Android:** unit tests for input classification in the new-chat sheet and person-row merge logic; full workspace gates (`fmt --all --check`, `clippy -D warnings`, `cargo test --workspace`) before every push.
- **Device smoke (per phase):**
  - P1: fedi DM reachable in ≤ 3 taps from messaging entry (People → person → message); a never-added correspondent's thread visible in Chats; feed compose + PQ DM + group send/receive all unregressed.
  - P2: full go-private end-to-end against a second real device: invite over fedi rail, accept, manual link, badge flip, divider render, PQ-only composer; plus the decline path and an impersonation drill (second importer of the same URI must not get auto-labeled).
  - P3: fedi-rail group invite end-to-end; copy pass on every new string on-screen.
- Cross-review by the second maintainer after each phase (established sensitive-work rule).

## 16. Phasing

- **P1 — IA skeleton:** tabs, real Feed screen, unified Chats list (needs §9.1), People tab v1 (search/contacts/following/blocked + §9.3 followers), delete pinned feed row, new-chat sheet. *Gate: P1 device smoke.*
- **P2 — Go private:** §7 end-to-end (needs §9.2). *Gate: P2 device smoke incl. impersonation drill.*
- **P3 — Groups + polish:** §8, empty states, copy pass, desktop-mirror handoff review. *Gate: P3 smoke + full suites + cross-review.*

Each phase lands on this feature branch and merges to main only after its gate passes (feature-branch-until-proven).

## 17. Out of scope

Browse-mode changes; unread counts / read receipts / typing indicators; avatars or fedi profile images; auto-linking of identities; multi-account; fedi-side rendering changes on other servers; any relay/x0x/wire change; post-launch scale items.
