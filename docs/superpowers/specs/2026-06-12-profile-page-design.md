# fetch>it Desktop Profile Page (Design)

**Date:** 2026-06-12
**Branch:** chat
**Lane:** [A] Alice (desktop). Trinity seam: a contact's profile is their
etch>it-published, Autonomi-hosted page, rendered as a first-class
read-only page in the reader.
**Status:** Design approved section-by-section by Josh 2026-06-12
(layout, features, states, approach, security, testing). Supersedes the
*placement* decision of `2026-06-10-profile-tab-design.md` (modal-only);
that spec's backend, modal, and security machinery all ship unchanged and
are reused here. The modal is demoted to the in-chat quick peek.

## 1. Goal & scope

Promote a profile from a chat-only modal to a page in the reader: open a
contact's (or your own, or any looked-up handle's) Autonomi-published
profile as a real tab with an address, history, back, dedupe, bookmarks,
and share. Handles become a first-class address: the address bar accepts
`@handle@domain` alongside 64-hex and `autonomi://` (the M5 "handles are
the front door" thesis carried into the reader).

In scope:
- A second address class (`@handle@domain` typed; canonical tab address
  `profile:<agent_id_hex>`) branching in the controller's submit path.
- A profile page renderer (banner layout) with verified-identity badge,
  bio, website, links, a lazy etchings gallery, and actions (Message,
  Invite to group, Share QR; Edit in etch/it on your own page).
- Seven entry points (section 4) converging on one `openProfile` call.
- The etch/it creation handoff for fetch-only users (own page, empty).
- Profile-manifest detection banner on the JSON renderer.
- One backend extension (optional relay hint on `chat_fetch_profile`)
  and one new command (`etchit_handoff` probe + launch).

Out of scope:
- Editing anything (etch/it owns publishing; fetch>it stays a reader).
- A core `Rendition::Profile` (post-v1.0 candidate at most: core is
  stateless, no network, no crypto by charter, so it could neither
  resolve the two-transport chain nor verify; an unverified profile
  rendition would invert the security posture).
- Android / CLI surfaces (post-v1.0 catch-up; renderer is built
  dispatch-shaped so a future engine variant can adopt it).
- Lease mechanics, premium release, follower teardown (M5.2, bridge lane).

## 2. Decisions log (all Josh, 2026-06-12)

- Navigation depth: UNIVERSAL FRONT DOOR. `@handle@domain` typed in the
  address bar resolves; profile tabs join history/dedupe/bookmarks.
- Layout: BANNER (option C): full-width identity band, actions on the
  band, work below. (Toured hero, settled banner, in companion.)
- Optional layers: ALL FOUR IN: etchings gallery, share-this-person QR,
  view-my-own-profile, profile-manifest detection banner.
- Modal fate: QUICK PEEK + LINK. The shipped chat modal stays; gains one
  "Open full profile" button that closes chat and opens the page.
- Build approach: SHELL ROUTE (no rendition-type pollution, no core
  changes; existing commands reused).
- Own-page empty state: TRINITY CARD (option B): "etch/ writes ->
  Autonomi keeps -> fetch> shows" story + create/get etch/it actions.
- Principle (binds this and future specs): Autonomi is the canonical
  storage layer; servers do only what only a server can do; fetch>it
  never grows a write path; creation hands off to etch/it.

## 3. Architecture

```
address bar / entry point
  -> address class parse
       64-hex / autonomi://  -> existing fetch_and_render path (untouched)
       @handle@domain        -> fediverse_lookup (WebFinger -> actor doc
                                -> attestation v2 verify -> relay index
                                -> manifest fetch + verify)   [shipped]
       profile:<agent_id>    -> chat_fetch_profile(agent_id, relay_hint?)
                                [shipped + one new optional param]
  -> LookupDto / ProfileDto
  -> src/profile/page.ts renders into the tab root
  -> avatar: chat_fetch_avatar, lazy after paint            [shipped]
  -> gallery: label-only cards; click opens autonomi:// in a reader tab
```

- Canonical tab address is ALWAYS `profile:<agent_id_hex>`; the address
  bar displays the `@handle@domain` form when known (tab carries a
  display string). Dedupe/history/bookmarks key on the canonical form,
  so handle-entry and sidebar-entry land in the same tab.
- `openProfile({ agentId?, handle?, relayHint?, display? })` is the one
  entry call. Handle entry resolves to an agent id first (the lookup
  already returns it); agent-id entry resolves the relay as: explicit
  hint (from lookup/contact card) -> contact-card relay hints -> own
  configured relay.
- `chat_fetch_profile` gains `relay: Option<String>`; `None` keeps
  today's behaviour exactly (existing callers unchanged).
- Manifest-detection banner: the JSON renderer already holds the parsed
  value; a shape check (version/agent_id/sig fields) shows one banner
  line, "This looks like a profile - view as profile page?", which
  navigates to `profile:<agent_id>` and the page performs the normal
  verified resolution. A pasted manifest is never trusted directly; if
  the identity does not resolve through the relay index, the page says
  so honestly. No extra fetch happens to render the banner.

## 4. Entry points (seven, one destination)

1. Address bar: `@handle@domain` typed or pasted.
2. M5.1 lookup card: new "View profile" action.
3. Contact sidebar: click-through on a contact row.
4. DM header modal: new "Open full profile" button (closes chat).
5. Fediverse pane: feed-author chip on verified-actor posts.
6. "View my profile": settings + chat panel (agent id = self).
7. JSON renderer manifest-detection banner.

## 5. Layout (banner, approved mockup)

Full-width identity band: avatar (lazy, bounded), display name in the
display serif, gold verified badge, `@handle@domain`, actions
right-aligned on the band (Message, Invite to group, Share QR; own page
adds Edit in etch/it). Below the band: bio + website line, link chips,
then the ETCHINGS section: a card grid of the profile's
`etchit`/`fetchit` links (label + kind only; zero prefetch; click opens
the address in a reader tab). `website` and unknown link kinds render in
the chips row, never in the gallery. Oxidation tokens throughout; no new
colour literals.

## 6. Verified badge (honest-claim language)

The badge asserts exactly: the handle, the chat keys, and this profile
content are cryptographically bound to the same keyholder, checked on
this device at view time (attestation v2 + manifest ML-DSA signature +
freshness watermark + the agent-id chain
`requested == index == manifest == derived`). It does NOT assert
real-world identity: no vouching, no KYC, not a celebrity checkmark.
Click opens a one-paragraph explainer saying the above in user words.
Copy is test-locked. States:

| State | Render |
| --- | --- |
| verified | gold badge; full actions |
| public-only (no attestation) | "public profile" label; Message/Invite absent |
| public-only (attestation failed) | same, plus the specific `verify_failure` line in rust red |
| changed hands | verified page + warning band: this handle previously pointed to different keys (continuity ledger) |
| loading | reader mascot, like any fetch |
| no profile (contact) | neutral "hasn't published a profile yet" |
| no profile (own) | Trinity handoff card (section 7) |
| transport error | honest error card + retry; never a trust downgrade |

A lapsed-and-re-issued handle is safe BY this design: the changed-hands
warning is the user-facing half of the lease lifecycle (bridge half:
HELD -> deliberate re-issue, M5.1 bridge; Delete(Actor) audience
teardown, M5.2).

## 7. The etch/it handoff (fetch-only users)

Own page, nothing published, renders the Trinity card: dashed avatar
placeholder, "Make this page yours", the one-breath story
("etch/ writes -> Autonomi keeps -> fetch> shows"), copy noting that
people who look you up land here, and two actions:

- "Create my profile in etch/it": invoke `etchit_handoff` -> probe for
  an installed etch/it (PATH binary / .desktop entry / platform
  equivalent) -> launch via the OS opener with the fixed URI
  `etchit://profile` -> report not-installed if the probe fails.
- "Get etch/it": confirm-then-open `https://etchit.io` (the existing
  external-link speed bump).

An EXISTING own page adds an "Edit in etch/it" action on the band, same
handoff. Contact empty states do not advertise etch/it (the visitor
cannot act on it). Cross-repo follow-up (etchit session, logged): etch>it
registers the `etchit://` scheme and routes `etchit://profile` to its
profile tab.

## 8. Security

- Re-verify everything on every load; no cross-session trust caching.
  The freshness watermark blocks stale-manifest replay (shipped).
- Fail closed, visibly: private affordances only in the verified state;
  every degradation names itself.
- All untrusted text via `textContent`; link kinds allowlisted
  (etchit/fetchit/image -> reader, x0x -> DM, website -> confirm, else
  inert). Hex addresses open in-app only.
- No new renderer I/O: the page calls `fediverse_lookup`,
  `chat_fetch_profile` (+ relay-hint param), `chat_fetch_avatar` only.
  `etchit_handoff` probes fixed targets (no user input near exec) and
  opens a fixed URI.
- Media discipline: avatar lazy + 512KB cap + magic sniff (shipped);
  gallery prefetches nothing.
- Address parse strictness: `@handle@domain` goes through the existing
  `parse_mention` (lowercase, charset) before any network.
- `htmlRewriter`, iframe sandbox, CSP: untouched.

## 9. Testing

Backend (`src-tauri`, wiremock + fixtures):
- `chat_fetch_profile` relay-hint threading: hinted relay queried;
  `None` falls back to configured relay (existing behaviour pinned).
- `etchit_handoff`: probe found -> launch attempted; probe missing ->
  typed not-installed result. No exec with user input.

Frontend (vitest/jsdom, same injected-handler style as the modal suite):
- Address-class parser: 64-hex, `autonomi://`, `@handle@domain`,
  `profile:<id>`, garbage.
- One render test per state in the section-6 table, including the
  changed-hands band and the Trinity card (both action paths).
- Actions matrix: Message/Invite verified-only; Edit-in-etch own-only;
  Share QR present whenever an agent id resolved.
- Gallery: zero fetches at render; click routes `autonomi://<addr>` to
  the reader handler; website/unknown kinds excluded from the grid.
- Share button on a profile tab yields the v3 contact-pointer QR.
- Bookmark round-trip on a `profile:` address (label = display name).
- Manifest-detection: triggers on profile-shaped JSON, not on ordinary
  JSON; banner action navigates to `profile:<agent_id>`.
- Tab semantics: handle entry and sidebar entry dedupe to one tab;
  back/history across reader -> profile -> reader.

Integration: lookup card -> page; DM modal "Open full profile" -> page.

## 10. File structure

New:
- `apps/fetchit-desktop/src/profile/page.ts` (+ `page.test.ts`):
  dispatch-shaped renderer (DTO + root + handlers in, DOM out).
- `apps/fetchit-desktop/src/profile/open.ts`: `openProfile` resolution
  glue (handle vs agent id vs hint).
- `apps/fetchit-desktop/src-tauri/src/etchit_handoff.rs`: probe +
  launch command.

Modified:
- `src/address.ts` (+ `address.test.ts`): extend the EXISTING parser
  with the `@handle@domain` and `profile:` address classes plus the
  canonical/display forms (one address parser in the app, not two).
- `src/controller.ts`: submit branch + openProfile wiring.
- `src/tabs.ts`: optional display string on a tab.
- `src/chat/profileCard.ts`: "Open full profile" button.
- `src/chat/panel.ts` + sidebar: contact click-through + "View my
  profile" entry; `src/settings.ts`: same entry.
- `src/fediverse/lookup.ts`: "View profile" action; `src/fediverse/`
  feed author chip.
- `src/renderers/json.ts`: manifest-detection banner.
- `src-tauri/src/profile.rs`: optional `relay` param.
- A `.profile-page` block in `src/styles.css` (tokens only).

Reused unchanged: `fediverse_lookup`, `chat_fetch_avatar`, the modal,
`parse_mention`, qrModal, confirmDialog, bookmarks, TabStore history.
