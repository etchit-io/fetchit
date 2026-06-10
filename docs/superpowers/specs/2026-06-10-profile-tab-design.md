# fetch>it Desktop Profile Tab (Design)

**Date:** 2026-06-10
**Branch:** chat
**Lane:** [A] Alice (desktop). Trinity seam: a contact's profile is their
etch>it-published, Autonomi-hosted page, fetched read-only in fetch>it.
**Status:** Design APPROVED by Josh 2026-06-10. Ready for spec review then writing-plans.

## 1. Goal & scope

Render a contact's Autonomi-published profile (v3 `ProfileManifest`) in a
read-only modal, opened from the conversation header. fetch>it reads the
profile; etch>it edits it. This is the consumption half of the profile-v3
feature whose data model already shipped (parse + verify, the v3 share
URI, the pair flow).

In scope:
- A backend command that resolves, fetches, verifies, and returns a
  contact's profile as a typed DTO.
- A backend command that fetches the (optional) avatar bytes, bounded
  and content-sniffed, lazily.
- A frontend modal that renders the profile read-only, routes the five
  link kinds, and handles the loading / empty / error / stale states.

Out of scope (not v1.0 of this feature):
- Editing a profile (etch>it owns publishing; read-only is on-charter).
- Persisting `profile_addr` onto the contact card (we re-resolve from the
  relay index each open; see section 4).
- Caching profile bodies across sessions (each open is a fresh fetch; the
  only persisted state is the per-contact freshness watermark).
- A profile surface for groups (DM contacts only).

## 2. Where it lives (locked)

A centered read-only modal over the chat panel, the same dialog pattern
as the existing share-card dialog (`src/chat/contactCard.ts`). It is
opened by clicking the contact's name or avatar in the conversation
header. Rejected alternatives (recorded): a right-pane Chat/Profile tab
(adds a pane state machine), and a full reader page (the chat panel is an
overlay, so it would force closing chat to view a profile).

## 3. Architecture

```
conversation header: click contact name/avatar
  -> controller mounts the profile modal in "loading"
  -> invoke chat_fetch_profile(agentId)
       [backend] resolve relay index  (pair::fetch_index_record)
                 -> ProfileIndexRecord (verified; carries profile_addr)
                 -> all-zeros addr  => ProfileOutcome::None (no profile yet)
       [backend] fetch manifest bytes off Autonomi at profile_addr
                 (AppState AutonomiClient)
       [backend] ProfileManifest::parse + verify(min = freshness watermark)
       [backend] cross-check agent ids
                 requested == index.agent_id == manifest.agent_id
                           == derive(ml_dsa_pubkey)
       [backend] persist new issued_at_ms watermark (monotonic)
       [backend] -> ProfileDto { displayName, bio, website, links[],
                                 avatar? {addr, mime, w, h, bytesLen},
                                 issuedAtMs }
  -> modal renders the card; if avatar present:
       invoke chat_fetch_avatar(addr, expectedMime, expectedBytesLen)
         [backend] fetch bytes; reject if > bytesLen or magic-bytes are
                   not the declared raster mime; -> base64 data URL
       -> <img> fills the bounded avatar box (placeholder until then)
  -> link routing on click (section 5)
```

The new code is thin: every load-bearing primitive already exists
(`ProfileManifest::parse`/`verify` in `profile.rs`, `pair::fetch_index_record`,
the `AutonomiClient` in `AppState`, `controller.onAutonomi` for reader
hand-off, `src/renderers/image.ts` for image display, `confirmDialog.ts`
for the external-link confirm).

## 4. Backend

New module `apps/fetchit-desktop/src-tauri/src/profile.rs`, registered in
`lib.rs`'s `invoke_handler`.

### 4.1 `chat_fetch_profile(agent_id) -> Result<ProfileOutcome, String>`

`ProfileOutcome` is `{ kind: "profile", ... } | { kind: "none" }` (serde
tag) so the frontend distinguishes "loaded" from "this contact has not
published a profile" (the all-zeros tombstone, or a relay 404) without an
error path.

Steps:
1. Build a `V3ShareUri` shell from the local user's configured relay URL
   plus `agent_id` (a thin `pair::fetch_index_record_by_id(relay, agent_id, http)`
   helper, so we do not need a full share URI). `fetch_index_record`
   already verifies the index record's ML-DSA signature and that the
   record's `agent_id` matches the request, and returns
   `PairError::Tombstoned` for the all-zeros address.
2. On `Tombstoned` or relay 404, return `ProfileOutcome::None`.
3. Fetch the manifest bytes off Autonomi at `record.profile_addr` via the
   `AppState` `AutonomiClient` (the same fetch path the reader uses),
   capped at 64 KiB (the manifest is small capped-field JSON, so a larger
   blob is a sign of a wrong or hostile address).
4. `ProfileManifest::parse(bytes)` (enforces field caps) then
   `verify(Some(watermark))` where `watermark` is the persisted last-seen
   `issued_at_ms` for this `agent_id` (or `None` on first view). `verify`
   re-derives `agent_id` from the embedded pubkey and ML-DSA-checks the
   manifest signature.
5. Cross-check `manifest.agent_id == agent_id` (the request) so neither
   the relay nor Autonomi can serve a different identity's profile under
   this contact. (The index record's pubkey already derived `agent_id`;
   this binds the separately-signed manifest to the same identity.)
6. Persist the new `issued_at_ms` as the watermark if it is `>=` the
   stored one (it must be, or `verify` already rejected it).
7. Return the `ProfileDto`. The avatar field carries only the avatar's
   metadata (`addr`, `mime`, `w`, `h`, `bytesLen`), never bytes.

Errors map to `String` for the frontend, distinguishing transport
("couldn't reach the network"), verify failure ("profile failed
verification"), and stale ("a stale copy of this profile was rejected")
so the modal can show an honest, specific line.

### 4.2 `chat_fetch_avatar(addr, expected_mime, expected_bytes_len) -> Result<String, String>`

Fetches the avatar bytes off Autonomi, then:
- rejects if `bytes.len() > expected_bytes_len` (the manifest's declared
  ceiling) or above a hard avatar cap,
- sniffs the leading magic bytes and rejects if they are not the declared
  raster image type (do not trust the manifest's `mime` string alone),
- returns a `data:<mime>;base64,<...>` URL the `<img>` renders directly.

Separate from `chat_fetch_profile` so the modal paints immediately and the
avatar fills in lazily, honoring the media discipline (no preload, fetch
on the explicit profile-open, bounded).

### 4.3 Freshness watermark store

A small JSON map `agent_id_hex -> last issued_at_ms`, persisted in the
chat data directory (`StoreLayout`). Read before `verify` (passed as the
`min`), written after a successful verify when newer. This is the
downgrade defense: an adversary re-serving an older validly-signed
manifest (to revert a `display_name` or `kem_pubkey`) is rejected. Plain
JSON at rest is fine: it is non-secret metadata (monotonic timestamps).

## 5. Frontend

New module `src/chat/profileCard.ts` plus `profileCard.test.ts`. A small
CSS block in `styles.css`. `conversation.ts` adds an `onViewProfile`
handler (the header subject becomes a button for DM conversations);
`controller.ts` wires it to the fetch + modal mount.

### 5.1 States
- **loading**: spinner while `chat_fetch_profile` is in flight.
- **none**: "This contact hasn't published a profile yet." (tombstone / 404)
- **error**: the specific honest line from the backend error.
- **stale**: "A stale copy of this profile was rejected." (downgrade defense)
- **loaded**: the card (section 5.2).

### 5.2 Layout (approved mockup)
Avatar box (bounded, <= 256px, placeholder until `chat_fetch_avatar`
resolves) + display name + bio + website row + a row of link chips. All
display text set via `textContent`, never `innerHTML` (the manifest is
untrusted content).

### 5.3 Link routing
- `etchit` / `fetchit` / `image` (64-hex Autonomi address): close the
  modal and open in the reader via the existing `onAutonomi` path.
- `x0x` (agent id): this is the contact themselves; render a "Message"
  chip that closes the modal (the user is already in / can open the DM).
- `website` (https URL): confirm-then-open. Click shows a confirm ("This
  opens an external website in your browser: <url>") and only on accept
  hands off to the system browser. This is the single path that leaves
  fetch>it's no-external-leak zone, so it gets the speed bump. The
  top-level `website` field renders the same way.

## 6. Error handling & security

- Two independent ML-DSA verifications (index record and manifest), with
  the agent-id chain cross-checked end to end
  (`requested == index.agent_id == manifest.agent_id == derive(pubkey)`).
- Monotonic `issued_at_ms` watermark blocks stale-manifest downgrade.
- Manifest field caps enforced by `parse` before any rendering work.
- Avatar: declared `bytes_len` and a hard cap bound the fetch; magic-byte
  sniff over the declared raster mime; rendered through the existing image
  renderer; never `innerHTML`.
- All hex-address links open in-app (the reader); only `website` leaves
  the app, and only behind the confirm.
- Untrusted display fields go in via `textContent`.

## 7. Testing

Backend (fixture-driven, reusing the existing
`tests/fixtures/profile-manifest-v1/{maximal,minimal,tampered-maximal}`):
- happy path: valid manifest parses, verifies, returns the DTO.
- tampered manifest: verify rejects.
- agent-id mismatch (manifest for a different identity): rejected.
- tombstone / relay 404: `ProfileOutcome::None`.
- stale `issued_at_ms` below the watermark: rejected.
- avatar fetch: oversize rejected, non-raster magic bytes rejected,
  valid webp returns a data URL.
Command-level tests use a wiremock relay for the index and a stubbed
Autonomi fetch for the manifest.

Frontend (`profileCard.test.ts`, jsdom):
- renders a loaded DTO (name, bio, website, link chips).
- each link kind routes to the correct handler.
- `website` click fires the confirm before any open.
- all four non-loaded states render.
- avatar is fetched lazily after mount and fills the box.

## 8. File structure

New:
- `apps/fetchit-desktop/src-tauri/src/profile.rs` (commands + DTO +
  watermark store), registered in `lib.rs`.
- `apps/fetchit-desktop/src/chat/profileCard.ts` + `profileCard.test.ts`.
- A `.chat-profile` CSS block in `src/chat/styles.css`.

Modified:
- `crates/fetchit-chat/src/pair.rs`: add `fetch_index_record_by_id`
  (resolve by relay + agent_id without a full share URI).
- `apps/fetchit-desktop/src/chat/conversation.ts`: header click ->
  `onViewProfile`.
- `apps/fetchit-desktop/src/chat/controller.ts`: wire `onViewProfile` to
  the fetch + modal.

Reused (not rewritten): `profile.rs` parse/verify, `pair.rs`
fetch/verify, `AutonomiClient`, `controller.onAutonomi`,
`src/renderers/image.ts`, `confirmDialog.ts`.

## 9. Decisions log
- Placement: modal over chat panel (vs pane tab, vs reader page). LOCKED.
- External `website` link: confirm-then-open in system browser (vs
  copy-only, vs open-no-confirm). LOCKED.
- `profile_addr`: re-resolve from the relay index each open (vs persist on
  the contact card). Re-resolve is freshness-correct and avoids a card
  schema migration.
- Avatar: fetched lazily on profile-open via a separate command, bounded
  and magic-sniffed (vs bundled into the profile fetch, vs fetched on
  contact-list render).
- Downgrade defense: persist a per-contact `issued_at_ms` watermark.
