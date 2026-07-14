# M7 — Fedi Social: follow, feed, fedi-DM, escalate-to-PQ (v1 gate)

**Decision (Josh, 2026-07-12):** the fediverse is fetch>it's *contact surface*,
not a broadcast target. Users must be able to search, follow, read a home
feed, post publicly, and DM people over ordinary ActivityPub rails — then
escalate any of those contacts into PQ chat when they want privacy.
"Come for the network, stay for the privacy."

Status: IN PROGRESS (2026-07-13, PR #29 josh-clsn/fetchit).
- **P1 Follow — DONE, proven on-device** (bridge-auth-v1 + follow routes +
  `follow_fedi` + FFI + Android). Includes the plain-Mastodon delivery fix:
  both `follow_fedi` and `publish_public_post` now decode the target with
  the lenient `fetch_remote_actor` (inbox-only, no PQ-attestation demand)
  instead of the strict fetchit actor parser.
- **Registration self-heal — DONE, bridge-proven** (2026-07-13). Root cause
  of the on-device follow/DM failures: pre-cutover (00796c4) vault
  attestations are raw-signed and can never verify under the agent-sign
  framing → bridge 403 → never in directory. `heal_actor_attestations`
  re-signs stale/rotated attestations at every ensure pass. Deployed bridge
  confirmed post-cutover empirically (framed probe → `201 registered`,
  actor-doc + WebFinger 200). On-device heal of @josh pending Josh's retry.
- **P3 outbound fedi-DM — DONE, gated, device-test pending** (`build_direct_note`
  + `Client::send_fedi_dm` + FFI `fedi_dm` + Android "fedi message" button
  with not-encrypted banner). Compose dialog keeps the draft on failure;
  follows persist to `FediFollowStore` for a durable "following" state.
- **@josh LIVE + follow proven e2e** (2026-07-13): heal → register 201 →
  `GET /actors/josh` 200 → Follow of `@happyborg@fosstodon.org` delivered
  + recorded (Josh saw the pending-accept snackbar). The reserved-handle
  gate needed a one-time release of `josh` from the droplet env extras
  (owner-claims mechanism = follow-up hardening item).
- **Social surface — BUILT, device-test pending** (2026-07-13, Josh's
  "UI a user would expect from a social app" directive): engine
  `list_fedi_following`/`unfollow_fedi` (bridge routes already existed) +
  `fetch_fedi_feed` (client-side outbox pull, SSRF-guarded, HTML→text via
  `fetchit_fedi::text::html_to_text`); FFI `fedi_following`/`fedi_unfollow`/
  `fedi_feed`; Android "your fediverse" sheet (tap your @name in the feed
  header): following list with message/unfollow/block per row, followers
  (honest empty state until inbound-Accept processing lands), blocked list
  with unblock; pulled remote posts merged into the feed (de-duped,
  block-filtered); blocked accounts gated on the lookup card.
- **Inbound loop — LIVE IN PROD** (2026-07-13): the reply half, deployed +
  edge-verified. `POST /actors/:handle/inbox` verifies the sender's HTTP
  signature (RFC 9421 + cavage, digest + date-skew) against their fetched
  RSA key, then Create(Note) → plain-text store (deduped by note id),
  Accept(Follow) → `follow_accepted`. Owner-only `GET
  /actors/:handle/messages` (bridge-auth-v1, since_ms cursor). Client:
  `fetch_fedi_inbox` + FFI `fedi_inbox`; the Android fedi thread pulls on
  open. Shared helpers lifted to fetchit-fedi (`parse_imf_fixdate`,
  `parse_rsa_public_key_pem`). **Bridge redeployed to the Trust droplet
  (Josh-run scp+restart); edge proven: public `POST /actors/josh/inbox`
  with `{}` → 400 "activity has no actor", with a real actor field →
  fetches sender key → 401 on unsigned (full verify path live). A signed
  delivery stores + serves. On-device reply-render pending Josh's test.**
- **Thread durability — DONE** (2026-07-14, on-device loss postmortem):
  fedi DMs previously lived only in the shell's in-memory conversation
  store while a durable shell-side cursor advanced past every pulled
  reply — any process death silently wiped sent messages and made
  pulled replies unrecoverable. Now the ENGINE owns durability:
  `fedi_thread.rs` keeps one sealed store per minted handle
  (`fedi/threads/<handle>.json.enc`, identity-vault seal shape) holding
  every fedi DM both directions plus the inbox cursor; messages and
  cursor persist in ONE atomic write. `send_fedi_dm` records the
  outbound message; `sync_fedi_inbox` lands every sender's messages
  (never skips a thread the user doesn't have open) then advances the
  cursor; `conversation_history` serves `f:<handle>` keys. The shell's
  SharedPreferences cursor + sender filtering are deleted. Fresh
  cursor starts at 0, so the first sync after upgrade re-pulls
  everything the bridge still holds (bridge rows are re-servable —
  recovery is server-backed).
- **P2 push feed** — Alice's delivery seam, not started (the pull feed +
  pull inbox above are the interim read paths; push replaces the polling).
- **P4 escalate-to-PQ** — not started (verified-user path ~90% via lookup
  `share_uri`; public-only path = invite-via-fedi-DM pointer + consent).

## Topology recap (built, M4/M5)

```
Mastodon et al ⇄ fetchit-bridge-server (Trust droplet, Caddy, SQLite)
                     • WebFinger + actor docs (inbox/outbox URLs point here)
                     • POST /actors registration (ML-DSA attestation gate)
                     • followers/outbox collections (stub/empty)
                 ⇄ fetchit-relay-server /inbox (feature fediverse-inbox)
                     • 5 gates: body cap → denylist → HTTP-sig verify
                       (WebFinger-resolved pubkey) → replay window → date skew
                     • PendingDeliverySink → PublicPost drain → clients
Clients (Android/desktop) ⇄ relay (chat) + bridge (registration; NEW: social API)
```

Inbound activities addressed to `https://<bridge>/actors/<handle>/inbox`
terminate at the bridge domain. v1 keeps ONE inbound door: the bridge
gains its own inbox route reusing the same gate stack (extracted from
`fetchit-relay-server/src/inbox/` into `fetchit-fedi` so both binaries
share it — Alice flagged extraction shape TBD).

## P1 — Follow (Bob)

New bridge tables (SQLite, additive):
```sql
CREATE TABLE following (
  handle TEXT NOT NULL,            -- our local actor
  target_actor_url TEXT NOT NULL,  -- remote actor id
  state TEXT NOT NULL,             -- 'pending' | 'accepted'
  follow_activity_id TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (handle, target_actor_url)
);
-- followers table exists; gains state + activity id columns.
```

**Key-custody invariant (drives everything below):** the bridge holds NO
private keys — today's entire outbound path (`FediverseTransport::deliver`)
signs with the CLIENT-held RSA key, and M7 keeps that. The bridge only
verifies (public keys), stores, and serves. Consequence: every outbound
activity (`Follow`, `Accept`, `Undo`) is signed and delivered FROM THE
DEVICE via the existing transport; the bridge records state through
authenticated endpoints. An inbound follow therefore stays "requested"
on the Mastodon side until our device next comes online and signs the
`Accept` — the standard follow-request UX, and the honest one.

Flows:
1. **Outbound follow** — client: parse_mention → WebFinger resolve →
   denylist gate → build_follow → sign+deliver via FediverseTransport
   (all existing machinery) → `POST /actors/:handle/following` records
   `pending` at the bridge (agent-key auth, same attestation machinery
   as registration).
2. **Inbound Accept/Reject** — bridge inbox verifies HTTP sig + gates,
   matches `object.id` == a stored follow_activity_id, flips
   state/deletes row (pure state transition, no signing).
3. **Inbound Follow** (someone follows us) — verify + gates → denylist →
   store as a pending inbound follow. Client drains pending follows on
   next connect (poll, same auth), signs `Accept` on-device, delivers,
   then confirms → bridge inserts the follower row. v1 auto-accepts at
   the CLIENT (open follows); manual approval is a UI toggle later.
4. **Unfollow / follower removal** — client signs+delivers `Undo(Follow)`
   then `DELETE .../following/:target` at the bridge; verified inbound
   `Undo(Follow)` removes the follower row directly.
5. Collections `followers`/`following` serve real counts + pages.

## P2 — Home feed (Alice counters)

Remote servers deliver `Create(Note)` from followed actors to our actors'
bridge inboxes (that's how AP push works once Follow/Accept lands).
Bridge stores into a per-handle `feed` table (id, actor_url, object JSON
subset, published_at; capped ring per handle, default 1000).

**Delivery to clients — Bob's proposal, Alice decides:** clients poll
`GET /actors/:handle/feed?since=<cursor>` over HTTPS with the same
agent-key auth. Rationale: CGNAT phones already poll the relay; the feed
is not latency-sensitive; avoids coupling the relay envelope schema to
AP object shapes. Alternative (Alice's 5.3 drain): wrap feed items as
relay envelopes. Pick ONE in the counter.

Backfill on first follow (remote outbox fetch, capped) is post-v1 —
the feed starts from follow time.

## P3 — Fedi-rails DM (Alice counters)

`Create(Note)` with visibility=direct (`to:[actor]`, no `cc`), both
directions, via the same bridge inbox/outbox machinery as P2 — a DM is
a feed item with `direct=true` addressed storage.
HARD UX RULE: rendered in a visually distinct thread with a persistent
"not end-to-end encrypted — server admins can read this" banner; never
interleaved with PQ messages.

## P4 — Escalate to PQ (Bob)

The product moment. On any fedi contact (feed author, DM thread, lookup
result):
- **They're a fetch>it user** (lookup kind == Verified): "Private chat"
  button → existing v3 share-URI/pair flow → PQ conversation. Already
  90% built (lookup returns share_uri today).
- **They're not** (PublicOnly): "Invite to private chat" → user-consented
  fedi DM containing my handle link + `x0x://pair/<agent_id>?r=<relay>`
  pointer (machine_id-carrying, landed 16ca8bd). Consent dialog states
  the pointer publicly links this fedi identity to a fetch>it identity
  (Decision 4: agent_id disclosure is explicit, never automatic).
- Receiving side: fedi DM containing an `x0x://pair/` URI renders an
  "Upgrade to private chat" affordance (URI already deep-links on
  Android; add in-thread parse).

## Invariants (unchanged)
- Decision 4: LIT agent_id ⟂ AP handle; disclosure only via explicit user
  action (the P4 consent dialog).
- Every inbound bridge surface runs: body cap → denylist → HTTP-sig verify
  → replay → date skew, plus SSRF guards on all outbound fetches.
- Fedi DMs visibly unencrypted; PQ chat unchanged.
- Wallet stays in etch/it. Bridge stays isolated from RAM-only chat relays.

## Work split (strawman v2 — Alice counters)
- Bob: bridge-crate landing on main (extraction from m4-publish-half,
  in progress), P1 end-to-end (bridge + client + Android UI), P4 flows,
  inbox-gate extraction into fetchit-fedi.
- Alice: P2 feed pipeline + delivery-seam decision, P3 fedi-DM engine +
  labeling UX, cross-review of every bridge inbound surface.
- Joint: EnvelopeKind/EntryKind first-touch coordination if the relay
  drain is chosen for P2.

## Test plan (device-verifiable, in order)
1. Follow a real Mastodon account from the phone → Accept arrives →
   following collection shows it. [P1 testable moment]
2. That account posts → item appears in phone feed. [P2]
3. DM that account from the phone; reply arrives, banner correct. [P3]
4. "Invite to private chat" on the DM thread → Mastodon side sees the
   pointer link; second fetch>it phone does the same dance and lands in
   a PQ conversation. [P4 — the demo]
