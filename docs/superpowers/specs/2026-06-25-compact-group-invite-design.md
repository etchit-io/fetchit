# Compact Group Invite (pointer + sealed blob) — Design

**Status:** Approved approach (Josh, 2026-06-25: "leave David out, do it"),
design for cross-review before build. Verified against code, not memory.

## Problem

A group invite is x0xd's `x0x://invite/<base64>` link, and x0xd inlines
the entire group bootstrap into it: every member's ML-KEM public key
(~1 KB base64 each) plus TreeKEM state. So the link grows ~linearly with
membership — measured live: ~3.8 KB at 1 member, ~25 KB at 2. A 20-person
group would be a multi-hundred-KB paste that cannot be shared by message
or QR. The invite format is upstream (x0xd `/groups/{id}/invite`), so we
cannot shrink it directly.

## Approach: wrap, exactly like the pair card

We already solved the same problem for the ~12 KB v2 pair card: replace
the inline blob with a tiny pointer URI and fetch the blob from a relay
(`pair_uri.rs` + `pair.rs` + `/v1/pair-record/:id`). Do the same for
group invites, leaving x0xd untouched:

1. **Mint.** Call the existing `groups().invite(group)` to get x0xd's big
   `invite_link`. Generate a fresh random 32-byte key `K` and 12-byte
   nonce. Seal the link: `ct = ChaCha20Poly1305(K, nonce, invite_link)`
   (reusing `chat_crypto::aead_seal`, the same AEAD as the at-rest vault).
   Generate a random opaque `token`. POST `{token, nonce, ct}` to the
   relay.
2. **Pointer.** Return a small URI:
   `x0x://ginvite/<token>?r=<relay>[&r=<relay>]#k=<K_base64url>`.
   token + relay hint(s) + the decryption key. ~120 chars, QR-able.
3. **Join.** Parse the pointer, fetch `{nonce, ct}` from a relay by
   `token`, `aead_open(K, nonce, ct)` to recover the original
   `invite_link`, then feed it to the existing `groups().join(...)` /
   `join_group_auto`. x0xd sees exactly what it sees today.

## The blind-relay invariant (non-negotiable)

The blob is **encrypted before it leaves the device**; `K` lives only in
the pointer and is never sent to the relay. The relay stores opaque
ciphertext keyed by an unguessable token. It therefore learns:

- that *some* authenticated agent published *a* blob, and its size
  (≈ group size — a coarse metadata leak; padding deferred as a v1.x
  option, noted not silently dropped);
- the token and the fetcher's IP.

It does **not** learn the group id, membership, member keys, or invite
contents. This preserves the blind-relay posture
([[feedback-decentralized-values]], [[feedback-autonomi-first-storage]]).

`K` goes in the URI **fragment** (`#k=`), not the query: defense-in-depth
so the secret is conventionally client-only and less likely to be logged
by any intermediary. The joiner extracts `token` to fetch and `K` to
decrypt locally; neither the fragment nor `K` is ever transmitted.

## Why the relay, not Autonomi

Invites are ephemeral and single-use, so transient relay storage with a
short TTL is the right shape. Autonomi is permanent and needs a wallet
(fetch>it is read-only) — wrong fit for a throwaway invite. This matches
"transient relay for ephemeral data; Autonomi for canonical durable data."

## Relay endpoint (mirrors `/v1/pair-record`)

- `POST /v1/group-invite` — body `{ token, nonce_b64, ct_b64 }`.
  **Auth required** (the minting agent's bearer), same as pair-record
  POST, so the blob store is not an open write surface. Body capped at
  `max_envelope_bytes`. Stored with a TTL (default 7 days; never longer
  than the invite's own `expires_at`).
- `GET /v1/group-invite/:token` — returns `{ nonce_b64, ct_b64 }`.
  **Unauthenticated but token-gated**: a joiner is not yet a member and
  may not be authenticated; the unguessable token is the capability. Not
  deleted on first read (the joiner may retry), aged out by TTL.

Storage reuses the in-memory, TTL-indexed record pattern of the pair
store. Going live needs a relay deploy (flagged: this is new server
surface, not a config flip).

## Engine API (fetch>it layer)

New module `group_invite_uri.rs` (mirrors `pair_uri.rs`):
- `emit_ginvite_uri(token, relays, key) -> Result<String>`
- `parse_ginvite_uri(&str) -> Result<ParsedGinviteUri { token, relays, key }>`

In `groups/mod.rs` (or a thin `group_invite.rs`):
- `compact_invite(&self, group) -> Result<String>`: invite → seal →
  POST → emit pointer.
- `resolve_compact_invite(&self, pointer) -> Result<GroupInvite>`: parse →
  GET → open → wrap as the existing `GroupInvite`.

## Backward compatibility

The join entry point accepts **both** schemes: a `x0x://ginvite/...`
pointer resolves to the big link first; a legacy `x0x://invite/...` link
is used as-is. The desktop `bubble.ts` link regex and the Android link
parser gain the `ginvite` scheme alongside `invite`. Old invites keep
working; nothing is a flag-day.

## Scope / split

- **Alice (engine + relay):** `group_invite_uri.rs`; the seal/publish and
  fetch/open engine functions; the relay `group-invite` store + two
  routes; tests at every layer.
- **Bob (Android):** mint shows the short pointer; join accepts the
  pointer scheme; link parser update.
- **Desktop (Alice):** `newGroup.ts` and the member-list "Invite someone"
  action emit the pointer; join/paste accepts it; `bubble.ts` regex.
- Security-sensitive (new crypto + new relay surface) → **mutual
  cross-review mandatory** ([[feedback-cross-review-after-sensitive-work]]).

## Test plan (TDD)

1. URI emit/parse round-trips; rejects bad token/relay/key; fragment key
   never appears in query.
2. Seal→open round-trips the exact invite_link; wrong `K` fails to open;
   truncated ct fails.
3. Relay store: POST then GET returns the same bytes; GET unknown token →
   404; TTL expiry drops it; POST without auth → 401; oversize → 413.
4. End-to-end: `compact_invite` output parses, fetches, opens, and the
   recovered link drives a successful join (mock relay + mock x0xd).
5. Legacy `x0x://invite/...` still joins unchanged (regression guard).
6. Relay-blindness assertion: the stored blob and token reveal no group
   id / member bytes (the ct is opaque; only size is observable).

## Open decisions (for Josh / Bob cross-review)

- TTL default (7 days vs the invite's own `expires_at`, whichever is
  sooner)? Proposed: min(7 days, expires_at).
- Pad the ciphertext to a fixed bucket to blunt the size→group-size leak,
  or accept the coarse leak for v1? Proposed: accept for v1, note it.
- Token length (16 vs 32 bytes random)? Proposed: 32 bytes base64url.
