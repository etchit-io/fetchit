# M5: Discovery - handle lookup, follow, and DM bootstrap over the fediverse layer

**Status:** approved direction, spec under review
**Decided:** 2026-06-12
**Companions:** `2026-06-07-m4-fediverse-brainstorm.md` (bridge architecture), `private/MILESTONES.md` (gate text), `private/lit-launch-roadmap.md` (live sequencing)

## Summary

Make fediverse handles the human-friendly front door to LIT Chat. A user finds
`@name@etchit.io`, sees a verified actor card, and starts an end-to-end
encrypted DM or group invite from it. The multi-kilobyte share URI stops being
the primary onboarding path and becomes the fallback for users who never mint
a public handle.

Four components:

| Component | What it is | Lane |
| --- | --- | --- |
| D. Discoverable actor record | Actor record gains the v3 share-URI fields (profile address + relay hint) inside the signed attestation; self-serve registration and update endpoints | B (bridge), A (client wiring) |
| A. Lookup + bootstrap | Handle search box, actor card with two outcomes, "Message privately" / "Invite to group" running the existing TOFU and invite flows | A (desktop) |
| B. Follow, both directions | Inbound (Mastodon follows us): already M4 gate scope. Outbound (we follow remote actors, their posts in our feed): new in M5, amends the M4 scope guard | B (bridge + relay), A (feed UI) |
| C. Directory search | Substring search over the etchit.io registry (handles + display names), rate-limited, paginated | B (bridge), A (UI) |

## Motivation

Contact establishment today requires moving a ~12 KB share URI (or QR, which
only works in person). The v3 profile work already shrank the payload to a
pointer (agent id + Autonomi profile address + relay hint), and the M4 mint
flow already publishes an ML-DSA-65 attestation binding handle, actor URL,
agent id, and the actor RSA key. M5 closes the loop: the handle becomes a
memorable alias for the v3 share URI, and the public fediverse graph becomes
the discovery and introduction layer for the private chat graph.

## Decisions (2026-06-12, Josh)

1. **Privacy model: one opt-in.** Minting a handle means you are publicly
   findable AND contactable by it. The mint consent copy states plainly:
   anyone who knows your handle can find you and send a contact request.
   Inbound strangers land in the existing TOFU pending-request queue.
2. **Follow ships both directions.** Full AP citizenship in v1.0. This
   amends the M4 scope guard (see "Relationship to M4").
3. **Inside the v1.0 gate.** v1.0 = M0 + M1 + M2 + M3 + M4 + M5. No partial
   launches; M5 closes before launch.

## Relationship to M4 (do not re-spec in-flight work)

The fediverse bridge SERVER is **`fetchit-relay-server` built with
`--features fediverse-inbox`** (there is no separate `fetchit-bridge-server`
crate; that name was a drafting error). The `fediverse-inbox` Cargo feature
IS the wyse37 isolation: the default relay build ships zero fediverse code or
deps, and a community-relay operator opts into the bridge role with the
feature, so the unauth internet-facing surface never shares a process with the
load-bearing chat relays. All M5 server endpoints land in that feature-gated
router, alongside the existing `POST /inbox`.

Already SHIPPED on `chat` (the inbound half):

- `POST /inbox` with the 5 pre-flight gates (body cap, per-instance rate limit,
  HTTP-Signature verify, replay window, denylist) and a WebFinger CLIENT for
  resolving inbound actor pubkeys.

Bob's approved foundation plan, NOT yet merged (the serving half M5 needs):

- WebFinger server for etchit.io (`/.well-known/webfinger`)
- AP actor doc + collections hosting (followers / following / outbox)
- Inbound Follow / Accept / Undo handling + outbox fan-out to follower
  inboxes with retry-backoff (Tier 3 organic)
- Moderation tooling (instance blocklist, report queue, suspend-actor)

M5.1's D-lane builds that serving half (plus the registry endpoints below) in
`fetchit-relay-server` under `fediverse-inbox`.

M5 adds on top, and amends one standing decision:

- **Scope-guard amendment (Josh, 2026-06-12):** the M4 guard read
  "Open-Mastodon INGEST (their posts in our feed) is post-v1.0." Follow
  outbound moves that INTO the gate: posts from actors a user explicitly
  follows are ingested, verified, and routed to that user's feed. General
  unsolicited ingest stays out; ingest is strictly follow-scoped.
- M4's "decoupled chat-identity / AP-handle, opt-in default-off" axis is
  preserved: the mint IS the single opt-in, and the attestation already
  publishes the agent id binding at mint time. M5 changes no default; it
  adds the consent copy and the affordances that use the binding.

## Component D: discoverable actor record

**Attestation v2.** Extend the ML-DSA-65 attestation signing input from
(handle, actor_url, agent_id, rsa_spki) to also cover:

- `profile_addr` - the Autonomi address of the user's profile manifest
  (which carries the ML-KEM-768 public key)
- `relay_hint` + `hint_epoch_ms` - same semantics as card v2 rendezvous
  hints; the existing epoch-monotonicity rules apply to record updates

Add an explicit `attestation_version: 2` field. v1 records (internal-only
population, M1 status) are re-minted transparently on first M5-capable client
run; the bridge rejects v1 registrations once M5 ships.

**Self-serve registry endpoints** on `fetchit-relay-server` (the
`fediverse-inbox` feature):

- `POST /v1/actors` - register: client submits the signed attestation v2.
  Bridge verifies the ML-DSA signature against the embedded agent id,
  enforces handle validation (same `[A-Za-z0-9_-]`, max 64 rules as the
  client), first-come-first-served on the handle, rate-limited per source.
- `PUT /v1/actors/<handle>` - update (new relay hint epoch, new profile
  addr, RSA key rotation): same verification, plus hint-epoch monotonicity
  and same-agent-id continuity (a handle never silently changes agent).
- The directory serves the attestation inside the WebFinger record and the
  actor document, so any client can verify the full chain offline.

The operator-assisted `mint-actor` CLI path remains for ops/recovery but is
no longer the registration path.

## Component A: lookup + bootstrap

**One search box, two outcomes.** Entry points: the fediverse pane header,
and the chat "Add contact" dialog, which accepts `@handle@domain` alongside
the share URI paste.

- **Verified fetch>it actor** (attestation v2 verifies end-to-end): full
  actor card with avatar, display name, handle, agent id (technical detail,
  shown the way profile cards show it), and the private affordances:
  "Message privately" and "Invite to group". Both resolve to the agent id
  and run the EXISTING flows: TOFU contact request through the relay, and
  the standard group invite path. No new crypto, no new envelope kinds for
  the DM path.
- **Any other fediverse actor** (no attestation, or verification fails):
  public-only card: follow and mention. No private affordances render, ever.
  A failed attestation on an etchit.io handle renders the public-only card
  plus a visible "could not verify" state; it never half-renders trust.

**Resolution chain** (every hop verifiable, the directory is untrusted):

```
handle -> WebFinger -> actor record -> verify attestation v2 (ML-DSA, binds
handle/actor_url/agent_id/rsa_spki/profile_addr/relay_hint) -> fetch profile
manifest from Autonomi -> verify manifest keys against the same agent id ->
TOFU contact request via relay_hint
```

All remote fetches go through the existing `fetchit-fedi` SSRF gates.
Lookup of non-etchit.io handles uses plain WebFinger + actor GET (already
implemented: `parse_mention`, `resolve_handle`, actor fetch with class
allowlist).

## Component B: follow, both directions

**Inbound (M4 dependency, not M5 scope):** remote users follow our actors;
the bridge stores follower lists and fans our posts out with retry-backoff.
M5 takes a dependency on this landing per Bob's plan and adds nothing to it.

**Outbound (new):**

- Desktop sends Follow (and Undo) activities from the user's actor via the
  bridge; the followed actor's Accept updates a per-user following list
  stored bridge-side next to the follower lists.
- Posts arriving at our actor inboxes from followed actors are verified
  (HTTP Signature against the WebFinger-resolved key, existing inbox
  verification path), checked against the denylist (actor URL arm), then
  routed to the following user as a DIRECTED relay delivery: a new
  routing of the existing `PublicPost` payload addressed to one agent,
  distinct from the broadcast fan-out. The RIDER-1 invariant (no deliveries
  TO the bridge sentinel) is preserved; the bridge sentinel remains a
  source marker only.
- Feed UI grows a "Following" filter; followed-actor posts carry the same
  from-fediverse badge and reply-publicly-only affordance.

## Component C: directory search

`GET /v1/actors/search?q=<term>` on the bridge: case-insensitive substring
match over handle and display name of registered etchit.io actors only.
Paginated, 20 results per page, hard cap of 5 pages per query, per-source
rate limit. Directory enumeration is
accepted openly; it is the definition of the one-opt-in model and the mint
copy says so. Desktop renders results as actor-card rows reusing the
Component A card.

## Trust model and security requirements

- The registry/bridge is untrusted for integrity: it cannot forge a
  handle-to-agent binding without the agent's ML-DSA key. It CAN deny
  service or serve stale records; relay-hint epochs bound staleness, and
  the share-URI path remains as the registry-independent fallback.
- Handle continuity: the bridge enforces same-agent-id on update. A handle
  re-registration after deletion is a NEW binding; clients that previously
  contacted the old agent id keep their existing contact (keyed by agent
  id, not handle) and the actor card surfaces "handle changed hands" when
  a known handle resolves to a different agent id.
- Attestation verification is mandatory before any private affordance
  renders. Fail closed to the public-only card.
- Spam: inbound contact requests stay behind the TOFU pending queue;
  registration, update, search, and contact-request paths are rate-limited
  at the bridge/relay. Denylist gates lookup results, follow targets,
  inbound followed posts, and search results (agent-id arm and actor-URL
  arm).
- The PQ asymmetry line from M4 stands and extends to follow-outbound:
  inbound remote posts are RSA-verifiable only. Launch copy never claims
  PQ or E2EE properties for any bridge surface.

## Storage and privacy statement (supersedes the 2026-06-12 audit answer)

Server-side fediverse data we now commit to storing, all public-by-nature:

1. The handle directory: attestation v2 records (handle, actor URL, agent
   id, RSA pubkey, profile addr, relay hint).
2. Follower and following lists for our actors (M4 + M5).
3. The outbound delivery queue (transient, retry-bounded).

Still never stored server-side: post content beyond the delivery queue,
DMs (cannot cross the bridge by construction: `FediverseTransport::deliver`
takes `&PublicPost`), feed history, remote actors' posts beyond follow-scoped
routing. Desktop feed remains RAM-only. `docs/SECURITY.md` gains this
inventory verbatim.

## Non-goals

- Fuzzy or global fediverse-wide user search (no crawling, no indexing of
  remote instances; search covers our registry only).
- Unsolicited open-Mastodon ingest (ingest is strictly follow-scoped).
- Custom domains / vanity registries (post-v1.0; natural premium surface
  per the revenue model, not designed here).
- Android surfaces (post-v1.0 catch-up per the standing M4 decision).
- Public-post history pull (feed remains live + followed; unchanged).

## Sequencing

Three implementation plans, in order, each through the normal
spec -> plan -> implement -> cross-review cycle:

1. **M5.1 = D + A** (the strategic piece): attestation v2 + registry
   endpoints + lookup/bootstrap UX. Lanes: B owns bridge endpoints, A owns
   client + desktop.
2. **M5.2 = B-outbound**: Follow/Undo emission, following lists, ingest
   verification + directed routing, feed filter. Depends on M4 inbound
   landing first.
3. **M5.3 = C**: search endpoint + UI. Small once M5.1's card and bridge
   exist.

MILESTONES.md gains the M5 gate text; the v1.0 definition line changes to
M0 + M1 + M2 + M3 + M4 + M5. The lit-launch-roadmap Phase 1 gains 1E (M5)
with the scope-guard amendment noted inline.

## Proposed M5 gate text (for MILESTONES.md)

> **Gate:** Handle lookup resolves and verifies attestation v2 end-to-end;
> "Message privately" from an actor card establishes a TOFU contact through
> the existing relay flow; add-contact accepts handles; follow works both
> directions with follow-scoped ingest only; directory search live on the
> bridge; SECURITY.md storage inventory updated; mint consent copy carries
> the one-opt-in language; all bridge surfaces cross-reviewed.
