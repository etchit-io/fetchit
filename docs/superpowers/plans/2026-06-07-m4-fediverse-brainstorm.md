# M4 — Fediverse Bridge Brainstorm

**Status:** brainstorm spec, not an implementation plan. Surfaces the design questions M4 has to answer before any code lands. Cross-review by Alice.

**Goal:** Make fetch>it chat addressable from (and able to address) the wider fediverse — Mastodon, Lemmy, Misskey, Pleroma, GoToSocial, et al. Once a fetch>it agent has a fediverse-resolvable handle, a Mastodon user can mention them, a Lemmy thread can link to a fetch>it conversation, and a fetch>it user can subscribe to a public fediverse actor's posts inside their existing chat UI. The fediverse becomes the *public* skin around fetch>it's private encrypted core.

**Non-goals (M4):**
- Replacing fetch>it's PQ-encrypted DM/group path. Fediverse traffic is observably public and signed-but-not-encrypted; private chat stays inside the relay federation.
- Two-way encrypted DM bridging. Mastodon DMs (encryption-less, not E2E) MUST NOT be cross-routed to the fetchit private-chat surface — UI must show them as a distinct channel.
- Acting as a Mastodon instance. fetch>it is a *client* + *bridge*, not an ActivityPub server in its own right (for M4 — revisit in M5 if we want first-class instance behaviour).

---

## Where M3 left us

The denylist + multi-home federation core is what makes M4 viable: a peer can reach multiple independent relays AND apply community moderation symmetrically across both inbound and outbound. M4 inherits these primitives — anything that flows across the bridge inherits the same denylist semantic. Two surfaces from M3 to keep in mind:

| M3 surface | What it does | M4 implication |
|---|---|---|
| `fetchit-relay-client::RelaySet` | Multi-home WS sessions, fan-out send, merged inbox | Pure transport abstraction over WebSocket relays. Not a bottleneck for ActivityPub HTTPS POSTs (which are NOT WS) but also not reusable for them. M4 needs a sibling transport, not a RelaySet variant. |
| `fetchit-chat::DenylistCheck` (trait) | Pluggable check on lowercase 64-hex agent IDs | Trait shape is already agent-id-keyed `&str`. WebFinger handles (`@user@instance`) are NOT 64-hex agent IDs — see "Identity bridge" below. Either the trait grows a sibling method or M4 introduces a parallel `FediverseDenylistCheck`. |

Neither is a blocker. Both are answered by additive design. Calling these out so we don't accidentally bake transport or identity assumptions into M3 that constrain M4.

---

## The three open design questions

### Q1 — Transport: ActivityPub HTTPS POSTs?

ActivityPub is the de-facto fediverse protocol. Mastodon/Lemmy/Misskey/Pleroma all speak some dialect of it. Wire shape is HTTP `POST` of a JSON-LD `Activity` object to an actor's `inbox` URL, signed with HTTP Signatures (RFC 9421). Reading another actor's posts is an HTTP `GET` of their `outbox` with content negotiation for `application/activity+json`.

**Why ActivityPub:**
- Already deployed everywhere we want to reach. Mastodon alone covers ~7M MAUs in 2026.
- No vendor lock — it's a W3C Rec, not a single-vendor protocol.
- Lemmy's group-actor pattern maps cleanly onto fetch>it's group concept.
- Existing Rust crates: `apub` and `fediverse-features` are the two healthiest at the time of writing; both consume `activitystreams`-shaped JSON. Worth confirming upstream activity per [[read-upstream-source-first]] before committing.

**Why NOT just extend the relay protocol:**
- Mastodon servers do not speak our WS protocol. Asking them to is a non-starter.
- HTTPS POST is the universal denominator; even servers that gateway to other protocols (Matrix bridges, IRC bridges, XMPP bridges) speak ActivityPub on the outside.

**What it costs:**
- New crate (`fetchit-fedi`?) with a sibling transport that is NOT a `Transport` impl in our existing chat router — different wire shape, different addressing model, different signing scheme.
- Need to host an HTTPS endpoint to receive deliveries (an inbox), which means fetch>it stops being purely client-only for the fediverse-facing surface. This is the "is fetch>it now a server" tension; see "Hosting model" below.

**Recommendation:** Yes, ActivityPub. Sibling transport, not a `Transport`-trait impl. Spec the inbox HTTP server as a separate concern from the chat router.

### Q2 — Identity bridge: WebFinger handles?

The fediverse addresses actors by handle: `@josh@etchit.io` resolves via WebFinger (RFC 7033 — `https://etchit.io/.well-known/webfinger?resource=acct:josh@etchit.io`) to a JSON document carrying the actor's ActivityPub `id` URL plus a public key for HTTP-Signature verification. From the actor URL you GET the `Actor` object and its `inbox` endpoint, and you can deliver.

**Mapping fetchit agent ID → fediverse handle.**

| Mapping | Pros | Cons |
|---|---|---|
| Per-user handle (`@josh@etchit.io`) chosen by the user | Familiar UX, matches Mastodon mental model | Requires a user-name registry; namespace squatting + abandoned handles |
| Agent-ID-as-handle (`@a48e8af1...@etchit.io`) — first 8 hex of agent ID | Zero registry; collision-proof; auto-generated | Looks alien, not memorable, fails the [[three-non-negotiables]] UX bar |
| Chainmark-bound handle | Cryptographic ownership proof via chainmark | Concept doesn't exist in fediverse; resolvers won't know what to do |

Recommendation: per-user handle, registry lives on a fetchit-operated etchit.io endpoint, ownership proof is the user signing a WebFinger-resource-JWS at handle-registration time. UI surfaces both the handle (public) and the agent ID (technical) — the two are bound by a signed mapping the registry serves.

**The signing-key question.** Mastodon HTTP Signatures use RSA-2048 keys by default. fetch>it agent IDs are derived from ML-DSA-65. Two options:

- (a) **Co-sign:** fetch>it generates a one-off RSA keypair PER ACTOR for HTTP Signature compatibility, signs the RSA pubkey with the agent's ML-DSA key, publishes the ML-DSA signature in the Actor JSON-LD `publicKey` extension. Mastodon ignores the extension; fetch>it nodes verify it.
- (b) **PQ-signature-aware:** push to publish the ML-DSA pubkey directly as the HTTP-Signature key. Doesn't interop with existing Mastodon servers without a profile they don't have.

Recommendation: (a) for M4 launch. (b) is the long-game once the fediverse adopts PQ HTTP Signatures (early proposals exist; nothing implemented yet at 2026-06-07). Document this as a known interop seam.

**ML-DSA signature asymmetry across the bridge.** Outbound deliveries from a fetchit actor carry BOTH the RSA HTTP Signature (Mastodon-compatible) AND an ML-DSA-65 signature over the same canonical bytes, published in the Actor `publicKey` extension. fetch>it nodes verify both layers; Mastodon nodes ignore the ML-DSA layer.

Inbound deliveries from a Mastodon-class instance carry ONLY an RSA HTTP Signature — there is no ML-DSA layer on traffic that didn't originate from a fetchit actor. We verify with the source actor's published RSA pubkey resolved via WebFinger. **This asymmetry is unavoidable and the bridge surface must NOT claim symmetric PQ behaviour.** The eventual SECURITY.md amendment needs to surface the line: "outbound PQ-protected and Mastodon-compatible; inbound RSA-only-verifiable from non-PQ peers." Until the fediverse adopts PQ HTTP Signatures, this is the floor — content-E2EE remains true where applicable (none, for the public bridge surface), metadata privacy remains false, and bridge inbound verification is non-PQ. Per [[feedback-pq-claims]].

### Q3 — Hosting model: who runs the inbox?

ActivityPub deliveries are PUSH — the remote server POSTs to OUR inbox. Someone has to host that inbox at a stable HTTPS URL. Three patterns:

| Pattern | Who runs the inbox | Pros | Cons |
|---|---|---|---|
| **A: Per-instance** | Operator of an `etchit.io`-class domain runs ONE inbox proxy for many users | Familiar (matches Mastodon's shape); existing operators already do this | Centralisation; operator outage = bridge outage; operator can read public-only ActivityPub traffic but cannot see PQ-encrypted chat |
| **B: Per-user** | Each user runs their own inbox (or a small relay-as-inbox cluster does it for them) | Decentralised; matches fetch>it's posture | Most users won't run their own HTTPS endpoint; back to the "everyone's a server" trap fetch>it deliberately avoided in M0 |
| **C: Relay-as-inbox** | Existing community relays add an `/inbox` endpoint, fan out inbound deliveries to subscribed agent IDs over the existing WS path | Reuses the M1.6 community-relay infrastructure; user keeps the read-only-no-wallet [[read-only-means-no-wallet]] posture | Couples WS chat to HTTPS fediverse — the relay now speaks two protocols; trust model gets wider |

Recommendation: **C, with A as the launch-day fallback.** Community relays grow an optional `/inbox` mode. For day-one, etchit.io runs the inbox for any user without a community-relay home, so launch isn't gated on operator buildout. Once a community has its own relay+inbox, users migrate.

Open: do we need the inbox to be censorship-resistant? An `autonomi://`-hosted inbox doesn't make sense (no HTTPS-PUSH semantic). The right answer is probably "the operator pattern itself is the resilience" — N independent operators run inboxes, any can serve any user, denylist consensus is community-curated.

---

## Visibility model

The fediverse is *observably public*. Anything that goes across the bridge is signed-but-not-encrypted. fetch>it's UI must make this visible at every send affordance:

- **Public actor on fetchit side:** A fetchit user can opt into being a public actor. Their PROFILE (display name, pubkey, public posts) is fediverse-addressable. Their DMs are NOT.
- **Private DM channel STAYS PRIVATE:** A DM in fetchit never crosses the bridge. Period. The bridge surface is for explicitly public posts only (call them `PublicPost`s — a new chat envelope kind, NOT a DM).
- **Inbound public-actor posts** from the fediverse land in the recipient's "Public" feed inside fetchit chat. Marked with a distinct "from fediverse" badge so users know the visibility model. Reply UX makes "reply public" the only option for a fediverse-sourced post.
- **No backchannel exfiltration:** A fediverse @mention of a fetchit user MUST NOT auto-route to their DM channel — visibility mismatch. Surfaces as a public-feed mention.

Mapping to [[two-privacy-contracts]]: M4 introduces a THIRD contract — `C = Public` — alongside the existing A (Relay) + B (Direct). The line becomes: "send like WhatsApp (A), send like nobody can prove you sent anything (B), or send like a public Mastodon post (C)." The UI is responsible for keeping these three legs visibly distinct.

---

## Denylist semantics across the bridge

M3's denylist is `agent_id_hex`-keyed. ActivityPub actors have URLs (`https://mastodon.social/users/Gargron`), not 64-hex agent IDs. The denylist model has to extend:

- **Outbound (fetchit → fediverse):** before POST'ing to a remote inbox, check if the actor URL maps to a blocked entry. The denylist needs an `actor_url` arm in addition to `agent_id_hex`. Single signed manifest, two key kinds.
- **Inbound (fediverse → fetchit):** before surfacing a fediverse-sourced post in any fetch>it UI, check the source actor URL against the denylist. Same gate as M3's inbound, different keying.
- **Native fediverse blocklists:** the existing community-curated lists (Oliphant's lists, Garden Fence, etc.) cover Mastodon-side abuse. Should fetchit consume those? Probably yes, as an *additional* filter — but the fetchit-curated list is the canonical one for fetchit-internal moderation decisions. Both filters AND'd at the bridge.

Open: should the denylist manifest cap how many `actor_url` entries it can carry to keep the bootstrap fetch cheap? Mastodon's typical instance-blocklists are ~10k entries; that's still a tractable JSON download. Recommendation: no cap for M4 launch.

---

## Self-review: does M3 over-constrain M4?

Per Alice's flag (`[a48e8af1] Worth confirming during brainstorm that M3's RelaySet / DenylistConsumer abstractions don't over-constrain what M4 needs to slot in`):

| M3 abstraction | M4 concern | Verdict |
|---|---|---|
| `RelaySet` (WS-only) | Fediverse transport is HTTPS POST — NOT a `Transport` impl, NOT a relay client | **No constraint.** Fediverse delivery rides a sibling abstraction (`FediverseTransport`?), not RelaySet. Confirmed acceptable: nothing in chat-layer code couples chat ↔ relay ↔ transport in a way that prevents introducing a parallel surface. |
| `RelayDescriptor` (base_url + Region + operator + is_official) | Fediverse instances would need a different descriptor (actor URL + software flavour + blocklist policy) | **No constraint.** Different concept, deserves a different type (`FediverseInstanceDescriptor`?). Reusing RelayDescriptor would conflate two different operator patterns. |
| `DenylistCheck` trait (`async fn is_blocked(&self, agent_id_hex: &str) -> bool`) | Needs an `actor_url` arm | **Minor extension.** Either the trait grows a sibling method (`async fn is_blocked_actor(&self, url: &str) -> bool`) OR M4 introduces a parallel `FediverseDenylistCheck`. Recommendation: extend the existing trait — same manifest, same consumer, same refresh schedule, just two keying arms. The signed manifest gets `[[blocked_actor_url]]` entries next to `[[blocked]]`. |
| `DenylistConsumer` (HTTPS poll + hourly refresh) | Same consumer can hold both agent_id and actor_url sets | **No constraint.** Internal data structure extension only; public API stays the same shape. |

**Net:** M3 does not over-constrain M4. Two surfaces grow additively (`DenylistCheck` adds a method; manifest gets a new entry kind); the rest is greenfield M4 territory.

---

## Open design questions for Alice cross-review

1. **ActivityPub crate choice.** `apub` vs `fediverse-features` vs hand-rolled minimal client. Need fresh upstream check per [[check-upstream-always-first]] — what shipped in last 6 months? Recommendation: defer until we actually start coding M4; brainstorm doesn't need to pick.

2. **Inbox hosting.** Q3 above. Recommendation: relay-as-inbox (option C) with etchit.io as launch-day fallback (option A).

3. **Third privacy contract (Public).** Visibility model section. Does adding C = Public muddy the [[two-privacy-contracts]] strategic framing, or does it cleanly extend it? My read: cleanly extends — the three contracts are the THREE ways a fetchit user might want a message handled. Three checkboxes per send affordance might be too much; recommendation: UI defaults to A (Relay) for chat, C (Public) for posts, B (Direct) is opt-in on either. **This is the only spec choice that touches strategic posture rather than just engineering — Josh's weigh-in is the blocker for graduating this brainstorm to a writing-plans handoff.**

4. **Native fediverse blocklist consumption.** Denylist section. Recommendation: consume Oliphant/Garden Fence as a secondary filter; fetchit-curated list is canonical for fetchit-internal moderation. Both AND'd at the bridge boundary.

5. **No-publishing constraint.** Does M4 cross the [[read-only-means-no-wallet]] line? My read: NO. The "read-only" phrase scopes specifically to Autonomi wallet/publishing. ActivityPub posts are NOT wallet-signed and NOT Autonomi-published — they're a transport sibling. But this is exactly the kind of phrase that needs guarding per [[read-only-means-no-wallet]] memo, so worth surfacing.

6. **M5 / instance-mode hand-off.** This brainstorm scopes M4 as bridge-only. At what point do we want fetchit to ACT as an instance (admin'd by an operator, hosting many users, presenting as a Mastodon-class object)? Recommendation: not until M5 at earliest; M4 should explicitly avoid baking instance assumptions into the bridge code.

---

## What this isn't

- An implementation plan. No tasks, no build sequence, no acceptance criteria. Those land after Alice + Josh weigh in on the Q1/Q2/Q3 decisions.
- A protocol spec. No JSON-LD shapes, no signature canonicalisation rules, no wire-format choices beyond "ActivityPub HTTPS POSTs". That's the next document.
- A commitment to ship. M4 is gated on M3 closing fully (operator pick + onboarding docs) and on Josh greenlighting the third privacy contract framing.

---

## Cross-references

Inline-linked memories that anchor decisions:
- [[two-privacy-contracts]] — A/B contracts that M4 extends with C
- [[three-non-negotiables]] — UX-at-Signal-parity bar that constrains identity-bridge choice
- [[read-only-means-no-wallet]] — the phrase to keep intact while introducing fediverse publishing
- [[check-upstream-always-first]] — gate before picking an ActivityPub crate
- [[read-upstream-source-first]] — same, for HTTP Signature implementation
