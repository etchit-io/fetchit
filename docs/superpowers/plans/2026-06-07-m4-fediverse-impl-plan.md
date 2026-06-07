# M4 — Fediverse Bridge Implementation Plan

**Goal:** Ship the fediverse bridge so a fetch>it user has a WebFinger-resolvable handle (`@user@etchit.io`), can post public messages that land in Mastodon-class instances, and can read public posts from any fediverse actor inside their existing chat UI. Three privacy contracts (A=Relay, B=Direct, C=Public) coexist; DMs never cross the bridge.

**Decision input:**
- Brainstorm at `docs/superpowers/plans/2026-06-07-m4-fediverse-brainstorm.md` (cross-reviewed by Alice, c581f9e).
- Q1 ActivityPub HTTPS POSTs ✅, Q2 per-user WebFinger handle + ML-DSA/RSA cosign ✅, Q3 relay-as-inbox with etchit.io fallback ✅. C=Public confirmed by Josh 2026-06-07.

**Architecture:** New `fetchit-fedi` crate (workspace member, NOT a chat-`Transport` impl). Holds the WebFinger client, ActivityPub Actor builder, outbound HTTPS POST delivery with HTTP Signatures (RFC 9421), and the inbound inbox handler. `fetchit-chat` grows ONE additional envelope kind (`PublicPost`) and ONE chat-layer surface that routes `PublicPost`s through the new fedi transport without sharing the existing `Router`/`Transport` plumbing. `fetchit-trust` denylist manifest grows an `EntryKind::ActorUrl` arm — one-line additive change per Alice [A].

**Tech stack:** Existing workspace pins. Rust 2021, MSRV 1.85, `tokio`, `reqwest` (already a dep via `x0xd-client`). New crates: `webfinger` (or hand-roll — confirm pre-spec), `http-signature-normalization`, `rsa` (for cosign-only RSA-2048 keypairs). PQ stays on ML-DSA-65. No `axum` pulled into `fetchit-chat` — the inbox HTTP server lives inside `fetchit-relay-server` (which already runs `axum`) as a new endpoint module.

**Spec:** This document. Brainstorm above is the design rationale.

---

## Scope split

| Sub-deliverable | Owns | Order |
|---|---|---|
| `fetchit-fedi` crate scaffold + Actor builder | Bob | Stage 1 |
| Outbound HTTPS POST + HTTP Signature cosign | Bob | Stage 2 |
| `fetchit-relay-server` inbox endpoint + pre-flight hardening | Bob | Stage 3 |
| `fetchit-trust` `EntryKind::ActorUrl` + Mastodon-blocklist secondary filter | Bob | Stage 4 |
| `fetchit-chat::PublicPost` envelope + UI confirmation surface | Bob (chat side), TBD (UI side) | Stage 5 |
| WebFinger endpoint on `etchit.io` (`/.well-known/webfinger`) | Joint (Bob impl, Josh hosts) | Stage 6 |
| First operator-mode community relay grows `/inbox` | Joint (Bob docs, Josh's operator) | Stage 7 |

Stages 1-4 are pure backend, no UI dependency. Stage 5 can land in two commits (envelope/wire first, UI surface second) — backend ships ahead of UI.

---

## Stage 1 — `fetchit-fedi` crate scaffold + Actor representation

A new workspace crate that knows nothing about chat — pure ActivityPub primitives.

**Public surface:**

```rust
// crates/fetchit-fedi/src/lib.rs
pub mod actor;
pub mod webfinger;
pub mod activity;
pub mod signature;
pub mod transport;

pub use actor::{Actor, ActorBuilder, ActorIdentity};
pub use webfinger::{WebFingerClient, WebFingerError};
pub use activity::{Activity, ActivityKind, PublicPost};
pub use signature::{SignedRequest, HttpSignatureKey, HttpSignatureError};
pub use transport::{FediverseTransport, DeliveryError};
```

```rust
// crates/fetchit-fedi/src/actor.rs
/// A fetchit-issued fediverse actor. Both ML-DSA (PQ) and RSA-2048
/// (HTTP-Signature-interop) keys; the ML-DSA-signed RSA pubkey rides
/// in the `publicKey` extension that Mastodon ignores and fetch>it
/// nodes verify.
pub struct ActorIdentity {
    pub handle: String,                 // `@josh@etchit.io`
    pub actor_url: url::Url,            // `https://etchit.io/actors/josh`
    pub agent_id_hex: String,           // bound to chat agent_id
    pub rsa_signing_key: HttpSignatureKey,
    pub ml_dsa_signing_key: fetchit_relay_client::MlDsaSigner,
}

impl ActorIdentity {
    /// Mint a fresh ActorIdentity. Stores the RSA key + binding
    /// signature in the StoreLayout for re-load on restart.
    pub fn mint(
        handle: &str,
        domain: &str,
        chat_identity: &fetchit_chat::FetchitIdentity,
        layout: &fetchit_chat::local_store::StoreLayout,
    ) -> Result<Self, ActorError>;

    /// Load a previously-minted ActorIdentity by handle.
    pub fn load(
        handle: &str,
        layout: &fetchit_chat::local_store::StoreLayout,
    ) -> Result<Option<Self>, ActorError>;
}

/// Serialised `Actor` JSON-LD as Mastodon expects, plus our PQ
/// extension. Renders to `application/activity+json`.
pub struct Actor {
    pub id: url::Url,
    pub preferred_username: String,
    pub inbox: url::Url,
    pub outbox: url::Url,
    pub public_key: RsaPublicKeyPem,
    pub ml_dsa_attestation: MlDsaAttestation, // (pubkey + signature over RSA pubkey)
}
```

**Acceptance criteria for Stage 1:**
- `ActorBuilder` mints + persists an Actor with both keys.
- Round-trip JSON-LD encode/decode against a Mastodon Actor fixture.
- ML-DSA attestation verifies against the chat-identity ML-DSA pubkey.
- 100% unit-test coverage on `mint` + `load` + `Actor::to_json_ld`.

**Open question 1.1:** Where does the `StoreLayout` for fedi keys live? Recommendation: a new `StoreLayout::fedi_dir()` sibling of `chat_dir()`, isolated namespace.

---

## Stage 2 — Outbound HTTPS POST + HTTP Signature cosign

Deliver an `Activity` (initially just `Create` of a `Note` representing a `PublicPost`) to a remote actor's inbox.

**Public surface:**

```rust
// crates/fetchit-fedi/src/transport.rs
/// Outbound delivery transport. NOT a `fetchit_chat::Transport` impl —
/// the signature explicitly takes `&PublicPost`, not `&Envelope`, so a
/// DM can't reach this path at compile time. Per Alice review [C].
pub struct FediverseTransport {
    actor: Arc<ActorIdentity>,
    http: reqwest::Client,
    webfinger: WebFingerClient,
}

impl FediverseTransport {
    pub fn new(
        actor: Arc<ActorIdentity>,
        http: reqwest::Client,
        webfinger: WebFingerClient,
    ) -> Self;

    /// Deliver a single PublicPost to a target handle (`@user@instance`).
    /// Resolves handle → actor URL → inbox URL via WebFinger, builds the
    /// signed POST request, sends it. Returns the remote's status.
    ///
    /// Type signature enforces the DM-never-bridge invariant: the
    /// function literally cannot be called with a DM envelope.
    pub async fn deliver(
        &self,
        post: &PublicPost,
        to_handle: &str,
    ) -> Result<DeliveryReceipt, DeliveryError>;
}
```

**HTTP Signature construction:**

```rust
// crates/fetchit-fedi/src/signature.rs
pub struct HttpSignatureKey {
    pub key_id: String,                // `https://etchit.io/actors/josh#main-key`
    pub rsa_private_pem: String,
}

impl HttpSignatureKey {
    /// Sign a POST request per RFC 9421. Headers signed:
    /// `(request-target) host date digest`. Includes SHA-256 Digest
    /// header per Mastodon's de-facto requirement.
    pub fn sign_post(
        &self,
        url: &url::Url,
        body: &[u8],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<SignedRequest, HttpSignatureError>;
}
```

**Acceptance criteria for Stage 2:**
- Wiremock-based test: POST a sample `Create(Note)` to a mock inbox, assert request shape (`Signature` header structure, `Digest: SHA-256=...`, body verbatim).
- Round-trip: signature verifies against the published RSA pubkey.
- ML-DSA cosignature is independently emitted as a header extension (`X-Fetchit-MLDSA-Signature: base64(...)`) — Mastodon ignores, fetch>it verifies.

**Open question 2.1:** RFC 9421 vs draft-cavage HTTP Signatures. Mastodon ships 2026-vintage builds that speak RFC 9421; older instances still expect draft-cavage. Recommendation: speak both, prefer RFC 9421, fall back if remote signals it. Worth confirming current state via WebFetch on Mastodon's HTTP-Sig docs before coding.

---

## Stage 3 — Inbox endpoint + security pre-flight

The inbox lives in `fetchit-relay-server`, which already runs `axum`. New endpoint module under `crates/fetchit-relay-server/src/inbox/`.

**Public surface:**

```rust
// crates/fetchit-relay-server/src/inbox/mod.rs
pub fn inbox_router(state: InboxState) -> axum::Router;

pub struct InboxState {
    pub webfinger: Arc<WebFingerClient>,
    pub denylist: Arc<dyn fetchit_chat::DenylistCheck>,
    pub pending_deliveries: PendingDeliveryQueue,
}
```

**Pre-flight hardening — checklist per Alice review [D]:**

1. **Rate-limit per source-instance.** Token bucket keyed by remote instance hostname (parsed out of the signing actor URL). Mirror the existing `R-002` rate-limit shape from relay-server. Default: 60 requests per minute per instance, configurable in `relay-server.toml`.

2. **HTTP Signature verification depth:**
   - Verify signature against the source actor's RSA pubkey from their WebFinger.
   - Reject if `Digest` header is missing OR doesn't match the SHA-256 of the body.
   - Reject if `Date` header is outside `±5 min` of server clock (RFC 9421 freshness window).
   - Reject if any required signed header is missing.

3. **Replay window.** Cache `(Digest, Date)` pairs in a sliding 5-minute window; reject duplicates. In-memory `HashMap<(String, i64), Instant>` cleaned per minute. Bounded to ~100k entries; LRU eviction past cap.

4. **Body size cap.** Reject any inbound POST with `Content-Length > 1MB`. Mastodon's typical activity body is ~64KB; 1MB is generous but bounded. Surface as `413 Payload Too Large`.

5. **WebFinger cache.** TTL-based cache of `(handle → actor JSON-LD)`. TTL 1 hour, invalidate-on-signature-mismatch (a key rotation forces re-resolve). Cap at 10k entries.

Each is its own metric counter:
- `fedi_inbox_dropped_rate_limit_total{instance}`
- `fedi_inbox_dropped_sig_fail_total{reason}`
- `fedi_inbox_dropped_replay_total`
- `fedi_inbox_dropped_body_size_total`
- `fedi_inbox_dropped_denylist_total{kind}`

**Acceptance criteria for Stage 3:**
- All 5 pre-flight gates have a test that asserts a hostile request is rejected.
- Happy-path test: well-formed POST → 202 Accepted, activity is enqueued for chat-layer delivery.
- Denylist gate (per Alice [A], extends `EntryKind::ActorUrl`) drops inbound from blocked source actors.

**Open question 3.1:** Where does the inbox enqueue inbound activities? Recommendation: a new `pending_deliveries` mpsc, drained by the chat-layer subscriber surface. The relay-server holds the queue; chat-clients pull via existing relay-WS or a new sibling endpoint. Defer the wire format to Stage 5.

---

## Stage 4 — `fetchit-trust` denylist `EntryKind::ActorUrl` + Mastodon-blocklist secondary

Per Alice [A], `EntryKind` already absorbs multi-arm keying — adding `ActorUrl` is a one-line enum addition plus a helper.

**Diff sketch:**

```rust
// crates/fetchit-trust/src/manifest.rs
pub enum EntryKind {
    AgentId,
    XorName,
    ActorUrl,         // M4 addition
}

pub struct TargetIdentity {
    pub kind: EntryKind,
    pub value: String,
}

impl DenylistConsumer {
    // Existing
    pub fn is_blocked_agent_hex(&self, hex: &str) -> bool;
    pub fn is_blocked_xor_name_hex(&self, hex: &str) -> bool;
    // M4 addition
    pub fn is_blocked_actor_url(&self, url: &str) -> bool;
}
```

`DenylistCheck` trait (in `fetchit-chat`) grows a sibling method:

```rust
#[async_trait]
pub trait DenylistCheck: Send + Sync {
    async fn is_blocked(&self, agent_id_hex: &str) -> bool;
    /// M4: check by fediverse actor URL.
    async fn is_blocked_actor(&self, url: &str) -> bool;
}
```

Default impl: `is_blocked_actor` returns `false`. M3-era consumers don't need to update.

**Mastodon-blocklist secondary filter:**

```rust
// crates/fetchit-trust/src/mastodon_blocklist.rs
pub struct MastodonBlocklistConsumer {
    sources: Vec<url::Url>,             // Oliphant, Garden Fence, etc.
    cache: Arc<RwLock<HashSet<String>>>,
}

impl MastodonBlocklistConsumer {
    /// Refresh on a schedule (default 6h — slower than fetchit denylist
    /// since Mastodon-side updates are infrequent).
    pub async fn refresh(&self) -> Result<(), ConsumerError>;

    pub fn is_instance_blocked(&self, hostname: &str) -> bool;
}
```

Inbox + outbound delivery AND fetchit denylist (`is_blocked_actor`) AND mastodon-blocklist (`is_instance_blocked`). Both must pass for the activity to flow.

**Acceptance criteria for Stage 4:**
- New `EntryKind::ActorUrl` round-trips through manifest signing/verification.
- `is_blocked_actor` test against a seeded list.
- Mastodon-blocklist consumer test against a fixture from Oliphant's list.
- Inbox integration test: blocked instance → 403 (or silent 202 + counter, per privacy preference).

**Open question 4.1:** Silent-drop vs `403` for blocked instances? Silent matches the [[two-privacy-contracts]] B-side ethos (no signal to the blocker). `403` is the ActivityPub-conventional response. Recommendation: silent 202 (Mastodon retries on non-2xx; silent acknowledgement makes the block invisible to the source). Counter still fires for ops.

---

## Stage 5 — `PublicPost` envelope + chat-layer surface + UI confirmation

The chat layer grows ONE new envelope kind and ONE new send method. The new method takes `&PublicPost`, not `&Envelope` — type-system DM-never-bridge enforcement per Alice [C].

**Envelope addition:**

```rust
// crates/fetchit-relay-proto/src/envelope.rs (or local to fedi)
pub struct PublicPost {
    pub author_handle: String,
    pub body_md: String,                // markdown body
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reply_to_actor_url: Option<url::Url>,
    pub mentions: Vec<String>,          // `@user@instance` list
}
```

**Chat-layer surface:**

```rust
// crates/fetchit-chat/src/public.rs (new)
impl Client {
    /// Publish a PublicPost to the fediverse. Resolves recipient
    /// instances from the mentions list, delivers via FediverseTransport.
    ///
    /// Returns `ChatError::Denied { actor_url }` if any target instance
    /// or mentioned actor is denylisted.
    pub async fn publish_public_post(
        &self,
        post: PublicPost,
    ) -> Result<PublishReceipt, ChatError>;

    /// Subscribe to a remote actor's outbox. Inbound posts arrive on
    /// the same event stream as chat events but tagged as PublicPost.
    pub async fn subscribe_actor(&self, handle: &str) -> Result<(), ChatError>;
}
```

`ChatError` grows a `Denied { actor_url: String }` variant alongside the existing `Denied { agent_id_hex: String }`. Single error enum, two keying arms.

**UI confirmation surface — per Alice [E]:**

C=Public sends MUST surface a confirmation step, not a silent toggle. The UI flow:

1. User composes a post in the "Public" tab.
2. On send, modal: "Post publicly to the fediverse — this will be visible to operators, instance admins, and any subscriber of your actor. Anyone you mention can see it; the denylist of your local community is the only filter."
3. Two buttons: "Post publicly" (primary) and "Cancel".
4. Tickbox: "Don't ask again for this session" (NOT cross-session).

This is a UI requirement, not a chat-API one. The chat surface returns `Ok` regardless of UI confirmation; the UI is responsible for gating the call. Doc note: the chat surface does NOT pop the modal on its own.

**Acceptance criteria for Stage 5:**
- `Client::publish_public_post` test with a wiremock'd fediverse instance: assert the POST body matches the expected JSON-LD shape.
- Type-check test: a DM `Envelope` cannot be passed where `PublicPost` is expected (compile-fail test).
- UI confirmation flow ships behind a TODO + a tracking issue when the chat backend lands.

---

## Stage 6 — WebFinger endpoint on `etchit.io`

The `etchit.io` static-pages site grows a `/.well-known/webfinger` endpoint. Cloudflare Worker (or a Functions endpoint) reads a static `webfinger.json` map keyed by `acct:<handle>@etchit.io`.

**Deliverables:**
- `etchit-website/.well-known/webfinger.json` — base map for known handles.
- A Cloudflare Worker (`etchit-website/functions/[[...].js]`) that returns the right JSON for `?resource=acct:<handle>@etchit.io`.
- Documentation at `docs/FEDIVERSE.md` describing the handle-registration flow.

**Acceptance criteria for Stage 6:**
- `curl https://etchit.io/.well-known/webfinger?resource=acct:josh@etchit.io` returns a valid WebFinger JRD.
- Cross-check: a vanilla Mastodon instance can resolve `@josh@etchit.io` to the actor URL.

---

## Stage 7 — First community relay grows `/inbox`

Per the brainstorm Q3: launch with etchit.io as fallback, migrate to community-relay-as-inbox once an operator opts in.

**Deliverables:**
- `fetchit-relay-server` ships the new `inbox/` module (from Stage 3) as a build-time-gated feature `fediverse-inbox`.
- `docs/COMMUNITY-RELAY.md` (M3 deliverable) gets a new section: "Optional: serving as a fediverse inbox."
- Josh's operator (M3 Stage 3.3) opts in to the fediverse-inbox role.

Sequential to M3 closing — Stage 7 cannot ship until the M3 community-relay onboarding is concrete.

---

## Build sequence

| # | Stage | Owner | Blockers |
|---|---|---|---|
| 1.1 | `fetchit-fedi` crate scaffold | Bob | none |
| 1.2 | `ActorIdentity` mint + load | Bob | 1.1 |
| 1.3 | `Actor` JSON-LD round-trip | Bob | 1.2 |
| 2.1 | `HttpSignatureKey` + RFC 9421 + draft-cavage | Bob | 1.3 |
| 2.2 | `FediverseTransport::deliver` outbound | Bob | 2.1 |
| 3.1 | `inbox` module scaffold + 5 pre-flight gates | Bob | 2.1 (shares signature code) |
| 3.2 | Inbox metrics + ops surface | Bob | 3.1 |
| 4.1 | `EntryKind::ActorUrl` + manifest test | Bob | none (parallel with Stage 1-3) |
| 4.2 | `DenylistCheck::is_blocked_actor` trait extension | Bob | 4.1 |
| 4.3 | `MastodonBlocklistConsumer` + Oliphant fixture | Bob | 4.2 |
| 5.1 | `PublicPost` envelope + `ChatError::Denied { actor_url }` | Bob | 1.3, 4.2 |
| 5.2 | `Client::publish_public_post` + wire test | Bob | 5.1, 2.2 |
| 5.3 | `Client::subscribe_actor` + inbound surface | Bob | 5.2, 3.1 |
| 6.1 | `etchit.io/.well-known/webfinger` Worker | Joint | 1.3 (for actor URL shape) |
| 7.1 | `COMMUNITY-RELAY.md` fediverse-inbox section | Joint | M3 #162 closes, Stage 3 ships |
| 7.2 | First operator opts in | Joint (Josh's pick) | 7.1 |

Stages 1-4 can land in parallel where independent; Stage 5 is the chat-layer join point.

---

## Risks + mitigations

- **HTTP Signature interop friction.** Mastodon, Lemmy, and Pleroma have subtly different HTTP-Sig expectations (header set, normalisation rules). Mitigation: test against live instances on a josh-clsn-fork sandbox before merging. List of test targets: `mastodon.social`, `lemmy.world`, `pleroma.site`.
- **RSA key compromise scope.** Per-actor RSA keys are stored on disk; compromise reveals public-bridge posting capability for that actor only. ML-DSA chat identity is unaffected. Mitigation: document this scoping in `SECURITY.md` so a casual reader doesn't conflate the two.
- **Mastodon-blocklist staleness.** Oliphant's list updates infrequently; a re-tooling that breaks the format is plausible. Mitigation: fail-soft on parse error (consume what parses, log + drop the rest); never block fetchit-internal moderation on Mastodon-blocklist availability.
- **Inbox flooding from a hostile instance.** Per Stage 3 hardening — rate-limit + replay window + body cap. Worst case: a single hostile instance burns rate-limit but the others stay unaffected. No cascading risk.
- **ActivityPub crate churn.** `apub` and `fediverse-features` are both <1.0. Mitigation: confirm fresh upstream activity via WebFetch before picking; budget for a vendored fork if necessary.

---

## SECURITY.md amendment seam

Per Alice [B], the bridge has asymmetric PQ properties. The eventual `docs/SECURITY.md` update needs to surface:

> **Fediverse bridge (M4).** Outbound deliveries from a fetch>it actor carry both an RSA HTTP Signature (Mastodon-compatible) and an ML-DSA-65 signature over the same canonical bytes, published in the Actor `publicKey` extension. fetch>it nodes verify both layers; Mastodon-class nodes ignore the ML-DSA layer. Inbound deliveries from non-fetchit peers carry RSA HTTP Signatures only — there is no PQ verification on that side. This is unavoidable until the fediverse adopts PQ HTTP Signatures and must NOT be misrepresented as symmetric PQ behaviour. Content-E2EE remains true where applicable (none, for the public bridge surface); metadata privacy remains false; bridge inbound verification is non-PQ.

Defer landing this amendment until Stage 5 ships and the bridge is actually carrying traffic.

---

## Out of scope for M4

- Fetchit acting as an ActivityPub *instance* (admin'd by an operator, hosting many users). Bridge-only for M4. Revisit in M5.
- PQ HTTP Signatures. No upstream proposal is implementable at 2026-06-07. Track via [[check-upstream-always-first]].
- DM bridging to Mastodon-DMs. Hard NO per visibility model. The two are different privacy contracts and conflating them breaks the [[two-privacy-contracts]] strategic framing.
- Live federation of group MLS state to ActivityPub group actors. The visibility models are incompatible (encrypted gossip vs observably-public). Out of scope.
