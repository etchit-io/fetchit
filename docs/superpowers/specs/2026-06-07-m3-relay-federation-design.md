# M3 — Relay federation constellation: design

**Owner:** [A] (Alice).
**Status:** spec, locked 2026-06-07.
**Source brainstorm:** chat session 2026-06-07 with Josh, building on `private/relay-federation-note.md` (2026-06-01).

## Goal

Ship the federation layer above today's single-relay-per-conversation wall.
At v1.0 launch:
1. fetch>it clients open **3 concurrent WebSocket sessions** to relays.
2. A signed denylist published by etchit.io is consumed by every client on
   boot + periodically + reactively. Matched entries are **hard-blocked**.
3. Community relays propagate **invitation-only** via contact cards'
   `v2_rendezvous_hints` field; no central registry.

Relays never speak to each other. The client is the federator. This is
deliberate — the NOSTR-style relay-to-relay federation model has no
abuse-story owner; with our model, each operator owns a partial graph only.

## Background

`MILESTONES.md` M3 gate: "Federation decisions M3.10/M3.11/M3.12 implemented
and shipped; relay-server denylist consumer + multi-home client config live;
one community-operated relay onboarded for E2E test."

The architectural wall + the threat model are documented in
`private/relay-federation-note.md`. This spec is what M3 actually builds.

## Locked decisions (from the 2026-06-07 brainstorm)

1. **Multi-home default count.** 3 concurrent WS sessions per client.
   User can opt up or down via Settings → Network → Advanced.
2. **Denylist scope.** Single unified consumer for `EntryKind` variants
   `RelayUrl` (M3), `XorName` (existing), `AgentId` (existing). `ActorUrl`
   (M4 Stage 4) lands additively into the same enum and consumer.
3. **Block behavior.** Hard block across the board, no user override at
   v1.0: `RelayUrl` = refuse to dial, `AgentId` = refuse send/receive,
   `XorName` = reader refuses to render with placeholder.
4. **Community-relay discovery.** Invitation-only via contact cards. No
   central registry; no etchit.io listing.
5. **`RendezvousHints` v=1 payload.** Simple ordered list of `wss://`
   URLs. Future extension via `v=2` bump.
6. **Slot allocation.** Slot 0 = my primary (pinned, immune to eviction).
   Slots 1–2 = LRU-managed, dynamically open to contacts' primary relays
   as recent-traffic dictates.
7. **My card's relay list.** Auto-populated as `[my_primary_url]`. Power
   users add more in Settings → Network → Advanced.
8. **Denylist trust anchor bootstrap.** Hardcoded etchit-io ML-DSA-65
   pubkey in the client release. Rotation = client release bump.
   Multisig migration is a documented v1.1 follow-up.

## Architecture

Three layers above the existing `Transport` trait:

```
                                  ┌──────────────────────┐
                                  │  fetchit-trust       │
                                  │  ::EntryKind         │  + RelayUrl (M3)
                                  │  ::DenylistResponse  │  + ActorUrl (M4)
                                  └──────────┬───────────┘
                                             │ shared types
              ┌──────────────────────────────┴──────────────────────────┐
              │                                                         │
   ┌──────────▼─────────────┐                              ┌────────────▼───────────┐
   │ fetchit-trust-client   │  (NEW crate)                 │ fetchit-relay-server   │
   │  ::DenylistConsumer    │                              │  publishes signed      │
   │  - fetch + verify      │                              │  /v1/denylist?kind=... │
   │  - in-mem index        │                              │  (already half built)  │
   │  - BlockEvent stream   │                              └────────────────────────┘
   │  - disk persist        │
   └──────────┬─────────────┘
              │ DenylistQuery API + BlockEvent
   ┌──────────┴─────────────┐
   │ fetchit-chat::transport│
   │  ::MultiHomeTransport  │  (NEW module)
   │  - 3 session slots     │
   │  - LRU eviction        │
   │  - inbound dedup       │
   │  - denylist enforce    │
   │  - owns N RelayTransport
   └────────────────────────┘
              │ also queries denylist
   ┌──────────┴─────────────┐
   │ fetchit-core / desktop │  (XorName denylist for reader UI)
   └────────────────────────┘
```

Implementation shape per Approach B (locked in brainstorm):
- New `MultiHomeTransport` wrapper owning N existing `RelayTransport`
  instances. Each `RelayTransport` stays 1:1 with one WS.
- New `fetchit-trust-client` crate consumed by both `fetchit-chat`
  (RelayUrl, AgentId enforcement) and `fetchit-core` / desktop
  (XorName enforcement for the reader UI).
- Mirrors Bob's M4 split pattern (`fetchit-fedi` separate from `fetchit-chat`).

## Crate layout

- **NEW** `crates/fetchit-trust-client/` — pure-Rust consumer crate. No
  hard-wired I/O; caller supplies an `HttpClient` impl (`reqwest::Client`
  in prod, mock in tests). Used by `fetchit-chat` and `fetchit-core` /
  desktop.
- **Extends** `crates/fetchit-trust/src/types.rs` — `EntryKind` gains
  `RelayUrl` (M3) and `ActorUrl` (M4 Stage 4). `TargetIdentity::value_hex`
  renamed to `value` (see §Bob convergence below).
- **NEW** `crates/fetchit-chat/src/transport/multi_home.rs` —
  `MultiHomeTransport` impl, slot policy, inbound dedup.
- **Modified** `crates/fetchit-chat/src/card.rs` — `RendezvousHintsV1`
  struct + serde + validators. v=1 payload locked.
- **Modified** `crates/fetchit-core/src/handler.rs` — `Rendition::Blocked
  { reason }` variant (additive, `#[non_exhaustive]` already).
- **Modified** desktop `apps/fetchit-desktop/src{,-tauri}/` — settings UI,
  conversation banner, contact denylist indicator, reader Blocked handler.
- **Modified** Android `apps/fetchit-android/` — parity surfaces.

## Wire schemas

### `RendezvousHints` v=1 payload

```rust
// crates/fetchit-chat/src/card.rs
pub struct RendezvousHintsV1 {
    /// Ordered list of `wss://` relay URLs the issuer can be reached on.
    /// First entry is the issuer's primary; subsequent entries are
    /// fallbacks the issuer also keeps a session to (power-user mode).
    pub relays: Vec<String>,
}
```

JSON wire shape inside the existing `RendezvousHints.data` opaque slot:

```json
{
  "v": 1,
  "data": {
    "relays": ["wss://nyc.etchit.io/v1/ws", "wss://my-community.example/v1/ws"]
  }
}
```

**Decoder validation:**
- `relays` non-empty.
- Each entry parses as a `wss://` URL (not `ws://`, not `https://`).
- Each entry ≤ 256 chars.
- `relays.len()` ≤ 8 (DoS guard against bloated cards).
- Decoder rejects the whole hints block on any violation; the card itself
  remains valid (the hints just don't apply).

### `EntryKind` (extended)

```rust
// crates/fetchit-trust/src/types.rs
pub enum EntryKind {
    XorName,    // existing — 64-hex Autonomi content address
    AgentId,    // existing — 64-hex chat identity
    RelayUrl,   // NEW (M3)  — lowercased wss:// URL
    ActorUrl,   // NEW (M4 Stage 4) — lowercased ActivityPub Actor URL
}
```

### `TargetIdentity` field rename

```rust
pub struct TargetIdentity {
    pub kind: EntryKind,
    /// Identifier value. Format depends on `kind`:
    /// - `XorName` / `AgentId`: lowercased 64-hex.
    /// - `RelayUrl` / `ActorUrl`: lowercased canonical URL string.
    pub value: String,    // renamed from `value_hex`
}
```

Validation lives in `TargetIdentity::new(kind, value)`. Field rename is a
breaking wire change in `fetchit-trust::types`; cost is bounded because no
external consumers ship today. Locked with Bob in a single chat-pipe
exchange (see §Bob convergence).

### `DenylistResponse` (unchanged shape, new EntryKind values)

Existing `DenylistResponse { etag, generated_at_ms, kind, entries,
issuer_signature_hex, issuer_key_id }` carries each kind's entries in a
separate published response, signed with the etchit-io v1 key.

Endpoint pattern:
- `GET https://etchit.io/v1/denylist?kind=xor_name`
- `GET https://etchit.io/v1/denylist?kind=agent_id`
- `GET https://etchit.io/v1/denylist?kind=relay_url`
- `GET https://etchit.io/v1/denylist?kind=actor_url` (M4 layered atop)

## Component design

### `fetchit-trust-client::DenylistConsumer`

```rust
pub struct DenylistConsumer {
    fetch_url_base: String,                       // "https://etchit.io/v1"
    pubkey: VerifyingKey,                         // hardcoded etchit-io ML-DSA-65
    indexes: Arc<RwLock<DenylistIndexes>>,
    poll_interval: Duration,                      // default 6h
    cache_path: Option<PathBuf>,                  // disk persist
    tx: tokio::sync::broadcast::Sender<BlockEvent>,
}

#[derive(Default)]
struct DenylistIndexes {
    xor_names: HashSet<String>,
    agent_ids: HashSet<String>,
    relay_urls: HashSet<String>,
    actor_urls: HashSet<String>,
}

pub struct BlockEvent {
    pub kind: EntryKind,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl DenylistConsumer {
    pub fn new(pubkey: VerifyingKey, base: String, cache: Option<PathBuf>) -> Self;
    pub fn spawn_poll_loop<C: HttpClient>(self: Arc<Self>, client: C) -> JoinHandle<()>;
    pub async fn refresh<C: HttpClient>(&self, client: &C) -> Result<(), TrustError>;
    pub fn is_blocked(&self, kind: EntryKind, value: &str) -> bool;
    pub fn subscribe(&self) -> Receiver<BlockEvent>;
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn get(&self, url: &str) -> Result<Vec<u8>, TrustError>;
}
```

**Refresh path:** for each `EntryKind` variant, GET its endpoint, deserialize
`DenylistResponse`, verify signature with hardcoded pubkey, swap into the
index atomically, emit `BlockEvent` describing the delta.

**Offline boot:** if `cache_path` is set, the consumer reads the last good
response per kind from disk on init. First successful network refresh
overwrites the cache.

**Failure handling:** signature mismatch on any kind = log + retain the
previous good index for that kind (do not clear). Network failure = log
+ retain the previous index. The consumer is **fail-closed against
poisoning** but **fail-open against unavailability** — we keep the last
known good denylist rather than letting an etchit.io outage open the
gates.

**Persistence format:** the cached response is the raw signed
`DenylistResponse` bytes (postcard); cache reload re-verifies signature
on every boot.

### `fetchit-chat::transport::MultiHomeTransport`

```rust
pub struct MultiHomeTransport {
    primary_url: String,
    slots: RwLock<[Option<Slot>; 3]>,             // slot 0 = primary
    inbox_dedup: Mutex<NonceDedup>,
    denylist: Arc<DenylistConsumer>,
    on_inbound: Arc<dyn Fn(InboundEnvelope) + Send + Sync>,
    _denylist_subscription: JoinHandle<()>,
}

struct Slot {
    relay_url: String,
    transport: Arc<RelayTransport>,
    last_traffic_at: SystemTime,
}

struct NonceDedup {
    // (sender_agent_id, envelope.nonce) -> first-seen-at
    seen: LruCache<(String, [u8; 12]), Instant>,
    // 10k entries, ~5min TTL
}
```

**Slot allocation algorithm:**

```
fn pick_slot_for_send(target_relay_url: &str) -> Result<&Slot, Err>:
    if denylist.is_blocked(RelayUrl, target_relay_url):
        return Err(BlockedRelay)
    if target_relay_url == primary_url:
        return slots[0]
    for slot in &mut slots[1..3]:
        if slot.relay_url == target_relay_url:
            slot.last_traffic_at = now()
            return slot
    // need a new slot
    let victim = empty_slot OR lru(slots[1..3])
    *victim = open_new_relay_transport(target_relay_url)?
    return victim
```

**Outbound:** caller passes the recipient's `card.v2_rendezvous_hints`.
We use `hints.relays[0]` (recipient's preferred primary) as the target.
If `hints` is `None` (legacy v1 card), we send via slot 0 (our primary)
on the assumption the recipient is also there.

**Inbound:** every open slot's inbound stream is multiplexed into a
single channel. Dedup key is `(envelope.from_agent_id, envelope.nonce)`.
First-seen wins; later duplicates are dropped + logged at debug level.

**Denylist mid-session reactivity:** a background task subscribes to
`denylist.subscribe()`. On `BlockEvent { kind: RelayUrl, added }` that
intersects any active slot's `relay_url`, the slot is closed with reason
`Denylisted` and emits a Tauri `chat:relay-denylisted` event so the
desktop layer surfaces a banner. The slot stays empty until the
allocator naturally fills it on the next outbound.

### Block enforcement points

| Point | Crate / file | Kind | Action |
| --- | --- | --- | --- |
| Outbound transport | `transport/multi_home.rs::send` | `RelayUrl`, `AgentId` | Return `TransportError::Blocked` |
| Inbound dispatch | `dispatch.rs::handle_envelope` | `AgentId` (sender) | Drop + log + emit `chat:warn` |
| Reader | `fetchit-core::handlers::dispatch` | `XorName` | Short-circuit to `Rendition::Blocked` |

The reader-side enforcement requires a small trait in `fetchit-trust`
(the schema crate is the right home — no I/O, both `fetchit-trust-client`
and `fetchit-core` import it without a reverse dep):

```rust
// crates/fetchit-trust/src/lib.rs
pub trait DenylistQuery: Send + Sync {
    fn is_blocked(&self, kind: EntryKind, value: &str) -> bool;
}
```

`fetchit-core` uses it via an injected callback:

```rust
// crates/fetchit-core/src/handler.rs
use fetchit_trust::DenylistQuery;

pub struct RenderingContext {
    pub denylist: Option<Arc<dyn DenylistQuery>>,
}

impl HandlerRegistry {
    pub fn render_with_context(&self, bytes: &[u8], ctx: &RenderingContext) -> Rendition;
}
```

`fetchit-trust-client::DenylistConsumer` implements `DenylistQuery`
directly so the desktop / Android shells inject the consumer Arc straight
into both `fetchit-chat` and `fetchit-core` rendering contexts.
`fetchit-core` stays stateless: it doesn't fetch the denylist itself, it
just queries the injected impl when present.

### Card population

`card.rs::extend_with_fetchit_fields` gains a `hints:
Option<RendezvousHintsV1>` parameter — taking the validated struct (not
a raw `Vec<String>`) so the `wss://` / length / count checks run once at
construction and the card-building path can assume valid hints. Default
callers in the desktop layer pass
`Some(RendezvousHintsV1 { relays: vec![primary_url] })`. The new Tauri
command `chat_regenerate_card_with_relays(relays: Vec<String>)` parses
the raw list into `RendezvousHintsV1` (rejects on validation failure),
rewrites the in-memory card + republishes the profile v3 manifest.

### Wiring at boot

```rust
// Client::new(...)
let denylist = Arc::new(DenylistConsumer::new(
    HARDCODED_ETCHITIO_PUBKEY,
    "https://etchit.io/v1".into(),
    Some(store.cache_dir().join("denylist")),
));
let _poll_handle = Arc::clone(&denylist).spawn_poll_loop(reqwest_client);

let multi_home = MultiHomeTransport::new(
    settings.primary_relay_url(),
    Arc::clone(&denylist),
    inbound_handler,
);

// expose for desktop layer
client.denylist_subscriber = denylist.subscribe();
client.denylist_query = Arc::clone(&denylist) as Arc<dyn DenylistQuery>;
```

## UI surfaces

### Desktop (`apps/fetchit-desktop/`)

- `src/settings/network-advanced.ts` (NEW) — Settings → Network → Advanced
  panel. "Advertise these relays in my card" editable list (default just
  primary). Add/remove + save calls `chat_regenerate_card_with_relays`.
- `src/chat/conversation-banner.ts` (modified) — listens for
  `chat:relay-denylisted` Tauri event; renders a banner "Your current
  relay was just added to the safety denylist. Reconnecting to an
  alternative." + automatic switch.
- `src/chat/contacts-list.ts` (modified) — when a contact's `agent_id`
  is blocked, render a blocked indicator next to the contact + tooltip.
  Contact stays visible (user needs to know who's blocked) but the
  message composer disables for that contact.
- `src/renderers/dispatch.ts` (modified) — handle new
  `Rendition::Blocked { reason }` variant with a safety-blocked placeholder
  card (consistent with etch>it/fetch>it safety design language).

### Android (`apps/fetchit-android/`)

Parity surfaces in Kotlin: Settings Advanced screen, conversation banner,
contacts denylist indicator, `RenditionRenderer.kt` Blocked branch.

## Bob convergence — EntryKind co-author

A single chat-pipe round-trip when this spec lands (today, in parallel with
this doc):

1. Alice sends Bob the proposed `EntryKind` enum + the `value_hex` →
   `value` rename + the signature shape (same hardcoded etchit-io ML-DSA-65
   pubkey signs all four kinds for v1.0).
2. Bob confirms / pushes back. We lock both variants + the field rename.
3. Whichever of us touches `fetchit-trust::types` first lands BOTH variants
   + the field rename in ONE commit. The other adds consumer code only.
   No two-commit interleave.

Outcome locked in this spec: **option (A) — rename `value_hex` to `value`,
plain String, kind-driven validation.**

## Test plan

### Unit (~50 tests)

**`fetchit-trust-client` (~20):**
- Signature verify good / bad / pubkey mismatch.
- Kind filter — only matching-kind entries land in the matching index.
- Index integrity (add/remove/replace).
- BlockEvent emission on additions, removals, and same-snapshot replays
  (BlockEvent.added.is_empty() when re-applying same response).
- Disk persistence round-trip — write good response, restart, read back.
- Offline boot — no network, only disk cache available, queries still work.
- Malformed response handling — bad JSON / missing fields / oversized
  payload → preserve previous index, return error.
- Concurrent refresh + lookup (multi_thread tokio runtime).

**`fetchit-chat::transport::MultiHomeTransport` (~15):**
- Slot init opens slot 0 to primary.
- Send to primary uses slot 0.
- Send to non-primary opens slot 1, then slot 2, then evicts LRU of slots 1-2.
- Slot 0 is never evicted.
- Inbound dedup: first envelope passed through, duplicate dropped.
- Distinct nonces preserved.
- Bounded LRU bounds — over capacity, oldest expires.
- Denylist hard-block on outbound `RelayUrl` returns Blocked.
- Denylist hard-block on outbound `AgentId` returns Blocked.
- Denylist mid-session: emit BlockEvent for RelayUrl matching an open slot,
  slot closes within one event-loop tick.
- Sender-card-missing `v2_rendezvous_hints` defaults to slot 0.

**`card.rs::RendezvousHintsV1` (~5):**
- v=1 decode round-trip.
- Empty `relays` rejected.
- Oversized URL rejected (>256 chars).
- >8 entries rejected.
- Non-`wss://` scheme rejected.
- Forward-compat: v=2 unknown payload preserved by outer card decoder.

**`fetchit-core::Rendition::Blocked` (~3):**
- `RenderingContext` with denylist that matches a XorName short-circuits
  to `Rendition::Blocked`.
- `RenderingContext` with no denylist behaves identically to existing
  `HandlerRegistry::render`.
- Bytes that would otherwise hit `BinaryHandler` get blocked when listed.

### Integration (3 tests)

- `crates/fetchit-chat/tests/m3_multi_home_basic.rs` — 3-agent topology,
  slots fill correctly under traffic, dedup works across slots.
- `crates/fetchit-chat/tests/m3_multi_home_denylist.rs` — in-memory denylist
  injection (no HTTP), assert hard-block enforcement on outbound + inbound
  + active-slot drop on mid-session add.
- `crates/fetchit-chat/tests/m3_card_rendezvous_hints.rs` — sender consumes
  recipient card's relays list to pick a session.

### Live (`#[ignore]`'d)

- `crates/fetchit-chat/tests/m3_live.rs` — Alice@NY ↔ Bob@FRA ↔
  Charlie@NY 3-agent test. Slot 0 = primary, slot 1 dynamically opens.
  Mid-test denylist update: shorten poll to 60s, add an agent to a
  test-denylist endpoint, assert clients enforce within 90s.

## Migration / rollout

The M3 changes are **additive against the existing chat wire**:
- `RendezvousHints v=1` lives inside the existing reserved `v2_rendezvous_hints`
  slot — v1 readers ignore unknown hint payloads (per `card.rs` docstring).
- `MultiHomeTransport` is a wrapper; existing `RelayTransport` keeps its
  current shape and its call sites.
- Denylist consumer is a new component; absence of the etchit.io pubkey
  / endpoints just leaves the indexes empty (fail-open on unavailability,
  fail-closed on poisoning).

Older clients without M3 keep talking to a single relay, oblivious to
the multi-home reach. They miss federation benefits but aren't broken.

**Server-side rollout:** the etchit.io `/v1/denylist?kind=...` endpoint
must publish all four kinds before clients ship M3, OR clients must
tolerate 404 / empty per-kind responses without erroring. We choose the
latter (tolerate empty) so client and server rollouts decouple.

## v1.1 follow-ups (out of scope for M3)

- **Multisig migration.** Trigger: ≥2 community operators publish their
  own denylists and we want K-of-N convergence. Implementation: roster
  as signed config, K-of-N signature aggregation in `DenylistResponse`,
  client verifies aggregated signature against current roster.
- **Multi-relay reachable-IN.** Card advertises >1 relay; client
  maintains sessions to all advertised so primary-down doesn't equal
  unreachable.
- **Outbound fan-out.** Today sends via first matching relay; v1.1
  tries N candidates concurrently for tail-latency improvement.
- **Per-`ReportKind` block differentiation.** Today hard-blocks
  everything; v1.1 soft-warns for low-confidence categories (Spam,
  Other) with user override.
- **Region picker upgrade.** Settings → Network already has a region
  picker; v1.1 lets users pick a community relay directly from there
  without the Advanced detour.

## Cross-references

- `private/relay-federation-note.md` — source threat model + Decision
  1/2/3 rationale.
- `MILESTONES.md` §M3 — launch gate.
- `crates/fetchit-chat/src/card.rs:62` — `v2_rendezvous_hints` slot
  reserved at `ef6d054`.
- `crates/fetchit-trust/src/types.rs` — `EntryKind` enum + `DenylistResponse`
  current shape.
- `crates/fetchit-relay-server/src/` — denylist publisher (already
  signs responses).
- M4 impl plan (Bob, commit `cd86cab`) — Stage 4 adds `ActorUrl`
  consumer + `MastodonBlocklistConsumer` against the same enum.
