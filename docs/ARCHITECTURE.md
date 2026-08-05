# Architecture

The tracked, lean architecture reference for fetch>it: the WHY and HOW of each
crate and shell, and the SEAMS between them. It is deliberately small. The
exhaustive facts (handler set + order, the `Rendition` variants, the crate
list, the pins) are LOCKED by tests and generated files; this document links to
those rather than restating them, because a restatement is a drift surface.

## Truth rules

- **Cite by symbol, never by line.** Entry points are rustdoc-style backticked
  paths (`crate::module::Symbol`); line numbers are a drift generator and are
  banned here.
- **Link, do not restate.** No exhaustive type/variant/file enumerations. When
  a fact is locked by a tripwire test or a generated file, the section's
  **Locked by** line points at it; that is the source of truth, not this prose.
- **Stamp + detector contract.** Every section ends with a machine-readable
  `<!-- arch: id=.. glob=.. verified=.. -->` stamp. `scripts/check-arch-stamps.sh`
  parses it and warns when files under `glob` changed since the `verified`
  commit, meaning that section needs re-verification and a bumped stamp.
- **No private or strategic content.** Roadmap, revenue, unshipped plans, and
  any private-folder material never live here. This file describes code that
  exists in the tree.
- **Upstream is WithAutonomi.** `ant-core` tracks `github.com/WithAutonomi`, not
  the older maidsafe repos.

## Overview

The shape is **engine + backend + shells**. `fetchit-core` is a pure, no-I/O
engine: it validates an `Address`, a `NetworkClient` fetches bytes, and a
`HandlerRegistry` turns them into a typed `Rendition` that every UI shell
dispatches on. `fetchit-net` is the production network backend; the CLI,
Android, and desktop shells are thin consumers; a chat + relay + trust + fedi
stack layers messaging and moderation on top. fetch>it is **read-only**: it
never holds a wallet, never signs Autonomi uploads, never writes content (the
wallet lives in the sibling etch>it). To onboard, read in order: `fetchit-core`,
`fetchit-net`, `fetchit-ffi`, then a shell.

**Key entry points:** `fetchit_core::Address`, `fetchit_core::NetworkClient`,
`fetchit_core::HandlerRegistry`, `fetchit_core::Rendition`.

<!-- arch: id=overview glob=crates/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-core (engine)

The engine half: zero network, zero filesystem, zero persistent state. It
defines the abstractions backends and shells share, so rendering stays
independent of storage and transport. `ContentHandler`s classify head bytes
(`can_handle` returns a `Confidence`) and produce a `Rendition`; the
`HandlerRegistry` picks the best handler per fetch. The load-bearing invariant
is that **registration order breaks confidence ties** (specific handlers first,
binary fallback last), so handler ordering is a deliberate design choice, not an
accident. Handlers are forbidden from filesystem, network, state, and
`unwrap`/`expect` outside tests; the ban is enforced by the workspace `[lints]`
in the root `Cargo.toml` (`unsafe_code = "forbid"`, unwrap/expect/panic warned)
plus the read-only `ContentHandler` method signatures.

**Key entry points:** `fetchit_core::ContentHandler`,
`fetchit_core::Confidence`, `fetchit_core::HandlerRegistry`,
`fetchit_core::handlers::default_registry`.
**Locked by:** handler set + registration order:
`crates/fetchit-core/tests/doc_invariants.rs`; `Rendition` variant set (an
in-crate exhaustive-match tripwire, because `Rendition` is `#[non_exhaustive]`):
`rendition_variants_match_snapshot` in `crates/fetchit-core/src/handler.rs`;
tie-break behavior: `ties_broken_by_registration_order` in
`crates/fetchit-core/src/registry.rs`.

<!-- arch: id=fetchit-core glob=crates/fetchit-core/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-net (Autonomi backend)

The production `fetchit_core::NetworkClient` over the Autonomi P2P network,
isolating the `ant-core` / `self_encryption` dependency weight from the engine
and lighter shells. Connecting uses a **bootstrap-warmup**: it returns as soon
as one peer connects or after a 10 s deadline, so an interactive viewer is never
blocked on full DHT bootstrap. The load-bearing behavior is **hierarchical
data-map resolution** via `self_encryption::get_root_data_map_parallel`:
`ant-core`'s download path does not walk shrunk (child) data maps, so without
this step large content silently returns garbage.

**Key entry points:** `fetchit_net::AutonomiClient`,
`fetchit_net::AutonomiClient::connect`, `fetchit_net::DEFAULT_PEERS`.
**Locked by:** `DEFAULT_PEERS` is a verbatim copy of WithAutonomi/ant-node's
bootstrap list (kept in sync by hand, with the source noted in
`crates/fetchit-net/src/peers.rs`).

<!-- arch: id=fetchit-net glob=crates/fetchit-net/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-ffi (uniffi)

The uniffi FFI surface that exposes `fetchit-core` + `fetchit-net` to
Kotlin/Swift, plus the daemonless chat surface the Android shell drives. Free
functions export via `#[uniffi::export]`; a `#[uniffi::Object] Client` wraps
`AutonomiClient` with async methods, and a `RenditionFFI` enum maps each
`fetchit_core::Rendition` variant for host-language pattern-matching. A second
`#[uniffi::Object] ChatClient` is the daemonless `fetchit-chat` surface: DMs are
signed by a local ML-DSA-65 vault signer with no separate daemon, while group
TreeKEM (the x0xd `/secure` surface) is served by an x0xd embedded in-process. It
carries the DM outbox (`enqueue_dm`, `start_outbox`, `outbox_snapshot`,
`retry_outbox`) plus a group create/join/send/moderate surface, and drains
`ChatEventFfi` (incl. `Outbox` bubbles) through one `next_event` pump. This crate is
**workspace-excluded** (its own `Cargo.lock`) because `uniffi-bindgen` walks
transitive deps and fails its metadata lookup silently inside a multi-crate
workspace; the reason is recorded in its `Cargo.toml`. The `.so` and the
generated Kotlin bindings must be built together from the matching
`uniffi-bindgen` version or the API-checksum check crashes the host app at
launch.

**Key entry points:** `fetchit_ffi::Client`,
`fetchit_ffi::Client::fetch_and_render`, `fetchit_ffi::RenditionFFI`,
`fetchit_ffi::ChatClient`, `fetchit_ffi::setup_logger`.
**Locked by:** uniffi pin: `PINS.md` + `scripts/check-pins.sh`.

<!-- arch: id=fetchit-ffi glob=crates/fetchit-ffi/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-cli

The `fetchit` binary: a thin driver over `fetchit-core` + `fetchit-net` used to
ground-truth handler behavior and the live fetch path. `detect` runs the default
registry on local file bytes with no network; `get` performs the full Autonomi
flow and renders the resulting `Rendition`. It is the smallest consumer of the
engine and the fastest way to reproduce a handler dispatch in isolation.

**Key entry points:** `fetchit_cli::Cli`, `fetchit_cli::Command`.
**Locked by:** the handler set it dispatches:
`crates/fetchit-core/tests/doc_invariants.rs`.

<!-- arch: id=fetchit-cli glob=crates/fetchit-cli/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-chat

The chat client engine. It discovers the local x0xd daemon for identity and
signing, opens the relay WebSocket, and routes outbound DMs through a
transport-agnostic stack with reachability-based ordering and fallback. The
load-bearing invariants: every outbound envelope is **sealed** before it leaves
the conversation layer, and inbound envelopes from blocked senders are dropped
at the dispatcher (the denylist gate) before reaching any handler. Outbound DM content rides the Router, which picks among its transports
by reachability (LAN-direct when the peer shares the network, the
always-available relay otherwise). Group MLS control-plane events do not use this
Router: they ride x0xd gossip as primary with the relay only as a cross-NAT
contingency (`crate::groups_reachability`). A durable, vault-persisted **DM
outbox** (`crate::outbox`) owns resend: a presence-edge retry loop, a
clock-driven retry (`OutboxDriver::flush_due`) that re-attempts every
relay-unacked bubble on a bounded per-bubble backoff so a message never
depends on a presence edge that may never arrive, a stalled-claim sweep, a
boot/restart claim reclaim, and a double-send guard, surfaced as
`OutboxEvent`s so both shells render one shared delivery state. A retry
carries no routing state forward -- the bubble stores the recipient's agent
id and body only, so every attempt re-resolves the recipient's devices and
relay hints and re-walks the transport chain from the top.
That state is a truthful four-step machine (`crate::send_state::SendState`):
**queued** (in the outbox, retried indefinitely -- a dropped socket or a lost
ack never reads as failure), **sent** (a relay acked durable acceptance, the
only transition into it), **delivered** (a `DeliveryReceipt` attributed
receipt), and **failed**, reserved for verdicts no retry can change
(`SendFailure::classify`: denylisted recipient, unsealed-envelope caller
error). Both the bubble and the persisted `HistoryEntry` carry the state plus
its transition timestamp, and a listing folds the live outbox over the
transcript (`outbox::overlay`) so a message is only ever as far along as its
least advanced copy. Group receive
additionally runs **missed-message detection** (`crate::conversation::seq_gap`):
senders seal a monotonic per-group counter inside the encrypted frame and the
receive-side ledger flags a skipped one as a gap (detection only; recovery
layers on top). **Sibling-device admission** (`crate::sibling_admission`) lands a
user's other devices in a group they join with zero UI -- the sibling mints its
own per-group `TreeKEM` `KeyPackage` and an already-in-group device verifies the
request chains to the account and admits it via x0xd's invite-free direct-add.

**Key entry points:** `fetchit_chat::Client`, `fetchit_chat::ClientBuilder`,
`fetchit_chat::Client::enqueue_dm`.
**Locked by:** wire types it sends: `crates/fetchit-relay-proto/**`; denylist
schema it gates on: `crates/fetchit-trust-types/**`.

<!-- arch: id=fetchit-chat glob=crates/fetchit-chat/** verified=bb7a046 -->
_Last verified: 2026-08-04 (`bb7a046`) -- bob._

## fetchit-relay-proto

The wire-protocol types shared by the relay server and clients, encoded with
postcard for compact binary frames. The relay sees only routing metadata
(sender, recipient, timestamp, signature); the body is ciphertext. The
load-bearing design is **forward compatibility**: `EnvelopeKind`, `Capability`,
and `FeatureFlag` each carry an `Unknown` shim so a relay or peer can round-trip
or skip a variant it does not recognize without breaking signature verification
or the session. `WIRE_VERSION` gates accepted frames during version transitions.

**Key entry points:** `fetchit_relay_proto::TransitEnvelope`,
`fetchit_relay_proto::EnvelopeKind`, `fetchit_relay_proto::WIRE_VERSION`.

<!-- arch: id=fetchit-relay-proto glob=crates/fetchit-relay-proto/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-relay-server

The operator-run relay: it routes opaque envelopes between connected clients
over WebSocket and buffers undelivered ones under a hard TTL -- in RAM by
default, or in an operator-selected durable `SQLite` store
(`FETCHIT_RELAY_TRANSIT_DB`) so a recipient's messages survive a relay restart
and a multi-day offline window. Either way the relay holds only opaque
ciphertext and never inspects the payload (stays blind); at-rest protection is
the operator's full-disk encryption, not relay-side. A parallel durable
group-log store keeps opaque per-group records (payload opaque; each record
stamped with its authenticated appender as provenance) for epoch catch-up, join-result
re-staging, and cold group reconstruction. WS upgrades authenticate with a
bearer token presented in the `Authorization` header (case-insensitive scheme). Built with the
`fediverse-inbox` feature it also hosts the
M4 ActivityPub `/inbox`, which verifies the HTTP Signature, applies the denylist
and per-actor rate limits, and fans valid posts into the relay as
`EnvelopeKind::PublicPost`. The fediverse inbox is opt-in: an operator must
enable the feature.

**Key entry points:** `fetchit_relay_server::Server`,
`fetchit_relay_server::ServerConfig`, `fetchit_relay_server::Metrics`.
**Locked by:** wire types: `crates/fetchit-relay-proto/**`.

<!-- arch: id=fetchit-relay-server glob=crates/fetchit-relay-server/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-relay-client

The client library for connecting to a relay constellation. It owns the auth
handshake, the `Hello`/`Ready` exchange, keepalive, and transparent
reconnection with backoff, so application code talks to channels that survive a
reconnect. Connection state is observable via `ConnState`; send timeouts surface
a wedged socket as an error rather than hanging. It is consumed by `fetchit-chat`
and the etch>it side for envelope delivery.

**Key entry points:** `fetchit_relay_client::Client`,
`fetchit_relay_client::ClientConfig`, `fetchit_relay_client::ConnState`.
**Locked by:** wire types: `crates/fetchit-relay-proto/**`.

<!-- arch: id=fetchit-relay-client glob=crates/fetchit-relay-client/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-trust (+ -types / -client)

The moderation stack, split three ways so readers and chat clients pull only
what they need. `fetchit-trust-types` is the leaf schema (the entry kinds and
target-identity shape); `fetchit-trust-client` fetches and verifies the signed
denylist and answers `is_blocked` queries from an in-memory index;
`fetchit-trust` adds the server-side report and signing surface. The denylist is
a JSON manifest signed by etchit-io with ML-DSA-65, refreshed on a poll
interval; the signing key is verified against a pinned public key. Per-kind
canonicalization (hex agent ids, scheme-checked relay/actor URLs) is the
load-bearing invariant so a blocked value matches regardless of formatting.

**Key entry points:** `fetchit_trust_types::EntryKind`,
`fetchit_trust_types::DenylistQuery`,
`fetchit_trust_client::DenylistConsumer`.

<!-- arch: id=fetchit-trust glob=crates/fetchit-trust*/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## x0xd-client

A slim REST client for the local x0xd daemon, with no chat-stack dependencies
so it can ship standalone. It discovers the running daemon by reading its data
directory (the `api.port` and token files) and forwards ML-DSA-65 signing to the
daemon's signing endpoint. The load-bearing behavior is **port-drift
tolerance**: x0xd rewrites `api.port` on every restart, so the client re-reads
the port file and retries rather than baking a stale port. The daemon's private
key never leaves the daemon; this client only ever holds the public half.

**Key entry points:** `x0xd_client::discover_local`,
`x0xd_client::DaemonEndpoint`, `x0xd_client::X0xdSigner`.
**Locked by:** x0xd pin: `PINS.md` + `scripts/check-pins.sh`.

<!-- arch: id=x0xd-client glob=crates/x0xd-client/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## fetchit-fedi

The ActivityPub helper crate behind the M4 bridge. It signs and verifies HTTP
Signatures, resolves `@user@instance` handles via WebFinger, and fetches actor
documents. These signatures are **classical RSA-2048** (`rsa-v1_5-sha256`), not
post-quantum and not Ed25519: the fediverse wire format is the constraint, so
the doc states it as classical so the claim matches what ships (see
`docs/honest-claims-crypto.md`). The load-bearing defense is the shared SSRF
guard (`pub mod ssrf`): every resolved host is checked against private,
loopback, link-local, and CGNAT ranges before and after redirects, on both
fediverse and other outbound dial paths.

`fetchit_fedi::avatar` fetches actor profile pictures over that same
resolver-pinned, redirect-disabled client, adding https-only, a 512 KiB body
cap, and an image `Content-Type` allowlist. It never decodes the bytes -- a
Rust image parser would add an attack surface for attacker-supplied data, so
decoding belongs to the shells' platform decoders. `fetchit_chat::fedi_avatar`
owns the bounded on-disk cache (`<root>/fedi/avatars/`, 24h refresh, 1h failure
backoff, oldest-first eviction past 32 entries / 8 MiB); avatars are
best-effort and never block or fail follow, DM, or feed.

The write half is the user's OWN picture. The shell crops, downscales and
re-encodes the photo on the device (the re-encode is what drops the EXIF);
`fetchit_chat::fedi_self_avatar` uploads it to the bridge under
`bridge-auth-v1`, publishes the resulting URL as the actor document's `icon`,
and pins a local copy. The bridge hosts the bytes itself
(`crates/fetchit-bridge-server/src/store_avatar.rs` + `routes/avatar.rs`),
serving them with the stored `Content-Type` and `nosniff`, and accepting an
upload only when the declared type is in the allowlist AND the bytes carry
that format's magic -- otherwise the endpoint would host arbitrary content
under our own domain. Nothing on the server decodes the image either.

A LIT contact linked to a fediverse identity reuses that identity's picture,
and does so **cache-only**. `ChatClient::fedi_avatar` may spawn a background
fetch on a miss and belongs to the fediverse surfaces; private surfaces call
`ChatClient::fedi_avatar_cached`, a disk read with no fetch, no spawn, and no
freshness logic. The reason is a correlation leak, not politeness: if drawing
a private row could fetch, the arrival of an end-to-end encrypted message
would appear as a request in a fediverse server's access log. Android holds
the same split in `FediAvatars` (separate in-flight / re-check lanes over one
shared bitmap cache) so a private row's re-check can never land on the
fetching call either. A stale face on a private row is the accepted cost.
The user's own picture is the one cache entry marked `pinned` and exempt from
eviction: it is drawn by those same private surfaces, which have no
cache-only way to get it back.

The read path carries the identity a social surface needs.
`fetchit_fedi::lookup::RemoteActor` decodes `name` and `summary` beside the
identity pair, and `RemotePost` carries the Note's `Mention` tags (capped at 32
per post). `fetchit_chat::fedi_profile::Client::fetch_fedi_profile` projects one
actor document into a profile card, accepting `@user@host`, `user@host`, or an
actor URL -- handle forms resolve through the denylist-gated mention path, URLs
through its URL-form twin -- and reduces the bio with `fetchit_fedi::text` so no
remote markup can reach a renderer.

`Like` / `Undo(Like)` ride the same signed-delivery shape as `Follow`.
`fetchit_chat::fedi_like` owns the driver plus a sealed, bounded liked-set
(`<root>/fedi/likes/<handle>.json.enc`, oldest-first eviction past 2000 posts)
joined against the feed when it is built. The like activity id is derived from
the post URL, so a re-send after a failed delivery is idempotent remotely and an
unlike works on a device holding no record of the original like. There are no
like COUNTS: no cheap ActivityPub source exists for a total, so v1 renders
liked-state only rather than a number the project cannot stand behind.

**Key entry points:** `fetchit_fedi::ssrf`,
`fetchit_fedi::webfinger::resolve_handle`, `fetchit_fedi::actor::fetch_actor`,
`fetchit_fedi::avatar::fetch_avatar`, `fetchit_fedi::lookup::RemoteActor`,
`fetchit_fedi::activity::build_like`,
`fetchit_fedi::signature::HttpSignatureKey`.

<!-- arch: id=fetchit-fedi glob=crates/fetchit-fedi/** verified=e771309 -->
_Last verified: 2026-08-05 (`e771309`) -- bob._

## Android shell

A native Kotlin/Gradle single-activity app: the read-only Autonomi content
viewer plus the LIT chat shell, wrapping `fetchit-core` + `fetchit-net` + the
daemonless `fetchit-chat` `ChatClient` through the uniffi JNI layer.
`RenditionRenderer` dispatches the FFI rendition enum into per-type views (HTML,
PDF, audio, video, images, archives, tabular, syntax-highlighted text). The chat
side (`chat/ChatController`, `chat/ChatModeView`) drains `ChatEventFfi`, projects
the engine DM outbox into per-bubble send status
(`ConversationStore.upsertOutbox`), and drives group create/join, the group
thread, and member moderation. The load-bearing security invariant is in the
HTML WebView: **DOM storage is disabled** (`domStorageEnabled = false`) because
every fetched page shares one synthetic origin, so a shared `localStorage` would
leak across SPAs; SPAs must treat DOM storage as optional. The generated uniffi
bindings under `apps/fetchit-android/app/src/main/java/uniffi/` are regenerated,
not hand-edited.

**Key entry points:**
`apps/fetchit-android/app/src/main/java/io/etchit/fetchit/MainActivity.kt`,
`apps/fetchit-android/app/src/main/java/io/etchit/fetchit/RenditionRenderer.kt`,
`apps/fetchit-android/app/src/main/java/io/etchit/fetchit/chat/ChatController.kt`.

<!-- arch: id=android glob=apps/fetchit-android/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## Desktop shell (Tauri 2)

A Tauri 2 app: a vanilla TS + Vite frontend over a thin Rust backend on
`fetchit-core` + `fetchit-net` (plus the chat/relay/trust stack). It registers
the `fetchit://` and `autonomi://` URI scheme protocols and, because WebKit
ignores custom schemes for `<video>`/`<audio>`, also runs a local `127.0.0.1`
HTTP media server on a random port to serve those bytes. The frontend
`renderers/` mirror the core handler set in TS. The backend crate is
**workspace-excluded** so Tauri's dep tree does not bloat root cargo, and it
re-states the safety `[lints]` block locally so the security claims stay
enforced. It bundles a pinned x0xd via `build.rs`.

**Key entry points:** `apps/fetchit-desktop/src-tauri/src/lib.rs`,
`apps/fetchit-desktop/src/controller.ts`,
`apps/fetchit-desktop/src-tauri/src/settings.rs`.
**Locked by:** bundled x0xd + relay-region pins: `PINS.md` +
`scripts/check-pins.sh`.

<!-- arch: id=desktop glob=apps/fetchit-desktop/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## Browser extension

A plain MV3 extension with no build step (load the directory unpacked). A
service worker plus a content script provide a context-menu entry and an omnibox
keyword that route `autonomi://` addresses to the desktop app. The address
parser is factored into its own module so the same logic is unit-tested in CI.
Chrome and Firefox manifests are both kept valid.

**Key entry points:** `apps/fetchit-web/manifest.json`,
`apps/fetchit-web/src/background.js`, `apps/fetchit-web/src/addr.js`.

<!-- arch: id=web glob=apps/fetchit-web/** verified=f9b9e98 -->
_Last verified: 2026-06-14 (`f9b9e98`) -- bob._

## Fediverse edge worker (Cloudflare)

A Cloudflare Worker that fronts the M4 ActivityPub bridge on the `etchit.io`
zone (decision DP2), so the pretty handle `@<h>@etchit.io` resolves to the
bridge's canonical actor documents without moving the static marketing site off
GitHub Pages. It is route-bound to ONLY the fediverse paths (WebFinger, actor
docs + collections, the `/v1/actors` register/rotate writes, and the avatar
route) and reverse-proxies them to `BRIDGE_ORIGIN`; every other path falls
through to GitHub Pages and never reaches the Worker. The load-bearing guard is
`classify()`, which pins the HTTP method per path so the route wildcards
(needed so query-bearing WebFinger requests match) widen the route, not the
proxy -- no open-proxy risk. Two `/actors/<h>/...` paths carry their own
methods: `/inbox` (POST, inbound federation) and `/avatar` (public GET plus
owner-authenticated POST/DELETE, which the bridge gates itself).

**Key entry points:** `apps/fetchit-bridge-worker/src/worker.js`,
`apps/fetchit-bridge-worker/wrangler.toml`.

<!-- arch: id=bridge-worker glob=apps/fetchit-bridge-worker/** verified=8197a79 -->
_Last verified: 2026-08-05 (`8197a79`) -- bob._

## CI / release

CI enforces the safety bar and the doc gates on every push and PR. `ci.yml` runs
`fmt`, `clippy` (with `-D warnings`), and `test` across Linux/macOS/Windows,
plus a `pins` job, a `licenses` job (cargo-deny license compliance across all
three lockfiles), a `docs-gates` job (crate-list, doc-path, stale-phrase, and
an informational ARCHITECTURE.md-stamp check), desktop and web-extension jobs,
and an Android debug-APK build (FFI to
cargo-ndk to uniffi-bindgen to gradle). `release.yml` triggers on `v*` tags and
produces a signed APK. The workspace-excluded crates are clippy/fmt-checked via
explicit manifest paths so they are not silently skipped.

**Key entry points:** `.github/workflows/ci.yml`,
`.github/workflows/release.yml`.
**Locked by:** the gates these jobs run: `scripts/check-crate-list.sh`,
`scripts/check-doc-paths.sh`, `scripts/check-stale-phrases.sh`,
`scripts/check-pins.sh`, `scripts/check-arch-stamps.sh`.

<!-- arch: id=ci glob=.github/workflows/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## Production invariants

The cross-cutting promises the whole tree must keep. fetch>it is **read-only**:
no wallet, no Autonomi signing, no content writes (non-wallet writes like chat
are a separate stack, but Autonomi publishing never happens here). Rendered HTML
runs under one synthetic origin, so DOM storage is treated as cross-SPA-leaky
and disabled. Relay servers hold only opaque envelope ciphertext (never the
plaintext) under a TTL -- in RAM, or in an operator-selected durable store that
keeps that ciphertext on disk across a restart, with at-rest protection
delegated to operator full-disk encryption. Forward-compatibility shims (`Unknown` variants) and the pinned wire
deps together protect historical messages from a silent format break. The lints
ban (`unsafe_code` forbidden; unwrap/expect/panic warned) holds even in the
workspace-excluded crates, which re-state it locally.

<!-- arch: id=production-invariants glob=crates/** apps/** verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._

## Pinned dependencies

A small set of deps bumps only deliberately, in lockstep across the
etch>it / fetch>it trinity, because each is wire-level: a silent bump can stop
historical messages from decrypting or break address resolution. `ant-core`
(WithAutonomi) is pinned by git rev; `self_encryption` and `xor_name` to exact
versions; `saorsa-pqc` to its minor; `uniffi` to an exact version that must
equal the `uniffi-bindgen` CLI; plus the out-of-tree x0xd pin and the relay
region defaults. `PINS.md` is the source of truth and the check fails CI on any
drift.

**Key entry points:** `PINS.md`, `scripts/check-pins.sh`.
**Locked by:** `scripts/check-pins.sh` (the `pins` job in
`.github/workflows/ci.yml`) asserts `Cargo.toml` / `Cargo.lock` against
`PINS.md`.

<!-- arch: id=pins glob=PINS.md Cargo.lock verified=6321a28 -->
_Last verified: 2026-07-08 (`6321a28`) -- bob._
