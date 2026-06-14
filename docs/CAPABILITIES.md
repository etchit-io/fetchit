# CAPABILITIES -- what's already built

> **Read this before calling anything missing, a gap, or "to build."** It is the
> code-anchored index of capabilities that already ship, so we stop re-discovering
> features we already wrote. Faster path: `scripts/whats-built.sh <keyword>`.
>
> **Contract**
> - Every entry cites a `file:symbol` you can open right now. If you can't anchor
>   it to code, it does not belong here.
> - Each subsystem section ends with an `<!-- arch: ... -->` stamp.
>   `scripts/check-arch-stamps.sh` warns when a section's implementing files have
>   changed since its stamped commit: re-verify the entries, then bump `verified=`.
> - **Branch caveat:** this describes the current (`chat`-line) tree. A capability
>   may live on an unmerged branch; those are flagged inline as `[branch: NAME]`.
>   `whats-built.sh` and your checkout only see the current branch, so also check
>   `git branch -a` and ask the other box (Alice / Bob) before concluding absence.
> - Seeded with the subsystems that kept getting re-discovered (chat reliability,
>   engine, shells). Extend other subsystems only with anchors you have opened.

## Engine core (read-only render pipeline)

- Stateless flow `address -> NetworkClient::fetch -> bytes -> HandlerRegistry::render -> Rendition` -- `crates/fetchit-core/src/network.rs:25` (`NetworkClient`), `registry.rs:30` (`HandlerRegistry`), `handler.rs:87` (`Rendition`), `handler.rs:246` (`ContentHandler`).
- Autonomi network client, the only crate linking `ant-core`/`self_encryption` -- `crates/fetchit-net/src` (`AutonomiClient`).

<!-- arch: id=engine-core glob=crates/fetchit-core/src/network.rs crates/fetchit-core/src/registry.rs crates/fetchit-core/src/handler.rs crates/fetchit-net/src verified=2eea972 -->

## Chat -- delivery and reliability

- Per-message delivery state **Sending / Delivered / Not delivered**: recipient emits `EnvelopeKind::DeliveryReceipt` via `build_receipt_outbox` (`crates/fetchit-chat/src/conversation/outbound.rs:225`), sender binds it with `Conversation::apply_delivery_receipt` (`conversation/types.rs:291`), desktop UI is `BubbleStatusTag` (`apps/fetchit-desktop/src/chat/bubble.ts:249`).
- **DM resend** (the client carries retention past the relay TTL): an offline->online edge re-sends in-flight/failed bubbles, a 24h sweep flips stuck sends to an honest "failed", survives app restart, double-send-guarded -- `apps/fetchit-desktop/src/chat/outboxDriver.ts:57` (`startOutboxDriver`). **Desktop TS only -- NOT in the shared engine, so Android cannot inherit it. Lifting it into `fetchit-chat` so both shells share one loop is in design `[branch: outbox-lift]`.**
- Relay **transit buffer** (RAM-only, hard 15-min TTL, fire-and-forget), drained on every WS reconnect -- `crates/fetchit-relay-server/src/transit.rs:37` (`TransitBuffer`, `drain` at :83); replay at connect in `crates/fetchit-relay-server/src/ws.rs:94` (`replay_transit` at :398). No cursor/since/inbox query; DM catch-up is implicit on reconnect.
- Per-group **bridge consent** (default-off, per-group opt-in), encrypted at rest and persisted across restart -- `crates/fetchit-chat/src/groups_reachability.rs:144` (`BridgeConsentStore`; `load` / `flush` seal the map to `bridge/consent.json.enc` via `at_rest::seal_to_path`, fail-safe to empty on a damaged file). The prod `Client` ctor loads it; `new()` stays in-memory.
- Direct-gossip **reachability cache** (60s window, rebuilt from live gossip after restart) -- `crates/fetchit-chat/src/groups_reachability.rs` (`ReachabilityCache`, `STALE_AFTER_MS`).

<!-- arch: id=chat-delivery glob=crates/fetchit-chat/src/conversation/outbound.rs crates/fetchit-chat/src/conversation/types.rs crates/fetchit-chat/src/groups_reachability.rs crates/fetchit-relay-server/src/transit.rs crates/fetchit-relay-server/src/ws.rs apps/fetchit-desktop/src/chat/outboxDriver.ts apps/fetchit-desktop/src/chat/bubble.ts verified=6685b7e -->

## Chat -- transport and groups

- Message **content routing by reachability** (relay = Always, LAN-direct = IfReachable, future WebRTC = cross-NAT) -- `crates/fetchit-chat/src/transport/mod.rs` (`Router`, `Reachability`).
- Group **MLS control-plane** (Welcome/Commit/member changes) rides x0xd gossip as PRIMARY, relay only as a cross-NAT contingency -- `crates/fetchit-chat/src/transport/mod.rs` (does NOT use the `Router`).
- Forward-compat envelopes: the relay routes opaquely by `to` (`SendFrame.envelope_bytes`) and peers round-trip unrecognized kinds (`EnvelopeKind::Unknown(u8)`) -- `crates/fetchit-relay-proto/src/envelope.rs`.

<!-- arch: id=chat-transport glob=crates/fetchit-chat/src/transport crates/fetchit-chat/src/groups crates/fetchit-relay-proto/src/envelope.rs verified=2eea972 -->

## Fediverse bridge (M4 / M5.1)

- HTTP Signatures use **classical RSA-2048 + PKCS#1 v1.5 + SHA-256** (`rsa-v1_5-sha256`), NOT Ed25519 and NOT post-quantum -- `crates/fetchit-fedi/src/signature.rs`. The PQ binding is the ML-DSA-65 attestation in the Actor JSON-LD, not the per-POST signature. Crypto source of truth: `docs/honest-claims-crypto.md` §3.

<!-- arch: id=fedi-sig glob=crates/fetchit-fedi/src/signature.rs docs/honest-claims-crypto.md verified=2eea972 -->

## Shells

- **Desktop** (Tauri 2): full reader plus the chat/relay/trust stack -- entry `apps/fetchit-desktop/src/controller.ts`, render dispatch `apps/fetchit-desktop/src/renderers/dispatch.ts`, backend `apps/fetchit-desktop/src-tauri/`.
- **Android** (merged on `chat`): read-only Autonomi viewer ONLY -- FFI exports `Client::{connect,fetch,fetch_and_render}` + `detect` (`crates/fetchit-ffi/src/lib.rs`), renders via `RenditionRenderer.kt`. No chat stack on this branch.
- **Android chat** `[branch: android-lit]` (worktree `fetchit-android-lit`): daemonless chat FFI (LocalSigner `ChatClient`), P0+P1+P1.1 built and gated, **not merged**; no DM catch-up yet. When it merges, DM catch-up parity with desktop becomes a live lane (task #42). [provenance: Bob; not verifiable from `chat`.]

<!-- arch: id=shells glob=crates/fetchit-ffi/src/lib.rs apps/fetchit-desktop/src/controller.ts apps/fetchit-desktop/src/renderers/dispatch.ts verified=2eea972 -->
