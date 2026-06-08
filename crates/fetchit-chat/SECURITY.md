# LIT Chat — security model

This document names the security caveats that ship with LIT Chat.
It is load-bearing: the in-app "About Chat" screen, and any "is this
secure?" question all resolve to the text below.

If a claim in the announcement or the UI contradicts something here,
the claim is wrong — fix the claim, not this document.

> **Scope.** This file covers the *chat* surface only. The reader
> surface — iframe sandbox, host process, on-disk cache, neutered
> web APIs — is documented in
> [`docs/SECURITY.md`](../../docs/SECURITY.md). If the two appear
> to disagree, both are bugs; report the divergence via the channel
> in [Reporting](#reporting-a-security-issue) below.

## The threat model in one paragraph

LIT Chat protects message **contents against the relay operator** on
the relay path (every outbound is sealed end-to-end before the relay
sees it) and protects contents + metadata against passive wire
observers on the LAN-direct path. It does **not** hide who-talks-to-
who from the relay (the contact graph is observable in flight, RAM
only, 15-min TTL). The relay is our own AGPL-3.0-only code
(`fetchit-relay-server`) and you can self-host it.

## Closed at M2

The two compromises that v1 documented for M2 closure shipped on the
`chat` branch on 2026-06-02:

### 1. Relay sees envelope contents — CLOSED

Until M2, callers that didn't supply a prebuilt sealed
`TransitEnvelope` triggered a fabricated v1 send path
(`fabricate_v1_envelope`) that forwarded payload bytes as plaintext
`TransitEnvelope.ciphertext` with empty `nonce`, `kem_ciphertext`,
and `sender_signature`. M2 deleted that function entirely
(commit `14941db`). `RelayTransport::send` now requires
`transit: Some(_)` and returns `ChatError::SealedRequired` otherwise.
`TransitEnvelope.version` bumped 2 → 3 (commit `a5646f2`) so there
is no unsealed wire shape left; relay-server inbound accepts both v2
and v3 during the transition window and v3-only sends emit.

The relay is fetch>it's own AGPL-3.0-only code. You can run your own
(`docker-compose` template ships with the relay repo). The fetch>it-
operated relays at `67.207.94.66:8088` (NYC) and `159.89.11.217:8088`
(Frankfurt) are disclosed-centralized defaults; the user-facing
"Custom relay" setting lets any user point at their own.

### 2. Groups are public rooms — CLOSED for private groups; public rooms remain as labeled opt-in

Private groups now ship as PQ TreeKEM via x0xd v0.20.x's MLS surface
(`preset=private_secure` + `discoverability=Hidden`), which the
daemon backs with `saorsa-mls v0.3.x` (ML-KEM-768 + ML-DSA-65 +
ChaCha20-Poly1305 + BLAKE3 — pure PQ, RFC-9420-subset wire format).
The chat layer consumes `secure::create_private_secure`,
`secure::encrypt`, `secure::decrypt` from `x0xd-client::secure`
(commits `282aeb9..a1fe9f5`), and `messages::Endpoint::send_private_group`
+ `receive_private_group_envelope` (commits `07abb78` + the fix-up
batch `b7730d4..2bb35e1`) wrap them end-to-end:

- `send_private_group` encrypts via x0xd, postcards the
  `EncryptedFrame` into `TransitEnvelope.ciphertext`, ML-DSA-65 signs
  the canonical envelope, queries x0xd's
  `GET /groups/<id>/members` roster, and fans out one envelope per
  member (excluding self) through `RelayTransport`.
- `receive_private_group_envelope` ML-DSA-65 verifies
  `env.sender_signature` against the cached card pubkey BEFORE the
  decrypt round-trip (so a forged envelope fails before x0xd is
  contacted), then runs decrypt, then `check_and_record_nonce` +
  `push_history` atomically inside `ConversationRegistry::mutate_in_place`
  so a captured envelope replayed twice produces exactly one history
  entry.
- The chat-peer inbound dispatcher (`bin/peer.rs`) filters self-
  source envelopes before routing to the private-group decoder, so a
  sender's own fanout doesn't double-count on loopback.
- The desktop create-group dialog defaults to "Private group
  (PQ-encrypted via x0x MLS)" with "Public room (plaintext on relay)"
  as a labeled opt-in (commit `b783ce9`). Public rooms keep the v1
  `public_open` plaintext path explicitly.

A startup-time gate refuses to operate against x0xd older than v0.20.1
(commit `c70a73c`); v0.20.0 over-included TreeKEM activation, v0.20.1
narrowed correctly.

**Honest-claim caveat we mirror from upstream:** the underlying
`saorsa-mls` README still self-flags as upstream-prototype ("Do not
use this crate to protect sensitive data in production systems"). We
ship what upstream ships and harden in tandem — our copy mirrors
that framing rather than overclaim "audited final crypto." We are
also NOT IETF `draft-ietf-mls-pq-ciphersuites` wire-compatible;
saorsa-mls is an RFC-9420 *subset* with PQ primitives substituted in,
not the IETF PQ codepoint. LIT Chat does not need cross-vendor MLS
interop for v1.0.

**What is NOT yet live-verified:** a cross-internet Alice↔Bob private-
group round-trip against the production NY relay has not yet run
end-to-end. The test scaffold landed (`crates/fetchit-chat/tests/m2_live.rs`,
`#[ignore]`'d, commit `5aa61da`); running it three times in a 24h
window against both rigs is the close-gate for "M2 verified," distinct
from "M2 implementation shipped."

## Remaining caveats

### 3. LAN-direct send path now matches the relay sealed-only contract

Closed. `LanDirectTransport::send` and the `materialise_transit`
helper now refuse `OutboundEnvelope { transit: None, .. }` with
`ChatError::SealedRequired { caller: "LanDirectTransport::send" }`
before any TCP connect or Noise XX handshake runs. The v1 fabricate
branch (epoch=0, empty signature/nonce/kem_ciphertext) is gone, so
both transports share one discipline: the conversation / group layer
is the only sanctioned producer of a `TransitEnvelope`, and a buggy
or wrong-version caller surfaces here rather than emitting an
unsealed wire shape. The sender-binding check
(`prebuilt.sender_agent_id == local_agent_id`) remains in place as
defense-in-depth against a buggy local layer.

### 4. DirectMessage.verified is honest about per-message signatures

Until 2026-05-31, the legacy `decode_direct_message` path hard-coded
`verified: Some(true)` with zero cryptographic basis. The legacy
schema (`LegacyEnvelope`) carries no per-message signature, so there
was nothing to verify. The M0 honesty PR fixed that: legacy decode
now emits `verified: Some(false)`, and the chat UI surfaces an
"⚠ unverified sender" badge under inbound bubbles where
`verified === false`.

Where the value IS truthful:

- `Some(true)` — the inbound message rode the `TransitEnvelope` path
  through `conversation::dispatch_inbound`, which performs real
  ML-DSA-65 verification (`Plan-1 Task 12` landed this).
- `Some(false)` — message lacks a per-message signature (legacy
  path) OR no sender card cached.
- `None` — outbound bubble; verification doesn't apply.

Session-level relay auth (the `auth_verify_ok_total` Prometheus
counter) authenticates the **relay session**, not individual messages.
The two are not the same; this document treats them as separate.

### 5. LAN-direct 32-byte agent-id preamble is unauthenticated

`LanDirectTransport` sends a 32-byte `agent_id` header in the clear on
TCP connect so the listener can look up the expected static Noise key
before the handshake runs. That preamble is **unauthenticated by
design** — its only job is to route the listener to the right key.
The security gate is the channel-binding signature inside Noise XX
msg2/msg3 over `(lan_binding_bytes(agent_id, x25519_pub, created_at_ms)
|| handshake_hash)`, plus the requirement that the peer already be a
contact on file.

A casual LAN scanner can observe `agent_id`s announcing on
`_fetchit-chat._tcp.local.` mDNS. They cannot impersonate one without
the matching ML-DSA-65 private key.

### 6. Per-device KEM keypair has no auto-backup (M1 closes this)

The local ML-KEM-768 keypair fetch>it generates lives in the FCV1
at-rest vault under an OS-keystore or Argon2id master key. Wiping
the x0xd data dir, reinstalling fetch>it, or moving to a new device
**loses decap of historical messages** for that identity.

M1 ships an "Export chat backup" button in Settings → Network that
exports the vault encrypted under a user-supplied passphrase, plus
an import flow on the receiving device. The KEM private key never
leaves the vault format; restore re-establishes decap continuity.

### 7. Crypto deps are pinned by git rev — drift breaks runtime

The post-quantum cryptography stack — `saorsa-pqc`, `snow`,
`ant-quic`, `x0xd`, `uniffi`, `self_encryption`, `xor_name` — is
pinned by git rev in `Cargo.toml` lockstep with the etch>it side.
`PINS.md` at the workspace root records the canonical revs and
`scripts/check-pins.sh` (wired into CI) fails the build if
`Cargo.lock` drifts.

This is not a security caveat in the conventional sense, but it is
operationally load-bearing: an unpinned upgrade to one of these
crates can land a wire-format change between releases that breaks
historical messages.

### 8. Fediverse public-post attribution is vouched by the bridge relay, not client-verified

M4 bridges inbound `ActivityPub` public posts (`Create { Note }`) into
the LIT Chat public feed. Each one rides an `EnvelopeKind::PublicPost`
envelope whose attribution lives in a `PublicPostPayload`
(`verified_actor_url`) carried out-of-band in the envelope body — **not**
the activity's self-asserted `actor` field, which is attacker-controlled.

The trust chain: a `fediverse-inbox`-enabled relay verifies the sending
instance's HTTP Signature at `POST /inbox` (proving which **instance**
delivered the activity), then canonicalises the signing actor URL
through the same `TargetIdentity::try_new(EntryKind::ActorUrl, ..)` path
the denylist uses and stamps it as `verified_actor_url`. Clients do not
fetch the instance's RSA key or see the raw HTTP Signature, so **they
cannot verify fediverse authorship themselves** — they trust the bridge
relay as the fediverse-attribution authority. That makes the WSS
client↔relay channel integrity load-bearing for this one claim. It is a
real trust boundary, not a hole: the same trust you place in any
fediverse server's rendering of who posted what, relocated to the relay
you already authenticate a session against.

`PublicPost` is the **sole** exemption from the chat sig/KEM verify
regime — its body is `application/activity+json`, not chat ciphertext,
and `sender_agent_id` is the all-zeros `FEDIVERSE_BRIDGE_SENDER`
sentinel (which the relay's directed-send path refuses as a delivery
target). `kind` drives the verify regime **and** the rendering
atomically, so a DM can never be smuggled through the exemption and a
bridged post always renders as a clearly-marked public post attributed
to `verified_actor_url`, never as a contact DM bubble. Code:
`crates/fetchit-relay-proto/src/public_post.rs`,
`crates/fetchit-relay-server/src/inbox/sink.rs`, and the `/inbox` HTTP
Signature gates in `crates/fetchit-relay-server/src/inbox/`.

## What we promise

- **fetch>it never holds a wallet, never signs Autonomi transactions,
  never writes to the network.** Read-only against Autonomi (`ant-core`
  over WithAutonomi bootstrap peers). The chat-signing path uses
  x0xd's ML-DSA-65 agent key, never an Autonomi key.
- **No telemetry from the chat surface.** Prometheus metrics on the
  relay are aggregate counters (region + version labels only) with
  no per-agent dimensions; see `private/metrics-policy.md`.
- **The relay is open source.** AGPL-3.0-only. You can read the code
  and run your own.

## What we do NOT promise

- Hiding the contact graph (who-talks-to-who) from the relay. Sender
  + recipient AgentIds are visible to the relay in flight; we keep
  no per-agent logs and the in-memory routing state has a 15-minute
  TTL, but a global passive adversary with court access to the relay
  sees the graph until M3+ sealed-sender / mix-net work.
- Direct peer-to-peer mode without a relay in the path (M2 brings
  LAN-direct; full WAN peer-to-peer remains future work).
- Cross-vendor MLS wire interop. The PQ TreeKEM is `saorsa-mls`'s
  RFC-9420-subset, not the IETF `draft-ietf-mls-pq-ciphersuites`
  codepoint.
- Client-side cryptographic verification of **fediverse** post
  authorship. Inbound bridged public posts are attributed by the bridge
  relay's HTTP-Signature check at `/inbox`, trusted transitively over
  the authenticated WSS session (see caveat 8); the client does not
  independently verify the originating instance's signature.

## Reading the code yourself

Every claim above maps to a source file or commit. Suggested reading
order:

- `crates/fetchit-chat/src/relay_transport.rs` — sealed-only send
  path (no fabricated fallback as of M2)
- `crates/fetchit-chat/src/messages.rs` — `send_private_group` +
  `receive_private_group_envelope` end-to-end shape;
  `decode_direct_message` for the legacy verified flag
- `crates/fetchit-chat/src/groups.rs` — `create_private` /
  `create` / `members` / `invite` HTTP wrappers
- `crates/x0xd-client/src/secure.rs` — typed wrappers over x0xd's
  MLS surface
- `crates/x0xd-client/src/version.rs` — the v0.20.1 minimum-version
  startup gate
- `crates/fetchit-chat/src/lan_noise.rs` — Noise XX channel-binding
- `crates/fetchit-chat/src/at_rest.rs` — FCV1 vault format
- `crates/fetchit-chat/src/conversation/inbound.rs` — the verified
  ML-DSA-65 path on the encrypted DM side
- `crates/fetchit-chat/src/conversation/registry.rs` — atomic
  mutate-in-place pattern that gates replay + history persistence

## Reporting a security issue

Please report security-impacting issues **privately** via GitHub's
private security advisory flow at
<https://github.com/etchit-io/fetchit/security/advisories/new> rather
than as a public issue. We'll acknowledge within a few days, agree on
a disclosure timeline, and credit you in the fix's release notes.

For non-security bugs, open a regular issue.
