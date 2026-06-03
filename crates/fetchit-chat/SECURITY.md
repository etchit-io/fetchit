# LIT Chat -- security model

This document names the security caveats that ship with LIT Chat.
It is load-bearing: the in-app "About Chat" screen, and any "is this
secure?" question all resolve to the text below.

If a claim in the announcement or the UI contradicts something here,
the claim is wrong -- fix the claim, not this document.

> **Scope.** This file covers the *chat* surface only. The reader
> surface -- iframe sandbox, host process, on-disk cache, neutered
> web APIs -- is documented in
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

### 1. Relay sees envelope contents -- CLOSED

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

### 2. Groups are public rooms -- CLOSED for private groups; public rooms remain as labeled opt-in

Private groups now ship as PQ TreeKEM via x0xd v0.20.x's MLS surface
(`preset=private_secure` + `discoverability=Hidden`), which the
daemon backs with `saorsa-mls v0.3.x` (ML-KEM-768 + ML-DSA-65 +
ChaCha20-Poly1305 + BLAKE3 -- pure PQ, RFC-9420-subset wire format).
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
ship what upstream ships and harden in tandem -- our copy mirrors
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

- `Some(true)` -- the inbound message rode the `TransitEnvelope` path
  through `conversation::dispatch_inbound`, which performs real
  ML-DSA-65 verification (`Plan-1 Task 12` landed this).
- `Some(false)` -- message lacks a per-message signature (legacy
  path) OR no sender card cached.
- `None` -- outbound bubble; verification doesn't apply.

Session-level relay auth (the `auth_verify_ok_total` Prometheus
counter) authenticates the **relay session**, not individual messages.
The two are not the same; this document treats them as separate.

### 5. LAN-direct 32-byte agent-id preamble is unauthenticated

`LanDirectTransport` sends a 32-byte `agent_id` header in the clear on
TCP connect so the listener can look up the expected static Noise key
before the handshake runs. That preamble is **unauthenticated by
design** -- its only job is to route the listener to the right key.
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

### 7. Crypto deps are pinned by git rev -- drift breaks runtime

The post-quantum cryptography stack -- `saorsa-pqc`, `snow`,
`ant-quic`, `x0xd`, `uniffi`, `self_encryption`, `xor_name` -- is
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
(`verified_actor_url`) carried out-of-band in the envelope body -- **not**
the activity's self-asserted `actor` field, which is attacker-controlled.

The trust chain: a `fediverse-inbox`-enabled relay verifies the sending
instance's HTTP Signature at `POST /inbox` (proving which **instance**
delivered the activity), then canonicalises the signing actor URL
through the same `TargetIdentity::try_new(EntryKind::ActorUrl, ..)` path
the denylist uses and stamps it as `verified_actor_url`. Clients do not
fetch the instance's RSA key or see the raw HTTP Signature, so **they
cannot verify fediverse authorship themselves** -- they trust the bridge
relay as the fediverse-attribution authority. That makes the WSS
client↔relay channel integrity load-bearing for this one claim. It is a
real trust boundary, not a hole: the same trust you place in any
fediverse server's rendering of who posted what, relocated to the relay
you already authenticate a session against.

`PublicPost` is the **sole** exemption from the chat sig/KEM verify
regime -- its body is `application/activity+json`, not chat ciphertext,
and `sender_agent_id` is the all-zeros `FEDIVERSE_BRIDGE_SENDER`
sentinel (which the relay's directed-send path refuses as a delivery
target). `kind` drives the verify regime **and** the rendering
atomically, so a DM can never be smuggled through the exemption and a
bridged post always renders as a clearly-marked public post attributed
to `verified_actor_url`, never as a contact DM bubble. Code:
`crates/fetchit-relay-proto/src/public_post.rs`,
`crates/fetchit-relay-server/src/inbox/sink.rs`, and the `/inbox` HTTP
Signature gates in `crates/fetchit-relay-server/src/inbox/`.

### 9. Linked-device reachability is only as fresh as the last account re-sign

An account's device list ships as a `PairRecord` v4 signed by the
**account key**, which is derived on demand from the 24-word recovery
phrase at an explicit passphrase moment -- a device enroll, a revoke, or
the first-launch self-cert -- and dropped immediately, never retained.
Between those moments the signed record is cached as plaintext (it is
public: the relay serves it verbatim) and republished to relays
byte-for-byte on every connect and home-relay failover, with **no
re-sign**.

The cost of never keeping the account key hot: each device's
advertised-relay hint inside the record is only as current as that last
passphrase-moment mint. If a device fails its home relay over to a new
one between mints, the relay hint published for that device in the
account record stays stale until the next mint. Account-level message
**delivery** is unaffected -- a DM fans out to every device the record
lists, and a contact reaching a device on a stale hint falls back to the
account's other listed devices -- but per-device **directness** for a
migrated device can lag its live relay. The mitigation is the next
passphrase-moment re-sign, which republishes that device's current
relay; a background cross-device reconciliation is a separate, later part
of the linked-devices work.

Code: `crates/fetchit-chat/src/pair_record_v4.rs` --
`republish_cached_pair_record_v4` re-POSTs the cached record verbatim,
and minting is gated behind `with_user_key` (derive-use-drop, so the
account key is never held to re-sign on the reachability path).

### 10. A contact card's `user_id` is an agent-asserted claim, not a user-proven binding

The share card you import (an `x0x://agent/...` link) is an x0x `AgentCard`: a
`user_id` field sitting beside the agent's ML-DSA key, the whole card signed by
the **agent** key. That signature proves the agent authored the card and binds
`agent_public_key` to `agent_id` -- but it does **not** bind the agent to the
`user_id`, because the agent signs its own claimed `user_id`. There is no
user-signed certificate on the card (the account key never touches it), so a
hostile card can assert `agent=Mallory, user_id=Victim` and still verify.
fetchit captures `user_id` from the card **unverified**; `verify_card_extension`
covers only the fetchit KEM/agent extension, not the `user_id`.

The only place an account actually proves it owns a device is the `PairRecord`
v4 (caveat 9): the **account key** signs a signing-input that covers every
device's `agent_id`, KEM key, and ML-DSA key. So a DM to an M6 contact fans out
to the account's devices **only when** the agent the contact was added as
(`to`) is itself one of the devices in that account's relay-resolved,
account-signed record -- the `to`-in-devices gate. A spoofed `user_id` resolves
the victim's genuine record, but `to` (Mallory) is not in it, so the fanout
falls back to a single-device send to `to` and never seals the DM to the
victim's devices. The card `user_id` is thus only ever a **lookup hint**; the
account signature on the resolved record is the trust anchor.

Code: `crates/fetchit-chat/src/messages.rs` -- `fanout_targets_from_record`
returns the device list only when `rec.devices` contains `to`, else `[to]`;
`StoredContactCard::from_share_uri` captures `user_id` as an unverified
`Option<String>`.

## What we promise

- **fetch>it never holds a wallet, never signs Autonomi transactions,
  never writes to the network.** Read-only against Autonomi (`ant-core`
  over WithAutonomi bootstrap peers). The chat-signing path uses
  x0xd's ML-DSA-65 agent key, never an Autonomi key.
- **No telemetry from the chat surface.** Prometheus metrics on the
  relay are aggregate counters (region + version labels only) with
  no per-agent dimensions; see `docs/metrics-policy.md` at the
  workspace root.
- **The relay is open source.** AGPL-3.0-only. You can read the code
  and run your own.

## What we do NOT promise

- Hiding the contact graph (who-talks-to-who) from the relay. Sender
  + recipient AgentIds are visible to the relay in flight; we keep
  no per-agent logs and the in-memory routing state has a 15-minute
  TTL, but a global passive adversary with court access to the relay
  sees the graph until M3+ sealed-sender / mix-net work.
- Hiding **group co-membership** from the relay. Private-group content
  messages fan out as one `TransitEnvelope` per non-self member, and
  every envelope in that fanout carries the same `group_id` field. An
  observer with full relay-process state can cluster fanouts by
  `group_id` and recover the set of AgentIds in a group together
  without decrypting any message content. The group's membership
  roster lives only at the x0xd daemon and is never on the relay;
  what the relay sees is the recipient set on each fanout. Defeating
  this exposure needs sealed-sender envelopes plus recipient-set
  unlinkability (Signal-style) or oblivious routing across non-
  colluding relays — both are post-v1.0 work.
- Hiding **group control-plane events** when the relay-mediated
  bridge is consented for a group. M2.5 ships a per-group "Use the
  relay if direct gossip fails" toggle (default OFF). When you opt
  in for a group whose gossip mesh can't reach a member, the chat-
  peer wraps the signed x0xd `NamedGroupMetadataEvent`
  (MemberAdded / Welcome / Commit / PolicyUpdated / …) as a DM-
  shaped envelope and sends it via the relay; the recipient's chat-
  peer hands the inner payload to its local x0xd `/publish` and the
  daemon's pubsub loopback advances local MLS state via the normal
  apply path. The seal encrypts the inner event end-to-end, but the
  relay sees one envelope per non-self member of the bridged group
  with the recipient AgentId in cleartext — the same recipient-set
  clustering signal the previous bullet describes, applied to
  control-plane traffic. The relay keeps no per-agent logs and
  routing state expires in 15 minutes, but a relay operator who
  chose to log this metadata could rebuild the co-membership graph
  for opted-in groups. Declining the bridge keeps the group's
  control-plane direct-gossip-only; if the gossip mesh can't reach
  a peer, that peer is unreachable and the group will desync for
  them. Adding a peer to a `private_secure` group also requires
  that you have already exchanged contact cards with that peer
  (the bridge seal is keyed on the recipient's ML-KEM-768 public
  key from their share-card).
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

- `crates/fetchit-chat/src/relay_transport.rs` -- sealed-only send
  path (no fabricated fallback as of M2)
- `crates/fetchit-chat/src/messages.rs` -- `send_private_group` +
  `receive_private_group_envelope` end-to-end shape;
  `decode_direct_message` for the legacy verified flag
- `crates/fetchit-chat/src/groups.rs` -- `create_private` /
  `create` / `members` / `invite` HTTP wrappers
- `crates/x0xd-client/src/secure.rs` -- typed wrappers over x0xd's
  MLS surface
- `crates/x0xd-client/src/version.rs` -- the v0.20.1 minimum-version
  startup gate
- `crates/fetchit-chat/src/lan_noise.rs` -- Noise XX channel-binding
- `crates/fetchit-chat/src/at_rest.rs` -- FCV1 vault format
- `crates/fetchit-chat/src/conversation/inbound.rs` -- the verified
  ML-DSA-65 path on the encrypted DM side
- `crates/fetchit-chat/src/conversation/registry.rs` -- atomic
  mutate-in-place pattern that gates replay + history persistence

## Reporting a security issue

Please report security-impacting issues **privately** via GitHub's
private security advisory flow at
<https://github.com/etchit-io/fetchit/security/advisories/new> rather
than as a public issue. We'll acknowledge within a few days, agree on
a disclosure timeline, and credit you in the fix's release notes.

For non-security bugs, open a regular issue.
