# LIT Chat v1 — security model

This document names the six security caveats that ship with LIT Chat
v1. It is load-bearing: the M1 forum announcement, the in-app "About
Chat" screen, and any "is this secure?" question all resolve to the
text below.

If a claim in the announcement or the UI contradicts something here,
the claim is wrong — fix the claim, not this document.

> **Scope.** This file covers the *chat* surface only. The reader
> surface — iframe sandbox, host process, on-disk cache, neutered
> web APIs — is documented in
> [`docs/SECURITY.md`](../../docs/SECURITY.md). If the two appear
> to disagree, both are bugs; report the divergence via the channel
> in [Reporting](#reporting-a-security-issue) below.

## The threat model in one paragraph

LIT Chat v1 protects message **contents and metadata against a passive
adversary on the wire**, on the LAN-direct path. It does **not**
protect message contents against the operator of the relay you happen
to be using, because the v1 relay-path bytes are not yet end-to-end
sealed. The relay is our own AGPL-3.0-only code (`fetchit-relay-server`)
and you can self-host it. v1 also does not provide forward secrecy for
groups (no MLS), and does not enforce per-message signature
verification on the legacy plaintext-decode path. None of these caveats
is a bug; each is a named compromise dated for closure in M2.

## The six caveats

### 1. Relay sees envelope contents (M2 closes this)

When the v1 fabricated send path runs — any caller that doesn't supply
a pre-sealed `TransitEnvelope` — `relay_transport.rs::send` builds a
`TransitEnvelope` with empty `nonce`, `kem_ciphertext`, and
`sender_signature`, then forwards the payload bytes as
`TransitEnvelope.ciphertext`. The wire-level confidentiality on this
branch is **TLS-to-the-relay plus relay-is-honest**.

The relay is fetch>it's own AGPL-3.0-only code. You can run your own
(`docker-compose` template ships with the relay repo). The fetch>it-
operated relays at `67.207.94.66:8088` (NYC) and `159.89.11.217:8088`
(Frankfurt) are disclosed-centralized defaults; the user-facing
"Custom relay" setting lets any user point at their own.

M2 wires real ML-KEM-768 encap + ChaCha20-Poly1305 sealed payload
through `crates/fetchit-chat/src/chat_crypto.rs` (helpers already
exist) and removes the v1 fallback.

### 2. Groups are public rooms — plaintext over gossip (M2 closes this)

The group surface in `groups.rs` uses x0xd's `public_open` preset, which
routes group messages over the daemon's gossip pub/sub **without any
group-level encryption**. fetch>it does not run an MLS state machine
in-process; we drive x0xd's MLS surface via REST.

Group messages in v1 should be treated as **public**. The UI surfaces
them as "public rooms" (the wire value is `public_open` for x0xd's
benefit, but no copy users see uses that string). No per-group
encryption badge exists yet; the M2 UI work (plan Task 14) adds the
private/public radio in the create-group dialog alongside the
caveat 2 closure.

M2 ships PQ TreeKEM groups via x0xd v0.20.x's MLS surface
(`preset=private_secure` + `discoverability=Hidden`), which the daemon
backs with `saorsa-mls v0.3.x` (ML-KEM-768 + ML-DSA-65 +
ChaCha20-Poly1305 + BLAKE3 — pure PQ, RFC-9420-subset wire format).
`groups.rs` rewires off `public_open` onto `/secure/encrypt` +
`/secure/decrypt` + `/publish` + `/subscribe`. Public rooms keep the
v1 plaintext path as an explicit opt-in.

**Honest-claim caveat:** the underlying `saorsa-mls` README still
self-flags as upstream-prototype ("Do not use this crate to protect
sensitive data in production systems"). We ship what upstream ships
and harden in tandem — our copy mirrors that framing rather than
overclaim "audited final crypto." We are also NOT IETF
`draft-ietf-mls-pq-ciphersuites` wire-compatible; saorsa-mls is an
RFC-9420 *subset* with PQ primitives substituted in, not the IETF PQ
codepoint. LIT Chat does not need cross-vendor MLS interop for v1.0.

### 3. DirectMessage.verified is honest about per-message signatures

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

### 4. LAN-direct 32-byte agent-id preamble is unauthenticated

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

### 5. Per-device KEM keypair has no auto-backup (M1 closes this)

The local ML-KEM-768 keypair fetch>it generates lives in the FCV1
at-rest vault under an OS-keystore or Argon2id master key. Wiping
the x0xd data dir, reinstalling fetch>it, or moving to a new device
**loses decap of historical messages** for that identity.

M1 ships an "Export chat backup" button in Settings → Network that
exports the vault encrypted under a user-supplied passphrase, plus
an import flow on the receiving device. The KEM private key never
leaves the vault format; restore re-establishes decap continuity.

### 6. Crypto deps are pinned by git rev — drift breaks runtime

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

- Sealed relay messages (M2).
- Encrypted groups (M2).
- Direct peer-to-peer mode without a relay in the path (M2).
- Resistance to a relay operator who is a global passive adversary
  with a court order (the relay sees the message in v1; if you need
  resistance to that threat model wait for M2 sealing or self-host).

## Reading the code yourself

Every claim above maps to a source file or commit. Suggested reading
order:

- `crates/fetchit-chat/src/relay_transport.rs` — the two send paths
- `crates/fetchit-chat/src/messages.rs` — `decode_direct_message` and
  the `DirectMessage::verified` field doc
- `crates/fetchit-chat/src/groups.rs` — the `public_open` preset usage
- `crates/fetchit-chat/src/lan_noise.rs` — Noise XX channel-binding
- `crates/fetchit-chat/src/at_rest.rs` — FCV1 vault format
- `crates/fetchit-chat/src/conversation/inbound.rs` — the verified
  ML-DSA-65 path on the encrypted side

## Reporting a security issue

Please report security-impacting issues **privately** via GitHub's
private security advisory flow at
<https://github.com/etchit-io/fetchit/security/advisories/new> rather
than as a public issue. We'll acknowledge within a few days, agree on
a disclosure timeline, and credit you in the fix's release notes.

For non-security bugs, open a regular issue.
