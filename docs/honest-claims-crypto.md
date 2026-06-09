# Honest Claims — Cryptographic Posture

The crypto/MLS half of the #180 honest-claims audit. This is the
**source of truth for what launch copy may and may not say** about
fetch>it's cryptography. Each section gives the claim we *can* make
(grounded in shipped code) and the claim we *cannot* make. The wallet /
etch>it half is tracked separately; both fold into the launch 1-pager.

Grounded in `crates/fetchit-chat/SECURITY.md` and the M4 inbox/bridge
code. When the code changes, this file changes first, then the copy.

---

## 1. Private chat (DMs + private groups) — post-quantum

- **DMs:** sealed with ML-KEM-768 (KEM) → ChaCha20-Poly1305 (AEAD);
  per-message ML-DSA-65 signature over the canonicalized envelope.
- **Private groups:** PQ TreeKEM via x0xd's MLS surface, which the
  daemon backs with `saorsa-mls` v0.3.x — ML-KEM-768 + ML-DSA-65 +
  ChaCha20-Poly1305 + BLAKE3, an **RFC-9420 *subset*** wire format with
  post-quantum primitives substituted in.

**CAN claim:** "Private messages and groups are end-to-end encrypted
with post-quantum primitives (ML-KEM-768 key exchange, ML-DSA-65
signatures)."

**CANNOT claim:**
- "Audited" — `saorsa-mls` self-flags as an upstream prototype ("do not
  use in production"); no independent audit.
- "IETF-standard MLS" / "MLS-compliant" — it is an RFC-9420 *subset*,
  not the IETF PQ ciphersuite codepoint
  (`draft-ietf-mls-pq-ciphersuites`).
- "Cross-vendor interoperable" — the subset does not interop with other
  MLS implementations, by design (LIT Chat doesn't need it).

**Honest framing:** *post-quantum by construction, prototype maturity,
pinned to a specific upstream rev.*

## 2. Content vs. metadata — encrypted content, visible graph

- **Content** (message bodies, group state) is end-to-end encrypted; the
  relay sees only opaque ciphertext.
- **Metadata** (sender + recipient agent IDs, contact graph, timing) is
  **visible to the relay in flight**. Mitigations: RAM-only routing
  buffer, ~15-minute TTL, no per-agent logs, region+version-only metric
  labels. But these are operational hygiene, not a cryptographic
  guarantee.

**CAN claim:** "The relay cannot read message content."

**CANNOT claim:** "metadata-private" / "the relay cannot see who talks
to whom." A global passive adversary with court access to the relay
sees the contact graph until sealed-sender / mix-net work lands
(post-v1.0).

## 3. Public fediverse bridge (M4) — classical, signed, not encrypted

- The fediverse bridge (inbound `POST /inbox` + outbound `Create{Note}`)
  uses **classical** cryptography: **RSA-2048 HTTP Signatures** — the
  ActivityPub / Mastodon standard. There is **no post-quantum protection
  on the bridge**, and public posts are **not** end-to-end encrypted
  (they are public by definition).
- Public posts are **signed for attribution**: the relay verifies the
  sending instance's HTTP Signature and vouches the canonical actor URL.
  Clients trust the relay as the fediverse-attribution authority (they
  cannot verify the HTTP Signature themselves) — a documented trust
  boundary, see `crates/fetchit-chat/SECURITY.md` caveat 8.

**CAN claim:** "Public fediverse posts are signed and attributed to a
relay-verified actor."

**CANNOT claim:** "post-quantum" or "end-to-end encrypted" anywhere on
the fediverse path. The PQ guarantees are for *private* chat only.

> Copy-accuracy flag for the 1-pager merge: the bridge signs/verifies
> with **RSA-2048 HTTP Signatures** (matches the code:
> `Actor.rsa_public_key_pem` / `HttpSignatureKey`), not Ed25519. State
> it as classical RSA so the claim matches what ships.

## 4. The binding line

> **"Everything private is PQ. Everything public is signed."**

Substantiated exactly: private chat = post-quantum end-to-end encryption
(ML-KEM-768 + ML-DSA-65); public fediverse posts = classical signature +
relay-vouched attribution. No metadata-privacy claim anywhere; no PQ
claim on the public side.

## 5. Operational caveat — pinned crypto stack

The PQ stack (`saorsa-pqc`, `saorsa-mls`, `snow`, `ant-quic`, `x0xd`,
`uniffi`, `self_encryption`, `xor_name`) is pinned by exact git rev
(`PINS.md` + the CI pin-check gate). An unpinned bump can change the
wire format between releases. Not a security claim — operational
honesty about why the versions are frozen.
