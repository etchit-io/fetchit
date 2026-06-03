# M2 — PQ TreeKEM groups via x0xd MLS adapter

**Date:** 2026-06-02
**Scope:** Wire `fetchit-chat` through x0xd v0.20.x's PQ TreeKEM MLS
surface so private groups become end-to-end PQ-encrypted with forward
secrecy and post-compromise security. Cut the v1 fabricated send path
so every sealed envelope is the only envelope on the wire.

## 1. Goals and non-goals

### 1.1 Goals
- Private groups in fetch>it ship as **PQ TreeKEM** (ML-KEM-768 +
  ML-DSA-65, ChaCha20-Poly1305 + BLAKE3) via x0xd's existing MLS
  surface — `saorsa-mls v0.3.x` upstream owns the TreeKEM state.
- The v1 `fabricate_v1_envelope` fallback in `relay_transport.rs:132`
  is **removed**. Every send is sealed.
- `crates/fetchit-chat/SECURITY.md` caveats 1 (relay sees envelope
  contents) and 2 (groups are plaintext gossip) close.
- Honest-claim language mirrors saorsa-mls's own upstream-prototype
  caveat — we ship what upstream ships, we don't overclaim.
- v1.0 launch claim "PQ end-to-end DM + groups" survives audit
  (task #180).

### 1.2 Non-goals (explicit)
- **No** in-process MLS state machine in `fetchit-chat`. The daemon
  owns the ratchet; we consume HTTP + SSE.
- **No** OpenMLS fork, **no** custom MLS ciphersuite registration,
  **no** maintained downstream OpenMLS branch.
- **No** IETF `draft-ietf-mls-pq-ciphersuites` wire interop. saorsa-mls
  is an RFC-9420 *subset* with PQ primitives substituted in. LIT Chat
  does not need cross-vendor MLS interop for v1.0.
- **No** rewrite of the home-grown PQ DM Conversation protocol.
  Sealed DMs already work; M2 leaves them untouched.
- **No** change to relay routing semantics. TreeKEM bytes ride inside
  `TransitEnvelope.ciphertext` opaque to the relay.

## 2. Upstream verified state (2026-06-02)

| Component | Version | Status |
| --- | --- | --- |
| x0xd binary | 0.20.2 (installed on Box A) | TreeKEM live |
| saorsa-mls (consumed by x0xd) | 0.3.8 | TreeKEM landed v0.3.6 (2026-05-30) |
| PQ ciphersuite naming | `MlKem768MlDsa65` (saorsa's taxonomy) | Pure PQ, RFC-9420-subset wire |
| Activation condition | `preset=private_secure` + `discoverability=Hidden` + `MlsEncrypted` | Public encrypted presets stay on legacy GSS |
| Upstream testing posture | 1,662 tests + 6-hour cross-region testnet (v0.20.0 changelog) | Real validation |
| README caveat | "treat this crate as a prototype for experimentation only" | We mirror honestly |

x0xd's MLS HTTP surface (verified by curl on Box A live x0xd 0.20.2):

- `POST /groups` body `{name, preset:"private_secure", discoverability:"Hidden", ...}` → returns `{group_id, chat_topic, ok}`.
- `POST /groups/<gid>/secure/encrypt` body `{payload_b64}` → returns `{ciphertext_b64, nonce_b64, secret_epoch, ok}`.
- `POST /groups/<gid>/secure/decrypt` body `{ciphertext_b64, nonce_b64, secret_epoch}` → returns plaintext bytes.
- `POST /publish` body `{topic, payload}` — fan out via gossip.
- `POST /subscribe` body `{topic}` — SSE stream of `chat:event` kind `gossip_message`.
- `GET /groups/<gid>/messages` deliberately errors `"MlsEncrypted groups do not publish a plaintext message history"` — client must persist history locally.

## 3. Architecture

```
fetchit-chat::groups
   │
   ▼
x0xd-client::secure   ──►  HTTP + SSE (loopback)  ──►  x0xd 0.20.x
   │                                                       │
   │                                                       ▼
   │                                                  saorsa-mls 0.3.x
   │                                                  (TreeKEM ratchet,
   │                                                   ML-KEM/ML-DSA,
   │                                                   FS + PCS)
   ▼
fetchit-chat::messages
   │
   ▼
RelayTransport ──► TransitEnvelope { ciphertext = MLS frame } ──► relay
```

Three concrete changes plus a SECURITY.md rewrite:

### 3.1 New module: `crates/x0xd-client/src/secure.rs`

Typed wrappers over the five endpoints above. Lives alongside
`signer.rs` and `discovery.rs` in the existing `x0xd-client` crate
(does NOT introduce a new crate; the split is between
`fetchit-chat` and `x0xd-client`, not within x0xd-client itself).

```rust
pub struct SecureGroupsEndpoint<'a> { /* … */ }

impl<'a> SecureGroupsEndpoint<'a> {
    pub async fn create_private_secure(
        &self,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<CreatedGroup>;

    pub async fn encrypt(
        &self,
        group_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedFrame>;

    pub async fn decrypt(
        &self,
        group_id: &str,
        frame: &EncryptedFrame,
    ) -> Result<Vec<u8>>;

    pub async fn publish(
        &self,
        topic: &str,
        payload: &[u8],
    ) -> Result<()>;

    pub async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<impl Stream<Item = GossipEvent>>;
}

pub struct EncryptedFrame {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub secret_epoch: u32,
}
```

The module includes byte-fixture round-trip tests against a
wiremocked x0xd to lock the wire JSON shape.

### 3.2 Rewire `crates/fetchit-chat/src/groups.rs`

Replace the `public_open` preset with `private_secure` +
`discoverability=Hidden` on `create`. Replace
`POST /groups/<id>/send` with the encrypt → publish pair. Replace the
`GET /groups/<id>/messages` history call with subscribe-and-decrypt.

The existing public-room code path is preserved as an explicit opt-in
(separate code path under a `--public-room` flag or a `Room::Public`
constructor — design TBD in the impl plan).

### 3.3 Cut `fabricate_v1_envelope`

In `crates/fetchit-chat/src/relay_transport.rs`, the `else` branch
that currently calls `fabricate_v1_envelope` is removed. Callers that
fail to supply a `prebuilt` sealed envelope return
`ChatError::Invalid("sealed envelope required")` instead. The
`fabricate_v1_envelope` function is deleted entirely along with its
test.

`TransitEnvelope.version` bumps 2 → 3 to make wire-level "unsealed
v1 path exists" untrue. Relay accepts both v2 and v3 during a
transition window; sends emit v3 only.

### 3.4 SECURITY.md caveat rewrite

Caveat 1 (relay sees envelope contents) and caveat 2 (groups are
public rooms) close at the same commit. New caveat 2 text already
landed at 2026-06-02 (this branch): mirrors saorsa-mls's
"upstream-prototype, hardening in tandem" framing; flags the
RFC-9420-subset wire format honestly.

## 4. Data flow

### 4.1 Create private group

```
1. User taps "Create private group" in chat panel
2. fetchit-chat::groups::create_private(name)
3. x0xd-client::secure::create_private_secure(name, display_name=Some(self_name))
4. x0xd → saorsa-mls: spin up TreeKemGroup, ML-KEM keypair, MemberId
5. Returns CreatedGroup { group_id, chat_topic }
6. fetchit-chat stores Group { group_id, name, member_count: 1, is_owner: true }
7. UI shows the new group in the sidebar with the lock-icon badge
```

### 4.2 Invite a peer (Add Member)

For v1.0 we use x0xd's existing `POST /groups/<id>/invite` for
membership management, which already routes through the daemon's
group-state machinery. The daemon emits the MLS Welcome to the
invitee via gossip; the invitee's x0xd processes it transparently.

```
1. User taps "Invite" on a private group
2. fetchit-chat → x0xd POST /groups/<id>/invite returns x0x://invite/<base64>
3. Invite URI shared out-of-band (same UX as today's public-room invites)
4. Peer pastes invite into their fetch>it → x0xd POST /groups/join
5. Peer's x0xd processes the MLS Welcome internally
6. Peer's fetchit-chat sees the new group in /groups list
```

The Welcome wire is x0xd-internal — we don't see it, we don't store
it. Out-of-band: nothing about this flow is fetchit-built.

### 4.3 Send message

```
1. User types "hello group" in private group conversation
2. fetchit-chat::messages::send(group_id, "hello group")
3. x0xd-client::secure::encrypt(group_id, plaintext_bytes)
   → EncryptedFrame { ciphertext_b64, nonce_b64, secret_epoch }
4. Build TransitEnvelope { version: 3, kind: GroupChat, group_id,
                            epoch: secret_epoch,
                            ciphertext: postcard(EncryptedFrame),
                            nonce: nonce from frame,
                            kem_ciphertext: empty,
                            sender_signature: ML-DSA over canonical }
5. relay_transport.send(envelope) — wire
```

**Decision recorded.** `private/m2-decisions.md` Decision 1 selects
Path A (TransitEnvelope-wrapped through our relay). x0xd's `/publish`
+ `/subscribe` endpoints are wired in `x0xd-client::secure` for
completeness but are NOT on the v1.0 group chat path.

### 4.4 Receive message

```
1. fetchit-chat subscribes to chat_topic on app startup per group
2. SSE event arrives: GossipEvent { kind: "gossip_message", payload }
3. x0xd-client::secure::decrypt(group_id, frame_from_payload)
   → plaintext bytes
4. fetchit-chat parses plaintext as MessagePayload (postcard)
5. UI shows the message
```

## 5. Error model

| Failure | Cause | Behavior |
| --- | --- | --- |
| `X0xdMlsVersionTooOld` | x0xd < 0.20.1 at startup | Refuse to enable private-secure groups; UI explains; user prompted to upgrade x0xd |
| `EncryptFailed` | x0xd returns error on `/secure/encrypt` | Surface to UI; do not fall back to unsealed |
| `DecryptFailed` | x0xd returns error on `/secure/decrypt` | Drop, emit `chat:warn`; possible epoch drift on the wire |
| `SealedRequired` | A caller invokes `RelayTransport::send` without a prebuilt envelope | Returns `ChatError::Invalid("sealed envelope required")`; the `fabricate_v1_envelope` path no longer exists |
| `GossipSubscribeLost` | SSE connection drops | Auto-reconnect via the same mechanism as relay-client (#175 pattern); rehydrate subscriptions |

## 6. Migration story

- DMs are already sealed (M0/M1 PQ DM work). No change for DM
  conversations.
- Existing public-room groups (pre-M2) keep flowing on the
  `public_open` path. They are NOT auto-upgraded; users create new
  private-secure groups for the encrypted experience.
- TransitEnvelope v2 → v3: relay accepts both for one minor release
  cycle; sends emit v3 only.
- Alice droplet peer needs a binary refresh to speak v3.

## 7. Testing

**Layer 1: unit tests.**
- `x0xd-client::secure`: wiremock the five endpoints; assert JSON
  shape, error handling.
- `groups.rs`: assert `create` emits `preset=private_secure` +
  `discoverability=Hidden` on the wire.
- `relay_transport.rs`: assert send without `prebuilt` returns
  `SealedRequired`.

**Layer 2: integration against a real x0xd 0.20.x.**
- Spin x0xd on a random port; create a private-secure group;
  encrypt + publish + subscribe + decrypt round-trip.
- 3-member sequence: A creates group, A invites B, A invites C, B
  sends, A and C receive.
- Membership churn drives epoch advance: confirm a banned member's
  stale `secret_epoch` decrypt fails.

**Layer 3: live cross-internet (`#[ignore]`'d).**
- Alice (Box A) ↔ Bob (Box B) ↔ NY relay over a real private-secure
  group. Send 5 messages, observe round-trip. Add a synthetic Carol
  via Alice droplet, verify 3-way works.

**Test gate:** v1.0 launch claim "PQ end-to-end DM + groups" requires
the cross-internet live test green at least three times in a row over
24 hours.

## 8. Out-of-scope changes

- DM crypto layer untouched.
- Relay protocol auth (X0xdSigner, ML-DSA-65 challenge-response) untouched.
- LAN-direct transport untouched.
- At-rest vault format untouched.
- Capability tokens, tenant_id, region selection untouched.
- fetch>it reader-side / Autonomi protocol untouched.

## 9. Honest-claim posture for v1.0 launch

This is load-bearing for task #180 (PQ honest-claim audit):

- **What we claim:** "PQ end-to-end content encryption via post-quantum
  TreeKEM (ML-KEM-768 + ML-DSA-65) for both DMs and private groups,
  with forward secrecy and post-compromise security. Built on x0x's
  daemon-side MLS surface (saorsa-mls upstream), which we ship in
  lockstep — we trust what upstream trusts and we harden in tandem."
- **What we do NOT claim:** "IETF-standard MLS wire format,"
  "third-party audited MLS implementation," "metadata privacy at the
  relay," "perfect forward secrecy at per-message granularity."
- **What our SECURITY.md mirrors honestly:** saorsa-mls's own
  upstream-prototype caveat; the RFC-9420-subset wire format; the
  scoping to `Hidden` + `MlsEncrypted` groups.

`[[feedback-pq-claims]]` memory: "content E2EE yes, metadata privacy
no; match David's framing exactly, no BS in launch copy."

## 10. Open questions

- **Publish-path choice (§4.3):** TransitEnvelope-wrapped through our
  relay vs x0xd's gossip pubsub. Both work; differ in privacy
  posture, latency, observability. Decide during impl phase against
  live measurements.
- **Per-group history persistence:** x0xd refuses `/messages` for
  MlsEncrypted groups. fetchit-chat must persist decrypted history
  locally. Storage shape: extend the existing `Conversation`
  on-disk vault or use a separate group-history vault? Resolves
  during impl plan write-up.
- **Backwards-compat on existing public-room groups:** at the v1.0
  cut, do we hide the "Create public room" affordance and only
  expose "Create private group"? Or keep both with clear labels?
  Defer to a UX call once the implementation lands.

## 11. References

- Spec drives MILESTONES.md M2 gate (post-pivot 2026-06-02)
- Pairs with `[[feedback-rely-on-x0x]]` memory (the rule that
  produced this pivot)
- Supersedes the `2026-06-XX-mls-openmls-groups-design.md`
  placeholder named in MILESTONES.md (file was named but never
  created)
- M0/M1 PQ DM spec at
  `docs/superpowers/specs/2026-05-28-pq-content-and-groups-design.md`
  (historical; describes the DM-side work that already shipped)
- x0x v0.20.0 changelog (the TreeKEM landing)
- saorsa-mls v0.3.6 ADR-002 (PQ TreeKEM design)
