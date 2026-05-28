# PQ content encryption and group chat — design

**Date:** 2026-05-28
**Scope:** Add ML-KEM-768 content encryption to all chat messages
and ship multi-device group chat through the relay. Same code path
for DMs and groups. Compatible with stock x0xd 0.19.49+; no fork.
**Deferrals doc:** `private/pq-encryption-and-groups-deferrals.md`

## 1. Goals and non-goals

### 1.1 Goals
- All chat content (DMs and groups) is sealed with ML-KEM-768 +
  ChaCha20-Poly1305. The relay never sees plaintext.
- Multi-device per user from day one — adding a second device for
  the same user is a first-class flow.
- Forward secrecy at epoch granularity. Auto-rekey on a schedule;
  manual rekey on membership change.
- A compromised or lost device can be revoked. Its prior knowledge
  expires at the next rekey; ongoing knowledge stops as soon as
  peers process the revocation.
- KEM secret keys and conversation keys are encrypted at rest using
  an OS-provided keystore (with a passphrase fallback).
- Cards remain compatible with stock x0xd `x0x://agent/<base64>`
  URIs — additive fields only.

### 1.2 Non-goals (explicit deferrals — see deferrals doc)
- Per-message forward secrecy (PQ Double Ratchet) → v2.
- Social graph hiding at the relay (sealed sender / mix-net) → v2.
- Mobile pairing UI → ships with each mobile platform; v1 desktop
  only.

## 2. Identity, devices, and the card

### 2.1 Identity hierarchy

```
User U (logical, opt-in user_id; default: anonymous = single device)
 │
 ├─ Device A
 │   ├─ x0xd ML-DSA-65 keypair  → agent_id_A   (held by x0xd)
 │   └─ fetchit ML-KEM-768 keypair → kem_pub_A (held by fetchit-chat)
 │
 └─ Device B (optional, added via pairing)
     ├─ x0xd ML-DSA-65 keypair  → agent_id_B
     └─ fetchit ML-KEM-768 keypair → kem_pub_B
```

x0xd holds one identity per install (one device = one agent_id).
fetchit-chat holds its own ML-KEM-768 keypair per device, separate
from x0xd's KEM key (which we don't use because x0xd has no
`/agent/decap` endpoint).

### 2.2 Extended share-card

The user-facing share URI stays `x0x://agent/<base64-json>`. The
JSON adds three additive fields x0xd doesn't know about:

```json
{
  "agent_id": "<hex>",
  "machine_id": "<hex>",
  "user_id": "<hex|null>",
  "dm_capabilities": { ... },
  "addresses": [...],

  "fetchit_kem_public_key_b64": "<base64 ML-KEM-768 pub>",
  "fetchit_card_version": 1,
  "fetchit_card_signature_b64": "<ML-DSA-65 sig of canonical card>"
}
```

`fetchit_card_signature_b64` is produced by x0xd's `/agent/sign`
with domain prefix `"fetchit-chat/v1/card"` over the canonical
postcard encoding of the card fields except the signature itself.
Recipients verify before trusting `fetchit_kem_public_key_b64`. This
prevents an attacker from substituting their KEM key into a card
they don't own.

x0xd silently preserves unknown fields on import (verified by
reading `agent_card` parsing code); our local card store retains
the full JSON for re-export and KEM lookup.

### 2.3 User manifest (multi-device discovery)

When a user has more than one device, their identity needs a
manifest enumerating all devices. The manifest is signed by any
device in the immediately-prior manifest version (cross-signing
chain). First version is TOFU.

```json
{
  "user_id": "<hex>",
  "manifest_version": 2,
  "created_at_ms": 1779912345000,
  "devices": [
    { "agent_id": "<a-hex>", "kem_public_key_b64": "...",
      "added_at_ms": ..., "status": "active" },
    { "agent_id": "<b-hex>", "kem_public_key_b64": "...",
      "added_at_ms": ..., "status": "active" }
  ],
  "revocations": [],
  "signed_by_agent_id": "<a-hex>",
  "signature_b64": "<ML-DSA-65 sig from device A>"
}
```

Single-device users do NOT need a manifest — the card alone is
their identity. Manifest is materialized on first pairing.

Manifest is published in two ways:
1. **Pull on demand**: any of the user's devices serves
   `/v1/manifest/<user_id>` via the relay (a new relay endpoint).
   Peers query when they import a card with a `user_id` that
   differs from the device they imported.
2. **Push update**: when a manifest changes (add/revoke), the user's
   devices emit a `ManifestUpdate` envelope to one device per
   already-known peer-user. Peers refresh their local copy.

## 3. Conversation model

### 3.1 Data structure

Stored at `~/.config/fetchit/conversations/<group_id_hex>.json.enc`
(encrypted; see §6.2).

```rust
struct Conversation {
    group_id: [u8; 32],           // random at creation, stable forever
    name: Option<String>,          // group only; DM uses peer's display
    members: Vec<Member>,          // includes self
    current_epoch: u32,            // bumps on every rekey
    current_key: [u8; 32],         // ChaCha20 key for this epoch
    prior_keys: Vec<PriorKey>,     // 60s sliding window for in-flight
    own_role: Role,                // Admin | Member
    created_at_ms: u64,
    last_rekey_at_ms: u64,         // for auto-rekey timer
}

struct Member {
    user_id: Option<[u8; 32]>,     // None for single-device legacy contacts
    devices: Vec<MemberDevice>,
    joined_at_epoch: u32,
}

struct MemberDevice {
    agent_id: [u8; 32],
    kem_public_key: Vec<u8>,
    added_at_epoch: u32,
    status: MemberDeviceStatus,    // Active | Revoked
}

struct PriorKey {
    epoch: u32,
    key: [u8; 32],
    expires_at_ms: u64,            // 60s from rekey time
}
```

### 3.2 Operations

Five lifecycle operations: **First Contact**, **Send Message**,
**Add Member**, **Revoke Device**, **Auto Rekey**.

#### First Contact (Alice DMs Bob, no prior conversation)

```
1. Alice generates group_id ← random 32B
2. Alice generates current_key ← random 32B
3. Alice's local members ← [self (all of Alice's devices),
                            Bob (all of Bob's devices: from his user
                                 manifest if Bob has a user_id, else
                                 the single device from his imported
                                 card)]
4. Alice's local epoch ← 0
5. For each device D in members (except sending device):
     (kem_ct, ss) ← MLKEM768.encap(D.kem_public_key)
     aead_key     ← HKDF(ss, info="lit/welcome/v1")
     welcome_body ← postcard({
       group_id, current_key, epoch: 0, members, name,
       sender_agent_id: alice_self_device_agent_id,
       sender_signature_at_canonical_state: <ML-DSA over canonical>
     })
     ct ← ChaCha20-Poly1305(aead_key).seal(welcome_body, nonce,
                                            aad=concat("lit/v1",
                                                       group_id,
                                                       0_u32_le))
     envelope ← TransitEnvelope {
       version: 2,
       kind: GroupChat,
       group_id: Some(group_id),
       epoch: 0,
       kem_ciphertext: kem_ct,
       ciphertext: ct,
       nonce, sender_agent_id, sender_machine_id,
       timestamp_ms, sender_signature: <ML-DSA over canonical envelope>
     }
     relay.send(to: D.agent_id, envelope)
```

#### Send Message (subsequent, in established conversation)

```
1. nonce ← random 12B
2. aad   ← concat("lit/v1", group_id, current_epoch.to_le_bytes())
3. ct    ← ChaCha20-Poly1305(current_key).seal(body, nonce, aad)
4. Build the fan-out device set:
     all_devices = ⋃ member.devices  for member in members
                   (filter: device.status == Active)
     fanout = all_devices.exclude(self_sending_device)
   Note: this INCLUDES the sender's own other devices (so all of
   sender's other devices see the message and update local state).
   Self-loopback excluded: only the currently-sending device is
   skipped, since it already has the plaintext locally.
5. For each device D in fanout:
     envelope ← TransitEnvelope {
       version: 2,
       kind: GroupChat,
       group_id: Some(group_id),
       epoch: current_epoch,
       kem_ciphertext: <empty>,       ← discriminator: Message
       ciphertext: ct,
       nonce, sender_agent_id, sender_machine_id,
       timestamp_ms, sender_signature
     }
     relay.send(to: D.agent_id, envelope)
```

#### Add Member (Alice adds Carol)

```
1. current_epoch += 1
2. current_key   ← random 32B (replaces old key)
3. prior_keys ← prior_keys + {old_epoch, old_key, expires_at: now+60s}
4. members.push(Carol's_full_record_from_her_manifest)
5. last_rekey_at_ms ← now
6. For each device D in members (every one, including Carol; except
   sending device):
     Send Welcome envelope (as in First Contact) carrying the NEW
     current_key, NEW epoch, updated members.
```

#### Revoke Device (Alice's phone was stolen; Alice's laptop revokes the phone)

Two-phase: first the manifest is updated to mark the device
`Revoked`, then every conversation that included the revoked device
performs a rekey that excludes the revoked device.

```
PHASE 1 — manifest update:
1. Generate new manifest version with revoked device entry:
     devices[phone].status ← Revoked
     revocations.push({ revoked_agent_id, revoked_at_ms,
                        revoked_by_agent_id })
     manifest_version += 1
2. Sign by laptop's ML-DSA via /agent/sign with domain
   "lit/manifest/v1".
3. For each known peer (anyone in our contacts/):
     send AdminEvent envelope to their primary device:
       payload = { ManifestUpdate, user_id, manifest, manifest_sig }
4. Peers' fetchit-chat updates stored card to mark phone Revoked.
   Their subsequent fanouts skip phone.

PHASE 2 — per-conversation rekey:
For each Conversation where phone was a member device:
  current_epoch += 1
  current_key ← random 32B
  prior_keys += {old key, 60s ttl}
  Send Welcome envelope to every CURRENTLY-ACTIVE device of every
  member (NOT the revoked phone) carrying the new key + epoch.
```

The revoked phone holds stale keys at the next epoch. Until peers
process the ManifestUpdate, they may continue sending the next
messages encrypted for the phone too — but the phone won't have
the rekeyed Welcomes, so it can't read messages past that rekey.

#### Auto Rekey (no membership change, scheduled)

```
Triggered by a background timer in fetchit-chat when:
  now - last_rekey_at_ms > AUTO_REKEY_INTERVAL
  (default: 7 days; configurable per-conversation)

Coordination across the user's devices is best-effort eventual
consistency, not a lock:

  - Each Admin device may independently fire the timer.
  - To reduce the duplicate-rekey rate, each device offsets its
    timer by jitter = HKDF(self_agent_id || group_id, "lit/rekey/v1")
    truncated to [0, 6h). Earlier-jittered devices fire first.
  - If two devices race and both emit Welcomes, the receiver picks
    the Welcome with the higher (epoch, sender_agent_id) lex tuple
    — the same rule used for concurrent membership changes (§7).
  - The losing device sees its peers respond with a higher epoch
    and adopts the winner's key.

Behavior on fire:
1. current_epoch += 1
2. current_key   ← random 32B
3. prior_keys   += {old, 60s ttl}
4. last_rekey_at_ms ← now
5. Build the fan-out device set as in Send Message (every Active
   device of every member, except the sending device).
6. For each device in the fan-out: send a Welcome envelope
   carrying the new key + epoch + (unchanged) members list.
```

Non-Admin (Member-role) devices do NOT auto-rekey; in single-Admin
v1 conversations, only the conversation creator's devices may
trigger this path.

### 3.3 Decryption dispatch

```
on TransitEnvelope received:
  if envelope.kem_ciphertext non-empty:
    → Welcome path:
       decap envelope.kem_ciphertext with our local kem_secret_key
       derive aead_key via HKDF
       AEAD-decrypt envelope.ciphertext
       interpret payload as Welcome { group_id, current_key,
                                       epoch, members, name }
       install/update Conversation accordingly
  else:
    → Message path:
       look up Conversation by envelope.group_id
       if no Conversation found → emit StaleEpoch warn, drop
       choose key by envelope.epoch:
         if current_epoch == envelope.epoch → use current_key
         else look in prior_keys (within 60s) → use that key
         else → emit StaleEpoch warn, drop
       AEAD-decrypt envelope.ciphertext with chosen key + AAD
       Surface message to UI
```

## 4. Multi-device pairing protocol

QR-based, two-message exchange via the relay (Hello and Onboard).
The user-facing flow is: tap "Add device" on Device A (existing),
scan the QR on Device B (fresh install).

### 4.1 QR contents (shown by Device A)

```json
{
  "v": 1,
  "relay_url": "http://67.207.94.66:8088",
  "a_agent_id": "<hex>",
  "pair_id": "<16 random bytes hex>",
  "a_ephem_kem_pub_b64": "<ephemeral ML-KEM-768 pub, used once>",
  "a_intent_sig_b64": "<ML-DSA over 'lit/pair/v1' || pair_id>"
}
```

The ephemeral KEM keypair is generated for this pairing only.
The intent signature proves Device A actually invited this
pairing (defends against QR replay).

### 4.2 Wire exchange

```
DEVICE A                            DEVICE B
────────                            ────────
1. Show QR; subscribe to relay
   inbox (already subscribed).

2.                                   Scan QR. Verify a_intent_sig
                                    against A's known public key
                                    (fetched from the user's existing
                                    contacts on B if B was previously
                                    installed; or directly from x0xd
                                    /agent on B's local daemon if A's
                                    agent matches B's). For a truly
                                    fresh B, the verification is
                                    against a card the user supplies
                                    out-of-band, OR TOFU.

3.                                   Generate own ML-KEM keypair.
                                    Build PairHello payload:
                                      { kind: PairHello,
                                        pair_id,
                                        b_agent_id,
                                        b_kem_pub_b64,
                                        b_intent_sig_b64 =
                                          x0xd_sign("lit/pair/v1"
                                            || pair_id
                                            || b_agent_id) }
                                    Encapsulate against a_ephem_kem:
                                      (kem_ct, ss)
                                      key = HKDF(ss, "lit/pair/v1")
                                      ct  = AEAD(key).seal(
                                              postcard(payload),
                                              nonce,
                                              aad="lit/pair/v1")
                                    Send AdminEvent envelope to
                                    a_agent_id with kem_ct + ct.

4. Receive PairHello via relay.
   Decap kem_ct with a_ephem_kem_sec.
   Verify b_intent_sig.
   Prompt user: "Add this device?
     fingerprint: <hash(b_agent_id ||
                      b_kem_pub)[:8 hex chunks]>"
   User confirms (or rejects).
   If rejects: send PairReject and stop.

5. Build new manifest version:
     devices ← [a, b], manifest_version++,
     signed_by = a.
   Build PairOnboard payload:
     { kind: PairOnboard,
       user_id,
       new_manifest,
       new_manifest_sig,
       conversations: [...full state...] }
   Encrypt under the SAME ss (still
   valid; this is a two-message session,
   so no fresh KEM needed).
   Send to b_agent_id.

6.                                   Receive PairOnboard.
                                    Decrypt with same ss.
                                    Verify manifest_sig chains
                                    against the prior manifest
                                    (TOFU if no prior).
                                    Install:
                                      identity.json
                                        (existing, plus user_id)
                                      user_manifests/<user_id>.json
                                      conversations/*.json.enc
                                    Open relay session as b_agent_id.
                                    Ready.

7. For each peer in contacts/:
     Send AdminEvent { ManifestUpdate,
       user_id, new_manifest,
       new_manifest_sig } to one device
       per peer-user.
```

### 4.3 Failure modes

- B scans an expired QR (pair_id seen before) → A rejects with
  PairReject; user retries by re-clicking "Add device" on A.
- Network partition between PairHello and PairOnboard → B times
  out after 5 minutes; user retries.
- User declines on A → A sends PairReject; B shows the rejection.

### 4.4 Security properties

- ephemeral KEM keypair on A is single-use; KEM secret zeroized on
  completion.
- Pairing exchange is confidential (encrypted under the ephemeral
  KEM-derived key) and authenticated (b_intent_sig on the hello,
  user confirmation on the onboard).
- Replay: pair_id binds the entire session; A tracks recently-seen
  pair_ids and rejects duplicates.
- MITM at the relay: relay sees kem_ct + ct (opaque). Relay can
  drop the message but can't forge a PairHello it can decrypt.

## 5. Wire format changes

`fetchit-relay-proto::TransitEnvelope` gains one field:

```rust
pub struct TransitEnvelope {
    pub version: u16,                          // bumped 1 → 2
    pub kind: EnvelopeKind,
    pub group_id: Option<GroupId>,             // REQUIRED for chat
    pub tenant_id: Option<TenantId>,
    pub sender_agent_id: AgentId,
    pub sender_machine_id: MachineId,
    pub timestamp_ms: u64,
    pub epoch: u32,                            // NEW
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,               // empty=Message, non-empty=Welcome
    pub sender_signature: Vec<u8>,
}
```

Canonical-bytes-for-signing: postcard-encode envelope with
`sender_signature` zeroed. Sign with x0xd `/agent/sign` and domain
`"lit/envelope/v1"`. Recipient zeroes the signature before
verifying.

AEAD AAD: `concat(b"lit/v1", group_id, epoch.to_le_bytes())`.

New `AdminEvent` envelope kinds (inside the encrypted payload after
decap, dispatched by an inner type tag):

```rust
enum AdminPayload {
    ManifestUpdate { manifest, manifest_sig },
    PairHello { b_agent_id, b_kem_pub, b_intent_sig },
    PairOnboard { manifest, conversations: Vec<Conversation> },
}
```

`ManifestUpdate` and the pairing variants are routed as regular
relay envelopes with `kind: AdminEvent`; the relay treats them
identically to chat traffic.

## 6. Storage and at-rest encryption (v1 includes)

### 6.1 Layout

```
~/.config/fetchit/                    # mode 0700
├── identity.json.enc                 # encrypted; KEM secret + card sig
├── contacts/                         # mode 0700
│   └── <peer_agent_id_hex>.json      # unencrypted; cards aren't secret
├── conversations/                    # mode 0700
│   └── <group_id_hex>.json.enc       # encrypted; contains current_key
├── user_manifests/
│   └── <user_id_hex>.json            # unencrypted; manifests are public
└── pairing/                          # transient, deleted after pairing
    └── <pair_id_hex>.json.enc
```

### 6.2 At-rest encryption

Files ending `.json.enc` are AEAD-sealed under a device-local
master key. The master key is held by the OS keystore:

| Platform | Backend | Crate |
| --- | --- | --- |
| macOS | Keychain Services | `keyring` (0.10+) |
| Linux | Secret Service (libsecret) / KWallet | `keyring` |
| Windows | DPAPI (CryptProtectData) | `keyring` |

The same `keyring` crate handles all three. Key entry id:
`"fetchit-chat-v1-master"`. The master key is 32 random bytes
generated on first launch.

**Passphrase fallback** when OS keystore is unavailable
(headless Linux, e.g. on the Alice droplet): user supplies a
passphrase at startup; we derive the master key with Argon2id
(parameters: m=64MiB, t=3, p=4). The same passphrase unlocks the
session.

Wire format for `.enc` files:

```
[u8;  4]  magic       = "FCV1"      (Fetchit Chat Vault 1)
[u8;  1]  kdf_id      = 0=keychain, 1=Argon2id
[u8; 16]  argon_salt  (zero when kdf_id=0)
[u8; 12]  nonce
[u8;  N]  AEAD ciphertext (ChaCha20-Poly1305)
[u8; 16]  AEAD tag (included in ciphertext above)
```

The KEM secret AND any conversation current_key/prior_keys go
through this layer. Cards and manifests are public — kept
plaintext.

## 7. Error model

| Failure | Cause | Behavior |
| --- | --- | --- |
| `RecipientNotImported` | No card stored for one or more recipient devices | Refuse to send; surface to UI. **No plaintext fallback.** |
| `RecipientKemUnknown` | Card lacks `fetchit_kem_public_key` | Refuse send for that device; emit warn. |
| `RecipientDeviceRevoked` | Device status is `Revoked` in manifest | Skip silently; do not fan out. |
| `StaleEpoch` (inbound) | Unknown `(group_id, epoch)` pair | Drop, emit `chat:warn`. |
| `KemDecapFailed` | Welcome encrypted to wrong KEM key | Drop, emit warn. |
| `EnvelopeSignatureInvalid` | ML-DSA verify fails | Drop, emit warn. |
| `ManifestSignatureInvalid` | Update not signed by prior-version device | Reject. |
| `ManifestVersionRegression` | Version ≤ known | Reject. |
| `MembershipChangeUnauthorized` | Non-admin attempted add/remove | Reject. |
| `MasterKeyUnavailable` | OS keystore + no passphrase entered | Surface modal; refuse to operate until resolved. |

Replay protection: 64-message sliding window keyed by
`(group_id, sender_agent_id, timestamp_ms, nonce)`.

Concurrent membership changes: last-write-wins by
`(epoch, sender_agent_id)` lex order.

Welcome-before-message ordering: senders emit all Welcomes for a
membership change before subsequent Messages in the new epoch.
`prior_keys` 60s window handles the race.

## 8. Threat model summary

| Threat | Defended? |
| --- | --- |
| Relay reads message contents | **Yes** (AEAD sealed; relay sees ciphertext only) |
| Relay reads who-talks-to-who | **No** (deferred — explicit gap, see deferrals doc) |
| Past messages decrypted if KEM secret stolen later | **Partial** — limited to messages in epochs the stolen key was active for. Auto-rekey (default 7-day) caps the window. |
| Future messages safe after device revoke | **Yes** — once peers process ManifestUpdate + rekey runs, revoked device is excluded. |
| Forged messages injected | **Yes** — ML-DSA-65 envelope signature + AEAD tag |
| Card key substitution attack | **Yes** — card signed by x0xd ML-DSA; verify at import |
| Manifest tampering | **Yes** — cross-signed chain anchored at TOFU |
| KEM/conversation key exfiltration via filesystem | **Yes (with mitigation)** — at-rest encryption via OS keystore (Argon2id passphrase fallback) |
| Quantum computer breaks ECC | n/a — no ECC used |
| Quantum computer breaks ML-KEM-768 | Catastrophic — same risk every PQ messenger carries. Mitigated only by NIST review depth. |

## 9. Code surface and module layout

Affected crates (touched but not rewritten unless noted):

```
crates/fetchit-relay-proto/
  src/envelope.rs        bump version; add epoch field
crates/fetchit-chat/
  src/chat_crypto.rs     NEW — encap/decap, AEAD, AAD, HKDF
  src/conversation.rs    NEW — Conversation state, lifecycle ops
  src/manifest.rs        NEW — UserManifest, signature chain
  src/card.rs            NEW — extended card builder + verifier
  src/at_rest.rs         NEW — vault file format, OS keystore, Argon2
  src/pairing.rs         NEW — QR shape, PairHello, PairOnboard
  src/messages.rs        rewire send → encrypts via conversation
  src/relay_transport.rs no change at the relay-routing layer
  src/client.rs          add chat_crypto + conversation registry init
crates/fetchit-relay-server/
  src/server.rs          add /v1/manifest/<user_id> route + storage
  src/manifest_cache.rs  NEW — relay-side manifest cache (RAM)
apps/fetchit-desktop/
  src/chat/contactCard.ts modify share-card display to show v2 fields
  src/chat/pairDevice.ts  NEW — pairing UI (QR display + scan)
  src-tauri/src/chat.rs   add chat_pair_device commands
```

The relay's manifest endpoint is a small addition — it caches the
most-recent manifest per user_id in RAM (60-min TTL) and serves it
on demand. Manifests are signed and self-verifying; the relay is a
mere conduit for them too.

## 10. Testing strategy

**Layer 1: unit tests per new module.**
- `chat_crypto`: KEM encap-decap round-trip; AEAD round-trip; HKDF
  derivation determinism; AAD binding (cross-conversation replay
  rejected).
- `conversation`: epoch advance; prior-keys eviction; add/remove
  member; auto-rekey trigger; concurrent change resolution.
- `manifest`: signature chain across N versions; TOFU on first
  import; revoke entry forces device exclusion.
- `card`: build + verify signature; reject tampered fields;
  preserve unknown fields through x0xd round-trip.
- `at_rest`: round-trip seal+open with OS keystore; round-trip with
  Argon2 fallback; tamper detection.
- `pairing`: full PairHello → PairOnboard happy path; rejected on
  bad intent_sig.

**Layer 2: integration against mock relay + mock x0xd.**
- DM round-trip with Welcome + Message + auto-rekey + Message.
- 3-member group: add Carol → rekey → send → remove Carol →
  rekey → Carol's stale key fails to decrypt next message.
- Multi-device: pair B to A's user; A and B both receive the same
  inbound message; A sends a message and B sees it in their own
  conversation view.
- Card tamper: forged card with substituted KEM key is rejected at
  import.

**Layer 3: live test (`#[ignore]`'d).**
- Extends `live_relay.rs`. Josh's desktop ↔ NY relay ↔ Alice's
  fetchit-chat-peer (which gets a fetchit-chat-peer update so it
  speaks the encrypted protocol).
- Send 5 messages, observe round-trip, observe auto-rekey at
  shortened TTL (60s for test).
- Add a synthetic third peer ("Bob") and verify 3-way group works.

## 11. Open questions / TBD-explicit

None — all design questions settled during brainstorm. Anything
that surfaces during implementation is a finding to bring back here.

## 12. Out-of-scope changes

This design does NOT change:
- Relay protocol auth (X0xdSigner, ML-DSA-65 challenge-response).
- Relay transport layer (RelayTransport in fetchit-chat).
- x0xd integration (still only `/agent/sign` and `/agent`).
- Capability tokens, tenant_id, region selection.
- Trust service (fetchit-trust).
- fetchit reader-side / Autonomi protocol.

## 13. Migration story

There are no shipped users on the encrypted protocol yet. Cutover:

1. Bump `TransitEnvelope.version` 1 → 2. Old version-1 envelopes
   continue to flow during a transition window — both versions
   coexist by inspecting `version` field.
2. The desktop chat panel starts using version-2 sends after this
   ships.
3. After one minor release cycle, we deprecate version-1 sends and
   only accept version-2 on relay.

Existing Alice-on-droplet peer needs a binary refresh to handle
version-2; this is a one-line script in our `journalctl`-driven
deployment.

Existing conversations (from the pre-encryption days) have no
group_id. Treat them as legacy DMs and re-bootstrap into encrypted
conversations on next send (a new group_id is generated; user is
informed: "starting a secure conversation with X"). Old transcripts
remain readable locally but new sends use the new path.
