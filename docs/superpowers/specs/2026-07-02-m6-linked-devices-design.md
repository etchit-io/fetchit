# M6: Linked devices — one person, every device, one account

**Status:** APPROVED — Josh 2026-07-02 ("lets do it right. do it", + spec "looks good to me" incl. all three judgment calls); Alice cross-review 2026-07-02 APPROVE with 6 convergence findings, folded below (hard requirements marked)
**Decided:** 2026-07-02
**Companions:** `2026-06-12-m5-discovery-design.md` (handle front door), `2026-06-11-reachability-v1-design.md` (signed PairRecord), x0x ADR-0007 (three-layer identity), x0x issue #91 (user-fabric addressing RFC)

## Summary

One human = one account = every device they own. A user installs fetch>it on
their laptop, scans a QR with their phone, and both devices are *them*: same
contacts, same groups, same conversations going forward, messages arriving on
both. No second identity, no vault shuttling, no "which Josh is this?"

The model, in one line: **each device keeps its own keys and its own MLS
leaf; a user-level key — derived from the 24-word recovery phrase — signs a
certificate binding every device into one account.** Keys are never copied
between devices. The account root is the phrase, not any single device.

| Component | What it is | Lane |
| --- | --- | --- |
| I. User root + device certificates | User ML-DSA key derived from the 24-word phrase; per-device `AgentCertificate`s; verification chain | joint (crypto surface — cross-reviewed) |
| II. PairRecord v4 | Signed record carries the user id + full device list; contacts pin the *user* key; contact-scoped disclosure | A-lead (owns reachability PairRecord), B review |
| III. DM fanout | Sender encrypts per device KEM key and delivers to every device-agent of the contact; receipts + dedup | joint engine |
| IV. Enrollment + revocation UX | QR link-a-device flow; lost-device revocation; phrase-only account recovery | B-lead (Android + FFI), A (desktop) |
| V. Group multi-leaf + roster collapse | Each device joins as its own member/leaf; sibling admission; UI shows one person | joint engine, shells per-side |
| VI. Devices-group self-sync | Auto-created private MLS group of your own devices; forward-sync of contacts/settings/messages | joint engine |
| VII. Fediverse rebinding | Handle attestation binds to the user layer, so @handle survives device loss and publishes from any device | B-lead (bridge), A review |

## Motivation

Today desktop LIT + mobile LIT are **two different people**: two agent_ids,
contacts must pair with each separately, groups show two members, a DM to one
never reaches the other. The only mitigation is moving the 24-word phrase —
which carries the ML-DSA identity seed ONLY (the ML-KEM key regenerates fresh,
history stays behind), one device alive at a time. Josh's verdict: "far far
from grandma easy." A 2026 chat app where phone and desktop are separate
identities also fails the Signal-parity non-negotiable outright.

LIT is unlaunched. There are zero real pair records, zero rosters to migrate.
This is the once-only moment where the identity model can be fixed for free.
Retrofitting "one user = many agents" after launch means migrating every
contact relationship in the field.

## Decisions (2026-07-02, Josh)

1. **In the v1.0 gate.** v1.0 = M0..M6. Two-account desktop+mobile does not
   ship, period.
2. **Do it right.** The fabric model below — no key copying, no interim
   single-leaf hacks, no "sync later" shortcuts that corrupt MLS state.
3. **Constraint inherited from the product mandate:** most private, easiest
   to use, nothing stored server-side that could identify or burn a user,
   decentralized to the max.

## Upstream verdict (research pass 2026-07-02)

x0x will not deliver this on any visible timeline — but the design goes
*with* its grain, not against it:

- **ADR-0007 three-layer identity** already defines MachineId (transport),
  AgentId (portable logical identity), and an optional consent-gated **UserId**
  that binds agents via `AgentCertificate`s signed by a user key
  (`src/identity.rs`). `Identity::from_seed` gives deterministic keygen.
- **Issue #91** (unscheduled RFC) sketches user-fabric *addressing*
  (`user-four-words.laptop`) and explicitly punts enrollment/key-sync —
  and states "Groups are still the right primitive for 'Alice's devices share
  encrypted state.'" Our design implements exactly the layer it punts.
  Once this spec is approved we comment on #91 with our shape so the
  addressing layer and our fabric converge instead of drifting.
- **Copying one vault to two live devices is confirmed broken three ways:**
  presence cache is last-writer-wins per agent_id (`src/lib.rs:1213`), DM
  routing resolves an agent to exactly one machine (`connected_agents`,
  `src/direct.rs:543`), and MLS binds one agent = one TreeKEM leaf
  (`src/groups/member.rs:150`) so shared keys = permanent epoch divergence.

**THE INVARIANT (non-negotiable, enforce in review): private keys never
leave the device that generated them. No vault copy, no key export, no
"temporary" shared-leaf mode. Ever.**

## I. Identity model

```
24-word phrase ──► user seed ──► user ML-DSA-65 keypair ──► user_id = SHA-256(user pubkey)
                                        │ signs
                                        ▼
                          AgentCertificate per device
                                        │ binds
        ┌───────────────────────────────┼──────────────────────────────┐
        ▼                               ▼                              ▼
  phone device                    laptop device                (future device)
  agent ML-DSA (random)           agent ML-DSA (random)
  agent ML-KEM (random)           agent ML-KEM (random)
  machine key   (random)          machine key   (random)
  = own MLS leaf                  = own MLS leaf
```

- **The phrase is the account.** It derives the user key deterministically
  (same BIP-39 path we ship today, re-rooted: phrase → user seed, not agent
  seed). Whoever holds the phrase can re-mint the user key and therefore
  re-anchor the account after losing every device.
- **Devices are disposable; the user is durable.** Each device generates its
  agent + machine + KEM keys locally at enrollment and never shares them.
  A stolen laptop burns one leaf, not the account.
- **AgentCertificate** = user-key signature over
  `(user_id, agent_id, agent ML-DSA pubkey, device KEM pubkey, added_at, cert_version)`.
  Contacts verify: pair record signed by user key → certificates chain each
  listed device to that user key → per-device keys authenticated transitively.
- **Migration from today's model:** current identities have phrase → *agent*
  seed. Pre-launch this is a clean re-root: first launch of an M6 build
  derives the user key from the existing phrase and self-certifies the
  existing agent as device #1. agent_id values do not change; the phrase's
  meaning upgrades from "this device's signing key" to "my account root."
  (Zero users in the field = zero migration risk; testers re-pair once.)

### Account recovery (phrase-only, all devices lost)

Restore = enter phrase → re-derive user key → mint a **fresh** device agent →
self-certify → publish an updated user-signed pair record listing only the
new device. Contacts' apps see a record signed by the *same pinned user key*
and treat it as continuity — no re-TOFU, no "who is this?" This is strictly
stronger than today's recovery (same agent_id but a silently fresh KEM key).
Groups re-admit the new device via the returning-member path. History is
gone (E2EE, nothing server-side) — same honest deal as today, stated in the
recovery copy.

## II. PairRecord v4 (contact-visible surface)

Alice owns the reachability PairRecord; this is the requirements list, not a
schema decree:

- Adds: `user_id`, user ML-DSA pubkey, `devices: [{agent_id, kem_pubkey,
  ml_dsa_pubkey, cert, added_at}]`, `record_version`, monotonic `revision`.
- **Signed by the user key** (device keys sign nothing account-scoped).
  Contacts **pin the user key** — TOFU moves up one layer. Device add/remove
  = new revision, same pinned root.
- **HARD REQUIREMENT — revision anti-rollback (Alice finding 1):** contacts
  MUST persist the last-seen `revision` per pinned user_id and REJECT any
  record with `revision <=` last-seen. Without this, revoking a stolen
  device is defeatable by replaying the older (still validly user-signed)
  record that re-lists it. Reject-on-rollback, not warn.
- Two schema specifics (Alice, owns the concrete schema): the record names a
  **canonical device #1** so v3-only readers get a deterministic
  single-device view; and the per-device `cert` is for **out-of-record**
  contexts (sibling admission, fedi bridge) — inside the record the user-key
  signature already covers the device list, so verifiers must not
  double-verify certs there.
- **Contact-scoped disclosure.** The device list travels inside the pair
  record a contact fetches — it is NOT broadcast to gossip or any global
  directory. The network sees N independent agents; only your contacts can
  associate them. (Deviation from #91's directory approach, on purpose:
  privacy mandate.) No device nicknames in the record — `phone`/`laptop`
  labels stay local.
- Backward compat: v3 records remain readable; a v3-only peer sees device #1
  and degrades to single-device behavior. `verify_card_extension` strip-list
  discipline applies to any new unsigned card slots.

## III. DM fanout

- Sender resolves the contact's pair record → encrypts the message **once per
  listed device** (each has its own ML-KEM-768 key) → delivers to each
  device-agent through the existing chain (raw_quic → gossip_inbox →
  peer_relay). A device being offline parks that copy in the normal relay
  ~15-min buffer; no new server state.
- Message IDs are stable across copies → receiving devices dedup; the
  sender's *own* sibling devices get a mirror copy via the devices-group
  (VI), so the conversation reads identically everywhere.
- Delivery receipts: aggregate per-user (any-device-delivered = delivered);
  read state syncs over the devices-group, not the wire to the contact.
  Outbox semantics confirmed (Alice): claim/ack stays **per-envelope** —
  fanout = N independent outbox entries, one per device-agent; the
  any-device-delivered aggregation lives in the receipt layer ABOVE the
  durable retry outbox, which is unchanged.
- **HARD REQUIREMENT — outbox honors pair-record revision (Alice finding
  3):** the retry outbox must re-check the contact's current device list and
  DROP pending entries addressed to a device that a newer revision removed.
  Otherwise a revoked device is retried forever — revocation and fanout are
  coupled through the revision, deliberately.
- Cost note: fanout multiplies sends by device count (cap: see open
  questions). Relay sees more envelopes but nothing new about content or
  association (sealed as today).

## IV. Enrollment + revocation UX

Grandma flow — link a device:

1. New device: install → "Link to your existing account" → shows a QR
   (its freshly minted agent pubkeys + a one-time nonce).
2. Existing device: scan → confirmation screen shows the new device's
   short-code → user taps **Link**.
3. Existing device signs the AgentCertificate with the user key, publishes
   pair record revision N+1, invites the new device into the devices-group,
   and triggers sibling admission into existing chat groups (V).
4. New device shows "You're in" with contacts + groups populating.

Both-sides confirmation prevents QR-swap attacks; the certificate is only
minted after explicit human confirmation on the *already-trusted* device.
Where does the user key live to sign this? Derived on demand from the phrase
at enrollment/revocation time on the confirming device — either re-entered or
unlocked from the passphrase-encrypted vault where the user seed is stored
(same custody class as today's identity seed; zeroize discipline per task
#277). No always-hot user key.

Revocation — lost phone:

- From a surviving device: Devices list → "Remove device" → user key signs a
  revocation entry, pair record revision bumps with the device dropped,
  devices-group removes the leaf and rekeys (PCS does its job), chat groups
  remove that member-device via the admin/removal path.
- **HARD REQUIREMENT — close the revocation-latency window (Alice finding
  5):** group traffic stops for the stolen device at the devices-group /
  chat-group rekey (immediate), but contacts' *DM fanout* keeps delivering
  to it until they re-resolve the pair record. Mitigate both ways: on
  revocation, proactively push the revised record to active contacts
  (existing DM channel), AND give resolvers a short re-resolve cadence /
  TTL on cached device lists so even unreachable contacts converge quickly.
  The residual window must be bounded and stated honestly in the security
  docs.
- From phrase alone (all devices gone): full account recovery (I) — the
  fresh record supersedes; contacts' apps drop delivery to de-listed devices
  on next resolve.

## V. Groups: multi-leaf membership + roster collapse

- Each device joins a group as **its own member with its own leaf** — MLS
  stays convergent, per-device PCS for free. The engine's existing
  `Member.user_id_hex` placeholder finally gets populated.
- **Sibling admission:** when a user accepts a group invite on one device,
  their other devices must land in the group too — automatically, zero UI
  ("Josh joined" just works). Mechanics resolved by code probe (see open
  question #1): the KeyPackage handshake rides the devices-group — the
  sibling derives its per-group TreeKEM KeyPackage locally (it is derived
  from the sibling's own secret + group id; nobody else can mint it) and
  sends it to the in-group device over the devices-group. Then:
  - *In-group device is admin (M6.5a, stock daemon):* it calls the
    invite-free TreeKEM direct-add (`POST /groups/:id/members` with
    `treekem_key_package_b64`), which creates + stages the Welcome and
    direct-delivers `MemberAdded` + `welcome_ref` to the sibling — full
    crypto parity with the invite flow, no invite bookkeeping at all.
  - *In-group device is plain member (M6.5b, fork patch):* same handshake,
    but authority requires the sibling-add capability (commit accepted when
    the added agent's certificate chains to the member's user_id recorded
    at join).
- **Roster collapse:** UI groups member-devices by `user_id_hex` — one
  avatar, one name, "2 devices" only in detail view. Message attribution is
  per-user, not per-device. Group size limits count leaves (document this).
- Ordering/duplication: inbound group messages from a user's several devices
  are already distinct-sender messages under MLS; nothing changes on the
  wire. Our own sibling-sent messages appear via normal group delivery (each
  device is a member) — no devices-group mirror needed for groups.

## VI. Devices-group self-sync

An auto-created, invisible, invite-locked MLS group containing exactly your
device-agents (created at first enrollment; membership maintained by
enrollment/revocation). It carries, forward-only from the moment a device
joins:

- contact adds/removes/renames (so a contact added on the phone exists on
  the laptop),
- profile + settings changes (display name, avatar pointer, preferences),
- DM mirror copies (III) + read-state markers,
- group-membership signals (join/leave/sibling-admission triggers, V),
- the sibling KeyPackage handshake for group admission (V).

**Reliability requirement (Alice finding 6):** the devices-group is one more
MLS group and inherits the StaleEpoch / TreeKEM catch-up failure class. It
MUST ship with the mobile-0.27 returning-member rekey fix + epoch catch-up
wired in, so an offline second device re-syncs on reconnect instead of
wedging — a wedged devices-group would silently kill all cross-device sync,
the worst possible failure for this feature.

**Explicit non-goal for M6 v1: retroactive history transfer.** A newly
linked device starts from link-time (Signal-linked-device semantics). Full
device-to-device history migration is a candidate M6.x follow-on using a
direct transfer (x0x tailnet streams, #131/#132, are the natural carrier
when they land upstream) — never a server-side store.

## VII. Fediverse rebinding

The M4/M5 mint attestation currently binds `handle ↔ actor URL ↔ agent_id`.
Under the fabric that binding is wrong-layer: the handle must survive device
loss and publish from any device. Change: attestation binds
**handle ↔ actor URL ↔ user_id**, and the bridge accepts a publish/update
signed by any device whose certificate chains to that user_id (bridge
verifies cert chain, still stores nothing beyond the public actor record it
already holds). The M5 "one opt-in" privacy model is unchanged: minting a
handle makes you publicly findable — now it publicly discloses your
*user_id* rather than a device agent_id, which is strictly less churn-prone
and no more identifying. Decision-4 separation (AP keys ≠ chat keys)
untouched.

## Privacy analysis (who learns what)

| Observer | Learns | Unchanged from today? |
| --- | --- | --- |
| Your contacts | Your device count + device agent_ids (via pair record; no nicknames) | new, inherent to fanout — contact-scoped only |
| Network/gossip | N independent agents with independent presence; no user association | yes — association never broadcast |
| Relay | Fanout multiplicity (k sealed envelopes where there was 1) | metadata delta, content-blind as today |
| Bridge (only if handle minted) | handle ↔ user_id (replaces handle ↔ agent_id) | improved: stable root, devices not enumerated |
| We (operators) | Nothing new stored anywhere | yes — no account server exists |

## What must change NOW (pre-M6 future-proofing, cheap today)

1. PairRecord/profile-manifest schema: version field discipline + reserved
   `user_id` slot so v4 is additive, not breaking (A-lead).
2. Populate `Member.user_id_hex` self-value from day one of M6.1 so rosters
   collapse without backfill.
3. Recovery-phrase copy everywhere says "account", never "device", so the
   re-root (I) doesn't contradict shipped UI text.
4. Any new card extension slots follow the `verify_card_extension` strip-list
   rule.

## Delivery order

M6.1 user root + certs (re-root phrase, cert mint/verify, unit + wiremock) →
M6.2 PairRecord v4 + pinning-on-user-key (A-lead) → M6.3 DM fanout + dedup +
receipts → M6.4 enrollment QR flow (FFI + Android + desktop) → M6.5a
admin-device sibling admission (stock daemon) + roster collapse → M6.5b
member-device sibling-add capability (fork patch + upstream offer) →
M6.6 devices-group sync (contacts,
settings, DM mirror) → M6.7 revocation + phrase-only recovery → M6.8 fedi
rebinding → M6.9 cross-NAT device-matrix verification (phone + laptop +
droplet peer; enroll/revoke/recover under CGNAT). Each stage lands
feature-branch → gates → cross-review → device-verify, per house rules.

## Open questions

1. **Sibling admission mechanics in invite_only groups** — RESOLVED
   (code probe of mobile-0.27, 2026-07-02). Split verdict:
   - *User's in-group device is an admin:* works **today**, zero daemon
     changes. Invite minting is admin-gated (`create_group_invite`,
     `src/server/mod.rs:11453`), admission is inviter-anchored to the same
     node, and an invite-free direct-add exists
     (`POST /groups/:id/members`, `:11987`). Personal groups where the user
     is creator/admin get sibling admission for free → **M6.5a**.
   - *User's in-group device is a plain member:* blocked at TWO independent
     gates — the mint gate and the distributed commit-authority gate (every
     peer rejects `MemberAdded` unless the actor is an active admin,
     `src/server/mod.rs:8746-8751`). No same-user carve-out exists; x0xd
     member records set `user_id: None` (`src/groups/mod.rs:913`).
   - *Capability for the member case (fork patch, offered upstream — fits
     #91):* record the joiner's `user_id` + AgentCertificate **at join** in
     the member record; add a sibling-add commit where member A adds agent B
     carrying `cert_B`, and every peer verifies `cert_B` chains to the
     user_id *already recorded for A at admission time*. The
     recorded-at-join anchor defeats the fabricated-user-key attack (a rogue
     member minting a fresh user key to "certify" an arbitrary agent as a
     sibling). Touches both gates + member-record schema → **M6.5b**.
   - Residual verify item — RESOLVED (second probe, 2026-07-02): on the
     TreeKEM plane the direct-add endpoint dispatches to
     `add_treekem_named_group_member` (`src/server/mod.rs:12023-12026`),
     which **requires the target's KeyPackage** (400 without it, `:12118`),
     creates + stages the Welcome (`:12204-12241`), and direct-delivers
     `MemberAdded` + `welcome_ref` to the added agent (`:12256-12261`); the
     sibling pulls the Welcome over DM/QUIC and joins — identical outcome to
     the invite flow. A read-blind roster-only member is impossible on
     TreeKEM. The KeyPackage is derivable only by the sibling itself (own
     secret + group id, `:19056-19059`), so M6.5a includes a small
     KeyPackage handshake over the devices-group. Caveat: legacy `Gss`-plane
     groups take a bare agent_id with **no Welcome** — M6 sibling admission
     asserts `secure_plane == TreeKem` before direct-add (all new
     MlsEncrypted groups are TreeKEM).
2. **Device cap** — AGREED (Josh + Alice): 5 linked devices (Signal parity;
   5× fanout acceptable, 5 leaves within group-size limits).
3. **User-key custody UX** — AGREED direction (Josh + Alice): vault-unlock
   with passphrase re-prompt, never 24-word retype after setup. User seed
   lives in the passphrase-encrypted vault (same custody class as the
   identity seed), derived on demand + zeroized (joint zeroize task).
   Implementation detail = the joint M6.1 custody call (A + B).
4. **Upstream #91 coordination** — comment with our fabric shape after this
   spec is approved; adopt their four-word user addressing when it lands
   (pure alias layer, no conflict).
5. **Relay outbox interaction** — RESOLVED (Alice): claim/ack is
   per-envelope, fanout = N entries, aggregation is receipt-layer above the
   outbox; see hard requirement in section III (outbox honors revision).
