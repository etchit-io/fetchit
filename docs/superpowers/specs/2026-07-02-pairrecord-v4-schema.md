# PairRecord v4 concrete schema (M6.2, Alice A-lead)

Companion to `2026-07-02-m6-linked-devices-design.md` section II. This pins the
wire schema Bob's M6 implementation plan references. Status: proposed by Alice
(reachability PairRecord owner), pending Bob review + fold into the M6 plan.

## Base

Current wire type (`fetchit_relay_proto::pair_record::PairRecordV1`) is
single-agent: `{ agent_id_hex, ml_dsa_pubkey_b64, kem_pubkey_b64,
advertised_relays: Vec<String>, issued_at_ms }`, signed by the agent's ML-DSA-65 key over a frozen
length-prefixed binary layout (domain separator `fetchit-pair-record-v1`,
built by `pair_signing_input`), with `issued_at_ms` as the relay logical-clock
watermark (409 clock-bump retry). v4 keeps that machinery and re-roots the record
at the user layer.

## v4 types

```rust
pub struct PairRecordV4 {
    pub record_version: u8,             // = 4
    pub user_id_hex: String,            // 64-hex = SHA-256(user_ml_dsa_pubkey bytes)
    pub user_ml_dsa_pubkey_b64: String, // account-root ML-DSA-65 pubkey
    pub revision: u64,                  // monotonic per user_id (anti-rollback)
    pub issued_at_ms: u64,              // relay logical-clock watermark (carried from V1)
    pub devices: Vec<DeviceEntryV4>,    // the signed device list
    pub user_signature_b64: String,     // ML-DSA-65 over JCS(record minus this field), by the USER key
}

pub struct DeviceEntryV4 {
    pub agent_id_hex: String,           // this device's agent id (64-hex)
    pub ml_dsa_pubkey_b64: String,      // device signing pubkey
    pub kem_pubkey_b64: String,         // device ML-KEM-768 pubkey (DM fanout target)
    pub advertised_relays: Vec<String>, // this device's reachability (http form, normalized as today)
    pub cert_b64: String,               // AgentCertificate (see below)
    pub added_at_ms: u64,               // certification time
    pub primary: bool,                  // exactly one true = canonical device #1 for V1 readers
}
```

`AgentCertificate` = user-key ML-DSA-65 signature over the canonical tuple
`(user_id_hex, agent_id_hex, ml_dsa_pubkey_b64, kem_pubkey_b64, added_at_ms,
cert_version)`.

## Rules

1. **User-key signed, user-key pinned.** `user_signature_b64` covers JCS of the
   whole record (device list included) minus the signature. A contact verifies
   `user_id_hex == SHA-256(user_ml_dsa_pubkey)` and the signature, then pins
   `user_id_hex` (TOFU moves up one layer). Device keys sign nothing
   account-scoped.
2. **Anti-rollback (HARD, m6-design section II).** The contact persists
   `last_seen_revision[user_id]` and REJECTS any record with `revision <=`
   last-seen; on accept, updates it. A replayed older record cannot resurrect a
   device dropped by a newer revision.
3. **Canonical device #1.** Exactly one `DeviceEntryV4.primary == true`. A
   V1-only reader (and the v3 share-URI resolver) projects the primary device's
   `{agent_id_hex, ml_dsa_pubkey_b64, kem_pubkey_b64, advertised_relays,
   issued_at_ms}` into a `PairRecordV1` and degrades to single-device. v4 must
   therefore keep the primary device's fields V1-projectable.
4. **Cert is out-of-record.** `cert_b64` is NOT re-verified while reading the
   record (the user signature already authenticates the whole list). It is
   verified only where a device presents itself OUTSIDE the record: sibling
   group admission (device proves it chains to the recorded `user_id`) and fedi
   publish (bridge verifies a publishing device chains to the handle's
   `user_id`). No double-verify on the resolve path.
5. **Canonicalization + signing** reuse the length-prefixed ML-DSA-65
   layout of `pair_signing_input` (NOT JCS) under a new domain separator
   `fetchit-pair-record-v4`; relay URLs are normalized to http for signing
   exactly as V1 does. The concrete v4 signing input is specified below.
6. **Backward compat.** `record_version = 4`; a V1 peer falls back to the v3
   share URI which resolves to the primary device (single-device). The
   `verify_card_extension` strip-list rule applies to any future unsigned slot
   (v4 has none, everything is inside the signed body).
7. **Migration (pre-launch, zero field migration).** First M6 launch derives the
   user key from the existing 24-word phrase, self-certifies the existing agent
   as the primary device, and publishes `revision = 1`. `agent_id_hex` is
   unchanged; the phrase's meaning upgrades from device-signing-key to
   account-root.

## v4 signing input (canonical layout)

`user_signature_b64` is an ML-DSA-65 signature by the user key over the
byte string below, mirroring `pair_signing_input` (`lp(x)` = `u32_be(len)
|| bytes`; multi-byte integers big-endian):

```text
PAIR_RECORD_V4_DOMAIN                 // b"fetchit-pair-record-v4"
|| lp(user_id_hex)                    // 64 ascii hex bytes
|| lp(user_ml_dsa_pubkey)             // raw bytes, base64-decoded
|| u64_be(revision)
|| u64_be(issued_at_ms)
|| u32_be(n_devices)
|| for each device, in listed order:
     lp(agent_id_hex)
     || lp(device_ml_dsa_pubkey)      // raw bytes
     || lp(device_kem_pubkey)         // raw bytes
     || u32_be(n_relays) || lp(relay_str) * n_relays
     || u64_be(added_at_ms)
     || u8(primary ? 1 : 0)
     || lp(cert bytes)                // base64-decoded cert_b64
```

Validation mirrors V1: `user_id_hex` is lowercase 64-hex and equals
`hex(SHA-256(user_ml_dsa_pubkey))`; each device `agent_id_hex` equals
`hex(derive_agent_id(device_ml_dsa_pubkey))`; relays are 1..=4
credential-free http/https URLs each <= 256 bytes, normalized to http for
signing; exactly one device has `primary == true`; and `n_devices` is
1..=5 (the OQ2 device cap). The device list is signed in its serialized
order and readers must preserve it. Binding `cert bytes` into the record
means a tampered or stripped cert invalidates the whole record; the cert
layout itself (`SIGN_DOMAIN_CERT`) is owned by M6.1 and treated as opaque
bytes here.

## Addressing

Record identity is `user_id_hex`; anti-rollback (rule 2) is tracked per
`user_id_hex`, and `issued_at_ms` stays the relay logical-clock
tiebreaker (the V1 409 clock-bump retry carries over). A v3-only reader
never parses v4: it resolves the primary device as a projected
`PairRecordV1` through the existing v3 share-URI path (rule 3). The exact
relay storage key (under `user_id_hex` versus the primary `agent_id_hex`,
and whether a projected V1 is also served for bare-agent-id lookups) is an
M6.2 relay-half detail to settle against the relay-server and share-URI
code, not fixed here.

## Consumers

- **DM fanout (section III):** sender resolves the contact's v4 record, encrypts
  once per `DeviceEntryV4.kem_pubkey_b64`, deposits one envelope per device to
  that device's `advertised_relays`. Per-envelope claim/ack unchanged.
- **Outbox honors revision (HARD, section III):** the durable retry outbox drops
  pending entries addressed to a device not present in the current revision, so
  a revoked device is not retried forever.

## Resolved

Naming: `PairRecordV4` (Bob agreed 2026-07-02), matching the
milestone/spec and the `record_version = 4` field. It is a new type with
its own domain separator, not additive fields on V1, matching the
frozen-layout V1/ForwardingV1 pattern already in `pair_record.rs`. M6.0
(committed `9b0104d7`) added the unsigned `record_version` selector to V1
so v4 records can share the transport.
