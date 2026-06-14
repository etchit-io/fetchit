# Profile Manifest v1 (Autonomi-backed)

**Status:** locked 2026-05-30. Both etch>it (publisher) and fetch>it
(consumer) ship against this spec.

The Profile Manifest is the rich-content card a peer publishes once
they pick a display name, a bio, an avatar, and a set of cross-app
links. The on-network artifact is a small JSON blob (≤ 1 KB)
addressed by a 64-hex Autonomi address (`profile_addr`). It is
signed by the peer's ML-DSA-65 identity, the same key x0xd holds.

```
                    +-----------------------------+
                    |   profile_manifest_v1.json  |   ≤ 1 KB on Autonomi
                    |   { ..., sig: "<sig>" }     |   addressed by profile_addr
                    +--------------+--------------+
                                   |
       (relay index)               | (autonomi)
            v                      v
+--------------------+   +------------------------+
| relay /v1/profile  |   | autonomi address       |
|  agent_id -> hint  |   |   fetch returns bytes  |
+--------------------+   +------------------------+
```

A separate avatar Autonomi address holds the WebP image (≤ 256² @
mime `image/webp`). The manifest carries the avatar's `addr`, `w`,
`h`, `mime`, `bytes_len` so the consumer can reserve layout space
and lazy-fetch only when the row scrolls into view.

The share-URI ([extended share card](./SECURITY.md)) carries the
three discovery items: `(agent_id, profile_addr, relay_hint)`.

---

## 1. Canonical schema

A manifest is a JSON object with **exactly** the fields below.
Unknown / extra top-level fields cause verification to fail.

| field            | type            | constraint                                                                |
| ---------------- | --------------- | ------------------------------------------------------------------------- |
| `version`        | u8              | `= 1`. Manifests with a different version are not v1 and don't parse here. |
| `agent_id`       | string          | 64 lowercase hex chars; must equal `derive_agent_id(ml_dsa_pubkey_raw)`.  |
| `display_name`   | string          | UTF-8, ≤ 64 bytes. Required.                                              |
| `bio`            | string          | UTF-8, ≤ 280 bytes. Omit when empty (omitempty).                          |
| `website`        | string          | URL, ≤ 256 bytes. Omit when empty.                                        |
| `links`          | array (object)  | ≤ 8 entries. See § 1.1. Omit when empty.                                  |
| `avatar`         | object          | See § 1.2. Omit when no avatar set.                                       |
| `ml_dsa_pubkey`  | string          | base64url-no-pad of the raw 1952-byte ML-DSA-65 public key.               |
| `kem_pubkey`     | string          | base64url-no-pad of the raw 1184-byte ML-KEM-768 public key.              |
| `issued_at_ms`   | u64             | Unix epoch milliseconds. Monotonic: a fresh manifest must exceed the last seen `issued_at_ms` for the same `agent_id`. |
| `expires_at_ms`  | u64             | Optional. UX freshness hint, not a security boundary.                     |
| `sig`            | string          | base64url-no-pad of the ML-DSA-65 signature over the canonical bytes. See § 2. |

### 1.1 `links[]` entries

Each link is an object:

| field   | type   | constraint                              |
| ------- | ------ | --------------------------------------- |
| `kind`  | string | one of: `website`, `image`, `etchit`, `fetchit`, `x0x`. |
| `label` | string | UTF-8, ≤ 32 bytes.                      |
| `addr`  | string | meaning depends on `kind`:              |
|         |        | • `website` -- URL (≤ 256 bytes)          |
|         |        | • `image` -- 64-hex Autonomi address      |
|         |        | • `etchit` -- 64-hex Autonomi address     |
|         |        | • `fetchit` -- 64-hex Autonomi address    |
|         |        | • `x0x` -- 64-hex `agent_id` (opens Add-contact prefilled) |

### 1.2 `avatar` object

| field      | type   | constraint                                              |
| ---------- | ------ | ------------------------------------------------------- |
| `addr`     | string | 64-hex Autonomi address of the WebP bytes.              |
| `mime`     | string | `image/webp` exactly. Allowlist for v1.                 |
| `w`        | u16    | width in pixels, ≤ 256.                                 |
| `h`        | u16    | height in pixels, ≤ 256.                                |
| `bytes_len`| u32    | size of the WebP bytes at `addr` (consumer cap check).  |

The avatar is **never inlined**. Its `addr` is fetched lazily by
the consumer when the contact row scrolls into view.

---

## 2. Canonicalisation + signing

The signature is computed over a domain-separated, JCS-canonicalised
form of the manifest:

```
sign_input  =  SIGN_DOMAIN_PROFILE
             || jcs_canonical_bytes(manifest_without_sig)

SIGN_DOMAIN_PROFILE = b"fetchit/profile-manifest/v1"
                       (27 bytes, no NUL terminator)
```

1. Strip the `sig` field from the manifest object.
2. Canonicalise the remaining JSON via **RFC 8785 JCS**. Both sides
   target the `serde_jcs` crate (1.0).
3. Concatenate the byte-literal `SIGN_DOMAIN_PROFILE` with the JCS
   output to form `sign_input`.
4. POST `sign_input` to x0xd's `/agent/sign` (existing endpoint, no
   protocol change). x0xd holds the ML-DSA-65 secret throughout --
   neither etch>it nor fetch>it ever sees it.
5. base64url-no-pad the returned signature bytes.
6. Inject the resulting string back as the `sig` field.

The `ml_dsa_pubkey` is part of the JCS object so the signature
binds to it. This closes the public-key rebind attack: an attacker
who substitutes a different pubkey but keeps the rest of the body
intact cannot make the sig verify.

---

## 3. Verification

A consumer verifies a manifest as:

```rust
1. Parse the JSON. Fail on unknown top-level fields.
2. Strip `sig`. Re-canonicalise via serde_jcs.
3. Build verify_input = SIGN_DOMAIN_PROFILE || jcs_bytes.
4. Decode `ml_dsa_pubkey` (base64url-no-pad → 1952 bytes).
5. Decode `agent_id` (64-hex → 32 bytes).
6. Re-derive: derive_agent_id(ml_dsa_pubkey_bytes) must equal the
   decoded `agent_id`. (Same convention as the relay; see
   fetchit_relay_proto::derive_agent_id.)
7. Decode `sig` (base64url-no-pad → 3309 bytes).
8. ml_dsa_verify(ml_dsa_pubkey, verify_input, sig) must succeed.
9. (Optional, UX) Reject manifests with `issued_at_ms` not strictly
   greater than the last seen value for this `agent_id`.
```

Steps 1-8 are mandatory; failing any one means the manifest is not
trusted. Step 9 is the freshness rule the relay index also enforces
on POST.

---

## 4. Relay profile-index endpoint

The relay exposes a thin index so consumers can discover the latest
`profile_addr` for a known `agent_id` without scraping Autonomi.
It is **a discovery hint, not the trust root**: every fetched
manifest is verified end-to-end by the consumer.

### POST `/v1/profile`

```json
{
  "agent_id":       "<64-hex>",
  "profile_addr":   "<64-hex>",
  "kem_pubkey":     "<base64url-no-pad>",
  "ml_dsa_pubkey":  "<base64url-no-pad>",
  "issued_at_ms":   1717000000000,
  "sig":            "<base64url-no-pad>"
}
```

Signed with `SIGN_DOMAIN_PROFILE` over the JCS canonical of the
body sans `sig`. (Same domain as the manifest; the relay index
record is a thin wrapper around the manifest's identity binding.)

The server:

1. Re-derives `agent_id` from `ml_dsa_pubkey` and rejects on mismatch.
2. Verifies the signature.
3. Rejects when `issued_at_ms` is not strictly greater than the
   stored value for this `agent_id`.
4. Persists the record.

### GET `/v1/profile/{agent_id}`

Returns the most recent record. Response shape is the POST body
verbatim. Verifier brings the `ml_dsa_pubkey` from the contact card
(option **b** in the design log) -- it re-verifies the sig against
its trusted copy.

### DELETE `/v1/profile/{agent_id}`

Tombstone. Body carries the same signed envelope shape with
`profile_addr = "0".repeat(64)`. Tombstones persist; subsequent GETs
return 404 once tombstoned and a stronger `issued_at_ms` is required
to undelete.

---

## 5. Test fixture

Shipped at `tests/fixtures/profile-manifest-v1/`:

```
profile-manifest-v1/
├── README.md                      pointers + provenance
├── test-ml-dsa-65.pk.bin          1952-byte ML-DSA-65 raw public key (TEST KEY)
├── test-ml-dsa-65.sk.bin          4032-byte ML-DSA-65 raw secret key (TEST KEY)
├── test-ml-kem-768.pk.bin         1184-byte ML-KEM-768 raw public key (TEST KEY)
├── minimal/
│   ├── manifest.json              the manifest with sig included
│   ├── canonical.bin              JCS canonical bytes of manifest_without_sig
│   └── sig.bin                    raw ML-DSA-65 signature (3309 bytes)
├── maximal/
│   ├── manifest.json
│   ├── canonical.bin
│   └── sig.bin
└── tampered-maximal/
    ├── manifest.json              maximal/manifest.json with the first byte of display_name flipped after signing
    ├── canonical.bin              recomputed from the tampered JSON
    └── sig.bin                    inherited from maximal/sig.bin (does NOT verify)
```

The keys are **test-only** -- published in this repo and any clone
holds the secret. They MUST NOT sign anything ever published on the
real Autonomi network.

The fixture is regenerated by an idempotent generator binary at
`crates/fetchit-chat/src/bin/profile_fixture_gen.rs`. `canonical.bin`
is always rewritten (JCS is deterministic); `sig.bin` is only
written when missing, since ML-DSA-65 sign is non-deterministic
in saorsa-pqc. The generator verifies each committed sig against
the live pubkey + freshly-computed canonical bytes -- a drift
between the spec and the committed signature surfaces as a
verify failure on the next run.

### Required assertions (both repos)

For each of `minimal/` and `maximal/`:

```
(a) jcs_canonical(strip_sig(load(manifest.json))) == load(canonical.bin)
(b) ml_dsa_verify(pubkey, SIGN_DOMAIN_PROFILE || load(canonical.bin),
                  load(sig.bin)) == Ok(())
(c) derive_agent_id(pubkey) == hex_decode(manifest.agent_id)
```

For `tampered-maximal/`:

```
(d) jcs_canonical(strip_sig(load(manifest.json))) == load(canonical.bin)
(e) ml_dsa_verify(pubkey, SIGN_DOMAIN_PROFILE || load(canonical.bin),
                  load(sig.bin)) == Err(_)
```

The tampered case exists so both implementations confirm a byte
flip after signing is caught -- i.e. neither side is verifying a
serialised echo of the input instead of the actual signed bytes.

---

## 6. References

- RFC 8785 -- JSON Canonicalization Scheme (JCS).
- `fetchit_relay_proto::derive_agent_id` (`crates/fetchit-relay-proto/src/identity.rs`)
  -- canonical agent_id derivation; both sides path-dep until publish.
- `x0xd_client::X0xdSigner` (`crates/x0xd-client/src/signer.rs`)
  -- POSTs `/agent/sign`; the only signing surface in v1.
- `crates/fetchit-chat/src/profile.rs` -- fetch>it consumer module
  (verify + cache; renders into the chat header / contact row).
- `apps/etchit-desktop/src/tabs/profile.ts` -- etch>it publisher tab.

---

## 7. Migration & invariants

- The manifest format and signing pipeline are frozen at v1. A
  future v2 raises `version` and lives at a different
  `SIGN_DOMAIN_*`.
- `agent_id` is permanent for the life of an x0xd keypair. Rotating
  x0xd identity is a destructive operation that issues a *new*
  agent_id (and breaks every existing contact card).
- `profile_addr` is mutable. The relay index resolves it; consumers
  cache by `(agent_id, issued_at_ms)`.
- Manifests must fit in 1 KB so a relay GET response stays small
  enough to bundle inside a single TLS record on the chat WS.
