# Profile Manifest v1 -- test fixture

Reference fixture for `docs/profile-manifest-v1.md`. Both etch>it
(publisher) and fetch>it (consumer) consume this in CI to confirm
JCS canonicalisation, ML-DSA-65 verification, and tamper detection
agree byte-for-byte across implementations.

## Test keys

`test-ml-dsa-65.pk.bin` (1952 B), `test-ml-dsa-65.sk.bin` (4032 B),
and `test-ml-kem-768.pk.bin` (1184 B) are committed for
reproducibility. **They are test-only**: the secret key is public
in this repo, anyone who clones can sign as "fixture-alice". They
MUST NOT sign anything ever published on the real Autonomi network.

`derive_agent_id(test-ml-dsa-65.pk.bin)` yields the `agent_id`
embedded in every fixture manifest. The committed pubkey + the
agent_id cross-check (manifest `agent_id` == `derive_agent_id(pk)`)
is one of the assertions consumers run.

## Layout

```
profile-manifest-v1/
├── test-ml-dsa-65.pk.bin           ML-DSA-65 public key
├── test-ml-dsa-65.sk.bin           ML-DSA-65 secret key (test-only)
├── test-ml-kem-768.pk.bin          ML-KEM-768 public key
├── minimal/                        manifest with the bare-minimum field set
│   ├── manifest.json
│   ├── canonical.bin
│   └── sig.bin
├── maximal/                        manifest with every optional field set
│   ├── manifest.json
│   ├── canonical.bin
│   └── sig.bin
└── tampered-maximal/               maximal + display_name byte flip after signing
    ├── manifest.json
    ├── canonical.bin               recomputed from the tampered JSON
    └── sig.bin                     copied verbatim from maximal/sig.bin
```

`canonical.bin` is RFC 8785 JCS canonical bytes of the manifest
**with `sig` stripped**. The signing input is
`b"fetchit/profile-manifest/v1" || canonical.bin`. `sig.bin` is the
raw ML-DSA-65 signature (3309 bytes).

## Regeneration

`cargo run -p fetchit-chat --bin profile-fixture-gen`. The
generator is **idempotent**: it always rewrites the JCS
`canonical.bin` (deterministic) but only writes `sig.bin` when
missing, then verifies the on-disk sig against the live pubkey +
canonical bytes. ML-DSA-65 is non-deterministic in saorsa-pqc,
so a fresh `sign()` would never byte-match the committed value --
the verify-on-regen step instead catches drift: if you change the
spec, JCS output, or signing input, the next run errors with
"committed sig does NOT verify". Delete the affected `sig.bin`
files and re-run to re-sign.
