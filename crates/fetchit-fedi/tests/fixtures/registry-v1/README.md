# Registry wire contract v1 (M5.1, Component D)

Client: `crates/fetchit-fedi/src/registry.rs`.
Server: **`fetchit-relay-server` built with `--features fediverse-inbox`** (the
fediverse bridge role; there is no separate `fetchit-bridge-server` crate). The
`/v1/actors` endpoints mount in the same feature-gated router that mounts
`POST /inbox` today (`fetchit-relay-server/src/inbox/router.rs`, composed in
`server.rs`).
Spec: `docs/superpowers/specs/2026-06-12-m5-discovery-design.md`.

These fixtures are the cross-lane handshake artifact: the client tests pin the
request/response JSON byte-for-byte against them, and the bridge's endpoint tests
should do the same. Changing a fixture is a contract change and needs both lanes'
sign-off.

## Fixtures

- `register-request.json` / `register-response.json`: pin the wire SHAPE
  (placeholder key bytes; does NOT cryptographically verify).
- `register-request-valid.json`: a cryptographically VALID request (real
  ML-DSA-65 keypair, real signature). The bridge's `register -> 201` success-path
  test should `include_str!` this; it verifies under `verify_binding_v2` against
  the canonical actor_url below. Regenerate after any wire change with
  `cargo test -p fetchit-fedi emit_valid_registration_fixture -- --ignored --nocapture`
  (a `#[test]`-guarded copy in `registry.rs` keeps it from rotting silently).

## Canonical actor_url (byte-sensitive, read this)

The bridge does NOT take the actor_url from the request. It CONSTRUCTS it from
`(domain, handle)` and feeds it to `verify_binding_v2`. `signing_input_v2` renders
it via `url::Url::as_str()`, so any drift (trailing slash, port, case, IDNA)
silently breaks EVERY signature. Construct it exactly as the client does
(`fetchit_chat::client::build_actor_url`):

```
actor_url = url::Url::parse(&format!("https://{domain}/actors/{handle}"))
// for domain="etchit.io", handle="josh":
//   actor_url.as_str() == "https://etchit.io/actors/josh"   (no trailing slash)
```

The valid fixture is signed against `https://etchit.io/actors/josh`.

## Handle case policy (decided 2026-06-12)

Handles are **lowercase**: `[a-z0-9_-]`, 1..=64. The client lowercases user input
at mint and lookup; `fetchit_chat::client::validate_actor_handle` rejects any
non-lowercase handle, so the signed bytes / actor_url / vault path are always the
single canonical form. The bridge MUST reject a request whose `handle` contains
an uppercase byte (422) rather than silently lowercasing it (the attestation was
signed over the exact handle; lowercasing server-side would invalidate the sig).
This matches the fediverse convention of case-insensitive acct local-parts and
removes the `Josh` vs `josh` desync across registration / WebFinger / actor-doc /
attestation.

## POST /v1/actors (register)

Body: `register-request.json` (shape) / `register-request-valid.json` (valid).
The bridge MUST:

1. Validate the handle: `[a-z0-9_-]`, 1..=64 chars (reject uppercase).
2. Construct `actor_url` as above.
3. Verify `attestation_v2` via `fetchit_fedi::attestation::verify_binding_v2`
   with `(handle, actor_url, rsa_spki_der)`. The agent id is DERIVED from the
   attested ML-DSA pubkey, never read from a claim.
4. Reject `version != 2` records (v1 records are re-minted client-side; there is
   no v1 registration path).
5. First come, first served on the handle. Rate-limit per source.

Responses:

| Status | Meaning | Body |
| --- | --- | --- |
| 201 | registered | `register-response.json` |
| 409 | handle taken | none required |
| 422 | handle not lowercase, or attestation invalid | reason text, served back to the user |
| 429 | rate limited | none required |

## PUT /v1/actors/&lt;handle&gt; (update)

Same body and verification as POST, plus:

1. Same-agent-id continuity: the derived agent id MUST equal the registered one
   (a handle never silently changes hands).
2. `hint_epoch_ms` MUST be strictly greater than the stored record's. This is the
   SAME monotonicity rule as the relay's pair-record `put_if_newer` watermark, and
   the desktop re-mints the actor record whenever it rotates the relay hint, so the
   fedi pointer and relay forwarding never diverge (one epoch source of truth per
   agent).

Responses:

| Status | Meaning |
| --- | --- |
| 200 | updated, body `register-response.json` |
| 404 | unknown handle |
| 409 | agent id mismatch or stale epoch |
| 422 | handle not lowercase, or attestation invalid |
| 429 | rate limited |

## Optional: SPKI parse-validation (SO-4)

`verify_binding_v2` treats `rsa_spki_der` as opaque bytes, so a registrant can
attest over garbage RSA and only fail later at HTTP-signature time
(self-inflicted). The bridge MAY parse-validate the SPKI at registration to fail
fast. Non-blocking. `register-request-valid.json` carries a real RSA-2048 SPKI, so
it stays green even with this check on.

The directory serves the stored attestation inside the WebFinger record and the
actor document (under `https://etchit.io/ns#mlDsaAttestation-v2`) so any client can
verify the full chain offline.
