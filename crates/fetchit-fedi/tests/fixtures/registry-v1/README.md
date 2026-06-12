# Registry wire contract v1 (M5.1, Component D)

Client: `crates/fetchit-fedi/src/registry.rs`. Server: `fetchit-bridge-server`.
Spec: `docs/superpowers/specs/2026-06-12-m5-discovery-design.md`.

These fixtures are the cross-lane handshake artifact: the client tests pin
the request/response JSON byte-for-byte against them, and the bridge's
endpoint tests should do the same. Changing a fixture is a contract change
and needs both lanes' sign-off.

## POST /v1/actors (register)

Body: `register-request.json`. The bridge MUST:

1. Validate the handle: `[A-Za-z0-9_-]`, 1..=64 chars.
2. Construct `actor_url` as `https://<domain>/actors/<handle>`.
3. Verify `attestation_v2` via
   `fetchit_fedi::attestation::verify_binding_v2` with
   `(handle, actor_url, rsa_spki_der)`. The agent id is DERIVED from the
   attested ML-DSA pubkey, never read from a claim.
4. Reject `version != 2` records (v1 records are re-minted client-side;
   there is no v1 registration path).
5. First come, first served on the handle. Rate-limit per source.

Responses:

| Status | Meaning | Body |
| --- | --- | --- |
| 201 | registered | `register-response.json` |
| 409 | handle taken | none required |
| 422 | attestation invalid | reason text, served back to the user |
| 429 | rate limited | none required |

## PUT /v1/actors/&lt;handle&gt; (update)

Same body and verification as POST, plus:

1. Same-agent-id continuity: the derived agent id MUST equal the
   registered one (a handle never silently changes hands).
2. `hint_epoch_ms` MUST be strictly greater than the stored record's
   (same monotonicity rule as card v2 rendezvous hints).

Responses:

| Status | Meaning |
| --- | --- |
| 200 | updated, body `register-response.json` |
| 404 | unknown handle |
| 409 | agent id mismatch or stale epoch |
| 422 | attestation invalid |
| 429 | rate limited |

The directory serves the stored attestation inside the WebFinger record
and the actor document (under `https://etchit.io/ns#mlDsaAttestation-v2`)
so any client can verify the full chain offline.
