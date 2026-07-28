# PINS.md -- pinned dependency revisions

Lockstep across the etch>it / fetch>it / LIT trinity. Bumping any
crate listed here without ALSO bumping the matching pin in etch>it
desktop and etch>it android breaks the wire format between the two
sides of the pair.

`scripts/check-pins.sh` (wired into `.github/workflows/ci.yml`) fails
CI if `Cargo.lock` drifts from any rev or version listed below.

## Workspace pins (root `Cargo.toml`)

| Crate              | Pin                                                  | Why                                                                 |
|--------------------|------------------------------------------------------|---------------------------------------------------------------------|
| `ant-core`         | `rev = "bcab72ae7"` (WithAutonomi/ant-client, v0.4.0) | Wire shape for Autonomi address resolution. Lockstep with etch>it.  |
| `self_encryption`  | `= "0.36.0"`                                          | Self-encryption chunking; rev affects renderer + relay payload size |
| `xor_name`         | `= "5.0.0"`                                           | Autonomi address type. Wire-level breaking on bump.                 |
| `saorsa-pqc`       | `"0.5"` (resolves to `0.5.1`)                         | ML-KEM-768 + ML-DSA-65 primitives. Affects vault + envelope crypto. |
| `snow`             | `"0.10.0"` (transitive lock)                          | Noise XX for LAN-direct channel-binding handshake.                  |
| `four-word-networking` | `= "2.7.0"`                                       | Word rendering for identities (`fetchit-words`). Same crate+version x0x uses; a dictionary change makes the same id read as different words across apps. |

## fetchit-ffi pins (workspace-excluded crate)

| Crate     | Pin                                          | Why                                                                                 |
|-----------|----------------------------------------------|-------------------------------------------------------------------------------------|
| `uniffi`  | `= "0.29.5"` (with `tokio` + `build` features) | Kotlin/Swift binding stability -- `uniffi-bindgen-cli` must match crate exactly.    |

## Out-of-tree pins (operational)

These aren't Cargo deps but ship lockstep with the binaries above:

| Asset                  | Pin                                  | Why                                                            |
|------------------------|--------------------------------------|----------------------------------------------------------------|
| `x0xd`                 | `0.34.3` (tail `e381a319de8581b0a7e80e28b8fafe9c088a1d93`) | Daemon REST + SSE + WS contract; bundled by desktop `build.rs` (`X0XD_PIN_VERSION`/`X0XD_PIN_SHA` — `check-pins.sh` asserts this row against those consts, so this row can no longer drift silently) and embedded on Android via the fetchit-ffi `x0x` git pin at the **same rev**. Post-defork: stock upstream v0.34.3 (which absorbed the 0.29-era fork tail — returning-member re-key, actor-authz `committed_by`, `GET /groups/:id/secure/self`) plus the short engine-A tail on `engine-a-34` (josh-clsn/x0x): relay-delivered group-join apply endpoints and TreeKEM join-retry convergence fixes. G3 cross-NAT verified 2026-07-27. Defork runbook lives in the ops repo (`x0x-defork-plan`). |
| `ant-quic`             | (Saorsa fork of ant-quic, not yet used) | M2 Contract B dependency.                                  |
| Relay region defaults  | NYC `https://nyc-relay.etchit.io` (sole live region) | Shipped `KNOWN_RELAYS` table in `apps/fetchit-desktop/src-tauri/src/settings.rs`. FRA decommissioned 2026-07; both retired bare-IP rows (`67.207.94.66:8088`, `159.89.11.217:8088`) survive only in the frozen `RELAY_URL_MIGRATIONS` / `BARE_IP_RELAY_MIGRATIONS` healing tables. |

## What "drift" means

The check script fails if any of the following diverges from the
table above:

1. `Cargo.lock` shows a different rev/version for any crate listed
2. `Cargo.toml` editing changed the pin shape without updating this
   document
3. The relay-region defaults in `settings.rs` don't match the
   `Relay region defaults` row

To bump a pin: update `Cargo.toml` + this document + run
`cargo update -p <crate>` + verify cross-repo (etch>it desktop /
android) on the same rev BEFORE merging. Commits land lockstep with
the etch>it side per the trinity-milestones contract.

## Why this exists

A silent crate bump can land a wire-format change between releases --
historical messages don't decrypt, contact cards reject, group
messages decode to gibberish. The Autonomi forum has been burned by
exactly this kind of drift on other projects. Naming the pins and
gating them at CI is one afternoon of work that prevents a launch-
week support nightmare.
