# fetchit-bridge-server

The dedicated ActivityPub bridge node for the fetch>it network. It runs
as its own binary, **structurally isolated** from the RAM-only chat
relays (`fetchit-relay-server`): the unauthenticated, internet-facing
federation surface never shares a process with the load-bearing chat
path.

## Milestone 1 surface (this crate today)

- `GET /health`, `GET /metrics`
- `POST /actors` — register a fetch>it-native actor (gated on the ML-DSA
  attestation, and bound to this bridge's own domain; rejects anything
  that is not PQ-attested or whose id is not `https://<domain>/actors/<handle>`)
- `GET /actors/:handle` — serve the canonical actor document
- `GET /actors/:handle/followers`, `GET /actors/:handle/outbox`
- `GET /.well-known/webfinger?resource=acct:<handle>@<domain>`

Durability is a single-file SQLite database (`FETCHIT_BRIDGE_DB`).

## Demo — closes the "Stage-6 actor-serving" gap

```bash
FETCHIT_BRIDGE_DOMAIN=etchit.io FETCHIT_BRIDGE_DB=/tmp/bridge.sqlite \
  cargo run -p fetchit-bridge-server          # listens on 127.0.0.1:8089

# Register a minted actor doc (actor.json carries the ML-DSA attestation):
curl -X POST http://127.0.0.1:8089/actors \
  -H 'content-type: application/activity+json' --data @actor.json

# Resolve the pretty handle:
curl 'http://127.0.0.1:8089/.well-known/webfinger?resource=acct:alice@etchit.io'

# Fetch the verifiable actor document:
curl http://127.0.0.1:8089/actors/alice
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `FETCHIT_BRIDGE_BIND` | `127.0.0.1:8089` | HTTP bind address |
| `FETCHIT_BRIDGE_DOMAIN` | `etchit.io` | authoritative fediverse domain |
| `FETCHIT_BRIDGE_DB` | `./bridge.sqlite` | SQLite database path |
| `FETCHIT_BRIDGE_RESERVED_HANDLES` | (built-in set) | extra handles blocked from open registration |
| `FETCHIT_BRIDGE_REGISTER_BURST` | `10` | per-IP registration burst (`0` disables the limiter) |
| `FETCHIT_BRIDGE_REGISTER_PER_MIN` | `10` | sustained per-IP registration rate (token refill, req/min) |
| `FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS` | `0` | trusted proxies in front (`0` = key on socket peer, ignore `X-Forwarded-For`) |

## Deploy

See [`DEPLOY.md`](DEPLOY.md) for the production runbook (build, config, TLS
topology, systemd unit, edge integration, and the security posture before
public exposure); ready-to-edit templates are in [`deploy/`](deploy/). The
Cloudflare Worker that fronts `etchit.io` lives in
[`../../apps/fetchit-bridge-worker/`](../../apps/fetchit-bridge-worker/).

## Not yet (follow-on plans)

Follow/Accept/Undo, outbox fan-out + durable retry, moderation, `/inbox`
relocation, and RSA proof-of-control on registration.
