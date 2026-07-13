# Deploying fetchit-bridge-server

`fetchit-bridge-server` is a standalone ActivityPub bridge: it serves
WebFinger plus PQ-attested actor documents for fetch>it-native handles, so
the wider fediverse can resolve `@<handle>@<your-domain>`. It is a single
axum binary backed by a `SQLite` file. It holds no wallet and never signs on
a user's behalf -- it verifies an ML-DSA-65 attestation at registration, then
stores and serves the canonical actor document.

This guide deploys one bridge behind a TLS-terminating edge. For the
Cloudflare Worker edge that lets the same domain keep serving a static site,
see `../../apps/fetchit-bridge-worker/README.md`.

## 1. Build

```bash
cargo build --release -p fetchit-bridge-server
```

The binary lands at `target/release/fetchit-bridge-server`.

## 2. Configuration

All configuration is environment variables, read once at startup:

| Variable | Default | Notes |
|---|---|---|
| `FETCHIT_BRIDGE_BIND` | `127.0.0.1:8089` | Listen address. Keep it on loopback behind the reverse proxy. |
| `FETCHIT_BRIDGE_DOMAIN` | `etchit.io` | The **public fediverse domain** -- the `<domain>` in `acct:<handle>@<domain>`. Must equal the host in every minted actor id. **Not** the bridge machine's own hostname (see the warning below). |
| `FETCHIT_BRIDGE_DB` | `./bridge.sqlite` | `SQLite` path. Put it on persistent disk and back it up: actor registrations live here. |
| `FETCHIT_BRIDGE_RESERVED_HANDLES` | (built-in set) | Comma-separated handles to block from open registration, merged with the built-in impersonation/operator/brand list. Add your operators and brand variants. |
| `FETCHIT_BRIDGE_REGISTER_BURST` | `10` | Per-IP registration burst before throttling. `0` disables the limiter. |
| `FETCHIT_BRIDGE_REGISTER_PER_MIN` | `10` | Sustained per-IP registration rate (token refill, requests/minute). |
| `FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS` | `0` | Number of trusted reverse proxies in front. `0` keys the limiter on the socket peer and ignores `X-Forwarded-For`. Set to the real proxy count behind a TLS terminator / CDN, or the limiter keys every client on the proxy IP. See section 3. |

> **The one misconfiguration that silently 403s every registration.**
> Registration requires the submitted actor id's host to equal
> `FETCHIT_BRIDGE_DOMAIN` -- this is what stops a self-attested foreign id
> from hijacking a handle. Every fetch>it client mints
> `https://<domain>/actors/<handle>`. If you set `FETCHIT_BRIDGE_DOMAIN` to
> the *machine's* name (e.g. `bridge-origin.example.com`) instead of the
> *public* domain (`example.com`), every `POST /actors` returns 403. The
> bridge warns at startup if the value carries a port, but it cannot detect a
> wrong-host value -- double-check it. Keep all four equal: client mint domain
> == `FETCHIT_BRIDGE_DOMAIN` == WebFinger host == actor URL host.

## 3. TLS topology

The bridge speaks plain HTTP on loopback; terminate TLS in front of it. Every
served endpoint is public-read except `POST /actors` (registration):

```
client ──TLS──▶ edge (CF Worker / proxy) ──TLS──▶ origin proxy (Caddy) ──http──▶ 127.0.0.1:8089 (bridge)
```

`deploy/Caddyfile.example` terminates TLS at the origin and reverse-proxies to
the bridge. Caddy auto-provisions a Let's Encrypt certificate; the origin
hostname must resolve publicly to this host (DNS-only -- not proxied -- if you
also front the public domain with Cloudflare).

Behind a proxy chain, set `FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS` to the number of
proxies between the client and the bridge that append to `X-Forwarded-For`, so
the registration rate limiter keys on the real client IP and not the proxy's.
For the reference CF Worker + Caddy chain above that is **2** (the Worker sets
the client IP, Caddy appends the Worker's egress); for a single origin proxy
with no CDN it is **1**. Leave it at `0` and every request is attributed to the
proxy, so the proxy shares one bucket and a burst from anyone throttles
everyone. Never set it *higher* than the real hop count -- that would let a
client spoof `X-Forwarded-For` to dodge the limit.

**A non-zero hop count is only safe if the origin is reachable solely through
that proxy chain.** If the origin is publicly reachable (e.g. a grey-DNS host
behind a CDN), firewall it to the CDN / edge IP ranges first; otherwise an
attacker who connects to the origin directly presents a shorter chain and can
spoof `X-Forwarded-For` to forge any key. When in doubt, keep `0` -- aggregate
but unspoofable.

## 4. Run as a service

`deploy/fetchit-bridge-server.service` uses systemd `DynamicUser` plus
`StateDirectory`, so it creates its own user and `/var/lib/fetchit-bridge`
with no manual account setup:

```bash
sudo cp target/release/fetchit-bridge-server /usr/local/bin/
sudo cp deploy/fetchit-bridge-server.service /etc/systemd/system/
sudoedit /etc/systemd/system/fetchit-bridge-server.service   # set FETCHIT_BRIDGE_DOMAIN etc.
sudo systemctl daemon-reload
sudo systemctl enable --now fetchit-bridge-server
```

## 5. Edge integration

A remote server resolving `acct:<h>@<domain>` does: `GET
/.well-known/webfinger?resource=acct:<h>@<domain>` -> follows the `self` link
to `https://<domain>/actors/<h>` -> fetches the attested actor document. Both
must be reachable at your public domain. If that domain also hosts a static
site, the Cloudflare Worker in `apps/fetchit-bridge-worker/` binds only the
two fediverse route prefixes and proxies them here, leaving the rest of the
site on its existing host.

## 6. Verify

```bash
curl "https://<domain>/.well-known/webfinger?resource=acct:<handle>@<domain>"
curl https://<domain>/actors/<handle>
```

A registered handle returns a JRD and an `application/activity+json` actor
document. `/health` and `/metrics` are intended for the operator's own
network, not the public edge.

`deploy/smoke.sh <domain> [actor.json]` runs these checks in one shot, plus
edge-routing assertions and a check that `/health` / `/metrics` are not
reachable through the public domain. Pass a desktop-minted `actor.json` to also
exercise the full register -> resolve -> fetch chain.

## 7. Security posture before public exposure

- **Open registration.** `POST /actors` accepts any valid ML-DSA-65
  self-attestation: the attestation is unforgeable, but the endpoint is
  unauthenticated. Three defenses are built in -- the reserved-handle
  block-list (section 2), a 64 KiB body cap, and a per-IP token-bucket rate
  limiter (`FETCHIT_BRIDGE_REGISTER_BURST` / `_PER_MIN`, enabled by default).
  The limiter keys on the client IP, so **set `FETCHIT_BRIDGE_TRUSTED_PROXY_HOPS`
  to your proxy count** (section 3) or it throttles per proxy instead of per
  client. RSA proof-of-control on registration is the remaining hardening step.
- **Reserved handles.** Seed `FETCHIT_BRIDGE_RESERVED_HANDLES` with your
  operators and brand variants so they cannot be squatted. Reserved handles
  are blocked from open registration; seed the ones you actually want out of
  band (direct store insert).
- **Persistence.** The `SQLite` file is the source of truth for who owns which
  handle. Back it up; losing it frees every handle for re-registration.
- **No wallet, no signing.** The bridge verifies attestations and serves
  documents. It never holds keys or publishes to Autonomi.
