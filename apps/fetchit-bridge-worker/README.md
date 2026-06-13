# fetchit-bridge-worker

A Cloudflare Worker that fronts the fetch>it ActivityPub bridge on the
`etchit.io` zone, so the pretty handle `@<h>@etchit.io` resolves to the
bridge's canonical, PQ-attested actor documents -- without moving the
static marketing site off GitHub Pages.

Part of the M4 publish-half (decision **DP2**).

## What it does

Bound to **only** these routes on `etchit.io`:

- `GET /.well-known/webfinger` -- WebFinger lookups
- `GET /actors`, `GET /actors/<handle>`, `GET /actors/<handle>/{followers,outbox}` -- actor docs + collections
- `POST /v1/actors` -- self-serve handle registration
- `PUT /v1/actors/<handle>` -- relay-hint rotation for an owned handle

it reverse-proxies them to the bridge (`BRIDGE_ORIGIN`). **Every other
path** (`/`, `/etch`, `/fetch`, `/city`, ...) is served straight from
GitHub Pages -- this Worker is never invoked for it, so the marketing
site is untouched.

A remote server resolving `acct:<h>@etchit.io` hits WebFinger here,
follows the `self` link to `https://etchit.io/actors/<h>` (also proxied
here), and receives the bridge's verifiable actor document.

## Security posture

- **Not an open proxy.** `classify()` (in `src/worker.js`) re-validates
  that the path is a fediverse route before proxying -- even if the CF
  route binding is ever too broad, a non-fediverse path returns `404`,
  never a forward. The match is exact-or-subpath, so `/actorsfoo` and
  `/blog/actors` are not treated as actor routes.
- **Method allowlist:** GET on WebFinger + `/actors`; POST on
  `/v1/actors`; PUT on `/v1/actors/<handle>`. Any other method on a
  fediverse path is `405` with an accurate `Allow` header. The origin's
  rate limiter keys on `x-real-ip`, which the Worker SETs from the
  Cloudflare-authoritative `CF-Connecting-IP` (never the client value).
- The bridge's `/health` and `/metrics` are deliberately **not**
  frontable here.

## Deploy (Cloudflare, on the etchit.io account -- Josh-direct)

Prerequisite: a deployed bridge reachable over **HTTPS** (its address is
`BRIDGE_ORIGIN`). Until that is set the Worker returns `503`.

```bash
npm install
npx wrangler login                                  # the etchit.io CF account
# set the bridge origin + deploy (binds the routes in wrangler.toml):
npx wrangler deploy --var BRIDGE_ORIGIN:https://<bridge-host>
```

Confirm the zone is `etchit.io` and the bridge origin is correct before
deploying. The routes in `wrangler.toml` bind on `wrangler deploy`.

## Verify (after deploy)

```bash
# resolve a registered handle end to end:
curl 'https://etchit.io/.well-known/webfinger?resource=acct:<h>@etchit.io'
curl https://etchit.io/actors/<h>
# confirm the marketing site is untouched (still GitHub Pages):
curl -I https://etchit.io/
```

## Test

```bash
npm test    # unit-tests the routing/security decision (classify)
```
