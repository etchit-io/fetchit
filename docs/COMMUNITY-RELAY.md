# Operating a Community Relay

fetch>it's chat surface routes opaque sealed envelopes through a
*federation* of relays. The two reference relays in `nyc` and `fra`
are the default; community-operated relays widen that to more regions
and more operator sovereignty.

If you want to run one and have it ship in the default bootstrap list
that every fetch>it client dials, this is the path.

## What a community relay is

A community relay is a deployment of the
[`fetchit-relay`](https://github.com/etchit-io/fetchit-relay) binary
operated by someone other than the fetch>it maintainers, included in
the default bootstrap list every fetch>it client dials. It carries
the same opaque, sealed traffic — the protocol's end-to-end
authenticated encryption holds regardless of who runs the relay, so
a community operator can't read message bodies, can't impersonate
participants, and can't censor by sender (the relay only sees
recipient routing).

The federation property — multiple independent relays carrying the
same conversations — means a community relay outage degrades reach
for the users it would have served, but doesn't break a single
conversation. fetch>it clients send to every healthy relay in their
set, so as long as one member of the federation is up, every send
lands.

## Why operate one

- **Geographic reach.** A relay close to your community cuts round-trip
  latency. `sgp`, `syd`, `sfo` (and beyond) are open regions.
- **Operator sovereignty.** You make the abuse / DMCA / compliance
  decisions for your relay. The protocol's threat model assumes the
  relay is honest-but-curious; your community decides what that
  means in practice.
- **Federation resilience.** Three reference relays are enough to
  stay reachable through ordinary outages, but a federation of ten
  community relays is harder to take down at scale.

## Acceptance criteria

For inclusion in the default `DEFAULT_RELAYS` table:

1. **7 days of clean operation.** No sustained downtime, no
   uncontrolled restarts, no `RAM-cap` overruns. Prometheus exporter
   on the loopback channel records the evidence.
2. **Maintainer-team read access to your Prometheus instance.** Not
   shell access; a scrape endpoint we can poll. This lets us notice
   degradation across the federation before users do.
3. **Public point of contact for security disclosures.** A monitored
   inbox at `security@<your-domain>` or a GitHub security advisory
   path on the operator's repo. We surface this on
   `etchit.io/relays` next to your region tag.
4. **A signed commitment to the protocol's contracts.** No content
   inspection, no on-disk envelope persistence (RAM-only transit
   buffer, per the unit's hardening flags), no plaintext metric
   labels (the
   [`fetchit-relay` repo](https://github.com/etchit-io/fetchit-relay)
   spells out the typed-incrementer + allow-list pattern).

These aren't legal contracts. They're the design properties fetch>it
clients rely on. A relay that diverges from them isn't *broken*, but
it's no longer the same threat model — so it isn't shipped as a
default.

## The onboarding flow

1. **Read the [`fetchit-relay`](https://github.com/etchit-io/fetchit-relay)
   repository.** README + systemd unit + `env.example` cover build,
   deploy, ops, and monitoring. The `fetchit-relay-server` binary is
   a single statically-linked ~15 MB Linux binary built with
   `cargo build --release`.
2. **Pick a region tag.** Common tags: `nyc`, `fra`, `sgp`, `syd`,
   `sfo`. New tags are fine — chat clients bucket unknown tags as
   `other` until the next default bump.
3. **Deploy on your infrastructure.** TLS termination is your
   responsibility (`fetchit-relay-server` speaks plain HTTP and
   WebSocket; sit it behind nginx / Caddy / a load balancer). The
   protocol carries its own end-to-end encryption so even a hostile
   intermediary can't read traffic, but TLS keeps relay-side
   metadata (recipient agent IDs) off the wire to in-path observers.
4. **Soak for 7 days.** Watch `fetchit_relay_uptime_seconds`,
   `fetchit_relay_connections_active`,
   `fetchit_relay_envelopes_dropped_ttl_total` (a rising drop count
   is the inter-relay reach signal: when high, clients you serve
   are talking to recipients on relays you don't peer with — that's
   fine; the federation routes around it).
5. **Open a PR against [`etchit-io/fetchit`](https://github.com/etchit-io/fetchit)
   adding your relay** to
   `crates/fetchit-relay-client/src/region_probe.rs::DEFAULT_RELAYS`.
   Include your scrape endpoint and your security-contact address in
   the PR description (we add them to `etchit.io/relays` after merge).
6. **Maintainer-team review.** We verify the 7-day Prometheus
   history, the security-disclosure path, and that your `Ready`
   frames advertise the region you claim. Once green, we merge — the
   next chat-peer release includes your relay in the default set.

## Ongoing responsibilities

- **Patch promptly.** Major fetch>it releases that change the wire
  shape (every six months or so) come with a 30-day patch window.
  Relays that lag get a "stale" badge on `etchit.io/relays`.
- **Disclose breaches and outages.** Anything that breaks the
  honest-but-curious model — root compromise, log retention beyond
  the documented memory footprint, anything — needs a public
  disclosure on your contact path. The federation routes around
  individual relays; transparency is the price of staying in the
  default set.
- **Don't impersonate operators.** A community relay is yours.
  Don't suggest it speaks for fetch>it or its maintainers.

## Optional: the fediverse-inbox role

A community relay can *also* opt in to bridging the fediverse —
accepting inbound `ActivityPub` public posts at `POST /inbox` and
fanning them into the LIT Chat public feed. This is **off by default**:
the standard relay build ships no fediverse code or its dependency
tree, and a default deployment has no `/inbox` route at all.

To enable it, build with the feature *and* set the opt-in flag:

```bash
cargo build --release --features fediverse-inbox
FETCHIT_FEDIVERSE_INBOX=1 ./fetchit-relay-server
```

Configuration (read from the environment):

| Variable | Default | Purpose |
| --- | --- | --- |
| `FETCHIT_FEDIVERSE_INBOX` | unset (off) | Set to `1` (or `true`) to mount `POST /inbox`. Unset = no fediverse surface, even on a `fediverse-inbox` build. |
| `FETCHIT_DENYLIST_URL` | `https://trust.etchit.io/v1` | Base URL of the signed denylist the inbox gates inbound actors against. Point it elsewhere to gate on a different moderation list. |
| `FETCHIT_DENYLIST_CACHE` | unset | Optional path to an on-disk denylist snapshot so the gate survives a restart before its first refresh. |

What the inbox does to every inbound activity, before it reaches any
client:

1. **Size + rate limits**, then **HTTP Signature verification** — the
   relay fetches the signing actor's public key from its actor document
   (SSRF-gated: private-IP and cloud-metadata targets are refused) and
   verifies the signature. An unsigned or wrong-signature post is
   dropped.
2. **Denylist gate** — the verified actor URL is checked against the
   signed `etchit-io` denylist (`EntryKind::ActorUrl`), the same list
   desktop clients consult. A denylisted actor's post never reaches a
   client. Until the consumer's first poll completes (seconds after
   boot), the list is empty and the gate is **fail-open** — a
   freshly-started inbox briefly accepts before its first refresh.
   `FETCHIT_DENYLIST_CACHE` narrows that window by seeding the last
   on-disk snapshot at boot.
3. **Replay window** — duplicate `(Content-Digest, Date)` pairs are
   dropped.

A post that clears every gate is fanned out to connected sessions as an
`EnvelopeKind::PublicPost`, attributed to the **relay-verified** actor
URL — not the activity's self-asserted `actor` field, which is
attacker-controlled.

**This is a real trust boundary.** Clients can't verify the HTTP
Signature themselves, so they trust your relay as the
fediverse-attribution authority for the posts it bridges. Running the
fediverse-inbox role means taking on that responsibility — and the
moderation surface that comes with it — for your community. See
[`crates/fetchit-chat/SECURITY.md`](../crates/fetchit-chat/SECURITY.md)
caveat 8 for the full trust model. The default LIT Chat relay role
carries none of this; opt in only if your community wants to bridge.

## When a relay leaves the federation

We remove a relay from `DEFAULT_RELAYS` when:

- The operator asks us to (sunsetting their deployment).
- The relay has been hard-down for 7 consecutive days without
  operator response.
- A confirmed protocol-contract violation comes to light.

Removal is via PR + the same review process as inclusion. Existing
deployed clients keep their cached bootstrap list until the next
release, but new clients stop dialing the removed relay.

---

Questions, applications, security disclosures:
[`security@etchit.io`](mailto:security@etchit.io) (catch-all forward
to maintainers).
