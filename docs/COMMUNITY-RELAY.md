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
   deploy, ops, and monitoring. The binary is a single statically-linked
   ~15 MB Linux binary built with `cargo build --release`.
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
