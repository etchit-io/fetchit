# ASSETS.md — what makes this acquirable

The trinity (etch writes / fetch reads / LIT discovers / Autonomi
stores) produces four kinds of asset over the M0 → M3 roadmap. This
document names each one, the milestone it lights up under, and the
load-bearing files that build it.

These four are what an acquirer or strategic partner buys when they
buy etchit-io. The chat surface, the relay binaries, the website —
all of those are vehicles for accumulating these four assets.

---

## 1. Contact graph

**What it is:** the social topology — who has whose share card,
which agent IDs have published profiles, the implicit trust edges
formed by paste-accept and TOFU welcomes. Once a user adds a
contact, the contact's published Autonomi addresses become reachable
to them; the social graph compounds the storage usage.

**Lights up:** M1 (LIT contact cards carry published addresses).
**Compounds:** M2 (Direct mode binds the graph to per-edge routing
hints) and M3 (the constellation operates on top of the graph).

**Load-bearing files:**
- `crates/fetchit-chat/src/card.rs` — extended share card v2 schema
  (frozen in M0 with reserved v2 rendezvous-hints field)
- `crates/fetchit-chat/src/messages.rs::StoredContactCard` — local
  card store
- `crates/fetchit-relay-server/src/profile.rs` — relay-side profile
  index (`/v1/profile/*`)
- `crates/fetchit-chat/src/pair.rs` — v3 share URI consume path

**Acquirer-legible signal:** add-contact funnel + paired-contacts
count per agent (aggregate, no per-agent label per
`private/metrics-policy.md`).

---

## 2. Creator roster

**What it is:** the set of agents who have PUBLISHED content (not
just consumed). These are the writers who feed the network. Tagged
on every etched address that flows through a LIT message starting in
M2 (per MILESTONES decision #3 — publisher-LIT-identity tagging
defaults to M2 with reserved schema field frozen in M0).

**Lights up:** M2 (tagging) and M3 (paid-publish receipts on every
roster member's address).
**Compounds:** M3 paid LIT tier targets this roster directly.

**Load-bearing files:**
- `crates/fetchit-chat/src/card.rs` — published-addresses field on
  v2 share card
- (M2) tagging hook in `relay_transport.rs` or a sibling
  `publisher_index.rs`
- (M3) etch>it paid-publish receipt format (cross-repo)

**Acquirer-legible signal:** distinct-publisher count over rolling
window. Anti-leak: bucketed via HLL with rotating salt
(`fetchit-ops/docs/hll-blurb-spec.md` — Bob drafts in 2 weeks).

---

## 3. Relay + denylist constellation

**What it is:** 3+ independently operated AGPL relay nodes plus a
signed denylist publisher feeding B2B subscribers (Brave / Mullvad /
threat-intel partners). The protocol is open (M3 RFC publish lean —
pending josh's call). The canonical constellation operation under a
separate commercial-license entity is the moat.

**Lights up:** M1 (one relay public AGPL + docker-compose deploy)
and M2 (relay sealing means the operator can't see content even
under court order). 
**Compounds:** M3 (constellation goes from 1 to N, denylist becomes
B2B revenue).

**Load-bearing files:**
- `crates/fetchit-relay-server/` — the relay binary (AGPL-3.0-only;
  splits to its own repo in M1)
- `crates/fetchit-relay-proto/` — wire protocol (the M3 RFC target)
- `private/metrics-policy.md` — the allow-list that gates what the
  constellation will ever expose
- Ops dashboard at `josh-clsn/fetchit-ops` — Bob's track

**Acquirer-legible signal:** relay uptime SLA across N independently
operated regions; ML-DSA-65-signed denylist feed subscriber count.

---

## 4. Revenue line (etch paid-publish)

**What it is:** etch>it side. Authors mint MLS-envelope Autonomi
addresses, pay storage bond through etch>it wallet, the address
lands on the network with a paid-publish receipt. fetch>it just
renders. **The only legitimate revenue surface in the workspace.**
fetch>it stays wallet-free forever (`docs/CONTRIBUTING.md` will
enforce — no write paths in PRs).

**Lights up:** M3 (real ANT settlement; per josh-pending decision
#4 we ship NO stub in M2).
**Compounds:** M3 (paid LIT tier, dual-license commercial track,
managed x0xd hosted tier).

**Load-bearing files:**
- `etchit-desktop` repo (separate; coordinated via PINS.md lockstep)
- (M3) paid-publish API in `etchit-desktop/src-tauri/src/publish.rs`
- (M3) receipt format embedded in MLS envelope so LIT contact cards
  can surface "paid-publish verified"
- `docs/CONTRIBUTING.md` — wallet-free constraint enforcement

**Acquirer-legible signal:** GMV (gross merchandise value) of ANT
settled through etch>it; paying creator cohort count.

---

## What we do NOT count as an asset

- **The chat surface itself.** LIT Chat is the mechanism by which
  the four assets accumulate — it's not the product. The product is
  the trinity through-line. A messenger competitor can ship better
  chat-UX and we still win on the assets.
- **The reader app (fetch>it).** Free, wallet-free, AGPL. The asset
  is the storage-usage growth that fetch>it drives on Autonomi
  (storage GMV → ant-core ecosystem health), not the binary itself.
- **User data.** Privacy-respecting framing requires this be NOT an
  asset. Aggregate counts only (per `private/metrics-policy.md`); no
  per-agent dimensions ever land in scrapeable metrics.

---

## Audit hook

`scripts/check-pins.sh` keeps the wire-format pins lockstep across
etch+fetch+LIT — without that, the four assets can drift apart and
the trinity story breaks. The pin check is the only piece of
ASSETS.md that has a CI gate today.
