# Mobile-carrier soak rig

Topology: smartphone tethered to laptop running fetchit-chat-peer on cellular network. Cone NAT (US T-Mobile typical) or CGNAT (Mint Mobile / Visible).

## Required hardware

- Smartphone with USB or hotspot tethering.
- Cellular plan with 5-10 GB data headroom per 24h round.
- Laptop running fetchit-chat-peer at chat-HEAD with bundled x0xd.

## Protocol

Mirror the wyse-rig protocol:

1. T=0: peer-anchor brings up the chat-peer on the mobile laptop via the bundled x0xd. Pin its peer-relay candidates to NY + FRA.
2. T+0: peer-joiner (wyse37 or equivalent cone-NAT laptop) creates a private group via the M2 endpoints, invites the mobile anchor.
3. T+0..24h: anchor sends 1 message every 60s; joiner echoes via the existing M2 live-test echo handler.
4. Monitor surfaces (hourly):
   - x0xd `peer_relay_attempts_total` + `..._successes_total`
   - bridge `envelope_accepted_legacy_v2_total` (if v2-window) + dropped
   - chat-peer `chat:warn` events
5. Pass criteria: at-or-above 99% round-trip success rate over the 24h window.

Three rounds in 7 days closes the topology gate.

## Sourcing

- Phone: pending Josh sign-off on which carrier accounts.
- Carrier: prefer one CGNAT plan + one cone-NAT plan to cover both.

## Log retention

`/var/log/fetchit-mobile-rig/round-<N>-<date>.jsonl`. Upload to `private/ops/mobile-rig/runs/` for archival.
