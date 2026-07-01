# CGNAT residential soak rig

Topology: laptop on a residential CGNAT ISP (T-Mobile home internet, Starlink Roam, Visible home, some MVNO fiber). Hard CGNAT both ends is the v1.0 stress case.

## Required hardware

- Laptop on a CGNAT residential ISP.
- Second laptop on a cone-NAT or wyse-rig endpoint for the joiner side.
- Both run fetchit-chat-peer at chat-HEAD with bundled x0xd.

## Protocol

Identical to the wyse-rig and mobile-rig protocols. Pass criteria: at-or-above 99% round-trip success rate over each 24h window; three rounds in seven days.

## Sourcing

Prefer a known-CGNAT ISP (verify with `dig +short myip.opendns.com @resolver1.opendns.com` from inside the LAN vs the WAN IP on the ISP-supplied modem; mismatch = CGNAT).

## Log retention

`/var/log/fetchit-cgnat-rig/round-<N>-<date>.jsonl`. Upload to `private/ops/cgnat-rig/runs/` for archival.
