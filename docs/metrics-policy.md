# Metrics policy — what the relay does and doesn't emit

The fetch>it relay-server's Prometheus surface (and its tracing
output) is explicitly allow-listed. This document records the
contract; the enforcement lives in `crates/fetchit-relay-server/src/metrics.rs`
(typed setters only — no generic label-set increment API) and in
`crates/fetchit-relay-server/src/ws.rs` (cleanup-trail tracing
scrubbed at write time).

## What the metrics surface emits

Aggregate counters and gauges only. No per-agent dimensions. The
full list of allowed series lives in `metrics.rs::Metrics`; every
field has a typed accessor.

| What | Type | Labels |
|---|---|---|
| Connected agent count | gauge | `{region, version}` |
| Envelopes in transit | gauge | `{region, version}` |
| Envelopes sent / pushed / delivered / buffered / dropped-TTL | counter | `{region, version}` |
| Auth challenges issued / verified-ok / verified-failed | counter | `{region, version}` |
| Throttles per-recipient / per-sender / envelope-too-large | counter | `{region, version}` |
| Process uptime seconds | gauge | `{region, version}` |

Only `{region, version}` labels — never `{agent_id}`, `{group_id}`,
`{machine_id}`, `{tenant_id}`, IP, country, ASN, or user-agent.

`envelopes_pushed_total` and `envelopes_delivered_total` are distinct
on purpose: a push is the hand-off to a live session's outbound queue,
which a dying socket can still swallow, while a delivery is the
recipient's `TransitAck` reclaiming the durable entry. `pushed -
delivered` is the un-acked backlog; only `delivered` means the client
has the bytes.

## What the tracing/log surface emits

The cleanup-trail trace in `ws.rs` (clean vs writer-task-death
distinction) carries only:

- the opaque, monotonic `session_id` (per-connection, never
  reused — not derivable to an agent id)
- the `LoopExit` reason variant (enum: `ClientClosed`,
  `WriterDied`, `ReadFrameError`, etc. — no payload)

No `agent_id`, no peer IP, no envelope content. The same rule
applies to every other trace line in the relay server.

## What the metrics surface DOES NOT emit

To preserve the privacy floor, the relay server intentionally
**cannot** emit any of these even on opt-in:

- Per-agent activity counters (which agent connected, how often,
  when, from where).
- Per-group / per-tenant metrics (what groups exist, how many
  members each has).
- Per-envelope event lines (which agent sent what, when, to whom).
- IP / geographic / network-fingerprint dimensions.

The mechanical enforcement: there is no generic
`registry.metric(name, labels)` API in `metrics.rs`. Each new
counter has to be added as a typed field on the `Metrics` struct
with an explicit setter or incrementer. Adding a forbidden
dimension means writing a method that would surface in code review.

## Cardinality-bounded counts for the investor pane

The investor pane needs cardinality estimates (DAU, distinct
publishers, distinct active regions) that the strict allow-list
above can't expose directly. Those flow through the HLL aggregator
sketched in `fetchit-ops/docs/hll-blurb-spec.md` — a separate
egress endpoint on `127.0.0.1`-only bind, hashed-and-salted
sketches that union without re-identifying individuals, and a
minimum-N gate (default 50) below which the value is suppressed.

The HLL surface is structurally incapable of emitting per-agent
state because the sketches don't carry it — by the time data
reaches the egress endpoint, individual `agent_id`s are unreachable.

See `fetchit-ops/docs/hll-blurb-spec.md` for the full design.

## Why this policy exists

The relay sees `agent_id` by construction — agents authenticate
with it. The metric surface and tracing output are the only places
where that observability could leak to a non-relay-operator
(Prometheus scrape consumers, log aggregators, dashboard viewers).
Holding the line at "no per-agent dimensions in the emitted blob"
is what lets `crates/fetchit-relay-server/SECURITY.md` and the
public marketing copy claim "no per-user telemetry" without
weasel-words.

The threat model the policy defends against is in
`fetchit-ops/docs/hll-blurb-spec.md §2`.

## Changing this policy

This document is normative. Any change to the metric or trace
surface must:

1. Update this file first.
2. Update `crates/fetchit-relay-server/src/metrics.rs` (or `ws.rs`)
   with the new typed accessor.
3. Surface in code review with an explicit reviewer ok on the
   privacy-impact summary.

Adding a dimension that would re-introduce a per-agent or
per-session identifier requires Box A + Box B + Josh sign-off.

— Last reviewed: 2026-06-02 (pre-M1.6 extraction scrub —
  consolidated from inline comments in metrics.rs / ws.rs / ASSETS.md
  / SECURITY.md that previously pointed at a `private/metrics-policy.md`
  file that didn't exist on disk; this is now the canonical home).
