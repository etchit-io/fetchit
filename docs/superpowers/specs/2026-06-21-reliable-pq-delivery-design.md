# Reliable PQ DMs + Group Chat: independent research + recommended design

**Date:** 2026-06-21
**Author:** Alice (Box A) — independent study per Josh's mandate ("study x0x, find the best
solution to reliable, stable PQ DMs and group chat; present a plan; not a competition,
converge with Bob afterward").
**Status:** INDEPENDENT FINDINGS + RECOMMENDED DESIGN. Bob convergence **CONFIRMED** (async,
2026-06-21 — see Joint synthesis below). Pending Josh sign-off on the one values decision.
**NOT approved for implementation.** Implementation is gated on Josh sign-off and a
writing-plans pass.

---

## TL;DR

Make the **blind relay a durable, ack-driven PQ store-and-forward delivery service** for
*all* end-to-end traffic — DM content, group message fan-out, **and** group control-plane
(join / commit / membership) events. Demote **gossip to an opportunistic accelerator, never
the reliability floor.** Layer **StaleEpoch detection + automatic re-Welcome self-heal** on
top (reusing the engine-A inline-Welcome path we already have). Sequence an
**Autonomi-backed canonical store as the v1.x values-pure durability return.**

This converges with Bob's independent headline ("relay = blind PQ MLS delivery service for
both DM and groups; gossip demoted to accelerator"). I reached it separately from the code.
What I add beyond that headline: the **Autonomi sequencing**, the **epoch self-heal**, the
explicit **values decision Josh must make**, and the **test reality** (cross-NAT + epoch
recovery are currently hope, not proof).

---

## How I got here

Five read-only code audits, each verified against code with `file:symbol` anchors (not docs —
this tree has a known stale-doc problem), plus direct reads of `transit.rs` and
`transport/mod.rs`:

1. DM delivery + durability (our side)
2. Relay buffering reality (`fetchit-relay-server`)
3. Group + MLS + epoch handling (our side)
4. Upstream x0xd capabilities @ `1f9f900` = our josh-clsn `dev/main` (0.25.0 base + engine-A,
   **not yet upstreamed**). NOTE (2026-06-21): David has since released **v0.26.0** on
   saorsa-labs/main — see "Upstream version target" below.
5. The upstream test suite as empirical authority

---

## Ground truth (what is actually built)

### Transport reality — messages already ride the relay

- **DM content is relay-only in practice.** `Router::send` (`transport/mod.rs:208`) tries
  transports in registration order; in the production build that is LAN-direct (off by
  default, `settings.rs:182`) then `MultiHomeTransport` (relay). There is **no x0xd
  peer-relay / gossip transport in the DM Router** (`transport/mod.rs:10-14`).
- **Group message content ALSO rides the relay.** `messages.rs:send_private_group` (~1043)
  encrypts via x0xd `/secure/encrypt` (real TreeKEM), then **fans out one sealed copy per
  member over `self.router.send`** with `OutboundKind::Group` (~1131-1165). Receive path:
  `receive_private_group_envelope` → `/secure/decrypt`. **MLS crypto = x0xd; transport =
  our relay.**
- **Gossip carries only group membership/commit metadata**, with the **engine-A relay
  bridge** as the cross-NAT contingency for those events (`groups/dispatch.rs`,
  `groups/bridge.rs`).

Implication: the relay is the de-facto content path for everything. Gossip is not the
content path and never was.

### What is solid — do not rebuild

- **Durable DM outbox: built and wired in production** — `OutboxStore` (sealed at rest,
  `outbox/store.rs`), `OutboxDriver` (presence-edge flush + boot sweep + 24h timeout,
  `outbox/driver.rs`), `Client::enqueue_dm` (`client.rs:1667`), `start_outbox_driver`
  (`client.rs:2428`), delivery receipts flip bubbles to Delivered (`conversation/inbound.rs:318`).
  Desktop + FFI both wired.
- **The relay is BLIND** — it only ever holds opaque ciphertext + routing metadata
  (`TransitEnvelope`, `envelope.rs:246-285`); it never decrypts.
- **x0xd 0.25.0 owns** (verified @ `1f9f900`): DM e2e + ACK + dedupe + liveness repair;
  real RFC-9420 TreeKEM (FS/PCS); group authority + signed monotonic state-commit chain +
  auditable history (`/groups/:id/state/commits`, `0ed8a87`); cross-NAT join apply endpoints
  (engine-A, `faa9f81`); embeddable in-process `serve()` for mobile (`2804cfc`).

### The holes (verified)

1. **Relay = RAM-only, 15-minute TTL, acks-then-silently-drops.** `TransitBuffer` is an
   in-process `DashMap` (`transit.rs:37-43`); TTL is exactly 15 min (`config.rs:60`), swept
   every 30s; the send handler **enqueues then Acks** even though nobody received it
   (`ws.rs:380-394`); on reconnect it drains FIFO (`ws.rs:124-136`). **Process restart =
   total loss.** **Cross-relay recipient = dead drop** (TTL-expires; no relay→relay
   forwarding, only migration redirect). This single buffer is the reliability ceiling for
   **both** DMs and group messages.
2. **StaleEpoch is unrecoverable on the group path.** x0xd `/secure/decrypt` returns
   `403 "stale epoch"`; the client collapses it to an **untyped** `X0xdError::Rejected`
   (`x0xd-client/secure.rs:457`), propagates it via `?` in `receive_private_group_envelope`
   (`messages.rs:1608`), and the desktop shows a generic warn toast
   (`private_group_decrypt_failed`, `chat.rs:2124`). **No detection, no catch-up, no
   auto-heal — manual re-pair only.**
3. **x0xd provides no epoch recovery to build on.** `/state/commits` retains the
   *control-plane authority chain only* (roster/role/signature) — **no TreeKEM key
   material**; `security_binding` is a label like `"epoch:3"`, not a way to enter the epoch.
   TreeKEM advances one commit at a time (`treekem.rs:311 process_commit`); there is no
   range/replay/catch-up API. Upstream recovery is **reject-and-re-share → fresh Welcome**
   (`server/mod.rs:14218`). So epoch self-heal is *ours* to layer, and it must be re-Welcome,
   not replay.
4. **Cross-NAT group reliability + epoch recovery are HOPE, not proof.** Every multi-daemon
   Rust test runs single-host loopback (`tests/harness/src/cluster.rs`; nextest serializes
   them because ant-quic dual-stack flakes on loopback). The genuine cross-NAT artifacts
   (`nat_traversal_integration.rs`, the VPS Python scripts) are `#[ignore]`/manual, never
   gate a merge, and **never send group traffic**. There is **no test** for: a NAT-isolated
   *existing* member receiving a commit, the engine-A relay-apply path end-to-end, or any
   epoch recovery from a missed/out-of-order commit or a StaleEpoch desync.
5. **The engine-A bridge has no durable retry.** Reply runs on a spawned task with a ~8s
   poll ladder; bridge envelopes are explicitly *not* queued (`bridge.rs` doc ~530). A
   dropped join-result or commit just never converges.

---

## The thesis

> Make the blind relay a **durable, ack-driven PQ store-and-forward delivery service** for
> all E2EE traffic (DM content + group fan-out + group control-plane events). Gossip becomes
> an **opportunistic accelerator**, never the reliability floor. Layer **StaleEpoch
> detection + automatic re-Welcome** on top. Sequence an **Autonomi-backed canonical store**
> as the v1.x values-pure return.

Why the evidence forces it:

- Messages already ride the relay; the only missing property is durability. Fixing the
  relay fixes DM *and* group reliability in one place.
- Group control-plane events (commits/joins) ride the relay too when gossip can't reach
  (engine-A). If those are durably delivered, **the StaleEpoch root cause — a member missing
  an epoch-advancing commit while offline — largely disappears**, and cross-NAT groups stop
  depending on gossip convergence at all. (Bob's complementary half: `MemberAdded` still
  rides gossip *as primary*, which is exactly why cross-NAT JOIN hangs ~60s — so the engine-A
  bridge must become the **primary** membership path over the relay, not a contingency.)
- x0xd will not give us epoch replay; the only recovery primitive is a fresh Welcome, which
  the engine-A path already produces. So self-heal = detect + reuse engine-A, not new
  protocol.
- **External backing (Bob's independent read):** ant-quic rates direct P2P over
  cellular/CGNAT at only 50-70%, and saorsa-gossip pubsub is best-effort-lossy *by design* —
  a relay floor is the *correct* architecture, not a compromise. x0xd's group state machine
  is already transport-agnostic (`apply-metadata-event` + `join-result` converge a group
  with zero gossip), so carrying membership over the relay needs no upstream change.

---

## Approaches considered (the durability fork)

**A — Durable blind relay store-and-forward.** Persist sealed envelopes to disk keyed by
recipient; deliver on reconnect; delete on explicit client ACK; bound retention to days, not
15 minutes; survive restart. Carry group control-plane events the same way. *This is the
Signal-server model: store opaque ciphertext until delivered, then delete.*
→ **Recommend as the v1 reliability floor.** Smallest change that closes the silent-loss
hole for both DM and groups, stays blind, stays fast (live push unchanged when online).

**B — Autonomi-backed durable log.** Sender writes the sealed envelope to Autonomi (our
canonical PQ store); the relay carries only a tiny pointer/notification; recipient pulls
from Autonomi on reconnect.
→ **Recommend as the v1.x canonical return.** Maximally values-aligned (Autonomi is the
store, relay stays pointer-only/transient, nothing user-data hosted on our servers,
cross-relay-agnostic, survives anything). Heavier: write latency and cost make it wrong for
the live hot path, right for cold/long-retention/large attachments.

**C — Client-outbox-only (status quo, hardened).** Keep the relay transient; fix the outbox
bugs and extend resend to groups.
→ **Rejected as the whole answer.** Structurally cannot cover "both offline, never
overlapping," "sender app closed," or group fan-out: delivery requires the sender online to
observe the recipient's presence edge. The outbox is necessary but not sufficient — it is
the *sender-side* half; we still need a *server-side* durable floor.

**Recommendation: A now (floor) + B sequenced (north star).** Hybrid by design, not
indecision — A buys reliable v1, B is the committed values-pure return, and the outbox (C)
stays as the sender-side complement (with its bugs fixed).

---

## The one decision for Josh

Approach A **flips the currently-locked stance "relay = contingency, NOT durability"** to
"relay = durable blind delivery floor." I will not silently override a locked decision, so
this is the decision to make in the morning.

Reconciliation with our values (why I believe A is still values-consistent):

- The relay stays **blind** — opaque ciphertext only, never decrypts (`envelope.rs:246-285`).
- **Bounded retention + delete-on-ACK** — a delivery buffer, not a data host. This is exactly
  what Signal/Matrix do for E2EE; it is not "hosting user data" in the legal sense we want to
  avoid.
- **Autonomi remains the canonical store** (Approach B) — the relay buffer is the fast path,
  Autonomi is the durable home. That honors "Autonomi-first storage."
- It matches the decentralized-values memory's own framing: *pragmatic transport that
  preserves PQ identity + e2e + Autonomi + blind relay, with the fully-decentralized path a
  committed v1.x return.*

If Josh prefers to keep the relay strictly transient, the fallback is **B-first** (Autonomi
durable log as the v1 floor), accepting higher staging latency — still better than the
status quo, but slower to feel snappy. My recommendation is A-now / B-next.

**Alice and Bob independently recommend making the flip (A-now / B-next).** It preserves all
three non-negotiables: the relay stays blind, gossip stays the decentralized accelerator and
committed return, and Autonomi stays the canonical store. Unanimous engineering
recommendation — still Josh's call.

---

## Recommended plan (sequenced, pending convergence + approval)

- **R1 — Typed StaleEpoch + auto re-Welcome self-heal.** Discriminate the 403 body into
  `X0xdError::StaleEpoch` / `NotAMember`; on StaleEpoch, trigger an owner-mediated re-add
  using the existing engine-A inline-Welcome path so the member silently re-enters the
  current epoch. *Cheapest, highest-felt-reliability win; no new protocol; reuses shipped
  machinery.*
- **R2 — Durable blind relay store-and-forward (Approach A).** Disk-backed, ack-driven,
  delete-on-delivery, bounded retention; replaces the 15-min RAM dead-drop. Survives restart.
- **R3 — Carry group control-plane events over the durable relay**, and route engine-A
  bridge envelopes through it — killing the StaleEpoch *root cause* and giving the bridge
  durable retry.
- **R4 — Fix the outbox bugs surfaced by the audit:** resend mints a new logical
  `message_id` so its receipt never matches (`messages.rs:786` vs `store.rs:224`); resend
  drops attachment + `reply_to` (`client.rs:2984`); auto-resend trigger depends on an x0xd
  presence edge that may never fire for relay-only peers.
- **R5 — Real cross-NAT + epoch-recovery test harness.** Two genuinely-NATed hosts (or the
  VPS fleet) exercising group commit propagation to a NAT-isolated member, engine-A
  relay-apply end-to-end, and StaleEpoch → self-heal. Loopback cannot prove these.
- **R6 — Autonomi-backed canonical store (Approach B), v1.x.** Cold path / long retention /
  large attachments; the values-pure durability return.

Sequencing rationale: R1 is a fast felt-reliability win; R2+R3 are the structural floor;
R4 hardens the sender side; R5 turns "hope" into "proof" (required for the launch gate); R6
is the committed decentralized return.

---

## Test strategy (reliability == proof, not hope)

The audit's sharpest finding: our reliability claims are untested by construction. "Reliable
and stable" is not a code change, it is a **proof**. R5 is therefore not optional polish —
it is part of the definition of done. Minimum: a two-host NAT harness that (a) delivers a
group commit to a NAT-isolated existing member, (b) drives a StaleEpoch and asserts
self-heal, (c) exercises engine-A relay-apply end-to-end, (d) survives a relay restart
mid-flight without message loss.

---

## Joint synthesis with Bob (convergence CONFIRMED async, 2026-06-21)

Bob ran an independent 6-agent source study and reached the identical headline. The two
halves compose into one v1 design:

- **Alice's half (durability):** the relay is a 15-min RAM dead-drop that
  acks-then-silently-drops — the core reliability lie. Fix: persistent, long-TTL,
  per-recipient blind store-and-forward.
- **Bob's half (membership-over-relay):** `MemberAdded` still rides gossip, which is *exactly
  why cross-NAT JOIN hangs ~60s*. Fix: the engine-A "Plan A" bridge becomes the **primary**
  membership path over the relay, not a contingency.
  - *Verified 2026-06-21:* there is **no `member_added` bridge fan-out today**.
    `groups/dispatch.rs` ships relay fan-out only for `member_removed` / `role_updated` /
    `policy_updated` / `banned` / `group_deleted`; the join path (`groups/join_bridge.rs`) is
    strictly joiner↔owner. So an existing non-owner member is never told about a *later*
    joiner over the relay, and never receives the TreeKEM commit that added them → it goes
    stale-epoch and can no longer decrypt. Only the owner sees the full roster gossip-free.
    This is the concrete gap R3 closes: add `member_added` + its commit to the relay fan-out.

**Locked nuance:** durability alone does NOT fix join-convergence, and the membership bridge
alone does NOT fix offline durability. A regular reliable chat app needs **both**.

**Combined v1 solution (agreed), mapped to the plan above:**

1. Relay durability — persistent long-TTL per-recipient blind store **[Alice lane]** = R2.
2. Plan A membership bridge so join converges over the relay **[Bob lane: engine + FFI/device]**
   = R3.
3. Gossip demoted to an `IfReachable` accelerator, never waited on.
4. MLS-DS hygiene — Commit dedup + epoch-skip **[Bob]** *plus* StaleEpoch auto re-Welcome
   self-heal reusing engine-A **[Alice]** = R1 (agreed: x0xd has no epoch replay; recovery
   must be a fresh Welcome).
5. Autonomi-backed canonical store = the v1.x values-pure durable return = R6.
6. Two-host NAT harness turns cross-NAT + epoch-recovery from hope into proof = R5.

Bob's writeup: `fetchit-ops/docs/2026-06-21-reliable-pq-chat-relay-floor-plan.md` (joint
synthesis on his side). This doc is the Box-A independent half plus the joint mapping. Both
are for Josh's morning review; the relay-durability **values decision** (above) remains his
to make.

---

## Upstream version target (updated 2026-06-21: v0.26.0 released)

David shipped **x0x v0.26.0** (saorsa-labs `origin/main` `a6fce96`, tagged 2026-06-21). It and
our engine-A work **diverged at `2804cfc`** (embeddable `serve()`):

- **Our `dev/main` (`1f9f900`)** = fork + `faa9f81` (engine-A relay group-join apply) +
  `1f9f900` (X0X-0070b peer-relay DM). ant-quic 0.27.26.
- **David's `v0.26.0` (`a6fce96`)** = fork + deterministic background-task teardown (#116) +
  force-cancel exec sessions (#118). ant-quic **0.27.27**.

So engine-A is **not** in 0.26.0, and 0.26.0's teardown + ant-quic bump are not on our branch.

What 0.26.0 gives us (relevant): the embeddable `serve()` officially shipped (our #110); a
race-free `shutdown_and_wait()` that stops every background task incl. the gossip runtime and
the QUIC `NetworkNode` (fixes a real `NetworkNode::shutdown()` deadlock) — clean Doze/idle
embed restart; and **ant-quic 0.27.27**, which releases the UDP socket on shutdown
(ant-quic#196) so an in-process embedder can **restart on the same fixed QUIC port** (removes
the ephemeral-port workaround adopt-115 needed).

**Honesty point:** ant-quic 0.27.27 is a *shutdown/restart* fix, **not** a NAT/CGNAT-success
improvement — direct P2P over CGNAT is still ~50-70%, so this does **not** change the
relay-floor conclusion.

**Action (pending go):** rebase our two commits (`faa9f81` + `1f9f900`) onto **v0.26.0** so v1
ships engine-A cross-NAT join *and* David's embed-teardown + socket-release. The reliability
plan's build target becomes **v0.26.0 + engine-A**, and adopt-115 (#63) retargets 0.26.0.

## Open questions

1. Retention bound for the durable relay buffer (days? until-ACK + N-day cap?).
2. Cross-relay/region: does v1 require relay federation, or is "reconnect to your home relay"
   acceptable for v1 (recipient's home relay holds the durable copy)?
3. Is the StaleEpoch self-heal owner-mediated only (needs an admin online), or can any admin
   re-Welcome (ADR-0016 flat-admin makes this viable)?
4. Autonomi write cost/latency budget for Approach B — micropayment model for staging cold
   messages.
5. Mobile gossip profile / `--no-mdns` (David ask) — needed for dev-box proof and to keep
   gossip a cheap accelerator on phones; not a v1 blocker if gossip is demoted.
