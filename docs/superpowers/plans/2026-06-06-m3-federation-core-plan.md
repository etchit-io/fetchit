# M3 — Federation Core Implementation Plan

**Goal:** Move fetch>it chat from one relay to a *federation* — a peer talks to **multiple independent relays simultaneously** (multi-home), enforces a community-curated **denylist** of abusive agent IDs, and the project documents how a third party stands up their own relay and gets onboarded into the default bootstrap list.

**Architecture:** New `fetchit-relay-client::RelaySet` wraps `Vec<Arc<Client>>` (one per relay). Outbound `send` fans out to all healthy relays so durability tolerates an N-1 relay outage; inbound `next_delivery` merges all relay inboxes and dedupes by `dedupe_key`. `fetchit-chat::relay_transport` swaps its single `RelayClient` for a `RelaySet`. Denylist is a typed `BlockedAgents` set surfaced to the chat layer; the consumer fetches it from a small signed manifest (HTTPS + chainmark, no live relay dependency) and gates outbound `to: AgentId` plus drops inbound from blocked senders before they reach the conversation layer. Community-relay onboarding is a markdown checklist in `docs/COMMUNITY-RELAY.md` plus a TOML manifest checked into `crates/fetchit-relay-client::region_probe::DEFAULT_RELAYS`.

**Tech stack:** Same workspace pins. Rust 2021, MSRV 1.85, `tokio`, `futures-util`. No new dependencies expected. Test harness uses existing `wiremock`-driven relay-side stubs (or a thin in-memory relay) for fan-out + merge coverage.

**Spec:** This document. No separate `docs/superpowers/specs/...` until the API shape is reviewed.

---

## Scope split

| Sub-deliverable | Owns | Status |
|---|---|---|
| Multi-home (3 concurrent WS) | Bob (Box B) | scoped here |
| Denylist consumer | Bob (Box B) | scoped here |
| One community relay onboarded | Joint (Bob drafts docs, Josh approves operator) | scoped here |

Alice's #251 (NAT-traversal design) runs in parallel; the two only interlock at the relay-ferried Welcome fallback (which #251 may consume from RelaySet's send-all property). No code dependency in either direction.

---

## Stage 1 — `RelaySet` scaffolding

A thin wrapper around `Vec<Arc<Client>>` exposing the same surface as `Client`, multiplexed.

**Public API sketch:**

```rust
/// A set of independent relay sessions a peer maintains concurrently.
pub struct RelaySet {
    relays: Vec<Arc<Client>>,
    inbox_rx: Mutex<mpsc::UnboundedReceiver<Deliver>>,
    presence_rx: Mutex<mpsc::UnboundedReceiver<PresenceUpdate>>,
    states: watch::Receiver<Vec<ConnState>>,
}

impl RelaySet {
    /// Connect to every config in `configs` concurrently. Fails only if
    /// ALL relays fail their initial handshake — surviving any subset
    /// keeps the peer reachable.
    pub async fn connect(
        configs: Vec<ClientConfig>,
        signer: Arc<dyn Signer + Send + Sync>,
    ) -> Result<Self, ClientError>;

    /// Fan-out send to every healthy relay. Returns the first `Ok(Receipt)`
    /// and accumulates the rest in `extras`. If every relay errors,
    /// returns the *last* error and the partial successes (none) — caller
    /// surfaces "no relay accepted the envelope" semantics.
    pub async fn send(
        &self,
        to: AgentId,
        envelope: Box<TransitEnvelope>,
        dedupe_key: DedupeKey,
    ) -> Result<SendOutcome, ClientError>;

    /// Pull the next Deliver from the merged inbox. Per-`dedupe_key`
    /// dedupe is applied before returning, so a fan-out delivery on
    /// three relays surfaces ONE message to the caller.
    pub async fn next_delivery(&self) -> Option<Deliver>;

    /// One `ConnState` per relay in the same order as `configs` passed
    /// to `connect`. UI surfaces "2 of 3 relays connected" from this.
    pub fn connection_states(&self) -> Vec<ConnState>;

    /// Watch-presence fan-out to every relay so any one of them can
    /// deliver the presence update.
    pub fn watch_presence(&self, agents: &[AgentId]) -> Result<(), ClientError>;

    pub async fn next_presence(&self) -> Option<PresenceUpdate>;
    pub async fn shutdown(&self);
}

pub struct SendOutcome {
    pub primary: Receipt,
    pub extras: Vec<Result<Receipt, ClientError>>,
}
```

**Open design questions for Alice review:**

1. **Send-all vs send-one with failover.** Send-all is simple + durable but triples relay bandwidth per message. Send-one falls back to next relay on failure — cheaper but adds tail latency. Recommendation: send-all for M3 core, revisit cost in M4 if real load matters.
2. **Inbound dedupe scope.** Per-`dedupe_key` covers the case where two relays both have a copy of the same transit envelope (common when sender fans out). Should we also dedupe by `(sender_agent_id, message_id, timestamp_ms)` to absorb relay-side replay attacks? Recommendation: leave to chat layer for M3 core, add transport-side dedupe in M3.1 if needed.
3. **Per-relay reconnect bookkeeping.** Each relay's `Client` already has its own reconnect supervisor. RelaySet does not re-implement that — it just observes per-relay `connection_state`. Confirm: no global "reconnect set" needed.

---

## Stage 2 — Denylist consumer

A read-only consumer of a community-curated `denylist.toml` manifest distributed via HTTPS (initially `etchit.io/denylist.toml`).

**Manifest shape:**

```toml
# denylist.toml — v1
version = 1
generated_at = "2026-06-06T08:00:00Z"
# 64-hex ML-DSA-65 chainmark signature over the body, separately verified.
signature = "…"

[[blocked]]
agent_id = "64-hex"
reason = "spam"     # one of: spam, scam, csam, terror, harassment, off-topic
added_at = "2026-06-04T14:00:00Z"

[[blocked]]
agent_id = "64-hex"
reason = "csam"
added_at = "2026-06-05T19:00:00Z"
```

**Consumer surface:**

```rust
pub struct DenylistConsumer { /* ... */ }

impl DenylistConsumer {
    /// Fetch + verify chainmark + parse + replace the in-memory set.
    /// Idempotent; can be called on a refresh schedule.
    pub async fn refresh(&self, url: &str) -> Result<(), DenylistError>;
    pub fn is_blocked(&self, agent: &AgentId) -> bool;
    pub fn snapshot(&self) -> DenylistSnapshot; // for ops introspection
}
```

The chat layer gates BOTH directions on `is_blocked`:
- Outbound: refuse to send to a blocked recipient (UX surfaces "this contact is on the community denylist")
- Inbound: drop incoming envelopes from a blocked sender before decryption (no plaintext leak path)

**Open design questions for Alice review:**

1. **Manifest distribution.** HTTPS pull from `etchit.io/denylist.toml` is centralised. Should the manifest itself ride a fetch>it `autonomi://` address so it's censorship-resistant? Recommendation: HTTPS for M3 core (faster ship), `autonomi://` mirror in M3.1.
2. **Refresh cadence.** Hourly? Daily? Caller-driven? Recommendation: hourly background refresh, cached snapshot survives transient HTTPS failure.
3. **Denylist scoping.** Same denylist for all communities, or per-community? Recommendation: M3 core ships ONE global denylist; per-community comes with M3.1 once the operator pattern is concrete.

---

## Stage 3 — Community relay onboarding

A markdown checklist + a manifest update.

**Deliverables:**

1. `docs/COMMUNITY-RELAY.md` — what an operator does:
   - Read [`fetchit-relay`](https://github.com/josh-clsn/fetchit-relay) (the M1.6 extraction).
   - Build the release binary, deploy to their hardware, point clients at it.
   - DNS / TLS / reverse-proxy notes.
   - Acceptance criteria: 7 days of clean uptime + Prometheus access for the maintainer team.
2. `crates/fetchit-relay-client/src/region_probe.rs::DEFAULT_RELAYS` — table of bootstrap relay URLs by region tag, updated to include the first community relay.
3. One community operator actually onboarded — Josh's pick.

This sub-deliverable is documentation + a single config change. No new code beyond the existing constant.

---

## Build sequence

1. **Stage 1 Task 1.1** — `RelaySet::connect` + `connection_states` + tests
2. **Stage 1 Task 1.2** — `RelaySet::send` (fan-out, SendOutcome) + tests
3. **Stage 1 Task 1.3** — `RelaySet::next_delivery` (merged inbox + dedupe) + tests
4. **Stage 1 Task 1.4** — `RelaySet::watch_presence` + `next_presence` + tests
5. **Stage 1 Task 1.5** — `RelaySet::shutdown` + tests
6. **Stage 1 Task 1.6** — Swap `fetchit-chat::relay_transport` from `Client` to `RelaySet`, gate behind feature flag `multi-home` for the chat-peer
7. **Stage 2 Task 2.1** — Denylist manifest type + chainmark verify + parser + tests
8. **Stage 2 Task 2.2** — `DenylistConsumer::refresh` (HTTPS pull, hourly cadence) + tests
9. **Stage 2 Task 2.3** — Outbound + inbound gate in chat layer + tests
10. **Stage 3 Task 3.1** — `docs/COMMUNITY-RELAY.md` draft
11. **Stage 3 Task 3.2** — `DEFAULT_RELAYS` table refactor for community entries
12. **Stage 3 Task 3.3** — Actual operator onboarded (Josh)

Sequential Stage 1 → Stage 2 → Stage 3 keeps each commit small and reviewable. Stage 1 lands first because Stage 2 and Stage 3 don't change without it.

---

## Risks + mitigations

- **Bandwidth blow-up from fan-out.** Send-all triples relay egress. Mitigation: M3 core measures the cost in the soak (already running); revisit in M3.1 if it bites.
- **Denylist abuse.** A compromised manifest signer could censor arbitrary agents. Mitigation: chainmark signature with the maintainer team's ML-DSA-65 key; threshold signing (e.g., 2-of-3) considered for M3.1.
- **Community-relay quality.** A misconfigured community relay degrades the experience for users that land on it. Mitigation: 7-day soak gate before adding to `DEFAULT_RELAYS`; per-relay health metrics drive auto-failover at the `RelaySet` layer.

---

## Sync points

- After Stage 1 Task 1.1 (RelaySet::connect): cross-review with Alice before continuing.
- After Stage 2 Task 2.1 (denylist parser + chainmark): cross-review the threat model with Alice's #251 results.
- After Stage 3 Task 3.1 (COMMUNITY-RELAY.md): joint copy-pass with Alice for tone.
- Continuous: M2 soak (#133) heartbeat lands on Box B in parallel; any soak anomaly takes priority over M3 progress.
