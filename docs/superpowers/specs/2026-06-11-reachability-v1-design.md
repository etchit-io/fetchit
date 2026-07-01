# Reachability v1 — pair records, deposit routing, and region mobility

Status: approved direction 2026-06-11 (fallback-hint default ON, in the
v1.0 launch gate, v2 share URI demoted to Advanced). Spec review pending.

## 1. Problem

Three failures observed live on 2026-06-11, all grandma-fatal:

1. **Cross-relay silence.** `RelayTransport::send` discards the
   recipient's `RendezvousHintsV1` (`relay_transport.rs:146`) and
   deposits into the sender's own relay. Two users on different relays
   cannot exchange DMs; messages sit in the wrong relay's 15-minute
   transit buffer and vanish without an error.
2. **Region-change traps.** Switching relays in Settings hot-swaps the
   client for future ops but leaves the inbound event pump bound to the
   old client and leaks the old WS (deaf-client state, hit twice in one
   hour). Even after a restart, the user's published whereabouts
   (contact cards, index records) still point at the old relay.
3. **The 12 KB share card.** The v2 extended URI carries the full
   ML-KEM-768 + ML-DSA-65 material inline (~12 KB after DEFLATE+b64).
   It cannot ride a QR code, breaks argv limits, and made the manual
   re-pair dance this morning miserable. A pointer-based v3 share
   (`chat_pair_share`) already exists but requires a published profile
   (wallet path), so the UI's "Share my card" still emits v2.

## 2. Design overview

One new record type powers pairing, region mobility, and relay churn:

```
PairRecord {
  agent_id_hex:        String,      // lowercase 64-hex
  ml_dsa_pubkey_b64:   String,      // signing identity
  kem_pubkey_b64:      String,      // ML-KEM-768 device key
  advertised_relays:   Vec<String>, // deposit-here list, priority order
  issued_at_ms:        u64,         // monotonic watermark
  sig_b64:             String,      // ML-DSA-65 over canonical bytes
}
```

- Published **walletless** to the user's relay profile index (additive
  optional fields on the existing index record so old records still
  parse; the existing `verify_index_record` + `derive_agent_id`
  binding extends to the new fields).
- Auto-published at boot, on key change, and on region change.
- Verification everywhere: `derive(ml_dsa_pubkey) == agent_id`, valid
  signature over the canonical encoding, and `issued_at_ms` strictly
  greater than any previously accepted record for that agent (rollback
  defense, same watermark discipline as the v3 profile).

### 2.1 Tiny share (kills the 12 KB card)

- "Share my card" emits a short pointer URI:
  `x0x://pair/<agent_id_hex>?r=<relay-url>[&r=<relay-url>]` plus a QR
  render. Order ~150 chars.
- Import: fetch the PairRecord from the first reachable hinted relay
  (existing `fetch_index_record_by_id` shape), verify the binding,
  store the contact card locally. Identical trust result to importing
  the v2 blob — the bytes just travel via the relay instead of the URI.
- The v2 extended URI remains available under Settings → Advanced as
  the fully-offline pairing path; it leaves the main UI.
- Unblocks QR pairing (#102) for free.

### 2.2 Deposit routing (cross-relay DMs)

- `RelayTransport` grows a per-relay connection pool keyed by relay
  URL: connections are created on demand with the existing
  challenge/verify auth, kept alive while in use, and idle-closed.
- `send(to, …, hints)` resolves the recipient's `advertised_relays`
  (stored card, refreshed per §2.3) and deposits at the first relay
  that accepts. The sender's own session relay is just another pool
  entry.
- The user listens on their own primary relay exactly as today; no
  relay-to-relay traffic exists anywhere (deposit model, not
  federation).

### 2.3 Hint freshness (the grandma-moved problem)

Three healing layers, strongest first:

1. **In-band refresh.** Outbound message payloads gain an additive
   `advertised_relays` field. Any verified inbound message updates the
   stored card's relay list. Active conversations heal on the next
   message with zero user action.
2. **Forwarding record.** On region change the app writes a signed
   `{ moved_to_relays, issued_at_ms }` record to the OLD relay's index
   (walletless, ~30-day retention). A sender whose deposit gets no
   ack re-resolves: old relay's forwarding record → new relay →
   redeposit. The watermark prevents replaying a stale location.
3. **Autonomi manifest (wallet tier).** etch/it users' v3 profile
   manifests republish with current relays — the relay-independent
   permanent root, fetched and verified with the existing profile-tab
   machinery when both relay paths fail.

### 2.4 Region picker, one click

`set_relay_url` becomes a real migration:

1. Tear down the old client correctly (fixes #358): abort all pump
   tasks, close the old WS, rebuild the client, respawn pumps bound to
   the new client. No "restart required."
2. Publish the PairRecord at the new relay.
3. Write the forwarding record at the old relay (best effort).
4. Republish the Autonomi manifest when a wallet is present.
5. Toast: "Moved. Your contacts will find you automatically."

### 2.5 Community relay churn

- Default `advertised_relays` = `[chosen relay, fetch>it NY]` — the
  operator fallback is on by default and removable in Settings →
  Advanced. A community relay dying never strands its users.
- Sender side: deposit walks the list.
- Recipient side: if the home relay is unreachable at boot or for a
  sustained window, the client fails over to the next listed relay,
  re-registers, republishes its PairRecord there, and (best effort)
  forwarding-records anywhere reachable from its old list.
- Relays appearing requires nothing from us: users point the picker at
  the URL; their records advertise it; every client can deposit there.

## 3. Security notes

- All records are ML-DSA-signed and bound by key derivation; relays
  store and serve but cannot forge or roll back (monotonic watermark).
- Deposit connections use the existing per-connection challenge auth;
  a recipient's relay applies its own rate limits and denylist to
  arriving traffic — abuse control stays single-point, per operator.
- Metadata posture unchanged and honest: the sender's IP is visible to
  the recipient's relay (today it is visible to the sender's relay).
  Content remains E2EE in all cases.
- The private plane never federates; the fediverse bridge remains the
  only federated surface, in the public plane.

## 4. Scope and launch

- **In the v1.0 gate** (Josh, 2026-06-11). No partial launch.
- Out of scope: relay directory/discovery UX, server federation, x0x
  mesh as a DM transport lane (future tier), paid/SLA routing policy.
- Test posture: every component unit-tested; the headless harness
  (#357) gets cross-relay missions — NY-peer ↔ FRA-peer send/read with
  exit-code asserts — as the live regression for this spec.

## 5. Build seams (for the plan)

- `fetchit-relay-proto` / relay-server: additive index-record fields +
  forwarding-record storage/serving (joint with Bob's relay lane).
- `fetchit-chat`: PairRecord publish/fetch/verify, transport pool,
  hint resolution, in-band refresh, failover logic.
- Desktop: share UI swap (pointer+QR primary, v2 → Advanced), picker
  migration flow, #358 teardown.
- Headless chat-peer: pair-record subcommands ride the same lib calls.
