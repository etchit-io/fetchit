# LIT Chat -- pre-release test plan (DM outbox + delivery reliability)

Manual test plan for extensive pre-release testing of LIT Chat, focused on
the engine-owned DM outbox (T8/T9) and delivery reliability -- the highest-risk
new surface -- plus a broader chat regression pass and the #114 TLS cutover.

Automated coverage already gates merges (frontend vitest, src-tauri + workspace
cargo test, Android unit tests). This plan covers what those cannot: real
two-party delivery, network/restart/reconnect conditions, and cross-shell
parity. Run it against `chat` at f9b9e98 or later.

Convention per test: **Steps** then **Expect**. Shells: `[D]` desktop,
`[A]` Android, `[D+A]` cross-shell. A test is a release blocker unless marked
`(observe)`.

## 0. Environment

- **Two peers**, A and B (any pairing of desktop and Android). For delivery
  tests they must be distinct identities.
- Build off `chat` in a worktree, NOT the chat-peer daemon's checkout (cargo
  there would replace the binary the daemon execs).
  - `[D]` `cd apps/fetchit-desktop && npm install && npm run tauri dev`
  - `[A]` `./scripts/build-jni-libs.sh && (cd apps/fetchit-android && ./gradlew :app:assembleDebug)`
- Chat is OFF by default in release builds; enable per run with
  `FETCHIT_CHAT_ENABLED=1` (or Settings -> Advanced).
- A relay must be reachable. Until #114 lands, that is the bare-IP
  `http://...:8088`; the https flip + migration are staged on
  `relay-client-tls-flip` and tested in section F once the CF edge is live.
- **Pair A and B** first (share card or pair URI) so a DM conversation exists.

## A. Happy-path DM + delivery `[D]` `[A]` `[D+A]`

- **A1 send while peer online.** Steps: A sends "hi" to online B. Expect: A's
  bubble shows Sending (clock), then Delivered (double-check) once B's
  `DeliveryReceipt` lands; B sees the inbound message.
- **A2 reply quote.** Steps: A long-press/replies to a message, sends. Expect:
  A's outbound bubble renders the quote strip (the reply metadata is staged
  shell-side and attached when the engine echoes the bubble). Quote survives a
  reload.
- **A3 image attachment.** Steps: A attaches an image, sends. Expect: A's
  outbound bubble renders the inline image immediately; B receives + renders
  it; survives reload.
- **A4 inbound receipt.** Steps: B receives A's DM. Expect: B auto-sends a
  receipt; A flips to Delivered.
- **A5 rapid sends.** Steps: A sends 5 messages fast (some with reply/image).
  Expect: all 5 appear in order, each reaches Delivered, no reply/attachment
  lands on the wrong bubble.

## B. Outbox resend / offline `[D]` `[A]`

- **B1 offline then online.** Steps: B offline; A sends. Bring B online.
  Expect: A's bubble sits Sending while B is offline; on B's presence edge the
  driver auto-resends and it reaches Delivered. No duplicate at B.
- **B2 failure then Retry.** Steps: force a send failure (stop the relay or B
  unreachable); A sends. Restore; tap the outbox banner Retry. Expect: bubble
  goes Failed (warn) with a reason, then Retry re-sends to Delivered.
- **B3 outbox banner.** Expect: the banner reads "N waiting to deliver" +
  "N undelivered"; Retry appears only when a failed bubble's peer is online.

## C. Persistence / restart `[D]` `[A]`

- **C1 in-flight survives restart.** Steps: A sends to offline B; kill and
  relaunch A before delivery. Expect: the bubble is still present (Sending);
  the engine outbox reloads from its vault and the driver re-sends when B
  returns. No double-send (relay dedupes by message_id).
- **C2 delivered stays delivered.** Steps: A sends, reaches Delivered; restart
  A. Expect: the bubble shows Delivered, NOT Sending, and is NOT re-sent on the
  next presence edge (the receipt marked the durable outbox Delivered via
  `dispatch_inbound_with_outbox`).
- **C3 pre-upgrade bubbles (observe).** Only when upgrading from a pre-T8
  build: outbound bubbles persisted with old `local-` ids have no engine
  outbox entry and may show a stuck Sending. Known deferred minor; note if
  seen, not a blocker.

## D. Reconnect / transport `[D]` `[A]`

- **D1 daemon/relay drop mid-session.** Steps: with chat open, drop the local
  daemon or the relay link briefly, then restore. On `[A]` navigate away from
  chat and back. Expect: inbound delivery resumes without an app kill (desktop
  pump reconnects; Android `ensureGateway` rebuilds a dead pump rather than
  returning the stale one).
- **D2 relay region switch.** Steps: Settings -> Network -> pick another
  region while chat is live. Expect: sends keep working; the outbox driver
  follows the in-place relay migration (no restart needed).
- **D3 broadcast lag (observe).** Hard to force; if the UI ever shows an
  outbound bubble stuck at a wrong status, reopening the panel re-snapshots and
  converges. Note if reproducible.

## E. Cross-shell parity `[D+A]`

- **E1 both directions.** desktop -> Android and Android -> desktop DM: both
  deliver + reach Delivered with receipts.
- **E2 Android send paths.** Android thread composer AND share-to-chat both
  enqueue through the engine outbox and show Sending/Delivered/Failed (no
  double-bubble; status collapses on one bubble keyed by outbox id).
- **E3 attachment/reply across shells.** image + reply quote render correctly
  in both directions.

## F. #114 TLS cutover -- run AFTER the CF edge is live `[D]` `[A]`

Prereq: droplet Caddy + Cloudflare DNS up (`nyc/fra.relay.etchit.io` resolve);
then unhold the staged client flips.

- **F1 fresh install.** Clean profile defaults to `https://nyc.relay.etchit.io`
  and connects (client upgrades https -> wss).
- **F2 existing install migrates.** A profile persisted on the bare-IP
  `relay_url` is migrated to the matching https host on load and connects
  (so it does not drop when D4 closes plaintext :8088). `[A]` connects to the
  flipped `DEFAULT_RELAY` const (no persisted relay to migrate).
- **F3 WS survives CF idle.** Leave a chat idle > ~2 min. Expect: the link
  stays up (client keepalive pings every 30s, under CF's ~100s idle close).
- **F4 bearer auth.** WS auth uses the `Authorization: Bearer` header (token
  not in the URL); the relay accepts the scheme case-insensitively.

## G. Broader chat regression (release-critical) `[D]` `[A]`

- **G1 pairing.** share card (v2 + v3), pair URI, QR scan. Include an
  uppercase-hex pair URI (must succeed -- the I1 fix lowercases before the FFI).
- **G2 contact requests.** TOFU first-contact welcome: accept and reject paths.
- **G3 groups.** create, join via invite, send, leave; history poll.
- **G4 denylist.** a blocked sender's inbound is dropped; the composer refuses
  to send to a denylisted contact.
- **G5 fediverse.** handle mint + public post + feed (if in v1 scope).
- **G6 presence.** online dot accuracy; greys out on staleness; relay
  PresenceUpdate wins.

## H. Known minors to watch (deferred -- observe, not blockers)

- Sender display name falls back to `fetchit` when the display name is unset;
  an initial send and a later retry can then show different names.
- Android reconnect (D1) has no unit test yet (needs an injectable connect
  seam); D1 is the manual coverage.
- Pre-upgrade `local-` outbound bubbles (C3).

## J. Cross-device soak (real-world conditions)

Long-running multi-peer soak across distinct networks, using wyse machines
(LAN, NAT'd) and VPSes (public IPs, ideally several regions). This is the only
way to surface what short tests cannot: slow leaks, outbox/RSS drift, delivery
rate under churn, MLS epoch wedges (StaleEpoch -> re-pair), relay failover, and
long-idle WS survival. Distinct networks exercise cross-NAT direct delivery,
relay-routed delivery, and multi-region relays together.

- **Topology.** wyse peers behind home/office NAT; VPS peers on public IPs in
  >=2 regions; >=1 relay per region. Mix so some pairs are same-LAN, some
  cross-NAT, some cross-region.
- **Driver.** a per-peer scripted loop: pick a random peer, random interval,
  random payload (text / reply / image), log `{send_id, from, to, t_sent}`.
- **Collector.** tally sent vs delivered (by receipt), time-to-delivery,
  duplicates received, bubbles stuck Sending, re-send count, outbox size on
  disk, and process RSS -- sampled over the whole run.
- **Induced churn (cycle through).** peer offline/online (drop the network),
  app restart, local daemon restart, relay restart + region failover, and a
  long idle window (> CF idle, ties to F3).
- **Duration.** hours to days. Watch for: monotonic outbox-size or RSS growth
  (leak), delivery rate trending below ~100% (modulo intentional drops),
  stuck-Sending bubbles accumulating, or a StaleEpoch that needs a manual
  re-pair (a known wedge to characterize, not silently accept).
- **Pass.** ~100% eventual delivery, no unbounded growth, no permanently stuck
  bubbles, and clean recovery after every churn event.

Dependency: a headless/scriptable chat peer for the VPSes (the chat-peer
harness, or a CLI driver) plus the collector above. Relays + VPS provisioning
+ the harness are Bob's ops lane; the desktop/peer behavior + scenarios are
mine. Provisioning details (how many wyse, how many VPSes + regions) feed the
concrete topology.

## Release gate

Blockers that must pass on both shells before release: A1-A5, B1-B3, C1-C2,
D1-D2, E1-E3, G1-G6. Section F runs after the CF edge is live. C3, D3, and
section H are observe-only.

Final release-confidence gate: a clean multi-day cross-device soak (section J)
with ~100% eventual delivery, no unbounded outbox/RSS growth, and clean
recovery from every churn event.
