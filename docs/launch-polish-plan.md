# Launch polish plan

A bounded sprint to take the chat surface from "extreme nerd-level
complications" to "idiot-proof v1 launch." This is mid-journey, not
end of road — feature work (Profile-tab consumer, real MLS groups,
file transfer, voice, multi-device, payment integration, etc.)
resumes the moment the polish gate closes.

The gate exists because every UX hole below was hit live during
two-PC testing. Shipping more features against a foundation that
lies about delivery status, auto-upgrades itself dead, and asks
users to copy-paste 12 KB strings turns each new feature into a
new failure surface.

---

## 1. Goal

> **The grandma bar.** A user with no technical background installs,
> gives themselves a name, scans a QR, and is chatting — with no
> terminal, no docs, no understanding of what x0xd is or what a
> relay does. If a feature requires the user to know how the
> plumbing works, the feature isn't done yet.

Every decision on the polish sprint is graded against this bar.
Anything that surfaces internal vocabulary ("daemon," "agent_id,"
"WebSocket," "vault," "relay") to a non-technical user fails. The
chat surface either Just Works or it surfaces a plain-English
"Try again" with no jargon.

Five flows must work without help text:

1. **Install** → single signed installer for the host OS.
2. **First launch** → onboarding wizard asks for a display name and
   nothing else.
3. **Add a contact** → scan a QR (paste-URI stays available, in
   Advanced).
4. **Send a DM** → bubble runs ⏳ → ✓ → ✓✓ honestly; any failure
   becomes ⚠ within seconds with a Retry button.
5. **Daemon hiccup** → the app self-heals; the user never sees
   "x0xd not running" or a green dot lying about delivery.

---

## 2. Non-goals (stays Advanced or deferred)

In Settings → Advanced, hidden from default UX:
- Custom relay URL
- Manual bootstrap peer list
- Raw paste-URI contact add
- LAN-direct toggle (already opt-in)

Deferred to v1.1+ (resumed once polish gate closes):
- Profile manifest v3 consumer (cache + render + relay
  `/v1/profile` integration — etch>it's publisher side ships
  ahead independently)
- MLS real groups
- File transfer beyond 1:1 small inline
- Voice / video
- Multi-device sync (per-device KEM keys + Welcome forwarding)

---

## 3. Polish sprint backlog

Sequenced by impact and dependency. Each item lists the task ID it
maps to (file additional ones as needed). Items 1–4 are the
ground-floor stability work; 5–8 are the surface polish riding on
top.

### 3.1 Daemon supervision · task #153

Today: x0xd auto-upgrades itself mid-session and exits "for service
manager restart." Without systemd, it just dies. Every Linux box
running x0xd headlessly hits this — including both test boxes
simultaneously today.

Ship one of:
- **(a)** fetch>it bundles x0xd as a subprocess it owns and restarts.
- **(b)** Installer ships a `systemd --user` unit for x0xd that
  picks up the upgrade-exit signal.

Acceptance: `pkill x0xd` from outside the app → x0xd is back up
within 5 s with no user click. Tested by killing the daemon mid-DM
and watching delivery resume.

### 3.2 Self-heal chat panel · task #152

Today: the panel discovers x0xd at launch. If the daemon comes up
*after* the panel is open (or restarts), the panel stays in the
"x0xd not running" empty state until reopened.

Watch `api.port` (inotify or 1s poll) + a daemon-reachable event
that triggers Tauri-side `ChatState` rebuild. Frontend listens,
re-mounts the chat panel transparently.

Acceptance: scenario from 3.1 → panel shows a "Reconnecting…"
banner that disappears once x0xd is back; no manual reopen needed.

### 3.3 Outbox feedback honesty · NEW task

Today: a stuck DM stays ⏳ for hours because the timeout is set for
"peer offline for days" semantics (#139's 24 h ⚠ threshold). When
the local daemon dies, ⏳ is the *wrong* status — it's not waiting
for the peer, the send literally cannot leave the box.

Two-tier timeout:
- **Local-fault tier (≤ 10 s)** — if `chat_send_dm` doesn't return
  within 10 s, flip the bubble to ⚠ with the reason ("Daemon
  reconnecting" / "Network unreachable"). Show a Retry button.
- **Peer-offline tier (24 h, current)** — keeps the existing
  semantics for ⏳ → ⚠ when the peer is simply offline.

Acceptance: kill x0xd mid-send → bubble flips ⚠ in ≤ 10 s with the
correct reason → Retry succeeds once x0xd recovers (per 3.1).

### 3.4 Daemon-status badge separate from peer-presence · NEW task

Today: the green dot on a contact reflects relay WS state of the
peer's *session*, not whether your local stack can actually
deliver. When your x0xd died but the relay WS stayed up on the
peer's side, the dot stayed green while sends were impossible.

Add a status pill in the chat panel header (or near the composer)
that reflects **local readiness**:
- ● green — daemon connected, relay WS open, ready to send
- ◐ amber — "Reconnecting…" (daemon down OR WS dead)
- ● red — manual intervention required (e.g. token mismatch after
  vault wipe)

Peer presence dot keeps its current meaning but the tooltip
clarifies: "online on relay — does not guarantee delivery."

Acceptance: kill local x0xd → header pill flips amber while peer
dot stays whatever it was → no user confusion about why sends
aren't moving.

### 3.5 Single contact-store source of truth · task #155

Today: contacts live in two places —
`~/.local/share/io.etchit.fetchit/chat/contacts/` (fetch>it's
StoredContactCard) and x0xd's `~/.local/share/x0x/contacts.json`.
They can disagree; today they did.

Decide and document:
- **Option A** — fetch>it owns the contact store; stop calling
  `Endpoint::import_uri` (x0xd's `/agent/card/import`) entirely.
  Cleaner, but loses any x0xd-side gossip-routing that depends on
  its contact list.
- **Option B** — keep the dual-write but make `chat_import_card`
  atomic + verify x0xd's side persisted; surface a "contact
  partially imported" warning when it didn't.

Acceptance: import a contact → both stores agree, or only one
exists. CI fixture covers the case.

### 3.6 QR pairing · task #102

Today: contact handoff = generate 12 KB URI, send it to the other
box, paste in dialog. Tested live today; even with byte-perfect
file transfer it's painful, and email/clipboard mangle the URI
silently.

Default add-contact affordance becomes "Show / Scan QR." For v2
DEFLATE URIs that exceed the QR ceiling (current cards are
~12 KB), either:
- compress the share URI further (drop unused v2 fields for v1
  scan, fetch full card from relay profile-index lazily)
- multi-frame QR (animated) with a fallback "tap to copy" link

Paste-URI flow stays for power users in Advanced.

Acceptance: two boxes pair end-to-end using only one box's screen
+ the other's camera. No copy-paste, no scp, no email.

### 3.7 Installer with bundled x0xd · NEW task

Today: install = clone repo, install Rust toolchain, install Node,
install x0x via shell pipe, build for 10 minutes. Hostile to
everyone who isn't a dev.

Ship per-OS installers that:
- Include the fetch>it desktop binary (Tauri 2 release build).
- Bundle x0xd or download it on first launch with a clear progress
  UI ("Installing chat daemon…").
- Install the systemd user unit (Linux) / launch agent (macOS) for
  x0xd alongside.
- Show an onboarding window on first launch: display name → done.

Acceptance: download → launch → onboarding → first message sent in
under 5 minutes on a fresh box, no terminal opened.

### 3.8 CLI papercuts · task #154

Lower priority — only devs see these — but trivial to clean up
during the polish sprint:
- Suppress Debug-print of `Welcomed { Conversation { ... } }` in
  `chat` subcommand.
- Change default `--data-dir` from `/opt/alice/fetchit-data` to
  `$XDG_DATA_HOME/fetchit-peer`.
- `card` subcommand emits agent_id on stdout (or `--format json`
  / `--print-agent-id`).
- `chat --peer` mentions `import` as prereq in `--help`.

Bundle as one PR.

---

## 4. Acceptance gate (when polish is done)

Concrete user-facing tests. All must pass without dev intervention:

1. **Fresh-box install** — wipe a Linux/macOS VM, download the
   installer, launch, set a display name, scan a QR shown by a
   known peer, send `hello`. Receive `hi`. Total time under 5 min,
   no terminal opened.
2. **Daemon-kill stress** — during an active chat,
   `pkill -KILL x0xd`. Within ~5 s the header pill flips amber.
   Within ~5 s after that, daemon back, pill green, the in-flight
   DM that flipped ⚠ retries successfully via the Retry button.
3. **WS-disconnect stress** — `iptables -A OUTPUT -d <relay-ip> -j
   DROP` for 30 s. Header pill flips amber, bubbles flip ⚠ in
   ≤ 10 s. Restore. Pill green, Retry succeeds.
4. **First-contact via QR** — neither side has paste-URI; pairing
   completes via QR scan only.
5. **Old-build update path** — install old version, get the
   update, daemon survives. No silent death.

Once 1–5 are green on both Linux and macOS, the polish gate closes
and feature work resumes against the Section 2 deferred list.

---

## 5. After polish (feature work resumes)

This is the parking lot for the in-flight / pending product
threads — nothing is dropped, only sequenced.

- **Profile manifest v3 consumer** (cache + render + relay
  `/v1/profile` GET path). etch>it ships the publisher tab
  in parallel.
- **MLS real groups** (replace the current TOFU one-DM group with
  the proper saorsa-mls path).
- **File transfer** (1:1 small inline, then chunked).
- **Voice / video** (long term — depends on x0xd transport surface).
- **Multi-device sync** (per-device KEM keys, welcome forwarding).
- **Payment integration** (LIT-side, depends on revenue model
  in `private/revenue-model.md`).

When the gate opens, these are sequenced by user-visible impact,
not engineering convenience.
