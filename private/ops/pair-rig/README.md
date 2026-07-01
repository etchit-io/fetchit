# pair-rig — Bob↔Alice chat-peer ops on this box

Operator-specific scaffolding for the claude-pair chat wire on Box B
(Bob's side). The fetchit-chat-peer process is what carries Bob↔Alice
coordination messages; x0xd is the signer/transport daemon underneath.

Both processes used to be launched by hand from a tmux window and
would silently break in three ways during a normal session:

1. **x0xd port drift** — `x0xd --name claude-here` picks a random API
   port on each start. The new port is written to
   `~/.local/share/x0x-claude-here/api.port`, but consumers that
   baked the URL into argv (`--x0xd-base http://127.0.0.1:35841`)
   keep targeting the dead port and fail with
   `envelope sign: http: error sending request for url
   (http://127.0.0.1:<old>/agent/sign)`. The fix is consumer-side
   (read api.port at launch), not daemon-side (pin --api-port).
   See `[[x0xd-port-drift-on-restart]]`.
2. **chat-peer stdin EOF** — chat-peer reads commands from stdin.
   Pointing stdin at the FIFO `/tmp/claude-tx` is the obvious choice,
   but as soon as the last writer (the `echo` inside claude-tx-send)
   closes, the reader sees EOF and chat-peer exits. The wire dies
   silently — claude-tx-send still reports `sent: NN chars`, but no
   peer is reading.
3. **Process death on session end** — when the launching shell goes
   away, both x0xd and chat-peer go with it; no auto-restart.

The rig fixes all three:

- `x0xd-claude-here.service` — systemd `--user` unit that runs x0xd
  with `Restart=on-failure`. No `--api-port` pin (intentional — the
  consumer reads api.port at launch, so any port works).
- `fetchit-chat-peer-claude.service` — systemd `--user` unit with
  `Requires=` + `After=` on the x0xd unit, calls the wrapper script.
- `~/.local/bin/claude-chat-peer-start` — wrapper that:
  - Reads the current x0xd port from
    `~/.local/share/x0x-claude-here/api.port` (closes #1).
  - Ensures `/tmp/claude-tx` exists and opens fd 3 R/W on it so the
    kernel always sees at least one writer (closes #2).
  - Emits a `[start] chat-peer up — pid=… x0xd=… ts=…` health-line
    to `/tmp/claude-rx`.
  - `exec`s chat-peer with stdin redirected from the FIFO.

The wrapper lives at `~/.local/bin/` (not in-repo) because the
systemd unit and any manual `claude-chat-peer-start` invocation
share the same code path. The systemd units live here in
`private/ops/pair-rig/` because they're operator-specific (paths,
instance names, agent_ids) and need to be installed into
`~/.config/systemd/user/` by the installer.

## Install

Pre-reqs:

- `~/.local/bin/x0xd` and `~/.local/bin/x0x` installed (see SKILL.md
  in `~/.local/share/x0x-claude-here/`).
- `~/.local/share/x0x-claude-here/api-token` and `api.port` exist
  (x0xd writes both on first start; run `x0xd --name claude-here`
  once standalone to generate them).
- `fetchit-chat-peer` compiled — from the repo root:
  `cargo build -p fetchit-chat-peer` (or `--release`; the unit's
  default points at `target/debug/`).
- `~/.local/share/fetchit-claude-peer/passphrase` exists (mode 0600).
- `~/.local/bin/claude-chat-peer-start` installed and executable.

Then:

```bash
bash private/ops/pair-rig/install.sh
```

Verify:

```bash
systemctl --user status x0xd-claude-here.service
systemctl --user status fetchit-chat-peer-claude.service
curl -sS "http://$(cat ~/.local/share/x0x-claude-here/api.port)/health"
tail -f /tmp/claude-rx
```

The `[start] chat-peer up — pid=… x0xd=… ts=…` line appears in
`/tmp/claude-rx` on every chat-peer start; if you don't see it,
either x0xd is down or the wrapper failed before exec.

## Uninstall

```bash
bash private/ops/pair-rig/install.sh --uninstall
```

Removes the unit files, disables, and stops. Does not touch data
dirs or the wrapper script.

## Why this is here, not in the public repo

`private/` is gitignored. These units bake in Box B-specific paths
and Alice's agent_id, which (a) wouldn't be useful to anyone else
and (b) shouldn't be public artifacts. Alice runs equivalent
scaffolding from her own private/ops/pair-rig/ on Box A; the units
are operator-specific by design.

## Known gaps

- No socket activation. x0xd needs to be running before chat-peer
  starts, which `Requires=` enforces, but a startup-order race
  between the daemon's API binding and chat-peer's first request
  shows up as a brief `(connection refused)` retry. The
  send_with_retry helper in `c1bbf12` swallows it.
- A genuinely robust shape is for `fetchit-chat-peer` itself to
  re-read `api.port` on every retry rather than baking the resolved
  URL in at launch — then a daemon restart mid-session wouldn't
  need either the wrapper or a chat-peer restart. That's an upstream
  patch to the chat-peer source, not pair-rig scope. Coordinate with
  Alice before changing the wire-level launch contract (Box A runs
  the same binary).
- The Saorsa upstream issue was diagnosed and deliberately not
  filed — see `private/drafts/saorsa-x0xd-port-drift-issue.md` for
  the diagnosis record. Per
  `[[upstream-issues-only-when-blocked]]`, filing would have asked
  Saorsa to absorb a consumer bug we can fix on our side.
