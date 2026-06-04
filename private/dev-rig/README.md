# Dev pair-rig — systemd configs

Templates of the systemd units and wrapper scripts powering the
Claude pair-rig (`/tmp/claude-pair/to-bob.txt` ↔ `/tmp/claude-rx`).
Versioned so each box has a canonical copy of the other side's setup.

## Failure-modes addressed by the current shape

1. **x0xd port drift.** x0xd binds a fresh free port on every start.
   The X0xdSigner self-heals via `--x0xd-port-file` (`b552a65`) so
   in-flight `/agent/sign` calls survive an x0xd restart. The
   wrapper script also reads `api.port` at start-time so a new
   chat-peer launches with the live port.

2. **Daemon clean-exit.** x0xd exits with status=0 don't propagate as
   "service failed" — `Requires=` ignores them. `PartOf=` cascades
   stop AND restart of the target unit to this one, so a deliberate
   `systemctl restart x0xd-claude-here` brings chat-peer back too.

3. **Mid-batch crash.** chat-peer reading stdin lost any queued line
   on death; `tail -F` resumes at EOF on restart so the pre-crash
   tail was permanently lost. The new `--outbox-file` /
   `--cursor-file` mode reads the outbox directly and persists a
   byte-offset cursor atomically per acked send. `Restart=always`
   brings chat-peer back; the new process resumes from the cursor.

4. **Permanent send failure.** chat-peer exits with code 2 on
   exhausted retries; `Restart=always` (not `Restart=on-failure`)
   covers this signal — a freshly-spawned chat-peer re-reads
   `api.port` via the wrapper and tries again.

## Files

- `box-a-x0xd-claude-here.service` — Box A's x0xd named instance.
- `box-a-claude-chat-peer-start.sh` — Box A wrapper script that
  resolves `api.port` once at start time and execs the binary in
  outbox+cursor mode.
- `box-a-fetchit-chat-peer-claude.service` — Box A unit. `PartOf` +
  `After` on x0xd; `Restart=always`.

Box B has equivalent files under his own paths — not versioned here
because the paths (`HOME`, agent_id, x0x service name) differ.
Adaptation template lives in `/tmp/claude-pair/to-bob.txt` message
chain.

## Acceptance tests (Box A confirmed passing 2026-06-03)

1. **Port drift recovery.** `systemctl stop x0xd-claude-here`; queue 3
   messages into outbox; `systemctl start x0xd-claude-here`. All 3
   deliver after recovery.
2. **Mid-batch crash.** `kill -KILL <chat-peer-pid>` while a batch is
   in flight; verify systemd restarts within `RestartSec` and the
   cursor resumes without dupes.
3. **Overnight zero-touch.** Leave the rig running overnight; expect
   no manual interventions.

## Known follow-up

- `Client::build` performs `/version` + `/health` probes via the
  `Http` wrapper, NOT via `X0xdSigner`, so an in-process port drift
  during build fails. systemd `Restart=always` covers this but burns
  one restart cycle. Threading the same self-heal pattern into
  `fetchit-chat::Http` would close this gap. Tracked as task #261.
