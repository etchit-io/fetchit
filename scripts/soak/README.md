# Cross-device soak harness (DM outbox reliability)

The long-running, multi-host soak that backs section J of
`docs/lit-chat-test-plan.md`: many daemonless chat peers on wyse (LAN/NAT) +
VPS (public, multi-region) hosts exchange DMs continuously while churn is
injected, so we catch what short tests cannot -- leaks, outbox/RSS drift,
delivery rate under churn, MLS epoch wedges, relay failover, long-idle WS.

## Pieces

| Piece | Owner | Role |
| --- | --- | --- |
| `fetchit-chat-peer --daemonless` | Bob (engine) | headless peer; one stable identity per `--data-dir`; sends each line of its `--outbox-file` to its `--peer`, advancing `--cursor-file` atomically |
| `driver.py` | Alice | appends sequence-tagged lines across local outbox files at a jittered rate (the send load) |
| `collector.py` | Alice | parses peer logs -> delivery rate, TTD, stuck-Sending, inbound + dup-delivery (the verdict) |
| `sampler.sh` | Alice | per-peer vault size (du) + RSS over time -> CSV (the leak/growth check) |
| provisioning + churn | Bob | data-dirs, the `--peer` topology, pre-seeded contact cards, net-drop / restart / relay-failover injection |

## Peer invocation (Bob's contract)

```sh
FETCHIT_PASSPHRASE=PASS fetchit-chat-peer --daemonless \
  --relay http://RELAY:8088 --data-dir /opt/soak/peer-N --display-name peer-N \
  chat --peer RECIPIENT_HEX \
  --outbox-file /opt/soak/peer-N.outbox --cursor-file /opt/soak/peer-N.cursor \
  2> /opt/soak/peer-N.log
```

- Daemonless **requires** `FETCHIT_PASSPHRASE` (no keychain on a headless host).
- Each `--data-dir` is a distinct, stable ML-DSA-65 identity. First boot prints
  `[peer] agent_id: <64hex>` to stderr -- capture it to learn each peer's
  address (feeds the `--peer` topology + contact pre-seeding).
- Pure receivers can use the `echo` subcommand instead of `chat` + the files.
- Card exchange daemonless is not live-verified yet, so provisioning pre-seeds
  each peer's contact card into the vault (Bob).

## Run

1. **Provision** (Bob): create data-dirs, decide the `--peer` topology (mix
   same-LAN / cross-NAT / cross-region pairs), pre-seed contact cards, start
   the peers with stderr -> `peer-N.log`, collect the `agent_id`s.
2. **Drive** (per host): `driver.py --rate 30 /opt/soak/peer-*.outbox`
3. **Collect** (central, over aggregated logs):
   `collector.py --follow --interval 60 /agg/peer-*.log`
4. **Sample** (per host): `sampler.sh 300 peer-0=/opt/soak/peer-0 ... > growth.csv`
5. **Churn** (Bob, cycled): network drop, app + daemon restart, relay restart +
   region failover, a long idle window (> CF idle, ties to test-plan F3).

Run it for days. `collector.py --selftest` checks the parser without a fleet.

## Pass (test-plan section J)

- delivery rate ~100% (modulo intentional drops during churn)
- no monotonic vault-size or RSS growth in `growth.csv` (no leak / outbox never drains)
- no permanently stuck-Sending bubbles (transient during churn is fine)
- clean recovery after every churn event

## Open items

- **Dupe detection** (live): the peer emits a post-decrypt
  `[peer] inbound-msg id=<hex> sender=<short>` anchor (one per received message
  that carries an id), so the collector de-dupes inbound by id -- any id received
  more than once is a double-delivery (the retry path resent an already-delivered
  DM), reported as `dup_delivered` and cross-checked against the sender
  `sent -- id=` lines.
- **Precise TTD**: raw peer lines are unstamped, so `--follow` measures TTD from
  observation time. Run peers under journald (`-o short-iso`) or pipe through
  `ts` for exact send->receipt latency (the collector auto-uses a leading ISO
  timestamp when present).
