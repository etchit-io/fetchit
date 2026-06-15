#!/usr/bin/env python3
"""Soak driver: feed the daemonless peer fleet a steady, tagged DM stream.

Each `fetchit-chat-peer --daemonless ... chat --outbox-file F --cursor-file C`
process tails its outbox file and sends one DM per appended line to its fixed
`--peer`, advancing the cursor atomically (restart-safe). This driver appends
sequence-tagged lines across one or more such outbox files at a jittered rate,
so the collector sees a continuous send stream to correlate against receipts.

The send TOPOLOGY (which peer talks to whom) is fixed by provisioning (each
peer's `--peer`); this driver only sets the RATE + payload. Run one driver per
host over that host's outbox files.

Payload is `soak <label> seq=<n> t=<unix> <pad>` so a stuck/duplicated message
is traceable back to its origin + sequence by eye.

Usage:
  driver.py --rate 30 peer-0.outbox peer-1.outbox        # 30 msgs/min total, forever
  driver.py --rate 60 --jitter 0.5 --count 1000 --size 200 peer-*.outbox
"""

from __future__ import annotations

import argparse
import glob
import os
import random
import sys
import time


def append_line(path: str, text: str) -> None:
    # Append + flush + fsync so the peer (and a restart) always see whole lines.
    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")
        f.flush()
        os.fsync(f.fileno())


def main() -> int:
    ap = argparse.ArgumentParser(description="fetchit soak send driver")
    ap.add_argument("outboxes", nargs="+", help="peer outbox files (globs ok)")
    ap.add_argument("--rate", type=float, default=30.0,
                    help="total messages per minute across all outboxes")
    ap.add_argument("--jitter", type=float, default=0.4,
                    help="fractional interval jitter, 0..1 (0.4 = +/-40%%)")
    ap.add_argument("--count", type=int, default=0, help="total messages (0 = forever)")
    ap.add_argument("--size", type=int, default=0,
                    help="pad each payload to ~this many bytes (0 = no pad)")
    ap.add_argument("--label", default=None, help="origin label (default: host name)")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed (reproducible mix)")
    args = ap.parse_args()

    paths: list[str] = []
    for g in args.outboxes:
        paths.extend(sorted(glob.glob(g)) or [g])
    if not paths:
        ap.error("no outbox files")
    for p in paths:  # touch so the peer + we agree the file exists
        open(p, "a", encoding="utf-8").close()

    rng = random.Random(args.seed)
    label = args.label or os.uname().nodename
    base_interval = 60.0 / args.rate if args.rate > 0 else 1.0
    pad = "x" * max(0, args.size)
    sent = 0
    try:
        while args.count == 0 or sent < args.count:
            path = rng.choice(paths)
            body = f"soak {label} seq={sent} t={time.time():.3f}"
            if pad:
                body = (body + " " + pad)[: max(len(body), args.size)]
            append_line(path, body)
            sent += 1
            j = 1.0 + rng.uniform(-args.jitter, args.jitter)
            time.sleep(max(0.0, base_interval * j))
    except KeyboardInterrupt:
        pass
    print(f"driver: appended {sent} messages across {len(paths)} outbox(es)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
