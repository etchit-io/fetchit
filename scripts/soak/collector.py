#!/usr/bin/env python3
"""Soak collector: parse fetchit-chat-peer logs into delivery metrics.

Consumes the per-peer stderr logs from a daemonless soak fleet
(`fetchit-chat-peer --daemonless ... `) and reports delivery health:
delivery rate, time-to-delivery (TTD), stuck-Sending, and inbound count.

Log contract (from fetchit-chat-peer, see crates/fetchit-chat/src/bin/peer.rs):
  send    : [peer] sent -- id=Some("<hex>")      (Option-debug wrapped)
  send    : [peer] sent -- id=None               (no relay id assigned)
  receipt : [peer] got receipt for message_id=<hex>   (bare hex, on the SENDER's log)
  inbound : [peer] inbound: kind=... sender=...
  identity: [peer] agent_id: <64hex>             (first boot, stderr)

A send and its delivery receipt both land on the SENDER's log, so a send is
"delivered" when a receipt with the same id appears. Raw peer lines carry no
timestamp, so TTD is measured from when the collector OBSERVES each line
(`--follow`); for exact TTD run the peers under journald/ts and feed timestamped
lines (the leading-ISO-timestamp parser handles that automatically).

Usage:
  collector.py --once   peer-*.log              # one-shot report over static logs
  collector.py --follow --interval 60 peer-*.log   # live tail, summary every 60s
  collector.py --selftest                       # parser/metric self-check, no files
"""

from __future__ import annotations

import argparse
import glob
import re
import sys
import time
from dataclasses import dataclass, field

SENT_RE = re.compile(r"\[peer\] sent -- id=Some\(\"([0-9a-fA-F]+)\"\)")
SENT_NONE_RE = re.compile(r"\[peer\] sent -- id=None")
RECEIPT_RE = re.compile(r"\[peer\] got receipt for message_id=([0-9a-fA-F]+)")
INBOUND_RE = re.compile(r"\[peer\] inbound:")
AGENT_RE = re.compile(r"\[peer\] agent_id: ([0-9a-fA-F]{64})")
# Optional leading ISO-8601 timestamp (journald `-o short-iso` / `ts`):
# "2026-06-15T01:02:03+00:00 [peer] ...". Used when present, else arrival time.
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:[+-]\d\d:?\d\d|Z)?)")


@dataclass
class Stats:
    sent: dict[str, float] = field(default_factory=dict)  # id -> t_sent
    delivered: dict[str, float] = field(default_factory=dict)  # id -> t_receipt
    sent_no_id: int = 0
    inbound: int = 0

    def observe(self, line: str, now: float) -> None:
        """Fold one log line into the running tallies. `now` is the fallback
        timestamp when the line carries no leading ISO stamp."""
        t = _line_time(line, now)
        m = SENT_RE.search(line)
        if m:
            self.sent.setdefault(m.group(1).lower(), t)
            return
        if SENT_NONE_RE.search(line):
            self.sent_no_id += 1
            return
        m = RECEIPT_RE.search(line)
        if m:
            self.delivered.setdefault(m.group(1).lower(), t)
            return
        if INBOUND_RE.search(line):
            self.inbound += 1

    def report(self, now: float, stuck_after: float) -> str:
        sent = len(self.sent)
        delivered = sum(1 for i in self.sent if i in self.delivered)
        rate = (100.0 * delivered / sent) if sent else 0.0
        ttds = sorted(
            self.delivered[i] - self.sent[i]
            for i in self.sent
            if i in self.delivered and self.delivered[i] >= self.sent[i]
        )
        stuck = [
            i for i, ts in self.sent.items()
            if i not in self.delivered and (now - ts) > stuck_after
        ]
        # Receipts for ids we never saw a send for (log gap / cross-host).
        orphan_receipts = sum(1 for i in self.delivered if i not in self.sent)
        lines = [
            f"sent={sent} delivered={delivered} rate={rate:.1f}% "
            f"stuck={len(stuck)} inbound={self.inbound} "
            f"sent_no_id={self.sent_no_id} orphan_receipts={orphan_receipts}",
        ]
        if ttds:
            lines.append(
                f"  TTD p50={_pct(ttds, 50):.2f}s p95={_pct(ttds, 95):.2f}s "
                f"max={ttds[-1]:.2f}s (n={len(ttds)})"
            )
        if stuck:
            lines.append(f"  STUCK ids (no receipt > {stuck_after:.0f}s): "
                         + " ".join(s[:12] for s in stuck[:10])
                         + (" ..." if len(stuck) > 10 else ""))
        return "\n".join(lines)


def _line_time(line: str, fallback: float) -> float:
    m = TS_RE.match(line)
    if not m:
        return fallback
    try:
        import datetime
        return datetime.datetime.fromisoformat(
            m.group(1).replace("Z", "+00:00")
        ).timestamp()
    except ValueError:
        return fallback


def _pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = max(0, min(len(sorted_vals) - 1, int(round((p / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def run_once(paths: list[str], stuck_after: float) -> Stats:
    st = Stats()
    now = time.time()
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    st.observe(line.rstrip("\n"), now)
        except OSError as e:
            print(f"warn: {path}: {e}", file=sys.stderr)
    return st


def run_follow(paths: list[str], stuck_after: float, interval: float) -> None:
    files = {p: open(p, encoding="utf-8", errors="replace") for p in paths}
    for f in files.values():
        f.seek(0, 2)  # tail: start at EOF
    st = Stats()
    last = time.time()
    try:
        while True:
            for f in files.values():
                for line in f:
                    st.observe(line.rstrip("\n"), time.time())
            if time.time() - last >= interval:
                print(f"[{time.strftime('%H:%M:%S')}] " + st.report(time.time(), stuck_after),
                      flush=True)
                last = time.time()
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n=== final ===\n" + st.report(time.time(), stuck_after))
    finally:
        for f in files.values():
            f.close()


def _selftest() -> int:
    st = Stats()
    t0 = 1000.0
    st.observe('[peer] agent_id: ' + 'a' * 64, t0)
    st.observe('[peer] sent -- id=Some("AbCd01")', t0)        # case-folded
    st.observe('[peer] sent -- id=Some("deadbeef")', t0)
    st.observe('[peer] sent -- id=None', t0)                  # no-id send
    st.observe('[peer] got receipt for message_id=abcd01', t0 + 1.5)  # delivers the first
    st.observe('[peer] inbound: kind=dm sender=ff', t0)
    st.observe('2026-06-15T00:00:05Z [peer] got receipt for message_id=cafe', t0)  # orphan
    rep = st.report(now=t0 + 600, stuck_after=300)
    checks = {
        "sent=2": "sent=2" in rep,
        "delivered=1": "delivered=1" in rep,
        "rate=50.0%": "rate=50.0%" in rep,
        "stuck=1": "stuck=1" in rep,            # deadbeef, no receipt, age 600 > 300
        "inbound=1": "inbound=1" in rep,
        "sent_no_id=1": "sent_no_id=1" in rep,
        "orphan_receipts=1": "orphan_receipts=1" in rep,
        "ttd present": "TTD p50=1.50s" in rep,
        "iso-ts parsed": _line_time("2026-06-15T00:00:05Z x", 0.0) > 0,
    }
    ok = all(checks.values())
    for name, passed in checks.items():
        print(f"  {'ok ' if passed else 'FAIL'} {name}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    print("--- sample report ---\n" + rep)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="fetchit soak delivery collector")
    ap.add_argument("logs", nargs="*", help="peer log files (globs ok)")
    ap.add_argument("--once", action="store_true", help="one-shot report over static logs")
    ap.add_argument("--follow", action="store_true", help="live tail + periodic summary")
    ap.add_argument("--interval", type=float, default=60.0, help="follow summary interval (s)")
    ap.add_argument("--stuck-after", type=float, default=300.0,
                    help="a send with no receipt older than this is 'stuck' (s)")
    ap.add_argument("--selftest", action="store_true", help="run parser/metric self-check")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    paths: list[str] = []
    for g in args.logs:
        paths.extend(sorted(glob.glob(g)) or [g])
    if not paths:
        ap.error("no log files given (or --selftest)")

    if args.follow:
        run_follow(paths, args.stuck_after, args.interval)
        return 0
    print(run_once(paths, args.stuck_after).report(time.time(), args.stuck_after))
    return 0


if __name__ == "__main__":
    sys.exit(main())
