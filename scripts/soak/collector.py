#!/usr/bin/env python3
"""Soak collector: parse fetchit-chat-peer logs into delivery metrics.

Consumes the per-peer stderr logs from a daemonless soak fleet
(`fetchit-chat-peer --daemonless ... `) and reports delivery health:
delivery rate, time-to-delivery (TTD), stuck-Sending, inbound count, and
duplicate deliveries (an id received more than once = the retry path resent).

Log contract (from fetchit-chat-peer, see crates/fetchit-chat/src/bin/peer.rs):
  send    : [peer] sent -- id=Some("<hex>")      (Option-debug wrapped)
  send    : [peer] sent -- id=None               (no relay id assigned)
  receipt : [peer] got receipt for message_id=<hex>   (bare hex, on the SENDER's log)
  inbound : [peer] inbound: kind=... sender=...        (every received msg, pre-decrypt)
  inbound-msg: [peer] inbound-msg id=<hex> sender=<short>  (post-decrypt; one per
            received msg that carries an id -- used to dedupe double-deliveries)
  identity: [peer] agent_id: <64hex>             (first boot, stderr)

A send and its delivery receipt both land on the SENDER's log, so a send is
"delivered" when a receipt with the same id appears. Raw peer lines carry no
timestamp, so TTD is measured from when the collector OBSERVES each line
(`--follow`); for exact TTD run the peers under journald/ts and feed timestamped
lines (the leading-ISO-timestamp parser handles that automatically).

Usage:
  collector.py --once   peer-*.log              # one-shot report over static logs
  collector.py --follow --interval 60 peer-*.log   # live tail, summary every 60s
  collector.py --follow --prometheus soak.prom peer-*.log  # + node_exporter gauges
  collector.py --selftest                       # parser/metric self-check, no files
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import time
from dataclasses import dataclass, field

SENT_RE = re.compile(r"\[peer\] sent -- id=Some\(\"([0-9a-fA-F]+)\"\)")
SENT_NONE_RE = re.compile(r"\[peer\] sent -- id=None")
RECEIPT_RE = re.compile(r"\[peer\] got receipt for message_id=([0-9a-fA-F]+)")
INBOUND_RE = re.compile(r"\[peer\] inbound:")
INBOUND_MSG_RE = re.compile(r"\[peer\] inbound-msg id=([0-9a-fA-F]+) sender=(\S+)")
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
    inbound_ids: dict[str, int] = field(default_factory=dict)  # received id -> times seen

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
        m = INBOUND_MSG_RE.search(line)
        if m:
            rid = m.group(1).lower()
            self.inbound_ids[rid] = self.inbound_ids.get(rid, 0) + 1
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
        # Inbound dedupe: an id received more than once is a double-delivery (the
        # retry path resent an already-delivered DM). Cross-check vs the sends.
        inbound_total = sum(self.inbound_ids.values())
        dup_ids = sorted(i for i, c in self.inbound_ids.items() if c > 1)
        dup_from_sent = sum(1 for i in dup_ids if i in self.sent)
        lines = [
            f"sent={sent} delivered={delivered} rate={rate:.1f}% "
            f"stuck={len(stuck)} inbound={self.inbound} "
            f"sent_no_id={self.sent_no_id} orphan_receipts={orphan_receipts}",
            f"inbound_msgs={inbound_total} inbound_unique={len(self.inbound_ids)} "
            f"dup_delivered={len(dup_ids)} sent-confirmed={dup_from_sent}",
        ]
        if dup_ids:
            lines.append("  DUP-DELIVERED ids (received >1x): "
                         + " ".join(d[:12] for d in dup_ids[:10])
                         + (" ..." if len(dup_ids) > 10 else ""))
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

    def metrics(self, now: float, stuck_after: float) -> dict[str, float]:
        """Scalar gauges for the Prometheus textfile exporter -- delivery rate as
        a 0..1 ratio, TTD percentiles in seconds. Mirrors report()'s numbers."""
        sent = len(self.sent)
        delivered = sum(1 for i in self.sent if i in self.delivered)
        ttds = sorted(
            self.delivered[i] - self.sent[i]
            for i in self.sent
            if i in self.delivered and self.delivered[i] >= self.sent[i]
        )
        stuck = sum(
            1 for i, ts in self.sent.items()
            if i not in self.delivered and (now - ts) > stuck_after
        )
        return {
            "soak_sent_total": sent,
            "soak_delivered_total": delivered,
            "soak_delivery_rate": (delivered / sent) if sent else 0.0,
            "soak_stuck": stuck,
            "soak_sent_no_id": self.sent_no_id,
            "soak_orphan_receipts": sum(1 for i in self.delivered if i not in self.sent),
            "soak_inbound_msgs": sum(self.inbound_ids.values()),
            "soak_inbound_unique": len(self.inbound_ids),
            "soak_dup_delivered": sum(1 for c in self.inbound_ids.values() if c > 1),
            "soak_ttd_p50_seconds": _pct(ttds, 50),
            "soak_ttd_p95_seconds": _pct(ttds, 95),
            "soak_ttd_max_seconds": ttds[-1] if ttds else 0.0,
        }


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


def write_prometheus(metrics: dict[str, float], path: str, now: float) -> None:
    """Atomically write node_exporter textfile-collector gauges (tmp + rename, so
    a concurrent node_exporter scrape never reads a half-written file)."""
    lines: list[str] = []
    for name, value in metrics.items():
        # Prometheus convention: cumulative *_total are counters (so rate() and
        # restart-reset detection work); point-in-time values are gauges.
        mtype = "counter" if name.endswith("_total") else "gauge"
        lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")
    lines.append("# TYPE soak_collector_updated_timestamp_seconds gauge")
    lines.append(f"soak_collector_updated_timestamp_seconds {now:.0f}")
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


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


def run_follow(paths: list[str], stuck_after: float, interval: float,
               prometheus: str | None = None) -> None:
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
                now = time.time()
                print(f"[{time.strftime('%H:%M:%S')}] " + st.report(now, stuck_after),
                      flush=True)
                if prometheus:
                    write_prometheus(st.metrics(now, stuck_after), prometheus, now)
                last = now
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
    st.observe('[peer] inbound-msg id=AbCd01 sender=ff00', t0)        # received (id we sent)
    st.observe('[peer] inbound-msg id=AbCd01 sender=ff00', t0 + 0.1)  # DUP delivery (>1x)
    st.observe('[peer] inbound-msg id=99ff sender=ee11', t0)          # received, never sent
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
        "inbound_msgs=3": "inbound_msgs=3" in rep,
        "inbound_unique=2": "inbound_unique=2" in rep,
        "dup_delivered=1": "dup_delivered=1" in rep,
        "dup sent-confirmed=1": "sent-confirmed=1" in rep,
        "ttd present": "TTD p50=1.50s" in rep,
        "iso-ts parsed": _line_time("2026-06-15T00:00:05Z x", 0.0) > 0,
    }
    m = st.metrics(now=t0 + 600, stuck_after=300)
    checks["m delivery_rate=0.5"] = abs(m["soak_delivery_rate"] - 0.5) < 1e-9
    checks["m dup_delivered=1"] = m["soak_dup_delivered"] == 1
    checks["m inbound_msgs=3"] = m["soak_inbound_msgs"] == 3
    checks["m ttd_p50=1.5"] = abs(m["soak_ttd_p50_seconds"] - 1.5) < 1e-9
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "soak.prom")
        write_prometheus(m, p, t0)
        with open(p, encoding="utf-8") as f:
            body = f.read()
    checks["prometheus textfile"] = (
        "soak_sent_total 2" in body
        and "# TYPE soak_sent_total counter" in body
        and "# TYPE soak_delivery_rate gauge" in body
        and "soak_collector_updated_timestamp_seconds" in body
    )
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
    ap.add_argument("--prometheus", default=None, metavar="FILE",
                    help="also write node_exporter textfile gauges (prefix soak_) to "
                         "FILE; works with --once and --follow")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    paths: list[str] = []
    for g in args.logs:
        paths.extend(sorted(glob.glob(g)) or [g])
    if not paths:
        ap.error("no log files given (or --selftest)")

    if args.follow:
        run_follow(paths, args.stuck_after, args.interval, args.prometheus)
        return 0
    st = run_once(paths, args.stuck_after)
    now = time.time()
    if args.prometheus:
        write_prometheus(st.metrics(now, args.stuck_after), args.prometheus, now)
    print(st.report(now, args.stuck_after))
    return 0


if __name__ == "__main__":
    sys.exit(main())
