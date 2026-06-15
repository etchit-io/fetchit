#!/usr/bin/env python3
"""Prepend a UTC ISO-8601 timestamp to each stdin line, line-buffered.

The soak peers log untimestamped diagnostics; piping their stderr through this
gives collector.py a leading ISO stamp per line so it computes true send->receipt
TTD (instead of observation-time). Python-only so it runs on every fleet box with
no moreutils/`ts` install. Pair with the peer launch:

    setsid bash -c 'fetchit-chat-peer ... 2>&1 | python3 tsprepend.py >> peer.log' &
"""
import datetime
import sys

for line in sys.stdin:
    sys.stdout.write(f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} {line}")
    sys.stdout.flush()
