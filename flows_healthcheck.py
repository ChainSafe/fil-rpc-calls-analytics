#!/usr/bin/env python3
"""Capture-health / delivery report for a mitmproxy dump.

By design the producers here are fire-and-forget: they write a request and
disconnect without reading the response (that's the point of the connection
extender), so ``Client disconnected.`` is expected. What matters is whether
the request *body* actually arrived. This classifies every POST flow as:

  delivered    request body present (a complete, usable call)
  aborted      body declared (Content-Length>0) but never arrived, and the
               flow errored / has no response — the fire-and-forget close race
  capture-gap  body missing on an OTHERWISE complete flow (response present,
               no error) — this is the only bucket that implies a real
               capture/streaming problem and should be ~0
  empty-ok     POST with no declared body (Content-Length 0/absent)

It also breaks the delivery rate down by producer (User-Agent) and by hour,
so you can see whether the loss tracks a client or a time window. The scan
reuses the converter's fast framing, fanned out across worker processes.
"""
from __future__ import annotations

import argparse
import os
from collections import Counter, deque
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from flows_to_parquet import _chunks, _deserialize, _open_input


def _classify_chunk(chunk: list) -> Counter:
    """Worker: classify each flow into delivery buckets. Returns one Counter
    with namespaced tuple keys so results merge with ``+`` across workers:
      ("class", <bucket>)            overall bucket counts
      ("ua",   <producer>, <bucket>) per-User-Agent (delivered/aborted/gap)
      ("hour", <epoch_hour>, <bucket>) per-hour (delivered/aborted/gap)
    """
    c: Counter = Counter()
    for _flow_id, blob in chunk:
        flow = _deserialize(blob)
        if not hasattr(flow, "request"):
            c["class", "non_http"] += 1
            continue
        req = flow.request
        if req.method != "POST":
            c["class", "non_post"] += 1
            continue

        if req.raw_content:
            bucket = "delivered"
        else:
            cl = req.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > 0:
                complete = (flow.response is not None
                            and getattr(flow, "error", None) is None
                            and req.timestamp_end is not None)
                bucket = "capture_gap" if complete else "aborted"
            else:
                bucket = "empty_ok"

        c["class", bucket] += 1
        if bucket in ("delivered", "aborted", "capture_gap"):
            producer = (req.headers.get("user-agent", "") or "<none>").split(" ")[0]
            c["ua", producer, bucket] += 1
            ts = req.timestamp_start
            if ts:
                c["hour", int(ts // 3600), bucket] += 1
        if bucket == "aborted":
            # Did the proxy still open an upstream connection to the node? If so
            # the request was likely forwarded/processed despite no stored body,
            # so the node saw load the capture doesn't reflect.
            sc = getattr(flow, "server_conn", None)
            c["aborted_upstream", bool(getattr(sc, "timestamp_tcp_setup", None))] += 1
    return c


def _scan(args) -> Counter:
    totals: Counter = Counter()
    stream = _open_input(args.input)
    try:
        gen = _chunks(stream, max(1, args.chunk))
        if args.jobs <= 1:
            for chunk in gen:
                totals += _classify_chunk(chunk)
        else:
            max_inflight = args.jobs * 3
            with ProcessPoolExecutor(max_workers=args.jobs) as ex:
                futures = deque()
                for chunk in gen:
                    futures.append(ex.submit(_classify_chunk, chunk))
                    if len(futures) >= max_inflight:
                        totals += futures.popleft().result()
                while futures:
                    totals += futures.popleft().result()
    finally:
        stream.close()
    return totals


def _rate(delivered: int, aborted: int, gap: int) -> float:
    denom = delivered + aborted + gap
    return (delivered / denom * 100) if denom else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help="mitmproxy dump (.mitm or .mitm.zst)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2),
                    help="parallel worker processes (1 = single process)")
    ap.add_argument("--chunk", type=int, default=200,
                    help="flows per work unit handed to a worker")
    ap.add_argument("--gap-pct", type=float, default=1.0,
                    help="warn if capture-gap exceeds this %% of POST flows")
    ap.add_argument("--top", type=int, default=12, help="producers to list")
    args = ap.parse_args()

    t = _scan(args)
    cls = {k[1]: v for k, v in t.items() if k[0] == "class"}
    delivered = cls.get("delivered", 0)
    aborted = cls.get("aborted", 0)
    gap = cls.get("capture_gap", 0)
    empty_ok = cls.get("empty_ok", 0)
    post = delivered + aborted + gap + empty_ok
    flows = post + cls.get("non_post", 0) + cls.get("non_http", 0)

    def pct(n, d):
        return f"{n / d * 100:5.1f}%" if d else "  0.0%"

    print(f"dump: {args.input}")
    print(f"\ntotal flows:        {flows:>14,}")
    print(f"  non-HTTP / non-POST {cls.get('non_http',0) + cls.get('non_post',0):>12,}")
    print(f"\nPOST flows:         {post:>14,}")
    ab_upstream = t.get(("aborted_upstream", True), 0)
    print(f"  delivered (body)  {delivered:>14,}  {pct(delivered, post)}")
    print(f"  aborted (no body) {aborted:>14,}  {pct(aborted, post)}   <- fire-and-forget, expected")
    print(f"    of which the proxy still opened an upstream conn to the node: "
          f"{ab_upstream:,}  {pct(ab_upstream, aborted)}")
    print(f"  capture-gap       {gap:>14,}  {pct(gap, post)}   <- should be ~0")
    print(f"  empty-ok (no CL)  {empty_ok:>14,}  {pct(empty_ok, post)}")
    print(f"\nbody delivery rate: {_rate(delivered, aborted, gap):.2f}% "
          f"({delivered:,} of {delivered + aborted + gap:,} body-bearing POSTs)")

    # ---- per-producer ----
    ua: dict = {}
    for k, v in t.items():
        if k[0] == "ua":
            _, producer, bucket = k
            ua.setdefault(producer, Counter())[bucket] += v
    rows = sorted(ua.items(), key=lambda kv: -sum(kv[1].values()))[:args.top]
    print(f"\ndelivery by producer (User-Agent), top {args.top}:")
    print(f"  {'producer':<26}{'delivered':>12}{'aborted':>12}{'gap':>10}{'deliv%':>9}")
    for producer, cc in rows:
        d, a, g = cc["delivered"], cc["aborted"], cc["capture_gap"]
        print(f"  {producer[:26]:<26}{d:>12,}{a:>12,}{g:>10,}{_rate(d, a, g):>8.1f}%")

    # ---- over time ----
    hours: dict = {}
    for k, v in t.items():
        if k[0] == "hour":
            _, h, bucket = k
            hours.setdefault(h, Counter())[bucket] += v
    if hours:
        print("\ndelivery by hour (UTC):")
        print(f"  {'hour':<17}{'delivered':>12}{'aborted':>12}{'deliv%':>9}")
        for h in sorted(hours):
            cc = hours[h]
            d, a, g = cc["delivered"], cc["aborted"], cc["capture_gap"]
            ts = datetime.fromtimestamp(h * 3600, timezone.utc).strftime("%Y-%m-%d %H:00")
            print(f"  {ts:<17}{d:>12,}{a:>12,}{_rate(d, a, g):>8.1f}%")

    gap_pct = (gap / post * 100) if post else 0.0
    if gap_pct >= args.gap_pct:
        print(f"\n  ⚠  CAPTURE GAP: {gap_pct:.1f}% of POSTs were recorded as complete flows "
              f"but have no body.\n     That's a real capture/streaming problem (not fire-and-forget). "
              f"Check mitmdump body options.")
    else:
        print(f"\n  ✓  no capture gap ({gap_pct:.2f}%). Missing bodies are fire-and-forget flows the "
              f"proxy didn't buffer — NOT a capture defect.")
        if ab_upstream:
            print(f"     Note: {pct(ab_upstream, aborted).strip()} of aborted flows still opened an "
                  f"upstream connection to the node, so they were likely forwarded/processed.\n"
                  f"     The capture UNDER-COUNTS real node load — confirm RPC volume on the node side "
                  f"(Forest/Lotus metrics), not from this Parquet.")


if __name__ == "__main__":
    main()
