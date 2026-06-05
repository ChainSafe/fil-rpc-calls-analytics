#!/usr/bin/env python
"""Fetch DigitalOcean monitoring metrics for the Forest droplet, aligned to a
capture.

For each parquet you pass, it reads the capture's first/last `ts_start`, then
pulls every metric over exactly that window from the DO Monitoring API and
writes `do-metrics/<label>__<metric>.json` (the raw API response, the shape
`do_metrics.py` reads). Because the window is derived from the parquet, the DO
data lines up with the captured traffic — no hand-typed dates.

    # Config comes from a .env file (gitignored) or the environment — neither the
    # API token nor the droplet id is hard-coded. Put in .env:
    #     DIGITALOCEAN_TOKEN=dop_v1_...     # a READ-ONLY token is enough
    #     DIGITALOCEAN_HOST_ID=123456789    # the droplet's numeric id (not its name)
    .venv/bin/python fetch_do.py <before.parquet> <after.parquet>

    # or pass them explicitly:
    .venv/bin/python fetch_do.py --token dop_v1_... --host 123456789 calls.parquet
    .venv/bin/python fetch_do.py --dry-run calls-26-05-26.parquet   # show the plan, fetch nothing

`doctl` does NOT expose time-series metrics, so this uses the raw API. Only the
standard library is used (no extra deps).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import polars as pl

API = "https://api.digitalocean.com/v2/monitoring/metrics/droplet"

# Plain metrics: endpoint name == output suffix.
METRICS = [
    "memory_total", "memory_available", "memory_free", "memory_cached",
    "cpu", "filesystem_free", "filesystem_size", "load_1",
]
# Bandwidth needs interface + direction; one file per direction.
BANDWIDTH = [("inbound", "bw_inbound"), ("outbound", "bw_outbound")]


def label_for(parquet: str, start: int) -> str:
    """Window label from the filename's date (`calls-26-05-26` -> `may26`),
    falling back to the capture's start date."""
    m = re.search(r"(\d{2})-(\d{2})-(\d{2})", Path(parquet).stem)
    if m:
        yy, mm, dd = (int(x) for x in m.groups())
        try:
            return dt.date(2000 + yy, mm, dd).strftime("%b%d").lower()
        except ValueError:
            pass
    return dt.datetime.fromtimestamp(start, dt.timezone.utc).strftime("%b%d").lower()


def capture_window(parquet: str, pad: int) -> tuple[int, int]:
    """`(start, end)` unix seconds spanning the capture, padded by `pad` seconds
    each side so DO's ~162s sampling covers the very edges."""
    ts = (pl.scan_parquet(parquet)
            .select(pl.col("ts_start").min().alias("a"), pl.col("ts_start").max().alias("b"))
            .collect())
    return int(ts["a"][0]) - pad, int(ts["b"][0]) + pad


def get(metric: str, params: dict, token: str) -> bytes:
    url = f"{API}/{metric}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def samples(body: bytes) -> int:
    """Count time-series points across all result series (for a friendly log)."""
    try:
        res = json.loads(body).get("data", {}).get("result", [])
        return sum(len(s.get("values", [])) for s in res)
    except (ValueError, AttributeError):
        return 0


def fetch_window(parquet, host, token, out_dir, interface, pad, dry_run):
    start, end = capture_window(parquet, pad)
    label = label_for(parquet, start)
    fmt = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
    print(f"\n{Path(parquet).name}  ->  window '{label}'  "
          f"[{fmt(start)} .. {fmt(end)} UTC, {(end - start) / 3600:.1f}h]")

    jobs = [(m, m, {"host_id": host, "start": start, "end": end}) for m in METRICS]
    jobs += [("bandwidth", suffix,
              {"host_id": host, "start": start, "end": end,
               "interface": interface, "direction": direction})
             for direction, suffix in BANDWIDTH]

    for endpoint, suffix, params in jobs:
        dest = out_dir / f"{label}__{suffix}.json"
        if dry_run:
            print(f"  would GET {endpoint:<11} {dict(direction=params.get('direction', '-'))}"
                  f"  ->  {dest}")
            continue
        try:
            body = get(endpoint, params, token)
        except urllib.error.HTTPError as e:
            print(f"  ! {suffix}: HTTP {e.code} {e.reason} — {e.read().decode(errors='replace')[:200]}",
                  file=sys.stderr)
            continue
        except urllib.error.URLError as e:
            print(f"  ! {suffix}: {e.reason}", file=sys.stderr)
            continue
        dest.write_bytes(body)
        print(f"  wrote {dest}  ({samples(body)} points)")


def load_dotenv(path=None):
    """Populate os.environ from a `.env` file (KEY=VALUE lines) WITHOUT overriding
    anything already set, so a real shell export or mise still wins. Stdlib only —
    keeps this script dependency-free. Looks next to the script by default; blank
    values are ignored so an empty `KEY=` doesn't mask a real export."""
    p = Path(path) if path else Path(__file__).resolve().parent / ".env"
    if not p.exists():
        return
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip().strip('"').strip("'")
        if val:
            os.environ.setdefault(key.strip(), val)


def main():
    ap = argparse.ArgumentParser(description="Fetch DigitalOcean metrics aligned to capture parquets.")
    ap.add_argument("parquets", nargs="+", help="capture parquet file(s); one DO window each")
    ap.add_argument("--token", help="DO API token (else $DIGITALOCEAN_TOKEN); read-only is enough")
    ap.add_argument("--host", help="droplet host id (else $DIGITALOCEAN_HOST_ID)")
    ap.add_argument("--out", default="do-metrics", help="output dir (default do-metrics)")
    ap.add_argument("--interface", default="public", help="bandwidth interface (default public)")
    ap.add_argument("--pad", type=int, default=300, help="seconds to pad each side (default 300)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, fetch nothing")
    args = ap.parse_args()
    load_dotenv()  # pull DIGITALOCEAN_TOKEN / DIGITALOCEAN_HOST_ID from .env if present

    token = args.token or os.environ.get("DIGITALOCEAN_TOKEN")
    host = args.host or os.environ.get("DIGITALOCEAN_HOST_ID")
    if not token and not args.dry_run:
        ap.error("no token: set DIGITALOCEAN_TOKEN (e.g. in .env) or pass --token (read-only is enough)")
    if not host:
        ap.error("no droplet id: set DIGITALOCEAN_HOST_ID (e.g. in .env) or pass --host")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"droplet host {host}  ->  {out_dir}{'  (dry run)' if args.dry_run else ''}")
    for parquet in args.parquets:
        fetch_window(parquet, host, token, out_dir, args.interface, args.pad, args.dry_run)
    print("\ndone")


if __name__ == "__main__":
    main()
