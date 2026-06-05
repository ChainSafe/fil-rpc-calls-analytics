"""Shared DigitalOcean monitoring layer.

Single source of truth for every DO number. Reads the monitoring JSON in
`do-metrics/` (one file per `<window>__<metric>.json`, fetched by `fetch_do.py`)
and exposes:

  * stats   — `mem_stats`, `cpu_stats`, `disk_stats`, `load_stats`, `bw_stats`
  * series  — `mem_series`, `cpu_series` (raw) and `mem_overlay`, `cpu_overlay`
              (time-aligned to a parquet capture's `t0`, for the load-over-time
              overlay in `mise-tasks/charts-do`)
  * windows — `windows()` (discover available windows) and `window_for()`
              (pick the window that best overlaps a capture's clock range)

Pure data: no Altair, no parquet. `mise-tasks/charts-do` and `do_summary.py`
import these; `verify_do.py` deliberately does NOT (it re-implements the maths
independently so it can audit these numbers).
"""
from __future__ import annotations

import glob
import json
import os
from statistics import mean

import pandas as pd

DIR = "do-metrics"
GiB = 1024 ** 3

# DO `cpu` is reported as cumulative seconds per mode; everything but `idle`
# counts as busy time. Kept here so the stats and the overlay agree.
BUSY_MODES = ["user", "system", "nice", "iowait", "irq", "softirq", "steal"]


# ----------------------------------------------------------------- io / helpers
def result(path: str) -> list:
    with open(path) as f:
        return json.load(f).get("data", {}).get("result", [])


def tsmap(res: list, idx: int = 0) -> dict[int, float]:
    """`{unix_seconds: value}` for one series of a metric result."""
    return {int(t): float(v) for t, v in res[idx]["values"]}


def pctl(xs, q: float) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(round((len(s) - 1) * q)))]


def windows() -> list[str]:
    """Available capture windows in `do-metrics/`, in a stable, meaningful order."""
    # Only `<window>__<metric>.json` files; skips droplet.json / volumes.json.
    names = {os.path.basename(f).split("__")[0]
             for f in glob.glob(f"{DIR}/*__*.json")}
    order = ["may22", "may26", "now24h"]
    return [n for n in order if n in names] + sorted(names - set(order))


# --------------------------------------------------------------------- stats
def mem_stats(w: str) -> dict:
    """Whole-server memory; `used = total - available`, in GiB and as % of box."""
    tot = tsmap(result(f"{DIR}/{w}__memory_total.json"))
    av = tsmap(result(f"{DIR}/{w}__memory_available.json"))
    ts = sorted(t for t in tot if t in av)
    used = [(tot[t] - av[t]) / GiB for t in ts]
    total = mean(tot.values()) / GiB
    return dict(total=total, used_min=min(used), used_mean=mean(used),
                used_p95=pctl(used, 0.95), used_max=max(used),
                pct_mean=100 * mean(used) / total, pct_max=100 * max(used) / total,
                n=len(used))


def cpu_stats(w: str) -> dict:
    """Whole-server CPU utilisation %; `util = 1 - idle/total` per interval.

    `cores` is derived from `sum(deltas)/Δt` (≈ the box's core count). Counter
    resets / reboots (any negative delta) are skipped.
    """
    res = result(f"{DIR}/{w}__cpu.json")
    modes = {r["metric"]["mode"]: {int(t): float(v) for t, v in r["values"]} for r in res}
    times = sorted(set.intersection(*[set(m) for m in modes.values()]))
    util, cores = [], []
    for a, b in zip(times, times[1:]):
        d = {m: modes[m][b] - modes[m][a] for m in modes}
        tot = sum(d.values())
        if tot <= 0 or b <= a or any(v < 0 for v in d.values()):
            continue
        util.append(100 * (1 - d.get("idle", 0) / tot))
        cores.append(tot / (b - a))
    return dict(util_mean=mean(util), util_p95=pctl(util, 0.95),
                util_max=max(util), cores=round(mean(cores)), n=len(util))


def disk_stats(w: str) -> dict:
    """Whole-server disk usage over the WHOLE series (not the last sample).

    Forest's DB compaction makes disk oscillate, so the peak only shows up if we
    look at every sample — taking the last value badly understates it.
    """
    size = tsmap(result(f"{DIR}/{w}__filesystem_size.json"))
    free = tsmap(result(f"{DIR}/{w}__filesystem_free.json"))
    ct = sorted(x for x in size if x in free)
    used = [(size[t] - free[t]) / GiB for t in ct]
    sz = mean(size.values()) / GiB
    return dict(size=sz, used_mean=mean(used), used_max=max(used),
                pct_mean=100 * mean(used) / sz, pct_max=100 * max(used) / sz)


def load_stats(w: str) -> dict:
    """1-minute load average (compare against the box's core count)."""
    xs = list(tsmap(result(f"{DIR}/{w}__load_1.json")).values())
    return dict(mean=mean(xs), p95=pctl(xs, 0.95), max=max(xs))


def bw_stats(w: str) -> dict:
    """Public network bandwidth (Mbps), inbound and outbound."""
    out = {}
    for d in ("inbound", "outbound"):
        xs = [v for _, v in tsmap(result(f"{DIR}/{w}__bw_{d}.json")).items()]
        out[d] = dict(mean=mean(xs), max=max(xs))
    return out


# --------------------------------------------------------------------- series
def mem_series(w: str) -> list[tuple[int, float]]:
    """`[(unix_seconds, gib_used)]` over the window."""
    tot = tsmap(result(f"{DIR}/{w}__memory_total.json"))
    av = tsmap(result(f"{DIR}/{w}__memory_available.json"))
    return [(t, (tot[t] - av[t]) / GiB) for t in sorted(t for t in tot if t in av)]


def cpu_series(w: str) -> list[tuple[int, float]]:
    """`[(unix_seconds_midpoint, util%)]` over the window."""
    res = result(f"{DIR}/{w}__cpu.json")
    modes = {r["metric"]["mode"]: {int(t): float(v) for t, v in r["values"]} for r in res}
    times = sorted(set.intersection(*[set(m) for m in modes.values()]))
    out = []
    for a, b in zip(times, times[1:]):
        d = {m: modes[m][b] - modes[m][a] for m in modes}
        tot = sum(d.values())
        if tot > 0 and b > a and all(v >= 0 for v in d.values()):
            out.append(((a + b) // 2, 100 * (1 - d.get("idle", 0) / tot)))
    return out


def disk_series(w: str) -> list[tuple[int, float]]:
    """`[(unix_seconds, gib_used)]` over the window (`size - free`)."""
    size = tsmap(result(f"{DIR}/{w}__filesystem_size.json"))
    free = tsmap(result(f"{DIR}/{w}__filesystem_free.json"))
    return [(t, (size[t] - free[t]) / GiB) for t in sorted(t for t in size if t in free)]


# --------------------------------------------- overlay series (aligned to a t0)
def mem_overlay(w: str, t0: float) -> pd.DataFrame:
    """Memory-used series as a frame of `hour` (since `t0`) and `mem` (GB)."""
    return pd.DataFrame([{"hour": (t - t0) / 3600, "mem": v} for t, v in mem_series(w)])


def cpu_overlay(w: str, t0: float) -> pd.DataFrame:
    """CPU-used series as a frame of `hour` (since `t0`) and `cpu` (%)."""
    return pd.DataFrame([{"hour": (t - t0) / 3600, "cpu": v} for t, v in cpu_series(w)])


def disk_overlay(w: str, t0: float) -> pd.DataFrame:
    """Disk-used series as a frame of `hour` (since `t0`) and `disk` (GB)."""
    return pd.DataFrame([{"hour": (t - t0) / 3600, "disk": v} for t, v in disk_series(w)])


def window_for(t0: float, span_h: float) -> str | None:
    """The window whose samples best overlap the capture's `[t0, t0+span]`.

    Lets the combined charts line DO data up with a parquet capture by clock
    time, without hard-coding which window goes with which capture.
    """
    best, best_ov = None, 0.0
    for f in glob.glob(f"{DIR}/*__memory_total.json"):
        w = os.path.basename(f).split("__")[0]
        try:
            ts = [int(t) for t, _ in result(f)[0]["values"]]
        except (IndexError, KeyError, ValueError):
            continue
        ov = max(0.0, min(max(ts), t0 + span_h * 3600) - max(min(ts), t0))
        if ov > best_ov:
            best, best_ov = w, ov
    return best
