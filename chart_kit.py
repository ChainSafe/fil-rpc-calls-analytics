"""Shared chart toolkit for Forest.

Pure styling/data helpers — this module renders nothing on its own. Two importers:

  * `mise-tasks/charts` (run via `mise run charts`) builds the parquet-only deck
    — reliability / batching / what-node-serves PNGs plus the latency-comparison
    charts — out of these primitives.
  * `mise-tasks/charts-do` reuses the styling helpers (`style`, `save`, colours,
    `per_flow`, `date_label`) for its load-over-time overlay and resource
    head-to-head charts.

Date labels auto-derive from `ts_start`. Wide PNGs may need `sips -Z 1700 <file>`
to view.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import altair as alt
import polars as pl
import vl_convert as vlc

INK, MUTED, GRID = "#111827", "#6b7280", "#e5e7eb"
FAINT, GREEN, BLUE = "#9ca3af", "#16a34a", "#2563eb"
# RED is deliberately soft — it flags "worse" without screaming danger.
RED, TEAL, AMBER = "#f28b82", "#0f766e", "#f59e0b"
PURPLE = "#7c3aed"
LGREEN = "#86efac"   # light green = peak headroom (used by the resource charts)
STONE = "#78716c"    # neutral storage tone for the disk panel
FONT = "Helvetica Neue, Helvetica, Arial, sans-serif"


def human(n):
    n = float(n)
    for unit, div in (("M", 1e6), ("k", 1e3)):
        if abs(n) >= div:
            v = n / div
            return f"{v:.1f}{unit}" if v < 100 else f"{v:.0f}{unit}"
    return f"{n:.0f}"


def ms(x):
    return f"{x:.1f} ms" if x < 10 else f"{x:.0f} ms"


# ---- per-metric honest-colour policy ---------------------------------------
# Each metric decides what "better" means its OWN way, so colour is never a
# blanket up=good / down=good rule. These return a colour only — the caller
# writes its own label. GREEN = good · AMBER = borderline · RED = worse ·
# FAINT = ≈ (no real change). `flat` is the dead-band % under which a move
# counts as "no change". Pick the helper that matches the metric's semantics.
NEUTRAL = BLUE   # volume / descriptive: not a win or a loss, just a magnitude


def pct_change(before, after):
    return (after - before) / before * 100.0 if before else 0.0


def colour_lower_better(before, after, *, flat=3.0):
    """latency, error rate, …: green when it fell, red when it rose."""
    d = pct_change(before, after)
    return FAINT if abs(d) < flat else (GREEN if d < 0 else RED)


def colour_higher_better(before, after, *, flat=3.0):
    """throughput, reliability, calls served, …: green when it rose."""
    d = pct_change(before, after)
    return FAINT if abs(d) < flat else (GREEN if d > 0 else RED)


def colour_vs_load(before, after, load_pct, *, flat=3.0):
    """A cost that naturally grows with load (memory, CPU): a win only if it grew
    far slower than the load it absorbed. green = sub-linear (≤ half the load's
    growth), amber = sub-linear but close, red = tracked or outpaced the load.
    Flat-or-down under more load is always a win — and a low before-baseline can
    never fake a green, because the test is relative to the load, not absolute."""
    d = pct_change(before, after)
    if d <= flat:
        return GREEN
    ratio = d / load_pct if load_pct > 0 else float("inf")
    return GREEN if ratio <= 0.5 else (AMBER if ratio <= 1.0 else RED)


def node_legend(domain, colours, *, field="node_label"):
    """Node colour legend shared by the comparison charts. `domain` lists the
    node labels in DISPLAY order and `colours` the colour each one wears —
    the compared node its verdict colour, the baseline node grey — so display
    order and colour semantics stay independent. `field` is the data column
    holding the labels (agent + version), so the legend dots read
    "Forest v… ● · Lotus v… ●"."""
    return alt.Color(f"{field}:N", sort=domain,
                     scale=alt.Scale(domain=domain, range=colours),
                     legend=alt.Legend(title=None, orient="bottom"))


def date_label(path):
    """Human date window from the data: 'May 25', 'May 25–26', 'May 12–14'."""
    ts = pl.scan_parquet(path).select(pl.col("ts_start").min().alias("a"),
                                      pl.col("ts_start").max().alias("b")).collect()
    a = dt.datetime.fromtimestamp(ts["a"][0], dt.timezone.utc)
    b = dt.datetime.fromtimestamp(ts["b"][0], dt.timezone.utc)
    if (a.month, a.day) == (b.month, b.day):
        return f"{a:%b} {a.day}"
    if a.month == b.month:
        return f"{a:%b} {a.day}–{b.day}"
    return f"{a:%b %-d} – {b:%b %-d}"


def save(chart, path):
    Path(path).write_bytes(vlc.vegalite_to_png(chart.to_json(), scale=2))
    print("wrote", path)


def style(chart, title, subtitle, *, title_size=19, sub_size=12.5, sub_pad=6):
    return (chart.properties(title=alt.TitleParams(
                text=title, subtitle=subtitle, anchor="start", font=FONT,
                fontSize=title_size, fontWeight=700, color=INK,
                subtitleFontSize=sub_size, subtitleColor=MUTED, subtitlePadding=sub_pad))
            .configure(font=FONT, background="white").configure_view(stroke=None)
            .configure_axis(labelColor=INK, titleColor=MUTED, labelFontSize=12,
                            titleFontSize=12, gridColor=GRID, gridDash=[2, 3],
                            domainColor=GRID, tickColor=GRID)
            .configure_legend(labelColor=INK, titleColor=MUTED, labelFontSize=12))


def per_flow(path):
    """One row per HTTP request: its latency, start time, and call count.

    `batch_size` is constant within a flow, so `.first()` is the number of RPC
    calls that request carried — lets us count calls/sec as well as requests/sec.
    """
    return (pl.scan_parquet(path).filter(pl.col("duration_ms").is_not_null())
            .group_by("flow_id").agg(pl.col("duration_ms").first(),
                                     pl.col("ts_start").first(),
                                     pl.col("batch_size").first())
            .collect())
