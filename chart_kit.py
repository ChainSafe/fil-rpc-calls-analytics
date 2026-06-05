"""Shared chart toolkit for Forest.

Pure styling/data helpers plus the one timeline builder shared across the chart
scripts — this module renders nothing on its own. Two importers:

  * `mise-tasks/charts` (run via `mise run charts`) builds the parquet-only deck
    — reliability / batching / what-node-serves PNGs plus the latency-comparison
    SVGs — out of these primitives.
  * `mise-tasks/charts-do` reuses the styling helpers (`style`, `save`, colours,
    `per_flow`, `date_label`) and the `over_time_chart` builder, passing in
    DigitalOcean CPU / memory / disk frames to light up its extra panels.

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
RED, TEAL, AMBER = "#dc2626", "#0f766e", "#f59e0b"
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


def honest(before, after, flat=3.0):
    """(colour, label) for a lower-is-better metric, coloured honestly."""
    d = (after - before) / before * 100 if before else 0.0
    if abs(d) < flat:
        return FAINT, "≈"
    return (GREEN, f"−{abs(d):.0f}%") if d < 0 else (RED, f"+{d:.0f}%")


def date_label(path):
    """Human capture window from the data: 'May 25', 'May 25–26', 'May 12–14'."""
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


# ===== shared timeline builder: parquet demand/latency + optional DO resource panels
def over_time_chart(path, resources=None):
    """Stacked timeline panels sharing one clock: RPC demand, then (optionally)
    whole-server resource panels from DigitalOcean, then median & p95 response.

    Parquet-only by default. Pass `resources` — a list of dicts
    `{df, field, title, color, domain?}` where each `df` has an `hour` column +
    the `field` (e.g. from `do_metrics.cpu_overlay`, aligned to this capture's
    `t0`) — to insert resource panels. `mise-tasks/charts-do` passes CPU, memory
    and disk, each title carrying its avg/peak vs capacity (folds in the old
    resource-peak chart). `domain` pins a panel's y-scale (disk → full capacity,
    so its low/flat usage reads as headroom).
    """
    df = per_flow(path).sort("ts_start")
    t0 = df["ts_start"].min()
    df = df.with_columns(((pl.col("ts_start") - t0) / 3600).alias("hour"))
    df = df.with_columns((pl.col("hour") * 6).floor().alias("bin"))  # 10-min bins
    g = (df.group_by("bin").agg(
            pl.col("batch_size").sum().alias("calls"),   # RPC calls (a batch = its size)
            pl.col("duration_ms").median().alias("median"),
            pl.col("duration_ms").quantile(0.95).alias("p95"))
         .sort("bin").with_columns((pl.col("bin") / 6).alias("hour"),
                                   (pl.col("calls") / 600).alias("calls_s")))  # 10-min bin = 600s
    pdf = g.to_pandas()
    span = float(df["hour"].max())
    med_typ = float(pdf["median"].median())
    avg_cps = float(pdf["calls"].sum() / (span * 3600))

    # Stacked panels sharing the time axis. Each metric keeps its OWN y-scale so a
    # flat ~6 ms median isn't crushed by p95 spikes or a climbing CPU line.
    def panel(src, field, title, color, height, *, area=False, zero=True, bottom=False, domain=None):
        chart = alt.Chart(src)
        mark = (chart.mark_area(opacity=0.85, color=color, line={"color": color})
                if area else chart.mark_line(strokeWidth=2, color=color))
        yscale = alt.Scale(domain=domain) if domain else alt.Scale(zero=zero)
        return mark.encode(
            x=alt.X("hour:Q", scale=alt.Scale(nice=False, domain=[0, span]),
                    title="hours into capture" if bottom else None,
                    axis=alt.Axis(labels=bottom, ticks=bottom, grid=False)),
            y=alt.Y(f"{field}:Q", title=None, scale=yscale)
        ).properties(width=760, height=height, title=alt.TitleParams(
            text=title, anchor="start", fontSize=12.5, fontWeight=700, color=MUTED, dy=-2))

    # demand (parquet) → what it cost the server (DigitalOcean) → how fast it answered (parquet)
    panels = [panel(pdf, "calls_s", "RPC demand — calls (queries) / sec", GREEN, 105, area=True)]
    for r in (resources or []):
        d = r["df"]
        d = d[(d["hour"] >= 0) & (d["hour"] <= span)]
        panels.append(panel(d, r["field"], r["title"], r["color"], 88, domain=r.get("domain")))
    panels += [panel(pdf, "median", "typical response — median (ms)", BLUE, 78, zero=False),
               panel(pdf, "p95", "tail response — p95 (ms)", AMBER, 105, bottom=True)]
    chart = alt.vconcat(*panels, spacing=12)
    sub = (f"client demand, whole-server CPU / memory / disk, and response time — same {span:.0f}-hour "
           f"clock · ~{avg_cps:.0f} calls/sec at ~{med_typ:.0f} ms typical"
           if resources else
           f"sustained for {span:.0f} hours · Forest answered ~{avg_cps:.0f} RPC calls/sec, "
           f"the typical request stayed ~{med_typ:.0f} ms, and only the p95 tail spiked")
    return style(chart, "Forest under real load", sub)
