"""Shared polars aggregations over a `calls*.parquet` capture.

Single source of truth for every analytics view. Both the table-printing tasks
(`compare`, `compare-batch`, `summary`, `latency`, `latency-batch`) and the
`charts` renderer call these helpers, so a chart can never disagree with the
table it came from.

Tasks live in `mise-tasks/`; they put the repo root on `sys.path` and
`import rpc_queries`.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.error
import urllib.request

import polars as pl

_LOTUS_VERSION_RE = re.compile(r'NodeBuildVersion string = "(v[^"]+)"')
_lotus_version: str | None = None

# Batch-size buckets used everywhere (singletons are handled separately).
BATCH_BUCKETS = ["2-10", "11-50", "51-99", "100+"]


def _batch_bucket_expr() -> pl.Expr:
    return (
        pl.when(pl.col("batch_size") <= 10).then(pl.lit("2-10"))
          .when(pl.col("batch_size") <= 50).then(pl.lit("11-50"))
          .when(pl.col("batch_size") <= 99).then(pl.lit("51-99"))
          .otherwise(pl.lit("100+"))
          .alias("bucket")
    )


# --------------------------------------------------------------- singletons
def singleton_per_method(path: str) -> pl.DataFrame:
    """Per-method latency stats over singleton flows (`batch_size == 1`)."""
    return (
        pl.scan_parquet(path)
          .filter(pl.col("batch_size") == 1)
          .group_by("method")
          .agg(
              pl.len().alias("n"),
              pl.col("duration_ms").mean().alias("mean"),
              pl.col("duration_ms").quantile(0.5, interpolation="linear").alias("p50"),
              pl.col("duration_ms").quantile(0.95, interpolation="linear").alias("p95"),
              pl.col("duration_ms").quantile(0.99, interpolation="linear").alias("p99"),
              pl.col("duration_ms").max().alias("max"),
          )
          .collect()
    )


def singleton_overall(path: str) -> dict[str, float]:
    """Method-agnostic latency over singleton flows (`batch_size == 1`).

    This is the honest "typical request" view for the business report: one HTTP
    request carrying one RPC call, so wall time == the cost the caller felt.
    Batches are summarised separately (their per-call cost is amortised).
    """
    return (
        pl.scan_parquet(path)
          .filter((pl.col("batch_size") == 1) & pl.col("duration_ms").is_not_null())
          .select(
              pl.len().alias("n"),
              pl.col("duration_ms").mean().alias("mean"),
              pl.col("duration_ms").quantile(0.5, interpolation="linear").alias("p50"),
              pl.col("duration_ms").quantile(0.95, interpolation="linear").alias("p95"),
          )
          .collect()
          .row(0, named=True)
    )


def top_singleton_methods(path: str, n: int) -> list[str]:
    """The `n` most-called singleton methods, most frequent first."""
    return (
        pl.scan_parquet(path)
          .filter(pl.col("batch_size") == 1)
          .group_by("method").agg(pl.len().alias("n"))
          .sort("n", descending=True).head(n)
          .collect()["method"].to_list()
    )


# --------------------------------------------------------------- batches
def batch_flows(path: str) -> pl.DataFrame:
    """One row per batched flow (`batch_size > 1`) with amortized cost + bucket.

    `duration_ms` is shared across all calls in a flow, so we collapse to the
    first row per `flow_id`.
    """
    return (
        pl.scan_parquet(path)
          .filter(pl.col("batch_size") > 1)
          .group_by("flow_id")
          .agg(pl.col("batch_size").first(), pl.col("duration_ms").first())
          .with_columns(
              (pl.col("duration_ms") / pl.col("batch_size")).alias("per_call_ms"),
              _batch_bucket_expr(),
          )
          .collect()
    )


def summarise_buckets(flows: pl.DataFrame, col: str) -> pl.DataFrame:
    """Per-bucket stats for `col` over an already-computed `batch_flows` frame."""
    return (
        flows.group_by("bucket")
             .agg(
                 pl.len().alias("flows"),
                 pl.col(col).mean().alias("mean"),
                 pl.col(col).quantile(0.5, interpolation="linear").alias("p50"),
                 pl.col(col).quantile(0.95, interpolation="linear").alias("p95"),
                 pl.col(col).quantile(0.99, interpolation="linear").alias("p99"),
             )
    )


# --------------------------------------------------------------- overall / throughput
def overall_latency(path: str) -> dict[str, dict[str, float]]:
    """Method-agnostic per-flow and per-call-amortized latency (avg/p50/p95/p99)."""
    df = pl.scan_parquet(path).filter(pl.col("duration_ms").is_not_null())
    flow = (
        df.unique(subset=["flow_id"]).select(
            pl.col("duration_ms").mean().alias("avg"),
            pl.col("duration_ms").quantile(0.5, interpolation="linear").alias("p50"),
            pl.col("duration_ms").quantile(0.95, interpolation="linear").alias("p95"),
            pl.col("duration_ms").quantile(0.99, interpolation="linear").alias("p99"),
        ).collect().row(0, named=True)
    )
    call = (
        df.with_columns((pl.col("duration_ms") / pl.col("batch_size")).alias("per_call_ms")).select(
            pl.col("per_call_ms").mean().alias("avg"),
            pl.col("per_call_ms").quantile(0.5, interpolation="linear").alias("p50"),
            pl.col("per_call_ms").quantile(0.95, interpolation="linear").alias("p95"),
            pl.col("per_call_ms").quantile(0.99, interpolation="linear").alias("p99"),
        ).collect().row(0, named=True)
    )
    return {"per-flow": flow, "per-call amortized": call}


# --------------------------------------------------------------- mix-normalized (reweight)
def _drop_excluded(lf: pl.LazyFrame, exclude: tuple[str, ...]) -> pl.LazyFrame:
    return lf.filter(~pl.col("method").is_in(exclude)) if exclude else lf


def per_flow_frame(path: str, exclude: tuple[str, ...] = ()) -> pl.DataFrame:
    """One row per flow: duration (`v`) and first call's method (for reweighting)."""
    return (
        _drop_excluded(pl.scan_parquet(path), exclude)
          .filter(pl.col("duration_ms").is_not_null())
          .group_by("flow_id")
          .agg(
              pl.col("duration_ms").first().alias("v"),
              pl.col("method").sort_by("position").first().alias("method"),
          )
          .collect()
    )


def per_call_frame(path: str, exclude: tuple[str, ...] = ()) -> pl.DataFrame:
    """One row per call: method and amortized duration (`v`) (for reweighting)."""
    return (
        _drop_excluded(pl.scan_parquet(path), exclude)
          .filter(pl.col("duration_ms").is_not_null())
          .select(
              pl.col("method"),
              (pl.col("duration_ms") / pl.col("batch_size")).alias("v"),
          )
          .collect()
    )


def reweighted_stats(df: pl.DataFrame, ref: dict) -> tuple:
    """Weighted (mean, p50, p95, p99) of df['v'] using shared method shares `ref`.

    Each row's weight = ref_share[method] / file_share[method], so the file's
    effective method mix becomes `ref`. Quantiles use a 'lower' weighted quantile."""
    n = df.height
    if n == 0:
        return (float("nan"),) * 4
    fs = {r["method"]: r["len"] / n for r in df.group_by("method").len().iter_rows(named=True)}
    w_map = {m: ref.get(m, 0.0) / fs[m] for m in fs}
    df = df.with_columns(pl.col("method").replace_strict(w_map, default=0.0).alias("w"))
    tot_w = df["w"].sum()
    mean = (df["w"] * df["v"]).sum() / tot_w
    s = df.sort("v")
    cw = s["w"].cum_sum()

    def wq(q: float) -> float:
        idx = (cw >= q * tot_w).arg_max()
        return s["v"][idx]

    return (mean, wq(0.5), wq(0.95), wq(0.99))


def ref_shares(a: pl.DataFrame, b: pl.DataFrame) -> dict:
    """Pooled method-share dict from two frames' `method` columns."""
    pooled = pl.concat([a.select("method"), b.select("method")])
    n = pooled.height
    return {r["method"]: r["len"] / n for r in pooled.group_by("method").len().iter_rows(named=True)}


def headline(path: str) -> dict:
    """Capture span, flow/call counts, and throughput (requests & calls per second)."""
    df = pl.scan_parquet(path)
    ts = df.select(
        pl.col("ts_start").min().alias("first"),
        pl.col("ts_start").max().alias("last"),
    ).collect()
    first, last = ts["first"][0], ts["last"][0]
    span = (last - first) if (first is not None and last is not None) else None
    flows = df.select(pl.col("flow_id").n_unique()).collect().item()
    calls = df.select(pl.len()).collect().item()
    return {
        "first": first,
        "last": last,
        "span_seconds": span,
        "flows": flows,
        "calls": calls,
        "req_per_s": (flows / span) if span else None,
        "calls_per_s": (calls / span) if span else None,
    }


# --------------------------------------------------------------- distribution / coverage
def batch_distribution(path: str) -> pl.DataFrame:
    """Flow + call counts per batch-size bucket, including singletons ('1')."""
    per_flow = (
        pl.scan_parquet(path).unique(subset=["flow_id"])
          .with_columns(
              pl.when(pl.col("batch_size") == 1).then(pl.lit("1"))
                .when(pl.col("batch_size") <= 10).then(pl.lit("2-10"))
                .when(pl.col("batch_size") <= 50).then(pl.lit("11-50"))
                .when(pl.col("batch_size") <= 99).then(pl.lit("51-99"))
                .otherwise(pl.lit("100+"))
                .alias("bucket")
          )
          .collect()
    )
    return (
        per_flow.group_by("bucket")
                .agg(pl.len().alias("flows"), pl.col("batch_size").sum().alias("calls"))
    )


def top_methods(path: str, n: int = 15) -> pl.DataFrame:
    return (
        pl.scan_parquet(path)
          .group_by("method")
          .agg(pl.len().alias("calls"), pl.col("flow_id").n_unique().alias("flows"))
          .sort("calls", descending=True).head(n)
          .collect()
    )


def error_codes(path: str, n: int = 10) -> pl.DataFrame:
    return (
        pl.scan_parquet(path)
          .filter(pl.col("error_code").is_not_null())
          .group_by("error_code").agg(pl.len().alias("calls"))
          .sort("calls", descending=True).head(n)
          .collect()
    )


def _namespace_expr() -> pl.Expr:
    """Map an RPC `method` to its namespace (eth, Filecoin, trace, F3, net, web3)."""
    return (
        pl.when(pl.col("method").str.starts_with("Filecoin.")).then(pl.lit("Filecoin"))
          .when(pl.col("method").str.starts_with("eth_")).then(pl.lit("eth"))
          .when(pl.col("method").str.starts_with("trace_")).then(pl.lit("trace"))
          .when(pl.col("method").str.starts_with("F3.")).then(pl.lit("F3"))
          .when(pl.col("method").str.starts_with("net_")).then(pl.lit("net"))
          .when(pl.col("method").str.starts_with("web3_")).then(pl.lit("web3"))
          .otherwise(pl.lit("other"))
          .alias("namespace")
    )


def namespace_coverage(path: str) -> pl.DataFrame:
    """Distinct methods + call volume grouped by RPC namespace.

    Answers "how broad is the API surface Forest is actually serving?".
    """
    return (
        pl.scan_parquet(path)
          .with_columns(_namespace_expr())
          .group_by("namespace")
          .agg(pl.col("method").n_unique().alias("methods"), pl.len().alias("calls"))
          .sort("calls", descending=True)
          .collect()
    )


def namespace_bytes(path: str) -> pl.DataFrame:
    """Response bytes served per namespace.

    `flow_resp_bytes` is per HTTP request (a whole batch shares one value), so we
    collapse to one row per flow and attribute it to the flow's first method's
    namespace. Batches are ~99% eth_call, so their (small) bytes land on `eth`,
    and the per-namespace total matches the headline GB.
    """
    return (
        pl.scan_parquet(path)
          .group_by("flow_id")
          .agg(pl.col("flow_resp_bytes").first(), pl.col("method").first())
          .with_columns(_namespace_expr())
          .group_by("namespace")
          .agg(pl.col("flow_resp_bytes").sum().alias("bytes"))
          .collect()
    )


def distinct_methods(path: str) -> int:
    return pl.scan_parquet(path).select(pl.col("method").n_unique()).collect().item()


def lotus_version_from_github() -> str:
    """`NodeBuildVersion` from filecoin-project/lotus on GitHub (master)."""
    global _lotus_version
    if _lotus_version is not None:
        return _lotus_version
    url = "https://raw.githubusercontent.com/filecoin-project/lotus/master/build/version.go"
    req = urllib.request.Request(url, headers={"User-Agent": "fil-rpc-calls-analytics"})
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode()
    m = _LOTUS_VERSION_RE.search(text)
    if not m:
        raise ValueError(f"NodeBuildVersion not found in {url}")
    _lotus_version = m.group(1)
    return _lotus_version


def node_identity(path: str) -> dict:
    """Identify the node behind a capture from the parquet data.

    Reads the latest `Filecoin.Version` / `web3_clientVersion` for agent,
    capture semver, and commit. Chart-facing `label` policy:

    - **Forest** — `Forest: {YYYY-MM-DD}-{commit[:7]}` from capture
    - **Lotus** — `Lotus: {version}` from GitHub master `build/version.go`
      (falls back to capture semver if GitHub is unreachable)
    """
    lf = pl.scan_parquet(path)
    agent = version = None

    # Agent: latest Filecoin.Version (always carries Agent). Version/commit: latest
    # response across Filecoin.Version and web3_clientVersion (web3 sometimes
    # lacks the "agent/" prefix, e.g. lotus returns bare "v1.36.1-dev+git.…").
    fc = (lf.filter((pl.col("method") == "Filecoin.Version") & pl.col("result_json").is_not_null())
            .select("result_json", "ts_start")
            .sort("ts_start", descending=True)
            .head(1)
            .collect())
    if len(fc):
        try:
            agent = json.loads(fc["result_json"][0]).get("Agent")
        except (ValueError, TypeError):
            pass

    r = (lf.filter(pl.col("method").is_in(["Filecoin.Version", "web3_clientVersion"])
                    & pl.col("result_json").is_not_null())
           .select("method", "result_json", "ts_start")
           .sort("ts_start", descending=True)
           .head(1)
           .collect())
    if len(r):
        method, raw = r["method"][0], r["result_json"][0]
        try:
            if method == "Filecoin.Version":
                v = json.loads(raw)
                agent = agent or v.get("Agent")
                version = v.get("Version")
            else:
                try:
                    s = json.loads(raw)
                except (ValueError, TypeError):
                    s = raw
                if isinstance(s, str) and "/" in s:
                    a, _, version = s.partition("/")
                    agent = agent or a
                elif isinstance(s, str):
                    version = s
        except (ValueError, TypeError):
            pass

    version = version or "unknown"
    commit = ""
    if "+git." in version:
        commit = version.partition("+git.")[2].split("+")[0]
    version = version.split("+")[0]
    if version[:1].isdigit():
        version = "v" + version
    agent_name = (agent or "node").capitalize()

    ts = lf.select(pl.col("ts_start").min()).collect().item()
    capture_date = (dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")
                    if ts is not None else "unknown")
    slug = (agent or "node").lower()
    forest_id = capture_date
    if commit:
        forest_id += f"-{commit[:7]}"

    if slug == "forest":
        label = f"Forest: {forest_id}"
    elif slug == "lotus":
        try:
            label = f"Lotus: {lotus_version_from_github()}"
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError) as e:
            print(f"warning: Lotus GitHub version lookup failed ({e}); using capture version",
                  file=sys.stderr)
            label = f"Lotus: {version}"
    else:
        label = f"{agent_name}: {version}"

    return {"agent": agent_name, "version": version, "commit": commit,
            "capture_date": capture_date, "tag": label, "label": label}
