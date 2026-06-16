"""Shared polars aggregations over a `calls*.parquet` capture.

Single source of truth for every analytics view. Both the table-printing tasks
(`compare`, `compare-batch`, `summary`, `latency`, `latency-batch`) and the
`charts` renderer call these helpers, so a chart can never disagree with the
table it came from.

Tasks live in `mise-tasks/`; they put the repo root on `sys.path` and
`import rpc_queries`.
"""

from __future__ import annotations

import json

import polars as pl

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


def node_identity(path: str) -> dict:
    """Identify the node behind a capture (agent + version + commit) from the data.

    Both nodes answer `Filecoin.Version` with `{Agent, Version}`, where `Version`
    carries the semver plus build metadata after a "+" — the git commit as
    "…+git.<sha>", e.g. "0.33.6+git.8602bfd8". We keep the semver, lift the commit
    out separately, and drop the rest. Falls back to `web3_clientVersion`
    ("forest/0.33.6+git.…"). Returns `{agent, version, commit, label}` so a chart can
    self-label exactly which builds it compares — no hand-typing.
    """
    lf = pl.scan_parquet(path)
    agent = version = None

    # Prefer Filecoin.Version: a clean object carrying Agent + Version.
    r = (lf.filter((pl.col("method") == "Filecoin.Version") & pl.col("result_json").is_not_null())
           .select("result_json").head(1).collect())
    if len(r):
        try:
            v = json.loads(r["result_json"][0])
            agent, version = v.get("Agent"), v.get("Version")
        except (ValueError, TypeError):
            pass

    # Fall back to web3_clientVersion: a JSON string like "forest/0.33.6+git.<sha>".
    if not version:
        r = (lf.filter((pl.col("method") == "web3_clientVersion") & pl.col("result_json").is_not_null())
               .select("result_json").head(1).collect())
        if len(r) and r["result_json"][0]:
            try:
                s = json.loads(r["result_json"][0])
            except (ValueError, TypeError):
                s = r["result_json"][0]
            agent, _, version = s.partition("/") if "/" in s else (agent, "", s)

    version = version or "unknown"
    # Lift the git commit out of the build metadata, then keep the semver only:
    # everything from the first "+" is build metadata (a network tag plus the git
    # commit, "…+git.<sha>") — drop it so the label is a clean, neutral version tag.
    commit = ""
    if "+git." in version:
        commit = version.partition("+git.")[2].split("+")[0]
    version = version.split("+")[0]
    if version[:1].isdigit():          # normalise to a v-tag: forest "0.33.6" -> "v0.33.6"
        version = "v" + version
    agent_name = (agent or "node").capitalize()
    # `commit` stays in the dict (for disambiguating same-agent builds) but is
    # intentionally NOT in the chart-facing `label` — charts show agent + version only.
    return {"agent": agent_name, "version": version, "commit": commit,
            "label": f"{agent_name} {version}"}
