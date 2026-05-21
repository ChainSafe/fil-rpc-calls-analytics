#!/usr/bin/env python3
"""Convert a mitmproxy flow dump to per-JSON-RPC-call Parquet."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from mitmproxy import io as mitm_io


SCHEMA = pa.schema([
    ("flow_id", pa.int64()),
    ("position", pa.int32()),
    ("batch_size", pa.int32()),
    ("ts_start", pa.float64()),
    ("duration_ms", pa.float64()),
    ("http_status", pa.int32()),
    ("host", pa.string()),
    ("path", pa.string()),
    ("method", pa.string()),
    ("rpc_id", pa.string()),
    ("params_json", pa.string()),
    ("result_json", pa.string()),
    ("error_code", pa.int64()),
    ("error_message", pa.string()),
    ("error_data_json", pa.string()),
    ("flow_req_bytes", pa.int64()),
    ("flow_resp_bytes", pa.int64()),
])


def _process_flow(flow_id: int, flow) -> list[dict]:
    if not hasattr(flow, "request") or flow.request.method != "POST":
        return []

    req_text = flow.request.get_text() or ""
    resp_text = (flow.response.get_text() if flow.response else "") or ""

    try:
        req_obj = json.loads(req_text)
    except Exception:
        return []

    req_calls = req_obj if isinstance(req_obj, list) else [req_obj]
    req_calls = [c for c in req_calls if isinstance(c, dict)]
    if not req_calls:
        return []

    resp_items: list[dict] = []
    try:
        if resp_text:
            resp_obj = json.loads(resp_text)
            if isinstance(resp_obj, list):
                resp_items = [i for i in resp_obj if isinstance(i, dict)]
            elif isinstance(resp_obj, dict):
                resp_items = [resp_obj]
    except Exception:
        pass

    resp_by_id: dict = {}
    for r in resp_items:
        rid = r.get("id")
        if rid is not None:
            resp_by_id[rid] = r

    ts_start = flow.request.timestamp_start
    ts_end = flow.response.timestamp_end if flow.response else None
    duration_ms = (ts_end - ts_start) * 1000 if (ts_end and ts_start) else None
    http_status = flow.response.status_code if flow.response else None
    host = flow.request.host
    path = flow.request.path
    req_bytes = len(req_text)
    resp_bytes = len(resp_text)
    batch_size = len(req_calls)

    rows: list[dict] = []
    for pos, c in enumerate(req_calls):
        method = str(c.get("method", "?"))
        rid = c.get("id")
        params = c.get("params")
        params_json = json.dumps(params, separators=(",", ":")) if params is not None else None

        match = resp_by_id.get(rid) if rid is not None else None
        if match is None and pos < len(resp_items):
            match = resp_items[pos]

        result_json = None
        error_code = None
        error_message = None
        error_data_json = None
        if match is not None:
            if "result" in match:
                result_json = json.dumps(match["result"], separators=(",", ":"))
            err = match.get("error")
            if isinstance(err, dict):
                ec = err.get("code")
                try:
                    error_code = int(ec) if ec is not None else None
                except (TypeError, ValueError):
                    error_code = None
                em = err.get("message")
                error_message = str(em) if em is not None else None
                ed = err.get("data")
                error_data_json = json.dumps(ed, separators=(",", ":")) if ed is not None else None

        rows.append({
            "flow_id": flow_id,
            "position": pos,
            "batch_size": batch_size,
            "ts_start": float(ts_start) if ts_start else None,
            "duration_ms": float(duration_ms) if duration_ms is not None else None,
            "http_status": int(http_status) if http_status is not None else None,
            "host": host,
            "path": path,
            "method": method,
            "rpc_id": None if rid is None else str(rid),
            "params_json": params_json,
            "result_json": result_json,
            "error_code": error_code,
            "error_message": error_message,
            "error_data_json": error_data_json,
            "flow_req_bytes": req_bytes,
            "flow_resp_bytes": resp_bytes,
        })
    return rows


def _flush(writer: pq.ParquetWriter, buf: list[dict]) -> None:
    if not buf:
        return
    cols: dict[str, list] = {field.name: [] for field in SCHEMA}
    for r in buf:
        for k in cols:
            cols[k].append(r[k])
    writer.write_table(pa.table(cols, schema=SCHEMA))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help="mitmproxy flow dump (.mitm)")
    ap.add_argument("output", type=Path, help="output .parquet file")
    ap.add_argument("--compression", default="zstd", choices=["zstd", "snappy", "gzip", "none"])
    ap.add_argument("--batch", type=int, default=50_000, help="rows per Parquet row-group flush")
    args = ap.parse_args()

    compression = None if args.compression == "none" else args.compression

    flow_id = 0
    written = 0
    buf: list[dict] = []
    with args.input.open("rb") as f, pq.ParquetWriter(args.output, SCHEMA, compression=compression) as writer:
        for flow in mitm_io.FlowReader(f).stream():
            flow_id += 1
            buf.extend(_process_flow(flow_id, flow))
            if len(buf) >= args.batch:
                _flush(writer, buf)
                written += len(buf)
                buf.clear()
                if written % (args.batch * 4) == 0:
                    print(f"  {written:,} rows ({flow_id:,} flows)", file=sys.stderr)
        if buf:
            _flush(writer, buf)
            written += len(buf)

    print(f"done: {written:,} rows from {flow_id:,} flows -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
