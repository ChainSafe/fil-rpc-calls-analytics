#!/usr/bin/env python3
"""Convert a mitmproxy flow dump to per-JSON-RPC-call Parquet.

The dump is read sequentially by a single producer (mitmproxy's FlowReader
is inherently sequential), but the expensive per-flow work — body
decompression and JSON parse/re-serialize — is fanned out across a process
pool. Reading can also stream straight from a zstandard-compressed dump
(``*.mitm.zst``) so the giant uncompressed ``.mitm`` never has to exist.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import sys
import zlib
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from mitmproxy import flow as mitm_flow
from mitmproxy.io import compat as mitm_compat
from mitmproxy.io import tnetstring


try:
    import brotli
except ImportError:
    brotli = None
try:
    import zstandard
except ImportError:
    zstandard = None


def _decode(raw: bytes, ce: str) -> str:
    """Decode an HTTP body to UTF-8 text from its raw (on-wire) bytes and
    declared Content-Encoding, tolerating mislabeled encodings and handling
    brotli/zstd which mitmproxy's bundled interpreter may not have. Mirrors
    the fallback path of the original get_text() handling, but works on plain
    bytes so it can run in a worker process without the flow object."""
    if not raw:
        return ""
    ce = (ce or "").lower().strip()
    try:
        if ce == "gzip" or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        elif ce == "deflate" or raw[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            raw = zlib.decompress(raw)
        elif ce == "br" and brotli is not None:
            raw = brotli.decompress(raw)
        elif ce == "zstd" and zstandard is not None:
            raw = zstandard.ZstdDecompressor().decompress(raw)
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")


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


def _client_ip(flow) -> str:
    """Originating IP per X-Forwarded-For/X-Real-IP, else direct TCP peer."""
    xff = flow.request.headers.get("X-Forwarded-For", "") if hasattr(flow, "request") else ""
    if xff:
        return xff.split(",")[0].strip()
    xri = flow.request.headers.get("X-Real-IP", "") if hasattr(flow, "request") else ""
    if xri:
        return xri.strip()
    if getattr(flow, "client_conn", None) and flow.client_conn.peername:
        return flow.client_conn.peername[0]
    return ""


def _deserialize(blob: bytes):
    """Reconstruct a mitmproxy flow from one raw tnetstring frame. This is the
    expensive step (~99% of read cost) that we deliberately run in workers."""
    loaded = tnetstring.load(io.BytesIO(blob))
    return mitm_flow.Flow.from_state(mitm_compat.migrate_flow(loaded))


def _process_flow(flow_id: int, flow) -> list[dict]:
    if not hasattr(flow, "request") or flow.request.method != "POST":
        return []

    req = flow.request
    resp = flow.response
    req_text = _decode(req.raw_content or b"", req.headers.get("content-encoding", ""))
    resp_text = _decode(
        (resp.raw_content or b"") if resp else b"",
        resp.headers.get("content-encoding", "") if resp else "",
    )
    return build_rows(
        flow_id, req.host, req.path, req.timestamp_start,
        resp.timestamp_end if resp else None,
        resp.status_code if resp else None,
        req_text, resp_text,
    )


def build_rows(flow_id: int, host: str, path: str, ts_start, ts_end, http_status,
               req_text: str, resp_text: str) -> list[dict]:
    """Turn one HTTP request/response (already decoded to text) into per-JSON-RPC-call
    rows matching SCHEMA. Shared by the mitm-dump and pcap conversion paths so both
    produce byte-identical columns."""
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

    duration_ms = (ts_end - ts_start) * 1000 if (ts_end and ts_start) else None
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


# Banned IPs are set once per worker process to avoid shipping the set with
# every chunk.
_BANNED: set[str] = set()


def _init_worker(banned_ips: set[str]) -> None:
    global _BANNED
    _BANNED = banned_ips


def _process_chunk(chunk: list) -> tuple[list[dict], int]:
    """Worker entry point: deserialize and process a batch of raw flow blobs.
    Each chunk item is (flow_id, blob). Returns (rows, banned_skipped)."""
    out: list[dict] = []
    skipped = 0
    for flow_id, blob in chunk:
        flow = _deserialize(blob)
        if not hasattr(flow, "request") or flow.request.method != "POST":
            continue
        if _BANNED and _client_ip(flow) in _BANNED:
            skipped += 1
            continue
        out.extend(_process_flow(flow_id, flow))
    return out, skipped


def _open_input(path: Path):
    """Return a binary stream of mitmproxy flow data, transparently
    stream-decompressing ``*.zst`` (by suffix or magic bytes)."""
    f = path.open("rb")
    is_zst = path.suffix == ".zst" or path.name.endswith(".mitm.zst")
    if not is_zst:
        magic = f.read(4)
        f.seek(0)
        is_zst = magic == b"\x28\xb5\x2f\xfd"
    if is_zst:
        if zstandard is None:
            f.close()
            raise SystemExit("zstandard is required to read .zst input")
        # Wrap in BufferedReader so the stream exposes peek(): mitmproxy's
        # FlowReader peeks the first bytes to detect the format and the raw
        # zstd reader supports neither peek nor seeking backwards.
        return io.BufferedReader(zstandard.ZstdDecompressor().stream_reader(f))
    return f


def _frame(stream):
    """Yield raw per-flow tnetstring frames without parsing them. This is the
    only work the reader process does; the costly deserialization runs in
    workers. tnetstring framing is ``<ascii-len>:<payload><type-byte>``."""
    read = stream.read
    while True:
        digits = bytearray()
        c = read(1)
        if not c:
            return
        while c != b":":
            digits += c
            c = read(1)
        size = int(digits)
        payload = read(size)
        type_byte = read(1)
        yield bytes(digits) + b":" + payload + type_byte


def _chunks(stream, size: int):
    """Group (flow_id, blob) work units. flow_id increments over every flow
    read so numbering is stable regardless of later filtering. The running
    flow count is exposed as an attribute for accurate mid-run progress."""
    buf = []
    flow_id = 0
    for blob in _frame(stream):
        flow_id += 1
        _chunks.last_flow_id = flow_id
        buf.append((flow_id, blob))
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


_chunks.last_flow_id = 0


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
    ap.add_argument("input", type=Path, help="mitmproxy flow dump (.mitm or .mitm.zst)")
    ap.add_argument("output", type=Path, help="output .parquet file")
    ap.add_argument("--compression", default="zstd", choices=["zstd", "snappy", "gzip", "none"])
    ap.add_argument("--batch", type=int, default=50_000, help="rows per Parquet row-group flush")
    ap.add_argument("--ban-ips", default="", help="comma-separated client IPs to exclude")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2),
                    help="parallel worker processes (1 = single process)")
    ap.add_argument("--chunk", type=int, default=200,
                    help="flows per work unit handed to a worker")
    args = ap.parse_args()
    banned_ips = {ip.strip() for ip in args.ban_ips.split(",") if ip.strip()}

    compression = None if args.compression == "none" else args.compression

    written = 0
    skipped = 0
    buf: list[dict] = []
    stream = _open_input(args.input)
    try:
        with pq.ParquetWriter(args.output, SCHEMA, compression=compression) as writer:
            chunk_gen = _chunks(stream, max(1, args.chunk))

            def drain(result: tuple[list[dict], int]) -> None:
                nonlocal written, skipped
                rows, banned = result
                skipped += banned
                buf.extend(rows)
                if len(buf) >= args.batch:
                    _flush(writer, buf)
                    written += len(buf)
                    buf.clear()
                    if written % (args.batch * 4) == 0:
                        print(f"  {written:,} rows ({_chunks.last_flow_id:,} flows)", file=sys.stderr)

            if args.jobs <= 1:
                _init_worker(banned_ips)
                for chunk in chunk_gen:
                    drain(_process_chunk(chunk))
            else:
                # Bounded sliding window of in-flight futures keeps memory flat
                # on huge inputs (a naive pool.imap would slurp the whole stream).
                max_inflight = args.jobs * 3
                with ProcessPoolExecutor(
                    max_workers=args.jobs,
                    initializer=_init_worker,
                    initargs=(banned_ips,),
                ) as ex:
                    futures = deque()
                    for chunk in chunk_gen:
                        futures.append(ex.submit(_process_chunk, chunk))
                        if len(futures) >= max_inflight:
                            drain(futures.popleft().result())
                    while futures:
                        drain(futures.popleft().result())

            if buf:
                _flush(writer, buf)
                written += len(buf)
    finally:
        stream.close()

    flows = _chunks.last_flow_id
    extra = f" (skipped {skipped:,} banned-IP flows)" if banned_ips else ""
    print(f"done: {written:,} rows from {flows:,} flows{extra} -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
