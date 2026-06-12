#!/usr/bin/env python3
"""Tests for flows_to_parquet conversion: parallel workers and .zst input
must produce the same rows as the single-process .mitm path."""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest
import zstandard
from mitmproxy.io import FlowWriter
from mitmproxy.test import tflow

HERE = Path(__file__).parent
SCRIPT = HERE / "flows_to_parquet.py"


def _make_flow(req_obj, resp_obj, client_ip, *, gzip_req=False):
    f = tflow.tflow(resp=True)
    f.request.method = "POST"
    f.request.host = "rpc.example"
    f.request.path = "/"
    req_bytes = json.dumps(req_obj).encode()
    if gzip_req:
        f.request.headers["content-encoding"] = "gzip"
        f.request.raw_content = gzip.compress(req_bytes)
    else:
        f.request.content = req_bytes
    f.response.status_code = 200
    f.response.content = json.dumps(resp_obj).encode()
    f.client_conn.peername = (client_ip, 12345)
    return f


def _sample_flows():
    return [
        # singleton call with a result
        _make_flow(
            {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": ["acct"]},
            {"jsonrpc": "2.0", "id": 1, "result": {"value": 42}},
            "10.0.0.1",
        ),
        # gzip-encoded request body
        _make_flow(
            {"jsonrpc": "2.0", "id": 2, "method": "getSlot", "params": []},
            {"jsonrpc": "2.0", "id": 2, "result": 99},
            "10.0.0.2",
            gzip_req=True,
        ),
        # batch request -> multiple rows
        _make_flow(
            [
                {"jsonrpc": "2.0", "id": "a", "method": "getBlock", "params": [1]},
                {"jsonrpc": "2.0", "id": "b", "method": "getBlock", "params": [2]},
            ],
            [
                {"jsonrpc": "2.0", "id": "a", "result": {"blk": 1}},
                {"jsonrpc": "2.0", "id": "b", "error": {"code": -32000, "message": "boom"}},
            ],
            "10.0.0.3",
        ),
        # flow from a banned IP (should be excluded when --ban-ips given)
        _make_flow(
            {"jsonrpc": "2.0", "id": 3, "method": "getHealth", "params": []},
            {"jsonrpc": "2.0", "id": 3, "result": "ok"},
            "192.168.1.3",
        ),
    ]


def _write_mitm(path: Path):
    with path.open("wb") as fh:
        w = FlowWriter(fh)
        for f in _sample_flows():
            w.add(f)


def _rows(parquet: Path):
    t = pq.read_table(parquet)
    rows = t.to_pylist()
    # order-independent comparison: sort by a stable key
    rows.sort(key=lambda r: (r["method"], str(r["rpc_id"]), r["position"]))
    return rows


def _convert(input_path: Path, output: Path, *extra):
    subprocess.run(
        [sys.executable, str(SCRIPT), str(input_path), str(output), *extra],
        check=True,
        cwd=HERE,
    )


@pytest.fixture
def mitm(tmp_path):
    p = tmp_path / "flows-test.mitm"
    _write_mitm(p)
    return p


def test_single_process_baseline(mitm, tmp_path):
    out = tmp_path / "calls.parquet"
    _convert(mitm, out, "--jobs", "1")
    rows = _rows(out)
    methods = sorted(r["method"] for r in rows)
    # 1 + 1 + 2 (batch) + 1 banned = 5 rows when nothing banned
    assert methods == ["getBalance", "getBlock", "getBlock", "getHealth", "getSlot"]
    bal = next(r for r in rows if r["method"] == "getBalance")
    assert json.loads(bal["result_json"]) == {"value": 42}
    err = next(r for r in rows if r["error_code"] is not None)
    assert err["error_code"] == -32000 and err["error_message"] == "boom"


def test_parallel_matches_single(mitm, tmp_path):
    out1 = tmp_path / "j1.parquet"
    out4 = tmp_path / "j4.parquet"
    _convert(mitm, out1, "--jobs", "1")
    _convert(mitm, out4, "--jobs", "4", "--chunk", "1")
    assert _rows(out1) == _rows(out4)


def test_zst_input_matches_mitm(mitm, tmp_path):
    zst = tmp_path / "flows-test.mitm.zst"
    data = mitm.read_bytes()
    zst.write_bytes(zstandard.ZstdCompressor().compress(data))

    out_mitm = tmp_path / "from_mitm.parquet"
    out_zst = tmp_path / "from_zst.parquet"
    _convert(mitm, out_mitm, "--jobs", "4")
    _convert(zst, out_zst, "--jobs", "4")
    assert _rows(out_mitm) == _rows(out_zst)


def test_ban_ips_excludes_flow(mitm, tmp_path):
    out = tmp_path / "banned.parquet"
    _convert(mitm, out, "--jobs", "4", "--ban-ips", "192.168.1.3")
    methods = sorted(r["method"] for r in _rows(out))
    assert "getHealth" not in methods
    assert methods == ["getBalance", "getBlock", "getBlock", "getSlot"]


def _make_aborted_flow(client_ip="10.0.0.9"):
    """A fire-and-forget POST: declares a Content-Length but the body never
    arrived and there's no response (resp=False) — an expected abort."""
    f = tflow.tflow(resp=False)
    f.request.method = "POST"
    f.request.path = "/rpc/v1"
    f.request.headers["content-type"] = "application/json"
    f.request.headers["content-length"] = "66"
    f.request.raw_content = b""
    f.client_conn.peername = (client_ip, 12345)
    return f


def _make_capture_gap_flow(client_ip="10.0.0.8"):
    """A POST recorded as a complete flow (response present, no error) but with
    an empty request body — the signature of a real capture/streaming gap."""
    f = tflow.tflow(resp=True)
    f.request.method = "POST"
    f.request.path = "/rpc/v1"
    f.request.headers["content-type"] = "application/json"
    f.request.headers["content-length"] = "66"
    f.request.raw_content = b""
    f.client_conn.peername = (client_ip, 12345)
    return f


def test_healthcheck_classifies_delivery(tmp_path):
    import io as _io
    from collections import Counter

    import flows_healthcheck as hc
    from flows_to_parquet import _frame

    # 4 delivered RPC flows + 3 aborted + 1 capture-gap
    flows = (_sample_flows()
             + [_make_aborted_flow() for _ in range(3)]
             + [_make_capture_gap_flow()])
    buf = _io.BytesIO()
    w = FlowWriter(buf)
    for f in flows:
        w.add(f)
    buf.seek(0)

    chunk = list(enumerate(_frame(buf)))
    totals: Counter = hc._classify_chunk(chunk)

    assert totals["class", "delivered"] == 4
    assert totals["class", "aborted"] == 3
    assert totals["class", "capture_gap"] == 1
