#!/usr/bin/env python3
"""Tests for pcap_to_parquet: synthetic HTTP/1.1 pcaps must convert to the same
schema as flows_to_parquet, covering keep-alive, batches, gzip, chunked, and
header-based IP banning."""
from __future__ import annotations

import gzip
import json

import dpkt
import pyarrow.parquet as pq

import pcap_to_parquet as p2p

PORT = 3456
CLIENT = b"\x0a\x00\x00\x02"   # 10.0.0.2 (proxy, client side of captured leg)
SERVER = b"\x0a\x00\x00\x01"   # 10.0.0.1 (gateway/forest)
TH_SYN = dpkt.tcp.TH_SYN
TH_ACK = dpkt.tcp.TH_ACK
TH_FIN = dpkt.tcp.TH_FIN


# ---- HTTP byte builders ----

def post(path, obj, xff=None):
    body = json.dumps(obj).encode()
    h = b"POST " + path + b" HTTP/1.1\r\nHost: rpc.example\r\nContent-Type: application/json\r\n"
    if xff:
        h += b"X-Forwarded-For: " + xff + b"\r\n"
    h += b"Content-Length: %d\r\n\r\n" % len(body)
    return h + body


def resp(obj, status=b"200 OK", gzip_body=False, chunked=False):
    body = json.dumps(obj).encode()
    h = b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
    if gzip_body:
        body = gzip.compress(body)
        h += b"Content-Encoding: gzip\r\n"
    if chunked:
        h += b"Transfer-Encoding: chunked\r\n\r\n"
        return h + (b"%x\r\n" % len(body)) + body + b"\r\n0\r\n\r\n"
    h += b"Content-Length: %d\r\n\r\n" % len(body)
    return h + body


# ---- pcap builder ----

def _pkt(src, dst, sport, dport, seq, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=0, off=5,
                       flags=flags, win=64240, data=payload)
    ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    return dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6,
                                  type=dpkt.ethernet.ETH_TYPE_IP, data=ip)


def write_pcap(path, connections):
    """connections: list of (cport, [req_bytes...], [resp_bytes...])."""
    pkts = []  # (ts, eth)
    t = 100.0
    for ci, (cport, reqs, resps) in enumerate(connections):
        c_isn = 1000 + ci * 100000
        s_isn = 5000 + ci * 100000
        # client SYN + server SYN-ACK (server's ISN must be anchored from SYN-ACK,
        # which carries SYN+ACK — regression guard for the empty-response bug)
        pkts.append((t, _pkt(CLIENT, SERVER, cport, PORT, c_isn, TH_SYN)))
        pkts.append((t, _pkt(SERVER, CLIENT, PORT, cport, s_isn, TH_SYN | TH_ACK)))
        t += 0.001
        seq = c_isn + 1
        for r in reqs:
            pkts.append((t, _pkt(CLIENT, SERVER, cport, PORT, seq, TH_ACK, r)))
            seq += len(r)
            t += 0.01
        seq = s_isn + 1   # response data starts after the SYN-ACK consumes one seq
        for r in resps:
            pkts.append((t, _pkt(SERVER, CLIENT, PORT, cport, seq, TH_ACK, r)))
            seq += len(r)
            t += 0.01
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for ts, eth in pkts:
            w.writepkt(eth, ts)


def convert(tmp_path, connections, ban=""):
    pcap = tmp_path / "c.pcap"
    write_pcap(pcap, connections)
    out = tmp_path / "c.parquet"
    banned = {x for x in ban.split(",") if x}
    p2p.convert_pcap(pcap, out, PORT, banned, compression="zstd")
    return pq.read_table(out).to_pylist()


def test_single_request_response(tmp_path):
    rows = convert(tmp_path, [(40001,
        [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": ["x"]})],
        [resp({"jsonrpc": "2.0", "id": 1, "result": {"v": 42}})])])
    assert len(rows) == 1
    r = rows[0]
    assert r["method"] == "eth_call" and r["batch_size"] == 1
    assert json.loads(r["result_json"]) == {"v": 42}
    assert r["http_status"] == 200 and r["path"] == "/rpc/v1"
    assert r["duration_ms"] is not None and r["duration_ms"] > 0


def test_keepalive_two_pairs(tmp_path):
    rows = convert(tmp_path, [(40002,
        [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": "a", "method": "getSlot", "params": []}),
         post(b"/rpc/v1", {"jsonrpc": "2.0", "id": "b", "method": "getBlock", "params": [9]})],
        [resp({"jsonrpc": "2.0", "id": "a", "result": 1}),
         resp({"jsonrpc": "2.0", "id": "b", "result": 2})])])
    by_method = {r["method"]: r for r in rows}
    assert set(by_method) == {"getSlot", "getBlock"}
    assert json.loads(by_method["getSlot"]["result_json"]) == 1
    assert json.loads(by_method["getBlock"]["result_json"]) == 2
    assert len({r["flow_id"] for r in rows}) == 2   # paired, distinct flows


def test_batch_request(tmp_path):
    rows = convert(tmp_path, [(40003,
        [post(b"/rpc/v1", [{"jsonrpc": "2.0", "id": 1, "method": "getBlock", "params": [1]},
                            {"jsonrpc": "2.0", "id": 2, "method": "getBlock", "params": [2]}])],
        [resp([{"jsonrpc": "2.0", "id": 1, "result": "A"},
               {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "boom"}}])])])
    assert len(rows) == 2
    assert all(r["batch_size"] == 2 for r in rows)
    byid = {r["rpc_id"]: r for r in rows}
    assert json.loads(byid["1"]["result_json"]) == "A"
    assert byid["2"]["error_code"] == -32000 and byid["2"]["error_message"] == "boom"


def test_gzip_response(tmp_path):
    rows = convert(tmp_path, [(40004,
        [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []})],
        [resp({"jsonrpc": "2.0", "id": 1, "result": "gz"}, gzip_body=True)])])
    assert len(rows) == 1 and json.loads(rows[0]["result_json"]) == "gz"


def test_chunked_response(tmp_path):
    rows = convert(tmp_path, [(40005,
        [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []})],
        [resp({"jsonrpc": "2.0", "id": 1, "result": "ch"}, chunked=True)])])
    assert len(rows) == 1 and json.loads(rows[0]["result_json"]) == "ch"


def test_merge_tar_zst(tmp_path):
    import tarfile

    import zstandard

    # two hourly pcaps, distinct methods so we can confirm both are merged
    p1 = tmp_path / "cap-01.pcap"
    p2 = tmp_path / "cap-02.pcap"
    write_pcap(p1, [(40010,
        [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "m_one", "params": []})],
        [resp({"jsonrpc": "2.0", "id": 1, "result": 1})])])
    write_pcap(p2, [(40011,
        [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "m_two", "params": []})],
        [resp({"jsonrpc": "2.0", "id": 1, "result": 2})])])

    archive = tmp_path / "caps.tar.zst"
    with open(archive, "wb") as fh:
        with zstandard.ZstdCompressor().stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|") as tar:
                tar.add(p1, arcname=p1.name)
                tar.add(p2, arcname=p2.name)

    out = tmp_path / "merged.parquet"
    written, flows, skipped, scrubbed, n_pcaps = p2p.convert_pcap(archive, out, PORT, set())
    rows = pq.read_table(out).to_pylist()

    assert n_pcaps == 2
    assert {r["method"] for r in rows} == {"m_one", "m_two"}
    # continuous, non-colliding flow_id across the merged files
    assert len({r["flow_id"] for r in rows}) == flows == 2


def _write_packets(path, packets):
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for ts, eth in packets:
            w.writepkt(eth, ts)


def test_cross_pcap_stitches_split_connection(tmp_path):
    # One keep-alive connection whose request is in pcap #1 and response in
    # pcap #2 (same 4-tuple, continuing seqs). Per-pcap reassembly would leave
    # the request unanswered; cross-pcap must stitch them and pair the response.
    cport, c_isn, s_isn = 40020, 1000, 5000
    req = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "split", "params": []})
    rsp = resp({"jsonrpc": "2.0", "id": 1, "result": "stitched"})

    p1 = tmp_path / "cap-01.pcap"
    _write_packets(p1, [
        (100.0, _pkt(CLIENT, SERVER, cport, PORT, c_isn, TH_SYN)),
        (100.0, _pkt(SERVER, CLIENT, PORT, cport, s_isn, TH_SYN | TH_ACK)),
        (100.1, _pkt(CLIENT, SERVER, cport, PORT, c_isn + 1, TH_ACK, req)),
    ])
    p2 = tmp_path / "cap-02.pcap"
    _write_packets(p2, [
        (100.2, _pkt(SERVER, CLIENT, PORT, cport, s_isn + 1, TH_ACK, rsp)),
    ])

    archive = tmp_path / "split.tar.zst"
    import tarfile

    import zstandard
    with open(archive, "wb") as fh:
        with zstandard.ZstdCompressor().stream_writer(fh) as zw:
            with tarfile.open(fileobj=zw, mode="w|") as tar:
                tar.add(p1, arcname=p1.name)
                tar.add(p2, arcname=p2.name)

    out = tmp_path / "split.parquet"
    p2p.convert_pcap(archive, out, PORT, set())
    rows = pq.read_table(out).to_pylist()

    assert len(rows) == 1
    assert rows[0]["method"] == "split"
    assert json.loads(rows[0]["result_json"]) == "stitched"   # response paired across files
    assert rows[0]["http_status"] == 200
    assert rows[0]["duration_ms"] is not None and rows[0]["duration_ms"] >= 0


def test_port_reuse_splits_connections(tmp_path):
    # Same 4-tuple reused: connection A (isn 2000) then a NEW connection B
    # (isn 9000) on the same client port. They must stay separate, each paired.
    cport = 40021
    reqA = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "aaa", "params": []})
    reqB = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "bbb", "params": []})
    rspA = resp({"jsonrpc": "2.0", "id": 1, "result": "A"})
    rspB = resp({"jsonrpc": "2.0", "id": 1, "result": "B"})
    pcap = tmp_path / "reuse.pcap"
    _write_packets(pcap, [
        (1.0, _pkt(CLIENT, SERVER, cport, PORT, 2000, TH_SYN)),
        (1.0, _pkt(SERVER, CLIENT, PORT, cport, 3000, TH_SYN | TH_ACK)),
        (1.1, _pkt(CLIENT, SERVER, cport, PORT, 2001, TH_ACK, reqA)),
        (1.2, _pkt(SERVER, CLIENT, PORT, cport, 3001, TH_ACK, rspA)),
        (1.3, _pkt(CLIENT, SERVER, cport, PORT, 2001 + len(reqA), TH_FIN | TH_ACK)),
        (1.3, _pkt(SERVER, CLIENT, PORT, cport, 3001 + len(rspA), TH_FIN | TH_ACK)),
        # reuse same client port for a brand-new connection
        (2.0, _pkt(CLIENT, SERVER, cport, PORT, 9000, TH_SYN)),
        (2.0, _pkt(SERVER, CLIENT, PORT, cport, 8000, TH_SYN | TH_ACK)),
        (2.1, _pkt(CLIENT, SERVER, cport, PORT, 9001, TH_ACK, reqB)),
        (2.2, _pkt(SERVER, CLIENT, PORT, cport, 8001, TH_ACK, rspB)),
    ])
    out = tmp_path / "reuse.parquet"
    p2p.convert_pcap(pcap, out, PORT, set())
    rows = pq.read_table(out).to_pylist()
    by_method = {r["method"]: r for r in rows}
    assert set(by_method) == {"aaa", "bbb"}
    assert json.loads(by_method["aaa"]["result_json"]) == "A"
    assert json.loads(by_method["bbb"]["result_json"]) == "B"


def test_pairing_skips_earlier_response_no_negative_latency():
    # A keep-alive stream captured mid-flight: the server side carries a leftover
    # response (t=50) that precedes the request (t=100), then the real reply
    # (t=101). Index pairing would match the request to the t=50 response and
    # produce a negative latency; time pairing must skip it and pair the t=101 one.
    from pcap_to_parquet import _HalfStream, rows_for_connection

    req = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "m", "params": []})
    r_early = resp({"jsonrpc": "2.0", "id": 1, "result": "early"})
    r_real = resp({"jsonrpc": "2.0", "id": 1, "result": "real"})

    c = _HalfStream(); c.add(1000, b"", 40.0, True); c.add(1001, req, 100.0, False)
    s = _HalfStream(); s.add(5000, b"", 40.0, True)
    s.add(5001, r_early, 50.0, False)
    s.add(5001 + len(r_early), r_real, 101.0, False)

    rows, nflows, _, _ = rows_for_connection(c, s, set(), 0)
    assert nflows == 1 and len(rows) == 1
    assert rows[0]["duration_ms"] >= 0
    assert json.loads(rows[0]["result_json"]) == "real"


def test_over_threshold_duration_is_nulled_response_dropped():
    # Two requests on one keep-alive. The first is answered promptly (0.5s); the
    # second's response only appears 99s later (its real reply wasn't captured and
    # time-pairing grabbed a far-future one). The implausible >60s duration must be
    # scrubbed: duration nulled and the suspect response dropped, but the request
    # row is still emitted so RPC counts stay accurate. The fast one is untouched.
    from pcap_to_parquet import _HalfStream, rows_for_connection

    req1 = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "fast", "params": []})
    req2 = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 2, "method": "slow", "params": []})
    rsp1 = resp({"jsonrpc": "2.0", "id": 1, "result": "ok"})
    rsp2 = resp({"jsonrpc": "2.0", "id": 2, "result": "late"})

    c = _HalfStream(); c.add(1000, b"", 40.0, True)
    c.add(1001, req1, 100.0, False)
    c.add(1001 + len(req1), req2, 101.0, False)
    s = _HalfStream(); s.add(5000, b"", 40.0, True)
    s.add(5001, rsp1, 100.5, False)
    s.add(5001 + len(rsp1), rsp2, 200.0, False)

    rows, nflows, skipped, scrubbed = rows_for_connection(c, s, set(), 0, 60_000)
    assert nflows == 2 and len(rows) == 2 and scrubbed == 1
    by_method = {r["method"]: r for r in rows}
    # fast call untouched
    assert by_method["fast"]["duration_ms"] is not None
    assert json.loads(by_method["fast"]["result_json"]) == "ok"
    assert by_method["fast"]["http_status"] == 200
    # slow call scrubbed: duration nulled, response dropped, but row kept
    assert by_method["slow"]["duration_ms"] is None
    assert by_method["slow"]["result_json"] is None
    assert by_method["slow"]["http_status"] is None


def test_threshold_disabled_keeps_long_duration():
    # max_duration_ms=0 disables scrubbing: even a 99s duration is kept as-is.
    from pcap_to_parquet import _HalfStream, rows_for_connection

    req = post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "slow", "params": []})
    rsp = resp({"jsonrpc": "2.0", "id": 1, "result": "late"})
    c = _HalfStream(); c.add(1000, b"", 40.0, True); c.add(1001, req, 100.0, False)
    s = _HalfStream(); s.add(5000, b"", 40.0, True); s.add(5001, rsp, 200.0, False)

    rows, nflows, skipped, scrubbed = rows_for_connection(c, s, set(), 0, 0)
    assert nflows == 1 and scrubbed == 0
    assert rows[0]["duration_ms"] is not None and rows[0]["duration_ms"] > 60_000
    assert json.loads(rows[0]["result_json"]) == "late"


def test_ban_by_xff(tmp_path):
    rows = convert(tmp_path, [
        (40006, [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "good", "params": []},
                      xff=b"10.0.0.50")],
                [resp({"jsonrpc": "2.0", "id": 1, "result": 1})]),
        (40007, [post(b"/rpc/v1", {"jsonrpc": "2.0", "id": 1, "method": "banned", "params": []},
                      xff=b"10.0.0.99")],
                [resp({"jsonrpc": "2.0", "id": 1, "result": 1})]),
    ], ban="10.0.0.99")
    methods = {r["method"] for r in rows}
    assert methods == {"good"}
