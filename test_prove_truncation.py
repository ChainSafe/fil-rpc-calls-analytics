#!/usr/bin/env python3
"""Tests for prove_truncation: a synthetic pcap with one complete request and
one truncated (producer closed before sending the body) must be classified
correctly."""
from __future__ import annotations

from pathlib import Path

import dpkt
import pytest

import prove_truncation as pt

PORT = 1234
SRV = b"\x0a\x00\x00\x01"  # 10.0.0.1 (server) — private, per project rule


def _pkt(src, sport, seq, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=PORT, seq=seq, ack=0,
                       off=5, flags=flags, win=64240, data=payload)
    ip = dpkt.ip.IP(src=src, dst=SRV, p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    return dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6,
                                  type=dpkt.ethernet.ETH_TYPE_IP, data=ip)


def _req(content_length, body=b""):
    return (b"POST /rpc/v1 HTTP/1.1\r\nHost: rpc.example\r\n"
            b"Content-Length: %d\r\n\r\n" % content_length) + body


def _write_pcap(path: Path, flows):
    with path.open("wb") as fh:
        w = dpkt.pcap.Writer(fh)
        ts = 0.0
        for eth in flows:
            w.writepkt(eth, ts)
            ts += 0.001


def test_complete_vs_truncated(tmp_path):
    src_ok = b"\x0a\x00\x00\x02"   # 10.0.0.2
    src_bad = b"\x0a\x00\x00\x03"  # 10.0.0.3

    body = b"hello"  # 5 bytes
    full = _req(5, body)
    headers_only = _req(5)  # declares CL=5 but sends no body

    flows = [
        # complete flow: SYN, full request, FIN
        _pkt(src_ok, 40001, 1000, pt.TH_SYN),
        _pkt(src_ok, 40001, 1001, pt.TH_ACK, full),
        _pkt(src_ok, 40001, 1001 + len(full), pt.TH_FIN | pt.TH_ACK),
        # truncated flow: SYN, headers only, RST (producer closed early)
        _pkt(src_bad, 40002, 2000, pt.TH_SYN),
        _pkt(src_bad, 40002, 2001, pt.TH_ACK, headers_only),
        _pkt(src_bad, 40002, 2001 + len(headers_only), pt.TH_RST | pt.TH_ACK),
    ]
    pcap = tmp_path / "t.pcap"
    _write_pcap(pcap, flows)

    recs = {r.src: r for r in pt.analyze(str(pcap), PORT)}
    assert set(recs) == {"10.0.0.2", "10.0.0.3"}

    ok = recs["10.0.0.2"]
    assert ok.declared == 5 and ok.body_seen == 5 and not ok.truncated

    bad = recs["10.0.0.3"]
    assert bad.declared == 5 and bad.body_seen == 0
    assert bad.truncated and bad.close == "RST"


def test_partial_body_truncation(tmp_path):
    src = b"\x0a\x00\x00\x04"
    partial = _req(10, b"abc")  # declares 10, sends 3
    flows = [
        _pkt(src, 41000, 5000, pt.TH_SYN),
        _pkt(src, 41000, 5001, pt.TH_ACK, partial),
        _pkt(src, 41000, 5001 + len(partial), pt.TH_RST | pt.TH_ACK),
    ]
    pcap = tmp_path / "p.pcap"
    _write_pcap(pcap, flows)
    (rec,) = pt.analyze(str(pcap), PORT)
    assert rec.declared == 10 and rec.body_seen == 3 and rec.truncated
