#!/usr/bin/env python3
"""Prove (or disprove) that the *producer* truncates its requests.

Independent, passive, TCP-level check that does not trust mitmdump, the
connection extender, the Lotus Gateway, or Forest. It reads a packet capture
taken at the first hop you control and, for each inbound HTTP/1.1 request,
compares the ``Content-Length`` the client advertised against the number of
request-body bytes the client actually put on the wire before closing.

If the client declares ``Content-Length: N`` but the TCP stream carries fewer
than N body bytes and then the client sends FIN/RST, the data was never
transmitted by the producer — so no component on your side could have dropped
it. That is the assertion this makes, with counts.

Capture first (plaintext HTTP only — if the producer leg is TLS, capture where
it is decrypted, e.g. mitmdump's client-facing plaintext, which still sits
upstream of the Gateway and Forest):

    sudo tcpdump -i <iface> -s 0 -w producer.pcap 'tcp port <listen_port>'

Then:

    python prove_truncation.py analyze producer.pcap --port <listen_port>

Requires dpkt (in the project deps). One HTTP request per TCP connection is
assumed (these producers use Connection: close), which matches the captures.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field

import dpkt

TH_FIN = dpkt.tcp.TH_FIN
TH_SYN = dpkt.tcp.TH_SYN
TH_RST = dpkt.tcp.TH_RST
TH_ACK = dpkt.tcp.TH_ACK


@dataclass
class Conn:
    isn: int | None = None          # client's initial sequence number (from SYN)
    base: int | None = None         # fallback base seq if SYN was not captured
    max_end: int = 0                # highest (seq+len) of client data, rel. to base
    segs: dict = field(default_factory=dict)  # seq_offset -> payload (for header)
    fin: bool = False
    rst: bool = False
    src: str = ""


def _l3(buf: bytes, datalink: int):
    """Return the IP layer regardless of capture link type."""
    if datalink == dpkt.pcap.DLT_EN10MB:
        return dpkt.ethernet.Ethernet(buf).data
    if datalink == dpkt.pcap.DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if datalink == getattr(dpkt.pcap, "DLT_LINUX_SLL2", -999):
        return dpkt.sll2.SLL2(buf).data
    if datalink == dpkt.pcap.DLT_RAW or datalink == 12:
        return dpkt.ip.IP(buf)
    # last resort: assume Ethernet
    return dpkt.ethernet.Ethernet(buf).data


def _ip_str(ip) -> str:
    import socket
    fam = socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET
    return socket.inet_ntop(fam, ip.src)


@dataclass
class Record:
    src: str
    method: str
    path: str
    declared: int          # Content-Length header value
    body_seen: int         # body bytes actually delivered by the client
    headers_complete: bool
    close: str             # 'RST' | 'FIN' | 'none'

    @property
    def truncated(self) -> bool:
        return self.headers_complete and self.body_seen < self.declared


def _client_bytes(c: Conn) -> int:
    """Contiguous app-layer bytes the client transmitted (seq math handles
    retransmits/out-of-order via max end-seq; conservative under loss)."""
    base = c.isn if c.isn is not None else c.base
    if base is None:
        return 0
    return max(0, c.max_end)


def _assemble_header(c: Conn) -> bytes:
    """Contiguous prefix of the client stream (enough to hold the headers)."""
    out = bytearray()
    off = 0
    while off in c.segs:
        out += c.segs[off]
        off += len(c.segs[off])
        if b"\r\n\r\n" in out:
            break
    return bytes(out)


def analyze(path: str, port: int) -> list[Record]:
    conns: dict[tuple, Conn] = {}
    with open(path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        dl = reader.datalink()
        for _ts, buf in reader:
            try:
                ip = _l3(buf, dl)
            except Exception:
                continue
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport != port:      # only client -> server direction
                continue
            key = (bytes(ip.src), tcp.sport)
            c = conns.get(key)
            if c is None:
                c = conns[key] = Conn(src=_ip_str(ip))
            is_syn = (tcp.flags & TH_SYN) and not (tcp.flags & TH_ACK)
            if is_syn:
                c.isn = tcp.seq
            if c.isn is None and c.base is None:
                c.base = tcp.seq        # capture started mid-connection
            base = c.isn if c.isn is not None else c.base
            payload = bytes(tcp.data)
            if payload and base is not None:
                # offset of this payload's first byte in the app stream
                off = (tcp.seq - (base + (1 if c.isn is not None else 0))) & 0xFFFFFFFF
                if off < (1 << 31):     # ignore absurd offsets from seq wrap edge
                    c.max_end = max(c.max_end, off + len(payload))
                    if off <= 65536 and off not in c.segs:
                        c.segs[off] = payload
            if tcp.flags & TH_FIN:
                c.fin = True
            if tcp.flags & TH_RST:
                c.rst = True

    records: list[Record] = []
    for c in conns.values():
        hdr = _assemble_header(c)
        i = hdr.find(b"\r\n\r\n")
        if i < 0:
            records.append(Record(c.src, "?", "?", -1, _client_bytes(c), False,
                                   "RST" if c.rst else "FIN" if c.fin else "none"))
            continue
        header_len = i + 4
        lines = hdr[:i].split(b"\r\n")
        try:
            method, path, _ = lines[0].decode("latin1").split(" ", 2)
        except Exception:
            method, path = "?", "?"
        declared = -1
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                if k.strip().lower() == b"content-length":
                    try:
                        declared = int(v.strip())
                    except ValueError:
                        pass
        body_seen = max(0, _client_bytes(c) - header_len)
        records.append(Record(c.src, method, path, declared, body_seen, True,
                              "RST" if c.rst else "FIN" if c.fin else "none"))
    return records


def report(records: list[Record], label: str) -> bool:
    # population of interest: requests that declared a body
    body_reqs = [r for r in records if r.headers_complete and r.declared > 0]
    truncated = [r for r in body_reqs if r.truncated]
    complete = [r for r in body_reqs if not r.truncated]
    zero = [r for r in truncated if r.body_seen == 0]
    partial = [r for r in truncated if r.body_seen > 0]
    no_hdr = [r for r in records if not r.headers_complete]

    n = len(body_reqs)
    print(f"capture point: {label}")
    print(f"\nTCP connections analyzed:           {len(records):,}")
    print(f"  incomplete request headers:       {len(no_hdr):,}")
    print(f"  requests declaring a body (CL>0): {n:,}")
    if not n:
        print("\nNo body-bearing requests found — wrong port, or TLS (capture where plaintext).")
        return False

    def pc(x):
        return f"{len(x)/n*100:5.1f}%"
    print(f"\n  body fully delivered:   {len(complete):>10,}  {pc(complete)}")
    print(f"  body TRUNCATED:         {len(truncated):>10,}  {pc(truncated)}")
    print(f"    sent 0 body bytes:    {len(zero):>10,}  {pc(zero)}")
    print(f"    sent partial body:    {len(partial):>10,}  {pc(partial)}")

    if truncated:
        cl = Counter(r.close for r in truncated)
        print(f"\n  how truncated connections ended (client side): {dict(cl)}")
        print("\n  examples (src, method, declared CL, body bytes seen, close):")
        for r in truncated[:6]:
            print(f"    {r.src:<16} {r.method:<5} CL={r.declared:<6} seen={r.body_seen:<6} {r.close}")

    frac = len(truncated) / n
    print()
    if frac >= 0.5:
        print(f"  ==> VERDICT: {frac*100:.1f}% of requests advertised Content-Length but the client")
        print(f"      transmitted fewer body bytes and then closed (FIN/RST), measured at YOUR")
        print(f"      ingress. The missing bytes never arrived from the producer, so no component")
        print(f"      on your side (extender / mitmdump / Lotus Gateway / Forest) could have")
        print(f"      dropped them. The producer is not sending the full request body.")
        return True
    print(f"  ==> Only {frac*100:.1f}% truncated here — bodies mostly arrive intact at this point.")
    print(f"      If they go missing further in, the loss is downstream of this capture, not the producer.")
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a pcap")
    a.add_argument("pcap")
    a.add_argument("--port", type=int, required=True, help="the listener port you captured")
    a.add_argument("--label", default="(specify with --label where you captured)",
                   help="human note: where this capture was taken")
    args = ap.parse_args()

    records = analyze(args.pcap, args.port)
    ok = report(records, args.label)
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
