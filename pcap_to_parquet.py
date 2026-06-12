#!/usr/bin/env python3
"""Convert a tcpdump pcap of HTTP/1.1 JSON-RPC traffic to per-call Parquet.

Companion to flows_to_parquet.py for the capture pipeline where nginx serves the
producers and tcpdump passively records an internal leg (nginx<->Gateway by
default, or Gateway<->Forest). Because the recorder is passive it can never drop
or alter traffic, and because the captured leg is between well-behaved HTTP
clients/servers every request has its matching response.

It reassembles each TCP connection (both directions, sequence-ordered), parses
HTTP/1.1 (keep-alive, Content-Length and chunked bodies, gzip/deflate/br/zstd
content-encoding), pairs requests with responses in order, optionally drops
banned client IPs (from X-Forwarded-For / X-Real-IP), and emits the SAME schema
as flows_to_parquet via its shared build_rows().

The input may be a single ``.pcap`` or a ``.tar.zst`` archive of (hourly) pcaps;
the archive is streamed-decompressed, every ``*.pcap`` member is converted in
chronological (sorted-name) order, and they are merged into one Parquet with a
continuous global flow_id so flows never collide across files.

Usage:
    pcap_to_parquet.py <in.pcap|in.tar.zst> <out.parquet> --port <server_port> \\
        [--ban-ips ip1,ip2] [--compression zstd|snappy|gzip|none]

Requires dpkt + zstandard (in the project deps).
"""
from __future__ import annotations

import argparse
import tarfile
import tempfile
from pathlib import Path

import dpkt
import pyarrow as pa
import pyarrow.parquet as pq

try:
    import zstandard
except ImportError:
    zstandard = None

from flows_to_parquet import SCHEMA, _decode, build_rows


# ---------------------------------------------------------------------------
# TCP reassembly
# ---------------------------------------------------------------------------

def _l3(buf: bytes, datalink: int):
    if datalink == dpkt.pcap.DLT_EN10MB:
        return dpkt.ethernet.Ethernet(buf).data
    if datalink == dpkt.pcap.DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if datalink == getattr(dpkt.pcap, "DLT_LINUX_SLL2", -999):
        return dpkt.sll2.SLL2(buf).data
    if datalink in (dpkt.pcap.DLT_RAW, 12, 14):
        return dpkt.ip.IP(buf)
    return dpkt.ethernet.Ethernet(buf).data


class _HalfStream:
    """One direction of a TCP connection: reassembles the byte stream and keeps
    a (stream_offset -> timestamp) index so we can time individual messages."""

    def __init__(self):
        self.isn = None
        self.base = None
        self.segs: dict[int, bytes] = {}     # offset -> payload
        self.ts_index: list[tuple[int, float]] = []  # (offset, ts) sorted by offset

    def add(self, seq: int, payload: bytes, ts: float, syn: bool):
        if syn:
            self.isn = seq
        if self.isn is None and self.base is None:
            self.base = seq
        base = self.isn if self.isn is not None else self.base
        if base is None or not payload:
            return
        off = (seq - (base + (1 if self.isn is not None else 0))) & 0xFFFFFFFF
        if off >= (1 << 31):
            return
        if off not in self.segs:
            self.segs[off] = payload
            self.ts_index.append((off, ts))

    def assemble(self) -> bytes:
        out = bytearray()
        off = 0
        while off in self.segs:
            out += self.segs[off]
            off += len(self.segs[off])
        return bytes(out)

    def ts_at(self, offset: int) -> float | None:
        """Timestamp of the segment covering this stream offset."""
        best = None
        for off, ts in sorted(self.ts_index):
            if off <= offset:
                best = ts
            else:
                break
        return best


def _read_tcp(path: str, port: int):
    """Yield (ts, ip, tcp, to_server) for TCP packets touching `port` in a pcap."""
    with open(path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        dl = reader.datalink()
        for ts, buf in reader:
            try:
                ip = _l3(buf, dl)
            except Exception:
                continue
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            to_server = tcp.dport == port
            if not (to_server or tcp.sport == port):
                continue
            yield ts, ip, tcp, to_server


def reassemble_many(pcap_paths, port: int):
    """Reassemble TCP connections across multiple pcaps (processed in the given,
    i.e. chronological, order) and yield (client_stream, server_stream) per
    connection. 'server' is the side whose port == the captured listen port.

    Connections are tracked across pcap boundaries so a keep-alive connection
    split over several hourly files is stitched into one stream (this is what
    prevents a request being mis-paired to a response from another file). Two
    points of care:
      * A reused 4-tuple (ephemeral client port re-dialed later) is split into a
        new connection at each fresh client SYN.
      * Connections are finalized and freed when they close (both-FIN, or RST),
        so memory is bounded by concurrently-open connections, not the archive."""
    conns: dict = {}
    for path in pcap_paths:
        for ts, ip, tcp, to_server in _read_tcp(str(path), port):
            key = frozenset(((bytes(ip.src), tcp.sport), (bytes(ip.dst), tcp.dport)))
            c = conns.get(key)
            client_syn = (to_server and (tcp.flags & dpkt.tcp.TH_SYN)
                          and not (tcp.flags & dpkt.tcp.TH_ACK))
            if client_syn and c is not None and c["client"].isn != tcp.seq:
                # fresh connection on a reused 4-tuple — finalize the old one
                yield c["client"], c["server"]
                del conns[key]
                c = None
            if c is None:
                c = conns[key] = {"client": _HalfStream(), "server": _HalfStream(),
                                  "cfin": False, "sfin": False, "rst": False}
            half = c["client"] if to_server else c["server"]
            # SYN (client) and SYN-ACK (server) both carry the side's ISN.
            half.add(tcp.seq, bytes(tcp.data), ts, bool(tcp.flags & dpkt.tcp.TH_SYN))
            if tcp.flags & dpkt.tcp.TH_FIN:
                c["cfin" if to_server else "sfin"] = True
            if tcp.flags & dpkt.tcp.TH_RST:
                c["rst"] = True
            if c["rst"] or (c["cfin"] and c["sfin"]):
                yield c["client"], c["server"]
                del conns[key]
    for c in conns.values():
        yield c["client"], c["server"]


def reassemble(path: str, port: int):
    """Single-pcap convenience wrapper around reassemble_many()."""
    yield from reassemble_many([path], port)


# ---------------------------------------------------------------------------
# HTTP/1.1 parsing (over a reassembled byte stream)
# ---------------------------------------------------------------------------

def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";", 1)[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        out += body[start:start + size]
        i = start + size + 2  # skip chunk + trailing CRLF
    return bytes(out)


def _headers_map(header_block: bytes) -> dict[str, str]:
    h: dict[str, str] = {}
    for line in header_block.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            h[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
    return h


def _body_text(body: bytes, headers: dict[str, str]) -> str:
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _dechunk(body)
    return _decode(body, headers.get("content-encoding", ""))


def parse_http_messages(stream: bytes, is_request: bool):
    """Yield messages from one direction of a keep-alive HTTP/1.1 stream.

    Each message: dict with start/end byte offsets, parsed start line, headers
    map, and decoded body text. Stops cleanly at a truncated tail (rolling pcap)."""
    pos = 0
    n = len(stream)
    while pos < n:
        hdr_end = stream.find(b"\r\n\r\n", pos)
        if hdr_end < 0:
            return
        header_block = stream[pos:hdr_end]
        headers = _headers_map(header_block)
        first = header_block.split(b"\r\n", 1)[0].decode("latin1")

        body_start = hdr_end + 4
        te = headers.get("transfer-encoding", "").lower()
        if te == "chunked":
            end_marker = stream.find(b"\r\n0\r\n\r\n", body_start)
            if end_marker < 0:
                return  # incomplete chunked body at tail
            body_end = end_marker + len(b"\r\n0\r\n\r\n")
            raw_body = stream[body_start:body_end]
        else:
            cl = headers.get("content-length")
            if cl is not None and cl.isdigit():
                body_end = body_start + int(cl)
                if body_end > n:
                    return  # truncated tail
                raw_body = stream[body_start:body_end]
            else:
                # no declared body (typical for GET requests / 204s)
                body_end = body_start
                raw_body = b""

        yield {
            "start": pos,
            "end": body_end,
            "first": first,
            "headers": headers,
            "text": _body_text(raw_body, headers),
            "raw_len": body_end - pos,
        }
        pos = body_end


def _client_ip(headers: dict[str, str]) -> str:
    """Originating IP per X-Forwarded-For / X-Real-IP (same precedence as the
    old mitmproxy addon). No TCP-peer fallback — on an internal captured leg the
    peer is the proxy, not the client."""
    xff = headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return headers.get("x-real-ip", "").strip()


# ---------------------------------------------------------------------------
# Connection -> rows
# ---------------------------------------------------------------------------

def rows_for_connection(client: "_HalfStream", server: "_HalfStream",
                        banned_ips: set[str], flow_id_start: int,
                        max_duration_ms: float = 60_000):
    """Pair requests with responses on one keep-alive connection and return
    (rows, n_flows_consumed, n_skipped_banned, n_scrubbed_durations).

    Pairing is by TIME, not by index: each request takes the first response that
    starts at or after it. HTTP/1.1 responses arrive in request order, so this is
    correct for clean connections, and it is robust to keep-alive streams captured
    mid-flight (fragmented across hourly pcaps): a leading partial response, or a
    response belonging to a pre-capture request, starts before the first real
    request and is skipped instead of being mis-paired. A request is never matched
    to an earlier response, so a (physically impossible) negative latency cannot
    be emitted."""
    requests = list(parse_http_messages(client.assemble(), is_request=True))
    # responses as (start_ts, end_ts, msg) in stream (= time) order
    resp_seq = [
        (server.ts_at(r["start"]), server.ts_at(r["end"] - 1), r)
        for r in parse_http_messages(server.assemble(), is_request=False)
    ]

    rows: list[dict] = []
    flow_id = flow_id_start
    skipped = 0
    scrubbed = 0
    ri = 0
    for req in requests:
        parts = req["first"].split(" ")
        if len(parts) < 2 or parts[0] != "POST":
            continue
        path = parts[1]
        if banned_ips and _client_ip(req["headers"]) in banned_ips:
            skipped += 1
            continue
        ts_start = client.ts_at(req["start"])

        resp = None
        ts_end = None
        while ri < len(resp_seq):
            r_start, r_end, rmsg = resp_seq[ri]
            if ts_start is not None and r_start is not None and r_start < ts_start:
                ri += 1            # response precedes this request -> not its reply
                continue
            resp, ts_end = rmsg, r_end
            ri += 1
            break

        # Hard guard: never emit a response whose end precedes the request start
        # (would be a negative latency). Covers the rare case where the chosen
        # response lacked a usable start timestamp and slipped the time check.
        if ts_end is not None and ts_start is not None and ts_end < ts_start:
            resp, ts_end = None, None

        # Implausibly long latency on an internal leg almost certainly means this
        # request's real response wasn't captured and time-pairing grabbed a
        # later one. Scrub it like a missing response: null the duration (by
        # dropping ts_end) and drop the suspect response, but still emit the
        # request row so RPC counts stay accurate.
        if (max_duration_ms and ts_end is not None and ts_start is not None
                and (ts_end - ts_start) * 1000 > max_duration_ms):
            resp, ts_end = None, None
            scrubbed += 1

        flow_id += 1
        http_status = None
        if resp is not None:
            sp = resp["first"].split(" ")
            if len(sp) >= 2 and sp[1].isdigit():
                http_status = int(sp[1])
        host = req["headers"].get("host", "")
        rows.extend(build_rows(
            flow_id, host, path, ts_start, ts_end, http_status,
            req["text"], resp["text"] if resp is not None else "",
        ))
    return rows, flow_id - flow_id_start, skipped, scrubbed


def _write(writer, buf):
    writer.write_table(pa.table({f.name: [r[f.name] for r in buf] for f in SCHEMA}, schema=SCHEMA))


def _resolve_pcaps(input_path: Path, workdir: str) -> list[Path]:
    """Return the pcap files to convert, in chronological (sorted-name) order.
    A .tar.zst/.tzst archive is decompressed in full into workdir (on the output
    filesystem, not /tmp). Cross-pcap reassembly needs all members available and
    processed in time order, so we extract rather than stream one-at-a-time."""
    name = input_path.name.lower()
    if name.endswith(".tar.zst") or name.endswith(".tzst"):
        if zstandard is None:
            raise SystemExit("zstandard is required to read .tar.zst input")
        with open(input_path, "rb") as f, \
                zstandard.ZstdDecompressor().stream_reader(f) as reader, \
                tarfile.open(fileobj=reader, mode="r|") as tar:
            tar.extractall(workdir, filter="data")   # filter guards path traversal
        return sorted(Path(workdir).rglob("*.pcap"))
    return [input_path]


def convert_pcap(input_path, output_path, port: int, banned_ips: set[str],
                 compression: str | None = "zstd",
                 max_duration_ms: float = 60_000) -> tuple[int, int, int, int, int]:
    """Convert a pcap or a .tar.zst of pcaps to a single parquet.

    All pcaps are reassembled together (cross-pcap), so keep-alive connections
    that span hourly files are stitched into one stream and request/response
    pairing stays correct across boundaries. flow_id is globally continuous.

    Requests whose paired latency exceeds max_duration_ms (0 disables) keep their
    row but have the implausible duration and suspect response scrubbed.
    Returns (rows_written, requests, skipped, scrubbed, n_pcaps)."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    written = flows = skipped = scrubbed = 0
    buf: list[dict] = []
    # temp dir on the output's filesystem (not /tmp, which may be a small tmpfs)
    with tempfile.TemporaryDirectory(dir=str(output_path.parent or ".")) as workdir:
        pcaps = _resolve_pcaps(input_path, workdir)
        with pq.ParquetWriter(output_path, SCHEMA, compression=compression) as writer:
            for client, server in reassemble_many(pcaps, port):
                rows, nflows, nskip, nscrub = rows_for_connection(
                    client, server, banned_ips, flows, max_duration_ms)
                flows += nflows
                skipped += nskip
                scrubbed += nscrub
                buf.extend(rows)
                if len(buf) >= 50_000:
                    _write(writer, buf)
                    written += len(buf)
                    buf.clear()
            if buf:
                _write(writer, buf)
                written += len(buf)
    return written, flows, skipped, scrubbed, len(pcaps)


def main() -> None:
    import sys
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="pcap file, or .tar.zst archive of pcaps, from tcpdump")
    ap.add_argument("output", type=Path, help="output .parquet file")
    ap.add_argument("--port", type=int, required=True,
                    help="server-side TCP port that was captured (the listen port of the captured leg)")
    ap.add_argument("--compression", default="zstd", choices=["zstd", "snappy", "gzip", "none"])
    ap.add_argument("--ban-ips", default="", help="comma-separated client IPs to exclude (XFF/X-Real-IP)")
    ap.add_argument("--max-duration-ms", type=float, default=60_000,
                    help="null the duration and drop the response for requests whose paired "
                         "latency exceeds this (likely a mis-pairing artifact); 0 disables "
                         "(default: 60000)")
    args = ap.parse_args()

    banned = {ip.strip() for ip in args.ban_ips.split(",") if ip.strip()}
    compression = None if args.compression == "none" else args.compression
    written, flows, skipped, scrubbed, n_pcaps = convert_pcap(
        args.input, args.output, args.port, banned, compression, args.max_duration_ms)

    extra = f" (skipped {skipped:,} banned-IP requests)" if banned else ""
    if args.max_duration_ms:
        extra += (f" (nulled {scrubbed:,} requests over "
                  f"{args.max_duration_ms / 1000:g}s)")
    src = f"{n_pcaps} pcaps" if n_pcaps != 1 else "1 pcap"
    print(f"done: {written:,} rows from {flows:,} requests across {src}{extra} -> {args.output}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
