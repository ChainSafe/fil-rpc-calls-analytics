"""mitmproxy addon for RPC capture.

Two jobs:

1. Tag each flow with the JSON-RPC method name(s) so downstream analytics
   can group without re-parsing request bodies.
2. Decouple the upstream call from the client connection lifetime. When
   the producer disconnects after sending the request (common with fire-
   and-forget batch senders), default mitmproxy aborts the upstream side
   and the .mitm dump never gets the response. This addon issues the
   upstream call itself from the `request` hook and assigns the result
   to `flow.response`, so the round trip completes regardless of what
   the client does. Setting `flow.response` also short-circuits mitm's
   own forwarding, so the upstream still only sees one request per flow.

Uses only the Python stdlib so it can run inside mitmproxy's bundled
interpreter without extra installs.

Banning policy: `banned_ips` blocks listed clients from reaching the
upstream — they get an immediate 403 instead. The 403 flow still lands
in the mitm dump (default `-w` behavior); filter those out at conversion
time via `flows_to_parquet.py --ban-ips` (env `BAN_IPS=` for the
`convert` task) so they don't pollute the parquet.

Sample usage:
```
mitmdump --mode reverse:http://127.0.0.1:1234/ \
         --listen-port 2345 -w flows.mitm \
         --set block_global=false \
         -s connection_extender.py \
         --set upstream_url=http://127.0.0.1:1234 \
         --set upstream_timeout=60 \
         --set banned_ips=1.2.3.4
```
"""

import asyncio
import http.client as httpclient
import json
import time
from urllib.parse import urlparse

from mitmproxy import ctx, http


def _client_ip(flow: http.HTTPFlow) -> str:
    """Originating IP per X-Forwarded-For/X-Real-IP, else direct TCP peer."""
    xff = flow.request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    xri = flow.request.headers.get("X-Real-IP", "")
    if xri:
        return xri.strip()
    if flow.client_conn and flow.client_conn.peername:
        return flow.client_conn.peername[0]
    return ""


def _post_sync(host: str, port: int, method: str, path: str,
               headers: dict, body: bytes, timeout: float):
    conn = httpclient.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


class ForestCapture:
    def load(self, loader):
        loader.add_option("upstream_url", str, "http://127.0.0.1:1234",
                          "Base URL the addon forwards to in place of mitmproxy's own forwarding.")
        loader.add_option("upstream_timeout", int, 60,
                          "Timeout (seconds) for the addon-issued upstream call.")
        loader.add_option("banned_ips", str, "",
                          "Comma-separated client IPs (X-Forwarded-For/X-Real-IP, else TCP peer) "
                          "to reject with 403 without forwarding upstream.")

    def _banned_set(self):
        return {ip.strip() for ip in (ctx.options.banned_ips or "").split(",") if ip.strip()}

    async def request(self, flow: http.HTTPFlow) -> None:
        # Buffer the full request before doing anything else.
        flow.request.stream = False

        # Reject banned IPs before doing any upstream work. The flow still
        # lands in the mitm dump; filter it out at convert-time instead.
        client_ip = _client_ip(flow)
        if client_ip and client_ip in self._banned_set():
            flow.metadata["banned_ip"] = client_ip
            flow.comment = f"banned:{client_ip}"
            flow.response = http.Response.make(
                403,
                json.dumps({"error": "forbidden"}).encode(),
                {"Content-Type": "application/json"},
            )
            return

        try:
            body = json.loads(flow.request.get_text() or "")
        except ValueError:
            body = None
        if isinstance(body, dict):
            methods = [body.get("method")]
        elif isinstance(body, list):
            methods = [m.get("method") for m in body if isinstance(m, dict)]
        else:
            methods = []
        methods = [m for m in methods if m]
        if methods:
            flow.metadata["rpc_methods"] = methods
            flow.comment = ",".join(methods)

        # Take over the upstream call so its lifetime is no longer tied
        # to the client's. mitmproxy will use whatever we set on
        # flow.response and skip its own forwarding.
        parsed = urlparse(ctx.options.upstream_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = flow.request.path
        headers = {
            k: v for k, v in flow.request.headers.items()
            if k.lower() not in ("host", "content-length", "connection")
        }
        req_body = flow.request.get_content() or b""

        t0 = time.time()
        try:
            status, resp_headers, data = await asyncio.to_thread(
                _post_sync, host, port, flow.request.method, path,
                headers, req_body, ctx.options.upstream_timeout,
            )
        except Exception as e:
            ctx.log.warn(f"upstream call failed for {host}:{port}{path}: {e}")
            return

        flow.response = http.Response.make(status, data, resp_headers)
        flow.response.timestamp_start = t0
        flow.response.timestamp_end = time.time()


addons = [ForestCapture()]
