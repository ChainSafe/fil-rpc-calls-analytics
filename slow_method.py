from mitmproxy import http
import heapq
import json
import os

TARGET = os.environ.get("METHOD", "eth_estimateGas")
TOP_N = int(os.environ.get("TOP_N", "15"))

_seq = 0
heap: list = []


def response(flow: http.HTTPFlow):
    global _seq
    if flow.request.method != "POST" or not flow.response:
        return
    if not flow.request.timestamp_start or not flow.response.timestamp_end:
        return

    req_text = flow.request.get_text() or ""
    try:
        req_obj = json.loads(req_text)
    except Exception:
        return

    calls = req_obj if isinstance(req_obj, list) else [req_obj]
    if not any(isinstance(c, dict) and c.get("method") == TARGET for c in calls):
        return

    duration = flow.response.timestamp_end - flow.request.timestamp_start
    _seq += 1
    resp_text = flow.response.get_text() or ""
    entry = (duration, _seq, len(calls), req_text, resp_text, flow.request.timestamp_start)

    if len(heap) < TOP_N:
        heapq.heappush(heap, entry)
    elif duration > heap[0][0]:
        heapq.heapreplace(heap, entry)


def done():
    print()
    print("=" * 88)
    print(f"Top {TOP_N} slowest flows containing method = {TARGET}")
    print("=" * 88)
    for duration, _, n, req_text, resp_text, ts in sorted(heap, key=lambda x: -x[0]):
        print()
        print(f"  duration: {duration*1000:.1f} ms   batch size: {n}   ts: {ts:.3f}")
        print(f"  --- request ---")
        try:
            pretty_req = json.dumps(json.loads(req_text), indent=2)
        except Exception:
            pretty_req = req_text
        for line in pretty_req.splitlines()[:120]:
            print(f"    {line}")
        print(f"  --- response (first 2000 chars) ---")
        try:
            pretty_resp = json.dumps(json.loads(resp_text), indent=2)
        except Exception:
            pretty_resp = resp_text
        snippet = pretty_resp[:2000]
        for line in snippet.splitlines():
            print(f"    {line}")
        if len(pretty_resp) > 2000:
            print(f"    ... [{len(pretty_resp) - 2000} more chars]")
