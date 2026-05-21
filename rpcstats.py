from collections import Counter, defaultdict
from mitmproxy import http
import heapq
import json

flow_count = 0
non_post = 0
parse_failures = 0
http_errors = Counter()
rpc_errors = Counter()
batch_sizes = Counter()

method_count = Counter()
method_singleton_count = Counter()
method_durations_singleton: dict[str, list[float]] = defaultdict(list)
method_errors: dict[str, Counter] = defaultdict(Counter)

bucket_durations: dict[str, list[float]] = defaultdict(list)
bucket_flow_count: Counter = Counter()

req_sizes: list[int] = []
resp_sizes: list[int] = []
all_flow_durations: list[float] = []

TOP_SLOW = 20
slowest_heap: list = []
_seq = 0

SAMPLES_PER_PAIR = 3
error_samples: dict[tuple, list[str]] = defaultdict(list)


def _bucket(n: int) -> str:
    if n == 1:
        return "1"
    if n <= 10:
        return "2-10"
    if n <= 50:
        return "11-50"
    if n <= 100:
        return "51-100"
    return "100+"


def response(flow: http.HTTPFlow):
    global flow_count, non_post, parse_failures, _seq
    flow_count += 1

    if flow.request.method != "POST":
        non_post += 1
        return

    req_body = flow.request.get_text() or ""
    resp_body = flow.response.get_text() if flow.response else ""
    req_sizes.append(len(req_body))
    resp_sizes.append(len(resp_body or ""))

    if flow.response:
        sc = flow.response.status_code
        if sc >= 400:
            http_errors[sc] += 1

    try:
        req_obj = json.loads(req_body)
    except Exception:
        parse_failures += 1
        return

    req_calls = req_obj if isinstance(req_obj, list) else [req_obj]
    req_calls = [c for c in req_calls if isinstance(c, dict)]
    methods_in_order = [c.get("method", "?") for c in req_calls]
    id_to_call = {c.get("id"): c for c in req_calls if c.get("id") is not None}

    n = len(methods_in_order)
    batch_sizes[n] += 1
    for m in methods_in_order:
        method_count[m] += 1
    if n == 1 and methods_in_order:
        method_singleton_count[methods_in_order[0]] += 1

    duration = None
    if flow.response and flow.request.timestamp_start and flow.response.timestamp_end:
        duration = flow.response.timestamp_end - flow.request.timestamp_start
        all_flow_durations.append(duration)

        b = _bucket(n)
        bucket_durations[b].append(duration)
        bucket_flow_count[b] += 1

        if n == 1 and methods_in_order:
            method_durations_singleton[methods_in_order[0]].append(duration)

    if resp_body:
        try:
            resp_obj = json.loads(resp_body)
            resp_items = resp_obj if isinstance(resp_obj, list) else [resp_obj]
            for i, item in enumerate(resp_items):
                if not isinstance(item, dict) or "error" not in item:
                    continue
                err = item["error"]
                code = err.get("code") if isinstance(err, dict) else "?"
                msg = err.get("message", "") if isinstance(err, dict) else ""
                rpc_errors[code] += 1

                cid = item.get("id")
                src_call = id_to_call.get(cid)
                if src_call is None and i < len(req_calls):
                    src_call = req_calls[i]
                method = src_call.get("method", "?") if src_call else "?"
                method_errors[method][code] += 1

                key = (method, code)
                if len(error_samples[key]) < SAMPLES_PER_PAIR:
                    preview = json.dumps(src_call)[:400] if src_call else ""
                    error_samples[key].append((preview, str(msg)[:200]))
        except Exception:
            pass

    if duration is not None:
        _seq += 1
        primary = methods_in_order[0] if methods_in_order else "?"
        entry = (
            duration,
            _seq,
            primary,
            n,
            len(req_body),
            len(resp_body or ""),
            req_body,
        )
        if len(slowest_heap) < TOP_SLOW:
            heapq.heappush(slowest_heap, entry)
        elif duration > slowest_heap[0][0]:
            heapq.heapreplace(slowest_heap, entry)


def _pct(sorted_xs: list[float], p: float) -> float:
    if not sorted_xs:
        return 0.0
    i = min(len(sorted_xs) - 1, int(len(sorted_xs) * p))
    return sorted_xs[i]


def _fmt_ms(s: float) -> str:
    return f"{s * 1000:.1f}ms"


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def done():
    print()
    print("=" * 88)
    print(f"flows:           {flow_count}")
    print(f"  non-POST:      {non_post}")
    print(f"  parse failed:  {parse_failures}")
    print(f"  POST parsed:   {sum(batch_sizes.values())}  (calls: {sum(method_count.values())})")
    print()

    if http_errors:
        print("HTTP errors:")
        for sc, n in sorted(http_errors.items()):
            print(f"  {sc}: {n}")
        print()

    if rpc_errors:
        print("JSON-RPC error codes (global, per-call):")
        for code, n in rpc_errors.most_common():
            print(f"  {code}: {n}")
        print()

    print("Batch sizes (size: count):")
    for size, n in sorted(batch_sizes.items()):
        print(f"  {size}: {n}")
    print()

    if req_sizes:
        rs = sorted(req_sizes)
        zs = sorted(resp_sizes)
        print("Body sizes:")
        print(f"  request   p50={_fmt_bytes(_pct(rs, 0.5))}  p95={_fmt_bytes(_pct(rs, 0.95))}  max={_fmt_bytes(rs[-1])}")
        print(f"  response  p50={_fmt_bytes(_pct(zs, 0.5))}  p95={_fmt_bytes(_pct(zs, 0.95))}  max={_fmt_bytes(zs[-1])}")
        print(f"  total req={_fmt_bytes(sum(req_sizes))}  total resp={_fmt_bytes(sum(resp_sizes))}")
        print()

    if all_flow_durations:
        ds = sorted(all_flow_durations)
        print("Per-flow latency (overall, regardless of batch size):")
        print(f"  p50={_fmt_ms(_pct(ds, 0.5))}  p95={_fmt_ms(_pct(ds, 0.95))}  p99={_fmt_ms(_pct(ds, 0.99))}  max={_fmt_ms(ds[-1])}")
        print()

    print("Per-flow latency by batch size bucket:")
    print(f"  {'bucket':>10}  {'flows':>10}  {'p50':>8}  {'p95':>8}  {'p99':>8}  {'max':>9}")
    for b in ("1", "2-10", "11-50", "51-100", "100+"):
        ds = sorted(bucket_durations.get(b, []))
        if not ds:
            continue
        print(f"  {b:>10}  {bucket_flow_count[b]:>10}  {_fmt_ms(_pct(ds, 0.5)):>8}  {_fmt_ms(_pct(ds, 0.95)):>8}  {_fmt_ms(_pct(ds, 0.99)):>8}  {_fmt_ms(ds[-1]):>9}")
    print()

    print("Top 30 methods by call count (latency = singleton-batch flows only):")
    print(f"  {'calls':>10}  {'singles':>10}  {'p50':>8}  {'p95':>8}  {'p99':>8}  method")
    for method, n in method_count.most_common(30):
        ns = method_singleton_count.get(method, 0)
        ds = sorted(method_durations_singleton.get(method, []))
        if ds:
            p50 = _fmt_ms(_pct(ds, 0.5))
            p95 = _fmt_ms(_pct(ds, 0.95))
            p99 = _fmt_ms(_pct(ds, 0.99))
        else:
            p50 = p95 = p99 = "-"
        print(f"  {n:>10}  {ns:>10}  {p50:>8}  {p95:>8}  {p99:>8}  {method}")
    print()

    eligible = [(m, sorted(ds)) for m, ds in method_durations_singleton.items() if len(ds) >= 10]
    eligible.sort(key=lambda x: x[1][int(len(x[1]) * 0.95)], reverse=True)
    print("Top 15 methods by singleton p95 latency (min 10 singleton calls):")
    print(f"  {'singles':>10}  {'p50':>8}  {'p95':>8}  {'p99':>8}  method")
    for method, ds in eligible[:15]:
        print(f"  {len(ds):>10}  {_fmt_ms(_pct(ds, 0.5)):>8}  {_fmt_ms(_pct(ds, 0.95)):>8}  {_fmt_ms(_pct(ds, 0.99)):>8}  {method}")
    print()

    print("Errors attributed by method (top 20 by error count, % of all calls of that method):")
    method_total_err = sorted(
        ((m, sum(c.values())) for m, c in method_errors.items()),
        key=lambda x: -x[1],
    )[:20]
    print(f"  {'errors':>10}  {'calls':>10}  {'err%':>6}  method  [codes]")
    for m, total_e in method_total_err:
        total = method_count.get(m, 0)
        pct = (total_e / total * 100) if total else 0.0
        codes = ", ".join(f"{c}:{n}" for c, n in method_errors[m].most_common())
        print(f"  {total_e:>10}  {total:>10}  {pct:>5.1f}%  {m}  [{codes}]")
    print()

    print("Top slowest individual flows (per HTTP request, regardless of batch size):")
    for dur, _, primary, n, rsz, zsz, preview in sorted(slowest_heap, key=lambda x: -x[0]):
        prev = preview.replace("\n", " ").replace("\r", " ")
        print(f"  {_fmt_ms(dur):>10}  batch={n}  primary={primary}  req={rsz}B resp={zsz}B")
        print(f"    {prev}")
    print()

    print("Sample failing requests (top (method, code) pairs):")
    pair_counts = []
    for m, codes in method_errors.items():
        for c, n in codes.items():
            pair_counts.append(((m, c), n))
    pair_counts.sort(key=lambda x: -x[1])
    for (m, c), n in pair_counts[:8]:
        print(f"\n  {m} / code {c}  ({n} occurrences):")
        for preview, msg in error_samples.get((m, c), []):
            prev = preview.replace("\n", " ").replace("\r", " ")
            print(f"    req: {prev[:260]}")
            print(f"    msg: {msg}")
    print("=" * 88)
