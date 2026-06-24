# rpc-cl-traffic

Tools for capturing and analyzing JSON-RPC traffic between Filecoin clients (Lotus, Forest) and their callers. Capture goes through mitmproxy, gets normalized into one row per RPC call in Parquet, and is then sliced with small polars scripts.

## Workflow

1. Capture traffic with mitmproxy into a `flows*.mitm` dump.
2. `mise run convert <flows.mitm>` → produces `calls*.parquet` (one row per JSON-RPC call, with method, params, duration, errors, …).
3. Query with the `mise run <task>` scripts below.

All analysis tasks read `calls.parquet` by default; override with `PARQUET=path mise run <task>`.

## Tasks

| Task | What it shows |
|---|---|
| `convert [input.mitm]` | `flows*.mitm` → `calls*.parquet` (default `flows.mitm` → `calls.parquet`) |
| `pcap-convert <in.pcap\|.tar.zst> [out]` | a pcap, or a `.tar.zst` of hourly pcaps (merged into one), HTTP/1.1 JSON-RPC → `calls*.parquet`, same schema. `PORT=` (captured server port, required), `BAN_IPS=`. See `deploy/` |
| `healthcheck [input.mitm]` | Scan a dump and flag POST flows whose request body wasn't captured (half-captured dumps) |
| `prove-truncation <capture.pcap>` | From a wire capture, prove whether the producer truncates request bodies (sends fewer bytes than its `Content-Length`). `PORT=`, `LABEL=` |
| `summary` | High-level analytics: counts, reply rate, batches, latency, top methods, errors |
| `latency` | Per-method p50/p95/p99/avg/max, singleton flows only |
| `latency-batch` | Per-flow latency for batched requests, by bucket and by method |
| `compare-batch <before> <after>` | Batch-efficiency diff between two parquet files |
| `slow [method] [top_n]` | Slowest individual flows; full params via `PARAMS_CAP=0` |
| `popular [method] [top_params]` | Most-used methods and their most common params |
| `errors` | Error rates per method |
| `compare <before.parquet> <after.parquet>` | Per-method latency diff |
| `charts <node-a> <node-b> [top_n] [out]` | Parquet-only deck (all PNG): reliability, batching, what-node-serves + node-vs-node latency comparisons (per-flow, per-call, per-method, batched) → `charts/` |
| `charts-do <node-a> <node-b> [out]` | Parquet + DigitalOcean: `load-over-time` — both nodes' server CPU/memory on one clock → `charts/`; run `fetch-do` first |
| `fetch-do <parquet>…` | Fetch DigitalOcean metrics aligned to each capture → `do-metrics/` (creds from `.env`: `DIGITALOCEAN_TOKEN` + `DIGITALOCEAN_HOST_ID`) |
| `peek` | Schema + first rows of the parquet |
| `install` | Install all Python deps (mitmproxy, polars, altair, vl-convert, …) |

## Charts

Polished charts land in `charts/`, split by the data they need:

- **Parquet only** — `mise run charts <node-a.parquet> <node-b.parquet>` renders the business deck (`reliability`, `batching`, `what-node-serves`) plus the node-vs-node latency comparisons. Charts self-label: Forest from capture (`Forest: 2026-06-15-8602bfd`), Lotus from GitHub `master` (`Lotus: v1.36.1-dev`) — all PNG. No DigitalOcean data required.
- **Parquet + DigitalOcean** — `mise run charts-do <node-a.parquet> <node-b.parquet>` renders `load-over-time`: both nodes' whole-server CPU and memory overlaid on one clock, over the same observation window (trimmed to the shorter run). Needs `do-metrics/` populated.

Populate `do-metrics/` first (the window is auto-derived from each parquet, so the resource data lines up with the captured traffic):

```sh
cp .env.example .env        # then set your DigitalOcean creds in .env:
#   DIGITALOCEAN_TOKEN=dop_v1_...     (a read-only token is enough)
#   DIGITALOCEAN_HOST_ID=123456789    (the droplet's numeric id, not its name)
mise run fetch-do <before.parquet> <after.parquet>
```

## Benchmarking

`rpc_bench.sh` drives [oha](https://github.com/hatoo/oha) against a Lotus/Forest endpoint with a chosen method/params, after a warm-up. Tweak `METHOD`, `PARAMS`, `LOTUS_URL`, `FOREST_URL` at the top of the script; results land in `results/`.

## Env knobs

- `PARQUET` — input parquet path (default `calls.parquet`).
- `PARAMS_CAP`, `ERROR_CAP` — column truncation for `slow` (defaults 200/80; set to `0` for no cap).
