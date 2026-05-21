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
| `latency` | Per-method p50/p95/p99/avg/max, singleton flows only |
| `slow [method] [top_n]` | Slowest individual flows; full params via `PARAMS_CAP=0` |
| `popular [method] [top_params]` | Most-used methods and their most common params |
| `errors` | Error rates per method |
| `compare <before.parquet> <after.parquet>` | Per-method latency diff |
| `peek` | Schema + first rows of the parquet |
| `install` | Install Python deps (mitmproxy, pyarrow, polars) |

## Benchmarking

`rpc_bench.sh` drives [oha](https://github.com/hatoo/oha) against a Lotus/Forest endpoint with a chosen method/params, after a warm-up. Tweak `METHOD`, `PARAMS`, `LOTUS_URL`, `FOREST_URL` at the top of the script; results land in `results/`.

## Env knobs

- `PARQUET` — input parquet path (default `calls.parquet`).
- `PARAMS_CAP`, `ERROR_CAP` — column truncation for `slow` (defaults 200/80; set to `0` for no cap).
