# Capture pipeline (nginx + tcpdump)

Replaces the `mitmdump` capture. mitmproxy reverse mode aborts fire-and-forget
requests (client disconnects before reading the response) *before* forwarding —
so ~99% were neither served nor captured. nginx buffers the request and
completes the upstream call regardless, and tcpdump captures passively so it can
never disrupt serving.

```
producers ─▶ nginx :2345 ─split SAMPLE_PCT%─▶ Lotus Gateway ─▶ Forest
                       └ rest: 444 (closed)
             tcpdump (lo, passive) ─▶ ./captures/*.pcap ─▶ [dev box] mise run pcap-convert ─▶ parquet
```

## On the VPS (only needs Docker)

```bash
cd deploy
# edit docker-compose.yml env: GATEWAY_PORT, SAMPLE_PCT, CAP_PORT
docker compose up -d --build
```

- **Point producers at nginx** on `:2345` (where mitmdump listened).
- **`SAMPLE_PCT`** controls the share forwarded to the Gateway→Forest (e.g. `100`,
  `50`); the rest get `444`. Change it and `docker compose up -d`.
- **`CAP_PORT`** chooses the captured leg:
  - `= GATEWAY_PORT` → **front of the Gateway** (nginx↔Gateway): original method
    names (`eth_call`) + responses. Default, best match to existing parquet.
  - `= Forest's port` → **Gateway↔Forest**: methods as Forest sees them.
- Capture files rotate hourly into `deploy/captures/` (24 kept). These are
  **confidential** — git-ignored; copy them to the analysis box out-of-band.

## On the dev box (existing uv/mise)

A single hourly pcap:
```bash
PORT=3456 mise run pcap-convert captures/cap-20260610-120000.pcap
```

A day's worth at once — bundle the hourly pcaps and convert/merge in one shot
(they're merged into a single parquet with a continuous flow_id):
```bash
# on the VPS (or after copying captures/ over):
tar -I zstd -cf caps-20260610.tar.zst -C captures .
# on the dev box:
PORT=3456 mise run pcap-convert caps-20260610.tar.zst
# -> calls-caps-20260610.parquet, then the usual:
PARQUET=calls-caps-20260610.parquet mise run summary
```

`PORT` must equal the captured server port (`CAP_PORT` above). `BAN_IPS=` drops
clients by `X-Forwarded-For`/`X-Real-IP`, same as `convert`.

## Notes
- Both containers use `network_mode: host` so the nginx↔Gateway loopback traffic
  is sniffable on `lo`.
- TLS: the converter needs plaintext HTTP on the captured leg (internal legs are
  plaintext). Producer→nginx TLS, if any, is terminated at nginx and doesn't
  affect the internal capture.
