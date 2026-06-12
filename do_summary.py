#!/usr/bin/env python
"""Per-window summary table of the DigitalOcean monitoring JSON in do-metrics/.

Stats come from the shared `do_metrics` layer, so this table can never disagree
with the charts — and the disk row is the honest series-based mean/peak, not the
last sample (which used to badly understate the compaction peak).

Run: .venv/bin/python do_summary.py
"""
import do_metrics as dm

print(f"{'window':<8} {'RAM GiB':>8} {'used mean':>10} {'used p95':>9} {'used max':>9} {'used %':>7} "
      f"{'cpu cores':>9} {'cpu mean%':>9} {'cpu p95%':>9} {'cpu max%':>8} {'load mean':>9} {'load max':>8} "
      f"{'disk mean':>10} {'disk max':>9} {'disk %':>7} {'net in Mbps':>11} {'net out Mbps':>12}")
for w in dm.windows():
    m = dm.mem_stats(w); c = dm.cpu_stats(w); l = dm.load_stats(w)
    dk = dm.disk_stats(w); b = dm.bw_stats(w)
    print(f"{w:<8} {m['total']:>8.1f} {m['used_mean']:>10.2f} {m['used_p95']:>9.2f} {m['used_max']:>9.2f} "
          f"{m['pct_mean']:>6.1f}% {c['cores']:>9} {c['util_mean']:>9.1f} {c['util_p95']:>9.1f} {c['util_max']:>8.1f} "
          f"{l['mean']:>9.2f} {l['max']:>8.2f} {dk['used_mean']:>9.1f}G {dk['used_max']:>8.1f}G {dk['pct_max']:>6.1f}% "
          f"{b['inbound']['mean']:>6.2f}/{b['inbound']['max']:>4.1f} "
          f"{b['outbound']['mean']:>7.2f}/{b['outbound']['max']:>4.1f}")
