# Load test baseline

`make load-test` runs a controlled burst of process events through the
agent and reports drop rate, CPU%, and RSS. The target is a single-host
smoke check, not continuous CI — privileged and noisy.

## Running

```bash
# root on a host with /sys/kernel/btf/vmlinux and stress-ng installed
sudo make load-test                     # defaults: 30s, --exec 100
sudo bash scripts/load-test.sh 60 200   # 60s duration, 200 exec workers
```

Output is a single summary block:

```
================= slither-agent load baseline =================
duration_s       30
stress_ng_exec   100
events_produced  123456
events_dropped   0
detections_fired 0
ringbuf_overflow 0
drop_rate_pct    0.00%
samples=30 mean_cpu=3.4 peak_cpu=6.1 peak_rss_kb=21504
===============================================================
```

## Methodology

- `stress-ng --exec N --timeout Ds` spawns N workers that each
  `fork`/`execve` `true` in a tight loop. This exercises the process
  collector's tracepoints and the enricher's /proc backfill path.
- The agent runs with **zero rules** loaded — the rule engine is
  out of scope for the process-ingest measurement. For a detection-path
  measurement, swap in `rules/linux/*.yml` and expect a modest CPU
  increase.
- CPU/RSS sampled via `ps -o %cpu=,rss= -p <pid>` at 1 Hz.
- Drop rate = `dropped / (produced + dropped)`, counting the
  `IncDrops()` calls from the collector ringbuf-drain loops, enricher
  channel full, and rule engine event-priority send.

## Exit criterion #3 from IMPLEMENTATION.md §3.5

The Phase 1 target is **drop rate < 1%** under this workload on a
4-core host. A higher rate indicates one of:

- Ringbuffer sized too small for the burst (look at
  `ringbuf_overflow`).
- Enricher saturated — parent chain depth too deep or /proc backfill
  stalling.
- Rule engine event-priority queue backed up (run with `-tags=pprof`
  when that lands; today, profile manually).

## Recording a baseline

The script prints one summary block per run. When evaluating a change,
capture before/after from the same host with the same arguments —
absolute numbers vary by kernel, core count, memory pressure, and
other running workloads, so only deltas on the same box are meaningful.

Do **not** commit machine-specific baselines into this file — the
expected block above is illustrative only.
