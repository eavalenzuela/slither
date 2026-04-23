# Load test baseline

`make load-test` runs a controlled burst of process events through the
agent and reports drop rate, CPU%, and RSS. The target is a single-host
smoke check, not continuous CI — privileged and noisy.

## Host sizing

The default workload (`--exec 100 --timeout 30s`) and the documented
exit criterion presume a host with at least:

- **4 vCPUs.** The `<1%` drop-rate bar below is defined on a 4-core
  host; fewer cores will drive the rate higher even on a healthy
  agent because stress-ng's 100 exec workers contend with the
  collector/enricher goroutines for CPU.
- **4 GB RAM.** stress-ng's `--exec` stressor warns and self-skips
  workers on tight-memory hosts (`recommend using --oom-avoid`);
  observed on a 2 GB Debian 13 VM where `stressor must not run`
  combined with the ambient allocations produced an unrepresentative
  run. 4 GB gives comfortable headroom for 100 workers plus the agent.

Smaller VMs may still run the load test, but the drop-rate number is
not comparable against the Phase 1 exit criterion.

## Running

Build the agent as your normal user first — `sudo` strips `PATH` on
most distros, so `go` is typically not reachable under root. The load
script therefore refuses to build; it only runs an already-built
binary.

```bash
make build-agent                        # as your user (go in PATH)
sudo make load-test                     # defaults: 30s, --exec 100
sudo bash scripts/load-test.sh 60 200   # 60s duration, 200 exec workers
```

If `sudo make load-test` reports `bin/slither-agent not found`, the
build step was skipped (or ran as root and failed) — re-run
`make build-agent` as your user and try again.

Output is a single summary block:

```
================= slither-agent load baseline =================
duration_s       30
stress_ng_exec   100
events_produced  123456
events_dropped   0
  by_stage       collector=0 dispatch=0 enricher=0 engine=0
detections_fired 0
ringbuf_overflow 0
drop_rate_pct    0.00%
samples=30 mean_cpu=3.4 peak_cpu=6.1 peak_rss_kb=21504
===============================================================
```

The `by_stage` line attributes `events_dropped` to the pipeline boundary
where the drop happened:

- `collector` — the kernel ringbuf drained cleanly but the collector's
  output channel to the enricher was full (i.e. the agent can read BPF
  faster than the enricher can dispatch).
- `dispatch` — pid-sharded dispatcher found a worker inbox full (one
  shard getting hammered; re-hash needed or workload skewed).
- `enricher` — a worker finished /proc backfill but the rule engine's
  input channel was full (engine/sink slow).
- `engine` — rule engine's non-blocking emit to the output sink was
  full (sink saturated — stdout/journald rate limits, network, etc).

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
4-core / 4 GB host. A higher rate indicates one of:

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
