# Slither — Implementation Plan

> Companion to [PROJECT.md](./PROJECT.md). PROJECT.md is the design / decision record. This document is the build plan.
>
> **Depth rule:** Phase 0 and Phase 1 are planned at enough detail to start writing code. Phases 2–7 are listed at bullet-level; each will be re-planned in detail when entered.

---

## 0. How to read this

- Each phase has **goals**, **scope**, **exit criteria**, and a **task breakdown**.
- Exit criteria are deliberately narrow — "Phase N is done" means "criteria met," not "everything we might want."
- The plan favors a thin end-to-end slice at each phase over any one deeply-finished subsystem.

---

## 1. Repository Layout

Go workspaces; three modules; everything else is flat directories.

```
/
├── go.work                           # Go workspace rooting agent, server, pkg
├── LICENSE
├── PROJECT.md                        # Design record
├── IMPLEMENTATION.md                 # This file
├── README.md                         # User-facing intro (write in Phase 0)
├── SECURITY.md                       # Vulnerability disclosure policy
├── CONTRIBUTING.md                   # DCO, dev setup, PR expectations
├── Makefile                          # Entry points: build, test, lint, gen, ci
├── .github/
│   └── workflows/
│       ├── ci.yml                    # build, test, lint, vet, vulncheck
│       ├── dco.yml                   # DCO enforcement
│       └── release.yml               # Tag-driven release build + signing
├── .golangci.yml                     # Linter config
├── .editorconfig
├── proto/                            # Protobuf definitions (buf-managed)
│   ├── buf.yaml
│   ├── buf.gen.yaml
│   └── slither/
│       ├── v1/
│       │   ├── agent.proto           # agent↔server service
│       │   ├── event.proto           # OCSF-mapped event envelope
│       │   ├── control.proto         # control channel (rules, tasks)
│       │   └── extension.proto       # agent↔extension interface (Phase 6)
│       └── gen/                      # Generated Go code (checked in — see §2.3)
├── pkg/                              # Shared libraries
│   ├── go.mod
│   ├── ocsf/                         # OCSF event type definitions + helpers
│   ├── ruleast/                      # Internal rule AST (Sigma compile target)
│   ├── wire/                         # Wire protocol helpers (versioning, framing)
│   ├── logx/                         # Structured logging wrapper
│   └── must/                         # Small assertion helpers
├── agent/
│   ├── go.mod
│   ├── cmd/
│   │   └── slither-agent/
│   │       └── main.go
│   ├── internal/
│   │   ├── collector/                # eBPF loader, ringbuf reader
│   │   ├── bpf/                      # eBPF C source (compiled via bpf2go)
│   │   │   ├── process.bpf.c
│   │   │   ├── file.bpf.c
│   │   │   ├── net.bpf.c
│   │   │   └── common.h
│   │   ├── enricher/                 # process tree, container ctx, hashing
│   │   ├── ruleengine/               # Edge rule engine (stateless Phase 1)
│   │   ├── response/                 # Response executor (Phase 4)
│   │   ├── transport/                # mTLS gRPC to server (Phase 2)
│   │   ├── buffer/                   # Offline/backpressure buffer (Phase 5)
│   │   ├── config/                   # Config loading, validation
│   │   └── output/                   # Sinks: stdout/jsonl (Phase 1), grpc (Phase 2)
│   └── testdata/
├── server/
│   ├── go.mod
│   ├── cmd/
│   │   └── slither-server/
│   │       └── main.go
│   ├── internal/
│   │   ├── ingest/                   # gRPC ingest API (Phase 2)
│   │   ├── store/
│   │   │   ├── clickhouse/           # Event store
│   │   │   └── postgres/             # Control-plane store
│   │   ├── detect/                   # Server detection engine (Phase 3)
│   │   ├── sigma/                    # Sigma compiler + classifier
│   │   ├── alerts/                   # Alert lifecycle
│   │   ├── rbac/                     # Auth + roles
│   │   ├── console/                  # HTMX+templ web console
│   │   │   ├── templates/            # .templ files
│   │   │   ├── static/               # Vendored JS/CSS
│   │   │   └── handlers/
│   │   ├── graph/                    # D2 graph rendering
│   │   └── config/
│   └── testdata/
├── deploy/
│   ├── docker/
│   │   ├── agent.Dockerfile
│   │   └── server.Dockerfile
│   ├── compose/
│   │   └── docker-compose.yml        # Single-node reference deploy
│   ├── systemd/
│   │   ├── slither-agent.service
│   │   └── slither-server.service
│   └── migrations/
│       ├── postgres/
│       └── clickhouse/
├── rules/                            # Bundled Sigma rules
│   └── linux/
├── docs/
│   ├── architecture.md
│   ├── install.md
│   ├── operators-guide.md
│   ├── rule-authoring.md
│   └── adr/                          # Architecture Decision Records
├── scripts/
│   ├── install-tools.sh              # Install dev tools (buf, templ, etc.)
│   ├── gen.sh                        # Run all codegen
│   └── release.sh                    # Tag-driven release
├── tools/
│   └── tools.go                      # go tool dependency pinning
└── testdata/                         # Cross-module fixtures (sample events, rules)
```

### Layout rationale

- **Go workspaces** let the agent and server share `pkg/` without Go module hell, while each keeping their own dependency graph. Tests can cross-compile against a pinned `pkg/` version.
- **`internal/` everywhere** — we do not publish Go APIs. Anyone importing `github.com/t3rmit3/slither/agent/internal/collector` is doing it wrong.
- **Generated code checked in.** Protobuf and templ generated files live in the repo. Contributors without the full toolchain can build; `make gen` regenerates and `make verify-gen` fails CI if drifted.

---

## 2. Phase 0 — Foundations ✅ Complete (2026-04-21)

**Goal:** Make it possible to write and merge real agent/server code. No feature work yet; only the runway.

**Scope:** repo scaffolding, toolchain, codegen, CI, dev environment, governance files, wire protocol v1 frozen.

**Exit criteria:**
1. ✅ `make ci` passes on a clean clone: builds agent + server binaries, runs tests, lints, vulncheck, regen-drift check. *(govulncheck flags GO-2025-3750, a Windows-only stdlib advisory fixed in go1.24.4 — not applicable to Linux-only v1 per ADR-0001; CI's setup-go pulls the patched release.)*
2. ✅ Protobuf definitions for agent↔server wire protocol v1 are merged and codegen produces Go types.
3. ✅ OCSF v1.3 event class subset is codegenned to Go types in `pkg/ocsf`.
4. ✅ CI runs on every PR; DCO check blocks unsigned commits.
5. ✅ ADRs 0001–0029 record every decision from PROJECT.md §9.1 as individual ADRs so history stays auditable if PROJECT.md is later restructured.
6. ✅ `README.md` describes what Slither is, project status, how to build from source, where to find docs.

### 2.1 Toolchain

| Tool | Purpose | Version pin |
|---|---|---|
| Go | Agent + server language | 1.23.x (latest stable at impl time) |
| clang + LLVM | eBPF compilation | 16+ (CO-RE requires modern clang) |
| `libbpf-dev` + kernel BTF | eBPF headers / CO-RE anchors | Distro-provided |
| `cilium/ebpf` | Go eBPF loader + `bpf2go` codegen | Pinned in `go.mod` |
| `buf` | Protobuf schema management + codegen | `bufbuild/buf` latest |
| `protoc-gen-go` + `protoc-gen-go-grpc` | Go codegen from proto | Pinned |
| `templ` | Typed HTML templates | `a-h/templ` latest |
| `tailwindcss` (standalone) | CSS build, no Node | Standalone binary |
| `golangci-lint` | Lint aggregator | Latest |
| `govulncheck` | Vulnerability database check | Part of Go toolchain |
| `staticcheck` | Included in golangci-lint |  |
| `gotestsum` | Nicer `go test` output | Dev-only |
| `cosign` + `syft` | Release signing + SBOM | Phase 5, listed here for tool install script |
| Docker / Podman | Container builds + compose | Latest stable |

**Tool install:** `scripts/install-tools.sh` is idempotent, installs to `$(go env GOBIN)` (pinned via `tools/tools.go`), and is CI-reusable. No `apt install` in this script — it assumes Go + clang + Docker already present. A separate `docs/dev-setup.md` lists system-package prerequisites per distro.

**Build entry points (Makefile):**

```
make tools         # Install Go tools via tools.go
make gen           # buf generate, templ generate, bpf2go
make verify-gen    # Fail if `make gen` would produce a diff
make build         # Agent + server binaries to bin/
make test          # Unit tests
make test-integration  # Requires root + kernel BTF; runs eBPF loader tests
make lint          # golangci-lint + govulncheck
make ci            # gen-verify + build + test + lint
make clean
make compose-up    # Start local dev stack
make compose-down
```

### 2.2 Go workspaces setup

```
// go.work
go 1.23

use (
    ./pkg
    ./agent
    ./server
)
```

Each module has its own `go.mod` and pinned deps. `pkg/` is the only module importable across the agent/server line; agent never imports server, server never imports agent.

### 2.3 Protobuf + OCSF codegen

**Protobuf.**
- `proto/` managed by `buf` (schema linting, breaking-change detection, codegen via `buf.gen.yaml`).
- `buf breaking` runs against `main` in CI — wire protocol v1 cannot break without an explicit version bump and ADR.
- Generated Go lives in `proto/slither/v1/gen/`; imports are `github.com/t3rmit3/slither/proto/slither/v1`.
- All three interfaces (agent↔server, control channel, extensions) are in this tree from day one even though the latter two are skeletons in Phase 0.

**OCSF.**
- Rather than pull OCSF's giant JSON schema directly, we maintain a curated subset for the event classes listed in PROJECT.md §5.1.
- `pkg/ocsf/` contains hand-written Go structs matching OCSF 1.3 field names and types, with a `ClassID()` method and a `Validate()` pass.
- An ADR (`docs/adr/0002-ocsf-subset-strategy.md`) documents: why a hand-curated subset, how we bump OCSF versions deliberately, how we test mapping stability.
- Generator script (`scripts/ocsf-check.sh`) downloads OCSF 1.3 schema files into `testdata/ocsf/` and a test in `pkg/ocsf/schema_test.go` verifies every field we use exists upstream with the expected type. Catches OCSF drift without coupling us to their codegen.

### 2.4 Wire protocol v1 (frozen in Phase 0)

**Transport:** gRPC over HTTP/2, mTLS.

**Three services:**

```proto
// proto/slither/v1/agent.proto
service Agent {
  // Long-lived bidi stream. Agent streams events up;
  // server streams control messages (rule updates, tasks) down.
  rpc Session(stream ClientMessage) returns (stream ServerMessage);

  // Used once at enrollment to exchange an enrollment token for an mTLS cert.
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
}
```

`ClientMessage` is a oneof: `Event`, `Heartbeat`, `Ack`, `DiagReport`.
`ServerMessage` is a oneof: `RuleSet`, `ResponseRequest`, `HuntQuery` (Phase 6), `ConfigUpdate`.

**Versioning:** service is registered as `slither.v1.Agent`. Phase 0 freezes the *shape* of the messages; field additions are permitted under buf's breaking-change rules; removals or type changes require `slither.v2`.

**Heartbeat cadence:** 30 s default, configurable. Server marks host "stale" after 3 missed heartbeats.

**Envelope:** every event carries an agent-assigned `event_id` (UUIDv7 for natural time ordering) and two timestamps: `observed_at` (kernel timestamp of the event) and `collected_at` (agent-stamped). Skew monitoring is a Phase 5 hardening item; the fields exist from v1.

### 2.5 CI/CD

**GitHub Actions, three workflows.**

**`ci.yml`** — on every PR and push to main:
- Matrix: Ubuntu 22.04 (kernel 5.15) + Ubuntu 24.04 (kernel 6.8). Agent tests run on both to catch eBPF CO-RE regressions.
- Steps: setup Go, setup clang, install tools, `make verify-gen`, `make build`, `make test`, `make lint`.
- Cache: Go module cache + bpf2go output keyed on .c file hashes.

**`dco.yml`** — on every PR:
- Reject unsigned-off commits. Uses `probot/dco` or equivalent action.

**`release.yml`** — on tag push matching `v*`:
- Build agent + server binaries for `linux/amd64` + `linux/arm64`.
- Build container images (agent, server), push to GHCR.
- Generate SBOMs (syft).
- Sign binaries + images (cosign, keyless via GitHub OIDC).
- Draft GitHub release with binaries, SBOMs, signatures attached.
- Phase 0 does not ship releases — this workflow is scaffolded and tested with a pre-release dry-run.

**Branch protection:**
- `main` requires: passing CI, DCO, 1 review (until we have collaborators, this is enforced by repo setting not workflow).
- No force-push.

### 2.6 Dev environment

- **Docker Compose stack** at `deploy/compose/docker-compose.yml`:
  - ClickHouse (single node, default config + mounted `deploy/migrations/clickhouse/`)
  - Postgres (default config + mounted migrations)
  - Skeleton server container (Phase 0: empty binary, just proves build works)
- `make compose-up` brings the stack up; `make compose-down` tears it down + clears volumes.
- **No dev-container / nix / vagrant** in Phase 0. A `docs/dev-setup.md` lists manual prerequisites per distro. We can revisit if contributor friction warrants it.

### 2.7 Governance files

- **`LICENSE`** — already MIT.
- **`CONTRIBUTING.md`** — DCO requirement (`Signed-off-by:` trailer), PR expectations (small PRs, link ADR if decision), how to run tests, how to add a Sigma rule.
- **`SECURITY.md`** — private vulnerability reporting via GitHub Security Advisories; no email PGP requirement; response SLA ("we'll acknowledge within 72h"); scope.
- **`CODE_OF_CONDUCT.md`** — not present. Per PROJECT.md §8, deferred.
- **`docs/adr/`** — Architecture Decision Records. One per row in PROJECT.md §9.1. Short format: context → decision → consequences.

### 2.8 Phase 0 task breakdown

1. ✅ Write `go.work`, scaffold three modules with empty `main.go` files that print their name + version.
2. ✅ Write `Makefile` with entry points listed in §2.1.
3. ✅ Write `scripts/install-tools.sh` + `tools/tools.go`. *(Tool versions pinned directly in the script; tools.go kept only as an IDE hint to decouple tool installation from the linter module's transitive Go-version requirements.)*
4. ✅ Set up `buf` with `buf.yaml` + `buf.gen.yaml` + initial proto files (skeleton messages, real enums for OCSF class IDs). *(Excepted `RPC_REQUEST_STANDARD_NAME`, `RPC_RESPONSE_STANDARD_NAME`, `RPC_REQUEST_RESPONSE_UNIQUE` for bidi-stream oneof shapes.)*
5. ✅ Hand-write `pkg/ocsf/` for 8 event classes from PROJECT.md §5.1.
6. ✅ Write `.golangci.yml` with a curated, not-everything-on ruleset.
7. ✅ Write `.github/workflows/ci.yml`, `dco.yml`, `release.yml`. Release workflow runs in dry-run mode for Phase 0.
8. ✅ Write `deploy/compose/docker-compose.yml` with ClickHouse + Postgres. Add basic migrations that create empty databases.
9. ✅ Write governance files: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/dev-setup.md`.
10. ✅ Write ADRs 0001–0029 mirroring PROJECT.md §9.1.
11. ✅ Verify: fresh clone → `make tools && make ci` passes.

**Estimated effort:** small. Phase 0 is a week or two of focused work for one person who already knows the tools.

---

## 3. Phase 1 — Linux Agent MVP

**Goal:** A standalone Linux agent that collects process, file, and network events via eBPF, runs stateless Sigma-subset rules locally, and emits both raw events and detections as JSON-lines to stdout.

**Non-goals for Phase 1:**
- No server. No networking. No persistence beyond stdout.
- No stateful rules. No response actions. No self-protection.
- No container-context enrichment. No auth events. No kernel-module events. (All Phase 3 or Phase 5.)

**Exit criteria:**
1. `slither-agent --config agent.yaml` runs on Ubuntu 22.04 and 24.04 with stock kernels, emits valid OCSF JSON for process exec/exit, file create/write/delete, and TCP/UDP connect events.
2. A rule file containing 10 Sigma-subset rules loads without error. At least 5 of those rules fire deterministically against a reference attack script (`testdata/scenarios/simple-reverse-shell.sh`).
3. Event loss under synthetic load (`stress-ng --exec 100 --timeout 30s`) is < 1% and is reported in a `DiagReport`-shaped log line on shutdown.
4. Agent binary is a single static ELF ≤ 40 MB including embedded eBPF bytecode.
5. Integration test suite (`make test-integration`) runs in CI on both kernel matrix entries, loads each eBPF program, triggers known events via small scripts, and asserts emission.

### 3.1 Agent module structure

```
agent/internal/
├── collector/     # Loads eBPF programs, reads from ringbuffers, decodes raw events
├── bpf/           # eBPF C source
├── enricher/      # Adds process tree (ppid chain, exe path), hashing on exec, user resolution
├── ruleengine/    # Stateless rule matcher (Sigma subset)
├── output/        # Sinks: stdout JSON-lines
├── config/        # YAML config load + validate
└── telemetry/     # Agent self-metrics (events/sec, drops, ring occupancy)
```

Data flow: `collector → enricher → ruleengine → output` as an in-process channel pipeline. Each stage is a goroutine; channels are bounded; overflow drops the oldest low-priority item (see §3.5 on priority classes).

### 3.2 eBPF programs

Three C files in `agent/internal/bpf/src/`, compiled via `bpf2go`. All programs are CO-RE (BPF type format) compatible via `vmlinux.h` embedded in the build. Sources live in a `src/` subdirectory (not the package root) so the Go toolchain doesn't reject `.c` files in a non-cgo package — `gen.go` references them as `src/*.bpf.c -I./src/headers`, and bpf2go writes the generated Go + `.o` back into the package root.

**`process.bpf.c`** — process lifecycle.
- Hooks: `tracepoint/sched/sched_process_exec`, `tracepoint/sched/sched_process_exit`, `tracepoint/sched/sched_process_fork`.
- Emits: struct containing pid, ppid, uid, gid, tgid, comm, timestamps. Cmdline and exe path read from `bpf_probe_read_user()` of the task struct's mm (for exec); for exit, we rely on the userspace process cache.
- Map: per-CPU ringbuffer (`BPF_MAP_TYPE_RINGBUF`) for events. One 4 MB ringbuf per program is the Phase 1 default.
- Ring events carry a 16-byte header + payload; payload size bounded so we don't over-copy strings from kernel space. Cmdline truncated at 4 KB; path at `PATH_MAX`.

**`file.bpf.c`** — file system events.
- Hooks: `tracepoint/syscalls/sys_enter_openat`, `sys_enter_unlinkat`, `sys_enter_renameat2`, `sys_enter_fchmodat`, `sys_enter_fchownat`. (Opening with `O_WRONLY|O_CREAT|O_TRUNC` is the Phase 1 proxy for "write".)
- Config-driven path filter (glob list) applied in BPF via a `BPF_MAP_TYPE_LPM_TRIE` keyed on path prefix to avoid flooding on unwatched paths.
- Emits: pid, fd, path, op, flags. Resolved path is built in-BPF from the fd or pathname arg.

**`net.bpf.c`** — network events.
- Hooks: `kprobe/tcp_connect`, `kprobe/inet_csk_accept`, `kprobe/udp_sendmsg`.
- Emits: pid, saddr, sport, daddr, dport, proto, direction.
- DNS not included in Phase 1 — deferred to Phase 3 (requires parsing DNS payload or hooking `getaddrinfo`).

**Portability.**
- Target kernel floor: 5.10 (RHEL 9 / Ubuntu 22.04 LTS).
- Tracepoints preferred over kprobes where available (ABI-stable). Kprobes are used for net hooks because the tracepoints there don't carry the data we need.
- CI kernel matrix: 5.15 (Ubuntu 22.04) + 6.8 (Ubuntu 24.04). A manual test on a 5.10 machine (RHEL 9 VM) is a Phase 1 exit bar.

### 3.3 Loader / collector

`agent/internal/collector/`:
- Uses `cilium/ebpf` to load compiled programs from embedded bytecode.
- On load failure, emits a diagnostic log with kernel version, kernel features probed, and exits with nonzero. No fallback to audit or other primitives in Phase 1.
- Opens ringbuffers with `ringbuf.NewReader()`; each program has its own reader goroutine.
- Decodes raw binary events into typed Go structs (`RawProcessEvent`, `RawFileEvent`, `RawNetEvent`). These are internal types, not OCSF — OCSF conversion happens in the enricher.

### 3.4 Enricher

Ingests raw events, produces OCSF events.

- **Process tree tracking.** Internal `processCache` keyed on pid holds: exec path, cmdline, ppid, uid, start time. Cache is populated on `exec` and `fork`; evicted on `exit` (with a grace period so events arriving just after exit can still resolve).
- **Parent chain resolution.** On every event, walk ppid chain up to depth N (default 8) using the cache, producing `process.parent_process` nested objects in OCSF.
- **Hashing.** On `exec`, compute SHA-256 of the executable file async (bounded goroutine pool, 4 workers default). Cached by (inode, mtime) to avoid re-hashing. Hash attaches to the event before emission if ready within timeout (100 ms default); otherwise event emits without hash and a followup emits the hash referencing the original event_id.
- **User resolution.** uid → username via /etc/passwd snapshot, refreshed on SIGHUP.
- **No container context in Phase 1.** Placeholder field left empty.

### 3.5 Edge rule engine (stateless)

- Rules are YAML files; Phase 1 supports a **strict subset of Sigma**:
  - `logsource` restricted to `product: linux` + a `category` we recognize (`process_creation`, `file_event`, `network_connection`).
  - `detection` restricted to named selections and a final `condition` that is a boolean combination of selections. No `count()`, no `timeframe`, no `near`, no aggregation.
  - Supported field operators: `equals`, `contains`, `startswith`, `endswith`, `regex`, and list forms.
- Compiler lives in `pkg/ruleast/` with a `CompileSigma([]byte) (Rule, error)` entrypoint. Compilation is ahead-of-time at agent startup; hot reload deferred.
- At runtime, each event is evaluated against the index of rules matching its OCSF class. Rules are sorted by estimated cost (number of predicates); simpler rules run first to short-circuit.
- Rule match emits an OCSF `detection_finding` event alongside the triggering event; both go to the output sink.

**Priority classes.** Internal queue between stages carries a `Priority` tag: `Detection > Event > Heartbeat`. Overflow drops lowest priority first. Detections are never dropped — if the detection queue is full, the agent exits with a diagnostic.

### 3.6 Output

- **Phase 1 single sink:** stdout, one JSON object per line. Heavy events (hash computations arriving late, diagnostic reports) go to the same stream with a `meta.event_kind` discriminator.
- Output goroutine uses `bufio.Writer` with `Flush()` on SIGTERM + every N events.
- File-based JSON-lines output is a trivial config addition but isn't required for Phase 1 exit.

### 3.7 Configuration

`agent.yaml`:

```yaml
agent:
  host_id_file: /var/lib/slither/host_id
  log_level: info
collectors:
  process:
    enabled: true
  file:
    enabled: true
    include_paths:
      - /etc/**
      - /usr/bin/**
      - /usr/sbin/**
      - /root/**
      - /home/**
    exclude_paths:
      - /proc/**
      - /sys/**
  net:
    enabled: true
rules:
  paths:
    - /etc/slither/rules/*.yml
output:
  kind: stdout
```

Validated at startup via a schema in `pkg/config/`. Errors are actionable ("unknown key `collecor` — did you mean `collector`?").

### 3.8 Packaging

- Single static ELF via `CGO_ENABLED=0 go build`. eBPF C is compiled at `make gen` time into `.o` bytecode, embedded via `go:embed` into the binary.
- **No `.deb` / `.rpm` in Phase 1.** Install = copy binary + write systemd unit + write config. Packaging is Phase 5.
- Systemd unit at `deploy/systemd/slither-agent.service` runs as root, uses `CapabilityBoundingSet` to restrict to what's actually needed (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` for exe path reads, `CAP_DAC_READ_SEARCH` for hashing), and disables `NoNewPrivileges=no` (we need it *off* to load BPF on some kernels — document why).

### 3.9 Testing strategy

**Unit tests** (fast, no kernel):
- `pkg/ruleast/`: Sigma compiler golden tests — 20+ input rules compiled, compared to expected AST JSON.
- `agent/internal/enricher/`: process tree resolution, hashing cache, user resolution against a fake /etc/passwd.
- `pkg/ocsf/`: validation, field presence, class ID routing.

**Integration tests** (require root + real kernel):
- Live in `agent/internal/collector/*_integration_test.go`, gated by `//go:build integration`.
- Each test loads a single eBPF program, triggers the relevant syscall in a child process, reads the ringbuffer, asserts event content.
- CI runs these with `sudo -E go test -tags=integration` on privileged runners.

**Scenario tests** (end-to-end, single-host):
- `testdata/scenarios/` holds small bash scripts representing attack patterns: reverse shell, suid escalation, ssh credential stuffing (simulated), config file tamper.
- Test harness starts agent, runs scenario, captures stdout for 30s, asserts expected detection IDs fired in expected order.

**Load test:**
- `make load-test` runs the agent against `stress-ng --exec 100 --timeout 30s` and measures drop rate + CPU. Not run in CI; operator-run baseline.
- Host sizing for the documented `<1%` drop-rate exit bar: **4 vCPUs + 4 GB RAM minimum**. On smaller hosts stress-ng's `--exec` workers contend with the agent for CPU and (on <2 GB VMs) self-skip under the memory-pressure heuristic. Smaller boxes may still run the test but the number is not comparable.

### 3.10 Kernel compatibility matrix

| Distro | Kernel | Target | Phase 1 exit bar |
|---|---|---|---|
| Ubuntu 22.04 | 5.15 | CI | Must pass |
| Ubuntu 24.04 | 6.8 | CI | Must pass |
| RHEL 9 / Rocky 9 | 5.14 | Manual | Must pass (loader loads, events emit) |
| Debian 13 | 6.12 | Manual | Must pass |
| RHEL 8 / Amazon Linux 2 | 4.18 | Not supported | Documented unsupported; no CO-RE |

BTF availability is the hard floor. Kernels without `/sys/kernel/btf/vmlinux` are unsupported; we do not ship BTF blobs in v1.

### 3.11 Phase 1 task breakdown

1. ✅ Scaffold `agent/internal/` subpackages with interfaces only, empty implementations. *(Completed 2026-04-21: pipeline/config/telemetry/bpf/collector/enricher/ruleengine/output/app packages; orchestrator wired under a cancellable context; main takes `--config`/`--version`.)*
2. ✅ Write `process.bpf.c`, `bpf2go` integration, minimal collector that prints raw events. *(Completed 2026-04-21: sched_process_{exec,exit,fork} tracepoints → 4MB ringbuf; bpf2go wired via `make gen-bpf`; vendored `bpf_helpers.h` + bpftool-generated `vmlinux.h` under `agent/internal/bpf/src/` so Go toolchain ignores `.c` files in the package; collector loads/attaches/drains with select-default drop onto `RawProcessEvent` channel.)*
3. ✅ Flesh out process-event enricher (process cache + parent chain), emit OCSF `process_activity`. *(Completed 2026-04-21: pid-keyed `procCache` with upsert-merge + delayed-eviction; /proc-backed ppid/exe/cmdline backfill on exec and child-comm refresh on fork; atomic `/etc/passwd` snapshot with SIGHUP reload; OCSF builder with depth-bounded parent chain, actor population, and exit-code passthrough; hostname/arch device stamp wired in `app.deviceIdentity`; unit tests cover cache merge/eviction/resurrection, passwd reload, activity-id mapping, exec/exit build paths, and depth-8 cap.)*
4. ✅ Build `pkg/ruleast/` Sigma compiler for the stateless subset + golden tests. *(Completed 2026-04-21: `CompileSigma([]byte) (*Rule, error)` produces a boolean AST (`NodeAnd`/`NodeOr`/`NodeNot`/`NodeSelection`) from selections with `equals/contains/startswith/endswith/regex` modifiers; condition tokeniser+parser accepts and/or/not/parens over named selections and rejects `"N of"`, `"them"`, pipe operators, `timeframe`, list-of-maps selections, unsupported Sigma modifiers (`all`/`cased`/`base64*`/utf16 variants) with `ErrCompile`-wrapped errors. 22-rule golden corpus under `testdata/rules/` covers all three Phase 1 categories and compile-path variants; 11 invalid fixtures cover rejection paths. Runtime `Rule.Match(Env)` honours Sigma's case-insensitive string semantics and short-circuits via a cost-aware AST.)*
5. ✅ Wire rule engine into pipeline; emit `detection_finding` events. *(Completed 2026-04-21: `agent/internal/ruleengine` wraps `*ruleast.Rule` in `sigmaCompiledRule`, indexes rules by OCSF `ClassID`, sorts each bucket cheap-first by `Rule.Cost()`. Sigma→OCSF field taxonomy (`fields.go`) covers process_creation / file_event / network_connection; an `ocsfEnv` adapts events to `ruleast.Env`. `engine.Run` does non-blocking Event-priority sends (drop-on-full + telem bump) and bounded Detection-priority sends (200 ms wait, then `ErrDetectionQueueFull` so the agent exits with a diagnostic per §3.5). `buildFinding` projects matches into `ocsf.DetectionFinding` with random 128-bit UIDs, severity mapped from Sigma level, and triggering-event id carried through. `app.loadRules` compiles rules from `cfg.Rules.Paths` globs at startup.)*
6. Add `file.bpf.c` + enrichment + rule-engine integration.
7. Add `net.bpf.c` + enrichment + rule-engine integration.
8. Implement hashing worker pool + OCSF hash attachment (+ followup event pattern).
9. Config loader + validation + reasonable errors.
10. ✅ Systemd unit, capability bounding, install docs. *(Completed 2026-04-22: `deploy/systemd/slither-agent.service` runs as root with `CapabilityBoundingSet`+`AmbientCapabilities` restricted to CAP_BPF/CAP_PERFMON/CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH, `NoNewPrivileges=no` with an in-unit comment explaining the RHEL-9/5.14 `BPF_PROG_LOAD`+`no_new_privs` incompatibility, BTF `ConditionPathExists`, `ExecReload=kill -HUP` for rule/filter hot reload, and systemd hardening directives (`ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernelLogs`, `RestrictSUIDSGID`, `LockPersonality`, `StateDirectory=slither`) layered on top. `deploy/config/agent.yaml.sample` ships §3.7 verbatim. `docs/install.md` walks copy-binary → write-config → enable-unit, documents the `SLITHER_*` env-var overrides and SIGHUP reload scope (rules + file filters only), and covers uninstall + common failure modes.)*
11. ✅ Integration test harness + CI wiring for privileged runners. *(Completed 2026-04-22: `//go:build linux && integration` test files per collector. `integration_harness_test.go` provides `requirePrivileged` (skips when non-root or no BTF), a `startCollector` helper that runs `Collector.Run` in a goroutine with a 2s cancel-wait, and a generic `waitForEvent` drainer with per-test timeout. `process_integration_test.go` execs `/bin/true` and asserts a matching `ProcExec` + `ProcExit` for the child PID. `file_integration_test.go` drives `openat`/`unlinkat` against a tempfile via `golang.org/x/sys/unix` and asserts decoded `FileOpen*`/`FileUnlink` with path match. `net_integration_test.go` dials a local listener and asserts a `NetTCPConnect` for 127.0.0.1:<port>. `.github/workflows/ci.yml` `integration` job flipped from `if: false` to `needs: build-test-lint`; runs on GH-hosted `ubuntu-24.04` (BTF + sudo bpf(2) exposed), regenerates bpf2go on the runner so embedded `.o` matches the runner's clang, then `sudo -E make test-integration`. Self-hosted runner kept as contingency.)*
12. ✅ Scenario tests + 10 bundled Sigma rules under `rules/linux/`. *(Completed 2026-04-22: implemented the real `output.stdoutSink.Run` — bufio JSON-lines with per-event flush (was a stub carried over from task #17). `rules/linux/` ships 10 compiler-validated Sigma rules (5 process_creation: bash /dev/tcp reverse shell, nc/ncat/socat -e, curl-pipe-to-shell, find -perm -4000 SUID discovery, chmod world-writable; 4 file_event: authorized_keys write, /etc/cron.* persistence, /etc/shadow access, rc-file persistence; 1 network_connection: cloud metadata IMDS egress). `testdata/scenarios/` has three harmless bash scripts (bash→/dev/tcp/127.0.0.1/1, find -perm -4000 maxdepth-2, authorized_keys write under a tempdir) with a README documenting the contract. `agent/internal/app/scenario_test.go` (build tag `integration`) builds the agent binary once, launches it per subtest with a tempdir config pointing at the bundled rule pack, waits 800 ms for tracepoints to attach, runs the scenario via bash, and scans the agent's JSON-lines stdout for a DetectionFinding whose `rule.uid` matches the expected UID, all under a 20 s context deadline. Skips when not root or when BTF is missing.)*
13. ✅ Load test script + documented baseline. *(Completed 2026-04-22: `scripts/load-test.sh` runs `stress-ng --exec N --timeout Ds` against the agent, samples agent CPU% + RSS via `ps` at 1 Hz, waits for the agent to print its final `telemetry: events=…` DiagReport line on SIGTERM, and prints a summary block (events / drops / detections / ringbuf overflows / drop-rate % / mean+peak CPU / peak RSS). `make load-test` target wired. `docs/load-test.md` documents methodology, the Phase 1 exit criterion of <1% drop rate on a 4-core host, and the three common drop-rate failure modes (ringbuf sizing, enricher saturation, rule-engine event queue backpressure). `app.Run` now dumps the final Counter snapshot to stderr on every exit path (exit-criterion #3 per §3.5) so both operators and the load test share the same reporting surface.)*
14. Phase 1 exit validation on RHEL 9 and Debian 13 (manual). *(Debian 13 partial 2026-04-22: kernel `6.12.74+deb13+1-amd64`, service active (running) for 18m under the shipped unit with CAP_BPF/CAP_PERFMON/CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH bounded, OCSF `process_activity` emitted for `/bin/true` (class_uid 1007, actor chain bash→gnome-terminal-→systemd), and a real `DetectionFinding` (class_uid 2004, `rule.uid` `8b7c4d00-0001-4000-8000-000000000001` — "Bash reverse shell via /dev/tcp", severity_id 4, with `x_triggering_event_ids` linking back to the process event) fired against the shipped reverse-shell scenario. Loader required `kernel.perf_event_paranoid=2` (Debian defaults to 3, fix shipped in `deploy/sysctl.d/99-slither.conf` at `87e97fa`). Still outstanding on Debian 13: `make load-test` drop_rate_pct. RHEL 9 validation not yet started.)*

**Estimated effort:** 6–10 weeks of focused work for one person. The eBPF CO-RE portability work and the Sigma compiler are the two biggest unknowns; budget slack there.

---

## 4. Phase 2 — Server MVP (bullet)

**Goal:** events flow agent → server → ClickHouse; basic HTMX console; mTLS enrollment works end-to-end.

- Agent gains gRPC transport module; swaps stdout for network by config.
- Server ingest service: receives events, writes to ClickHouse in batches (tuned batch size + flush interval).
- Server control plane: Postgres schema for hosts, users, enrollment tokens, rules, alerts, audit log.
- mTLS CA setup: `scripts/gen-ca.sh` bootstraps a local CA; enrollment endpoint signs per-host client certs from single-use tokens.
- Console: `templ` layout shell, auth login, live tail page (SSE), events search page (paginated ClickHouse queries), host inventory page.
- `docker compose up` brings the whole stack online with a seeded admin user.
- Tailwind compile wired into `make gen` via standalone CLI.
- RBAC seeded with three roles (viewer, analyst, admin) but only enforced at endpoint level; row-level authorization deferred.

## 5. Phase 3 — Detection (bullet)

**Goal:** full Sigma (not just subset), edge/server partitioning, alerts with flow graphs, bounded-stateful on edge.

- Sigma compiler promoted from subset to full (within the partitioning policy of PROJECT.md §3.6).
- Compiler emits two artifacts per rule: edge bytecode (if eligible) and server plan.
- Edge rule engine gains bounded-stateful evaluation (`count()` with `timeframe`, bounded per host + rule).
- Server detection engine: stream-based, consumes ingest bus (in-process channel), emits alerts.
- Alert lifecycle: new → acknowledged → in-progress → closed, with reason codes and operator attribution.
- Detection flow graph: server builds DAG of events linked to an alert, renders via D2 to SVG, caches.
- Process-tree mini-graph endpoint uses same D2 pipeline.
- Small IOC feed push (hashes, IPs ≤ 100k entries) to agents via control stream.

## 6. Phase 4 — Response (bullet)

**Goal:** manual response primitives; opt-in immediate response from edge.

- Response executor in agent: kill pid / pid tree, quarantine file (move to encrypted local staging), isolate host (netfilter rules allowing only mgmt traffic), collect artifact bundle (pid memory dump via `/proc/[pid]/mem` where permitted, /proc snapshot, recent journal, process tree).
- Operator UI: response buttons on alert detail, confirmation modal for destructive actions, pending/running/done status.
- Audit log: every response recorded with operator identity, time, target, result.
- `immediate: true` + `auto_respond: true` edge firing path: edge evaluates, executes, streams both action record and triggering event to server.
- Response reversal where possible (un-isolate, un-quarantine).

## 7. Phase 5 — Hardening (bullet)

- Agent self-protection: `PR_SET_DUMPABLE=0`, cap bounding, lockdown on critical files, tamper-evident logs (hash chain flushed before shutdown).
- Offline buffering: on-disk ringbuffer at `/var/lib/slither/buffer`, replay on reconnect, bounded size with oldest-wins drop.
- Backpressure: end-to-end from output back to eBPF (raise sampling on low-priority classes when downstream is slow).
- Reproducible builds: pinned Go toolchain, pinned `llvm`/`clang`, `-trimpath`, `-buildvcs=true`, `-mod=readonly`.
- Signed releases: cosign keyless via GitHub OIDC.
- SBOM generation: syft, attached to release.
- `.deb` + `.rpm` packages (nfpm).
- Hardening docs, threat model doc (`docs/threat-model.md`).

## 8. Phase 6 — Extensions & Console Expansion (bullet)

- Agent extension interface (`proto/slither/v1/extension.proto`): unix socket, protobuf, capability-gated, signature-checked, supervised with backoff.
- Reference extension: osquery bridge. Subscribes to curated tables, maps to OCSF via extension-side mappers, emits through agent.
- Live-query hunt: server-dispatched osquery over bridge, aggregated in console.
- Forensic snapshot-on-alert: alert rule can trigger a one-shot capture through enabled extensions.
- Fully-interactive live process-tree explorer.
- Saved queries + dashboards in console.

## 9. Phase 7 — Platform Expansion (bullet, demand-driven)

- macOS agent (Endpoint Security framework; Apple Developer ID required).
- Windows agent (ETW-first; minifilter driver only if kernel-level file-write telemetry is needed; driver signing via EV cert).
- Explicitly gated on demand + funding; not on the default trajectory.

---

## 10. Deferred Technical Questions

Things we know we will need to answer but do not need to answer *now*:

1. **Rule hot reload.** Phase 1 loads rules at startup only. Phase 3 needs reload without agent restart. Choose between SIGHUP-based reload vs. watched file vs. server-pushed. Decide at Phase 3 entry.
2. **On-agent TLS cert storage.** Phase 2 bootstraps certs into `/etc/slither/`. Phase 5 may require kernel keyring or TPM-sealed storage. Decide at Phase 5 entry.
3. **ClickHouse schema evolution.** Phase 2 picks an initial schema; OCSF version bumps will force migrations. Build a migration harness at Phase 5, not before.
4. **Cardinality and retention controls in ClickHouse.** Phase 2 assumes defaults. Tune at Phase 3 once real event volumes are observable.
5. **Rule distribution signing.** Phase 3 pushes rules over the control channel. Whether rules themselves need individual signatures vs. trusting the server is a Phase 5 decision.
6. **Extension binary distribution.** Phase 6 extensions are config-declared + signature-checked. Whether they live on disk via OS package manager or are pushed by the server is a Phase 6 decision.
7. **Console auth backends.** Phase 2 ships local-users-only. SSO (OIDC) is a plausible Phase 5 or 6 addition.

---

## 11. Milestone Sequencing

Rough calendar shape, assuming one committed developer. Durations are planning targets, not commitments.

| Phase | Target duration |
|---|---|
| Phase 0 — Foundations | 1–2 weeks |
| Phase 1 — Linux agent MVP | 6–10 weeks |
| Phase 2 — Server MVP | 6–8 weeks |
| Phase 3 — Detection | 6–8 weeks |
| Phase 4 — Response | 4–6 weeks |
| Phase 5 — Hardening | 4–6 weeks |
| **v1.0 release candidate** | — |
| Phase 6 — Extensions & console expansion | 6–10 weeks |
| Phase 7 — Platform expansion | indefinite |

v1.0 ships after Phase 5, as a **Linux-only, self-hosted, single-node EDR with working eBPF collection, Sigma detection (edge + server), manual + opt-in immediate response, and hardened agent**. That's the minimum coherent product. Extensions and cross-platform are deliberately above the v1.0 line.

---

## 12. How we'll re-plan

- Each phase entry prompts a re-plan: updated tasks, updated risks, updated exit criteria based on what Phase N-1 actually taught us.
- The existing phase's plan doesn't get rewritten in-place — it gets an addendum (`PHASE-N-ADDENDUM.md` or appended section) so history is preserved.
- ADRs are written as decisions arise during implementation, not only at design time.
