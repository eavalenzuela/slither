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
- Target kernel floor: **5.15** (Ubuntu 22.04 LTS / RHEL 10). Raised from 5.10 on 2026-04-22 after RHEL 9's 5.14 verifier rejected our per-syscall tracepoint programs with `max_ctx_offset`/`PTR_TO_CTX` checks that 5.15+ handles cleanly. RHEL 9 support is deferred; users should deploy on RHEL 10 (6.12) instead.
- Tracepoints preferred over kprobes where available (ABI-stable). Kprobes are used for net hooks because the tracepoints there don't carry the data we need.
- CI kernel matrix: 5.15 (Ubuntu 22.04) + 6.8 (Ubuntu 24.04). Manual validation on RHEL 10 / 6.12 is a Phase 1 exit bar.

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
| RHEL 10 / Rocky 10 | 6.12 | Manual | Must pass (loader loads, events emit) |
| Debian 13 | 6.12 | Manual | Must pass |
| RHEL 9 / Rocky 9 | 5.14 | Not supported | Verifier rejects per-syscall tracepoints with `max_ctx_offset`/`PTR_TO_CTX` checks that 5.15+ handles cleanly; retarget to RHEL 10. |
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
10. ✅ Systemd unit, capability bounding, install docs. *(Completed 2026-04-22: `deploy/systemd/slither-agent.service` runs as root with `CapabilityBoundingSet`+`AmbientCapabilities` restricted to CAP_BPF/CAP_PERFMON/CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH, `NoNewPrivileges=no` with an in-unit comment explaining a legacy `BPF_PROG_LOAD`+`no_new_privs` incompatibility on some 5.x kernels, BTF `ConditionPathExists`, `ExecReload=kill -HUP` for rule/filter hot reload, and systemd hardening directives (`ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernelLogs`, `RestrictSUIDSGID`, `LockPersonality`, `StateDirectory=slither`) layered on top. `deploy/config/agent.yaml.sample` ships §3.7 verbatim. `docs/install.md` walks copy-binary → write-config → enable-unit, documents the `SLITHER_*` env-var overrides and SIGHUP reload scope (rules + file filters only), and covers uninstall + common failure modes.)*
11. ✅ Integration test harness + CI wiring for privileged runners. *(Completed 2026-04-22: `//go:build linux && integration` test files per collector. `integration_harness_test.go` provides `requirePrivileged` (skips when non-root or no BTF), a `startCollector` helper that runs `Collector.Run` in a goroutine with a 2s cancel-wait, and a generic `waitForEvent` drainer with per-test timeout. `process_integration_test.go` execs `/bin/true` and asserts a matching `ProcExec` + `ProcExit` for the child PID. `file_integration_test.go` drives `openat`/`unlinkat` against a tempfile via `golang.org/x/sys/unix` and asserts decoded `FileOpen*`/`FileUnlink` with path match. `net_integration_test.go` dials a local listener and asserts a `NetTCPConnect` for 127.0.0.1:<port>. `.github/workflows/ci.yml` `integration` job flipped from `if: false` to `needs: build-test-lint`; runs on GH-hosted `ubuntu-24.04` (BTF + sudo bpf(2) exposed), regenerates bpf2go on the runner so embedded `.o` matches the runner's clang, then `sudo -E make test-integration`. Self-hosted runner kept as contingency.)*
12. ✅ Scenario tests + 10 bundled Sigma rules under `rules/linux/`. *(Completed 2026-04-22: implemented the real `output.stdoutSink.Run` — bufio JSON-lines with per-event flush (was a stub carried over from task #17). `rules/linux/` ships 10 compiler-validated Sigma rules (5 process_creation: bash /dev/tcp reverse shell, nc/ncat/socat -e, curl-pipe-to-shell, find -perm -4000 SUID discovery, chmod world-writable; 4 file_event: authorized_keys write, /etc/cron.* persistence, /etc/shadow access, rc-file persistence; 1 network_connection: cloud metadata IMDS egress). `testdata/scenarios/` has three harmless bash scripts (bash→/dev/tcp/127.0.0.1/1, find -perm -4000 maxdepth-2, authorized_keys write under a tempdir) with a README documenting the contract. `agent/internal/app/scenario_test.go` (build tag `integration`) builds the agent binary once, launches it per subtest with a tempdir config pointing at the bundled rule pack, waits 800 ms for tracepoints to attach, runs the scenario via bash, and scans the agent's JSON-lines stdout for a DetectionFinding whose `rule.uid` matches the expected UID, all under a 20 s context deadline. Skips when not root or when BTF is missing.)*
13. ✅ Load test script + documented baseline. *(Completed 2026-04-22: `scripts/load-test.sh` runs `stress-ng --exec N --timeout Ds` against the agent, samples agent CPU% + RSS via `ps` at 1 Hz, waits for the agent to print its final `telemetry: events=…` DiagReport line on SIGTERM, and prints a summary block (events / drops / detections / ringbuf overflows / drop-rate % / mean+peak CPU / peak RSS). `make load-test` target wired. `docs/load-test.md` documents methodology, the Phase 1 exit criterion of <1% drop rate on a 4-core host, and the three common drop-rate failure modes (ringbuf sizing, enricher saturation, rule-engine event queue backpressure). `app.Run` now dumps the final Counter snapshot to stderr on every exit path (exit-criterion #3 per §3.5) so both operators and the load test share the same reporting surface.)*
14. ✅ Phase 1 exit validation on RHEL 10 and Debian 13 (manual). *(RHEL 10 complete 2026-04-22: kernel `6.12.0-124.52.1.el10_1.x86_64`, service active under the shipped unit, OCSF `process_activity` (class_uid 1007) emitted cleanly for exec/fork/exit with full actor parent chains, real `DetectionFinding` (class_uid 2004, `rule.uid` `8b7c4d00-0001-4000-8000-000000000001` — "Bash reverse shell via /dev/tcp") fired against the shipped reverse-shell scenario. Functional criteria pass identically to Debian 13. **Load-test known variance:** Eight optimisation passes (task #15 steps 1–8 plus unsafe-pointer decode and cache shard count 16→64) took RHEL 10 from 34.79% → 11.61% drops on this 4 vCPU / 4 GB VM; further tuning exhausted cheap levers. Successful throughput ceiling on RHEL 10 is ~6k events/s vs Debian 13's ~12k/s under identical stress-ng load — the delta is inherent to this VM's CPU-per-goroutine scheduling rather than any single agent stage. Documented in `docs/load-test.md` §"Known variance: RHEL 10 on 4-vCPU VMs"; production deployments should run on hosts with more than 4 vCPUs, and Phase 5 may revisit with a kernel scheduler trace. Raw outputs in `rhel_10_phase1_validation` at repo root.)* *(Debian 13 complete 2026-04-22: kernel `6.12.74+deb13+1-amd64`, service active under the shipped unit with CAP_BPF/CAP_PERFMON/CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH bounded. OCSF `process_activity` (class_uid 1007) confirmed for `/bin/true` with full actor chain. Real `DetectionFinding` (class_uid 2004, `rule.uid` `8b7c4d00-0001-4000-8000-000000000001` — "Bash reverse shell via /dev/tcp", severity_id 4, `x_triggering_event_ids` linking back to the process event) fired against the shipped reverse-shell scenario. `make load-test` produced `drop_rate_pct=0.09%` (see task #15 for the optimisation work that got us there). Loader required `kernel.perf_event_paranoid=2` (Debian defaults to 3, fix shipped in `deploy/sysctl.d/99-slither.conf` at `87e97fa`). Raw outputs in `debian_13_phase1_validation` at repo root. **RHEL 10 validation still pending** — RHEL 9 was originally targeted but its 5.14 verifier rejected our per-syscall file tracepoints with `max_ctx_offset`/`PTR_TO_CTX` checks that 5.15+ handles cleanly; retargeted to RHEL 10 (6.12) which matches the Debian 13 kernel family.)*
15. ✅ Enricher worker pool — pid-sharded parallel /proc backfill. *(Completed 2026-04-22 after task #29 Debian 13 load test measured 46.08% drop rate at 11k events/s with `ringbuf_overflow=0` and peak_cpu=6.9% on a 4-core host. Root cause: single-goroutine enricher Run loop serialised three `/proc/<pid>/{status,exe,cmdline}` reads per ProcExec, producing an I/O-bound ceiling of ~6k events/s. Fix landed in five passes:
    1. Pid-sharded worker pool (default 4, bumped to 8). Dispatcher in Run routes by `pid % N`; per-pid exec-before-exit order preserved. Drop rate on Debian 13: 46% → 34%.
    2. Per-stage drop attribution (`IncDropCollector/Dispatch/Enricher/Engine`) + bigger pipeline buffers (collector 1024→8192, enricher.out / engine.out 2048→16384, ProcessInboxSize 1024→2048). Drop rate: 34% → 21%, 100% of residual attributed to `dispatch`.
    3. Per-event `/proc` parallelism: cache-first ppid (fork events already populate it), concurrent `go`-spawned reads of `exe` + `cmdline` + optional `ppid` collapsed from serial to max-latency via `sync.WaitGroup`. Stacks with (1) for ~3× worker throughput.
    4. Lock-striped procCache: 16 shards keyed by `pid & 15`, each with its own `sync.RWMutex`. The single RWMutex was the dominant remaining contention point — at ~9k events/s × (1 upsert + 1 rebuild get + up to 8 parent-chain gets) = ~90k lock ops/s through one lock. Sharding removes contention for any workers operating on different pids; stress-ng's sequential pid allocation distributes uniformly across shards.
    5. ProcessWorkers default 8 → 16 → 32. After cache contention was removed, each worker's per-event cost was dominated by kernel /proc-read latency under stress-ng's fork storm (~1 ms/event), and mean agent CPU was 20% on a 4-core host — ~3 cores idle. Doubling workers parallelises more concurrent /proc reads into the kernel without touching the critical path. 8→16 took 20.6% → 5.36%; bumping again to 32 targets the remaining gap to <1%.
    6. Dedicated process-dispatcher goroutine. RHEL 10 load-test revealed a second bottleneck invisible at Debian's ~12k events/s: the enricher's main Run goroutine shared its single select between process dispatch AND inline file/net event handling (each doing /proc reads + cache + emit). Under RHEL 10's ~24k events/s, file/net handling stalls the loop long enough that cg.Process fills and the collector drops at the ringbuf-drain boundary (observed as `by_stage collector=…` attribution). Moving the `procIn` reader into its own goroutine keeps process dispatch running while file/net events are enriched in parallel on the main loop. Drops shifted 252k → 54k at collector and 0 → 182k at dispatch — i.e. the dispatcher is no longer the ceiling, but the 32 workers can't sustain RHEL's 17k events/s enrichment rate at only ~26% of a 4-core host's CPU (kernel /proc latency dominates).
    7. ProcessWorkers default 32 → 64. Second doubling for RHEL 10's higher kernel event rate; workers remain I/O-bound on kernel /proc serving, and the 4-core host still has ~3 cores of headroom at 26% CPU so scheduler oversubscription is well within Go's tolerance.
    8. BPF-side exe + cmdline capture. The sched_process_exec tracepoint carries the exec filename in its `__data_loc_filename` arg, and the kernel keeps argv between `current->mm->arg_start` and `arg_end`. `process.bpf.c` now reads both into the wire record (`exe[128]` + `cmdline[256]` with a `cmdline_len` marker); the collector decodes argv's null-separated bytes into a space-separated string. Enricher takes the short-circuit path when BPF supplied both: zero /proc syscalls on exec in the common case (vs. up to three before), falling back to /proc only on cold paths (kthreads, very long paths, mm unreadable). Exe alone was insufficient because the parallel /proc reads had cmdline as their latency floor — removing only the faster readlink left max-latency unchanged.
    Cache is already `sync.RWMutex`, userResolver uses `atomic.Value`, procReader is stateless — no new synchronisation needed. Exposed via `Options.ProcessWorkers` / `ProcessInboxSize` with zero-value defaults; unit test under `-race` verifies per-pid ordering across 64 interleaved pids. Final measurement on Debian 13 kernel 6.12: `drop_rate_pct=0.09%` (357582 events / 323 drops, all dispatch-stage residual), mean CPU 29.0% / peak 36.4% on a 4 vCPU / 4 GB host — clears exit criterion #3 with a 10× margin. Progression across the five passes: 46.08% → 20.64% → 16.58% → 5.36% → 0.09%.)*

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

### 4.1 Phase 2 task breakdown

Task numbering continues from Phase 1 (which closed at #30). Dependency graph:
- **A. Transport & enrollment:** #31 → #33 → #34 → #35 → #36
- **B. Storage:** #32 and #38 after #31
- **C. Ingest:** #37 after A + B
- **D. Console:** #40 → #41 → #42/#43/#44 → #45 after A + B
- **E. Control plane:** #39 after #32 + #35
- **Exit gate:** #46 after all

1. **#31 — Server scaffold.** Mirror the agent's `internal/` layout: `server/internal/{app,config,grpcserv,store,ingest,console,mtls}`. Wire `cmd/slither-server/main.go` to a real `app.Run(ctx, configPath)` with signal handling and a final counters snapshot (parallel to the agent's telemetry surface). Config loader is yaml.v3 + `KnownFields(true)` + Levenshtein typo suggestions (copy the pattern from `agent/internal/config`). Add `make build-server`, `make test-server`. **Exit:** `slither-server --config …yaml` starts, logs, SIGTERM-drains cleanly, zero RPCs yet.

2. **#32 — Postgres schema + migration harness.** `server/internal/store/pg/` with pgx/v5. Tables per §4: `hosts`, `users`, `enrollment_tokens` (single-use, TTL, hashed), `rules` (yaml source + compiled bytecode blob + enabled flag), `alerts` (new/ack/in-progress/closed per §5), `audit_log`. Migrations live at `server/migrations/` using `pressly/goose` (sql-only — keeps schema reviewable). `make db-migrate` + `make db-reset`. ADR `docs/adr/0030-postgres-schema-v1-and-migrations.md` for the initial schema so Phase 5 migration harness has a baseline. **Exit:** `docker run postgres` + `make db-migrate` → all tables exist; store-package tests pass against ephemeral pg via testcontainers-go.

3. **#33 — mTLS CA bootstrap.** `scripts/gen-ca.sh` generates a P-256 root CA + server cert into `deploy/pki/` (gitignored). `server/internal/mtls/` loads CA key + cert from config paths, exposes `SignCSR(csrPEM, hostID, ttl) ([]byte, error)` enforcing: CSR key type ∈ {P-256, Ed25519}, CN == host_id, no SAN. gRPC listener uses `tls.Config{ClientAuth: RequireAndVerifyClientCert}` but Enroll RPC accepts unauthenticated clients on a **separate** listener/port (enrollment is pre-cert). **Exit:** unit tests cover happy path + wrong-CN + weak-key rejection; `scripts/gen-ca.sh` is idempotent.

4. **#34 — Server `Enroll` RPC.** Implement `AgentService.Enroll` on the enrollment listener: look up token by hash in `enrollment_tokens`, check unused + not-expired, `SELECT … FOR UPDATE` to burn it, insert `hosts` row with fingerprint, call `SignCSR`, return chain. Audit-log every attempt (success and failure reason). **Exit:** integration test against ephemeral pg + in-proc grpc: valid token → cert; reused token → `FailedPrecondition`; expired → same.

5. **#35 — Agent gRPC transport output sink.** New `agent/internal/output/grpc/` implementing the existing `output.Sink` interface. Config: `output.kind: grpc` with sub-fields `server_addr`, `ca_path`, `cert_path`, `key_path`, `host_id_path`. Opens `AgentService.Session`, marshals `ocsf.Event` → `Envelope` (proto types already exist under `proto/slither/v1/gen/`), sends as `ClientMessage.Event`. Heartbeat goroutine at config-driven cadence (default 30 s per §2.4). Reconnect backoff: exponential 1s → 60s, jittered; events buffered into a bounded channel during disconnect (drop-oldest to preserve existing telemetry invariants). `stdout` sink stays selectable (needed for dev + scenario tests). **Exit:** agent configured with `kind: grpc` against a stub server streams events end-to-end; killing the server mid-stream → agent reconnects; `dropped` counter increments when the buffer fills.

6. **#36 — Agent enrollment first-run flow.** New CLI subcommand `slither-agent enroll --token … --server …`. Generates P-256 key, builds CSR (CN set by server, blank client-side), calls `Enroll`, writes `client.key` (0600), `client.crt`, `ca.crt`, `host_id` into `/var/lib/slither/` (matches StateDirectory from the systemd unit). `docs/install.md` gets an "Enroll this host" section. **Exit:** manual flow on a dev box against docker-compose server produces usable certs; `slither-agent run` then connects without further config changes.

7. **#37 — Server ingest Session handler + in-proc bus.** `server/internal/ingest/`: `AgentService.Session` handler consumes `ClientMessage`, routes Envelope → bus, Heartbeat → hosts.last_seen update, Ack → outstanding-ResponseRequest tracker (stub OK for Phase 2), DiagReport → audit_log. Bus is a fan-out in-process channel with a subscriber registry (the ClickHouse writer and the live-tail SSE are the two Phase 2 subscribers). Backpressure: slow subscriber → its per-conn queue fills → that subscriber drops, incrementing a subscriber-specific counter; ingest never blocks upstream. **Exit:** 2 concurrent fake agents stream 10k events each; both land on the bus; telemetry counters exposed via `/metrics` (prometheus textfile is fine for Phase 2).

8. **#38 — ClickHouse schema + batched writer.** `server/internal/store/ch/`: one table per OCSF class shipped in Phase 1 (`ocsf_process_activity_1007`, `ocsf_file_activity_1001`, `ocsf_network_activity_4001`, `ocsf_detection_finding_2004`) with shared columns (`event_id UUID`, `host_id`, `observed_at DateTime64(9)`, `collected_at DateTime64(9)`, `class_uid UInt32`, `severity_id UInt8`, `raw String` for full OCSF JSON) plus class-specific materialized columns for search hot paths. Partition by `toYYYYMMDD(observed_at)`, ORDER BY `(host_id, observed_at)`. Writer is a bus subscriber with batch size (default 10k) + flush interval (default 2 s), whichever fires first; `async_insert=1` on the CH side. Migrations via `golang-migrate/migrate` (CH driver), `make ch-migrate`. ADR `docs/adr/0031-clickhouse-schema.md`. **Exit:** integration test via testcontainers CH: 50k events in, rowcount matches, `SELECT count() WHERE host_id=…` correct.

9. **#39 — Control plane: rule distribution over Session.** Server loads enabled rules from the `rules` table on boot + on `NOTIFY rules_changed`, compiles via the existing `pkg/ruleast`, and sends `ServerMessage.RuleSet` to every live Session on change. Agent applies via the already-shipped `engine.ReplaceRules` (#24). Initial RuleSet is sent at Session-open so freshly-connected agents converge. **Exit:** insert a rule row → every connected agent receives it within 1 s; toggle `enabled=false` → agent drops it; unit test for the compile-once-push-to-N-sessions path.

10. **#40 — docker compose stack.** `deploy/compose/docker-compose.yml`: `postgres:16`, `clickhouse/clickhouse-server:24`, `slither-server` (built from local), volumes for PKI + data, healthchecks. Bootstrap service runs `gen-ca.sh` on first `up`, applies migrations, seeds one admin user (password from env or random-and-logged). `make compose-up` / `make compose-down`. **Exit:** `make compose-up` on a clean checkout → `http://localhost:8080` serves a login page; `docker compose ps` all healthy.

11. **#41 — Console scaffold + Tailwind + auth.** `server/internal/console/`: chi router, templ for views, session cookies (scs with pg store), argon2id password hashing, RBAC middleware reading role from session. Three roles seeded (viewer/analyst/admin) but only route-level enforcement (row-level deferred per §4). Layout shell (`layout.templ`) with sidebar nav. Tailwind via the standalone CLI (pinned version under `tools/tailwind/`); `make gen` runs `buf generate` then `tailwindcss -i … -o server/internal/console/static/app.css --minify`. Embed static via `embed.FS`. **Exit:** login with seeded admin → `/dashboard` placeholder renders; wrong password → audit-log entry; `make gen` produces deterministic CSS.

12. **#42 — Live tail page (SSE).** `/live` subscribes a per-request subscriber to the ingest bus, streams OCSF-formatted rows as `text/event-stream`. Filters: host_id, class_uid, free-text substring on raw. Pause/resume client-side. Per-connection drop counter shown in the UI footer (honest about backpressure). **Exit:** two browser tabs both receive the same events; pausing one does not stall the other or the bus.

13. **#43 — Events search page.** `/events` paginated ClickHouse queries with cursor pagination on `(observed_at DESC, event_id DESC)` (not offset — keeps large skips cheap). Filters: time range, host_id, class_uid, severity_id. Detail view renders raw OCSF as pretty JSON + a human-rendered summary per class. **Exit:** 1M-row CH table, last-hour query returns in <500 ms on localhost.

14. **#44 — Host inventory page.** `/hosts` lists from the `hosts` table: host_id, hostname, os, kernel, enrolled_at, last_seen (heartbeat-derived), status (online/stale/offline per §2.4 "3 missed heartbeats"), agent version. Admin-only actions: revoke cert (appends to CRL table, server refuses the cert on next connect). **Exit:** stale/offline transitions observable; revocation test — revoked agent's next Session fails with `Unauthenticated`.

15. **#45 — Enrollment-token UX.** Admin page `/enrollment-tokens`: create (TTL + optional hostname-hint), display **once** (store hash only), list outstanding, revoke. Copy-paste UX for the `slither-agent enroll --token …` command. **Exit:** operator-facing flow — generate token → copy command → paste onto fresh VM → agent shows up in `/hosts` within 5 s.

16. ✅ **#46 — Phase 2 exit validation.** Doc-backed manual run (mirrors the #29 pattern): bring up `make compose-up`, enroll a fresh agent VM, generate process/file/net events, confirm they land in ClickHouse via `/events`, confirm a server-pushed rule fires on edge and the resulting `DetectionFinding` is also searchable. Also load-test the server path: 3 agents × the Phase 1 stress-ng workload (~36k events/s aggregate) with `drop_rate_pct` reported at both agent and server-subscriber level. Commit `docs/phase2-validation.md` with raw outputs under `phase2_validation/`. **Exit:** all green, Phase 2 closed, Phase 3 scope unlocks. *(Single-host smoke passed 2026-04-25 in `phase2_validation/`. Multi-host load criterion was subsumed into Phase 3 #70 per scoping note; closed alongside #70 on 2026-04-29 — server-subscriber drop_rate 0.048 %, Debian 13 + Ubuntu 24.04 agents at 0.000 %, RHEL 10 at 1.962 % logged as Phase-1-known variance under the project's >4-vCPU production guidance for RHEL.)*

**Cross-cutting notes.**
- **No row-level authz** — endpoint-level only (§4 explicit). Row-level is a Phase 3+ item; don't backdoor it into RBAC middleware now.
- **Wire protocol is frozen** (§2.4). Any message-shape need that surfaces during Phase 2 → ADR + `slither.v2` discussion, not a silent edit.
- **Rule hot reload on the agent** is already in place (#24 `ReplaceRules`); #39 is the server push side. No agent-side reload rework needed.
- **Offline buffering** is deliberately Phase 5 (§7) — #35's disconnect-drop is acceptable for Phase 2.
- **Deferred technical questions** activated by this phase: §10.2 (TLS cert storage — plain files in `/etc/slither/`, revisit Phase 5), §10.3/§10.4 (CH schema + retention — initial schema now, tune Phase 3), §10.7 (console auth — local users only).

**Estimated effort:** 6–8 weeks for one person. The two biggest unknowns are the ClickHouse schema/query-shape tuning (#38 + #43) and the enrollment + CRL plumbing (#33/#34/#44 together); budget slack there.

### 4.2 Phase 2 follow-ups (non-blocking)

Issues surfaced during #46's local stand-up validation (see `docs/phase2-validation.md`). These are environment-agnostic — they don't depend on the multi-VM workload — and shouldn't gate Phase 2 closure. Land in the early-Phase-3 window.

1. **#47 — Server-push ruleset apply: structured stderr log.** During #46 the agent's silent happy-path made it impossible to tell whether server-pushed RuleSets were reaching the engine, were empty, or were failing to compile. A diagnostic line was added under `applyRuleSetTo` that fires on rule-count transitions; promote it to a proper log call (when the agent gets a real logger — see #49) with fields for `rule_count`, `skipped_count`, `ruleset_version`. **Exit:** operator running `journalctl -u slither-agent` can see, on every transition, that the agent received N rules from the server.

2. **#48 — Control-hub publish observability.** `server/internal/control` has zero logging today. Refresh, NOTIFY-driven re-fans, subscriber publish all happen silently. Add a single stderr line per `Refresh()` (`hub: refreshed N enabled rules (skipped K)`) and a counter exposed via telemetry for `RulesetsPublished` per subscriber. **Exit:** server log shows `hub: refreshed …` on every rule INSERT/UPDATE; `slither-server` telemetry snapshot includes per-subscriber publish counts.

3. **#49 — Agent + server: structured logging facade.** Both binaries currently use raw `fmt.Fprintf(os.Stderr, …)` everywhere. The `agent.log_level` config knob is parsed and validated but doesn't actually gate any output. Wire a minimal `slog`-shaped facade so info/debug levels become meaningful. Don't over-engineer — small wrapper around `log/slog` with text handler is enough; structured fields, no JSON-by-default. **Exit:** `SLITHER_AGENT_LOG_LEVEL=debug` actually produces more output than info; the same on the server side.

4. **#50 — Console UK/US spelling consistency.** Sidebar nav says "Enrolment" (UK) but the route is `/enrollment-tokens` (US). Pick UK throughout (matches the misspell config — see `project_toolchain.md`). Rename route to `/enrolment-tokens`, update handlers + templates. **Exit:** grep for `enrollment` in `server/internal/console/` returns zero hits; misspell linter reports clean.

5. **#51 — Operator-facing rule push helper.** `docs/phase2-validation.md` walks the operator through INSERTing a Sigma rule via raw `psql -c`. Terminal autoindent silently produces tab-indented YAML which YAML-parses fine but Sigma compile rejects, leading to an empty RuleSet and a silent agent — a 30-minute debug rabbit hole during #46. Ship `scripts/insert-rule.sh <yaml-path>` (or equivalent psql `\set`-based one-liner) that takes a file path, validates the YAML compiles via `pkg/ruleast`, then UPDATEs/INSERTs via psql variable substitution — bypasses both terminal autoindent and shell-quoting hazards. Update the runbook to use it. **Exit:** the runbook's "push a rule" step is one command, no SQL prose.

6. **#52 — Runbook: fix server-pushed rule reload log claim.** `docs/phase2-validation.md` §9 says "agent journal logs `reload: applied N rules` within ~1 s". That's the SIGHUP-driven local-config reload (`applyReload` at `agent/internal/app/app.go`) — not the server-push path (`applyRuleSetTo`), which is currently silent. Once #47 lands, update the runbook to point at the new line. **Exit:** runbook accurately tells the operator which log line to grep.

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

### 5.1 Phase 3 task breakdown

Task numbering continues from Phase 2 (#46 + §4.2 follow-ups #47–#52). Locked scoping calls (2026-04-26):

- **Wire format:** additive bumps inside `slither.v1` (no `slither.v2` namespace). `EdgeRule.ast_version` 1→2; agents that don't speak v2 stateful nodes refuse via `DiagReport`.
- **Alert dedupe (#60):** per-rule setting, not a global default. Fast-retriggering rules carry signal; that signal is preserved by letting analysts tune the window per rule.
- **D2 SVG cache (#64):** on-disk under `/var/lib/slither/graphs/` (matches the systemd unit's `StateDirectory=slither` pattern), in-memory LRU on top.
- **#70 / #46 overlap:** the deferred Phase 2 #46 multi-host load test folds into #70's cloud-VM run — one stand-up, both criteria satisfied. The §4.1 #46 ✅ flip happens alongside the §5.1 #70 flip.
- **IOC agent storage (#67):** in-memory map keyed by feed_id. ~10 MB per 100k-entry feed, native Go map lookup, atomic pointer swap on reload. Restart blindness is bounded by the agent's reconnect window (seconds). mmap'd-on-disk and Bloom-filter alternatives explicitly deferred — mmap until restart blindness is measured to matter, Bloom until ADR-0019's FP-handling story is worked out (Phase 4+).
- **Stateful cold-start (#59):** opt-in per rule, default off. Rules with `lookback: true` get a CH replay of their `timeframe` window at rule push; everything else starts with an empty window and warms up live. Re-examine the hybrid (always-on with a `max_cold_start_lookback` cap) in Phase 5 once CH query telemetry shows the real cost of always-on on production data — recorded as Phase 5 follow-up below.

Dependency graph:

- **A. Compiler split (gates almost everything):** #53 → #54 → #55
- **B. Edge stateful runtime:** #56 → #57 (parallel with C; needs #54)
- **C. Server detection engine:** #58 → #59 → #60 (needs #54)
- **D. Alert lifecycle:** #61 → #62 (after #60)
- **E. D2 graphs:** #63 → #64 → #65 (after #61)
- **F. IOC feeds:** #66 → #67 (parallel; needs #54)
- **G. Cross-cutting:** #68 (CH retention §10.4), #69 (rule reload §10.1)
- **Exit gate:** #70 (subsumes deferred #46 multi-host criterion)

1. **#53 — ADR + scoping spike for two-artefact rule shape.** Locked: additive `slither.v1` bumps. Pin the wire and storage representation: edge artefact stays `EdgeRule.compiled_ast` with `ast_version` 2 for stateful nodes; server plan is server-only (never on the wire) and lives next to the rule row in pg. Touches: new `docs/adr/0032-two-artefact-rules.md`, `proto/slither/v1/control.proto` review note, `PROJECT.md §3.6` cross-reference. **Exit:** ADR accepted with concrete answers to (a) classification metadata fields surfaced on `EdgeRule` (e.g. `state_window_secs`, `state_cap`) so agents enforce ADR-0018 at runtime, (b) server-plan column shape on `rules`, (c) `DiagReport` shape for v1-only agents that get v2 rules.

2. **#54 — Sigma compiler: full-grammar promotion + dual-artefact emit.** Extend `pkg/ruleast/sigma.go` + `condition.go` to accept the rest of the Sigma spec: `N of`, `them`, pipe aggregations (`| count() by …`), `near` (server-only), list-of-maps selections, `all`/`base64`/`base64offset`/`utf16*` modifiers, the `timeframe` field. Compiler now emits `(EdgeArtefact, ServerPlan, Classification)` per rule; `Classification` evaluates the four ADR-0018 predicates and reports the failed predicate by name on `force: edge` violations. Touches: `pkg/ruleast/`, new `pkg/ruleast/serverplan/`, expanded `testdata/rules/` corpus covering all four predicates + every new modifier. **Exit:** golden tests for the full Sigma feature set; `force: edge` on a 2-host-join rule fails compile with the predicate cited; existing 22-rule Phase 1 corpus still compiles (regression guard).

3. **#55 — Wire & storage plumbing for two-artefact rules.** Bump `EdgeRule.ast_version` to 2 (additive — v1 agents still get v1 rules; v2 rules omitted with a `DiagReport` per agent). Add classification metadata fields to `EdgeRule` per #53. Extend `rules` Postgres table with `server_plan jsonb` + `classification text` via a new goose migration; `server/internal/control/hub.go` stops pushing server-only rules to agents and routes them only to the engine in #58. Touches: `proto/slither/v1/control.proto`, regen `proto/gen/…`, new `server/migrations/00010_rules_server_plan.sql`, `server/internal/store/pg/rules.go`, `server/internal/control/{hub,runner}.go`. **Exit:** mixed ruleset (edge + server-only + force-server-override) round-trips through pg → hub → agent with the correct rules dropped/kept on each side; per-rule classification logged via the slog facade from #49.

4. **#56 — Edge runtime: bounded-stateful evaluator (`count()` + `timeframe`).** Extend `agent/internal/ruleengine/` with a state subsystem. State is a per-(host, rule) ring of monotonic timestamps keyed by the `by`-tuple; window ≤ 300 s and ≤ 1024 keys per ADR-0018, enforced at runtime (over-cap → drop oldest + bump per-rule `state_evicted` counter). Janitor goroutine prunes expired keys on a coarse tick to keep the hot path lock-light. Touches: new `agent/internal/ruleengine/state.go`, `ruleengine/engine.go`, `pkg/ruleast/runtime.go` evaluator dispatch. **Exit:** unit test fires `count() > 5 within 60s` correctly across boundary conditions (window edge, eviction, restart-clears-state); `-race` clean; benchmark ≤2× per-event cost vs stateless rules.

5. **#57 — Edge: ast_version=2 deserialise + classification refusal.** Agent rejects rules with `state_window_secs > 300` or `state_cap > 1024` even if a misconfigured server pushes them, citing ADR-0018, reports via `DiagReport.message`. Touches: `agent/internal/ruleengine/loader.go`, `agent/internal/output/grpc/session.go` (DiagReport plumbing). **Exit:** integration test — server pushes oversize rule, agent refuses, server log shows the diag.

6. **#58 — Server detection engine: stream subscriber + plan executor.** New `server/internal/detect/` package subscribes to the ingest bus (existing in-proc fan-out from #37) as one more subscriber, runs server-only Sigma plans against incoming OCSF events, emits internal `Finding` to a follow-on alert sink. Plan executor handles aggregations + temporal joins (`count() by …` + `near`) using a bounded in-memory window keyed off `(rule_id, group_key)`; window default 1 h, cap config-surfaced; eviction on time + on cardinality. Touches: new `server/internal/detect/{engine,window,plan}.go`, wired in `server/internal/app/app.go`. **Exit:** synthetic 100k-event stream triggers deterministic count-by-host alert; backpressure: slow detect drops + counters increment; ingest never blocks.

7. **#59 — Detection engine: ClickHouse lookback for cold-start.** On boot or rule change, backfill the window from CH for stateful rules with `lookback: true` in their YAML, provided `lookback ≤ retention`. Default is off — rules without the flag start with an empty window and warm up live; this protects CH from read amplification at every rule push and keeps surprise scans out of the operator's day. Touches: new `server/internal/detect/lookback.go`, `server/internal/store/ch/`, `pkg/ruleast/sigma.go` (parse the `lookback` flag). **Exit:** rule with `lookback: true` added at T fires on events from T-window if already in CH; rule without the flag starts cold; CH query budget is bounded by the rules-with-lookback set, not the full ruleset.

8. **#60 — Alert sink: write findings to existing `alerts` table.** Detection engine `Finding` → INSERT into `alerts` (already shipped in #32 / `00006_alerts.sql` with `rule_uid`, `host_id`, `event_ids[]`, `severity`, `status`, `reason_code`, `assigned_to`, lifecycle timestamps — no new migration). Edge `DetectionFinding` events take the same path so edge + server alerts share schema + UI. Per-rule dedupe window: new column `rules.dedupe_window_secs` (NULL = no dedupe), keyed on `(rule_uid, host_id, dedupe_window)`. Touches: new `server/internal/detect/sink.go`, `server/internal/ingest/router.go`, new `server/internal/store/pg/alerts.go`, new `server/migrations/00012_rules_dedupe_window.sql`. **Exit:** server-rule + edge-rule fires both produce alerts row with `event_ids` populated; per-rule dedupe respects the column; rules with NULL window deduplicate not at all (fast-retriggering rules carry signal).

9. **#61 — Alert lifecycle endpoints + audit.** RBAC-gated transitions `new → acknowledged → in_progress → closed`, set `reason_code`, assign `assigned_to`. Every transition writes to `audit_log` (#32) with operator id, before/after state, free-text note. Console: `/alerts` list + `/alerts/{id}` detail with action buttons. Touches: new `server/internal/console/alerts/`, `server/internal/store/pg/alerts.go`, `server/internal/console/views/alerts*`. **Exit:** analyst can ack → in-progress → close; viewer cannot; audit_log shows the chain; CHECK on `alerts.closed_at` (already in #00006) honoured.

10. **#62 — Console: alert list filters + cursor pagination.** Filters: status, severity, host, rule, assignee, time range. Cursor pagination on `(created_at DESC, id DESC)` matching the #43 events page pattern. Touches: `server/internal/console/alerts/`. **Exit:** 100k seeded alerts; filter combinations return <300 ms localhost.

11. **#63 — D2 vendoring + render harness.** Add `oss.terrastruct.com/d2` to `server/go.mod`; isolate behind `server/internal/graph/` exposing `Render(ctx, source string) ([]byte, error)` (SVG bytes). Document Apache 2.0 / MIT compatibility note in ADR-0024 references; pin the version. Touches: `server/go.mod`, new `server/internal/graph/{render,render_test}.go`. **Exit:** smoke test renders 5-node D2 source to SVG; binary-size delta noted.

12. **#64 — Detection flow graph: DAG builder + caching.** For each alert, build a DAG from `alerts.event_ids[]` walking parent/child + causality edges out of CH (process exec → spawned net connect → file write, etc.), emit D2 source, render via #63, cache the SVG keyed on `(alert_id, ruleset_version)`. In-memory LRU on top of on-disk cache under `/var/lib/slither/graphs/` (matches systemd unit's StateDirectory pattern); size cap + LRU eviction on disk. Touches: new `server/internal/detect/graph.go`, `server/internal/console/alerts/detail.go`. **Exit:** alert detail page shows the SVG; second load is a cache hit; cache invalidates when alert's event_ids change.

13. **#65 — Process-tree mini-graph endpoint.** `/hosts/{id}/process-tree?pid=…&depth=…` reuses `server/internal/graph/` to render a depth-bounded process tree from CH `process_activity`. Same cache shape as #64 keyed on `(host_id, root_pid, depth)`. Touches: new `server/internal/console/hosts/process_tree.go`. **Exit:** depth=4 tree renders <500 ms on a 1M-row CH table.

14. **#66 — IOC feed: server-side store + classification gate.** New `server/internal/ioc/` + `iocs` Postgres table (id, kind ∈ FeedKind, entries stored as a single row per feed with `entries text[]`, capped at 100k per ADR-0018, enforced server-side on insert). Console: `/iocs` admin CRUD. Sigma compiler (#54) recognises `ioc:<feed_id>` references; if any feed exceeds 100k, classifies the rule server-only. Touches: new `server/internal/ioc/`, new `server/migrations/00011_iocs.sql`, new `server/internal/console/iocs/`, `pkg/ruleast/serverplan/` integration. **Exit:** 100k SHA256 feed admits, 100001 rejects; rule referencing oversized feed compiles server-only with the ADR predicate cited.

15. **#67 — IOC feed: agent storage + push over RuleSet.** Agent receives `IocFeed` via existing `RuleSet.ioc_feeds` field (proto already has it — no wire change). Storage is an in-memory map keyed by `feed_id` → set of entries (`[32]byte` for SHA256, `uint32` for IPv4, `[16]byte` for IPv6). Compiler emits `iocMatch(feed_id, value)` AST nodes; runtime resolves O(1). Reload: build the new map off the hot path, atomic pointer swap; old map GCs when the last in-flight lookup returns. Memory budget: ~10 MB per 100k-entry feed, well inside the agent's footprint. Restart blindness is bounded by reconnect window (seconds); deemed acceptable for v1. Touches: new `agent/internal/ruleengine/ioc.go`, `pkg/ruleast/runtime.go`. **Exit:** integration test — push 50k-IP feed, fire rule on matching `network_connection`; eviction on feed update is atomic; `-race` clean across reload + lookup interleavings.

16. **#68 — ClickHouse retention + cardinality tuning.** Activates §10.4. Set TTL on each `ocsf_*` table (default 30d; configurable), add materialised-column choices informed by Phase 2 query shapes, document in `docs/adr/0033-clickhouse-retention-v1.md`. Touches: `server/clickhouse/migrations/`, new ADR. **Exit:** TTL applied; rowcount stable under sustained 36k events/s for 7 days in a soak test.

17. **#69 — Rule hot-reload decision (closes §10.1).** Phase 2 ships server-pushed `ReplaceRules` (#39) + agent SIGHUP for local rules (#10). This task is the formal §10.1 close-out: confirm server-push is the sole production path; agent SIGHUP is dev-only. Touches: `IMPLEMENTATION.md §10.1`, `docs/install.md`. **Exit:** §10.1 marked resolved; install doc clarifies.

18. ✅ **#70 — Phase 3 exit validation (subsumes deferred #46 multi-host criterion).** Doc-backed manual run on cloud VMs (mirrors #29 + #46 pattern): `make compose-up`, enrol 3 agent VMs, push a mixed ruleset (5 stateless edge, 3 bounded-stateful edge with `count() within 60s`, 4 server-only including one `near` + one cross-host aggregation, 2 IOC-driven). Drive a synthetic adversary scenario (brute-force ssh, IOC-hit network connection, multi-step exec → net → file write). Confirm: edge stateful rules fire without server round-trip; server-only rules fire from the bus; alerts land with correct lifecycle initial state; flow graph renders for a multi-step alert; process-tree mini-graph renders; **plus** the deferred Phase 2 #46 load criterion (3 agents × stress-ng baseline workload, drop_rate <1 % at agent + server-subscriber level). Commit `docs/phase3-validation.md` with raw outputs under `phase3_validation/`. **Exit:** all green; §4.1 #46 ✅ flipped alongside §5.1 #70 ✅; Phase 3 closed; Phase 4 scope unlocks. *(Completed 2026-04-29 on AWS us-west-2: 1 server (Debian 13 c7i.2xlarge) + 3 agents (1 Debian 13 / 1 RHEL 10 / 1 Ubuntu 24.04, c7i.xlarge each). Validation captures live in `phase3_validation/`; narrative in `docs/phase3-validation.md`. 5 in-flight bug fixes from the run shipped in commit 2063a27. Known gaps (detect engine refresh-on-NOTIFY, scenario design for some server-only rules) listed in the validation doc as Phase 4 follow-ups.)*

**Cross-cutting notes:**

- **Wire freeze stays intact.** Additive `ast_version=2` keeps `slither.v1`; v1 agents that don't understand v2 stateful nodes refuse the rule via `DiagReport`. Any non-additive change → ADR + `slither.v2` discussion per §2.4.
- **ADR-0018 enforced twice.** Compile-time on server (#54), runtime on agent (#57). Both must cite the failed predicate by name on rejection. No silent classification.
- **D2 dependency.** #63 is the only task pulling in a non-trivial new Go dep. Kept behind `server/internal/graph/`'s single surface so swapping for graphviz CLI shell-out later is a one-package change.
- **Deferred technical questions activated by this phase:** §10.1 (closed by #69), §10.4 (closed by #68); §10.2/§10.5 (cert storage, rule signing) remain Phase 5; §10.3 (CH schema evolution) remains Phase 5; §10.7 (SSO) remains Phase 5/6.

**Estimated effort:** 6–8 weeks for one person. Biggest unknowns: #54 (`near` semantics + aggregation IR are real design surface) and #58 (server detection engine's window/eviction shape). Budget slack there.

**Start here:** #53 → #54 → #56. #53 is a one-day ADR pinning the artefact contract so #54 doesn't iterate on shape. #54 is the longest single block and gates the entire detection-engine track (#55, #58–#60). #56 (edge bounded-stateful) starts in parallel once #53's AST shape locks — touches `agent/internal/ruleengine/` rather than `pkg/ruleast/sigma.go`; the two converge cleanly at #57.

**Phase 5 follow-up parked here for visibility:** once #68's CH retention is in place and #59's lookback path has shipped, re-examine whether the hybrid cold-start (always-on with a `max_cold_start_lookback` cap) is worth the complexity. Decision needs real query telemetry from a production-shaped CH — premature in Phase 3.

## 6. Phase 4 — Response

**Goal:** manual response primitives + opt-in edge auto-respond.

Phase 3 ended at task #70 (cloud-VM exit validation). Phase 4 picks up
at #71, mirroring the §3.x / §4.1 / §5.1 numbered-task pattern.

Architectural contract for Phase 4 lives in **ADR-0034**
(`docs/adr/0034-response-model.md`): two-layer auth (per-rule +
per-host policy), `response_actions` table as audit + state-machine
row, six-action surface freeze, additive `ClientMessage.response_result`
wire bump.

### 6.1 Tasks

**Dependency graph at a glance:**
- **A. Foundation:** #71 → #72 → #73 (sequential)
- **B. Server side:** #74 → #75 → #76 (after #72 + #73)
- **C. Agent executor:** #77 → {#78, #79, #80, #81} (parallel after #77)
- **D. Edge auto-respond:** #82 → #83 → #84 (after #71)
- **E. Reversal:** #85 (after #80 + #79)
- **Exit gate:** #86 (subsumes everything; user-execution like #29/#46/#70)

1. **#71 — ADR-0034 + scoping spike.** Adopted: per-host policy as the
   single auth surface for both console-driven and edge auto-respond
   paths; `response_actions` as the durable on-host record;
   `ClientMessage.response_result` additive wire bump; six-action
   surface freeze. Touches: `docs/adr/0034-response-model.md`. **Exit:**
   ADR accepted; PROJECT.md §3.6 cross-reference; concrete table
   shapes for `response_actions` + `host_response_policies` recorded
   in the ADR for #72 to implement.

2. **#72 — Postgres schema for response_actions + host_response_policies.**
   New goose migration adding both tables per ADR-0034. CHECK on
   `response_actions.status` enumerates `pending/running/done/
   failed/denied_by_policy/reverted`; CHECK on
   `(operator_id IS NOT NULL OR rule_uid IS NOT NULL)` enforces "who
   asked" invariant. NOTIFY trigger on `host_response_policies` updates
   (mirrors `rules_changed` from #39). pg helpers:
   `InsertResponseAction`, `TransitionResponseAction`, `GetHostPolicy`,
   `UpsertHostPolicy`, `WatchHostPolicies`. Touches: new
   `server/migrations/00014_response_actions.sql`,
   `server/migrations/00015_host_response_policies.sql`,
   `server/internal/store/pg/response.go`. **Exit:**
   testcontainers integration test inserts → transitions → reverts a
   row + verifies CHECK constraints; per-host policy NOTIFY observable.

3. **#73 — Wire freeze: `ClientMessage.response_result` + `HostPolicy`.**
   Additive bumps per ADR-0034. New `ResponseResult` message,
   `ResponseStatus` enum, `HostPolicy` message in `proto/slither/v1/`.
   `ServerMessage.host_policy` (oneof field, additive) for delivery.
   Regen Go bindings. v1-agent compatibility holds: agents that don't
   know `response_result` simply never emit it (same field-number
   contract as #55's `ast_version` bump). Touches:
   `proto/slither/v1/agent.proto`, `proto/slither/v1/control.proto`,
   regen `proto/gen/...`. **Exit:** `make gen` clean; existing tests
   compile against the new shape; ADR-0011's wire-stability invariant
   verified.

4. **#74 — Console: response buttons + confirmation modal.** Extend
   `/alerts/{id}` detail with action buttons gated on `pg.HostPolicy`:
   "Kill PID N", "Quarantine /path", "Isolate host", "Collect
   artefacts". Each requires a confirmation modal (HTMX + a small
   bit of JS) — destructive actions get a typed confirmation;
   non-destructive (collect, unisolate) get a single-click. New
   `/hosts/{id}/policy` admin page for promoting hosts out of
   detect-only. Touches: `server/internal/console/alerts.go`,
   `server/internal/console/views/alerts.templ`, new
   `server/internal/console/policy.go`, new
   `server/internal/console/views/policy.templ`. **Exit:** analyst
   sees buttons only on response-permitted hosts; viewer sees no
   buttons; admin can edit policy.

5. **#75 — Server dispatch path.** Operator submits response from
   console → handler validates host policy + role → inserts
   `response_actions` row (status=pending) → enqueues
   `ResponseRequest` onto a per-host channel feeding the Session
   send goroutine → agent emits `ResponseResult` →
   `SessionService` resolves to `response_actions` by action_id and
   flips status. Bounded queue per session with drop-oldest +
   `response_dispatch_dropped` telemetry counter. Touches:
   new `server/internal/respond/`,
   `server/internal/grpcserv/session.go`, `server/internal/app/app.go`.
   **Exit:** integration test (testcontainers + bufconn) — operator
   POST → row inserted → fake agent receives ResponseRequest → emits
   ResponseResult → row transitions to `done`.

6. **#76 — Audit chain on every transition.** Each
   `response_actions` state change writes one `audit_log` row keyed
   on `target_kind=response_action`, `target_id=action_id`, with
   structured detail capturing prev/next status + operator id +
   error string when failed. Forensic-ready chain. Touches:
   `server/internal/respond/`, `server/internal/store/pg/response.go`.
   **Exit:** `audit_log` query for an action shows the full
   `pending → running → done` (or `→ failed`) trail.

7. **#77 — Agent response executor scaffold.** New
   `agent/internal/respond/` package with `Executor` that handles
   `ServerMessage_ResponseRequest`, dispatches by action enum to
   per-action handlers, returns a `pb.ResponseResult` for the sink to
   stream back. Cap on concurrent in-flight responses (default 4);
   queue overflow reports `RESPONSE_STATUS_FAILED` with detail
   `"queue full"`. Touches: new `agent/internal/respond/executor.go`,
   wired in `agent/internal/output/grpc/sink.go` + `agent/internal/app/app.go`.
   **Exit:** unit test — a stub Executor receives a
   `ResponseRequest` and emits a `ResponseResult` round-trip via a
   bufconn agent.

8. **#78 — kill_process / kill_tree handlers.** Single PID:
   `unix.Kill(pid, SIGTERM)` + 3 s grace + `SIGKILL`. Tree: walk
   `/proc/<pid>/task/<tid>/children` recursively, depth-cap 1024,
   send TERM to all then KILL after grace. Refuse to kill PID 1, the
   slither-agent's own PID, or any PID in pid-namespace ancestor
   chain. Touches: `agent/internal/respond/kill.go`. **Exit:**
   integration test on a Linux host (privileged): spawn a sleep
   child, fire kill_process, verify `WaitPid` reports SIGKILL exit;
   tree variant against a 3-deep fork chain.

9. **#79 — quarantine_file handler.** `mkdir -p
   /var/lib/slither/quarantine/`; `os.Rename` target into a
   sha256-of-original-path-named subdir; write a JSON sidecar
   capturing original path + mtime + size + sha256 + caller's
   action_id. Refuse to quarantine paths under `/proc`, `/sys`,
   `/dev`, `/run/systemd`, the slither state dir, or the operator's
   running shell's $0. Reversal (#85) reads the sidecar to put the
   file back. Touches: `agent/internal/respond/quarantine.go`.
   **Exit:** integration test — quarantines `/tmp/x`, verifies file
   moved + sidecar correct + reversal restores byte-identical
   content.

10. **#80 — isolate_host / unisolate_host handlers.** Use `iptables`
    (or `nft` if available; iptables-shim path on RHEL). Isolate
    rules: append a chain `slither-isolation` allowing established +
    related, allowing the configured management subnet (default
    derives from the agent's default-route gateway), dropping
    everything else. Unisolate flushes the chain.
    `host_response_policies.allow_isolate` + an additional
    `mgmt_subnet` text column on `hosts` for operator override.
    Touches: `agent/internal/respond/isolate.go`,
    new migration `00016_hosts_mgmt_subnet.sql`. **Exit:** integration
    test — isolate; assert outbound to non-mgmt is blocked; unisolate;
    assert restored. Test on a kvm/network-namespaced host (skip on
    GH-hosted runners; covered in #86 cloud run).

11. **#81 — collect_artifacts handler.** Tarball:
    `/proc/<pid>/{maps,status,environ,cmdline,fd}` snapshot, recent
    `journalctl` (60 s window), depth-3 process tree of the target
    pid + ancestors, `/etc/{passwd,group,os-release}` (no shadow).
    Memory dump via `/proc/<pid>/mem` is gated on `ptrace_scope` +
    `dumpable` flag — when blocked, skip with an explicit note in
    the bundle's manifest rather than failing the whole action.
    Stream as `result_blob` on `ResponseResult`; server stores under
    `/var/lib/slither/artefacts/<action_id>.tgz` (new compose volume
    pattern matching #64's graphs cache). Touches:
    `agent/internal/respond/collect.go`,
    `server/internal/respond/sink.go`, deploy/compose updates.
    **Exit:** integration test — collect against `sleep 30` +
    verify tarball has expected entries + manifest.

12. **#82 — Sigma `slither.response` block + classifier.** Extend
    Sigma compiler to recognise an optional top-level `slither.response`
    block carrying `{action: kill_process, target_field: pid,
    immediate: true|false}`. Compiler emits the response intent on
    the `EdgeArtefact` (new field). Validates target_field exists in
    the rule's selection. Touches: `pkg/ruleast/sigma.go`,
    `pkg/ruleast/artefact.go`, `pkg/ruleast/compile.go`. **Exit:**
    golden test — rule with response block round-trips with intent
    populated; rule referencing missing target_field fails compile.

13. **#83 — Edge auto-respond engine.** When a stateless or stateful
    edge rule fires AND the rule has a response intent AND the agent's
    cached `HostPolicy` permits the action class → invoke the local
    Executor in addition to emitting the DetectionFinding. Both the
    triggering event and the action's row stream to the server (the
    server inserts the `response_actions` row with `rule_uid` set,
    `operator_id` NULL, status starting at `running` since the agent
    already executed). Detect-only hosts emit a
    `would_have_executed` field on the DetectionFinding. Touches:
    `agent/internal/ruleengine/`, `agent/internal/respond/`,
    `pkg/ocsf/finding.go` (new field), wire bump for
    DetectionFinding may be needed (additive). **Exit:** integration
    test — rule with `kill_process` intent + permissive policy fires
    on a synthetic spawn → child killed within 1 s; same rule on a
    detect-only host emits `would_have_executed=true` only.

14. **#84 — Per-host policy push.** Server reads
    `host_response_policies` on Session open, sends initial
    `ServerMessage.host_policy`. NOTIFY-driven push on policy edits
    (mirrors hub Refresh from #39). Agent caches latest in atomic
    pointer; auto-respond gate (#83) consults it; missing policy =
    all-false = detect-only. Touches:
    `server/internal/control/policy.go`,
    `server/internal/grpcserv/session.go`,
    `agent/internal/output/grpc/sink.go`,
    `agent/internal/respond/policy.go`. **Exit:** integration test —
    update policy via console → agent's cached policy reflects
    within debounce window; auto-respond gate flips correspondingly.

15. **#85 — Reversal flows.** New endpoints + handlers for
    un-quarantine + un-isolate. Each creates a `response_actions`
    row with `parent_action` set to the original; reversal handler
    on the agent reads parent's `result_blob` (or sidecar for
    quarantine) to perform the inverse. Parent flips to `reverted`
    when reverse hits `done`. Console "Revert" button on the alert
    detail's action history list. Touches:
    `agent/internal/respond/quarantine.go` (un-quarantine),
    `agent/internal/respond/isolate.go` (already covers
    UNISOLATE_HOST from #80 — this just adds the parent_action
    plumbing on the server side),
    `server/internal/respond/`, console views. **Exit:** integration
    test — quarantine → revert → file is byte-identical at original
    path; both `response_actions` rows audited + linked.

16. ✅ **#86 — Phase 4 exit validation.** Doc-backed manual run on the
    Phase 3 cloud fleet (existing stopped instances —
    `start-instances` brings them back). Promote one agent to
    `allow_kill_process=true`, leave the other two detect-only.
    Console-driven kill: operator clicks Kill → `response_actions`
    row → agent kills → status=done; non-promoted host: button
    absent. Auto-respond rule with `kill_process` + `immediate: true`:
    fires + executes on promoted host; emits `would_have_executed`
    on detect-only host. Reversal: quarantine + un-quarantine
    round-trip. Audit chain visible in `audit_log`. Capture under
    `phase4_validation/`; commit `docs/phase4-validation.md`. **Exit:**
    all green; Phase 4 closed; Phase 5 (hardening) opens. *(Completed
    2026-05-01 on the same AWS us-west-2 fleet that closed Phase 3.
    All eleven exit criteria pass live (kill/quarantine/auto-respond
    on promoted, denied/would_have_executed on detect-only, full
    audit chain) or by static evidence (CAP_NET_ADMIN / isolate_host
    not live-fired to avoid SSH-session disruption — cap present in
    unit). Two deploy-posture gaps caught and pushed to Phase 5:
    sysctl drop-in not provisioned at install time (Debian-only
    perf_event_paranoid issue), and `PrivateTmp` + `ProtectSystem=strict`
    blocking quarantine on `/tmp/` and `/opt/`. Captures in
    `phase4_validation/`; narrative in `docs/phase4-validation.md`.)*

### 6.2 Cross-cutting notes

- **Wire stability holds.** Phase 4 adds `ResponseResult` + `HostPolicy`
  + `would_have_executed` on DetectionFinding — all additive
  inside `slither.v1`. No `slither.v2` discussion. ADR-0011's
  wire-freeze invariant is preserved per §2.4.
- **Default-detect-only for every host.** Phase 4 ships safer than
  Phase 3 in that respect — even with the executor wired, no host
  acts on a rule without explicit promotion.
- **Action surface frozen at six.** `kill_process`,
  `kill_process_tree`, `quarantine_file`, `isolate_host`,
  `unisolate_host`, `collect_artifacts`. New actions need ADR +
  enum-bump per §2.4.
- **Reversal is a new row, not a mutation.** Forensic chain stays
  append-only.
- **Phase 4 starts here:** #71 (ADR — already accepted in this
  commit) → #72 (DB schema) → #73 (wire bump) lands a sequential
  foundation; everything else parallelises off those three. Biggest
  single block is #83 (auto-respond), gated on #82's compiler
  extension.

**Estimated effort:** 4–6 weeks for one person. Biggest unknowns:
#80 (isolation correctness on heterogeneous nft/iptables hosts) and
#83 (auto-respond's interaction with the bounded-stateful runtime
when a rule fires on the same key window twice). Budget slack
there.

## 7. Phase 5 — Hardening

**Goal:** production-readiness. Distribution (signed deb/rpm/OCI),
self-protection (the agent defends itself from local tampering),
resilience (no event loss on disconnect, end-to-end backpressure),
and closure of the deferred technical questions Phase 5 was tagged
to handle. Zero new operator-facing capability — all of Phase 5 is
in service of "operator can install this on a fresh host and trust
what's running."

Phase 4 ended at task #86 (cloud-VM exit validation, closed
2026-05-01 with the re-validation captured under
`phase4_validation/`). Phase 5 picks up at #87, mirroring the §3.x
/ §4.1 / §5.1 / §6.1 numbered-task pattern.

Architectural contract for Phase 5 lives in **ADR-0035**
(`docs/adr/0035-phase5-scope.md`): zero new feature scope,
distribution surface (deb + rpm + OCI + signed binaries), kernel
keyring cert storage (closes §10.2), CH migration harness (closes
§10.3), six-hour offline buffering with class-priority backpressure,
quarantine subprocess decoupling for the Gap-B fix, deferred §10.5
(rule signing) to Phase 6.

### 7.1 Tasks

**Dependency graph at a glance:**
- **A. Foundation:** #87 (this ADR + breakdown) → #88 (Phase 4 punch list) — sequential
- **B. Build/release track:** #89 (reproducibility) → {#90 SBOM, #91 signing, #92 deb/rpm, #93 OCI} (parallel after #89)
- **C. Runtime hardening:** #94 self-protection → #95 tamper-evident logs (#95 sequenced after #94 because both touch the agent's state-dir hardening)
- **D. Resilience:** #96 (offline buffering), #97 (backpressure) — independent of each other, parallel after #87
- **E. Server-side closures:** #98 (cert storage), #99 (CH migration harness), #100 (quarantine subprocess) — all independent, parallel after #87
- **F. Decisions/docs:** #101 (#59 hybrid call), #102 (threat model) — late in the phase
- **Exit gate:** #103 (subsumes everything; user-execution like #29/#46/#70/#86)

1. **#87 — ADR-0035 + scoping spike (this commit).** Locks: zero
   new feature scope; distribution surface (deb + rpm + multi-arch
   OCI + cosign-signed binaries); kernel-keyring cert storage with
   file fallback (closes §10.2); CH migration harness (closes §10.3);
   §10.5 rule signing parked Phase 6+; six-hour offline buffer with
   256 MiB default + class-priority backpressure; quarantine
   subprocess decoupling for Gap B; threat model as `docs/threat-model.md`
   only (no separate ADR); §59 cold-start hybrid decision deferred to
   #101 once Phase 5 fleet telemetry is available. Touches:
   `docs/adr/0035-phase5-scope.md`, `IMPLEMENTATION.md §7`. **Exit:**
   ADR accepted; §7.1 task breakdown in place.

2. **#88 — Phase 4 carry-over punch list.** Four operational
   papercuts batched: (a) `detect.Engine` subscribes to `rules_changed`
   NOTIFY (re-uses #39's plumbing; engine only loaded plans at
   startup); (b) auto-respond dedupe — collapse the duplicate
   `response_actions` row when the immediate-fire path and the
   detection-emit path both observe the same exec event for the
   same rule + target_pid (key on `(rule_uid, host_id, target,
   ±100ms)` and squash); (c) `hosts.agent_version` writeback —
   server stamps the column from the agent's heartbeat metadata
   on each `UpdateHostLastSeen` call; (d) `deploy/sysctl.d/99-slither.conf`
   manual-install step documented in `docs/install.md` as a
   transitional measure until #92 ships postinst. Touches:
   `server/internal/detect/`, `agent/internal/respond/auto.go`,
   `server/internal/grpcserv/session.go`, `server/internal/store/pg/hosts.go`,
   `docs/install.md`. **Exit:** integration tests for (a)+(b)+(c);
   doc step verified by re-reading.

3. **#89 — Reproducible builds.** `Makefile` build targets gain
   `-trimpath`, `-buildvcs=true`, `-mod=readonly`; CI workflow
   `verify-reproducible` job builds twice and diffs the SHA-256.
   Pin `llvm`/`clang` versions in `agent/internal/bpf/src/Makefile`
   + the agent build Dockerfile via Debian package pinning. Pin
   Go toolchain via `go.work` `toolchain` directive (matches
   existing 1.25 pin). Touches: `Makefile`, `.github/workflows/ci.yml`,
   `deploy/docker/server.Dockerfile`, `deploy/docker/bootstrap.Dockerfile`,
   new `deploy/docker/agent.Dockerfile`, `go.work`. **Exit:** CI
   green; two consecutive `make build` runs produce byte-identical
   `bin/*`.

4. **#90 — SBOM via syft.** Goreleaser-style hook (or scripted
   step in `.github/workflows/release.yml`) runs `syft` against
   each release artefact and attaches the SBOM as a release asset.
   Both SPDX-JSON and CycloneDX-JSON formats. Touches:
   `.github/workflows/release.yml` (new), `tools/sbom.sh` (new).
   **Exit:** a tagged release produces `*.spdx.json` +
   `*.cyclonedx.json` for each binary + each package + each OCI
   manifest digest.

5. **#91 — Cosign keyless signing.** GitHub OIDC → cosign-keyless
   signature on every release artefact (binaries, deb, rpm, OCI
   image manifests). Verification documented in `docs/install.md`
   for both the cosign path and the `gpg --verify` path on deb/rpm
   (nfpm signing keyring case). Touches:
   `.github/workflows/release.yml`, `docs/install.md`.
   **Exit:** `cosign verify --certificate-identity-regexp ...
   slither-agent` passes against a tagged release.

6. **#92 — nfpm `.deb` + `.rpm` packaging.** `nfpm.yaml` config
   building both formats. Postinst:
   (i) install `99-slither.conf` into `/etc/sysctl.d/` + `sysctl --system`
       — closes Gap A from #86;
   (ii) install systemd unit + reload + enable (don't auto-start —
        operator runs `slither-agent enroll` first);
   (iii) install `agent.yaml.sample` to `/etc/slither/`;
   (iv) chown `/var/lib/slither` + `/etc/slither` to root:root mode 0700.
   Postuninst removes the systemd unit + sysctl drop-in but preserves
   `/var/lib/slither/quarantine/` + `/var/lib/slither/buffer/` (operator
   data). Touches: new `deploy/nfpm/nfpm.yaml`,
   `.github/workflows/release.yml`, `docs/install.md` rewrite.
   **Exit:** install/upgrade/remove on a fresh Debian 13 + RHEL 10 +
   Ubuntu 24.04 VM; `apt install ./slither-agent_*.deb` works
   end-to-end; postinst applied sysctl drop-in observable in
   `/etc/sysctl.d/`.

7. **#93 — OCI image build.** Multi-arch (amd64 + arm64) agent +
   server images. Agent image runs as a k8s daemonset shape:
   capabilities-only (no `privileged: true`), bind-mounts
   `/sys/kernel/btf`, `/proc`, `/sys/fs/bpf`, `/var/lib/slither` (PVC),
   `/etc/slither` (Secret). Server image productionised — distroless
   base, signed, includes `slither-db` + `slither-ch` for migration
   sidecar use. Both pushed to ghcr.io on release tag. Sample
   k8s manifests in `deploy/k8s/`. Touches:
   `deploy/docker/agent.Dockerfile` (new),
   `deploy/docker/server.Dockerfile` (rewrite to distroless +
   multi-arch),
   new `deploy/k8s/{daemonset,deployment,service}.yaml`,
   `.github/workflows/release.yml`. **Exit:** kind-cluster smoke test
   in CI brings up agent daemonset + server deployment, agent enrolls
   + reports events, console reachable.

8. **#94 — Agent self-protection v1.** On startup:
   `prctl(PR_SET_DUMPABLE, 0)` to block ptrace + core dumps;
   refuse to run if attached via PTRACE_ATTACH (check `/proc/self/status`
   `TracerPid` field); after BPF programs load, drop unused caps
   via `prctl(PR_CAP_AMBIENT_LOWER)` — keep CAP_BPF/CAP_PERFMON
   only in the long-running tracepoint goroutine, drop the rest;
   chmod 0700 on `/var/lib/slither` + `/etc/slither` at startup
   (agent owns these via systemd's StateDirectory). Touches:
   new `agent/internal/selfprotect/`, `agent/internal/app/app.go`.
   **Exit:** integration test (privileged) — start agent, attempt
   `gdb -p <agent-pid>` → fails with EPERM; agent logs the rejection
   on a tracer-attached startup; capability bound observable in
   `/proc/<agent-pid>/status` post-BPF-load.

9. **#95 — Tamper-evident logs.** Hash-chain over the agent's local
   forensic state: each `response_actions` execution + each emitted
   detection finding writes one line to `/var/lib/slither/log.chain`
   carrying `prev_hash + record_hash + timestamp + record_summary`.
   Flushed before shutdown via signal handler. New
   `slither-agent verify-logs --since DURATION` walks the chain and
   exits non-zero on any break. Server-side cross-check (Phase 6+):
   periodically compare against the equivalent CH-side records.
   Touches: `agent/internal/selfprotect/chain.go` (new),
   `agent/cmd/slither-agent/verify.go` (new), state-dir hardening
   from #94. **Exit:** unit test breaks the chain at row N → verify
   exits non-zero pointing at row N; clean chain → exit 0.

10. **#96 — Offline buffering.** On-disk ringbuffer at
    `/var/lib/slither/buffer/`. 6 h cap × ~1k events/s/host →
    256 MiB default budget (operator-tunable via
    `agent.output.grpc.buffer.{disk_max_bytes,max_age}`). Oldest-wins
    drop on overflow. Replay protocol on reconnect: agent streams
    buffered Envelopes ahead of fresh ones; server detects via
    `Envelope.observed_at < (now - 1m)` and routes to a replay-bypass
    path that lands in CH but skips the live-tail SSE bus (replay
    clutters live-tail). Buffer survives agent restart. Touches:
    `agent/internal/output/grpc/sink.go`, new
    `agent/internal/output/grpc/buffer/`, `server/internal/grpcserv/session.go`,
    `server/internal/ingest/bus.go` (replay-class subscriber filter).
    **Exit:** integration test — disconnect agent for 30s → reconnect
    → assert all events from the disconnect window land in CH but
    don't appear on `/live/stream` retroactively; oldest-wins eviction
    holds at the configured cap.

11. **#97 — End-to-end backpressure.** Two-direction signal:
    **Up:** agent monitors `telemetry.DropsOutput` over a 30s window;
    when non-zero, raises sampling on low-priority classes
    (NetworkActivity for non-IOC events first; FileSystemActivity
    for non-rule paths second). Sampling rate computed from drop
    pressure with hysteresis. **Down:** server's CH writer reports
    subscriber drops via a new `BackpressureSignal` message
    (additive `slither.v1` wire bump on `ServerMessage`). Agents
    cache the signal in atomic pointer; auto-respond + detection
    paths consult it; cleared by a follow-up signal or 5min timeout.
    Touches: `proto/slither/v1/control.proto`,
    `agent/internal/collector/`, `agent/internal/output/grpc/sink.go`,
    `server/internal/store/ch/writer.go`, new
    `server/internal/control/backpressure.go`. **Exit:** integration
    test under `make load-test` — pin server CH writer to slow
    flush, observe agent-side sampling raise on Network class
    within 30s; recovery within 30s after writer unpins.

12. **#98 — Cert storage: kernel keyring + file fallback.**
    Closes §10.2. Agent stores client cert + key via
    `add_key(2)` to the user keyring on enrollment; reads via
    `keyctl(2)` on subsequent boot. Falls back to `/etc/slither/`
    files when `/proc/keys` is unavailable (containers without
    keyring access, kernels < 5.4). New `agent/internal/keystore/`
    with `Keyring` + `FileFallback` impls behind a `Store` interface.
    Touches: `agent/internal/enroll/enroll.go`,
    `agent/internal/output/grpc/sink.go` (cert load),
    new `agent/internal/keystore/`, `docs/install.md` (TPM is
    Phase 6+ — note that). **Exit:** integration test on Debian 13
    with keyring → cert lives in keyring, file absent;
    container-shape test with `/proc/keys` unreadable → falls back
    to file, both paths produce a working agent.

13. **#99 — CH migration harness.** Closes §10.3. Goose-style
    forward + down migrations with a `schema_version` table in CH.
    Tooling: `slither-ch migrate-up`, `slither-ch migrate-down`,
    `slither-ch status`, plus a `--dry-run` flag that prints SQL
    without applying. Symmetric to the existing pg path
    (`slither-db`). Phase 5 ships the harness only — no OCSF
    version bump in this phase. Touches: `server/cmd/slither-ch/`
    extensions, new `server/internal/store/ch/migrate/`, possibly
    `server/clickhouse/migrations/` reorganisation if the existing
    files don't fit goose's down-migration shape.
    **Exit:** integration test — applies all migrations forward,
    rolls back the last two, re-applies forward, assert
    `schema_version` row count + table contents stable.

14. **#100 — Quarantine subprocess decoupling (Gap B fix).** Spawn
    a short-lived sub-process for each `quarantine_file` /
    `unquarantine` action with relaxed namespace (no `PrivateTmp`,
    `ProtectSystem=` off) so it can see + modify `/tmp/`, `/opt/`,
    `/var/spool/`. Sub-process drops all caps except
    `CAP_DAC_OVERRIDE` + `CAP_DAC_READ_SEARCH`, communicates with
    the parent agent over a unix socket pair, returns the same
    `ResponseResult` shape. Audited via the existing
    `response_actions` chain — operator never sees the subprocess.
    Touches: `agent/internal/respond/quarantine.go`,
    new `agent/internal/respond/quarantine_subprocess/`,
    `deploy/systemd/slither-agent.service` (no change — sub-process
    inherits unit caps but not namespacing because `ExecStartPost`
    doesn't propagate `PrivateTmp` to forked children with a
    bespoke namespace setup). **Exit:** integration test —
    quarantine `/tmp/x` succeeds, unquarantine restores byte-identical;
    BPF + detection paths still observably namespaced (verify via
    agent's view of `/tmp` differs from operator's).

15. ✅ **#101 — Stateful cold-start hybrid decision.** Re-examine
    §5.1 #59 with Phase 5 fleet telemetry. Operate the cloud fleet
    for ≥48 h with a representative mix of stateful rules; sample
    CH `system.query_log` for the lookback queries; measure
    read-amplification + p95 latency. Decision matrix:
    | Telemetry shows | Decision |
    |-----------------|----------|
    | Lookback queries < 5% of total CH read budget AND p95 < 500ms | Ship hybrid (always-on + max_cold_start_lookback=1h cap). |
    | Either threshold crossed | Close as won't-do; document in `docs/phase5-validation.md`. |
    Either way, this is a numbered task that ships: code + tests OR
    a doc-only commit recording the closure rationale. Touches:
    `server/internal/detect/lookback.go` (if shipping),
    `docs/phase5-validation.md` (the decision either way).
    **Exit:** decision recorded with the underlying telemetry. *(Closed
    2026-05-01 as won't-do via ADR-0036. Decision is structural
    rather than telemetry-driven: the hybrid's only tuning knob is
    global (`max_cold_start_lookback`) while the existing per-rule
    `lookback: true` flag is per-rule, strictly more expressive.
    Phase 3/4 cloud runs surfaced no operator pain point that the
    hybrid would relieve. Reopen criterion in Phase 6+: "operator
    UX failure pattern documented", not "lookback queries cost too
    much" (which the per-rule shape already controls). One-line
    flip from `lookback: false` to `lookback: true` default in the
    compiler is all it would take to reopen.)*

16. ✅ **#102 — Threat model doc.** `docs/threat-model.md`. STRIDE
    per surface: ingest path (gRPC mTLS), control plane (rule push,
    response dispatch), console (HTMX session auth), agent runtime
    (BPF + capability bound + state dir), package distribution
    (cosign + reproducible builds). Captures: what slither defends
    against (local-root tamper, opportunistic malware on a host
    with kill_process permitted, unauthorised response action via
    console RBAC); what slither does **not** defend against
    (kernel-mode rootkits, supply-chain compromise of the build
    system, physical access, TPM-less firmware attack); residual
    risks. Lands toward the end of Phase 5 so it describes
    what shipped. Touches: new `docs/threat-model.md`,
    `README.md` (link). **Exit:** doc reviewed end-to-end; every
    §3.x trust assumption referenced. *(Committed 2026-05-01. Five
    surface-by-surface STRIDE tables (ingest / control plane /
    console / agent runtime / distribution); explicit
    "does NOT defend against" section listing kernel-mode rootkits,
    supply-chain compromise, physical access, server compromise,
    insider operator abuse, side-channels, network-level traffic
    analysis, upstream Sigma-rule logic flaws; defence-in-depth
    posture summary cross-referencing every Phase 1-5 task that
    contributes. Cross-referenced from README.md.)*

17. ✅ **#103 — Phase 5 exit validation.** Doc-backed manual run on
    the Phase 3/4 cloud fleet (existing stopped instances —
    `start-instances` brings them back). Validates:
    (i) `apt install ./slither-agent_*.deb` on Debian 13 + Ubuntu 24.04;
        `dnf install ./slither-agent-*.rpm` on RHEL 10. Postinst
        applies sysctl drop-in. Service starts via `systemctl enable`;
    (ii) cosign verify on a tagged release artefact;
    (iii) reproducible-builds proof — two consecutive CI builds on
        the same SHA → same binary SHA-256;
    (iv) OCI image works as a k8s daemonset against a kind cluster
        (or one of the cloud VMs running k3s);
    (v) Self-protection — `gdb -p <agent>` rejected; cap bound
        observably reduced post-startup;
    (vi) Tamper-evident log chain verifies on every host;
    (vii) Offline buffering — disconnect agent 30 minutes →
        reconnect → all events from the disconnect window land in CH
        but stay out of `/live/stream` history;
    (viii) Backpressure — pin CH writer slow → agent observably
        raises NetworkActivity sampling within 30s;
    (ix) Cert storage — kernel keyring used on Debian 13 (verify
        via `keyctl list @u`); file fallback exercised on the OCI
        image where keyring is unavailable;
    (x) Quarantine on `/tmp/`, `/opt/` works (Gap B fix);
    (xi) #101 already closed via ADR-0036 — no telemetry to collect;
        the cloud run sanity-checks the existing per-rule lookback
        path still fires correctly (single rule with `lookback: true`,
        agent restarted mid-window, threshold crosses on warm window);
    (xii) Threat model doc walked through against the running fleet —
        every claim verifiable.
    Capture under `phase5_validation/`; commit
    `docs/phase5-validation.md`. **Exit:** all green; Phase 5 closed;
    Phase 6 (extensions) opens. *(Completed 2026-05-02 on the same
    AWS us-west-2 fleet that closed Phases 3 and 4. Twelve exit
    criteria pass live or via static evidence + unit-test coverage.
    Two real bugs caught + hot-fixed in-flight: Gap A — kernel-
    keyring storage cross-process gap (enroll.go now writes files
    first, keyring is best-effort additive); Gap B — quarantine
    blocked by ProtectSystem=strict even after PrivateTmp removal
    (unit's ReadWritePaths extended to /tmp + /opt + /var/spool).
    Captures in `phase5_validation/`; narrative in
    `docs/phase5-validation.md`. Phase 5 closed; Phase 6 scope is
    open.)*

### 7.2 Cross-cutting notes

- **Wire stability holds.** Phase 5 adds `BackpressureSignal` on
  `ServerMessage` — additive inside `slither.v1`. No `slither.v2`
  discussion. ADR-0011's wire-freeze invariant is preserved per
  §2.4.
- **No new operator capability.** Phase 5 ships zero new alerts,
  responses, or console pages. End-users see "we package now" and
  "the agent defends itself" — not new dashboards.
- **Reproducibility before signing.** #91 (signing) depends on #89
  (reproducibility) so the signed artefact is meaningful — signing
  a non-reproducible binary attests to "the build that happened on
  this CI run produced this byte sequence", which is weaker than
  "this source tree at this commit produces this byte sequence".
- **Default-detect-only carries forward.** Per ADR-0034, every
  freshly-enrolled host lands at all-false. Phase 5 packaging
  doesn't change that — `apt install` produces a host that emits
  telemetry and detects, but acts on nothing until an operator
  promotes it.

**Estimated effort:** 6–8 weeks for one person. Biggest unknowns:
#93 (OCI daemonset shape across CRI implementations — containerd
should be uniform, but BPF mounts differ subtly between Docker /
containerd / cri-o), #97 (backpressure signal stability — tuning
the agent-side hysteresis without thrashing on bursty load), and
#100 (subprocess unix-socket protocol — keep it dirt-simple to
avoid re-inventing gRPC inside the agent).

## 8. Phase 6 — Extensions & Console Expansion

**Goal:** ship the first-party extension model (interface + supervisor +
reference osquery bridge), the live-query hunt workflow, snapshot-on-
alert wiring, the deferred-from-v1 console surfaces (live process-tree
explorer, saved queries, dashboards, OIDC SSO), and the §10 deferred-
question closures that ADR-0035 parked here. New operator-facing capability
*does* land in Phase 6 (unlike Phase 5) — but bounded to the extension
surface + console UX. Detection content + response action surface stay
frozen.

Phase 5 closed at task #103 (cloud-VM exit validation, 2026-05-02 with
captures under `phase5_validation/`). Phase 6 picks up at #104,
mirroring the §3.x / §4.1 / §5.1 / §6.1 / §7.1 numbered-task pattern.

Architectural contract for Phase 6 lives in **ADR-0037**
(`docs/adr/0037-phase6-scope.md`): first-party extension model only
(no public SDK, no marketplace, no dynamic loading); operator-installed
extension binaries (closes §10.6); osquery as the sole shipped
reference extension; rule-pack signing folded into extension-signing
infra (closes §10.5); OIDC SSO console backend (closes §10.7);
TPM-sealed cert variant + Gap A keyring strategy (Phase 6+ piece of
§10.2 + Phase 5 #103 carry-over); snapshot-on-alert wire ships empty;
multi-arch buildx + live k8s validation closing #93's deferred piece.

### 8.1 Tasks

**Dependency graph at a glance:**
- **A. Foundation:** #104 (this ADR + breakdown) → #105 (Phase 5 carry-over remediation) — sequential
- **B. Extension wire + supervisor:** #106 (extension.proto + framing) → #107 (agent supervisor) → #108 (distribution + signing decision) — sequential, locks the wire
- **C. Reference extension:** #109 (osquery bridge) → #110 (live-query hunt) — sequential, both need #107
- **D. Server-side surfaces:** #111 (snapshot-on-alert wire — needs #107), #112 (server-side tamper-chain cross-check — independent) — parallel after #107
- **E. Console expansion:** #113 (OIDC SSO), #114 (live process-tree explorer), #115 (saved queries + dashboards), #116 (search refinements + reopen-alert) — independent of the extension track, parallel from #105
- **F. Keystore + TPM:** #117 (Gap A keyring strategy — ADR-0038 + code), #118 (TPM-sealed variant) — sequential
- **G. Distribution polish:** #119 (multi-arch buildx + live k8s) — independent, parallel after #105
- **H. External read-only JSON API:** #120 (eyeexam contract — ADR-0040; bearer-token middleware + tag plumbing + JSON handlers) — independent, parallel after #105
- **Exit gate:** #121 (subsumes everything; user-execution like #29/#46/#70/#86/#103)

1. **#104 — ADR-0037 + scoping spike (this commit).** Locks: first-
   party extension model (unix socket + length-delimited protobuf,
   capability-enum-gated, cosign-keyless-signed, agent-supervised);
   operator-installed extension binaries (closes §10.6); rule-pack
   signing folded into extension-signing infra (closes §10.5); osquery
   bridge as the sole shipped reference extension; live-query hunt
   workflow with per-host row cap + per-hunt timeout; snapshot-on-
   alert wire ships empty (no extension in Phase 6 provides one);
   OIDC SSO closes §10.7; live process-tree explorer + saved queries +
   dashboards on the console expansion track; server-side tamper-
   chain cross-check (#95 follow-up); Gap A keyring strategy
   resolution + TPM-sealed cert variant (Phase 6+ piece of §10.2);
   multi-arch buildx + live k8s validation (#93 carry-over); default-
   detect-only carries forward; action surface still frozen at six.
   Touches: `docs/adr/0037-phase6-scope.md`, `IMPLEMENTATION.md §8`.
   **Exit:** ADR accepted; §8.1 task breakdown in place.

2. **#105 — Phase 5 carry-over remediation.** Three operational
   papercuts from the #103 cloud validation captured under
   `docs/phase5-validation.md §"Cosmetic warnings caught"`:
   (a) `selfprotect.LockdownStateDirs` should detect read-only mounts
       (e.g. `/etc/slither` under `ProtectSystem=strict`) and skip the
       chmod attempt rather than logging a self-inflicted WARN;
   (b) `nfpm.yaml` postinst order — `/var/log/slither` came back at
       0755 not 0700 on Debian apt-install; verify the postinst chmod
       runs after the dir creation regardless of pre-existing dir
       state, and add a regression check on the deb install path;
   (c) `docs/threat-model.md §"Surface 4 — Information disclosure"`
       amended to reflect the keyring is best-effort additive (not
       the primary cert store) per Gap A's hot-fix; #117's resolution
       overwrites this section in turn.
   Touches: `agent/internal/selfprotect/lockdown.go`,
   `deploy/nfpm/nfpm.yaml`, `docs/threat-model.md`. **Exit:**
   integration test for (a)+(b); doc edit verified by re-reading.

3. **#106 — Extension wire + framing.** New
   `proto/slither/v1/extension.proto` namespace (separate from
   agent.proto + control.proto — extensions never touch the server-
   facing wire). Messages: `Hello{name, version, capabilities[]}`,
   `OCSFEvent{class_uid, payload}`, `LiveQueryRequest{query_id, sql}`,
   `LiveQueryRow{query_id, columns, values}`, `LiveQueryComplete{query_id, error?}`,
   `SnapshotRequest{snapshot_id, alert_id, target}`,
   `SnapshotChunk{snapshot_id, sha256, bytes}`, `SnapshotComplete{snapshot_id, manifest}`.
   Capability enum: `CAPABILITY_OCSF_EMIT`, `CAPABILITY_LIVE_QUERY_RESPOND`,
   `CAPABILITY_SNAPSHOT_PROVIDE`. Length-delimited protobuf framing
   over a unix socket — each direction is a stream; sender writes
   varint-length + payload, reader matches. Generated bindings live
   at `proto/slither/v1/extension/*.go`. Touches: `proto/slither/v1/extension.proto`
   (new), `make gen-proto` (extend), `pkg/extsdk/codec.go` (new
   length-delim helpers — agent and extensions share). **Exit:**
   `make verify-gen` clean; round-trip codec tests; ADR-0011's
   slither.v1 additive-only invariant preserved (no edits to
   agent.proto / control.proto in this task).

4. **#107 — Agent extension supervisor.** New `agent/internal/extensions/`
   with `Manager` (per-extension lifecycle), `Process` (cosign-verify +
   spawn + cap-cgroup + RSS limit + stdout/stderr capture + restart
   with 1s→60s ±25% jitter backoff matching #35), and `Channel` (the
   length-delim codec + capability-gate enforcement — an extension
   that didn't declare `OCSFEmit` cannot push events). Operator
   declaration: new `extensions:` list in `agent.yaml` with
   `name`, `binary_path`, `signature_path`, `capabilities[]`, optional
   `rss_limit_mib` (default 256), optional `cpu_share` (default 256/1024).
   Cosign verify uses the same trust root as Phase 5 #91 release
   verification — read `~/.slither/cosign.pub` or
   `/etc/slither/cosign.pub`, fail-closed on missing. OCSF events
   from extensions get stamped with `device.uid` + `time` + audit
   fields by the agent before forwarding on the existing gRPC sink
   (#35) — extensions never see the server-facing wire. New telemetry
   counters: `ext_spawned`, `ext_restarts`, `ext_signature_failures`,
   `ext_capability_violations`, `ext_events_emitted`. Touches:
   `agent/internal/extensions/` (new), `agent/internal/config`
   (extensions schema), `agent/internal/app/app.go`. **Exit:** unit
   tests cover signature reject + capability violation + restart
   backoff + RSS-cap kill; integration test with a stub extension
   that emits 1k OCSF events shows them landing in the gRPC sink
   indistinguishable from native collector events.

5. **#108 — Extension distribution + signing model (closes §10.5 + §10.6).**
   Concretely: (i) operator-installed only — agent.yaml declares paths,
   no server-pushed binaries (server-pushed deferred to Phase 6+ per
   ADR-0037); (ii) every extension binary cosign-keyless-signed using
   the same OIDC chain as the slither release (Phase 5 #91), verified
   by the agent on every spawn (#107); (iii) rule-pack signing — folds
   into the same infra: `slither-db insert-rule --signed-bundle FILE`
   verifies a detached cosign signature on a tar of YAML files before
   ingest, default required when reading from any path under
   `/usr/share/slither/rules/` and any HTTPS URL; in-band rule push
   over the control channel stays unsigned (mTLS + server-trust
   covers it per ADR-0035's reasoning). New `slither-db verify-rule-bundle`
   subcommand for offline checks. ADR-0039 (drafted as part of this
   task) documents the trust root, the keyless-vs-keyed call, and the
   verification sequence. Touches: `server/cmd/slither-db/`,
   `server/internal/store/pg/rules.go`, new `pkg/sigverify/`,
   `docs/adr/0039-extension-and-rule-signing.md` (new), `docs/install.md`
   (signed bundle workflow). **Exit:** signed bundle + signed extension
   binary install paths both work end-to-end on Debian 13; tampered
   bundle / tampered extension binary both refuse cleanly.

6. **#109 — osquery bridge reference extension.** New
   `extensions/osquery/` (in-tree). Imports `pkg/extsdk/`. Connects to
   osqueryd via the standard osquery extension socket (`osquery.em`).
   Subscribes to a curated table list:
   `process_events`, `socket_events`, `file_events`, `listening_ports`,
   `kernel_modules`, `ssh_keys`, `authorized_keys`. Per-table OCSF
   mapper in `extensions/osquery/mappers/<table>.go` — fixture-tested
   against captured osquery row JSON. Declares `CAPABILITY_OCSF_EMIT`
   + `CAPABILITY_LIVE_QUERY_RESPOND`. **Does not** declare
   `CAPABILITY_SNAPSHOT_PROVIDE` — osquery snapshot tables are a
   Phase 7 exercise. Build: `make ext-osquery` produces
   `bin/slither-ext-osquery` (single static binary); release pipeline
   signs it via the existing cosign step (#91). Operator install:
   drop binary + signature into `/usr/lib/slither/extensions/`,
   declare in `agent.yaml`, restart agent. Touches: new
   `extensions/osquery/`, `Makefile` (ext-osquery target),
   `.github/workflows/release.yml` (osquery binary + signature in
   release artefacts), `docs/install.md` (extensions section).
   **Exit:** integration test on Debian 13 — install osqueryd, install
   bridge, fire a `process_events` row from osquery → assert OCSF
   `process_activity` lands in CH with `provenance.tag=osquery`.

7. **#110 — Live-query hunt workflow.** Server side: new `hunts` pg
   table (id, dispatched_by, query, host_filter, dispatched_at,
   timeout_secs, max_rows_per_host, status, completed_at). New
   `pb.ServerMessage.hunt_query` (additive on slither.v1). Console
   `/hunt` page (analyst+admin gated) — POST dispatches, GET lists,
   GET `/hunt/{id}` shows aggregated results with pagination + CSV
   export. New `pb.ClientMessage.hunt_result` (additive) carries
   row chunks. Hub fans `HuntQuery` to subscribed sessions filtered
   by `host_filter`; agent forwards to the extension declaring
   `LiveQueryRespond` (osquery bridge in v1); bridge runs query,
   streams `LiveQueryRow` chunks back; agent wraps in
   `HuntResult` and ships over Session stream. Per-host row cap
   default 10k; per-hunt timeout default 60s; both operator-tunable
   per-hunt. CH `hunt_results` table for aggregated rows (raw JSON
   + host_id + query_id, partitioned daily, 7-day TTL). Audited
   like response actions (`hunt.dispatched`, `hunt.completed`,
   `hunt.cancelled`). RBAC: analyst dispatches; viewer 403. Touches:
   `proto/slither/v1/control.proto` (additive), `proto/slither/v1/agent.proto`
   (additive), `server/internal/hunt/` (new), `server/internal/grpcserv/session.go`
   (multiplex `HuntQuery` onto runSendLoop), `server/migrations/00017_hunts.sql`,
   `server/clickhouse/migrations/00006_hunt_results.sql`,
   `server/internal/console/hunt.go` (new), `agent/internal/output/grpc/sink.go`
   (handle `HuntQuery`, dispatch to extension via #107). **Exit:**
   integration test — dispatch `SELECT * FROM listening_ports` against
   a 3-host fleet, assert all three respond within 60s, results
   aggregate at `/hunt/{id}` with per-host source attribution; row
   cap enforced (synthetic 100k-row response truncated to 10k).

8. ✅ **#111 — Snapshot-on-alert wire + alert-detail UX.** Optional
   per-rule top-level YAML key `slither.snapshot: true` (parsed in
   `pkg/ruleast` alongside `slither.response`). When the rule fires,
   AutoResponder (#83) submits a synthetic `SnapshotRequest` to every
   loaded extension declaring `CAPABILITY_SNAPSHOT_PROVIDE`.
   Extension streams `SnapshotChunk` back; agent reassembles and
   uploads via the existing `collect_artifacts` upload path
   (Phase 4 #81) under `/var/lib/slither/artefacts/<alert_id>/<extension_name>.tgz`.
   Console alert-detail page surfaces per-extension snapshot
   downloads inline. Phase 6 ships **no extension that provides
   snapshots** — the wire + UX land empty so Phase 7 can slot in
   without a wire bump. New `pb.SnapshotRequest` etc. on extension.proto
   (already covered by #106). New telemetry counters:
   `ext_snapshots_requested`, `ext_snapshots_completed`,
   `ext_snapshots_failed`. Touches: `pkg/ruleast/` (snapshot parse),
   `agent/internal/respond/auto.go`, `server/internal/respond/hub.go`,
   `server/internal/console/alerts.go`. **Exit:** unit tests cover
   the auto-trigger path with a stub extension; alert-detail page
   shows an "(no snapshot extensions configured)" note when the
   alert's rule has snapshot=true but no extension declares the
   capability — operator never sees a silent no-op.
   *(Shipped 2026-05-05. `slither.snapshot: true` parses through
   `pkg/ruleast` onto both `EdgeArtefact.Snapshot` and
   `ServerPlan.Snapshot`. ResponseRequest + ResponseResult gained
   additive `snapshot_alert_id` + `snapshot_extension_name` fields
   (slither.v1 wire-freeze preserved per ADR-0011). Agent supervisor
   gained `Process.DispatchSnapshot` + `Manager.DispatchSnapshot`
   fanout; reassembly runs in the AutoResponder with a rolling
   SHA-256 chain verify and a 60 s per-provider deadline. Reassembled
   blobs ride the existing collect_artifacts result path via
   `Executor.EmitSnapshotResult`; the server's
   `Hub.persistSnapshotArtefact` lands them under
   `<artefactDir>/<alert_id>/<extension>.tgz`. Console alert detail
   surfaces per-extension blobs with size + capture-time and exposes
   downloads at `/alerts/{id}/snapshots/{extension}`; rules with
   `snapshot=true` and no providers render the "(no snapshot
   extensions configured)" no-op note. Phase 6 ships **no extension
   that provides snapshots** — the wire + UX land empty so Phase 7
   slots in without a wire bump. New telemetry counters
   `ext_snapshots_requested`, `ext_snapshots_completed`,
   `ext_snapshots_failed`. New OCSF finding markers
   `x_snapshot_requested`, `x_snapshot_no_providers`. Tests cover
   no-provider path, fanout-and-submit path with two stub
   providers, and per-provider failure accounting.)*

9. ✅ **#112 — Server-side tamper-chain cross-check.** New
   `pb.ClientMessage.chain_summary` (additive slither.v1 bump).
   Agent emits `ChainSummary{last_seq, last_hash, count, since}` to
   the server every 5 minutes (cheap; the chain is small). Server
   walks the equivalent CH `response_actions` + `detection_findings`
   rows for that host + window, recomputes the expected chain hash,
   compares. Mismatch fires a `chain.mismatch` audit event with
   severity 4 (high). New console page `/hosts/{id}/chain-status`
   shows last summary + mismatch history. **No new alert class** —
   audit-only, surfaced in the audit log + the host page. New pg
   helper `pg.RecordChainSummary` + `pg.ListChainMismatches`. Touches:
   `proto/slither/v1/agent.proto` (additive), `agent/internal/selfprotect/chain.go`
   (emit summary), `server/internal/grpcserv/session.go` (handle
   summary), `server/internal/detect/chain.go` (new — verifier),
   `server/internal/console/hosts.go` (chain-status page), migrations
   `00018_chain_summaries.sql`. **Exit:** integration test — agent
   emits valid summary → no mismatch; tamper a single audit row in
   pg → next summary fires `chain.mismatch`; doc-link from
   `/hosts/{id}` to the chain-status page.
   *(Shipped 2026-05-05. Phase 6 lands the **count-based** form: the
   agent's per-record hash includes a wall-clock TS the server can't
   reconstruct from CH/pg rows, so a literal record-by-record
   recompute would silently always mismatch. Server counts equivalent
   rows in `pg.response_actions` (terminal status, completed_at in
   window) + ClickHouse `ocsf_detection_finding_2004` (observed_at in
   window) for (host, [since, observed_at)) and compares against the
   agent's `count` field. SkewSlack=1 absorbs the one-row CH-batch
   flush race; beyond that fires a `chain.mismatch` audit row at
   severity 4. `last_hash` is stored verbatim for forensic compare,
   not recomputed. Phase 7 carry-over (§9) picks between dropping
   `ts` from hash inputs and stamping per-record hashes onto each
   row so the chain can be replayed link-by-link. Wire (additive
   slither.v1 per ADR-0011): `ClientMessage.chain_summary` carrying
   `ChainSummary{last_seq, last_hash, count, since, observed_at}`.
   Agent adds `ChainWriter.SnapshotAndReset()` (windowed counter
   resets each tick) + `runChainSummaryTicker` (5min cadence,
   non-blocking emit onto sink). Sink gains `chainSummaries chan` +
   `ChainSummaries()` accessor; session goroutine multiplexes
   `ClientMessage_ChainSummary` alongside hunt + response paths.
   Server adds `detect.NewChainVerifier`, pg helpers
   `RecordChainSummary` / `ListChainSummaries` /
   `ListChainMismatches` / `CountResponseActionsForChain`, ch helper
   `CountDetectionFindingsForChain`, and migration
   `00018_chain_summaries.sql` with mismatch partial index. Console
   page `/hosts/{id}/chain-status` lists recent summaries and a
   dedicated mismatch sub-table; viewer-readable, no role gate
   beyond auth. Tests: agent
   `TestChainWriter_SnapshotAndReset` covers windowed counter +
   reset-rolls-forward; server
   `TestChainVerifier_{HappyPath,SkewSlackAbsorbs,MismatchFiresAudit,
   CHErrorDegrades,InvertedWindowSkipsCount,PGErrorSurfaces}` cover
   the audit-firing + degradation paths.)*

10. ✅ **#113 — Console SSO (OIDC) backend (closes §10.7).** New
    `server/internal/console/oidc.go` with the standard
    `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3` pair.
    Auth-code flow with PKCE; discover via `well_known_url` config.
    Role mapping via configurable `role_claim` + per-claim-value role
    table (e.g. `role_mappings: { "slither-admin": "admin", "slither-analyst": "analyst" }`).
    No group sync, no SCIM. Sits *alongside* local users — operator
    can still log in as the bootstrap admin if the IdP is down. New
    /login page gains "Sign in with SSO" button (rendered only when
    OIDC is configured). New pg column `users.oidc_subject` (UNIQUE,
    nullable) — first-time SSO login creates the user with
    `username=email`, role from claim mapping; subsequent logins
    match on `oidc_subject`. Audit: `auth.oidc.success` /
    `auth.oidc.failure` (with reason). Touches: new
    `server/internal/console/oidc.go`, `server/internal/store/pg/users.go`
    (oidc_subject helpers), migrations `00019_users_oidc.sql`,
    `server/internal/config` (oidc block in console config),
    `docs/install.md` (SSO setup section). **Exit:** integration test
    against a Dex-shaped local IdP — login flow completes, user is
    created on first login with role from claim, role mapping
    persists across logins, IdP-down fallback to local-user login
    still works.
    *(Shipped 2026-05-05. New `server/internal/console/oidc.go`
    implements auth-code flow with PKCE (RFC 7636 §4.2 S256 challenge),
    state + nonce binding, and rotated session tokens after
    successful auth. Provider discovery via go-oidc has a 10s timeout
    and degrades gracefully — discovery failure logs + leaves SSO off
    rather than blocking server boot, since refusing boot would lock
    every operator out for a transient IdP blip. Migration
    `00019_users_oidc.sql` adds `users.oidc_subject text UNIQUE` and
    relaxes `password_hash` to nullable, gated by a CHECK constraint
    requiring at least one of (password_hash, oidc_subject). pg
    helpers: `GetUserByOIDCSubject`, `InsertOIDCUser` (returns
    `ErrUserExists` on collision), `UpdateUserRole` (refreshes role
    on subsequent SSO logins when the IdP claim mapping changes).
    Config: `console.oidc` block with `issuer_url`, `client_id`,
    `client_secret`, `redirect_url`, `scopes` (default openid + email
    + profile), `role_claim` (default "groups"), `role_mappings`
    (claim-value → role), `username_claim` (default "email").
    Validation refuses partial blocks at boot (issuer set but
    client_id blank → clean error). Audit:
    `auth.oidc.success`/`auth.oidc.failure` with reason codes
    (state_mismatch, state_expired, nonce_mismatch, exchange_failed,
    id_token_invalid, no_role_mapping, username_collision,
    insert_failed, lookup_failed). Login page renders "Sign in with
    SSO" button only when `s.oidc != nil`. 11 unit tests cover role
    mapping (string/array/[]any/[]string variants, first-match
    wins, no-match, missing claim), PKCE S256 against the RFC 7636
    sample, randomness uniqueness, claim helpers, and 5 config
    validation paths (partial block, missing role_mappings, bad role,
    full block accepted, empty block accepted).)*

11. ✅ **#114 — Live process-tree explorer (closes ADR-0024 deferral).**
    Replaces the SSR mini-graph (#65) on the alert-detail page with
    an interactive explorer; mini-graph stays as the fallback for
    server-rendered notification targets. New
    `server/internal/console/static/process-tree.js` (vanilla, no
    framework — matches Phase 4's respond.js). Backend: new
    `GET /alerts/{id}/process-tree.json?root_pid=N&depth=N` returns
    JSON nodes + edges (re-uses #65's `ch.Store.ListProcessChildren`
    + new `ch.Store.ListProcessAncestors`). Client renders via SVG
    pan/zoom; click a node to expand its children inline (lazy-loaded
    from the same endpoint with the clicked PID as root); right-click
    surfaces "kill_process" + "kill_tree" + "collect_artifacts"
    buttons gated on `pg.HostPolicy.PermitsAction` (re-uses #74).
    Default root = the alert's triggering PID; default depth = 4
    (matches #65). Hard cap 256 nodes per render (matches #65) with
    "expand more" sentinel for over-cap subtrees. Cache: same
    `graph.Cache` instance (#64) with `pte_<host>_<pid>_<depth>`
    namespace. Touches: `server/internal/console/alerts.go`,
    new `server/internal/console/static/process-tree.js`,
    new `server/internal/detect/processtree_json.go`,
    `server/internal/store/ch/process.go`. **Exit:** alert detail
    page renders the explorer; click expand walks one hop per click;
    response-action right-click respects host policy (denied actions
    hidden). Manual UX walkthrough on a fleet alert during #120.
    *(Shipped 2026-05-05. New
    `server/internal/detect/processtree_json.go` builds the JSON
    projection (nodes + edges + has_more_children + truncated_at)
    using the same ProcessTreeLookup interface as the D2 builder so
    test stubs work for both. New
    `ch.Store.ListProcessAncestors` walks parent_pid up to maxDepth
    hops with cycle defence. New JSON endpoint
    `GET /alerts/{id}/process-tree.json?root_pid=N&depth=N` defaults
    root_pid to the alert's first triggering event's actor PID
    (process events expose PID directly; file/net via ActorPID).
    Vanilla JS in `server/internal/console/static/process-tree.js`:
    BFS-grid layout, SVG pan via mousedown drag, zoom via wheel
    (0.25–4× clamp), click-to-expand re-fetches with the clicked PID
    as the new root, right-click menu surfaces kill_process /
    kill_process_tree / collect_artifacts buttons gated on
    `pg.HostPolicy` data-attributes. Right-click menu hidden for
    viewers and for actions the host policy denies; submitted via
    the existing /alerts/{id}/respond form so #75's RBAC + audit path
    still gates the executor. Mini-graph (#65) stays available via
    the same alert detail page for SSR notification targets;
    explorer renders alongside it when `chStore != nil`. 6 unit
    tests cover root-missing → not_found, stable depth-bounded
    render, fanout-cap signalling, depth bound respected, empty/zero
    input rejection.)*

12. **#115 — Saved queries + per-user dashboards.** New pg tables:
    `saved_queries` (id, user_id, name, surface ∈ {events, alerts,
    hunts}, params jsonb, created_at, updated_at) and `dashboards`
    (id, user_id, name, layout jsonb, created_at, updated_at).
    Filter forms on `/events`, `/alerts`, `/hunt` gain a "Save"
    button that captures the URL params under a user-supplied name.
    New `/queries` page lists the user's saved queries; click to
    re-run on the original surface. New `/dashboards` page — per-user
    layout of saved-query result cards (count + top-N list per card,
    fixed grid; v1 layout shape stays simple — no resize/drag in
    Phase 6, just card-add/card-remove). Shared dashboards parked
    Phase 7+ per ADR-0037. Touches: migrations `00020_saved_queries.sql`
    + `00021_dashboards.sql`, new `server/internal/console/queries.go`,
    new `server/internal/console/dashboards.go`, console nav. **Exit:**
    save a filter on `/events`, see it on `/queries`, re-run lands
    on `/events?...` with the same filter; create a dashboard with
    two cards, refresh persists; delete a saved-query that's referenced
    by a dashboard card → card surfaces a "(query deleted)" placeholder
    instead of erroring.

13. **#116 — Search refinements + reopen-alert.** Two sub-deliverables
    bundled because both are small UX wins on existing pages:
    (a) `/events` query language — promote from filter form to a
        single text-input parser supporting `host:foo class:1007 since:24h`-shape
        tokens, with autocomplete on the host and class axes. Filter
        form stays as the fallback for non-shell users (toggle).
        Query history at `/events/history` — last-50-queries per user,
        click to re-run.
    (b) Reopen-alert — `closed → in_progress` transition on the
        `/alerts/{id}/transition` endpoint (existing route, just add
        the transition to `IsValidAlertTransition`). Was deferred from
        Phase 3 #61 ("closed is terminal in v1, reopen Phase 5"); slid
        to Phase 6. Audit logs the reopen with `alert.reopened` reason.
    Touches: `server/internal/console/events.go`, new
    `server/internal/console/static/query-parser.js`, new
    `server/internal/store/pg/query_history.go`, migrations
    `00022_query_history.sql`, `server/internal/store/pg/alerts.go`
    (transition table), `server/internal/console/alerts.go`. **Exit:**
    unit tests for query-parser tokeniser (host:/class:/since: forms,
    quoted strings, unknown tokens fall through to raw-bytes contains);
    reopen-alert path 200s and writes audit row.

14. **#117 — Keystore Gap A resolution + ADR-0038.** Decide between
    options (a) drop kernel-keyring entirely, (b) `KEY_SPEC_USER_KEYRING`
    (`@u`) per-uid persistent, (c) systemd helper unit pre-populating
    via `KeyringMode=shared`. ADR-0037 narrowed the trade table; this
    task makes the call with code. Working hypothesis from the trade
    table: option (b) — `@u` survives session boundary, available on
    every kernel ≥ 3.5, smallest code change vs (a)/(c). Validate
    against Debian 13 + RHEL 10 + Ubuntu 24.04 + the OCI image during
    the task's integration tests, not during #120. ADR-0038 records
    the chosen option + the alternatives considered. `docs/threat-model.md
    §"Surface 4"` rewritten to describe the chosen strategy as the
    primary cert store, file fallback for keyring-unavailable hosts.
    Touches: `agent/internal/keystore/keyring_linux.go`, possibly
    `deploy/systemd/slither-agent.service` (KeyringMode=shared if (c)),
    new `docs/adr/0038-keystore-strategy.md`, `docs/threat-model.md`.
    **Exit:** integration test on all four host shapes — keyring
    survives enroll → restart → second-boot lookup; unattended-host
    use cases (no PAM session) still resolve cleanly.

15. **#118 — TPM-sealed cert variant.** New `agent/internal/keystore/tpm_linux.go`
    using `github.com/google/go-tpm` (or equivalent). PCR 7 (Secure
    Boot state) bound — host that boots un-Secure-Boot can't unseal.
    Opt-in via `agent.keystore.tpm: true` in `agent.yaml`; absent
    `/dev/tpmrm0` or unreadable PCR → fall back to #117's chosen
    keyring strategy → fall back to file. Operator workflow: on
    first enroll with TPM enabled, the seal is created; on every
    subsequent boot, agent unseals against current PCR state. PCR
    re-measure (kernel update changing the boot chain) breaks the
    seal — operator-visible failure mode documented in install.md.
    **Not the default** — the configuration matrix gets large fast
    and ROI without measured boot is small. ADR-0037 already locks
    the scope. Touches: `agent/internal/keystore/tpm_linux.go` (new),
    `agent/internal/keystore/store.go` (TPM as another `Store` impl
    behind the same interface), `docs/install.md` (TPM section,
    "When to use this"). **Exit:** integration test on a TPM-equipped
    VM (AWS nitro-enclave-shaped instance) — seal on enroll, unseal
    on restart; intentionally bump kernel → next boot fails to unseal,
    falls back, operator sees the documented error.

16. **#119 — Multi-arch buildx + live k8s validation (#93 carry-over).**
    Phase 5 #93 shipped a single-arch amd64 OCI build with daemonset
    YAML; multi-arch buildx + live cluster validation were deferred.
    This task: (i) `.github/workflows/release.yml` extended with
    `docker buildx` for `linux/amd64` + `linux/arm64` on the agent +
    server images; (ii) k3s spin-up on a Phase 6 validation VM,
    daemonset deploy via the existing `deploy/k8s/daemonset.yaml`,
    enrolment + event-flow + revoke-cycle smoke; (iii) k8s-shape
    documentation in `docs/install.md §"Kubernetes deployment"`
    (PVC sizing, Secret rotation pattern, daemonset rolling-restart
    behaviour). Touches: `.github/workflows/release.yml`,
    `docs/install.md`, possibly small `deploy/k8s/*.yaml` tweaks
    surfaced by live validation. **Exit:** `ghcr.io/.../slither-agent:vX`
    has both arch manifests; daemonset on k3s reports events to the
    server; arm64 host (Graviton EC2) runs the agent natively without
    qemu-user.

17. **#120 — External read-only JSON API for BAS integrations.**
    Adds a `/api/v1/*` route subtree separate from the HTML console,
    bearer-token-authenticated, read-only, contract-frozen at v1.
    Built to satisfy the eyeexam contract at
    `../eyeexam/docs/slither-api-requirements.md`; future external
    detector / scoring consumers slot into the same surface.
    ADR-0040 locks the shape. Four sub-deliverables, one task to
    keep the contract atomic:
    (a) Bearer-token middleware + `api_keys` pg schema (id, name,
        argon2id hash, created_by, created_at, last_used_at,
        revoked_at, scopes text[]). 32-byte URL-safe-base64 token
        prefixed `slither_apikey_`. First-16-chars-of-base64 prefix
        index drives lookup so we don't argon2id every row per
        request. Admin-only console pages `/api/keys` (list + mint
        with one-shot scs flash) and POST `/api/keys/{id}/revoke`,
        mirroring #45's enrolment-token UX. Audit `api_key.minted` /
        `api_key.revoked` / `api_key.used`. New
        `server/internal/console/apiauth/middleware.go` — applied
        only on `/api/v1/*`, leaves `/healthz` (HTML console),
        `/login`, the rest of the console untouched.
    (b) MITRE tag plumbing — agent → OCSF → CH. Today
        `pkg/ruleast.Rule.Tags []string` carries Sigma `tags:`
        verbatim; `agent/internal/ruleengine/finding.go.buildFinding`
        drops them on the floor. This task: buildFinding picks up
        `rule.Tags`, normalises to lowercase, filters to
        `attack.t*`/`attack.s*`/`attack.g*` prefixes, populates
        `ocsf.DetectionFinding.MitreATTACK[]MitreTag` with
        `Technique.UID = "T1070.003"`-shape values. CH writer in
        `server/internal/store/ch/writer.go` extracts the technique
        UIDs into the existing `mitre_techniques Array(String)`
        column on `ocsf_detection_finding_2004` (provisioned by
        migration 00004, unused since). No backfill — pre-existing
        events stay tag-less; eyeexam queries post-test detections.
    (c) `EventFilter` + `SearchEvents` filter additions:
        `RuleUID string` → `WHERE rule_uid = ?` and `Tag string` →
        `WHERE has(mitre_techniques, ?)`. Both narrow on
        class_uid=2004; queries pairing `Tag != ""` with
        non-2004-only `class_uids` return zero rows by construction.
        HTML console's `/events` page does NOT grow these inputs in
        this task — keeping the JSON API additive avoids regressing
        anyone's saved queries from #115.
    (d) JSON handlers:
        - `GET /api/v1/healthz` — JSON `{"ok": true}`,
          unauthenticated. Distinct from HTML `/healthz` so an API
          consumer never sees an HTML body.
        - `POST /api/v1/events/search` — body matches the eyeexam
          spec: `host_id`/`host_name`, `sigma_id`/`rule_uid`,
          `tag`, `class_uids`, `since`/`until`, `cursor`, `limit`.
          `host_name` resolves to `host_id` via `pg.GetHostByName`
          before hitting CH. Response: `hits[]` (id, host_id,
          host_name, observed_at, class_uid, severity_id, rule_uid,
          rule_name, raw OCSF JSON) + `next_cursor`. Cursor reuses
          the existing `ch.Cursor` opaque encoding — same shape as
          the HTML pagination key.
        - `GET /api/v1/rules` (optional, recommended) — JSON list
          of currently-loaded Sigma rules with optional
          `?since=&technique=` filters. Wraps `pg.ListEnabledRules`
          + a slim projection.
        - 401/403/4xx all return JSON error bodies, never the HTML
          login page.
    Touches: `server/internal/store/ch/search.go` (filter fields +
    WHERE clauses), `server/internal/store/ch/writer.go` (technique
    extraction), `agent/internal/ruleengine/finding.go` (tag
    population), `pkg/ocsf/finding.go` (no struct change — the
    `MitreATTACK` field already exists), new
    `server/internal/api/v1/{events,rules,health,errors}.go`,
    new `server/internal/console/apiauth/`, new
    `server/internal/store/pg/api_keys.go`, new migrations
    `00023_api_keys.sql`, new `server/internal/console/api_keys.go`,
    new `docs/api-v1.md`. **Exit:** integration test — mint a key,
    fire a Sigma rule with ATT&CK tags, query
    `POST /api/v1/events/search` with `tag=attack.t1070.003` →
    one hit, technique extracted into `mitre_techniques`,
    `host_name` lookup resolves correctly, revoke key → next call
    401s with JSON body; OpenAPI/JSON-Schema description in
    `docs/api-v1.md` reviewed end-to-end.

18. **#121 — Phase 6 exit validation.** Doc-backed manual run on the
    Phase 3/4/5 cloud fleet (existing stopped instances —
    `start-instances` brings them back; allocate one Graviton instance
    for arm64 coverage from #119). Validates:
    (i) extension supervisor — install osquery bridge on Debian 13
        + RHEL 10 + Ubuntu 24.04, signed-bundle install path works,
        tampered binary refuses cleanly, OCSF events from osquery
        land in CH with `provenance.tag=osquery`;
    (ii) live-query hunt — dispatch `SELECT * FROM listening_ports`
        against the 3-host fleet, all three respond within 60s,
        results aggregate at `/hunt/{id}` with per-host attribution;
        per-host row cap enforced;
    (iii) snapshot-on-alert wire — fire a rule with
        `slither.snapshot: true`, alert detail surfaces the
        "no snapshot extensions configured" note (Phase 6 ships no
        snapshot provider — empty path validation);
    (iv) server-side tamper-chain cross-check — happy path emits
        clean summaries; intentional pg-side audit-row tamper fires
        `chain.mismatch` within 5 minutes; chain-status page
        reflects;
    (v) console SSO — Dex-shaped IdP integration roundtrip; first-
        login user creation; role mapping; IdP-down fallback;
    (vi) live process-tree explorer — replaces the mini-graph on a
        real alert; expand-on-click walks the tree; right-click
        response actions respect host policy;
    (vii) saved queries + dashboards — operator saves filters from
        `/events`, `/alerts`, `/hunt`; assembles a dashboard;
        per-user persistence;
    (viii) search refinements — `host:foo class:1007 since:24h`
        parses on `/events`; reopen-alert transition works;
    (ix) keystore Gap A resolution — chosen strategy survives the
        enroll → restart → second-boot lookup cycle on every host
        shape;
    (x) TPM-sealed cert variant — opt-in path works on the TPM-
        equipped instance; PCR-bump fallback observable on a
        kernel update;
    (xi) multi-arch + live k8s — daemonset on k3s reports events;
        Graviton agent runs natively;
    (xii) sustained-load backpressure e2e (deferred from Phase 5
        #103 V8) — `make load-test` against the fleet under pinned
        slow CH writer; agents observably raise NetworkActivity
        sampling within 30s; recovery within 30s of writer unpin;
    (xiii) eyeexam JSON API contract (#120 / ADR-0040) — mint an
        api key, fire a known Atomic test on a fleet host, eyeexam
        runs end-to-end (`eyeexam exec --pack ...`) against a
        live `slither-server`, scoring marks the expectation
        `caught` with `raw_json` populated and the host_name +
        sigma_id + tag filters all narrowing as advertised; revoked
        key returns 401 with JSON body.
    Capture under `phase6_validation/`; commit
    `docs/phase6-validation.md`. **Exit:** all green; Phase 6
    closed; Phase 7 (platform expansion) opens or stays parked
    pending demand per ADR-0037.

### 8.2 Cross-cutting notes

- **Wire stays additive within slither.v1.** Phase 6 adds three
  fields: `ServerMessage.hunt_query`, `ClientMessage.hunt_result`,
  `ClientMessage.chain_summary`. The extension wire is a *new*
  namespace (`extension.proto`) — first-party only, not part of
  slither.v1's public surface, no wire-freeze obligations. ADR-0011's
  invariant on slither.v1 holds.
- **First operator-facing capability since Phase 4.** Phase 5 was
  deliberately invisible to end-users; Phase 6 puts the live-query
  hunt + dashboards + SSO in front of operators. Release notes for
  Phase 6 are user-facing, not just changelog-facing.
- **Default-detect-only carries forward.** Per ADR-0034, every
  freshly-enrolled host lands at all-false. Extensions inherit the
  same posture — capability declarations are operator-scoped, not
  auto-granted.
- **§10 closes for v1.** §10.5 (rule signing — closed by #108),
  §10.6 (extension distribution — closed by #108), §10.7 (console
  SSO — closed by #113), §10.2's TPM piece (closed by #118). Only
  §10.3 (CH schema evolution under OCSF version bumps) remains open
  — we have the harness from Phase 5 #99; we don't yet have a forced
  bump.
- **External JSON API surface lands additively (#120 / ADR-0040).**
  `/api/v1/*` is a new public-facing surface contract; ADR-0040 binds
  it to the same wire-stability discipline as ADR-0011 binds
  `slither.v1`. Read-only by construction; future write surfaces need
  a fresh ADR. Bearer-token auth is orthogonal to argon2id+SCS
  (humans) and OIDC (#113, SSO humans) — three auth backends, three
  consumer types.
- **Snapshot-on-alert lands empty.** No extension in Phase 6 provides
  snapshots. This is deliberate — Phase 7's auditd / FIM / canary
  candidates are the natural snapshot providers; locking the wire +
  alert-detail UX without coupling rollout buys Phase 7 a clean
  slot-in.
- **Action surface still frozen.** Phase 4's six actions hold. New
  actions still need an ADR + an additive enum bump per §2.4.

**Estimated effort:** 8–10 weeks for one person — Phase 6 is broader
than Phase 5 because the extension model (4 tasks), console expansion
(4 tasks), and the new external JSON API track (1 task) are
independent fronts. #120 was a late add via ADR-0040 to satisfy the
eyeexam BAS-scoring contract; the work is small (1–2 weeks for one
person) because every CH-side filter, the cursor encoding, and the
`mitre_techniques` column already exist — only the agent-side tag
plumbing, the API tree, and the bearer-token middleware are net-new.
Biggest unknowns: #107 (cosign verify on every spawn — latency budget
vs operator restart UX), #110 (live-query latency budget across
≥10-host fleets — osquery itself is fast; the aggregation + console
SSE-shaped streaming is the unknown), #114 (vanilla-JS process-tree
pan/zoom without a framework — refresh-load + lazy-expand state
machine is fiddlier than #65's SSR shape), and #118 (TPM PCR re-
measure UX across distros — PCR 7 semantics differ subtly between
Secure Boot implementations).

## 9. Phase 7 — Platform Expansion (bullet, demand-driven)

- macOS agent (Endpoint Security framework; Apple Developer ID required).
- Windows agent (ETW-first; minifilter driver only if kernel-level file-write telemetry is needed; driver signing via EV cert).
- **Tamper-chain hash recompute (carry-over from #112).** Phase 6 #112 ships
  count-based cross-check only — the agent's per-record hash includes
  `ts` (RFC3339Nano local wall-clock) which the server cannot reconstruct
  from CH/pg rows, so a literal `record_hash` recompute is physically
  impossible without changing the canonical hash inputs. Phase 7 picks
  one of: (a) drop `ts` from the hash inputs and key on a server-derivable
  field per record kind (OCSF `time` for findings, pg `created_at` for
  response actions), or (b) carry the agent's per-record hash on each
  CH/pg row so the server can replay the chain link-by-link without
  re-deriving the fields. Either approach is an ADR + on-disk format
  bump for `log.chain` + a migration. Until then, count-based detection
  catches truncation + replay-then-extend; record-level edits remain
  detectable only via on-agent `slither-agent verify-chain`.
- Explicitly gated on demand + funding; not on the default trajectory.

---

## 10. Deferred Technical Questions

Things we know we will need to answer but do not need to answer *now*:

1. **Rule hot reload.** ✅ **Resolved (Phase 3 #69).** Production path is server-push: `control.Hub.Refresh` recompiles every enabled `rules` row, broadcasts the canonical `pb.RuleSet` to every connected agent's per-session capacity-1 channel, and the agent's `applyRuleSetTo` swaps the new pack into the running engine via `Engine.ReplaceRules` (#39). Postgres NOTIFY (`rules_changed`) drives a 200 ms-debounced refresh; a 30 s fallback poll covers the trigger missing case. Agent-side SIGHUP (`/agent/internal/app.applyReload`) stays in the binary for **dev only** — it re-reads the local YAML config and applies rule paths + file-collector globs without server involvement, useful for offline iteration on a rule pack before pushing to a real fleet. Production deployments don't ship with local rule paths configured (the systemd unit's `agent.yaml.sample` points at `/etc/slither/rules/` only as a fallback for air-gapped runs); the `slither-agent enroll` flow is the canonical onboarding path and lights up the server-push channel.
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
