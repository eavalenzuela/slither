# ADR 0002 — Agent language: Go (with eBPF C for kernel programs)

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The agent runs as root next to the kernel and parses untrusted data. Memory safety is a hard requirement for anything parsing event buffers. C and C++ are rejected on safety grounds. The viable options are Rust and Go.

## Decision

Agent userspace is Go. Kernel-side eBPF programs are C, compiled via clang + `bpf2go` and loaded with `cilium/ebpf`. Rust remains a future option for specific hot-path components if profiling demands it.

## Consequences

- Faster iteration than Rust; single-binary static-build story; large stdlib and ecosystem fit the networking, CLI, and observability needs.
- Go's garbage collector introduces pause variability. Acceptable so long as eBPF ring-buffer reads are tight; revisit if GC pauses ever cause dropped events in practice.
- Shared proto/OCSF types with the Go server with no codegen mismatch.
- Must use `cilium/ebpf` (pure-Go loader) — no libbpf runtime dependency in the shipped binary.

## Alternatives considered

- **Rust.** Strong safety, slower iteration, higher onboarding cost for contributors; deferred as an option if Go-side safety bugs prove to be a real issue.
- **C/C++.** Rejected on safety.

## References

- PROJECT.md §4.1, §9.1 row 2.
