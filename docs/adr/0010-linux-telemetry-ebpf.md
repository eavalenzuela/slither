# ADR 0010 — Linux telemetry primitive: eBPF via CO-RE

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Linux provides several ways to observe kernel activity: eBPF, the audit subsystem, kernel modules, and `/proc`-polling. Each has different fidelity, performance, and operational characteristics. CO-RE (Compile Once, Run Everywhere) makes eBPF portable across kernels with BTF.

## Decision

eBPF with CO-RE is the sole kernel-telemetry primitive. Loader is `cilium/ebpf` (pure Go). Target kernel floor is 5.10 (ships in RHEL 9, Ubuntu 22.04). Kernels without `/sys/kernel/btf/vmlinux` are not supported.

## Consequences

- Best-in-class event fidelity for processes, files, networking, and kernel-module loads.
- Higher performance than audit at equivalent coverage.
- Requires BTF on every monitored host. Older kernels (RHEL 8, Amazon Linux 2) are explicitly unsupported in v1.
- eBPF C source is a real build-time dependency (clang 16+, libbpf headers).

## Alternatives considered

- **audit subsystem.** Works on older kernels but lower fidelity and lossy under load.
- **Kernel module.** Rejected on maintenance + distro signing burden.

## References

- PROJECT.md §4.1, §9.1 row 11; IMPLEMENTATION.md §3.10.
