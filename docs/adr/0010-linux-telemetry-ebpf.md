# ADR 0010 — Linux telemetry primitive: eBPF via CO-RE

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Linux provides several ways to observe kernel activity: eBPF, the audit subsystem, kernel modules, and `/proc`-polling. Each has different fidelity, performance, and operational characteristics. CO-RE (Compile Once, Run Everywhere) makes eBPF portable across kernels with BTF.

## Decision

eBPF with CO-RE is the sole kernel-telemetry primitive. Loader is `cilium/ebpf` (pure Go). Target kernel floor is 5.10 (ships in RHEL 9, Ubuntu 22.04). Kernels without `/sys/kernel/btf/vmlinux` are not supported.

### Amendment 2026-04-22

Kernel floor raised from 5.10 to **5.15**. RHEL 9's 5.14 verifier rejected
our per-syscall tracepoint programs with `max_ctx_offset`/`PTR_TO_CTX`
checks (EACCES on `BPF_LINK_CREATE`) that 5.15+ handles cleanly. Rather
than carry RHEL-9-specific workarounds (raw_syscalls dispatch, inlined
helpers), the support matrix retargets to **RHEL 10 / 6.12** which
matches the Debian 13 kernel family. Ubuntu 22.04 (5.15) remains the
floor; RHEL 9, RHEL 8, and Amazon Linux 2 are unsupported.

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
