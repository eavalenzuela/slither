// Package bpf holds the eBPF C programs and their generated Go bindings.
//
// Phase 1 programs (IMPLEMENTATION.md §3.2):
//   - process.bpf.c — sched_process_exec/exit/fork tracepoints.
//   - file.bpf.c    — openat, unlinkat, renameat2, fchmodat, fchownat syscalls.
//   - net.bpf.c     — tcp_connect, inet_csk_accept, udp_sendmsg kprobes.
//
// Bindings are produced by bpf2go at `make gen` time and embedded into the
// slither-agent binary via go:embed. No handwritten Go should live here except
// the bpf2go directive file.
package bpf
