// Package bpf holds the eBPF C programs and their generated Go bindings.
//
// Phase 1 programs (IMPLEMENTATION.md §3.2):
//   - process.bpf.c — sched_process_exec/exit/fork tracepoints.
//   - file.bpf.c    — openat, unlinkat, renameat2, fchmodat, fchownat syscalls.
//   - net.bpf.c     — tcp_connect, inet_csk_accept, udp_sendmsg kprobes.
//   - auth.bpf.c    — libpam uprobes: pam_start/set_item/end entry,
//     pam_authenticate/open_session/close_session return (Phase 7).
//   - kernel.bpf.c  — module_load/module_free tracepoints, init_module/
//     finit_module exit, bpf(BPF_PROG_LOAD), perf_event_open (Phase 7).
//   - cgroup.bpf.c  — cgroup_mkdir/cgroup_rmdir tracepoints: container
//     create/stop, and the cgroup-id → container map (Phase 7).
//
// Bindings are produced by bpf2go at `make gen` time and embedded into the
// slither-agent binary via go:embed. No handwritten Go should live here except
// the bpf2go directive file.
package bpf
