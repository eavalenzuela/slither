/* process.bpf.c — process lifecycle telemetry.
 *
 * Phase 1 (IMPLEMENTATION.md §3.2) hooks three scheduler tracepoints:
 *   - sched_process_exec
 *   - sched_process_exit
 *   - sched_process_fork
 *
 * Each emits a fixed-size record on a shared BPF_MAP_TYPE_RINGBUF. Strings
 * (comm) are fixed-length in the record; richer context (exe path, cmdline,
 * parent chain) is resolved userspace-side from /proc in the enricher,
 * keeping the BPF program small and the verifier happy.
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN    16
#define EXE_LEN     128
#define CMDLINE_LEN 256

/* Event kind discriminator. Values align with Go's RawProcessKind in
 * agent/internal/pipeline/types.go. Named with an SL_ prefix to avoid a
 * name collision with the kernel's proc_cn_mcast_op enum values in
 * vmlinux.h (SL_PROC_EXEC etc. are defined there for netlink use). */
enum {
    SL_PROC_UNKNOWN = 0,
    SL_PROC_EXEC    = 1,
    SL_PROC_EXIT    = 2,
    SL_PROC_FORK    = 3,
};

/* Wire record. Layout is C-explicit; the Go decoder uses encoding/binary
 * LittleEndian to read it (eBPF is host-endian; we only target little-endian
 * architectures — amd64 + arm64 — per ADR-0001 / release targets). */
struct process_event {
    __u64 ts_ns;       /* bpf_ktime_get_ns at emission */
    __u32 kind;        /* SL_PROC_* */
    __u32 pid;         /* thread pid (kernel pid) */
    __u32 tgid;        /* thread-group leader (userspace pid) */
    __u32 ppid;        /* parent pid — populated on fork; 0 elsewhere */
    __u32 uid;
    __u32 gid;
    __s32 exit_code;   /* populated on exit; 0 elsewhere */
    __u32 cmdline_len; /* valid bytes in cmdline[]; args are null-separated
                        * in place. Userspace converts nulls to spaces. */
    char  comm[COMM_LEN];
    char  exe[EXE_LEN]; /* exec path — populated from the sched_process_exec
                         * tracepoint's __data_loc_filename on SL_PROC_EXEC,
                         * zero otherwise. */
    char  cmdline[CMDLINE_LEN]; /* argv blob — populated on SL_PROC_EXEC from
                                 * current->mm->arg_{start,end}, zero
                                 * otherwise. Lets userspace skip the
                                 * /proc/<pid>/cmdline read on exec, which
                                 * was the last /proc syscall on the hot
                                 * path after the exe BPF capture. */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); /* 4 MB ringbuf per IMPLEMENTATION.md §3.2 */
} events SEC(".maps");

/* Force the compiler to emit BTF for struct process_event so bpf2go's -type
 * flag can find it. The symbol is otherwise unreferenced. */
const struct process_event *unused __attribute__((unused));

static __always_inline struct process_event *reserve(void) {
    return bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
}

static __always_inline void fill_common(struct process_event *e) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = (__u32)pid_tgid;
    e->tgid  = (__u32)(pid_tgid >> 32);
    e->uid   = (__u32)uid_gid;
    e->gid   = (__u32)(uid_gid >> 32);
    e->ppid  = 0;
    e->exit_code = 0;
    e->cmdline_len = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    /* exe/cmdline are zero-initialised here; handle_exec populates them
     * on SL_PROC_EXEC. fork/exit leave them empty. */
    __builtin_memset(e->exe, 0, sizeof(e->exe));
    __builtin_memset(e->cmdline, 0, sizeof(e->cmdline));
}

/* ---------------------------------------------------------------------------
 * exec
 * struct trace_event_raw_sched_process_exec is generated in vmlinux.h.
 * The filename (exec path) is carried in the variable-length __data section
 * at offset encoded in __data_loc_filename — lower 16 bits = byte offset from
 * ctx start, upper 16 bits = length. Reading it here saves userspace one
 * /proc/<pid>/exe readlink per exec, which dominates enricher throughput
 * under fork storms (task #15 on RHEL 10).
 * --------------------------------------------------------------------------*/
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct process_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind = SL_PROC_EXEC;

    /* exe: copy from the tracepoint's __data_loc_filename arg. */
    __u32 loc = ctx->__data_loc_filename;
    __u16 off = (__u16)(loc & 0xFFFF);
    const char *filename = (const char *)ctx + off;
    bpf_probe_read_kernel_str(&e->exe, sizeof(e->exe), filename);

    /* cmdline: argv is contiguous null-separated bytes between
     * task->mm->arg_start and arg_end. Read up to sizeof(cmdline) and
     * record the actual length so userspace can convert nulls to spaces
     * without scanning. If mm or arg_{start,end} can't be read we leave
     * cmdline_len=0 and userspace falls back to /proc. */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct mm_struct *mm;
        bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
        if (mm) {
            unsigned long arg_start = 0, arg_end = 0;
            bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &mm->arg_start);
            bpf_probe_read_kernel(&arg_end,   sizeof(arg_end),   &mm->arg_end);
            unsigned long len = arg_end - arg_start;
            /* Bound the length so the verifier accepts the probe-read size
             * as a scalar less than sizeof(cmdline). */
            if (arg_end > arg_start && len <= sizeof(e->cmdline)) {
                bpf_probe_read_user(&e->cmdline, len, (const void *)arg_start);
                e->cmdline_len = (__u32)len;
            } else if (arg_end > arg_start) {
                bpf_probe_read_user(&e->cmdline, sizeof(e->cmdline), (const void *)arg_start);
                e->cmdline_len = (__u32)sizeof(e->cmdline);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * exit
 * trace_event_raw_sched_process_template carries pid, comm, prio.
 * The exit code isn't in the tracepoint context — leaving it 0 for Phase 1;
 * userspace can backfill from /proc or the followup enricher.
 * --------------------------------------------------------------------------*/
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct process_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind = SL_PROC_EXIT;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * fork
 * trace_event_raw_sched_process_fork carries parent_pid, child_pid (child_comm
 * is stored at __data_loc_child_comm and decoded userspace-side from /proc;
 * not worth the BPF complexity here). We surface parent_pid → ppid and
 * the child's pid as pid. The comm field holds the parent's comm
 * (current task at fork time); the enricher backfills child comm from
 * /proc/<child_pid>/comm when processing the event.
 * --------------------------------------------------------------------------*/
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct process_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind = SL_PROC_FORK;
    e->ppid = (__u32)ctx->parent_pid;
    e->pid  = (__u32)ctx->child_pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

LICENSE("GPL");
