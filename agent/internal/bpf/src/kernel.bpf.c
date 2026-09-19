/* kernel.bpf.c — kernel-module and probe-attach telemetry.
 *
 * PROJECT.md §3.1 asks for "module load, kprobe/uprobe attach
 * (defense-in-depth for rootkit detection)". Five hooks cover it:
 *
 *   - tracepoint/module/module_load             — a module finished loading.
 *       Authoritative, fires for init_module and finit_module alike,
 *       carries the module name + the kernel taint flags it added.
 *   - tracepoint/module/module_free             — a module was unloaded.
 *   - tracepoint/syscalls/sys_exit_init_module,
 *     tracepoint/syscalls/sys_exit_finit_module — a load *attempt* that
 *       failed (ret < 0). module_load never fires for these, and the
 *       reason is the interesting part: EKEYREJECTED is signature
 *       enforcement doing its job, EPERM is lockdown. No name is
 *       available here; the enricher's process cache supplies the
 *       loader's command line, which for insmod carries the path.
 *   - tracepoint/syscalls/sys_enter_bpf         — BPF_PROG_LOAD only:
 *       program type + name. BPF rootkits (ebpfkit, TripleCross, ...)
 *       are the modern replacement for an LKM, and they all start here.
 *   - tracepoint/syscalls/sys_enter_perf_event_open — a dynamic-PMU
 *       perf event, i.e. anything with attr.type >= PERF_TYPE_MAX.
 *       kprobe and uprobe attaches are dynamic PMUs whose type ids are
 *       only known at runtime (/sys/bus/event_source/devices/{kprobe,uprobe}/type),
 *       so the program emits every dynamic-PMU open and userspace keeps
 *       the two it cares about. config1 is the function name (kprobe)
 *       or the file path (uprobe); config bit 0 is the retprobe flag.
 *
 * Not covered: probes created through tracefs (kprobe_events /
 * uprobe_events writes) — those are ordinary file writes and a
 * file_event rule on the tracefs path is the right tool; and
 * bpf(BPF_LINK_CREATE) / BPF_RAW_TRACEPOINT_OPEN attaches, which always
 * follow a BPF_PROG_LOAD this program already reported.
 *
 * The agent itself loads BPF programs and attaches probes on start-up
 * and on every collector restart. The enricher drops events whose tgid
 * is its own pid; nothing here special-cases it.
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN   16
#define NAME_LEN   64
#define TARGET_LEN 128

/* enum bpf_cmd / enum perf_type_id values; stable uapi. */
#define BPF_PROG_LOAD_CMD 5
#define PERF_TYPE_MAX_ID  6

/* Event kind discriminator. Values align with pipeline.RawKernelKind in Go. */
enum {
    SL_KERNEL_UNKNOWN              = 0,
    SL_KERNEL_MODULE_LOAD          = 1,
    SL_KERNEL_MODULE_UNLOAD        = 2,
    SL_KERNEL_MODULE_LOAD_REJECTED = 3,
    SL_KERNEL_BPF_PROG_LOAD        = 4,
    SL_KERNEL_PROBE_ATTACH         = 5,
};

/* Wire record. Field meaning is kind-dependent:
 *   result    — MODULE_LOAD_REJECTED: -errno from the syscall; else 0.
 *   taints    — MODULE_LOAD: the taint mask this module added.
 *   attr_type — BPF_PROG_LOAD: bpf_attr.prog_type;
 *               PROBE_ATTACH:  perf_event_attr.type (dynamic PMU id).
 *   config    — PROBE_ATTACH: perf_event_attr.config (bit 0 = retprobe).
 *   config2   — PROBE_ATTACH: kprobe_addr / probe_offset.
 *   name      — module name, or bpf_attr.prog_name.
 *   target    — PROBE_ATTACH: kprobe_func or uprobe_path (from config1).
 */
struct kernel_event {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __s32 result;
    __u32 taints;
    __u32 attr_type;
    __u64 config;
    __u64 config2;
    char  name[NAME_LEN];
    char  target[TARGET_LEN];
    char  comm[COMM_LEN];
};

/* Kernel events are rare; a boot-time modprobe storm is the worst case. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} events SEC(".maps");

const struct kernel_event *unused __attribute__((unused));

static __always_inline struct kernel_event *reserve(__u32 kind) {
    struct kernel_event *e = bpf_ringbuf_reserve(&events, sizeof(struct kernel_event), 0);
    if (!e) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns     = bpf_ktime_get_ns();
    e->kind      = kind;
    e->pid       = (__u32)pid_tgid;
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->uid       = (__u32)uid_gid;
    e->gid       = (__u32)(uid_gid >> 32);
    e->result    = 0;
    e->taints    = 0;
    e->attr_type = 0;
    e->config    = 0;
    e->config2   = 0;
    __builtin_memset(e->name, 0, sizeof(e->name));
    __builtin_memset(e->target, 0, sizeof(e->target));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

/* __data_loc fields pack (len << 16 | offset); the string lives at
 * ctx + offset. */
static __always_inline void read_data_loc(char *dst, __u32 len, void *ctx, __u32 data_loc) {
    __u32 off = data_loc & 0xffff;
    bpf_probe_read_kernel_str(dst, len, (char *)ctx + off);
}

SEC("tracepoint/module/module_load")
int handle_module_load(struct trace_event_raw_module_load *ctx) {
    struct kernel_event *e = reserve(SL_KERNEL_MODULE_LOAD);
    if (!e) return 0;
    e->taints = ctx->taints;
    read_data_loc(e->name, sizeof(e->name), ctx, ctx->__data_loc_name);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/module/module_free")
int handle_module_free(struct trace_event_raw_module_free *ctx) {
    struct kernel_event *e = reserve(SL_KERNEL_MODULE_UNLOAD);
    if (!e) return 0;
    read_data_loc(e->name, sizeof(e->name), ctx, ctx->__data_loc_name);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int handle_module_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    if (ret >= 0) return 0; /* success is reported by module_load */
    struct kernel_event *e = reserve(SL_KERNEL_MODULE_LOAD_REJECTED);
    if (!e) return 0;
    e->result = (__s32)ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_init_module")
int handle_init_module_exit(struct trace_event_raw_sys_exit *ctx) { return handle_module_exit(ctx); }

SEC("tracepoint/syscalls/sys_exit_finit_module")
int handle_finit_module_exit(struct trace_event_raw_sys_exit *ctx) { return handle_module_exit(ctx); }

/* bpf(cmd, attr, size). Only BPF_PROG_LOAD is reported. prog_type sits at
 * offset 0 of the union; prog_name is further in and absent from callers
 * built against a pre-4.15 uapi, so a failed read leaves it empty rather
 * than dropping the event. */
SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx) {
    int cmd = (int)ctx->args[0];
    if (cmd != BPF_PROG_LOAD_CMD) return 0;
    const char *uattr = (const char *)ctx->args[1];
    __u32 size = (__u32)ctx->args[2];

    struct kernel_event *e = reserve(SL_KERNEL_BPF_PROG_LOAD);
    if (!e) return 0;

    __u32 prog_type = 0;
    if (size >= sizeof(prog_type)) {
        bpf_probe_read_user(&prog_type, sizeof(prog_type), uattr);
    }
    e->attr_type = prog_type;

    __u32 name_off = __builtin_offsetof(union bpf_attr, prog_name);
    if (size >= name_off + 16) {
        bpf_probe_read_user_str(e->name, 16, uattr + name_off);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* perf_event_open(attr, pid, cpu, group_fd, flags). Dynamic PMUs only. */
SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int handle_perf_event_open(struct trace_event_raw_sys_enter *ctx) {
    const char *uattr = (const char *)ctx->args[0];
    __u32 type = 0;
    if (bpf_probe_read_user(&type, sizeof(type), uattr) < 0) return 0;
    if (type < PERF_TYPE_MAX_ID) return 0;

    struct kernel_event *e = reserve(SL_KERNEL_PROBE_ATTACH);
    if (!e) return 0;
    e->attr_type = type;

    __u64 config = 0, config1 = 0, config2 = 0;
    bpf_probe_read_user(&config,  sizeof(config),  uattr + __builtin_offsetof(struct perf_event_attr, config));
    bpf_probe_read_user(&config1, sizeof(config1), uattr + __builtin_offsetof(struct perf_event_attr, config1));
    bpf_probe_read_user(&config2, sizeof(config2), uattr + __builtin_offsetof(struct perf_event_attr, config2));
    e->config  = config;
    e->config2 = config2;
    if (config1) {
        bpf_probe_read_user_str(e->target, sizeof(e->target), (const void *)config1);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

LICENSE("GPL");
