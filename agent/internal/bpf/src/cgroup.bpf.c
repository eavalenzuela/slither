/* cgroup.bpf.c — container lifecycle via cgroup directory events.
 *
 * Every Linux container runtime — docker, containerd / CRI, cri-o,
 * podman, LXC, systemd-nspawn — puts each container in its own cgroup
 * and names that cgroup after the container id. Watching the
 * cgroup_mkdir and cgroup_rmdir tracepoints therefore gives one
 * runtime-agnostic source for "a container was created" and "a
 * container's cgroup went away" (its processes are gone: stopped or
 * destroyed), with the id in the path and, on cgroup v2, the cgroup id
 * that process events also carry (bpf_get_current_cgroup_id), which is
 * how the enricher stamps x_container_id onto every process, file, net,
 * auth and kernel event without a single /proc read.
 *
 * "Started" is not a cgroup event: the enricher emits it on the first
 * exec it sees inside a container's cgroup.
 *
 * What this does not see: image pulls and container names / image
 * names. Those live in the runtime's own state, not the kernel; a
 * runtime-API extension (the Phase 6 extension model) is the right
 * place for them.
 *
 * cgroup v1: the tracepoints fire once per controller hierarchy for the
 * same container, and the ids are per-hierarchy. The record carries
 * root (0 = the v2 default hierarchy) so userspace can de-duplicate by
 * container id and only use root-0 ids for process mapping.
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN 16
#define PATH_LEN 256

/* Event kind discriminator. Values align with pipeline.RawCgroupKind in Go. */
enum {
    SL_CGROUP_UNKNOWN = 0,
    SL_CGROUP_MKDIR   = 1,
    SL_CGROUP_RMDIR   = 2,
};

struct cgroup_event {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __s32 root;   /* hierarchy id; 0 is the cgroup v2 default hierarchy */
    __s32 level;
    __u32 _pad0;
    __u64 id;     /* cgroup id (kernfs inode number) in that hierarchy */
    char  path[PATH_LEN];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} events SEC(".maps");

const struct cgroup_event *unused __attribute__((unused));

static __always_inline int emit(struct trace_event_raw_cgroup *ctx, __u32 kind) {
    struct cgroup_event *e = bpf_ringbuf_reserve(&events, sizeof(struct cgroup_event), 0);
    if (!e) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns = bpf_ktime_get_ns();
    e->kind  = kind;
    e->pid   = (__u32)pid_tgid;
    e->tgid  = (__u32)(pid_tgid >> 32);
    e->uid   = (__u32)uid_gid;
    e->gid   = (__u32)(uid_gid >> 32);
    e->root  = ctx->root;
    e->level = ctx->level;
    e->_pad0 = 0;
    e->id    = ctx->id;
    __builtin_memset(e->path, 0, sizeof(e->path));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 off = ctx->__data_loc_path & 0xffff;
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), (char *)ctx + off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/cgroup/cgroup_mkdir")
int handle_cgroup_mkdir(struct trace_event_raw_cgroup *ctx) { return emit(ctx, SL_CGROUP_MKDIR); }

SEC("tracepoint/cgroup/cgroup_rmdir")
int handle_cgroup_rmdir(struct trace_event_raw_cgroup *ctx) { return emit(ctx, SL_CGROUP_RMDIR); }

LICENSE("GPL");
