/* file.bpf.c — filesystem syscall telemetry.
 *
 * Phase 1 (IMPLEMENTATION.md §3.2) hooks five syscall-enter tracepoints:
 *   - sys_enter_openat        (O_CREAT → Create; O_WRONLY/O_RDWR/O_TRUNC → Write)
 *   - sys_enter_unlinkat
 *   - sys_enter_renameat2
 *   - sys_enter_fchmodat
 *   - sys_enter_fchownat
 *
 * Read-only opens are dropped in-kernel to keep ringbuf pressure manageable;
 * the detection surface we care about for Phase 1 is writes, deletes, and
 * attribute changes. The in-kernel LPM_TRIE path prefilter sketched in §3.2
 * is deferred — the userspace enricher applies include/exclude globs instead.
 * Paths are captured at up to PATH_BYTES-1 chars via bpf_probe_read_user_str;
 * relative paths (dfd != AT_FDCWD or not absolute) are resolved userspace-side
 * against /proc/<pid>/cwd.
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN   16
#define PATH_BYTES 256

/* asm-generic/fcntl.h values — identical on amd64 + arm64 (our only targets
 * per ADR-0001). Duplicated here because vmlinux.h doesn't surface these. */
#define O_WRONLY 00000001
#define O_RDWR   00000002
#define O_CREAT  00000100
#define O_TRUNC  00001000

/* Event kind discriminator. Values match pipeline.RawFileKind in Go. */
enum {
    SL_FILE_UNKNOWN     = 0,
    SL_FILE_OPEN_CREATE = 1,
    SL_FILE_OPEN_WRITE  = 2,
    SL_FILE_UNLINK      = 3,
    SL_FILE_RENAME      = 4,
    SL_FILE_CHMOD       = 5,
    SL_FILE_CHOWN       = 6,
};

/* Wire record. Layout read little-endian by the Go decoder (amd64/arm64 only
 * per ADR-0001). path/newpath are fixed-size for verifier friendliness;
 * truncation at PATH_BYTES-1 is accepted for Phase 1. */
struct file_event {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 flags;  /* openat flags, or renameat2 flags */
    __u32 mode;   /* openat/chmod mode, chown uid — kind-dependent */
    __u32 extra;  /* chown gid when kind == SL_FILE_CHOWN, else 0 */
    __u32 _pad;
    char  comm[COMM_LEN];
    char  path[PATH_BYTES];
    char  newpath[PATH_BYTES];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); /* 4 MB ringbuf per IMPLEMENTATION.md §3.2 */
} events SEC(".maps");

/* Force BTF emission for struct file_event so bpf2go's -type flag finds it. */
const struct file_event *unused __attribute__((unused));

static __always_inline struct file_event *reserve(void) {
    return bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
}

static __always_inline void fill_common(struct file_event *e) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = (__u32)pid_tgid;
    e->tgid  = (__u32)(pid_tgid >> 32);
    e->uid   = (__u32)uid_gid;
    e->gid   = (__u32)(uid_gid >> 32);
    e->flags = 0;
    e->mode  = 0;
    e->extra = 0;
    e->_pad  = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    /* Zero string fields: probe_read_user_str NUL-terminates but doesn't
     * scrub trailing bytes, and the ringbuf memory is uninitialised. */
    __builtin_memset(e->path, 0, sizeof(e->path));
    __builtin_memset(e->newpath, 0, sizeof(e->newpath));
}

/* ---------------------------------------------------------------------------
 * openat
 * args: dfd, filename, flags, mode. We filter to write-intent opens; the
 * read-only stream dominates the ringbuf otherwise (tens of thousands/sec
 * on a busy host).
 * --------------------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    int flags = (int)ctx->args[2];
    if (!(flags & (O_CREAT | O_WRONLY | O_RDWR | O_TRUNC))) return 0;

    struct file_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = (flags & O_CREAT) ? SL_FILE_OPEN_CREATE : SL_FILE_OPEN_WRITE;
    e->flags = (__u32)flags;
    e->mode  = (__u32)ctx->args[3];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * unlinkat
 * args: dfd, pathname, flags.
 * --------------------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = SL_FILE_UNLINK;
    e->flags = (__u32)ctx->args[2];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * renameat2
 * args: olddfd, oldname, newdfd, newname, flags.
 * --------------------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = SL_FILE_RENAME;
    e->flags = (__u32)ctx->args[4];
    bpf_probe_read_user_str(&e->path,    sizeof(e->path),    (const void *)ctx->args[1]);
    bpf_probe_read_user_str(&e->newpath, sizeof(e->newpath), (const void *)ctx->args[3]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * fchmodat
 * args: dfd, filename, mode.
 * --------------------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind = SL_FILE_CHMOD;
    e->mode = (__u32)ctx->args[2];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * fchownat
 * args: dfd, filename, user, group, flag.
 * --------------------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_fchownat")
int handle_fchownat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = SL_FILE_CHOWN;
    e->mode  = (__u32)ctx->args[2]; /* new uid */
    e->extra = (__u32)ctx->args[3]; /* new gid */
    e->flags = (__u32)ctx->args[4];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

LICENSE("GPL");
