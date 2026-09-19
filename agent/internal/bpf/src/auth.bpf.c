/* auth.bpf.c — authentication telemetry via libpam uprobes.
 *
 * Every interactive authentication path on a stock Linux host — sshd,
 * sudo, su, login, getty, display managers — goes through libpam's
 * public API, and libpam is one shared object with a stable exported
 * symbol set (LIBPAM_1.0). Hooking that API gives one collector that
 * covers all of them, with no per-daemon log parsing and no dependence
 * on which of auth.log / secure / journald a distro happens to use.
 *
 * Hooks (all on the public API, never on libpam internals):
 *   - pam_start / pam_start_confdir   entry  — service + user → per-tgid
 *                                             context map
 *   - pam_set_item                    entry  — PAM_USER / PAM_TTY / PAM_RHOST
 *                                             updates to that context
 *   - pam_authenticate                return — SL_AUTH_ATTEMPT with the
 *                                             PAM result (0 = success)
 *   - pam_open_session                return — SL_AUTH_SESSION_OPEN
 *   - pam_close_session               return — SL_AUTH_SESSION_CLOSE
 *   - pam_end                         entry  — drop the context
 *
 * The context is keyed by tgid rather than by pam_handle_t* because a
 * uretprobe cannot see the call's arguments. That is the right key in
 * practice: sshd forks a monitor per connection, sudo / su / login are
 * one process per attempt, and no mainstream PAM client runs concurrent
 * transactions in one process.
 *
 * What this does not see, and why:
 *   - sshd public-key failures. sshd only enters libpam once a key or
 *     password is accepted (pam_acct_mgmt + pam_open_session) or when
 *     it does password / keyboard-interactive auth (pam_authenticate).
 *     A rejected key never reaches PAM. That is an sshd design choice,
 *     not a probe gap; the net collector still sees the TCP accept.
 *   - A libpam inside a container image. A uprobe attaches to one
 *     inode, so the host's libpam is covered and a container's is not.
 *   - Statically linked or non-PAM authenticators (rare on Linux).
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN    16
#define SERVICE_LEN 32
#define USER_LEN    64
#define RHOST_LEN   64
#define TTY_LEN     32

/* PAM item types (security/_pam_types.h). */
#define PAM_USER  2
#define PAM_TTY   3
#define PAM_RHOST 4

/* Event kind discriminator. Values align with pipeline.RawAuthKind in Go. */
enum {
    SL_AUTH_UNKNOWN       = 0,
    SL_AUTH_ATTEMPT       = 1,
    SL_AUTH_SESSION_OPEN  = 2,
    SL_AUTH_SESSION_CLOSE = 3,
};

/* Per-transaction context accumulated between pam_start and pam_end. */
struct auth_ctx {
    char service[SERVICE_LEN];
    char user[USER_LEN];
    char rhost[RHOST_LEN];
    char tty[TTY_LEN];
};

/* Wire record. result is the raw PAM return code (PAM_SUCCESS == 0);
 * the enricher maps it to OCSF status and keeps the code for the rule
 * engine, so "user unknown" (10) and "max tries" (11) stay separable
 * from a plain bad password (7). */
struct auth_event {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __s32 result;
    __u32 _pad0;
    char  service[SERVICE_LEN];
    char  user[USER_LEN];
    char  rhost[RHOST_LEN];
    char  tty[TTY_LEN];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct auth_ctx);
} pam_ctx SEC(".maps");

/* Auth events are rare (tens per minute on a busy bastion, not
 * thousands per second), so the ring is a quarter of the net one. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} events SEC(".maps");

const struct auth_event *unused __attribute__((unused));

static __always_inline __u32 current_tgid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

/* ctx_for returns the context for the current tgid, creating an empty
 * one if none exists. Creation on the pam_set_item path matters when
 * the agent attached mid-transaction: the later result event still
 * carries whatever items were set after attach. */
static __always_inline struct auth_ctx *ctx_for(__u32 tgid) {
    struct auth_ctx *c = bpf_map_lookup_elem(&pam_ctx, &tgid);
    if (c) return c;
    struct auth_ctx zero = {};
    bpf_map_update_elem(&pam_ctx, &tgid, &zero, BPF_ANY);
    return bpf_map_lookup_elem(&pam_ctx, &tgid);
}

static __always_inline void read_str(char *dst, __u32 len, const void *src) {
    if (!src) {
        dst[0] = 0;
        return;
    }
    if (bpf_probe_read_user_str(dst, len, src) < 0) dst[0] = 0;
}

/* handle_start is shared by pam_start and pam_start_confdir. On libpam
 * >= 1.4 pam_start tail-jumps into pam_start_confdir so both probes
 * fire for one call; they write identical values, so the double update
 * is harmless. On older libpam only pam_start exists and the
 * pam_start_confdir attach fails cleanly in the loader. */
static __always_inline int handle_start(struct pt_regs *ctx) {
    const char *service = (const char *)PT_REGS_PARM1(ctx);
    const char *user    = (const char *)PT_REGS_PARM2(ctx);
    __u32 tgid = current_tgid();

    struct auth_ctx fresh = {};
    read_str(fresh.service, sizeof(fresh.service), service);
    read_str(fresh.user, sizeof(fresh.user), user);
    bpf_map_update_elem(&pam_ctx, &tgid, &fresh, BPF_ANY);
    return 0;
}

SEC("uprobe/pam_start")
int handle_pam_start(struct pt_regs *ctx) { return handle_start(ctx); }

SEC("uprobe/pam_start_confdir")
int handle_pam_start_confdir(struct pt_regs *ctx) { return handle_start(ctx); }

/* pam_set_item(pamh, item_type, item). Only the three string items the
 * event carries are captured; everything else (conv, authtok, ...) is
 * ignored, which is also what keeps PAM_AUTHTOK — the password — out of
 * the event stream by construction. */
SEC("uprobe/pam_set_item")
int handle_pam_set_item(struct pt_regs *ctx) {
    int item_type   = (int)PT_REGS_PARM2(ctx);
    const void *item = (const void *)PT_REGS_PARM3(ctx);

    if (item_type != PAM_USER && item_type != PAM_TTY && item_type != PAM_RHOST) return 0;

    struct auth_ctx *c = ctx_for(current_tgid());
    if (!c) return 0;

    switch (item_type) {
    case PAM_USER:  read_str(c->user,  sizeof(c->user),  item); break;
    case PAM_TTY:   read_str(c->tty,   sizeof(c->tty),   item); break;
    case PAM_RHOST: read_str(c->rhost, sizeof(c->rhost), item); break;
    }
    return 0;
}

static __always_inline int emit(struct pt_regs *ctx, __u32 kind) {
    struct auth_event *e = bpf_ringbuf_reserve(&events, sizeof(struct auth_event), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns  = bpf_ktime_get_ns();
    e->kind   = kind;
    e->pid    = (__u32)pid_tgid;
    e->tgid   = (__u32)(pid_tgid >> 32);
    e->uid    = (__u32)uid_gid;
    e->gid    = (__u32)(uid_gid >> 32);
    e->result = (__s32)PT_REGS_RC(ctx);
    e->_pad0  = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct auth_ctx *c = bpf_map_lookup_elem(&pam_ctx, &e->tgid);
    if (c) {
        __builtin_memcpy(e->service, c->service, sizeof(e->service));
        __builtin_memcpy(e->user,    c->user,    sizeof(e->user));
        __builtin_memcpy(e->rhost,   c->rhost,   sizeof(e->rhost));
        __builtin_memcpy(e->tty,     c->tty,     sizeof(e->tty));
    } else {
        __builtin_memset(e->service, 0, sizeof(e->service));
        __builtin_memset(e->user,    0, sizeof(e->user));
        __builtin_memset(e->rhost,   0, sizeof(e->rhost));
        __builtin_memset(e->tty,     0, sizeof(e->tty));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe/pam_authenticate")
int handle_pam_authenticate_ret(struct pt_regs *ctx) { return emit(ctx, SL_AUTH_ATTEMPT); }

SEC("uretprobe/pam_open_session")
int handle_pam_open_session_ret(struct pt_regs *ctx) { return emit(ctx, SL_AUTH_SESSION_OPEN); }

SEC("uretprobe/pam_close_session")
int handle_pam_close_session_ret(struct pt_regs *ctx) { return emit(ctx, SL_AUTH_SESSION_CLOSE); }

SEC("uprobe/pam_end")
int handle_pam_end(struct pt_regs *ctx) {
    __u32 tgid = current_tgid();
    bpf_map_delete_elem(&pam_ctx, &tgid);
    return 0;
}

LICENSE("GPL");
