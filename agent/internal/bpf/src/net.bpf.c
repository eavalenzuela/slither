/* net.bpf.c — network connection telemetry.
 *
 * Phase 1 (IMPLEMENTATION.md §3.2) hooks three kprobes:
 *   - tcp_connect(struct sock *sk)        — outbound TCP connect
 *   - inet_csk_accept return              — inbound TCP accept (kretprobe;
 *                                           the returned sock is the new
 *                                           server-side view of the client)
 *   - udp_sendmsg(struct sock *sk, ...)   — outbound UDP datagram
 *
 * DNS is deferred to Phase 3 per §3.2. We emit raw endpoint addresses only;
 * orientation (inbound vs outbound) and v4/v6 stringification happen in the
 * userspace enricher, which is cheaper than doing it in BPF and keeps the
 * verifier happy with simpler programs.
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10

/* Event kind discriminator. Values align with pipeline.RawNetKind in Go. */
enum {
    SL_NET_UNKNOWN     = 0,
    SL_NET_TCP_CONNECT = 1,
    SL_NET_TCP_ACCEPT  = 2,
    SL_NET_UDP_SEND    = 3,
};

/* Wire record. saddr/daddr are 16 bytes so IPv6 fits; IPv4 lives in the
 * first 4 bytes. family tells the enricher which layout to read. dport is
 * captured in host byte order — the kernel stores it big-endian as skc_dport
 * but we convert on emission to keep the Go side trivial. */
struct net_event {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u16 family;
    __u8  proto;      /* IPPROTO_TCP = 6, IPPROTO_UDP = 17 */
    __u8  _pad0;
    __u16 sport;
    __u16 dport;
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

const struct net_event *unused __attribute__((unused));

static __always_inline struct net_event *reserve(void) {
    return bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
}

static __always_inline void fill_common(struct net_event *e) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = (__u32)pid_tgid;
    e->tgid  = (__u32)(pid_tgid >> 32);
    e->uid   = (__u32)uid_gid;
    e->gid   = (__u32)(uid_gid >> 32);
    e->family = 0;
    e->proto  = 0;
    e->_pad0  = 0;
    e->sport  = 0;
    e->dport  = 0;
    __builtin_memset(e->saddr, 0, sizeof(e->saddr));
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* bswap16 — dport is stored big-endian as skc_dport; the port-number fields
 * on the wire record are host-endian so the Go decoder doesn't have to care
 * about kernel byte order. */
static __always_inline __u16 bswap16(__u16 v) {
    return (__u16)((v << 8) | (v >> 8));
}

/* populate_from_sk reads family, protocol, addresses, and ports from a
 * struct sock via CO-RE-relocated kernel reads. Returns 0 on success,
 * nonzero if the family isn't one we handle (so the caller can drop). */
static __always_inline int populate_from_sk(struct net_event *e, struct sock *sk) {
    __u16 family = 0;
    BPF_CORE_READ_INTO2(&family, sk, __sk_common, skc_family);
    if (family != AF_INET && family != AF_INET6) return -1;
    e->family = family;

    __u16 dport_be = 0, sport_host = 0;
    BPF_CORE_READ_INTO2(&dport_be,  sk, __sk_common, skc_dport);
    BPF_CORE_READ_INTO2(&sport_host, sk, __sk_common, skc_num);
    e->dport = bswap16(dport_be);
    e->sport = sport_host;

    if (family == AF_INET) {
        __be32 daddr = 0, saddr = 0;
        BPF_CORE_READ_INTO2(&daddr, sk, __sk_common, skc_daddr);
        BPF_CORE_READ_INTO2(&saddr, sk, __sk_common, skc_rcv_saddr);
        __builtin_memcpy(e->daddr, &daddr, 4);
        __builtin_memcpy(e->saddr, &saddr, 4);
    } else {
        BPF_CORE_READ_INTO2(&e->daddr, sk, __sk_common, skc_v6_daddr);
        BPF_CORE_READ_INTO2(&e->saddr, sk, __sk_common, skc_v6_rcv_saddr);
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * tcp_connect — outbound TCP. Fires before the SYN goes out; the sock already
 * has source/dest set.
 * --------------------------------------------------------------------------*/
SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct net_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = SL_NET_TCP_CONNECT;
    e->proto = IPPROTO_TCP;
    if (populate_from_sk(e, sk) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * inet_csk_accept — inbound TCP. The kretprobe runs after the function
 * returns; the return value is the newly-accepted sock (or NULL on failure).
 * The returned sock's skc_daddr/skc_dport describe the *client* peer; the
 * enricher interprets kind == accept to swap endpoint orientation.
 * --------------------------------------------------------------------------*/
SEC("kretprobe/inet_csk_accept")
int handle_inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;

    struct net_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = SL_NET_TCP_ACCEPT;
    e->proto = IPPROTO_TCP;
    if (populate_from_sk(e, sk) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------------
 * udp_sendmsg — outbound UDP. Not every UDP send has dest set on the sock
 * (connectionless sends pass dest via msghdr); populate_from_sk will return
 * zeros for dport/daddr in that case and the enricher can still log the local
 * endpoint + pid for correlation.
 * --------------------------------------------------------------------------*/
SEC("kprobe/udp_sendmsg")
int handle_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct net_event *e = reserve();
    if (!e) return 0;
    fill_common(e);
    e->kind  = SL_NET_UDP_SEND;
    e->proto = IPPROTO_UDP;
    if (populate_from_sk(e, sk) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

LICENSE("GPL");
