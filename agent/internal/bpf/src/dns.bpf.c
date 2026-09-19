/* dns.bpf.c — DNS query / response telemetry from the UDP socket buffer.
 *
 * DNS was deferred from Phase 1 because the obvious hooks are wrong:
 * uprobes on getaddrinfo miss Go, musl-static and hand-rolled
 * resolvers, and the sendto / sendmsg / sendmmsg / write syscalls each
 * carry the payload differently and cannot tell a DNS socket from any
 * other. Every UDP send on every one of those paths converges on one
 * built sk_buff, so this program reads the datagram there:
 *
 *   - kprobe/ip_send_skb(net, skb), kprobe/ip6_send_skb(skb)
 *       the outbound datagram, still in the sending process's context,
 *       with the UDP header at skb->head + transport_header. Kept when
 *       the destination port is 53.
 *   - kretprobe/__skb_recv_udp
 *       the inbound datagram as the receiving process dequeues it, with
 *       skb->data at the UDP header. Kept when the source port is 53.
 *
 * Up to DNS_MAX bytes of the payload are copied verbatim; parsing
 * (names, types, answers, rcode) happens in userspace where a real DNS
 * parser is a library call and the verifier is not involved. Anything
 * beyond the linear part of the skb is not read; a query never needs
 * it and a response that large is EDNS-padded past what the answers
 * need.
 *
 * With a local stub resolver (systemd-resolved at 127.0.0.53, dnsmasq,
 * unbound) each lookup is seen twice — the application's query to the
 * stub and the stub's query upstream — and both are wanted: the first
 * is the attribution, the second is the wire truth. DNS over TCP, DoT
 * and DoH are not seen; they are not UDP/53.
 */
#include "vmlinux.h"
#include "bpf_helpers.h"

#define COMM_LEN 16
#define DNS_MAX  1024
#define DNS_PORT_BE 0x3500  /* htons(53) on little-endian */
#define ETH_P_IP_BE   0x0008 /* htons(0x0800) */
#define ETH_P_IPV6_BE 0xDD86 /* htons(0x86DD) */
#define UDP_HDR_LEN 8

/* Event kind discriminator. Values align with pipeline.RawDNSKind in Go. */
enum {
    SL_DNS_UNKNOWN  = 0,
    SL_DNS_QUERY    = 1,
    SL_DNS_RESPONSE = 2,
};

struct dns_event {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u16 family;   /* 4 or 6 */
    __u16 sport;    /* host order */
    __u16 dport;    /* host order */
    __u16 _pad0;
    __u32 payload_len;
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[COMM_LEN];
    __u8  payload[DNS_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} events SEC(".maps");

const struct dns_event *unused __attribute__((unused));

static __always_inline __u16 bswap16(__u16 v) {
    return (__u16)((v << 8) | (v >> 8));
}

/* skb_view reads the handful of sk_buff fields the two paths need. */
struct skb_view {
    unsigned char *head;
    unsigned char *data;
    __u32 len;
    __u32 data_len;
    __u16 transport;
    __u16 network;
    __u16 protocol;
};

static __always_inline int read_skb(struct sk_buff *skb, struct skb_view *v) {
    if (BPF_CORE_READ_INTO(&v->head, skb, head) < 0) return -1;
    if (BPF_CORE_READ_INTO(&v->data, skb, data) < 0) return -1;
    if (BPF_CORE_READ_INTO(&v->len, skb, len) < 0) return -1;
    if (BPF_CORE_READ_INTO(&v->data_len, skb, data_len) < 0) return -1;
    if (BPF_CORE_READ_INTO(&v->transport, skb, transport_header) < 0) return -1;
    if (BPF_CORE_READ_INTO(&v->network, skb, network_header) < 0) return -1;
    if (BPF_CORE_READ_INTO(&v->protocol, skb, protocol) < 0) return -1;
    return 0;
}

static __always_inline void fill_addrs(struct dns_event *e, struct skb_view *v, __u16 family) {
    unsigned char *nh = v->head + v->network;
    e->family = family;
    __builtin_memset(e->saddr, 0, sizeof(e->saddr));
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    if (family == 4) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), nh) == 0) {
            __builtin_memcpy(e->saddr, &ip.saddr, 4);
            __builtin_memcpy(e->daddr, &ip.daddr, 4);
        }
    } else {
        struct ipv6hdr ip6;
        if (bpf_probe_read_kernel(&ip6, sizeof(ip6), nh) == 0) {
            __builtin_memcpy(e->saddr, &ip6.saddr, 16);
            __builtin_memcpy(e->daddr, &ip6.daddr, 16);
        }
    }
}

/* emit copies the UDP payload starting at udp (which points at the UDP
 * header) if the port test passes. avail is how many bytes of linear
 * data exist from udp onwards. */
static __always_inline int emit(__u32 kind, __u16 family, struct skb_view *v,
                                unsigned char *udp, __u32 avail) {
    if (avail < UDP_HDR_LEN + 12) return 0; /* not even a DNS header */

    struct udphdr uh;
    if (bpf_probe_read_kernel(&uh, sizeof(uh), udp) < 0) return 0;
    if (kind == SL_DNS_QUERY && uh.dest != DNS_PORT_BE) return 0;
    if (kind == SL_DNS_RESPONSE && uh.source != DNS_PORT_BE) return 0;

    __u32 n = bswap16(uh.len);
    if (n < UDP_HDR_LEN + 12) return 0;
    n -= UDP_HDR_LEN;
    if (n > avail - UDP_HDR_LEN) n = avail - UDP_HDR_LEN;
    if (n > DNS_MAX) n = DNS_MAX;

    struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(struct dns_event), 0);
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->ts_ns = bpf_ktime_get_ns();
    e->kind  = kind;
    e->pid   = (__u32)pid_tgid;
    e->tgid  = (__u32)(pid_tgid >> 32);
    e->uid   = (__u32)uid_gid;
    e->gid   = (__u32)(uid_gid >> 32);
    e->sport = bswap16(uh.source);
    e->dport = bswap16(uh.dest);
    e->_pad0 = 0;
    e->payload_len = n;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    fill_addrs(e, v, family);

    if (bpf_probe_read_kernel(e->payload, n, udp + UDP_HDR_LEN) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Outbound: skb->data is the network header; the UDP header sits at
 * head + transport_header; linear data ends at data + (len - data_len). */
static __always_inline int handle_send(struct sk_buff *skb, __u16 family) {
    struct skb_view v;
    if (!skb || read_skb(skb, &v) < 0) return 0;
    unsigned char *udp = v.head + v.transport;
    unsigned char *end = v.data + (v.len - v.data_len);
    if (udp >= end) return 0;
    __u32 avail = (__u32)(end - udp);
    return emit(SL_DNS_QUERY, family, &v, udp, avail);
}

SEC("kprobe/ip_send_skb")
int handle_ip_send_skb(struct pt_regs *ctx) {
    return handle_send((struct sk_buff *)PT_REGS_PARM2(ctx), 4);
}

SEC("kprobe/ip6_send_skb")
int handle_ip6_send_skb(struct pt_regs *ctx) {
    return handle_send((struct sk_buff *)PT_REGS_PARM1(ctx), 6);
}

/* Inbound: __skb_recv_udp returns the dequeued skb with skb->data at the
 * UDP header (udp_recvmsg copies from data + sizeof(udphdr)). */
SEC("kretprobe/__skb_recv_udp")
int handle_skb_recv_udp(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
    struct skb_view v;
    if (!skb || read_skb(skb, &v) < 0) return 0;
    __u16 family = 0;
    if (v.protocol == ETH_P_IP_BE) family = 4;
    else if (v.protocol == ETH_P_IPV6_BE) family = 6;
    else return 0;
    __u32 avail = v.len - v.data_len;
    return emit(SL_DNS_RESPONSE, family, &v, v.data, avail);
}

LICENSE("GPL");
