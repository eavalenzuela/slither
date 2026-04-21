/* bpf_helpers.h — vendored subset of libbpf's bpf_helpers.h.
 *
 * Upstream: https://github.com/libbpf/libbpf (LGPL-2.1 / BSD-2-Clause).
 * Vendored here so the repo compiles without requiring libbpf-dev on every
 * builder. Only macros / helpers the Phase 1 programs use are declared;
 * expand deliberately.
 */
#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include "vmlinux.h"

/* -----------------------------------------------------------------------
 * Section + attribute macros.
 * -------------------------------------------------------------------- */
#define SEC(name) __attribute__((section(name), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* -----------------------------------------------------------------------
 * libbpf map declaration helpers.
 *
 * The idiom
 *
 *   struct {
 *       __uint(type, BPF_MAP_TYPE_RINGBUF);
 *       __uint(max_entries, 1 << 22);
 *   } events SEC(".maps");
 *
 * expands into an anonymous struct whose member *types* encode the
 * numeric values libbpf reads when loading the map (the member itself is
 * a pointer-to-array whose size is the encoded value). This is a well-
 * known libbpf trick; we reproduce it verbatim.
 * -------------------------------------------------------------------- */
#define __uint(name, val)  int(*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name

/* -----------------------------------------------------------------------
 * Map-type constants. Pulled in from vmlinux.h on most kernels; define
 * defensively in case a particular vmlinux dump elides the enum.
 * -------------------------------------------------------------------- */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_LPM_TRIE
#define BPF_MAP_TYPE_LPM_TRIE 11
#endif

/* -----------------------------------------------------------------------
 * Helper-function prototypes. IDs match include/uapi/linux/bpf.h
 * enum bpf_func_id. Only helpers the Phase 1 programs use are declared.
 * -------------------------------------------------------------------- */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags)      = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags)                       = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags)                      = (void *)133;
static __u64 (*bpf_get_current_pid_tgid)(void)                                   = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void)                                    = (void *)15;
static long  (*bpf_get_current_comm)(void *buf, __u32 size)                      = (void *)16;
static __u64 (*bpf_ktime_get_ns)(void)                                           = (void *)5;
static long  (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *src)  = (void *)114;
static long  (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *src)= (void *)115;

/* Licence — required by the verifier for GPL-only helpers like bpf_ktime_get_ns. */
#define LICENSE(s) char LICENSE[] SEC("license") = s

#endif /* __BPF_HELPERS_H__ */
