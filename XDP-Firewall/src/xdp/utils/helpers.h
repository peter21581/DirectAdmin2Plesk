#pragma once

#include <common/all.h>

#include <linux/bpf.h>

#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#ifdef __LIBXDP_STATIC__
#include <bpf_helpers.h>
#else
#include <bpf/bpf_helpers.h>
#endif

#include <xdp/utils/maps.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

// Builds a dotted-quad IPv4 address into the same in-memory representation
// as an iphdr's saddr/daddr (raw network byte order), so it can be compared
// directly with == or passed to is_ip_in_range(). Used by the bogon and
// amplification-protection exemption lists.
#define IPV4(a, b, c, d) ((u32)(a) | ((u32)(b) << 8) | ((u32)(c) << 16) | ((u32)(d) << 24))

// Same idea for IPv6, built from its 16 individual bytes (write it out the
// way the address's canonical form reads left-to-right), packed into the
// same u32[4] representation already used throughout this codebase for v6
// addresses (filter_ip_t.src_ip6/dst_ip6, iphdr6->saddr.in6_u.u6_addr32).
#define IPV6(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) \
    ((u32[4]){ \
        (u32)(a) | ((u32)(b) << 8) | ((u32)(c) << 16) | ((u32)(d) << 24), \
        (u32)(e) | ((u32)(f) << 8) | ((u32)(g) << 16) | ((u32)(h) << 24), \
        (u32)(i) | ((u32)(j) << 8) | ((u32)(k) << 16) | ((u32)(l) << 24), \
        (u32)(m) | ((u32)(n) << 8) | ((u32)(o) << 16) | ((u32)(p) << 24) \
    })

// Compares two u32[4]-represented IPv6 addresses.
static __always_inline int ipv6_eq(const u32 *a, const u32 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr);

#ifdef ENABLE_IP_RANGE_DROP
static __always_inline int check_ip_range_drop(u32 ip);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "helpers.c"