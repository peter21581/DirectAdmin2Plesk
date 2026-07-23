#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#include <linux/ip.h>
#ifdef ENABLE_IPV6
#include <linux/ipv6.h>
#endif
#include <linux/tcp.h>

#ifdef ENABLE_SYN_PROTECTION

#define SUBNET_WINDOW_NS 1000000000ULL // 1s

/**
 * Rough OS plausibility check from the SYN's own IP/TCP header -- not full
 * signature matching, just "does this look like a real client stack, and
 * is it Windows-shaped (the common case for players) or not". Used as a
 * weight against the adaptive rate-limit budget (see adaptive_rl.h) --
 * implausible/non-Windows-shaped SYNs cost more of the same budget.
 */
static __always_inline u32 syn_weight_v4(struct iphdr *ip, struct tcphdr *tcp)
{
    if (ip->ttl > 250 || ntohs(tcp->window) == 0)
    {
        return 50; // implausible for any real stack -- burn the budget in one hit
    }

    if (ip->ttl <= 64)
    {
        return 4; // Linux/BSD/macOS-shaped -- less common for players
    }

    if (ip->ttl <= 128)
    {
        return 1; // Windows-shaped -- generous, matches typical player base
    }

    return 4; // rare bucket (router/embedded/Solaris-shaped) -- stricter
}

/**
 * A real OS's SYN is never exactly 40 bytes of IP total length (a bare
 * 20-byte IP + 20-byte TCP header with zero options -- every real stack
 * sends at least MSS) and never much over ~64 bytes either (already a
 * generous allowance for MSS+SACK+timestamp+window-scale+NOP padding).
 * Checked before touching any map.
 */
static __always_inline int bad_syn_length_v4(struct iphdr *ip)
{
    u16 total_len = ntohs(ip->tot_len);

    return total_len == 40 || total_len > 64;
}

static __always_inline int subnet_syn_flood_v4(u32 src_ip, u64 now)
{
    u32 subnet = src_ip & htonl(0xFFFFFFFFu << (32 - SUBNET_MASK_BITS));

    pps_state_t *st = bpf_map_lookup_elem(&map_subnet_syn, &subnet);

    if (st)
    {
        if (now - st->window_start > SUBNET_WINDOW_NS)
        {
            st->window_start = now;
            st->pkt_count = 1;

            return 0;
        }

        st->pkt_count++;

        return st->pkt_count > SUBNET_SYN_LIMIT;
    }

    pps_state_t new_st = { .window_start = now, .pkt_count = 1 };
    bpf_map_update_elem(&map_subnet_syn, &subnet, &new_st, BPF_ANY);

    return 0;
}

#ifdef ENABLE_IPV6
static __always_inline u32 syn_weight_v6(struct ipv6hdr *ip6, struct tcphdr *tcp)
{
    if (ip6->hop_limit > 250 || ntohs(tcp->window) == 0)
    {
        return 50;
    }

    if (ip6->hop_limit <= 64)
    {
        return 4;
    }

    if (ip6->hop_limit <= 128)
    {
        return 1;
    }

    return 4;
}

/**
 * IPv6's payload_len is everything AFTER the fixed 40-byte base header
 * (unlike IPv4's tot_len, which includes the IP header itself), so the
 * bare-TCP-header size is 20, not 40, and the upper bound is 44, not 64.
 */
static __always_inline int bad_syn_length_v6(struct ipv6hdr *ip6)
{
    u16 payload_len = ntohs(ip6->payload_len);

    return payload_len == 20 || payload_len > 44;
}

/**
 * @param src_ip Source address as a u128 (same convention as
 *               map_block6/map_rl_state6/map_icmp_state6 -- see prog.c's
 *               src_ip6, built via memcpy from saddr.in6_u.u6_addr32).
 */
static __always_inline int subnet_syn_flood_v6(u128 src_ip, u64 now)
{
    int keep_bytes = SUBNET_MASK_BITS_V6 / 8;
    u8 *ab = (u8 *)&src_ip;
    u128 subnet = 0;
    u8 *sb = (u8 *)&subnet;

    #pragma unroll
    for (int i = 0; i < 16; i++)
    {
        sb[i] = (i < keep_bytes) ? ab[i] : 0;
    }

    pps_state_t *st = bpf_map_lookup_elem(&map_subnet_syn6, &subnet);

    if (st)
    {
        if (now - st->window_start > SUBNET_WINDOW_NS)
        {
            st->window_start = now;
            st->pkt_count = 1;

            return 0;
        }

        st->pkt_count++;

        return st->pkt_count > SUBNET_SYN_LIMIT;
    }

    pps_state_t new_st = { .window_start = now, .pkt_count = 1 };
    bpf_map_update_elem(&map_subnet_syn6, &subnet, &new_st, BPF_ANY);

    return 0;
}
#endif

#endif
