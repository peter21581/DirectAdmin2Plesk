#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#include <linux/icmp.h>
#ifdef ENABLE_IPV6
#include <linux/icmpv6.h>
#endif

#ifdef ENABLE_ICMP_PROTECTION

#define ICMP_WINDOW_NS 1000000000ULL // 1s rolling window

/**
 * Echo requests (common, expected -- monitoring/path checks) cost less of
 * the per-IP budget than other, rarer, more-often-abusive ICMP types.
 */
static __always_inline u32 icmp_weight_v4(struct icmphdr *icmp)
{
    return icmp->type == ICMP_ECHO ? 1 : 4;
}

static __always_inline int icmp_rate_limited_v4(u32 ip, u32 weight, u64 now)
{
    icmp_state_t *st = bpf_map_lookup_elem(&map_icmp_state, &ip);

    if (st)
    {
        if (now - st->window_start > ICMP_WINDOW_NS)
        {
            st->window_start = now;
            st->pkt_count = weight;

            return 0;
        }

        st->pkt_count += weight;

        return st->pkt_count > ICMP_PPS_LIMIT;
    }

    icmp_state_t new_st = { .window_start = now, .pkt_count = weight };
    bpf_map_update_elem(&map_icmp_state, &ip, &new_st, BPF_ANY);

    return 0;
}

#ifdef ENABLE_IPV6
static __always_inline u32 icmp_weight_v6(struct icmp6hdr *icmp6)
{
    return icmp6->icmp6_type == ICMPV6_ECHO_REQUEST ? 1 : 4;
}

static __always_inline int icmp_rate_limited_v6(u128 ip, u32 weight, u64 now)
{
    icmp_state_t *st = bpf_map_lookup_elem(&map_icmp_state6, &ip);

    if (st)
    {
        if (now - st->window_start > ICMP_WINDOW_NS)
        {
            st->window_start = now;
            st->pkt_count = weight;

            return 0;
        }

        st->pkt_count += weight;

        return st->pkt_count > ICMP_PPS_LIMIT;
    }

    icmp_state_t new_st = { .window_start = now, .pkt_count = weight };
    bpf_map_update_elem(&map_icmp_state6, &ip, &new_st, BPF_ANY);

    return 0;
}
#endif

#endif
