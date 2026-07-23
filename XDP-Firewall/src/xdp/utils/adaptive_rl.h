#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#ifdef ENABLE_ADAPTIVE_RATE_LIMIT

#define ADAPTIVE_RL_WINDOW_NS 1000000000ULL // 1s rolling window

/**
 * Always-on per-source-IP TCP/UDP packet budget (see config.h's
 * ENABLE_ADAPTIVE_RATE_LIMIT comment for the full rationale). Exceeding
 * the budget blackholes the source into map_block for ADAPTIVE_BLOCK_TIME
 * seconds -- the same block map (and the same expiry handling already at
 * the top of xdp_prog_main) a filter rule's own block_time uses.
 *
 * @param weight How much of the budget this packet costs -- normally 1;
 *               ENABLE_SYN_PROTECTION passes a higher cost for
 *               implausible-looking SYNs (see syn_protect.h).
 *
 * @return 1 if this packet should be dropped (just tripped the budget), 0 if not.
 */
static __always_inline int adaptive_rate_limited_v4(u32 ip, u64 now, u32 weight)
{
    pps_state_t *st = bpf_map_lookup_elem(&map_rl_state, &ip);

    if (!st)
    {
        pps_state_t new_st = { .window_start = now, .pkt_count = weight };
        bpf_map_update_elem(&map_rl_state, &ip, &new_st, BPF_ANY);

        return 0;
    }

    if (now - st->window_start > ADAPTIVE_RL_WINDOW_NS)
    {
        st->window_start = now;
        st->pkt_count = weight;

        return 0;
    }

    st->pkt_count += weight;

    if (st->pkt_count > ADAPTIVE_PPS_LIMIT)
    {
        u64 until = now + ((u64)ADAPTIVE_BLOCK_TIME * NANO_TO_SEC);
        bpf_map_update_elem(&map_block, &ip, &until, BPF_ANY);

        return 1;
    }

    return 0;
}

#ifdef ENABLE_IPV6
static __always_inline int adaptive_rate_limited_v6(u128 ip, u64 now, u32 weight)
{
    pps_state_t *st = bpf_map_lookup_elem(&map_rl_state6, &ip);

    if (!st)
    {
        pps_state_t new_st = { .window_start = now, .pkt_count = weight };
        bpf_map_update_elem(&map_rl_state6, &ip, &new_st, BPF_ANY);

        return 0;
    }

    if (now - st->window_start > ADAPTIVE_RL_WINDOW_NS)
    {
        st->window_start = now;
        st->pkt_count = weight;

        return 0;
    }

    st->pkt_count += weight;

    if (st->pkt_count > ADAPTIVE_PPS_LIMIT)
    {
        u64 until = now + ((u64)ADAPTIVE_BLOCK_TIME * NANO_TO_SEC);
        bpf_map_update_elem(&map_block6, &ip, &until, BPF_ANY);

        return 1;
    }

    return 0;
}
#endif

#endif
