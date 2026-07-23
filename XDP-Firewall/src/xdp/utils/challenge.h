#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifdef ENABLE_UDP_CHALLENGE

// A source is trusted once a SECOND handshake-shaped packet arrives from it
// within this window after the first -- real UDP game clients universally
// retry an unanswered handshake attempt on a short timeout (a property of
// the protocols themselves, not something this firewall has to emulate).
// An indiscriminate spoofed-source flood essentially never re-sends from
// the exact same forged source at a plausible retry cadence, so this alone
// (the passive path) is enough to separate real clients from noise without
// ever constructing a reply packet. See config.h's ENABLE_UDP_ACTIVE_
// CHALLENGE comment for the opt-in active alternative, which shares this
// same pending-challenge record (map_challenge/map_challenge6) -- a
// packet is trusted if EITHER the timing check below passes OR (when
// active challenges are on) its first 4 bytes echo the cookie this box
// sent back.
#define CHALLENGE_MIN_GAP_NS 100000000ULL   // 100ms -- reject a repeat this fast (same burst, not a retry)
#define CHALLENGE_MAX_GAP_NS 5000000000ULL  // 5s -- reject a repeat this slow (stale, start over)

static __always_inline int challenge_is_whitelisted_v4(u32 ip, u64 now)
{
    u64 *ts = bpf_map_lookup_elem(&map_whitelist, &ip);

    return ts && (now - *ts) < ((u64)UDP_CHALLENGE_TTL * NANO_TO_SEC);
}

#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
static __always_inline u32 gen_challenge_cookie(u16 src_port, u64 now)
{
    return bpf_get_prandom_u32() ^ (u32)src_port ^ (u32)now;
}
#endif

/**
 * Checks a not-yet-whitelisted source's pending challenge record and
 * decides whether it's now trusted.
 *
 * @param payload/data_end Only used when ENABLE_UDP_ACTIVE_CHALLENGE is on,
 *                          to check for an echoed cookie -- pass NULL/NULL
 *                          if unavailable.
 * @param out_cookie Set to a fresh cookie to send in an active challenge
 *                    reply when this returns 0 and ENABLE_UDP_ACTIVE_
 *                    CHALLENGE is on -- the caller (rule.c/prog.c) builds
 *                    and sends the actual reply packet. Ignored/unused
 *                    otherwise.
 *
 * @return 1 if the source is now trusted (record cleared, whitelisted), 0 if not.
 */
static __always_inline int challenge_check_v4(u32 ip, void *payload, void *data_end, u64 now, u32 *out_cookie)
{
    pps_state_t *rec = bpf_map_lookup_elem(&map_challenge, &ip);

    if (rec)
    {
#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
        if (payload && data_end)
        {
            u32 *maybe_cookie = payload;

            if ((void *)(maybe_cookie + 1) <= data_end && *maybe_cookie == rec->pkt_count)
            {
                bpf_map_update_elem(&map_whitelist, &ip, &now, BPF_ANY);
                bpf_map_delete_elem(&map_challenge, &ip);

                return 1;
            }
        }
#endif

        u64 gap = now - rec->window_start;

        if (gap >= CHALLENGE_MIN_GAP_NS && gap <= CHALLENGE_MAX_GAP_NS)
        {
            bpf_map_update_elem(&map_whitelist, &ip, &now, BPF_ANY);
            bpf_map_delete_elem(&map_challenge, &ip);

            return 1;
        }
    }

#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
    u32 cookie = gen_challenge_cookie(0, now);
    pps_state_t new_rec = { .window_start = now, .pkt_count = cookie };

    if (out_cookie)
    {
        *out_cookie = cookie;
    }
#else
    pps_state_t new_rec = { .window_start = now, .pkt_count = 0 };
#endif

    bpf_map_update_elem(&map_challenge, &ip, &new_rec, BPF_ANY);

    return 0;
}

#ifdef ENABLE_IPV6
static __always_inline int challenge_is_whitelisted_v6(u128 ip, u64 now)
{
    u64 *ts = bpf_map_lookup_elem(&map_whitelist6, &ip);

    return ts && (now - *ts) < ((u64)UDP_CHALLENGE_TTL * NANO_TO_SEC);
}

static __always_inline int challenge_check_v6(u128 ip, void *payload, void *data_end, u64 now, u32 *out_cookie)
{
    pps_state_t *rec = bpf_map_lookup_elem(&map_challenge6, &ip);

    if (rec)
    {
#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
        if (payload && data_end)
        {
            u32 *maybe_cookie = payload;

            if ((void *)(maybe_cookie + 1) <= data_end && *maybe_cookie == rec->pkt_count)
            {
                bpf_map_update_elem(&map_whitelist6, &ip, &now, BPF_ANY);
                bpf_map_delete_elem(&map_challenge6, &ip);

                return 1;
            }
        }
#endif

        u64 gap = now - rec->window_start;

        if (gap >= CHALLENGE_MIN_GAP_NS && gap <= CHALLENGE_MAX_GAP_NS)
        {
            bpf_map_update_elem(&map_whitelist6, &ip, &now, BPF_ANY);
            bpf_map_delete_elem(&map_challenge6, &ip);

            return 1;
        }
    }

#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
    u32 cookie = gen_challenge_cookie(0, now);
    pps_state_t new_rec = { .window_start = now, .pkt_count = cookie };

    if (out_cookie)
    {
        *out_cookie = cookie;
    }
#else
    pps_state_t new_rec = { .window_start = now, .pkt_count = 0 };
#endif

    bpf_map_update_elem(&map_challenge6, &ip, &new_rec, BPF_ANY);

    return 0;
}
#endif

#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
/**
 * IPv4 header checksum (fixed 20-byte header, no options -- consistent
 * with the rest of this project, which never parses IP options).
 */
static __always_inline u16 ip_checksum(struct iphdr *ip)
{
    ip->check = 0;

    u32 csum = 0;
    u16 *p = (u16 *)ip;

    #pragma unroll
    for (int i = 0; i < 10; i++)
    {
        csum += p[i];
    }

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    return ~csum;
}

#ifdef ENABLE_IPV6
/**
 * Mandatory (RFC 8200) UDP checksum for the IPv6 active-challenge reply --
 * unlike IPv4, IPv6 UDP checksums can't just be left at 0.
 *
 * @param saddr/daddr Already-swapped reply addresses, u32[4] raw byte order.
 * @param udp The (already payload-filled) UDP header to checksum.
 * @param len_bytes sizeof(udphdr) + 4 (the cookie).
 */
static __always_inline u16 udp6_checksum(const u32 *saddr, const u32 *daddr, struct udphdr *udp, u16 len_bytes)
{
    u32 csum = 0;
    const u16 *sp = (const u16 *)saddr;
    const u16 *dp = (const u16 *)daddr;

    #pragma unroll
    for (int i = 0; i < 8; i++)
    {
        csum += sp[i];
    }

    #pragma unroll
    for (int i = 0; i < 8; i++)
    {
        csum += dp[i];
    }

    csum += htons(len_bytes);
    csum += htons(IPPROTO_UDP);

    udp->check = 0;

    u16 *up = (u16 *)udp;

    #pragma unroll
    for (int i = 0; i < 6; i++) // 8-byte UDP header + 4-byte cookie = 6 words
    {
        csum += up[i];
    }

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    u16 result = ~csum;

    return result == 0 ? 0xffff : result;
}
#endif
#endif

#endif
