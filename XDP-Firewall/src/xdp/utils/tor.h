#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#ifdef ENABLE_TOR_RELAY

#define TOR_CONN_ALLOW 0
#define TOR_CONN_DROP_BLACKLIST 1
#define TOR_CONN_DROP_CONNLIMIT 2

// Tor directory authorities and snowflake bridge distributors -- always
// exempt from ORPort filtering entirely (not just a higher limit, unlike
// known relays below). Small, curated, rarely-changing list, hardcoded
// rather than routed through xdpfw-add's block/allow rules. Addresses
// current as of this feature's writeup -- Tor's authority list changes
// rarely but does change; cross-check against the Tor Project's own
// published authority list if this has been running a long time.
static __always_inline int is_tor_trusted_v4(u32 saddr)
{
    return saddr == IPV4(141, 212, 118, 18) || // snowflake
        saddr == IPV4(193, 187, 88, 42) ||
        saddr == IPV4(193, 187, 88, 43) ||
        saddr == IPV4(193, 187, 88, 44) ||
        saddr == IPV4(193, 187, 88, 45) ||
        saddr == IPV4(193, 187, 88, 46) ||
        saddr == IPV4(45, 66, 35, 11) || // directory authorities
        saddr == IPV4(66, 111, 2, 131) ||
        saddr == IPV4(128, 31, 0, 39) ||
        saddr == IPV4(131, 188, 40, 189) ||
        saddr == IPV4(171, 25, 193, 9) ||
        saddr == IPV4(193, 23, 244, 244) ||
        saddr == IPV4(199, 58, 81, 140) ||
        saddr == IPV4(204, 13, 164, 118) ||
        saddr == IPV4(216, 218, 219, 41) ||
        saddr == IPV4(217, 196, 147, 77);
}

static __always_inline int tor_is_known_relay_v4(u32 saddr)
{
    lpm_trie_key_t key = { .prefix_len = 32, .data = saddr };

    return bpf_map_lookup_elem(&map_tor_known_relays, &key) != NULL;
}

/**
 * ORPort new-connection-flood mitigation, called on every inbound SYN to
 * TOR_ORPORT from a source that isn't in the trusted list. Two
 * independent mechanisms: (1) a dual-window new-connection-rate blacklist
 * (TOR_BLACKLIST_TIME once tripped) -- known relays are exempt entirely;
 * (2) a live concurrent-connection cap, checked regardless of relay
 * status (just a higher cap for relays), released on FIN/RST (see
 * tor_conn_release_v4 below).
 */
static __always_inline int tor_conn_check_v4(u32 src_ip, u64 now, int is_relay)
{
    tor_conn_state_t *st = bpf_map_lookup_elem(&map_tor_conn, &src_ip);
    tor_conn_state_t fresh = { .fast_window_start = now, .slow_window_start = now };

    if (!st)
    {
        bpf_map_update_elem(&map_tor_conn, &src_ip, &fresh, BPF_ANY);
        st = bpf_map_lookup_elem(&map_tor_conn, &src_ip);

        if (!st)
        {
            return TOR_CONN_ALLOW; // alloc failure -- fail open
        }
    }

    if (!is_relay)
    {
        if (st->blackhole_until && now < st->blackhole_until)
        {
            return TOR_CONN_DROP_BLACKLIST;
        }

        if (now - st->fast_window_start > TOR_FAST_WINDOW_NS)
        {
            st->fast_window_start = now;
            st->fast_count = 0;
        }

        st->fast_count++;

        if (now - st->slow_window_start > TOR_SLOW_WINDOW_NS)
        {
            st->slow_window_start = now;
            st->slow_count = 0;
        }

        st->slow_count++;

        if (st->fast_count > TOR_FAST_LIMIT || st->slow_count > TOR_SLOW_LIMIT)
        {
            st->blackhole_until = now + ((u64)TOR_BLACKLIST_TIME * NANO_TO_SEC);

            return TOR_CONN_DROP_BLACKLIST;
        }
    }

    u32 cap = is_relay ? TOR_RELAY_CONN_LIMIT : TOR_CONN_LIMIT;

    if (st->concurrent >= cap)
    {
        return TOR_CONN_DROP_CONNLIMIT;
    }

    st->concurrent++;

    return TOR_CONN_ALLOW;
}

static __always_inline void tor_conn_release_v4(u32 src_ip)
{
    tor_conn_state_t *st = bpf_map_lookup_elem(&map_tor_conn, &src_ip);

    if (st && st->concurrent > 0)
    {
        st->concurrent--;
    }
}

#ifdef ENABLE_IPV6
static __always_inline int is_tor_trusted_v6(const u32 *saddr)
{
    static const u32 snowflake_1[4] = IPV6(0x2a, 0x0c, 0xdd, 0x40, 0, 1, 0, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0x42);
    static const u32 snowflake_2[4] = IPV6(0x26, 0x07, 0xf0, 0x18, 0x06, 0, 0, 0x08, 0xbe, 0x30, 0x5b, 0xff, 0xfe, 0xf1, 0xc6, 0xfa);
    static const u32 dirauth_1[4] = IPV6(0x20, 0x01, 0x04, 0x70, 0x01, 0x64, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x02);
    static const u32 dirauth_2[4] = IPV6(0x20, 0x01, 0x06, 0x38, 0xa0, 0, 0x41, 0x40, 0, 0, 0, 0, 0xff, 0xff, 0x01, 0x89);
    static const u32 dirauth_3[4] = IPV6(0x20, 0x01, 0x06, 0x78, 0x05, 0x58, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x44);
    static const u32 dirauth_4[4] = IPV6(0x20, 0x01, 0x06, 0x7c, 0x28, 0x9c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09);
    static const u32 dirauth_5[4] = IPV6(0x26, 0x10, 0x01, 0xc0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0x01, 0x31);
    static const u32 dirauth_6[4] = IPV6(0x26, 0x20, 0x00, 0x13, 0x40, 0, 0x60, 0, 0, 0, 0, 0, 0x10, 0, 0x01, 0x18);
    static const u32 dirauth_7[4] = IPV6(0x2a, 0x02, 0x16, 0xa8, 0x06, 0x62, 0x22, 0x03, 0, 0, 0, 0, 0, 0, 0, 0x01);

    return ipv6_eq(saddr, snowflake_1) || ipv6_eq(saddr, snowflake_2) ||
        ipv6_eq(saddr, dirauth_1) || ipv6_eq(saddr, dirauth_2) ||
        ipv6_eq(saddr, dirauth_3) || ipv6_eq(saddr, dirauth_4) ||
        ipv6_eq(saddr, dirauth_5) || ipv6_eq(saddr, dirauth_6) ||
        ipv6_eq(saddr, dirauth_7);
}

static __always_inline int tor_is_known_relay_v6(const u32 *saddr)
{
    lpm_trie_key6_t key = { .prefix_len = 128 };

    #pragma unroll
    for (int i = 0; i < 4; i++)
    {
        key.data[i] = saddr[i];
    }

    return bpf_map_lookup_elem(&map_tor_known_relays6, &key) != NULL;
}

static __always_inline int tor_conn_check_v6(u128 src_ip, u64 now, int is_relay)
{
    tor_conn_state_t *st = bpf_map_lookup_elem(&map_tor_conn6, &src_ip);
    tor_conn_state_t fresh = { .fast_window_start = now, .slow_window_start = now };

    if (!st)
    {
        bpf_map_update_elem(&map_tor_conn6, &src_ip, &fresh, BPF_ANY);
        st = bpf_map_lookup_elem(&map_tor_conn6, &src_ip);

        if (!st)
        {
            return TOR_CONN_ALLOW;
        }
    }

    if (!is_relay)
    {
        if (st->blackhole_until && now < st->blackhole_until)
        {
            return TOR_CONN_DROP_BLACKLIST;
        }

        if (now - st->fast_window_start > TOR_FAST_WINDOW_NS)
        {
            st->fast_window_start = now;
            st->fast_count = 0;
        }

        st->fast_count++;

        if (now - st->slow_window_start > TOR_SLOW_WINDOW_NS)
        {
            st->slow_window_start = now;
            st->slow_count = 0;
        }

        st->slow_count++;

        if (st->fast_count > TOR_FAST_LIMIT || st->slow_count > TOR_SLOW_LIMIT)
        {
            st->blackhole_until = now + ((u64)TOR_BLACKLIST_TIME * NANO_TO_SEC);

            return TOR_CONN_DROP_BLACKLIST;
        }
    }

    u32 cap = is_relay ? TOR_RELAY_CONN_LIMIT : TOR_CONN_LIMIT;

    if (st->concurrent >= cap)
    {
        return TOR_CONN_DROP_CONNLIMIT;
    }

    st->concurrent++;

    return TOR_CONN_ALLOW;
}

static __always_inline void tor_conn_release_v6(u128 src_ip)
{
    tor_conn_state_t *st = bpf_map_lookup_elem(&map_tor_conn6, &src_ip);

    if (st && st->concurrent > 0)
    {
        st->concurrent--;
    }
}
#endif

#endif
